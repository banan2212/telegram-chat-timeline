import Foundation
import UIKit
import Display
import SwiftSignalKit
import TelegramCore
import AccountContext
import QrCode

// Owned by AuthorizationSequenceController, never by the disappearing phone node.
// All methods and delivered callbacks run on the main queue.
final class AuthorizationQRLoginCoordinator {
    enum DisplayState {
        case loading
        case finishing
        case code(UIImage)
        case retry(Reason)
    }

    enum Reason {
        case failed
        case limitExceeded
        case expired
        case suspended
        case completionFailed
    }

    private let sharedContext: SharedAccountContext
    private var account: UnauthorizedAccount
    private let syncContacts: Bool
    private var lifecycle = AuthorizationQRLoginLifecycle()
    private let requestDisposable = MetaDisposable()
    private let eventsDisposable = MetaDisposable()
    private let expiryDisposable = MetaDisposable()
    private let renderDisposable = MetaDisposable()
    private var refreshPending = false
    private var isForeground = true
    private var migrationCount = 0
    private var eventsGeneration: UInt64 = 0

    var displayStateUpdated: ((DisplayState) -> Void)?
    var accountUpdated: ((UnauthorizedAccount) -> Void)?
    var completed: (() -> Void)?
    var stopped: (() -> Void)?

    var isActive: Bool { self.lifecycle.isActive }

    init(sharedContext: SharedAccountContext, account: UnauthorizedAccount, syncContacts: Bool) {
        self.sharedContext = sharedContext
        self.account = account
        self.syncContacts = syncContacts
    }

    deinit {
        self.requestDisposable.dispose()
        self.eventsDisposable.dispose()
        self.expiryDisposable.dispose()
        self.renderDisposable.dispose()
    }

    // Called only by the visible QR entry or Retry button. Foregrounding never
    // silently creates a fresh credential.
    func start() {
        guard self.isForeground else { return }
        self.migrationCount = 0
        self.cancelWork()
        self.observeTokenUpdates()
        self.requestToken()
    }

    func cancel() {
        self.lifecycle.invalidate(.inactive)
        self.cancelWork()
        self.displayStateUpdated?(.retry(.suspended))
    }

    func updateApplicationIsActive(_ isActive: Bool) {
        self.isForeground = isActive
        if !isActive {
            self.lifecycle.invalidate(.suspended)
            self.cancelWork()
            self.displayStateUpdated?(.retry(.suspended))
            self.stopped?()
        }
    }

    private func cancelWork() {
        self.eventsGeneration &+= 1
        self.requestDisposable.set(nil)
        self.eventsDisposable.set(nil)
        self.expiryDisposable.set(nil)
        self.renderDisposable.set(nil)
        self.refreshPending = false
    }

    private func observeTokenUpdates() {
        self.eventsGeneration &+= 1
        let eventsGeneration = self.eventsGeneration
        self.eventsDisposable.set((self.account.updateLoginTokenEvents
        |> deliverOnMainQueue).startStrict(next: { [weak self] _ in
            guard let self, eventsGeneration == self.eventsGeneration, self.lifecycle.isActive, self.isForeground else { return }
            if self.lifecycle.phase == .requesting {
                self.refreshPending = true
            } else {
                self.requestToken()
            }
        }))
    }

    private func requestToken() {
        guard self.isForeground else { return }
        let generation = self.lifecycle.beginRequest()
        self.expiryDisposable.set(nil)
        self.renderDisposable.set(nil)
        self.refreshPending = false
        self.displayStateUpdated?(.loading)

        let account = self.account
        let sharedContext = self.sharedContext
        let syncContacts = self.syncContacts
        let signal = sharedContext.activeAccountContexts
        |> castError(ExportAuthTransferTokenError.self)
        |> take(1)
        |> mapToSignal { activeAccountsAndInfo -> Signal<ExportAuthTransferTokenResult, ExportAuthTransferTokenError> in
            let (_, activeAccounts, _) = activeAccountsAndInfo
            let userIds = activeAccounts.map { $0.1.account }
                .filter { $0.testingEnvironment == account.testingEnvironment }
                .map { $0.peerId.id }
            return TelegramEngineUnauthorized(account: account).auth.exportAuthTransferToken(
                accountManager: sharedContext.accountManager,
                otherAccountUserIds: userIds,
                syncContacts: syncContacts
            )
        }
        // Bound an unresponsive request while preserving every Core auth result.
        |> timeout(30.0, queue: .mainQueue(), alternate: .fail(.generic))
        |> deliverOnMainQueue

        // Install a holder before subscribing, so synchronous signals cannot
        // overwrite a newer request's cancellation handle.
        let currentRequest = MetaDisposable()
        self.requestDisposable.set(currentRequest)
        currentRequest.set(signal.startStrict(next: { [weak self] result in
            guard let self, self.lifecycle.accepts(generation), self.isForeground else { return }
            switch result {
            case let .displayToken(token):
                if self.refreshPending {
                    self.requestToken()
                    return
                }
                let validUntil = TimeInterval(token.validUntil)
                guard self.lifecycle.display(generation: generation, validUntil: validUntil, now: Date().timeIntervalSince1970) else {
                    self.fail(.expired)
                    return
                }
                self.scheduleExpiry(generation: generation, validUntil: validUntil)
                let encodedToken = token.value.base64EncodedString()
                    .replacingOccurrences(of: "+", with: "-")
                    .replacingOccurrences(of: "/", with: "_")
                    .replacingOccurrences(of: "=", with: "")
                // Kept only inside the renderer's cancellable signal. Never
                // logged, persisted, shared, or exposed as an accessibility value.
                let rendering = qrCode(string: "tg://login?token=\(encodedToken)", color: .black, backgroundColor: .white, icon: .none)
                |> take(1)
                |> deliverOnMainQueue
                let currentRender = MetaDisposable()
                self.renderDisposable.set(currentRender)
                currentRender.set(rendering.startStrict(next: { [weak self] _, generate in
                    guard let self, self.lifecycle.canRender(generation: generation, now: Date().timeIntervalSince1970), self.isForeground else { return }
                    let size = CGSize(width: 768.0, height: 768.0)
                    let context = generate(TransformImageArguments(corners: ImageCorners(), imageSize: size, boundingSize: size, intrinsicInsets: UIEdgeInsets()))
                    guard let image = context?.generateImage() else {
                        self.fail(.failed)
                        return
                    }
                    guard self.lifecycle.canRender(generation: generation, now: Date().timeIntervalSince1970), self.isForeground else { return }
                    self.displayStateUpdated?(.code(image))
                    self.renderDisposable.set(nil)
                }))
            case let .changeAccountAndRetry(updatedAccount):
                self.account = updatedAccount
                self.accountUpdated?(updatedAccount)
                self.migrationCount += 1
                guard self.migrationCount <= 3 else {
                    self.fail(.failed)
                    return
                }
                self.observeTokenUpdates()
                self.requestToken()
            case let .passwordRequested(updatedAccount):
                guard self.lifecycle.finish(generation: generation) else { return }
                self.account = updatedAccount
                // The password UI must use the migrated account before it can
                // submit a password. Do this before dismissing or flushing state.
                self.accountUpdated?(updatedAccount)
                self.cancelWork()
                self.displayStateUpdated?(.finishing)
                self.completed?()
            case .loggedIn:
                guard self.lifecycle.finish(generation: generation) else { return }
                self.cancelWork()
                self.displayStateUpdated?(.finishing)
                self.completed?()
            }
        }, error: { [weak self] error in
            guard let self, self.lifecycle.accepts(generation) else { return }
            switch error {
            case .generic:
                self.fail(.failed)
            case .limitExceeded:
                self.fail(.limitExceeded)
            }
        }))
    }

    private func scheduleExpiry(generation: UInt64, validUntil: TimeInterval) {
        let currentExpiry = MetaDisposable()
        self.expiryDisposable.set(currentExpiry)
        currentExpiry.set((Signal<Never, NoError>.complete()
        |> delay(max(0.0, validUntil - Date().timeIntervalSince1970), queue: .mainQueue())).startStrict(completed: { [weak self] in
            guard let self, self.lifecycle.accepts(generation), self.isForeground else { return }
            if Date().timeIntervalSince1970 < validUntil {
                self.scheduleExpiry(generation: generation, validUntil: validUntil)
            } else {
                // requestToken clears the expired image before making a request.
                self.requestToken()
            }
        }))
    }

    private func fail(_ reason: Reason) {
        self.lifecycle.invalidate(.failed)
        self.cancelWork()
        self.displayStateUpdated?(.retry(reason))
        self.stopped?()
    }
}
