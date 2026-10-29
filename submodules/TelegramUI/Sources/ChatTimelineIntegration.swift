import Foundation
import UIKit
import AccountContext
import ChatControllerInteraction
import ChatInterfaceState
import Display
import SwiftSignalKit
import TelegramCore
import TelegramPresentationData
import TelegramStringFormatting
import UndoUI

struct ChatTimelineReturnLocation {
    let peerId: EnginePeer.Id
    let scrollState: ChatInterfaceHistoryScrollState
}

private enum ChatTimelineValidationResult {
    case message(EngineMessage)
    case unavailable
    case failed
}

private final class ChatTimelinePreviewProvider {
    private let context: AccountContext
    private let peerId: EnginePeer.Id
    private let calendar: Calendar
    private var cache: [Int32: (savedAt: Date, preview: ChatTimelinePreview)] = [:]
    private var cacheOrder: [Int32] = []

    init(context: AccountContext, peerId: EnginePeer.Id, timeZone: TimeZone) {
        self.context = context
        self.peerId = peerId
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        self.calendar = calendar
    }

    // UI requests run on the main queue, after the date-control debounce. A short-lived cache is
    // scoped to this account + chat + sheet; errors and empty responses are never cached.
    func preview(date: Date) -> Signal<ChatTimelinePreviewResult, NoError> {
        let start = self.calendar.startOfDay(for: date)
        guard let end = self.calendar.date(byAdding: .day, value: 1, to: start) else {
            return .single(.failed)
        }
        let timestamp = Int32(clamping: Int64(start.timeIntervalSince1970))
        let upperTimestamp = Int32(clamping: Int64(end.timeIntervalSince1970))
        if let entry = self.cache[timestamp], Date().timeIntervalSince(entry.savedAt) < 30.0 {
            return .single(.message(entry.preview))
        }

        return self.context.engine.messages.previewMessageByTimestamp(peerId: self.peerId, timestamp: timestamp, upperTimestamp: upperTimestamp)
        |> map { [context = self.context] message -> ChatTimelinePreviewResult in
            guard let message else {
                return .unavailable
            }
            let presentationData = context.sharedContext.currentPresentationData.with { $0 }
            let author = message.author?.displayTitle(strings: presentationData.strings, displayOrder: presentationData.nameDisplayOrder) ?? ""
            let description = descriptionStringForMessage(contentSettings: context.currentContentSettings.with { $0 }, message: message, strings: presentationData.strings, nameDisplayOrder: presentationData.nameDisplayOrder, dateTimeFormat: presentationData.dateTimeFormat, accountPeerId: context.account.peerId).0.string
            let hasSpoiler = message.attributes.contains { attribute in
                guard let entities = attribute as? TextEntitiesMessageAttribute else {
                    return false
                }
                return entities.entities.contains { entity in
                    if case .Spoiler = entity.type {
                        return true
                    }
                    return false
                }
            }
            let text = hasSpoiler ? "Message contains a spoiler" : String(description.prefix(360))
            return .message(ChatTimelinePreview(messageId: message.id, timestamp: message.timestamp, author: author, text: text))
        }
        |> `catch` { error -> Signal<ChatTimelinePreviewResult, NoError> in
            switch error {
            case .unavailable:
                return .single(.unavailable)
            case .generic:
                return .single(.failed)
            }
        }
        |> timeout(10.0, queue: Queue.mainQueue(), alternate: .single(.failed))
        |> take(1)
        |> deliverOnMainQueue
        |> map { [weak self] result in
            if let self, case let .message(preview) = result {
                self.cache[timestamp] = (Date(), preview)
                self.cacheOrder.removeAll(where: { $0 == timestamp })
                self.cacheOrder.append(timestamp)
                while self.cacheOrder.count > 32 {
                    self.cache.removeValue(forKey: self.cacheOrder.removeFirst())
                }
            }
            return result
        }
    }
}

extension ChatControllerImpl {
    private func isChatTimelineAvailable(peerId: EnginePeer.Id) -> Bool {
        guard self.isNodeLoaded, self.chatTimelineChatVisible, !self.isUpdatingChatLocationThread,
              case .standard(.default) = self.mode,
              case let .peer(currentPeerId) = self.chatLocation, currentPeerId == peerId,
              !self.chatDisplayNode.isInputViewFocused,
              self.presentationInterfaceState.historyFilter == nil,
              self.presentationInterfaceState.search == nil,
              self.presentationInterfaceState.interfaceState.selectionState == nil,
              let peer = self.presentationInterfaceState.renderedPeer?.peer,
              !peer.isForumOrMonoForum else {
            return false
        }
        switch self.presentationInterfaceState.subject {
        case nil, .message:
            break
        default:
            return false
        }
        return peerId.namespace == Namespaces.Peer.CloudUser || peerId.namespace == Namespaces.Peer.CloudGroup || peerId.namespace == Namespaces.Peer.CloudChannel
    }

    /// Called from the chat's existing date header, without a competing scroll/swipe recognizer.
    /// Unsupported histories keep the original date/calendar behavior.
    @discardableResult
    func openChatTimeline(timestamp: Int32) -> Bool {
        guard let peerId = self.chatLocation.peerId, self.isChatTimelineAvailable(peerId: peerId) else {
            return false
        }
        if self.chatTimelineController != nil {
            return true
        }
        guard let original = self.chatDisplayNode.historyNode.chatTimelineScrollState() else {
            return false
        }
        self.cancelChatTimelineNavigation()
        let generation = self.chatTimelineNavigationGeneration

        let timeZone = TimeZone.current
        let provider = ChatTimelinePreviewProvider(context: self.context, peerId: peerId, timeZone: timeZone)
        let returnLocation = self.chatTimelineReturnLocation.flatMap { $0.peerId == peerId ? $0 : nil }
        let returnAction: (() -> Void)?
        if let returnLocation {
            returnAction = { [weak self] in
                guard let self, self.chatTimelineNavigationGeneration == generation else {
                    return
                }
                self.returnFromChatTimeline(to: returnLocation)
            }
        } else {
            returnAction = nil
        }
        let controller = ChatTimelineController(
            context: self.context,
            initialDate: Date(timeIntervalSince1970: TimeInterval(original.messageIndex.timestamp)),
            minimumDate: Date(timeIntervalSince1970: 1375315200), // August 2013; not a claim about this chat's oldest loaded message.
            maximumDate: Date(),
            timeZone: timeZone,
            loadPreview: { date in provider.preview(date: date) },
            openCalendar: { [weak self] in
                guard let self, self.chatTimelineNavigationGeneration == generation, self.isChatTimelineAvailable(peerId: peerId) else {
                    return
                }
                self.openCalendarSearch(timestamp: timestamp, isMedia: true)
            },
            confirm: { [weak self] preview in
                guard let self, self.chatTimelineNavigationGeneration == generation else {
                    return
                }
                self.confirmChatTimeline(preview: preview, original: original, peerId: peerId)
            },
            returnToReadingPosition: returnAction
        )
        self.chatTimelineController = controller
        self.present(controller, in: .window(.root))
        return true
    }

    func cancelChatTimelineNavigation() {
        self.chatTimelineNavigationGeneration += 1
        self.chatTimelineNavigationDisposable.set(nil)
        self.chatTimelineHistoryNavigationDisposable.set(nil)
        if self.chatTimelineHistoryNavigationActive {
            self.chatTimelineHistoryNavigationActive = false
            self.loadingMessage.set(.single(nil))
        }
    }

    func dismissChatTimeline(clearReturnLocation: Bool = false) {
        self.cancelChatTimelineNavigation()
        let controller = self.chatTimelineController
        self.chatTimelineController = nil
        controller?.dismiss()
        self.chatTimelineReturnNotice?.dismissWithCommitAction()
        self.chatTimelineReturnNotice = nil
        if clearReturnLocation {
            self.chatTimelineReturnLocation = nil
        }
    }

    private func confirmChatTimeline(preview: ChatTimelinePreview, original: ChatInterfaceHistoryScrollState, peerId: EnginePeer.Id) {
        guard self.isChatTimelineAvailable(peerId: peerId) else {
            return
        }
        self.validateChatTimelineMessage(id: preview.messageId, peerId: peerId, completion: { [weak self] message in
            guard let self else {
                return
            }
            let returnLocation = ChatTimelineReturnLocation(peerId: peerId, scrollState: original)
            self.chatTimelineReturnLocation = returnLocation
            let generation = self.chatTimelineNavigationGeneration
            self.chatTimelineHistoryNavigationActive = true
            self.navigateToMessage(from: original.messageIndex.id, to: .id(message.id, NavigateToMessageParams(timestamp: nil, quote: nil)), rememberInStack: false, forceInCurrentChat: true, animated: !self.presentationData.reduceMotion && !UIAccessibility.isReduceMotionEnabled, completion: { [weak self] in
                guard let self, self.chatTimelineNavigationGeneration == generation else {
                    return
                }
                self.chatTimelineHistoryNavigationActive = false
                guard self.isChatTimelineAvailable(peerId: peerId) else {
                    return
                }
                self.chatTimelineReturnNotice?.dismissWithCommitAction()
                let notice = UndoOverlayController(presentationData: self.presentationData, content: .info(title: nil, text: "Your reading position is saved. You can also return from Timeline.", timeout: 8.0, customUndoText: "Return"), elevatedLayout: false, action: { [weak self] action in
                    if action == .undo {
                        self?.returnFromChatTimeline(to: returnLocation)
                        return true
                    }
                    return false
                })
                self.chatTimelineReturnNotice = notice
                self.present(notice, in: .current)
            }, customNavigationDisposable: self.chatTimelineHistoryNavigationDisposable, isNavigationValid: { [weak self] in
                guard let self, self.chatTimelineNavigationGeneration == generation else {
                    return false
                }
                guard self.isChatTimelineAvailable(peerId: peerId) else {
                    self.cancelChatTimelineNavigation()
                    return false
                }
                return true
            })
        })
    }

    private func returnFromChatTimeline(to location: ChatTimelineReturnLocation) {
        guard self.isChatTimelineAvailable(peerId: location.peerId) else {
            return
        }
        self.validateChatTimelineMessage(id: location.scrollState.messageIndex.id, peerId: location.peerId, completion: { [weak self] message in
            guard let self else {
                return
            }
            let generation = self.chatTimelineNavigationGeneration
            self.chatTimelineHistoryNavigationActive = true
            self.navigateToMessage(from: nil, to: .id(message.id, NavigateToMessageParams(timestamp: nil, quote: nil)), scrollPosition: .top(CGFloat(location.scrollState.relativeOffset)), rememberInStack: false, forceInCurrentChat: true, animated: !self.presentationData.reduceMotion && !UIAccessibility.isReduceMotionEnabled, completion: { [weak self] in
                guard let self, self.chatTimelineNavigationGeneration == generation else {
                    return
                }
                self.chatTimelineHistoryNavigationActive = false
            }, customNavigationDisposable: self.chatTimelineHistoryNavigationDisposable, isNavigationValid: { [weak self] in
                guard let self, self.chatTimelineNavigationGeneration == generation else {
                    return false
                }
                guard self.isChatTimelineAvailable(peerId: location.peerId) else {
                    self.cancelChatTimelineNavigation()
                    return false
                }
                return true
            })
        })
    }

    private func validateChatTimelineMessage(id: EngineMessage.Id, peerId: EnginePeer.Id, completion: @escaping (EngineMessage) -> Void) {
        self.cancelChatTimelineNavigation()
        let generation = self.chatTimelineNavigationGeneration
        self.chatTimelineNavigationDisposable.set((self.context.engine.messages.fetchChatTimelineMessage(id: id)
        |> map { message -> ChatTimelineValidationResult in
            if let message {
                return .message(message)
            }
            return .unavailable
        }
        |> `catch` { error -> Signal<ChatTimelineValidationResult, NoError> in
            switch error {
            case .unavailable:
                return .single(.unavailable)
            case .generic:
                return .single(.failed)
            }
        }
        |> timeout(10.0, queue: Queue.mainQueue(), alternate: .single(.failed))
        |> take(1)
        |> deliverOnMainQueue).startStrict(next: { [weak self] result in
            guard let self, self.chatTimelineNavigationGeneration == generation, self.isChatTimelineAvailable(peerId: peerId) else {
                return
            }
            switch result {
            case let .message(message):
                completion(message)
            case .failed:
                self.controllerInteraction?.displayUndo(.info(title: nil, text: "Couldn’t load the message. Check your connection and try again.", timeout: nil, customUndoText: nil))
            case .unavailable:
                self.controllerInteraction?.displayUndo(.info(title: nil, text: self.presentationData.strings.Conversation_MessageDoesntExist, timeout: nil, customUndoText: nil))
            }
        }))
    }
}
