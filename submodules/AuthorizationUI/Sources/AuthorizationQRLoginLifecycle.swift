import Foundation

// No credentials or QR contents belong in this state machine. Every asynchronous
// result must match the current generation before it can affect the screen.
struct AuthorizationQRLoginLifecycle {
    enum Phase: Equatable {
        case inactive
        case requesting
        case displaying(validUntil: TimeInterval)
        case failed
        case suspended
        case finished
    }

    private(set) var phase: Phase = .inactive
    private(set) var generation: UInt64 = 0

    var isActive: Bool {
        switch self.phase {
        case .requesting, .displaying:
            return true
        default:
            return false
        }
    }

    mutating func beginRequest() -> UInt64 {
        self.generation &+= 1
        self.phase = .requesting
        return self.generation
    }

    func accepts(_ generation: UInt64) -> Bool {
        return self.isActive && generation == self.generation
    }

    mutating func display(generation: UInt64, validUntil: TimeInterval, now: TimeInterval) -> Bool {
        guard self.accepts(generation), validUntil > now else {
            return false
        }
        self.phase = .displaying(validUntil: validUntil)
        return true
    }

    func canRender(generation: UInt64, now: TimeInterval) -> Bool {
        guard self.accepts(generation), case let .displaying(validUntil) = self.phase else {
            return false
        }
        return now < validUntil
    }

    mutating func invalidate(_ phase: Phase) {
        self.generation &+= 1
        self.phase = phase
    }

    mutating func finish(generation: UInt64) -> Bool {
        guard self.accepts(generation) else {
            return false
        }
        self.invalidate(.finished)
        return true
    }
}

// A committed password state can arrive before the export result, even after
// cancellation. Keep that state, but never allow an obsolete DC reconciliation
// to release the password screen against the wrong account.
struct AuthorizationQRLoginHandoffGate {
    enum Destination: Equatable {
        case password(masterDatacenterId: Int32)
        case authorized
    }

    private(set) var destination: Destination?
    private(set) var revision: UInt64 = 0
    private(set) var ownsAuthorization = false

    mutating func beginSession() {
        self.discardPendingState()
        self.ownsAuthorization = true
    }

    mutating func releaseOwnership() {
        self.discardPendingState()
        self.ownsAuthorization = false
    }

    @discardableResult mutating func observe(_ destination: Destination) -> Bool {
        guard self.ownsAuthorization else { return false }
        self.revision &+= 1
        self.destination = destination
        return true
    }

    mutating func invalidateReconciliation() {
        self.revision &+= 1
    }

    mutating func discardPendingState() {
        self.revision &+= 1
        self.destination = nil
    }

    func canApply(revision: UInt64, accountMasterDatacenterId: Int32) -> Bool {
        guard self.ownsAuthorization, revision == self.revision, let destination = self.destination else { return false }
        switch destination {
        case let .password(masterDatacenterId):
            return accountMasterDatacenterId == masterDatacenterId
        case .authorized:
            return true
        }
    }

    mutating func consume(revision: UInt64, accountMasterDatacenterId: Int32) -> Bool {
        guard self.canApply(revision: revision, accountMasterDatacenterId: accountMasterDatacenterId) else { return false }
        self.destination = nil
        // Password submission belongs to the ordinary password flow from this
        // point. QR recovery must never race its normal AccountManager commit.
        self.ownsAuthorization = false
        self.revision &+= 1
        return true
    }
}
