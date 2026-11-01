import Foundation

// Deliberately accepts only closed enums. Never add an RPC payload, error string,
// account/DC identifier, proxy address, timestamp, token, or persistence here.
public enum AuthorizationDiagnosticConnection: String, CaseIterable {
    case unobserved
    case waitingForNetwork = "waiting_for_network"
    case connecting
    case updating
    case online
}

public enum AuthorizationDiagnosticStage: String, CaseIterable {
    case sendCode = "send_code"
    case migratedSendCode = "migrated_send_code"
    case passwordFetch = "password_fetch"
    case firebaseFallback = "firebase_fallback"
}

public enum AuthorizationDiagnosticOutcome: String {
    case codeSent = "code_sent"
    case loggedIn = "logged_in"
    case timeout
    case serverError = "server_error"
    case cancelled
}

public enum AuthorizationDiagnosticObservation: String {
    case observed
    case notObserved = "not_observed"
    case unsupported
}

enum AuthorizationDiagnosticEvent {
    case apnsChallenge
    case recaptchaChallenge
    case serverErrorRetry
}

public struct AuthorizationDiagnosticStageSnapshot {
    public let stage: AuthorizationDiagnosticStage
    public let connections: [AuthorizationDiagnosticConnection]
    public let apnsChallenge: AuthorizationDiagnosticObservation
    public let recaptchaChallenge: AuthorizationDiagnosticObservation
    public let serverErrorRetry: AuthorizationDiagnosticObservation
}

public struct AuthorizationCodeDiagnosticSnapshot {
    public let lastStage: AuthorizationDiagnosticStage
    public let stages: [AuthorizationDiagnosticStageSnapshot]
    public let dcMigration: Bool
    public let outcome: AuthorizationDiagnosticOutcome

    public var summary: String {
        func observations(_ value: (AuthorizationDiagnosticStageSnapshot) -> AuthorizationDiagnosticObservation) -> String {
            return self.stages.isEmpty ? "unobserved" : self.stages.map {
                $0.stage.rawValue + "=" + value($0).rawValue
            }.joined(separator: "; ")
        }
        let connections = self.stages.map { stage in
            stage.stage.rawValue + "=" + stage.connections.map { $0.rawValue }.joined(separator: ",")
        }.joined(separator: "; ")
        return [
            "outcome=" + self.outcome.rawValue,
            "stage=" + self.lastStage.rawValue,
            "connection: " + connections,
            "apns: " + observations { $0.apnsChallenge },
            "recaptcha: " + observations { $0.recaptchaChallenge },
            "server_retry: " + observations { $0.serverErrorRetry },
            "dc_migration=" + (self.dcMigration ? "observed" : "not_observed")
        ].joined(separator: "\n")
    }
}

// This handle may be armed by the UI, but the collector is created only when
// sendAuthorizationCode is actually subscribed. Cancelling before subscription
// prevents a delayed push-configuration callback from starting observation.
public final class AuthorizationCodeDiagnostics {
    private let lock = NSLock()
    private var cancelled = false
    private var collector: AuthorizationDiagnosticCollector?
    private var cancellation: (() -> Void)?
    private var completedSnapshot: AuthorizationCodeDiagnosticSnapshot?

    public var snapshot: AuthorizationCodeDiagnosticSnapshot? {
        self.lock.lock()
        defer { self.lock.unlock() }
        return self.completedSnapshot
    }

    public init() {
    }

    func begin() -> AuthorizationDiagnosticCollector? {
        self.lock.lock()
        guard !self.cancelled else {
            self.lock.unlock()
            return nil
        }
        let previous = self.collector
        let cancellation = self.cancellation
        self.cancellation = nil
        self.completedSnapshot = nil
        let collector = AuthorizationDiagnosticCollector()
        self.collector = collector
        self.lock.unlock()
        _ = previous?.finish(.cancelled)
        cancellation?()
        return collector
    }

    func setCancellation(_ cancellation: @escaping () -> Void, collector: AuthorizationDiagnosticCollector) {
        self.lock.lock()
        let isCurrent = !self.cancelled && self.collector === collector
        if isCurrent { self.cancellation = cancellation }
        self.lock.unlock()
        if !isCurrent { cancellation() }
    }

    func complete(_ collector: AuthorizationDiagnosticCollector, outcome: AuthorizationDiagnosticOutcome) {
        guard let snapshot = collector.finish(outcome) else { return }
        self.lock.lock()
        let isCurrent = !self.cancelled && self.collector === collector
        let cancellation = self.collector === collector ? self.cancellation : nil
        if self.collector === collector {
            self.collector = nil
            self.cancellation = nil
            if isCurrent { self.completedSnapshot = snapshot }
        }
        self.lock.unlock()
        cancellation?()
    }

    public func cancel() {
        self.lock.lock()
        self.cancelled = true
        let collector = self.collector
        let cancellation = self.cancellation
        self.collector = nil
        self.cancellation = nil
        self.completedSnapshot = nil
        self.lock.unlock()
        _ = collector?.finish(.cancelled)
        cancellation?()
    }
}

final class AuthorizationDiagnosticCollector {
    struct RequestToken {
        fileprivate let generation: UInt64
        fileprivate let stage: AuthorizationDiagnosticStage
    }

    private struct StageState {
        var connections = Set<AuthorizationDiagnosticConnection>()
        var fullEventCoverage = true
        var apns = false
        var recaptcha = false
        var retry = false
    }

    private let lock = NSLock()
    private var active = true
    private var requestGeneration: UInt64 = 0
    private var networkGeneration: UInt64 = 0
    private var currentStage: AuthorizationDiagnosticStage = .sendCode
    private var currentConnection: AuthorizationDiagnosticConnection = .unobserved
    private var stageStates: [AuthorizationDiagnosticStage: StageState] = [:]
    private var migrated = false

    func beginNetworkObservation(migrated: Bool, stage: AuthorizationDiagnosticStage? = nil) -> UInt64 {
        self.lock.lock()
        defer { self.lock.unlock() }
        guard self.active else { return self.networkGeneration }
        self.networkGeneration &+= 1
        self.requestGeneration &+= 1
        if let stage = stage { self.currentStage = stage }
        self.currentConnection = .unobserved
        self.migrated = self.migrated || migrated
        return self.networkGeneration
    }

    func connection(_ connection: AuthorizationDiagnosticConnection, generation: UInt64) {
        self.lock.lock()
        defer { self.lock.unlock() }
        guard self.active, generation == self.networkGeneration else { return }
        self.currentConnection = connection
        if var state = self.stageStates[self.currentStage] {
            state.connections.insert(connection)
            self.stageStates[self.currentStage] = state
        }
    }

    func beginRequest(_ stage: AuthorizationDiagnosticStage, supported: Bool) -> RequestToken {
        self.lock.lock()
        defer { self.lock.unlock() }
        if self.active {
            self.requestGeneration &+= 1
            self.currentStage = stage
            var state = self.stageStates[stage] ?? StageState()
            state.fullEventCoverage = state.fullEventCoverage && supported
            if self.currentConnection != .unobserved {
                state.connections.insert(self.currentConnection)
            }
            self.stageStates[stage] = state
        }
        return RequestToken(generation: self.requestGeneration, stage: stage)
    }

    func event(_ event: AuthorizationDiagnosticEvent, token: RequestToken) {
        self.lock.lock()
        defer { self.lock.unlock() }
        guard self.active, token.generation == self.requestGeneration, var state = self.stageStates[token.stage] else { return }
        switch event {
        case .apnsChallenge: state.apns = true
        case .recaptchaChallenge: state.recaptcha = true
        case .serverErrorRetry: state.retry = true
        }
        self.stageStates[token.stage] = state
    }

    func finish(_ outcome: AuthorizationDiagnosticOutcome) -> AuthorizationCodeDiagnosticSnapshot? {
        self.lock.lock()
        defer { self.lock.unlock() }
        guard self.active else { return nil }
        self.active = false
        let stages = AuthorizationDiagnosticStage.allCases.compactMap { stage -> AuthorizationDiagnosticStageSnapshot? in
            guard let state = self.stageStates[stage] else { return nil }
            func observation(_ observed: Bool) -> AuthorizationDiagnosticObservation {
                return observed ? .observed : state.fullEventCoverage ? .notObserved : .unsupported
            }
            let connections = AuthorizationDiagnosticConnection.allCases.filter { state.connections.contains($0) }
            return AuthorizationDiagnosticStageSnapshot(stage: stage, connections: connections.isEmpty ? [.unobserved] : connections, apnsChallenge: observation(state.apns), recaptchaChallenge: observation(state.recaptcha), serverErrorRetry: observation(state.retry))
        }
        return AuthorizationCodeDiagnosticSnapshot(lastStage: self.currentStage, stages: stages, dcMigration: self.migrated, outcome: outcome)
    }
}
