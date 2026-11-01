import Foundation

// Standalone, offline checks. No Telegram account, device, network or credentials.
@main
private enum AuthorizationDiagnosticsChecks {
    static func check(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() { fatalError(message) }
    }

    static func stage(_ snapshot: AuthorizationCodeDiagnosticSnapshot, _ stage: AuthorizationDiagnosticStage) -> AuthorizationDiagnosticStageSnapshot {
        guard let value = snapshot.stages.first(where: { $0.stage == stage }) else {
            fatalError("Missing diagnostic stage")
        }
        return value
    }

    static func requestAttributionAndMigration() {
        let collector = AuthorizationDiagnosticCollector()
        let originalNetwork = collector.beginNetworkObservation(migrated: false, stage: .sendCode)
        collector.connection(.online, generation: originalNetwork)
        let original = collector.beginRequest(.sendCode, supported: true)
        collector.event(.apnsChallenge, token: original)

        let migratedNetwork = collector.beginNetworkObservation(migrated: true, stage: .migratedSendCode)
        // An old engine callback must not contaminate either the new request or network.
        collector.connection(.waitingForNetwork, generation: originalNetwork)
        collector.event(.serverErrorRetry, token: original)
        collector.connection(.connecting, generation: migratedNetwork)
        let migrated = collector.beginRequest(.migratedSendCode, supported: true)
        collector.event(.recaptchaChallenge, token: migrated)
        collector.connection(.online, generation: migratedNetwork)

        let password = collector.beginRequest(.passwordFetch, supported: true)
        collector.event(.apnsChallenge, token: migrated)
        collector.event(.serverErrorRetry, token: password)
        let snapshot = collector.finish(.timeout)!
        check(snapshot.dcMigration, "Migration must be observable without a DC identifier")
        check(snapshot.lastStage == .passwordFetch, "Timeout must identify the current auth stage")
        check(stage(snapshot, .sendCode).connections == [.online], "Old connection events must not mutate prior stages")
        check(stage(snapshot, .sendCode).apnsChallenge == .observed, "Original request challenge lost")
        check(stage(snapshot, .sendCode).serverErrorRetry == .notObserved, "Late pre-migration event accepted")
        check(stage(snapshot, .migratedSendCode).connections == [.connecting, .online], "Migration must reset and observe the new account network")
        check(stage(snapshot, .migratedSendCode).recaptchaChallenge == .observed, "Migrated challenge missing")
        check(stage(snapshot, .migratedSendCode).apnsChallenge == .notObserved, "Late request callback crossed a stage boundary")
        check(stage(snapshot, .passwordFetch).serverErrorRetry == .observed, "Password retry attributed to wrong request")
        collector.event(.apnsChallenge, token: password)
        collector.connection(.waitingForNetwork, generation: migratedNetwork)
        check(collector.finish(.serverError) == nil, "A finished attempt must not report twice")
        check(stage(snapshot, .passwordFetch).apnsChallenge == .notObserved, "Snapshot changed after completion")
    }

    static func unobservedAndUnsupported() {
        let collector = AuthorizationDiagnosticCollector()
        _ = collector.beginNetworkObservation(migrated: false)
        _ = collector.beginRequest(.sendCode, supported: false)
        let supported = collector.beginRequest(.sendCode, supported: true)
        collector.event(.recaptchaChallenge, token: supported)
        let snapshot = collector.finish(.serverError)!
        let send = stage(snapshot, .sendCode)
        check(send.connections == [.unobserved], "Missing connection evidence must remain explicit")
        check(send.apnsChallenge == .unsupported, "Unsupported engine must not imply no challenge")
        check(send.serverErrorRetry == .unsupported, "Mixed engine coverage must remain conservative")
        check(send.recaptchaChallenge == .observed, "Positive evidence should survive partial coverage")
        check(snapshot.summary.contains("apns: send_code=unsupported"), "Visible report hides unsupported observation")
        let unsupportedOnly = AuthorizationDiagnosticCollector()
        _ = unsupportedOnly.beginRequest(.sendCode, supported: false)
        let unsupportedSummary = unsupportedOnly.finish(.timeout)!.summary
        check(unsupportedSummary.contains("apns: send_code=unsupported"), "Rust-only summary must state unsupported")
        check(!unsupportedSummary.contains("apns: send_code=not_observed"), "Rust-only summary must not imply absence of a challenge")
    }

    static func cancellationAndReplacement() {
        var cancellations = 0
        let owner = AuthorizationCodeDiagnostics()
        let original = owner.begin()!
        let originalRequest = original.beginRequest(.sendCode, supported: true)
        owner.setCancellation({ cancellations += 1 }, collector: original)
        let replacement = owner.begin()!
        check(cancellations == 1, "New subscription must stop prior connection observation")
        original.event(.apnsChallenge, token: originalRequest)
        owner.complete(original, outcome: .timeout)
        check(owner.snapshot == nil, "Replaced subscription retained a late result")
        owner.setCancellation({ cancellations += 1 }, collector: replacement)
        _ = replacement.beginRequest(.sendCode, supported: true)
        owner.cancel()
        owner.cancel()
        owner.complete(replacement, outcome: .timeout)
        check(cancellations == 2, "Cancellation cleanup must be idempotent")
        check(owner.snapshot == nil, "Cancelled attempt retained data")
        check(owner.begin() == nil, "Delayed subscription revived a cancelled handle")
        owner.setCancellation({ cancellations += 1 }, collector: replacement)
        check(cancellations == 3, "Late observation registration must dispose immediately")
    }

    static func completionAndDisposal() {
        var cancellations = 0
        let owner = AuthorizationCodeDiagnostics()
        let collector = owner.begin()!
        owner.setCancellation({ cancellations += 1 }, collector: collector)
        _ = collector.beginRequest(.sendCode, supported: true)
        owner.complete(collector, outcome: .codeSent)
        owner.complete(collector, outcome: .cancelled)
        check(owner.snapshot?.outcome == .codeSent, "Dispose must not erase a completed result before UI reads it")
        check(cancellations == 1, "Completion must stop connection observation exactly once")
        owner.cancel()
        check(owner.snapshot == nil, "UI release must erase the in-memory report")

        let reentrant = AuthorizationCodeDiagnostics()
        let nested = reentrant.begin()!
        reentrant.setCancellation({ reentrant.cancel() }, collector: nested)
        _ = nested.beginRequest(.sendCode, supported: true)
        reentrant.complete(nested, outcome: .loggedIn)
        check(reentrant.snapshot == nil, "Observation cleanup must be safely reentrant")
    }

    static func boundedClosedVocabulary() {
        let collector = AuthorizationDiagnosticCollector()
        let generation = collector.beginNetworkObservation(migrated: false)
        for stage in AuthorizationDiagnosticStage.allCases {
            for _ in 0 ..< 250 {
                let request = collector.beginRequest(stage, supported: true)
                for connection in AuthorizationDiagnosticConnection.allCases where connection != .unobserved {
                    collector.connection(connection, generation: generation)
                }
                collector.event(.apnsChallenge, token: request)
                collector.event(.recaptchaChallenge, token: request)
                collector.event(.serverErrorRetry, token: request)
            }
        }
        let snapshot = collector.finish(.timeout)!
        check(snapshot.stages.count == 4, "Repeated events must not grow report state")
        check(snapshot.stages.allSatisfy { $0.connections.count == 4 }, "Connection evidence must be deduplicated")
        let allowed = Set([
            "outcome", "timeout", "stage", "connection", "apns", "recaptcha", "server_retry", "dc_migration",
            "send_code", "migrated_send_code", "password_fetch", "firebase_fallback",
            "waiting_for_network", "connecting", "updating", "online", "observed", "not_observed", "unsupported", "unobserved"
        ])
        let words = snapshot.summary.components(separatedBy: CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz_").inverted).filter { !$0.isEmpty }
        check(words.allSatisfy { allowed.contains($0) }, "Summary includes data outside fixed vocabulary")
        check(snapshot.summary.utf8.count < 1400, "Report must remain bounded after repeated requests")
        check(snapshot.summary.split(separator: "\n").count == 7, "Report must stay compact")
    }

    static func concurrentCompletion() {
        let collector = AuthorizationDiagnosticCollector()
        let generation = collector.beginNetworkObservation(migrated: false)
        let request = collector.beginRequest(.sendCode, supported: true)
        let queue = DispatchQueue(label: "authorization-diagnostics-check", attributes: .concurrent)
        let group = DispatchGroup()
        let completionLock = NSLock()
        // Reference storage avoids captured mutable value races in the test itself.
        final class Results: @unchecked Sendable { var count = 0 }
        let results = Results()
        for _ in 0 ..< 100 {
            group.enter()
            queue.async {
                collector.event(.apnsChallenge, token: request)
                collector.connection(.connecting, generation: generation)
                if collector.finish(.timeout) != nil {
                    completionLock.lock()
                    results.count += 1
                    completionLock.unlock()
                }
                group.leave()
            }
        }
        check(group.wait(timeout: .now() + 5) == .success, "Concurrent diagnostic callbacks deadlocked")
        check(results.count == 1, "Concurrent completion must produce exactly one snapshot")

        var cancelledOwners: [AuthorizationCodeDiagnostics] = []
        for _ in 0 ..< 100 {
            let owner = AuthorizationCodeDiagnostics()
            let attempt = owner.begin()!
            _ = attempt.beginRequest(.sendCode, supported: true)
            cancelledOwners.append(owner)
            group.enter()
            queue.async {
                owner.complete(attempt, outcome: .timeout)
                group.leave()
            }
            group.enter()
            queue.async {
                owner.cancel()
                group.leave()
            }
        }
        check(group.wait(timeout: .now() + 5) == .success, "Concurrent cancellation deadlocked")
        check(cancelledOwners.allSatisfy { $0.snapshot == nil && $0.begin() == nil }, "Completion race revived a cancelled attempt")
    }

    static func main() {
        requestAttributionAndMigration()
        unobservedAndUnsupported()
        cancellationAndReplacement()
        completionAndDisposal()
        boundedClosedVocabulary()
        concurrentCompletion()
        print("Authorization diagnostics checks passed")
    }
}
