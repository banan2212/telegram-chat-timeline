import Foundation

// Offline lifecycle and account-handoff checks: no account, QR token, or network.
@main
private enum AuthorizationQRLoginChecks {
    static func check(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() { fatalError(message) }
    }

    static func expiryAndStaleRendering() {
        var lifecycle = AuthorizationQRLoginLifecycle()
        check(!lifecycle.isActive, "Creating the UI must not begin login")
        let first = lifecycle.beginRequest()
        check(lifecycle.display(generation: first, validUntil: 130, now: 100), "Valid token rejected")
        check(lifecycle.canRender(generation: first, now: 129.9), "Valid QR not renderable")
        check(!lifecycle.canRender(generation: first, now: 130), "QR must disappear at exact expiry")
        let next = lifecycle.beginRequest()
        check(!lifecycle.canRender(generation: first, now: 110), "Old renderer survived token refresh")
        check(!lifecycle.display(generation: first, validUntil: 200, now: 110), "Old export replaced new request")
        check(!lifecycle.display(generation: next, validUntil: 110, now: 110), "Expired export was displayed")
        check(lifecycle.display(generation: next, validUntil: 140, now: 110), "Current export rejected")
    }

    static func cancellationBackgroundAndRetry() {
        var lifecycle = AuthorizationQRLoginLifecycle()
        let first = lifecycle.beginRequest()
        lifecycle.invalidate(.inactive)
        check(!lifecycle.accepts(first), "Cancelled export result accepted")
        check(!lifecycle.finish(generation: first), "Cancelled callback completed login UI")
        let retry = lifecycle.beginRequest()
        check(lifecycle.display(generation: retry, validUntil: 150, now: 100), "Explicit retry failed")
        lifecycle.invalidate(.suspended)
        check(!lifecycle.isActive, "Background must stop auth refreshes")
        check(!lifecycle.canRender(generation: retry, now: 110), "Background left a QR renderable")
        check(!lifecycle.display(generation: retry, validUntil: 180, now: 110), "Late background render resurrected code")
        let resumed = lifecycle.beginRequest()
        check(lifecycle.finish(generation: resumed), "Explicit foreground retry could not finish")
        check(!lifecycle.finish(generation: resumed), "Completion was delivered twice")
        check(!lifecycle.accepts(retry), "Prior session survived completion")
    }

    static func migratedPasswordHandoffAndCancelRace() {
        var gate = AuthorizationQRLoginHandoffGate()
        gate.beginSession()
        gate.observe(.password(masterDatacenterId: 4))
        let first = gate.revision
        check(!gate.canApply(revision: first, accountMasterDatacenterId: 2), "Password UI opened against pre-migration account")
        // Cancelling requests invalidates reconciliation, but must preserve a
        // password state already committed by the official Core flow.
        gate.invalidateReconciliation()
        check(gate.destination == .password(masterDatacenterId: 4), "Cancel discarded committed password state")
        check(!gate.consume(revision: first, accountMasterDatacenterId: 4), "Cancelled reconciliation was applied")
        let recovered = gate.revision
        check(gate.consume(revision: recovered, accountMasterDatacenterId: 4), "Authoritative DC recovery could not hand off password")
        check(!gate.consume(revision: recovered, accountMasterDatacenterId: 4), "Password handoff occurred twice")
        check(gate.destination == nil, "Completed handoff remained pending")
    }

    static func newerStateWinsOverLateReconciliation() {
        var gate = AuthorizationQRLoginHandoffGate()
        gate.beginSession()
        gate.observe(.password(masterDatacenterId: 4))
        let passwordRevision = gate.revision
        gate.observe(.authorized)
        check(!gate.consume(revision: passwordRevision, accountMasterDatacenterId: 4), "Old reconciliation replaced authorized state")
        check(gate.consume(revision: gate.revision, accountMasterDatacenterId: 2), "Already-authorized state was lost")
        gate.beginSession()
        gate.observe(.password(masterDatacenterId: 5))
        let nextPassword = gate.revision
        gate.invalidateReconciliation() // UpdatedAccount callback won the race.
        check(!gate.consume(revision: nextPassword, accountMasterDatacenterId: 5), "Stale DC reconstruction replaced returned account")
        check(gate.consume(revision: gate.revision, accountMasterDatacenterId: 5), "Migrated account could not release 2FA")
        gate.beginSession()
        gate.observe(.password(masterDatacenterId: 4))
        let replaced = gate.revision
        gate.discardPendingState()
        check(!gate.consume(revision: replaced, accountMasterDatacenterId: 4), "New phone-entry state resurrected old password UI")
        check(gate.destination == nil, "Nonterminal state retained old handoff")
    }

    static func ordinaryAuthOwnsItsCompletion() {
        var gate = AuthorizationQRLoginHandoffGate()
        check(!gate.observe(.authorized), "Normal launch must not use QR account completion")
        gate.beginSession()
        gate.observe(.password(masterDatacenterId: 4))
        check(gate.consume(revision: gate.revision, accountMasterDatacenterId: 4), "QR password handoff failed")
        check(!gate.ownsAuthorization, "QR retained ownership after releasing password UI")
        check(!gate.observe(.authorized), "QR recovery raced ordinary password completion")
        gate.beginSession()
        gate.observe(.authorized)
        let oldRevision = gate.revision
        gate.releaseOwnership() // Explicit phone/passkey login after QR Cancel.
        check(!gate.observe(.authorized), "QR recovery raced explicit phone/passkey completion")
        check(!gate.consume(revision: oldRevision, accountMasterDatacenterId: 4), "Old QR reconciliation survived normal login")
        check(gate.destination == nil, "Normal login retained a QR handoff")
    }

    static func main() {
        self.expiryAndStaleRendering()
        self.cancellationBackgroundAndRetry()
        self.migratedPasswordHandoffAndCancelRace()
        self.newerStateWinsOverLateReconciliation()
        self.ordinaryAuthOwnsItsCompletion()
        print("Authorization QR login lifecycle and handoff checks passed")
    }
}
