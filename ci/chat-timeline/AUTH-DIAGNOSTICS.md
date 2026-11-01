# Opt-in authorization diagnostics

An owner-installed Chat Timeline build reaches the phone-number screen but reports the existing network error after requesting a code. The current source maps this error to the authorization timeout. The underlying cause is not established.

Normal builds keep diagnostics off. A dedicated signing input must explicitly contain the Boolean `ChatTimelineAuthDiagnosticsEnabled = true` in the main application's Info.plist. This arms observation of the first owner-initiated attempt; it does not initiate a login request. After a timeout, **Diagnose next attempt** only rearms observation. The owner must initiate any next attempt separately.

The in-memory report contains closed enum values only: request stage, observed connection states, APNs/reCAPTCHA challenge observations, server retry observation, whether a datacenter migration occurred, and the final outcome. It contains no phone number, account/datacenter identifiers, addresses, API values, error descriptions, challenge data, codes or tokens. There is no file logging, clipboard copy, export or transmission. Cancellation, a new attempt, leaving authorization, or controller destruction clears the diagnostic session. Unsupported request hooks must remain distinguishable from an observation that did not occur.

The transport hooks apply to fixed MtProtoKit networks. Rust and live-switching networks report unsupported coverage. Existing authorization requests, options, timeouts, challenge handling and retry decisions are preserved. Migration changes the observed network to the network actually used by the migrated request.

The focused-checks workflow compiles and runs the Foundation collector tests and parses the changed Swift integration files. A full Telegram build is still required to check module integration and Objective-C enum import. Neither test layer establishes the cause of the owner's login error; that requires a diagnostic result from a signed build on the iPhone. Normal Timeline acceptance remains separate.

The original public fixture profiles expired on 2026-10-30. The existing device preflight remains enforced. A passing simulator build cannot be repackaged as an iPhone build. Do not weaken that guard or represent the earlier IPA as containing this instrumentation.
