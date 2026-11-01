# Opt-in QR login for the test application

This interface exposes Telegram Core's [official QR-login protocol](https://core.telegram.org/api/qr-login) in the separate Chat Timeline test app. The owner approves the temporary code in an already signed-in Telegram client. Server authorization, data-center migration and the normal two-step-password flow remain enforced. Successful login with the public upstream test API configuration has not been demonstrated.

## Reproduce the build

Native QR implementation: [`5db23d16da7fb15154ffb49b45be55e2b2f0e6f4`](https://github.com/banan2212/telegram-chat-timeline/commit/5db23d16da7fb15154ffb49b45be55e2b2f0e6f4). Commit `966c6e2498149b084295ec9631892d2bfaa36a66` changes only the general workflow's API-secret environment gating. Both retain the upstream pin documented in [README.md](README.md).

Run the focused checks and full simulator build from the published feature branch. Record each dispatched SHA independently and compare it with the artifact manifest:

```sh
gh workflow run chat-timeline-checks.yml --repo banan2212/telegram-chat-timeline --ref feature/chat-timeline
gh workflow run chat-timeline.yml --repo banan2212/telegram-chat-timeline --ref feature/chat-timeline -f operation=feature -f target=simulator -f api_source=upstream-test
```

The simulator route requires no owner profile or Apple ID. It compiles the QR Swift files into `AuthorizationUI`, but does **not** enable the QR button. The main app reads this exact Boolean from `Info.plist`; an absent or false value leaves the interface off:

```xml
<key>ChatTimelineQRLoginEnabled</key>
<true/>
```

For an owner-approved device build, follow [OWNER-BUILD.md](OWNER-BUILD.md). `owner_signing_input.py` writes the flag before ad-hoc sealing and records `qr_login_enabled: true` in the private manifest. The resulting package remains a non-installable signing input until the owner signs it through the separate installation process. Do not patch an already signed application or treat this flag as authorization to transfer a profile. Public sample API configuration remains limited to explicit testing.

## Owner interaction

1. Open the initial phone-entry screen and select **QR**. It is unavailable in the change-phone-number flow.
2. Scan and approve the temporary code with an already signed-in Telegram client. If both apps are on one phone, display the code on a second screen under the owner's control.
3. Return to Chat Timeline. After switching away from the app, select **Continue** to check approval or obtain a fresh code. Enter a two-step-verification password only in the app when Telegram requests it.

While the QR screen is active, the displayed code refreshes at its server-provided expiration. Backgrounding pauses export, update events, expiry timers and rendering, and clears the visible image. Foregrounding alone does not request another code. **Cancel** closes the screen and stops its work; it does not revoke a token already issued by the server or a session the owner has already approved. A local completion error offers Retry; after closing that error, the QR button can reopen the local completion attempt without exporting a fresh token.

The QR UI keeps its display token in memory and does not log, persist or expose it as an accessibility value. Never attach a QR image, token URI, password or login code to issues, reviewer messages or public CI artifacts.

## Evidence and remaining limits

Snapshot: 2026-11-01. Linked runs may have later updates.

| Check | Evidence and boundary |
| --- | --- |
| Swift syntax and Foundation checks | [41342512328](https://github.com/banan2212/telegram-chat-timeline/actions/runs/41342512328) passed on the native QR commit. Lifecycle tests cover expiry, stale results, cancellation/background, migrated-password handoff and release to ordinary authentication. They do not typecheck UIKit or execute the server protocol. |
| Full simulator build | [41343133592](https://github.com/banan2212/telegram-chat-timeline/actions/runs/41343133592), source `966c6e2498149b084295ec9631892d2bfaa36a66`, is compiling at this checkpoint. The build includes the QR modules with the UI flag off; no successful result is claimed yet. |
| Owner QR device build | The owner approved one new build. [41343667365](https://github.com/banan2212/telegram-chat-timeline/actions/runs/41343667365), source `966c6e2498149b084295ec9631892d2bfaa36a66`, is preparing dependencies at this checkpoint; profile values remain private. No successful result is claimed yet. The older owner build predates QR and had an overall cleanup failure, despite completing compilation and packaging. |
| Real QR login and Timeline acceptance | Not verified on iPhone 15 / iOS 26. Installation, successful authentication, preview/cancel, Jump/Return and real demo recording require separate evidence. |

QR completion uses a guarded local AccountManager transition after Core has already committed authorization. Two concurrency boundaries remain: process death between the Postbox and AccountManager commits, and a queued Postbox commit racing an immediate different authentication flow after Cancel. The implementation does not make those two stores crash-atomic or claim to eliminate every authentication race.
