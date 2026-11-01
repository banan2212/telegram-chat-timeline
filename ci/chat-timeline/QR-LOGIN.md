# Opt-in QR login for the test application

This interface exposes Telegram Core's [official QR-login protocol](https://core.telegram.org/api/qr-login) in the separate Chat Timeline test app. The owner approves the temporary code in an already signed-in Telegram client. Server authorization, data-center migration and the normal two-step-password flow remain enforced. Successful login with the public upstream test API configuration has not been demonstrated.

## Reproduce the build

Initial QR implementation: [`5db23d16da7fb15154ffb49b45be55e2b2f0e6f4`](https://github.com/banan2212/telegram-chat-timeline/commit/5db23d16da7fb15154ffb49b45be55e2b2f0e6f4). Presentation fix [`30d4e0bf6bb1bab16a5ed10245b59efb5f9d6a47`](https://github.com/banan2212/telegram-chat-timeline/commit/30d4e0bf6bb1bab16a5ed10245b59efb5f9d6a47) replaces two invalid NavigationController calls with root WindowHost presentation, explicit presentationArguments and missing-window guards. Commit966c6e24 only changed workflow API-secret gating. The upstream pin remains in [README.md](README.md).

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

Snapshot: 2026-11-01 after the presentation fix. Linked runs may have later updates. The earlier00:10MSK readiness estimate has been withdrawn.

| Check | Evidence and boundary |
| --- | --- |
| Swift syntax and Foundation checks | Initial [41342512328](https://github.com/banan2212/telegram-chat-timeline/actions/runs/41342512328) and corrected-source [41347494113](https://github.com/banan2212/telegram-chat-timeline/actions/runs/41347494113) passed. Lifecycle tests cover expiry, stale results, cancellation/background, migrated-password handoff and release to ordinary authentication. They do not typecheck UIKit or execute the server protocol; the first full build exposed a presentation type mismatch that these checks and the earlier source review missed. |
| Full simulator build | [41343133592](https://github.com/banan2212/telegram-chat-timeline/actions/runs/41343133592), source966c6e24, failed at20:24:31UTC on the two incompatible presentation calls. [41347496635](https://github.com/banan2212/telegram-chat-timeline/actions/runs/41347496635), source30d4e0bf6bb1bab16a5ed10245b59efb5f9d6a47, is compiling the fix at this checkpoint. QR modules are included with the UI flag off; no successful full build is claimed yet. |
| Owner QR device build | [41343667365](https://github.com/banan2212/telegram-chat-timeline/actions/runs/41343667365), source966c6e24, passed native profile/build preflight at19:50:16UTC, then was deliberately cancelled because the same unconditional code error was present. Terminal CANCELLED at20:31:55UTC; compilation incomplete. Cleanup step8 FAILED (`stage=remove_tree reason=changed`), so runner-file/profile deletion is unproven. The temporary secret was deleted and absence verified. No new owner build or profile transfer has occurred; new consent has not been requested while cleanup is investigated. |
| Real QR login and Timeline acceptance | Not verified on iPhone 15 / iOS 26. Installation, successful authentication, preview/cancel, Jump/Return and real demo recording require separate evidence. |

QR completion uses a guarded local AccountManager transition after Core has already committed authorization. Two concurrency boundaries remain: process death between the Postbox and AccountManager commits, and a queued Postbox commit racing an immediate different authentication flow after Cancel. The implementation does not make those two stores crash-atomic or claim to eliminate every authentication race.
