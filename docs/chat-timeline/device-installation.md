# Physical iPhone installation from Windows

Research checked 2026-10-30 against source revision `774a31de368e01552f9e6478e8f086dc7c30357b`. Target: a separate test installation on iPhone 15 / iOS 26.

**Current artifact status:** full [device](https://github.com/banan2212/telegram-chat-timeline/actions/runs/40977552237) and [simulator](https://github.com/banan2212/telegram-chat-timeline/actions/runs/40977729961) builds passed for native source `67cdc26e9e9cd4408f1d966a749352e4bbfdd0d6`. The device IPA uses the public signing fixture and a testing-only sample API configuration. It is not installable as-is.

As of 2026-11-01, the inspected fixture profiles have expired (2026-10-30 17:06:30 UTC). This does not invalidate the recorded compilation result, but any device installation needs fresh legitimate personal profiles and re-signing. Do not bypass profile-expiration checks or treat a refreshed public fixture as Apple-authorized provisioning.

The actual device bundle ID is `ph.telegra.Telegraph`, which collides with the primary Telegram installation. A separate final application identity, compatible extension/App Group and keychain identities, and legitimate personal signing are mandatory. Static inspection still fails for five extensions with `Wildcard not permitted in signed entitlement group keychain-access-groups (values omitted)`; their XML parses, so this is a semantic entitlement failure, not XML corruption. No IPA or profile was modified to bypass it.

The [controlled simulator startup check](https://github.com/banan2212/telegram-chat-timeline/actions/runs/40987169198) passed on iPhone 15 / iOS 27.0: both screenshot commands exited successfully, the app process passed checks before and after both captures, and observation lasted 47.44 seconds. Both real PNGs were reviewed and show Telegram's welcome screen; the upper illustration area is blank. No matching crash report was found. This does not verify login, Chat Timeline or physical iPhone behavior. The Windows signing workflow below remains unverified for this candidate; personal signing, installation, launch, login and device acceptance are still required. See [acceptance.md](acceptance.md).

## What the free route allows

Apple Personal Team provisioning permits 10 App IDs, 3 devices, and 3 apps per device; the relevant registrations/profiles expire after 7 days. Apple's supported-capabilities table currently includes App Groups and Keychain sharing for the free Apple Developer tier. Therefore App Groups are not automatically a paid-membership blocker. This does not establish that a particular Windows signer will provision and preserve Telegram's groups correctly. [Apple account overview](https://developer.apple.com/help/account/basics/about-your-developer-account), [supported capabilities](https://developer.apple.com/help/account/reference/supported-capabilities-ios/).

Sideloadly offers free Windows sideloading. Its current FAQ includes iOS 26 in its support claim, but this is not evidence that this Telegram build works. Its custom-entitlements feature is explicitly restricted to Apple Developer Program members and Patreon supporters; it is not a free fallback. Current release notes also say free-account Watch app support is still pending. Keep Watch out of this test package. [Sideloadly](https://sideloadly.io/), [FAQ](https://sideloadly.io/faq.html), [official changelog](https://sideloadly.io/changelog).

## Telegram-specific signing requirements

The following conclusions come from the pinned source, not from an attempted installation:

| Component | Requirement and evidence |
| --- | --- |
| Separate identity | Use a stable test bundle ID distinct from the App Store app. The final ID after signing matters; do not assume the fixture ID or the original IPA ID survives. |
| Shared data container | `Telegram/BUILD:550–560` generates `group.<bundleID>`. At launch, `AppDelegate.swift:571–576` derives this name from the actual main bundle ID. At `699–702`, a missing container stops normal startup with `Error 2`. Removing App Groups is not a valid generic fix. |
| Keychain | `BuildConfig.m:228–234` derives private access from the signing seed/prefix plus bundle ID. `Passcode.swift:72–100,119–127` uses both the app group and the private group. Main-app-only packaging still needs these identities. |
| Extensions | `Telegram/BUILD:1943–1954` lists **six** iOS extensions: Share, NotificationContent, NotificationService, Intents, Widget, BroadcastUpload. Watch embedding is separately opt-in (`1955–1961`). Confirm the actual inventory in the built IPA. |
| CI package | The workflow builds `release_arm64` with public fixture signing and does not request Watch embedding. The collector labels the file `self-signed-requires-resigning`, records its hash/platform/ID, and explicitly records `device_installable_directly: false` and `device_tested: false`. |

Source paths: [build rules](../../Telegram/BUILD), [startup](../../submodules/TelegramUI/Sources/AppDelegate.swift), [BuildConfig](../../submodules/BuildConfig/Sources/BuildConfig.m), [PasscodeCore](../../submodules/PasscodeCore/Sources/Passcode.swift), [workflow](../../.github/workflows/chat-timeline.yml), [collector](../../ci/chat-timeline/bootstrap.py).

For a final bundle ID `B`, the signed main app and its Apple-issued profile must authorize `group.B`; its application identifier and private keychain access must belong to the actual signing account. Retained extensions need their own valid IDs/profiles and compatible shared-group access. The signing account's prefix replaces the fixture prefix. App groups can themselves provide keychain access; an extra arbitrary keychain entitlement is not a universal solution. Compare the signed entitlements with the profile permissions rather than copying old values. [Apple App Groups](https://developer.apple.com/documentation/xcode/configuring-app-groups), [keychain access groups](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps), [entitlement diagnostics](https://developer.apple.com/documentation/bundleresources/diagnosing-issues-with-entitlements).

Each retained extension consumes another App ID. Six extensions plus the app normally require seven. Frameworks are not separate application IDs. Existing unexpired registrations also consume the allowance, so repeatedly changing IDs can exhaust the week’s quota. [AltStore App IDs](https://faq.altstore.io/altstore-classic/app-ids).

## Candidate workflow

1. **Prepare and inspect the artifact first.** Require a successful exact-revision device build, its manifest, and matching SHA-256. Verify iPhoneOS platform, arm64 executable, minimum OS compatible with the phone's exact iOS version, and every nested app/extension. The current collector checks the platform and executable presence; it is not a complete Mach-O or signing audit. A simulator archive cannot be substituted.
2. **Choose one separate test identity.** Record the final bundle ID, display name, signing-account choice, and retained extensions. Preserve the original candidate. Never target `ph.telegra.Telegraph`, overwrite the primary Telegram, or reuse its data/keychain group. A fresh test installation needs its own Telegram login; copying the main app's credentials is not part of this process.
3. **Set up Windows locally.** Download Sideloadly only from its official site and follow its current Windows dependency instructions, including the linked Apple web versions of iTunes/iCloud when required. Connect the unlocked phone by USB and accept Trust This Computer. Apple account credentials and two-factor codes are entered by the user locally, never in chat, repository, or CI. [Official setup and troubleshooting](https://sideloadly.io/faq.html).
4. **Make one controlled signing attempt.** Select the inspected device IPA and phone, use the chosen separate bundle identity, and retain the resulting ID consistently. Verify the available App ID allowance before starting. Do not enable injections or assume deleting entitlements will fix failures. Starting is an installation attempt, not a harmless signing preview: the official v0.70.1 release notes say signing/repacking and streaming to the phone can overlap. Do not plan to press Start and interrupt before installation to inspect the signed output. The documented Export mode produces a modified IPA; export after Apple-account provisioning/signing without installation is not confirmed. Normal Install and Ad-hoc are not substitutes for legitimate personal provisioning. Record the exact non-sensitive error if provisioning, signing, or installation fails; stop to diagnose the relevant gate. [Official changelog](https://sideloadly.io/changelog).
5. **Trust and launch.** Trust the developer profile under Settings → General → VPN & Device Management if requested. Enable Developer Mode under Privacy & Security, restart, and confirm after restart. If the setting is absent, use the official pairing/installation troubleshooting flow; do not invent a bypass. [Sideloadly FAQ](https://sideloadly.io/faq.html), [Apple Developer Mode](https://developer.apple.com/documentation/xcode/enabling-developer-mode-on-a-device).
6. **Validate persistence before the demo.** Confirm the separate app launches, completes a legitimate Telegram login, survives force-close/relaunch, and retains its session. Then run the physical-device acceptance checks below. Installation success alone is insufficient.

Sideloadly refresh uses the same Apple account and final bundle ID; changing either can create a different installation. Renew within seven days. Its optional refresh daemon needs the computer and USB or configured Wi-Fi connectivity. A refresh is not a backup guarantee. [Sideloadly renewal guidance](https://sideloadly.io/faq.html).

## Unknowns and free fallback choices

- **Provisioning remains the first hard unknown.** We have not verified that free Sideloadly creates a usable `group.B` and compatible keychain permissions for this IPA, or how it rewrites every retained extension. Apple's capability availability alone does not prove that workflow. Do not buy custom entitlements to paper over an unexplained failure.
- **A main-app-only candidate can reduce App ID and extension constraints.** The build rules have a `//Telegram:disableExtensions` switch; Watch should remain disabled. Preparing this variant requires an explicit build change and a fresh artifact audit. It is not prepared by this document and still requires the main app's group/keychain access. The existing project-generation `--disableExtensions` option must not be assumed to be an accepted `Make.py build` option.
- **AltStore Classic is a second free Windows route.** Follow its official Windows installation guide, then import the candidate. AltStore itself occupies an app slot and consumes App IDs; inspect the remaining allowance and any extension-removal prompt. It does not remove the Telegram identity/group requirements. [Windows guide](https://faq.altstore.io/altstore-classic/how-to-install-altstore-windows), [refresh and app limits](https://faq.altstore.io/altstore-classic/your-altstore).
- **An already available borrowed Mac is another no-purchase option.** Xcode Personal Team signing exposes capabilities/profile configuration directly. It still needs the phone and account owner, matching groups, and successful builds; cloud CI is not a USB-connected substitute. A simulator can support debugging, but cannot close the iPhone gate. [Apple Personal Team](https://developer.apple.com/help/account/basics/about-your-developer-account).
- **Telegram access and runtime are independent unknowns.** A sample API configuration is for testing and may have server limits; successful signing does not guarantee login, notifications, extensions, or iOS 26 compatibility. An account rate limit should be allowed to expire rather than retried repeatedly. This guide does not promise production distribution or unrestricted Telegram service behavior.

## Minimum morning actions for the device owner

After a candidate passes artifact inspection:

1. Have the unlocked iPhone, USB cable, Windows computer, and your own Apple account/2FA available. Keep the primary Telegram installed.
2. Complete local signer authentication, Trust This Computer, developer-profile trust, and Developer Mode confirmations yourself.
3. Open the separate app and complete Telegram login only if requested. Report the exact launch/login error if it fails; avoid retry loops.
4. In a test chat with known older messages, record: scrub without history movement → actual preview date → Cancel; then preview → Jump → Return to the original reading position. Also test a media album return and a slow/failed preview request.
5. Cold-launch again; verify session persistence. Capture light/dark mode and larger text/Reduce Motion checks under [acceptance.md](acceptance.md). Use safe test conversations in recordings.

Required evidence: artifact revision/hash, final test bundle ID, iOS version, signer/version, launch and persistence result, and an actual device recording. Keep Apple account details, device identifiers, provisioning profiles, and authentication logs out of public evidence. No screenshot mockup or browser prototype closes this gate.

## Audit scope

Only the listed source/configuration logic and official public documentation were inspected. No Apple account, credential store, private signing material, or authentication configuration was accessed; no installer was run. Code graph coverage was requested for the cited paths, but this checkout is not indexed, so source evidence used bounded direct reads. This document makes no installation or runtime success claim.
