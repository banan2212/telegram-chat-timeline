# Chat Timeline build preparation

This manual workflow builds either the pinned upstream baseline or **the dispatched commit of this repository**. A passing probe does not mean compilation succeeded. Compilation does not mean the feature works on an iPhone.

## Run

In Actions, open **Chat Timeline - build and probe**. Use only this workflow, not the inherited upstream release workflow.

1. Run `operation=probe`, `target=simulator`, `api_source=upstream-test`. Read the summary and diagnostic JSON: the probe intentionally finishes successfully even when it reports blockers, so the evidence remains available.
2. Run `operation=baseline`, `target=simulator` to compile upstream commit `fb0e62ba8a147f0821da6aa63c09da7d79a10111`.
3. Run `operation=feature`, `target=simulator` on the feature branch to compile **that exact workflow commit**, including Chat Timeline. The manifest records both source and workflow revisions.
4. Select `target=device` separately to attempt `release_arm64` with the pinned public fixture. It produces a self-signed IPA **requiring re-signing**, not a directly installable iPhone app.

CLI example (after this workflow is present on the default branch):

```sh
gh workflow run chat-timeline.yml --repo banan2212/telegram-chat-timeline --ref main -f operation=probe -f target=simulator -f api_source=upstream-test
gh workflow run chat-timeline.yml --repo banan2212/telegram-chat-timeline --ref main -f operation=baseline -f target=simulator -f api_source=upstream-test
# Replace the ref with the published feature branch or its commit.
gh workflow run chat-timeline.yml --repo banan2212/telegram-chat-timeline --ref feature/chat-timeline -f operation=feature -f target=simulator -f api_source=upstream-test
```

Only the standard `xcode-27` runner is used, and the job refuses private repositories. GitHub lists this ARM64 runner as free for public repositories, with 7 GB RAM and 14 GB SSD. No large/xlarge/paid fallback is configured. The job is bounded to 350 minutes; compilation gets 285 minutes after preparation. A full Telegram build may exceed memory, disk or time even with two Bazel jobs. Resource thresholds (6 GiB RAM, 8 GiB free disk) are minimal guards chosen here, not official Telegram requirements or proof of sufficient resources. Every run records actual resources and installed SDKs.

### Focused checks before the full build

The separate manual workflow **Chat Timeline - focused checks** (`chat-timeline-checks.yml`) runs Swift syntax checks for `ChatTimeline*.swift` and compiles/runs the pure Foundation date-selection regression program. It uses the exact dispatched commit on the same free `xcode-27` runner, with a 15-minute limit and no Telegram/Apple login. Run it on the published feature branch after the feature files and `Tests/ChatTimeline/TimelineDateSelectionChecks.swift` are present. Passing these checks does not establish full Telegram linkage or UI behavior.

Local CI guard checks: `python -B ci/chat-timeline/test_bootstrap.py`. These check public sample provenance, missing secrets, expired/near-expiry device profiles, source mismatch and rejection of a simulator artifact as an iPhone artifact. They simulate host metadata and cannot establish native signing or compilation.

## API configuration

`upstream-test` reads only the public `build-system/appstore-configuration.json` from the pinned upstream source. Its SHA-256 after Git line-ending normalization must be `51defacf9aa00046e6ef108369632c53e6beb97e3fffd30926f700718b496352`. Only its API ID/hash are used; feature configuration disables App Store mode, Siri and iCloud and uses a distinct URL scheme. No private previous-project configuration is read. API values are not printed or uploaded as configuration artifacts.

Telegram expressly permits the included sample API ID **for testing only**. It is server-limited; login or API use is not guaranteed. Do not distribute a sample-configured app to end users. Before distribution, select `api_source=secrets` and provide the repository's own `TELEGRAM_API_ID` and `TELEGRAM_API_HASH`. Do not retry a rate-limited my.telegram.org login. The compiled binary necessarily contains its API configuration; an IPA is not a secret store.

## Simulator versus device

The simulator build uses upstream `Make.py build --configuration=debug_sim_arm64 --xcodeManagedCodesigning`, together with the existing Bazel setting `--//Telegram:disableProvisioningProfiles=true` in the ephemeral checkout's `.bazelrc`. It needs neither an Apple account nor device provisioning profiles. This setting is a Bazel flag, **not** a supported `Make.py build --disableProvisioningProfiles` option. `XcodeManagedCodesigningSource` supplies empty signing metadata; with all provisioning inputs disabled, the simulator path does not invoke a private signing service. This path still needs a real successful run to establish all upstream dependencies work in this runner.

Simulator bundle ID is `org.banan2212.ChatTimeline`. Its `.ipa` is an archive for the simulator only; it cannot run on an iPhone. No UI automation or account login happens in CI. The artifact manifest records `MinimumOSVersion`, but SDK/build compatibility alone does not establish iOS 26 runtime behavior.

The device path imports only upstream's published `fake-codesigning` fixture, smoke-checks its key with `codesign`, and uses `release_arm64`. The pinned profiles expire on **2026-10-30 at 17:06:30 UTC / 20:06:30 Moscow**. Expired profiles, or less than six hours remaining, block the device build. The check repeats immediately before compilation. It is never disabled. Simulator mode is independent of device profiles and is explicitly labelled as such.

A device candidate inherits the fixture bundle ID so its provisioning matches. **Do not install it over the user's normal Telegram.** A later local signing process must create a distinct application and consistent extension/App Group identifiers, then validate launch, data separation and features on the iPhone. That process is not implemented or proven by this CI. No Apple ID, private certificate or password is collected here.

## Provenance and limits

### Read-only IPA inspection on Windows

After downloading an artifact, use the standard-library-only inspector. It reads the IPA and manifest without changing them, extracting files, contacting Apple or installing anything:

```sh
python ci/chat-timeline/inspect_ipa.py Telegram-self-signed-requires-resigning.ipa --manifest manifest.json --source-revision FULL_EXPECTED_SOURCE_SHA --target-ios 26.0 --target device --output ipa-audit.json
```

Take the expected SHA independently from the selected CI source: the pinned upstream SHA for a baseline, or the dispatched feature commit for a feature build. Do not merely copy a potentially untrusted manifest's SHA into the command. A matching manifest ties the downloaded bytes to that manifest; it is not cryptographically signed source provenance.

The report uses **pass / fail / unknown**. `static_checks=pass` means the implemented static checks found no inconsistency; the overall `result` stays **unknown** because Apple trust, code-page/resource signatures, installation and runtime behavior are not verified. Exit codes: `1` for known failures, `2` for unknown overall status. This inspector cannot currently return overall pass. Argument errors also use argparse's exit code `2`, but do not emit an audit JSON report. Unknown does not establish signature validity or installability; use separate signing and device verification.

Checks include manifest SHA-256/size/source/target; every ZIP member's CRC; duplicate/case-colliding/unsafe paths; actual main app, nested `.app`/`.appex`, frameworks and loose dylib inventory; declared executables; thin/fat Mach-O CPU and `LC_BUILD_VERSION`; declared and actual minimum iOS versions against `--target-ios`. ARM64 alone does not prove a device build: platform `2` is iPhoneOS, `7` is iPhoneSimulator. A legacy minimum-version command without an explicit platform stays unknown. Watch companions are inventoried separately and their watchOS compatibility stays unknown; their version is never compared numerically to iOS 26.

Embedded provisioning XML is parsed as **untrusted metadata**, without claiming CMS verification. The limited report includes only application/team identifiers, App Groups, keychain groups and expiration. Apple IDs, profile names, device UDIDs, certificates and full profiles are never emitted. When an executable contains an XML entitlement slot, it is checked against the profile's identifier/group allowlist and, where supported, its CodeDirectory special-slot hash. That hash match is an internal consistency check, **not** a signature/trust check. DER entitlement blobs are detected but not interpreted or compared to XML; that remains unknown. Nested identifiers/teams and intersections of host/extension groups are reported. A missing shared group is a warning because not every extension needs shared storage.

No unsafe archive path is extracted or followed. Inspected metadata/executables must be regular ZIP members, not symlink entries. Inspection is bounded to 100,000 entries, 8 GiB total uncompressed data, 1 GiB per member and 8 MiB per plist. An unreadable/unsupported format is reported without dumping its contents. These limits can reject oversized archives; that is not a device compatibility finding.

Regression checks: `python -B ci/chat-timeline/test_inspect_ipa.py`. Synthetic fixtures cover corrupted CRC, mismatching manifest/revision, missing executable, simulator code hidden behind device Info.plist, minimum iOS too high, entitlement/group/hash inconsistency, fat bounds, unsafe paths, privacy and the unknown exit status. Fixtures are neither signed nor runnable apps. All nine actual public upstream provisioning files were additionally parsed without exporting identity/device fields; a real built IPA still needs inspection after the build finishes.

Primary format references:

- [Apple Mach-O load commands and platform constants](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [Apple CPU type definitions](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/machine.h)
- [Apple fat Mach-O layout](https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/fat.h)
- [Apple code-signature blob layouts and hash types](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [Apple TN3125: provisioning profiles and their trust boundary](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)
- [Apple bundle identifier changes and companion targets](https://developer.apple.com/documentation/xcode/changing-the-bundle-identifier)

Checkout uses exact revisions. Fork-relative submodule URLs are resolved against TelegramMessenger in a command-local Git setting, avoiding nonexistent forks such as `banan2212/rlottie`; each submodule must remain at its recorded revision. Artifacts come exclusively from the current `bazel-bin/Telegram/Telegram.ipa`, with ZIP integrity, declared executable and device/simulator platform checks. A SHA-256 manifest records the selected source, build and API mode. No Releases are created. Artifacts expire after three days.

The workflow does not override Xcode/Bazel versions. It selects Xcode 27.1 only if actually installed, then requires the pins in `versions.json`. Upstream `Make.py` does not wire its declared `--bazelArguments` into `build()`, so jobs/provisioning flags are appended only to the temporary CI checkout's `.bazelrc`.

Sources:

- [Upstream build workflow](https://github.com/TelegramMessenger/Telegram-iOS/blob/fb0e62ba8a147f0821da6aa63c09da7d79a10111/.github/workflows/build.yml)
- [Make.py and supported configurations](https://github.com/TelegramMessenger/Telegram-iOS/blob/fb0e62ba8a147f0821da6aa63c09da7d79a10111/build-system/Make/Make.py)
- [Signing configuration sources](https://github.com/TelegramMessenger/Telegram-iOS/blob/fb0e62ba8a147f0821da6aa63c09da7d79a10111/build-system/Make/BuildConfiguration.py)
- [Telegram provisioning setting](https://github.com/TelegramMessenger/Telegram-iOS/blob/fb0e62ba8a147f0821da6aa63c09da7d79a10111/Telegram/BUILD)
- [Public upstream sample config](https://github.com/TelegramMessenger/Telegram-iOS/blob/fb0e62ba8a147f0821da6aa63c09da7d79a10111/build-system/appstore-configuration.json)
- [Telegram's sample API restrictions](https://core.telegram.org/api/obtaining_api_id)
- [GitHub standard public runners](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job)

Local checks can validate Python/YAML syntax, profile dates and public configuration provenance. Windows cannot validate native compilation, keychain import, simulator launch or iPhone behavior. Source investigation used bounded direct reads because the graph project was unavailable; it was not an exhaustive build-system audit.
