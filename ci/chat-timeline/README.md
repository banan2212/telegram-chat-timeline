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
