# Chat Timeline for Telegram iOS

An unofficial feature proposal for browsing chat history by date, previewing a real message before jumping, and returning to the previous reading position.

Intended flow: in an eligible cloud chat or channel, tap a date header to open Timeline. Select a year, month and day, inspect the actual preview date, then choose Jump. Cancel preserves the current view; Return restores the saved reading position. See [feature scope and current limitations](docs/chat-timeline/README.md).

**Verification status:** full feature [device](https://github.com/banan2212/telegram-chat-timeline/actions/runs/40977552237) and [simulator](https://github.com/banan2212/telegram-chat-timeline/actions/runs/40977729961) builds passed for native source `67cdc26e9e9cd4408f1d966a749352e4bbfdd0d6`. The [startup run](https://github.com/banan2212/telegram-chat-timeline/actions/runs/40984443420) produced genuine Telegram welcome-screen evidence, but its screenshot command timed out after 90 seconds; the full smoke check failed. The device candidate is not installable as-is and still has [signing/identity findings](docs/chat-timeline/device-installation.md). Authenticated Timeline behavior, physical iPhone verification and a finished demo remain pending under the [acceptance checks](docs/chat-timeline/acceptance.md).

Based on TelegramMessenger/Telegram-iOS commit [`fb0e62ba8a147f0821da6aa63c09da7d79a10111`](https://github.com/TelegramMessenger/Telegram-iOS/commit/fb0e62ba8a147f0821da6aa63c09da7d79a10111). For Chat Timeline builds, use **this fork** and a full feature commit SHA. The [CI build guide](ci/chat-timeline/README.md) explains exact-revision builds and artifact manifests, focused checks, simulator startup checks and their limits. Its public sample API configuration is for testing only, not end-user distribution. A device candidate requires personal signing; follow the [Windows/iPhone installation guide](docs/chat-timeline/device-installation.md).

For a manual macOS build, prepare the selected feature checkout, then continue with [Setup Xcode](#setup-xcode), [Adjust Configuration](#adjust-configuration) and [Generate an Xcode project](#generate-an-xcode-project) below, using the pins in [`versions.json`](versions.json). Replace `FULL_FEATURE_COMMIT_SHA` with the revision you intend to test:

```sh
git clone https://github.com/banan2212/telegram-chat-timeline.git
cd telegram-chat-timeline
git checkout FULL_FEATURE_COMMIT_SHA
git -c remote.origin.url=https://github.com/TelegramMessenger/Telegram-iOS.git submodule init
git submodule update --init --recursive --jobs 2
```

The upstream guide below is preserved as reference; its original clone command selects upstream. Existing upstream licenses and notices apply. This feature has not been accepted or endorsed by Telegram.

---

# Telegram iOS Source Code Compilation Guide

We welcome all developers to use our API and source code to create applications on our platform.
There are several things we require from **all developers** for the moment.

# Creating your Telegram Application

1. [**Obtain your own api_id**](https://core.telegram.org/api/obtaining_api_id) for your application.
2. Please **do not** use the name Telegram for your app — or make sure your users understand that it is unofficial.
3. Kindly **do not** use our standard logo (white paper plane in a blue circle) as your app's logo.
3. Please study our [**security guidelines**](https://core.telegram.org/mtproto/security_guidelines) and take good care of your users' data and privacy.
4. Please remember to publish **your** code too in order to comply with the licences.

# Quick Compilation Guide

## Get the Code

```
git clone --recursive -j8 https://github.com/TelegramMessenger/Telegram-iOS.git
```

## Setup Xcode

Install Xcode (directly from https://developer.apple.com/download/applications or using the App Store).

## Adjust Configuration

1. Generate a random identifier:
```
openssl rand -hex 8
```
2. Create a new Xcode project. Use `Telegram` as the Product Name. Use `org.{identifier from step 1}` as the Organization Identifier.
3. Open `Keychain Access` and navigate to `Certificates`. Locate `Apple Development: your@email.address (XXXXXXXXXX)` and double tap the certificate. Under `Details`, locate `Organizational Unit`. This is the Team ID.
4. Edit `build-system/template_minimal_development_configuration.json`. Use data from the previous steps.

## Generate an Xcode project

```
python3 build-system/Make/Make.py \
    --cacheDir="$HOME/telegram-bazel-cache" \
    generateProject \
    --configurationPath=build-system/template_minimal_development_configuration.json \
    --xcodeManagedCodesigning
```

# Advanced Compilation Guide

## Xcode

1. Copy and edit `build-system/appstore-configuration.json`.
2. Copy `build-system/fake-codesigning`. Create and download provisioning profiles, using the `profiles` folder as a reference for the entitlements.
3. Generate an Xcode project:
```
python3 build-system/Make/Make.py \
    --cacheDir="$HOME/telegram-bazel-cache" \
    generateProject \
    --configurationPath=configuration_from_step_1.json \
    --codesigningInformationPath=directory_from_step_2
```

## IPA

1. Repeat the steps from the previous section. Use distribution provisioning profiles.
2. Run:
```
python3 build-system/Make/Make.py \
    --cacheDir="$HOME/telegram-bazel-cache" \
    build \
    --configurationPath=...see previous section... \
    --codesigningInformationPath=...see previous section... \
    --buildNumber=100001 \
    --configuration=release_arm64
```

# FAQ

## Xcode is stuck at "build-request.json not updated yet"

Occasionally, you might observe the following message in your build log:
```
"/Users/xxx/Library/Developer/Xcode/DerivedData/Telegram-xxx/Build/Intermediates.noindex/XCBuildData/xxx.xcbuilddata/build-request.json" not updated yet, waiting...
```

Should this occur, simply cancel the ongoing build and initiate a new one.

## Telegram_xcodeproj: no such package 

Following a system restart, the auto-generated Xcode project might encounter a build failure accompanied by this error:
```
ERROR: Skipping '@rules_xcodeproj_generated//generator/Telegram/Telegram_xcodeproj:Telegram_xcodeproj': no such package '@rules_xcodeproj_generated//generator/Telegram/Telegram_xcodeproj': BUILD file not found in directory 'generator/Telegram/Telegram_xcodeproj' of external repository @rules_xcodeproj_generated. Add a BUILD file to a directory to mark it as a package.
```

If you encounter this issue, re-run the project generation steps in the README.


# Tips

## Codesigning is not required for simulator-only builds

Add `--disableProvisioningProfiles`:
```
python3 build-system/Make/Make.py \
    --cacheDir="$HOME/telegram-bazel-cache" \
    generateProject \
    --configurationPath=path-to-configuration.json \
    --codesigningInformationPath=path-to-provisioning-data \
    --disableProvisioningProfiles
```

## Versions

Each release is built using a specific Xcode version (see `versions.json`). The helper script checks the versions of the installed software and reports an error if they don't match the ones specified in `versions.json`. It is possible to bypass these checks:

```
python3 build-system/Make/Make.py --overrideXcodeVersion build ... # Don't check the version of Xcode
```
