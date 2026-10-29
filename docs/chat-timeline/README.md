# Chat Timeline

Chat Timeline is a native Telegram iOS feature proposal. Select a calendar date, inspect a real nearby message, then jump deliberately. Keep a return point to resume reading where you started.

## Intended behavior

- A compact date navigation sheet offers year, month, and day controls and a scrubber.
- Preview loading does not move the chat or mark previewed messages as read.
- The preview shows the actual message date when it differs from the selected date.
- Jump navigates to the confirmed message and highlights it. Return restores the captured message and its relative scroll position.
- Cancel leaves the chat position untouched.
- The native calendar remains available. The first scope is ordinary cloud chats and channels, excluding secret chats, forum topics, and special history modes.

No activity heatmap, inferred message density, all-history download, AI, or server changes are part of this proposal. Message ID gaps cannot be used as an exact message count.

## Verification status

Implementation is in progress. Build success, simulator behavior, physical iPhone behavior, accessibility, and video quality are separate acceptance gates. A passing Python guard test or Swift syntax check is not an app build or runtime verification.

See [acceptance.md](acceptance.md) for the required evidence. Target device: iPhone 15 with iOS 26. See [the build guide](../../ci/chat-timeline/README.md) for exact-revision workflows and their limitations.

Current scope limits: new feature labels are English; histories in secret chats, forum topics, scheduled/pinned views, search and selection modes keep their existing navigation. The date header also keeps its existing behavior while the composer is focused, so opening and cancelling Timeline cannot silently close the keyboard or resize the history.

The first cloud probe passed on Xcode 27.1/macOS 27.0.1 with iOS 27.0/27.1 simulator runtimes. This confirms the available toolchain only. It does not establish runtime compatibility with the target iOS 26 device.

## Development and sample API configuration

CI can use the public sample configuration from the pinned official source for testing only, as allowed by [Telegram's documentation](https://core.telegram.org/api/obtaining_api_id). It is limited on the server and is not suitable for distribution to end users. Do not retry rate-limited authentication or publish account credentials. Own API credentials, actual signing, and device testing remain release requirements.

The simulator archive is not an iPhone IPA. A self-signed device candidate still needs legitimate local signing with a separate application identity. It must not replace the user's primary Telegram installation.

## Submission materials

- [Demo storyboard and capture plan](demo-storyboard.md)
- [English submission draft](submission-en.md)

These documents are preparation artifacts. They do not claim the proposed functionality has already passed acceptance, and no submission is sent automatically.
