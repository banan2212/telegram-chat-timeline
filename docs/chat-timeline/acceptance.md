# Acceptance and evidence

Every row starts unverified. Record source commit, build run, device/OS, reproduction, and actual outcome when running it.

| Requirement | Evidence required |
|---|---|
| Entry in a normal cloud chat and channel | Device recording of opening the timeline from the actual chat UI; unsupported histories do not expose a broken entry |
| Year/month/day and calendar correctness | Production date model tests for leap years, month lengths, partial bounds, future clamp, and DST; device timezone check |
| Preview before jump | Recording shows a real matching message and actual date while the main history remains at the original position |
| Query cancellation | Slow responses arriving out of order cannot replace the latest selected date's preview or enable an obsolete Jump |
| Bounded network use | Request traces during continuous scrubbing show debounce/cancellation and bounded caching; no full-history fetch |
| Confirm and highlight | Recording demonstrates the same previewed message opening and highlighting, after its availability is revalidated |
| Return position | Record original visible message and viewport offset, jump, then return; original reading position restored within one logical point when the message still exists |
| New messages during navigation | Return preserves original reading location while new messages arrive at the bottom |
| Cancel and dismissal | Opening, scrubbing, cancelling, or dismissing does not change the underlying history position |
| Error states | Airplane/connection failure, delayed response, deleted target, inaccessible history, and empty result are distinct from a confirmed empty date |
| Scope changes | Closing the chat or switching chat invalidates outstanding preview/confirmation callbacks |
| Themes and text | Light and dark themes, increased text size, VoiceOver labels/actions, long author/text, and media-only previews remain usable |
| Reduced motion | Opening/closing and preview changes obey Reduce Motion; essential navigation remains available |
| Reproducible build | Successful native build logs and artifact manifest contain the exact feature commit, base revision, platform, SDK, and archive SHA-256 |
| Actual iPhone | Separate signed install launches on iPhone 15/iOS 26 and completes the above core flows; simulator alone does not satisfy this |
| Demo | Source recording and final 15–25 second MP4 show the accepted feature commit; no composited replacement of in-app behavior |

## Motion expectations, defined before recording

The selected-date indicator follows input immediately. Loading does not shake or resize the preview card. A new preview replaces the prior one coherently without briefly mixing its author, date and text. Jump remains disabled for a loading/failed/stale selection. The parent chat stays still until confirmation. After dismissing a preview, there must be no empty gap, duplicate message, or invisible interaction layer above the chat.

Use short native transitions. Avoid an exaggerated spring on the selected date or a delayed response to scrubbing. Reduce Motion removes unnecessary translation and scaling. Evaluate real-speed footage before any slowed demonstration.

For each final visual change, follow the upstream AGENTS.md recording and frame review procedure. Log actual frame indices/timestamps and describe any clipping, jumps, flashes, overshoot, or delayed layout. A 60 fps export does not establish a 60 fps application.

## Completion rule

Source and draft documents can be ready while physical-device gates remain blocked. Do not mark this proposal complete until the required runtime evidence exists. Do not use test fixtures or simulated messages as an unlabeled substitute for real message retrieval in the final demo.
