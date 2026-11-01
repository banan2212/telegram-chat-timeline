# Owner-profile device preparation

This manual route is preparation for an owner-signed test application. It is not a
signed release, a profile-expiry workaround, or proof of successful Telegram login.
The original public-fixture device workflow and its expiry guard remain intact.

## Data and consent boundary

Before dispatch, the owner must approve transferring **one exact Chat Timeline
provisioning profile and the target iPhone identifier** to GitHub Actions. A profile
contains device and Apple team metadata and public certificates. It is not a private
signing key. No Apple password, session, private signing key, or Telegram account
credential is required by this route.

The local preparation input has the following closed JSON schema. Values are read
from private files; never paste a populated example into a chat or commit it:

```json
{
  "version": 1,
  "profile_der_b64": "BASE64_OF_THE_SINGLE_PROFILE",
  "device": "EXACT_TARGET_DEVICE_IDENTIFIER",
  "recipient_certificate_pem": "PUBLIC_CERTIFICATE_FOR_LOCAL_ARTIFACT_DECRYPTION"
}
```

Only this JSON is supplied as the repository Actions secret
`CHAT_TIMELINE_OWNER_INPUT`. The artifact encryption private key stays on the local
machine. The secret must be removed after the approved build. There is no profile
discovery or credential lookup in the workflow, and no pull-request trigger.

## Explicit API source

The manual workflow requires an `api_source` choice and defaults to `secrets`:

| Choice | Required input | Behavior |
| --- | --- | --- |
| `secrets` | Repository Actions secrets `TELEGRAM_API_ID` and `TELEGRAM_API_HASH` from the owner's Telegram API application | Validate both values; stop if either is missing or invalid. |
| `upstream-test` | Explicit selection of this testing mode | Use only the reviewed, checksum-pinned public upstream sample; Telegram server limitations apply. |

There is no automatic switch to the sample. The Python entry point requires an
explicit `API_SOURCE` environment value from this closed set; missing or unknown
values are rejected before private build files are created. The workflow supplies
API secrets only to the consuming preflight/build step, and only in `secrets` mode.
After preflight, these environment variables are removed before compiler and
encryption subprocesses run. The validated configuration remains private and is
removed by the existing cleanup. No API value is printed or added to the public
artifact receipt. Supplying API application credentials does not replace the
owner's Telegram login or prove that authentication works.

## Build checks

The manual `chat-timeline-owner-device.yml` workflow checks out its exact commit on
the standard free `xcode-27` runner. It retains Xcode/macOS/Bazel, source provenance,
the selected API configuration validation, resource and pinned-submodule checks.
The public sample provenance check remains mandatory for `upstream-test` mode.

`owner_profile.py` verifies the CMS content signature and evaluates Apple's native
provisioning-signing policy plus certificate validity. It rejects unavailable
policies, missing certificate-chain intermediates, or unknown trust. Network
certificate fetching is disabled. Decoding a plist is not treated as verification.
The expected exact main-app identity, App Group, keychain allowance, device,
development entitlement and at least six hours of validity must all agree.

`Make.py build --deferredOwnerSigning` accepts only the explicitly supplied main
profile and a device configuration. It never imports a private signing identity.
It forces these Bazel settings:

```text
--features=disable_legacy_signing
--//Telegram:disableExtensions=true
--//Telegram:embedWatchApp=false
--//Telegram:disableProvisioningProfiles=false
--output_groups=+dossier
```

The dossier output is essential: it consumes processed entitlements and the real
profile, forcing the existing validation action despite deferred signing. A missing
APS entitlement becomes an empty setting only in this explicit mode; none is
invented. The build profile is checked again after compilation.

## Handoff and private results

The build uses the final personal bundle identity so its compiled background-task
identifiers agree with the eventual app. The non-installable AltServer input uses
the canonical base bundle and App Group expected by the reviewed AltServer
identifier transformation. Its ad-hoc signature carries the requested metadata;
it is not an Apple authorization or an installable signature. The owner profile is
removed from that handoff. Final signing and installation remain owner-controlled.

The reviewed public AltServer Windows source is version 1.7.5. Its transformation
is not proof of identical behavior in the owner's installed 1.8.0.1. Final bundle,
group/container, keychain and background-task consistency still need verification.

Only CMS-encrypted results and a non-personal ciphertext receipt are uploaded,
retained for one day. Compiler output stays private; a failed compiler log may be
included in an encrypted failure result for local diagnosis. No plaintext profile,
dossier, build configuration, raw log or IPA is an uploaded artifact. The receipt's
SHA-256 checks downloaded ciphertext integrity; it is not signed source attestation.

Generated configuration copies and the private runner working directory are
removed at cleanup. No build cache is uploaded. A hosted runner necessarily handles
the supplied profile and identifier while the approved job runs.

## Verification limits

Synthetic tests exercise rejection, wrapper flags, scoped cleanup and encryption
round trips. The macOS empty-CMS smoke checks native API integration and rejection;
it does not establish acceptance of a real owner profile. This route still needs an
actual successful device compilation, owner re-signing, installation, login and
physical Timeline acceptance before it can be described as working on an iPhone.
