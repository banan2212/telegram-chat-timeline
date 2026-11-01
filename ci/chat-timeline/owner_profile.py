"""Fail-closed, private owner-profile preflight. No signing, upload or key access.

verify_profile(path, expected_device, now=None) returns PRIVATE configuration.
Only result['public_summary'] may be logged. ProfileRejected contains no input data.
Native verification requires macOS/Xcode and Apple's Security.framework policies;
decoding CMS alone is never accepted as verification. No alternate trust fallback.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import platform
import plistlib
import re
import stat
import subprocess
import sys
import tempfile

MAX_PROFILE_BYTES = 4 * 1024 * 1024
MINIMUM_LIFETIME = dt.timedelta(hours=6)
UTC = dt.timezone.utc
_SUMMARY_KEYS = (
    'accepted', 'cms_signature_verified', 'apple_chain_verified',
    'certificate_validity_verified', 'development_profile_verified',
    'bundle_team_group_verified', 'target_device_verified',
    'minimum_lifetime_verified', 'aps_present',
)


class ProfileRejected(ValueError):
    def __init__(self):
        super().__init__('owner_profile_rejected')
        self.public_summary = {key: False for key in _SUMMARY_KEYS}


# Apple's native policy OIDs, not a custom certificate-name/root heuristic:
# https://github.com/apple-oss-distributions/Security/blob/main/OSX/sec/Security/SecPolicy.list
# https://github.com/apple-oss-distributions/Security/blob/main/OSX/sec/Security/SecPolicy.c
# .56 pins the provisioning-profile signer to Apple. BasicX509 additionally checks
# time because Apple's profile-signing policy intentionally omits expiration checks.
# .55 checks Apple-issued profile application-signing certificates with expiration.
# Any unavailable policy, SDK, chain certificate or trust result is a rejection.
_NATIVE_SWIFT = r'''
import Foundation
import Security

func reject() -> Never { exit(2) }
func require(_ status: OSStatus) { if status != errSecSuccess { reject() } }

guard CommandLine.arguments.count == 2,
      let seconds = Double(CommandLine.arguments[1]), seconds.isFinite
else { reject() }
guard let profilePolicy = SecPolicyCreateWithProperties("1.2.840.113635.100.1.56" as CFString, nil),
      let developerPolicy = SecPolicyCreateWithProperties("1.2.840.113635.100.1.55" as CFString, nil)
else { exit(3) }
let now = Date(timeIntervalSince1970: seconds)
let horizon = now.addingTimeInterval(6 * 60 * 60)
let policies = [profilePolicy, SecPolicyCreateBasicX509()] as CFArray

func evaluate(_ trust: SecTrust) {
    require(SecTrustSetNetworkFetchAllowed(trust, false))
    for date in [now, horizon] {
        require(SecTrustSetVerifyDate(trust, date as CFDate))
        if !SecTrustEvaluateWithError(trust, nil) { reject() }
    }
}

let encoded = FileHandle.standardInput.readDataToEndOfFile()
guard !encoded.isEmpty, encoded.count <= 4 * 1024 * 1024 else { reject() }
var decoderOptional: CMSDecoder?
require(CMSDecoderCreate(&decoderOptional))
guard let decoder = decoderOptional else { reject() }
require(encoded.withUnsafeBytes { CMSDecoderUpdateMessage(decoder, $0.baseAddress!, $0.count) })
require(CMSDecoderFinalizeMessage(decoder))
var signerCount = 0
require(CMSDecoderGetNumSigners(decoder, &signerCount))
guard signerCount == 1 else { reject() }
var signerStatus = CMSSignerStatus.unsigned
var signerTrust: SecTrust?
// false defers certificate evaluation so network access can be disabled first.
// The content signature must be valid AND the returned trust must separately pass.
require(CMSDecoderCopySignerStatus(decoder, 0, policies, false, &signerStatus, &signerTrust, nil))
guard signerStatus == .valid, let signerTrust = signerTrust else { reject() }
require(SecTrustSetPolicies(signerTrust, policies))
evaluate(signerTrust)
var contentOptional: CFData?
require(CMSDecoderCopyContent(decoder, &contentOptional))
guard let content = contentOptional as Data?, !content.isEmpty,
      content.count <= 4 * 1024 * 1024,
      let profile = (try? PropertyListSerialization.propertyList(from: content, format: nil)) as? [String: Any],
      let certificates = profile["DeveloperCertificates"] as? [Data],
      !certificates.isEmpty, certificates.count <= 16
else { reject() }
for data in certificates {
    guard !data.isEmpty, data.count <= 64 * 1024,
          let certificate = SecCertificateCreateWithData(nil, data as CFData)
    else { reject() }
    var certificateTrust: SecTrust?
    require(SecTrustCreateWithCertificates(certificate, developerPolicy, &certificateTrust))
    guard let certificateTrust = certificateTrust else { reject() }
    evaluate(certificateTrust)
}
// Private decoded payload goes only to the parent's captured pipe, never a log.
FileHandle.standardOutput.write(content)
'''


def _run_native(encoded: bytes, now: dt.datetime) -> subprocess.CompletedProcess:
    if platform.system() != 'Darwin':
        raise ProfileRejected()
    try:
        with tempfile.TemporaryDirectory(prefix='owner-profile-native-') as directory:
            folder = Path(directory).resolve()
            if folder.parent != Path(tempfile.gettempdir()).resolve():
                raise ProfileRejected()
            source = folder / 'verify.swift'
            source.write_text(_NATIVE_SWIFT, encoding='utf-8')
            result = subprocess.run(
                ['/usr/bin/xcrun', 'swift', '-module-cache-path', str(folder / 'module-cache'),
                 str(source), str(now.timestamp())],
                input=encoded, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=120, check=False,
            )
        return result
    except (OSError, subprocess.SubprocessError):
        raise ProfileRejected() from None


def _verified_payload(encoded: bytes, now: dt.datetime) -> bytes:
    """Native trust boundary. Tests may mock it; production exposes no bypass flag."""
    result = _run_native(encoded, now)
    if result.returncode != 0 or not 0 < len(result.stdout) <= MAX_PROFILE_BYTES:
        raise ProfileRejected()
    return result.stdout


def native_verifier_smoke() -> bool:
    """Compile/import/policy availability and empty-input rejection, NOT positive trust."""
    try:
        result = _run_native(b'', dt.datetime(2026, 11, 1, tzinfo=UTC))
        # Compile failure normally exits 1; missing policy exits 3. Only the
        # intentional empty-CMS rejection after policy creation exits 2 here.
        return result.returncode == 2 and result.stdout == b''
    except Exception:
        return False


def _date(value: object) -> dt.datetime:
    if not isinstance(value, dt.datetime):
        raise ProfileRejected()
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _private_configuration(profile: object, expected_device: str, now: dt.datetime) -> dict:
    """Check decoded policy only AFTER _verified_payload succeeds."""
    if not isinstance(profile, dict):
        raise ProfileRejected()
    platforms = profile.get('Platform')
    # Current Apple iOS profiles can also name the Vision Pro platforms.
    # Require explicit iOS authorization; multiple supported platforms are valid.
    if (not isinstance(platforms, list) or not platforms
            or not all(isinstance(item, str) for item in platforms)
            or len(set(platforms)) != len(platforms)
            or 'iOS' not in platforms or not set(platforms) <= {'iOS', 'xrOS', 'visionOS'}):
        raise ProfileRejected()
    created = _date(profile.get('CreationDate'))
    expires = _date(profile.get('ExpirationDate'))
    if not (dt.datetime(2007, 1, 1, tzinfo=UTC) <= created <= now + dt.timedelta(minutes=5)):
        raise ProfileRejected()
    if created >= expires or expires - now < MINIMUM_LIFETIME:
        raise ProfileRejected()
    if profile.get('ProvisionsAllDevices') is not None and profile.get('ProvisionsAllDevices') is not False:
        raise ProfileRejected()
    teams = profile.get('TeamIdentifier')
    prefixes = profile.get('ApplicationIdentifierPrefix')
    if not isinstance(teams, list) or len(teams) != 1 or not isinstance(teams[0], str):
        raise ProfileRejected()
    team = teams[0]
    if re.fullmatch(r'[A-Z0-9]{10}', team) is None or prefixes != [team]:
        raise ProfileRejected()
    bundle = 'ph.telegra.Telegraph.' + team
    application_id = team + '.' + bundle
    entitlements = profile.get('Entitlements')
    if not isinstance(entitlements, dict) or entitlements.get('get-task-allow') is not True:
        raise ProfileRejected()
    if entitlements.get('application-identifier') != application_id:
        raise ProfileRejected()
    if entitlements.get('com.apple.developer.team-identifier') != team:
        raise ProfileRejected()
    groups = entitlements.get('com.apple.security.application-groups')
    if not isinstance(groups, list) or not 1 <= len(groups) <= 64 or not all(
            isinstance(item, str) and '*' not in item for item in groups):
        raise ProfileRejected()
    if 'group.' + bundle not in groups:
        raise ProfileRejected()
    keychain_groups = entitlements.get('keychain-access-groups')
    if not isinstance(keychain_groups, list) or not 1 <= len(keychain_groups) <= 64 or not all(
            isinstance(item, str) and item.startswith(team + '.') for item in keychain_groups):
        raise ProfileRejected()
    if application_id not in keychain_groups and team + '.*' not in keychain_groups:
        raise ProfileRejected()
    devices = profile.get('ProvisionedDevices')
    if not isinstance(devices, list) or not 1 <= len(devices) <= 1000 or not all(
            isinstance(item, str) and len(item) <= 64 for item in devices):
        raise ProfileRejected()
    # Exact comparison only. No device enumeration, suffix matching or logging.
    if expected_device not in devices:
        raise ProfileRejected()
    certificates = profile.get('DeveloperCertificates')
    if not isinstance(certificates, list) or not 1 <= len(certificates) <= 16 or not all(
            isinstance(item, bytes) and 0 < len(item) <= 64 * 1024 for item in certificates):
        raise ProfileRejected()
    aps = entitlements.get('aps-environment', '')
    if 'aps-environment' in entitlements and aps not in ('development', 'production'):
        raise ProfileRejected()
    return {
        'team_id': team,
        'bundle_id': bundle,
        'aps_environment': aps,
        'public_summary': dict.fromkeys(_SUMMARY_KEYS, True) | {'aps_present': bool(aps)},
    }


def verify_profile(path: Path | str, expected_device: str, now: dt.datetime | None = None) -> dict:
    """Return PRIVATE config and original verified bytes; only public_summary is loggable.

    profile_data is provided so the caller can copy the exact verified CMS bytes,
    avoiding a second read of a potentially replaced input path. No private key is
    requested or inspected. A valid profile does not prove a signing key is owned.
    """
    try:
        now = dt.datetime.now(UTC) if now is None else _date(now)
        if not isinstance(expected_device, str) or re.fullmatch(r'[0-9A-Fa-f-]{8,64}', expected_device) is None:
            raise ProfileRejected()
        path = Path(path).absolute()
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or path.is_symlink() or not 0 < before.st_size <= MAX_PROFILE_BYTES:
            raise ProfileRejected()
        with path.open('rb') as stream:
            raw = stream.read(MAX_PROFILE_BYTES + 1)
        after = path.stat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or len(raw) != before.st_size:
            raise ProfileRejected()
        payload = _verified_payload(raw, now)
        profile = plistlib.loads(payload)
        result = _private_configuration(profile, expected_device, now)
        result.update(profile_path=str(path.resolve()), profile_data=raw,
                      profile_sha256=hashlib.sha256(raw).hexdigest())
        return result
    except ProfileRejected:
        raise
    except Exception:
        # Never surface native stderr, certificate names, device IDs or input paths.
        raise ProfileRejected() from None


if __name__ == '__main__':
    passed = sys.argv[1:] == ['--native-smoke'] and native_verifier_smoke()
    print(json.dumps({'native_compiles_and_rejects_empty': passed}))
    raise SystemExit(0 if passed else 2)
