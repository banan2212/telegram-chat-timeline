"""Private, macOS-only preparation for a later owner-controlled AltServer signing.

No Apple signing identity or private key is accessed. Ad-hoc signatures preserve
only integrity and the requested canonical App Group for AltServer to read. They
are NOT device-installable signatures. The already verified owner profile is
compared byte-for-byte with the build input and never included in output.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import plistlib
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile

from inspect_ipa import ARM64, macho, sha256

CANONICAL_BUNDLE = 'ph.telegra.Telegraph'
APP_PATH = 'Payload/Telegram.app'
OUTPUT_NAME = 'Chat-Timeline-SIGNING-INPUT-NOT-INSTALLABLE.ipa'
MAX_MEMBER = 1024 ** 3
MAX_TOTAL = 4 * 1024 ** 3
MACHO_MAGICS = (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe',
                b'\xfe\xed\xfa\xce', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
                b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca')


class PackageRejected(ValueError):
    def __init__(self):
        super().__init__('owner_signing_input_rejected')


def _require(condition: bool) -> None:
    if not condition:
        raise PackageRejected()


def _run(arguments: list[str], cwd: Path | None = None) -> bytes:
    result = subprocess.run(arguments, cwd=cwd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=120, check=False)
    _require(result.returncode == 0)
    return result.stdout


def _revision(source: Path, expected: str) -> None:
    _require(isinstance(expected, str) and re.fullmatch(r'[0-9a-f]{40}', expected) is not None)
    _require(_run(['git', 'rev-parse', 'HEAD'], source).decode('ascii').strip() == expected)


def _owner(verified: dict) -> tuple[str, str, bytes]:
    # The caller must obtain this object from owner_profile.verify_profile after
    # compilation. These checks cannot independently establish Apple's CMS trust.
    _require(isinstance(verified, dict))
    team, bundle, raw = (verified.get(key) for key in ('team_id', 'bundle_id', 'profile_data'))
    _require(isinstance(team, str) and re.fullmatch(r'[A-Z0-9]{10}', team) is not None)
    _require(bundle == CANONICAL_BUNDLE + '.' + team)
    _require(isinstance(raw, bytes) and 0 < len(raw) <= 4 * 1024 ** 2)
    _require(verified.get('profile_sha256') == hashlib.sha256(raw).hexdigest())
    summary = verified.get('public_summary')
    _require(isinstance(summary, dict) and all(summary.get(key) is True for key in (
        'accepted', 'cms_signature_verified', 'apple_chain_verified',
        'certificate_validity_verified', 'development_profile_verified',
        'bundle_team_group_verified', 'target_device_verified', 'minimum_lifetime_verified')))
    return team, bundle, raw


def _unpack(ipa: Path, stage: Path, profile: bytes) -> None:
    """Extract a single app; reject symlinks, traversal and unexpected code bundles."""
    with zipfile.ZipFile(ipa) as archive:
        members = archive.infolist()
        _require(0 < len(members) <= 100000)
        seen, total = set(), 0
        for member in members:
            name = member.filename.rstrip('/')
            path = PurePosixPath(name)
            _require(name and '\\' not in name and ':' not in name and
                     not path.is_absolute() and all(part not in ('', '.', '..') for part in name.split('/')))
            _require(name.casefold() not in seen)
            seen.add(name.casefold())
            _require(name in ('Payload', APP_PATH) or name.startswith(APP_PATH + '/'))
            parts = path.parts[2:]
            _require(not any(part.lower().endswith(('.app', '.appex')) or
                             part in ('Watch', 'PlugIns', 'AppClips') for part in parts))
            kind = stat.S_IFMT(member.external_attr >> 16)
            _require(kind in (0, stat.S_IFREG, stat.S_IFDIR))
            _require(not (member.flag_bits & 1) and 0 <= member.file_size <= MAX_MEMBER)
            total += member.file_size
            _require(total <= MAX_TOTAL)
            if name.lower().endswith(('.mobileprovision', '.provisionprofile')):
                _require(name == APP_PATH + '/embedded.mobileprovision')
        _require(APP_PATH.lower() + '/embedded.mobileprovision' in seen)
        _require(archive.read(APP_PATH + '/embedded.mobileprovision') == profile)
        for member in members:
            if member.filename.rstrip('/') == APP_PATH + '/embedded.mobileprovision':
                continue  # Never write the owner profile to the signing-input tree.
            destination = stage.joinpath(*PurePosixPath(member.filename).parts)
            _require(destination.resolve().is_relative_to(stage))
            if member.is_dir():
                destination.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with archive.open(member) as source, destination.open('xb') as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                destination.chmod(0o700 if member.external_attr >> 16 & 0o111 else 0o600)


def _plist(path: Path) -> dict:
    _require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 8 * 1024 ** 2)
    value = plistlib.loads(path.read_bytes())
    _require(isinstance(value, dict))
    return value


def _executable(folder: Path, info: dict) -> Path:
    name = info.get('CFBundleExecutable')
    _require(isinstance(name, str) and name not in ('', '.', '..') and
             '/' not in name and '\\' not in name and ':' not in name)
    path = folder / name
    _require(path.is_file() and not path.is_symlink())
    return path


def _binary(path: Path, file_type: int) -> None:
    slices = macho(path.read_bytes())
    _require(bool(slices) and all(item['cpu_type'] == ARM64 and item['file_type'] == file_type and
        item['build_versions'] and all(build['platform_id'] == 2 for build in item['build_versions'])
        for item in slices))
    path.chmod(0o700)


def _validate_app(app: Path, bundle: str, native_version: str, build: str) -> tuple[dict, list[Path]]:
    info = _plist(app / 'Info.plist')
    _require(info.get('CFBundleIdentifier') == bundle and info.get('CFBundlePackageType') == 'APPL')
    _require(info.get('CFBundleSupportedPlatforms') == ['iPhoneOS'])
    _require(info.get('CFBundleShortVersionString') == native_version and info.get('CFBundleVersion') == build)
    tasks = info.get('BGTaskSchedulerPermittedIdentifiers')
    _require(isinstance(tasks, list) and len(tasks) == 3 and
             set(tasks) == {bundle + '.refresh', bundle + '.cleanup', bundle + '.upload.*'})
    main = _executable(app, info)
    _binary(main, 2)  # MH_EXECUTE
    known, sign_targets = {main}, []
    for framework in sorted(app.rglob('*.framework'), key=lambda path: len(path.parts), reverse=True):
        _require(framework.is_dir() and not framework.is_symlink())
        framework_info = _plist(framework / 'Info.plist')
        _require(framework_info.get('CFBundlePackageType') == 'FMWK' and
                 framework_info.get('CFBundleSupportedPlatforms') == ['iPhoneOS'])
        executable = _executable(framework, framework_info)
        _binary(executable, 6)  # MH_DYLIB
        known.add(executable)
        sign_targets.append(framework)
    for path in app.rglob('*'):
        if not path.is_file() or path in known:
            continue
        with path.open('rb') as stream:
            is_macho = stream.read(4) in MACHO_MAGICS
        if path.suffix == '.dylib' or is_macho:
            _require(path.suffix == '.dylib')
            _binary(path, 6)
            sign_targets.append(path)
    return info, sorted(sign_targets, key=lambda path: len(path.parts), reverse=True)


def _adhoc(app: Path, targets: list[Path], entitlements: dict, stage: Path) -> None:
    for target in targets:
        _run(['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', str(target)])
    requested = stage / 'requested-entitlements.plist'
    requested.write_bytes(plistlib.dumps(entitlements))
    requested.chmod(0o600)
    _run(['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none',
          '--generate-entitlement-der', '--entitlements', str(requested), str(app)])
    _run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)])
    actual = plistlib.loads(_run(['/usr/bin/codesign', '-d', '--entitlements', ':-', str(app)]))
    _require(actual == entitlements)


def _localized_display_names(app: Path) -> None:
    # These two compiled resources override the main Info.plist display name.
    # Preserve their plist format and every other localization/permission string.
    for locale in ('ar', 'ko'):
        path = app / (locale + '.lproj') / 'InfoPlist.strings'
        value = _plist(path)
        _require(isinstance(value.get('CFBundleDisplayName'), str))
        with path.open('rb') as stream:
            binary = stream.read(8) == b'bplist00'
        value['CFBundleDisplayName'] = 'Chat Timeline'
        path.write_bytes(plistlib.dumps(value, fmt=plistlib.FMT_BINARY if binary else plistlib.FMT_XML,
                                        sort_keys=False))


def package_input(source: Path, output: Path, verified_owner: dict, expected_revision: str) -> None:
    """Write only private IPA + manifest. Caller encrypts both before publication.

Source SHA linkage relies on the caller's fresh, isolated build; HEAD verification
alone cannot prove which source bytes an arbitrary pre-existing binary contains.
"""
    created = False
    try:
        _require(platform.system() == 'Darwin')
        source, output = Path(source).resolve(), Path(output).absolute()
        _require(not output.exists() and not output.is_symlink() and output.parent.is_dir())
        _require(not output.resolve().is_relative_to(source))
        team, bundle, profile = _owner(verified_owner)
        _revision(source, expected_revision)
        versions = json.loads((source / 'versions.json').read_text(encoding='utf-8'))
        version, build = versions.get('app'), os.environ.get('GITHUB_RUN_NUMBER', '')
        _require(isinstance(version, str) and re.fullmatch(r'\d+\.\d+\.\d+', version) is not None)
        _require(re.fullmatch(r'[1-9]\d*', build) is not None)
        ipa = source / 'bazel-bin/Telegram/Telegram.ipa'
        _require(ipa.is_file() and 0 < ipa.stat().st_size <= MAX_TOTAL)
        output.mkdir(mode=0o700)
        created = True
        with tempfile.TemporaryDirectory(prefix='owner-package-', dir=output.parent) as temporary:
            stage = Path(temporary).resolve()
            _unpack(ipa, stage, profile)
            app = stage / APP_PATH
            info, targets = _validate_app(app, bundle, version, build)
            info.update(CFBundleIdentifier=CANONICAL_BUNDLE, CFBundleName='Chat Timeline',
                        CFBundleDisplayName='Chat Timeline', ChatTimelineAuthDiagnosticsEnabled=True)
            # AltServer appends .TEAM to canonical B and each requested App Group.
            # BGTask identifiers deliberately remain final-B values compiled above.
            (app / 'Info.plist').write_bytes(plistlib.dumps(info))
            _localized_display_names(app)
            entitlements = {
                'application-identifier': team + '.' + CANONICAL_BUNDLE,
                'com.apple.developer.team-identifier': team,
                'keychain-access-groups': [team + '.' + CANONICAL_BUNDLE],
                'com.apple.security.application-groups': ['group.' + CANONICAL_BUNDLE],
                'get-task-allow': True,
            }
            _adhoc(app, targets, entitlements, stage)
            _revision(source, expected_revision)
            destination = output / OUTPUT_NAME
            with zipfile.ZipFile(destination, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
                for path in sorted(app.rglob('*')):
                    _require(not path.is_symlink())
                    if path.is_file():
                        _require(not path.name.lower().endswith(('.mobileprovision', '.provisionprofile')))
                        archive.write(path, path.relative_to(stage).as_posix())
            destination.chmod(0o600)
        manifest = {
            'label': 'SIGNING-INPUT-NOT-INSTALLABLE', 'source_revision': expected_revision,
            'version': version, 'build': build, 'target': 'device', 'platform_id': 2,
            'bundle_identifier': CANONICAL_BUNDLE, 'expected_signed_bundle_identifier': bundle,
            'signing': 'ad-hoc canonical request template; requires owner AltServer signing',
            'embedded_profile_included': False, 'apple_private_key_used': False,
            'device_installable_directly': False, 'device_tested': False,
            'auth_diagnostics_enabled': True, 'sha256': sha256(destination),
            'bytes': destination.stat().st_size,
            'identity_mapping_runtime_verified': False,
        }
        manifest_path = output / 'manifest.json'
        manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        manifest_path.chmod(0o600)
    except Exception:
        # Never expose profile bytes, owner identifiers, native output or paths.
        if created:
            try:
                shutil.rmtree(output)
            except OSError:
                # Caller owns a private temporary root and must clean it on failure.
                pass
        raise PackageRejected() from None
