#!/usr/bin/env python3
"""Manual CI preflight and artifact checks. No private Apple credentials or releases."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import zipfile

PIN = 'fb0e62ba8a147f0821da6aa63c09da7d79a10111'
SAMPLE_SHA256 = '51defacf9aa00046e6ef108369632c53e6beb97e3fffd30926f700718b496352'
GIB = 1024 ** 3
PROFILES = ('Telegram', 'BroadcastUpload', 'Intents', 'NotificationContent',
            'NotificationService', 'Share', 'WatchApp', 'WatchExtension', 'Widget')


def command(*args: str, cwd: Path | None = None) -> str:
    return subprocess.check_output(args, cwd=cwd, text=True, stderr=subprocess.PIPE).strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def read_profile(path: Path) -> dict:
    if platform.system() == 'Darwin':
        raw = subprocess.check_output(['openssl', 'smime', '-inform', 'der', '-verify',
                                     '-noverify', '-in', str(path)], stderr=subprocess.PIPE)
    else:
        # Offline plist inspection is not a CMS or codesign verification.
        data = path.read_bytes()
        start, end = data.find(b'<?xml'), data.find(b'</plist>')
        if start < 0 or end < start:
            raise ValueError('No embedded plist')
        raw = data[start:end + len(b'</plist>')]
    return plistlib.loads(raw)


def resource_report(source: Path) -> dict:
    ram = int(command('sysctl', '-n', 'hw.memsize')) if platform.system() == 'Darwin' else None
    return {'ram_gib': round(ram / GIB, 2) if ram is not None else None,
            'free_disk_gib': round(shutil.disk_usage(source).free / GIB, 2)}


def resource_findings(resources: dict) -> tuple[list[str], list[str]]:
    blockers, warnings = [], []
    if resources['ram_gib'] is not None and resources['ram_gib'] < 6:
        blockers.append('Less than 6 GiB RAM: below this CI safety threshold.')
    if resources['free_disk_gib'] < 8:
        blockers.append('Less than 8 GiB free disk: below this CI safety threshold.')
    if resources['ram_gib'] is not None and resources['ram_gib'] < 16:
        warnings.append('Below 16 GiB RAM: jobs=2 may still run out of memory.')
    if resources['free_disk_gib'] < 40:
        warnings.append('Below 40 GiB disk: full sources and Bazel output may exhaust the disk.')
    return blockers, warnings


def api_values(source: Path, api_source: str) -> tuple[str, str]:
    if api_source == 'upstream-test':
        path = source / 'build-system/appstore-configuration.json'
        # Git may convert LF to CRLF on a Windows checkout. Verify canonical bytes.
        if hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest() != SAMPLE_SHA256:
            raise ValueError('Public sample configuration differs from the reviewed upstream SHA-256.')
        data = json.loads(path.read_text())
        values = str(data['api_id']), str(data['api_hash'])
    else:
        values = os.environ.get('TELEGRAM_API_ID', '').strip(), os.environ.get('TELEGRAM_API_HASH', '').strip()
    if not re.fullmatch(r'[1-9][0-9]*', values[0]) or not re.fullmatch(r'[0-9a-fA-F]{32}', values[1]):
        raise ValueError('API ID/hash are missing or invalid; values are not printed.')
    return values


def probe(source: Path, output: Path, target: str, api_source: str, expected: str,
          signing_mode: str = 'fixture', owner_profile_path: Path | None = None,
          expected_device: str | None = None) -> dict:
    native = platform.system() == 'Darwin'
    now = dt.datetime.now(dt.timezone.utc)
    blockers, warnings, device_blockers = [], [], []
    revision = command('git', 'rev-parse', 'HEAD', cwd=source)
    versions = json.loads((source / 'versions.json').read_text())
    report = {'upstream_pin': PIN, 'source_revision': revision,
              'source_repository': os.environ.get('SOURCE_REPOSITORY', 'local'),
              'source_kind': os.environ.get('SOURCE_KIND', 'local'),
              'checked_at': now.isoformat(), 'target': target, 'api_source': api_source,
              'host': platform.system(), 'architecture': platform.machine(),
              'signing_mode': signing_mode,
              'versions': versions, 'blockers': blockers, 'warnings': warnings,
              'device_signing_blockers': device_blockers, 'profiles': [],
              'compiled': False, 'device_tested': False}
    if revision != expected:
        blockers.append('Checked-out revision differs from the exact requested revision.')
    if versions['xcode'] != '27.1' or versions['bazel'].split(':')[0] != '9.2.0':
        blockers.append('Source toolchain pin differs from the reviewed CI configuration.')
    if not native or platform.machine() != 'arm64':
        blockers.append('Actual Apple Silicon macOS runner required; offline probe cannot pass.')
    if native:
        try:
            report['xcode'] = command('xcodebuild', '-version').splitlines()[0].removeprefix('Xcode ')
            report['macos'] = platform.mac_ver()[0]
            if report['xcode'] != versions['xcode']:
                blockers.append('Installed active Xcode does not match versions.json; no override allowed.')
            if report['macos'].split('.')[0] != versions['macos'].split('.')[0]:
                blockers.append('Installed macOS major does not match versions.json.')
            for sdk in ('iphoneos', 'iphonesimulator'):
                report[sdk + '_sdk'] = command('xcrun', '--sdk', sdk, '--show-sdk-version')
            report['simulator_runtimes'] = json.loads(command('xcrun', 'simctl', 'list', 'runtimes', '-j'))
        except (subprocess.SubprocessError, OSError, ValueError) as exc:
            blockers.append('Native toolchain probe failed: ' + type(exc).__name__)
    report['resources'] = resource_report(source)
    rb, rw = resource_findings(report['resources'])
    blockers.extend(rb)
    warnings.extend(rw)
    if signing_mode not in ('fixture', 'owner-deferred'):
        blockers.append('Unknown signing mode.')
    if signing_mode == 'owner-deferred':
        if target != 'device':
            blockers.append('Owner deferred signing is limited to the device target.')
        try:
            from owner_profile import verify_profile, ProfileRejected
            if owner_profile_path is None or not expected_device:
                raise ProfileRejected()
            owner = verify_profile(owner_profile_path, expected_device, now=now)
            report['owner_profile_checks'] = owner['public_summary']
        except (OSError, ValueError, RuntimeError, ImportError, TypeError, KeyError):
            device_blockers.append('Owner profile verification failed; private details are omitted.')
    for name in (PROFILES if signing_mode == 'fixture' else ()):
        path = source / 'build-system/fake-codesigning/profiles' / (name + '.mobileprovision')
        try:
            profile = read_profile(path)
            expiry = profile['ExpirationDate'].replace(tzinfo=dt.timezone.utc)
            report['profiles'].append({'name': name, 'expires_at': expiry.isoformat(), 'sha256': sha256(path)})
            if expiry <= now:
                device_blockers.append(f'{name} public profile expired at {expiry.isoformat()}.')
            elif expiry - now < dt.timedelta(hours=6):
                device_blockers.append(f'{name} public profile has less than six hours validity left.')
            if name == 'Telegram' and not profile['Entitlements'].get('aps-environment'):
                device_blockers.append('Base profile lacks required aps-environment.')
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            device_blockers.append(f'{name} profile could not be checked: {type(exc).__name__}.')
    for name in (('Public.cer', 'SelfSigned.p12') if signing_mode == 'fixture' else ()):
        if not (source / 'build-system/fake-codesigning/certs' / name).is_file():
            device_blockers.append('Missing public fixture ' + name)
    if target == 'device':
        blockers.extend(device_blockers)
    elif device_blockers:
        warnings.append('Device signing is blocked; simulator uses no provisioning profiles or device identity.')
    try:
        api_values(source, api_source)
        report['api_configuration_valid'] = True
    except (OSError, ValueError, KeyError) as exc:
        report['api_configuration_valid'] = False
        blockers.append(str(exc))
    if api_source == 'upstream-test':
        warnings.append('Public upstream API sample: TESTING ONLY, server limited, not for end-user distribution.')
    report['ready_for_selected_build'] = not blockers
    output.mkdir(parents=True, exist_ok=True)
    (output / 'preflight.json').write_text(json.dumps(report, indent=2) + '\n')
    summary = ['## Chat Timeline preflight (not a successful build)',
               f'- Source: `{revision}`; target: `{target}`; API: `{api_source}`.',
               f'- Resources: `{report["resources"]}`.',
               f'- Ready for selected build: **{not blockers}**.']
    summary += ['- BLOCKER: ' + item for item in blockers]
    summary += ['- NOTE: ' + item for item in warnings]
    print('\n'.join(summary))
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
            stream.write('\n'.join(summary) + '\n')
    return report


def prepare(source: Path, output: Path, target: str, api_source: str, expected: str,
            signing_mode: str = 'fixture', owner_profile_path: Path | None = None,
            expected_device: str | None = None) -> None:
    report = probe(source, output, target, api_source, expected,
                   signing_mode, owner_profile_path, expected_device)
    if report['blockers']:
        raise SystemExit('Build stopped by preflight. See preflight.json; no bypass flag exists.')
    api_id, api_hash = api_values(source, api_source)
    if signing_mode == 'owner-deferred':
        from owner_profile import verify_profile
        owner = verify_profile(owner_profile_path, expected_device)
        team_id, bundle_id = owner['team_id'], owner['bundle_id']
    elif target == 'device':
        base = read_profile(source / 'build-system/fake-codesigning/profiles/Telegram.mobileprovision')
        team_id, bundle_id = base['Entitlements']['application-identifier'].split('.', 1)
    else:
        team_id, bundle_id = 'C67CF9S4VU', 'org.banan2212.ChatTimeline'
    config = {'bundle_id': bundle_id, 'team_id': team_id, 'api_id': api_id, 'api_hash': api_hash,
              'app_center_id': '0', 'is_internal_build': 'false', 'is_appstore_build': 'false',
              'appstore_id': '0', 'app_specific_url_scheme': 'chattimeline',
              'premium_iap_product_id': '', 'enable_siri': False, 'enable_icloud': False}
    destination = output / 'configuration.json'
    destination.write_text(json.dumps(config, indent=2) + '\n')
    destination.chmod(0o600)
    print('Generated temporary API configuration; values omitted. No Apple login requested.')


def collect(source: Path, output: Path, target: str, api_source: str, expected: str) -> None:
    revision = command('git', 'rev-parse', 'HEAD', cwd=source)
    if revision != expected:
        raise SystemExit('Source revision changed during the run.')
    ipa = source / 'bazel-bin/Telegram/Telegram.ipa'
    if not ipa.is_file():
        raise SystemExit('No current IPA at bazel-bin/Telegram/Telegram.ipa.')
    with zipfile.ZipFile(ipa) as archive:
        if archive.testzip():
            raise SystemExit('IPA failed CRC validation.')
        info = plistlib.loads(archive.read('Payload/Telegram.app/Info.plist'))
        platform_name = 'iPhoneSimulator' if target == 'simulator' else 'iPhoneOS'
        if info.get('CFBundleSupportedPlatforms') != [platform_name]:
            raise SystemExit('Built artifact platform does not match the requested target.')
        if f'Payload/Telegram.app/{info["CFBundleExecutable"]}' not in archive.namelist():
            raise SystemExit('IPA is missing its declared executable.')
    artifacts = output / 'artifacts'
    artifacts.mkdir(exist_ok=True)
    label = 'simulator-not-for-iPhone' if target == 'simulator' else 'self-signed-requires-resigning'
    destination = artifacts / ('Telegram-' + label + '.ipa')
    shutil.copyfile(ipa, destination)
    manifest = {'upstream_pin': PIN, 'source_revision': revision,
                'source_repository': os.environ.get('SOURCE_REPOSITORY', 'local'),
                'source_kind': os.environ.get('SOURCE_KIND', 'local'), 'target': target,
                'workflow_revision': os.environ.get('GITHUB_SHA'), 'run_id': os.environ.get('GITHUB_RUN_ID'),
                'configuration': 'debug_sim_arm64' if target == 'simulator' else 'release_arm64',
                'api_source': api_source, 'sha256': sha256(destination), 'bytes': destination.stat().st_size,
                'bundle_identifier': info.get('CFBundleIdentifier'), 'minimum_os': info.get('MinimumOSVersion'),
                'version': info.get('CFBundleShortVersionString'), 'build': info.get('CFBundleVersion'),
                'device_installable_directly': False, 'device_tested': False,
                'signing': 'simulator only' if target == 'simulator' else 'public self-signed upstream fixture'}
    (artifacts / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    shutil.copyfile(output / 'preflight.json', artifacts / 'preflight.json')
    print('Collected and hashed the current build. iPhone installation/behavior remain unverified.')


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=('probe', 'prepare', 'resources', 'collect'))
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--target', choices=('simulator', 'device'), default=os.environ.get('BUILD_TARGET', 'simulator'))
    parser.add_argument('--api-source', choices=('upstream-test', 'secrets'), default=os.environ.get('API_SOURCE', 'upstream-test'))
    parser.add_argument('--expected-revision', default=os.environ.get('EXPECTED_REVISION', PIN))
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    if args.command in ('probe', 'prepare', 'collect'):
        globals()[args.command](source, output, args.target, args.api_source, args.expected_revision)
    else:
        output.mkdir(parents=True, exist_ok=True)
        resources = resource_report(source)
        (output / 'resources-after-checkout.json').write_text(json.dumps(resources, indent=2) + '\n')
        submodules = command('git', 'submodule', 'status', '--recursive', cwd=source)
        (output / 'submodules.txt').write_text(submodules + '\n')
        if any(line.startswith(('-', '+', 'U')) for line in submodules.splitlines()):
            raise SystemExit('Some submodules are missing, conflicted or differ from their pinned revision.')
        blockers, warnings = resource_findings(resources)
        for item in blockers + warnings:
            print(item)
        if blockers:
            raise SystemExit('Insufficient resources after source checkout.')


if __name__ == '__main__':
    main()
