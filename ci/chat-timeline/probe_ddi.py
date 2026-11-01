#!/usr/bin/env python3
"""Read fixed public Xcode DDI locations; never attach, extract, download or mount."""
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
import subprocess
import time

XCODE = Path('/Applications/Xcode_27.1.app')
DMGS = (
    XCODE / 'Contents/Resources/CoreDeviceDDIs/iOS_DDI.dmg',
    Path('/Library/Developer/CoreDevice/CandidateDDIs/iOS_DDI.dmg'),
)
MANIFEST = Path('/Library/Developer/DeveloperDiskImages/iOS_DDI/Restore/BuildManifest.plist')
MAX_DMG_BYTES = 1024 ** 3
MAX_MANIFEST_BYTES = 4 * 1024 ** 2


def run_check(args: list[str], env: dict[str, str]) -> tuple[dict, str]:
    try:
        result = subprocess.run(args, env=env, capture_output=True, timeout=60, check=False)
        return {'status': 'passed' if result.returncode == 0 else 'failed',
                'returncode': result.returncode}, result.stdout.decode('utf-8', errors='replace')
    except subprocess.TimeoutExpired:
        return {'status': 'timeout'}, ''
    except OSError:
        return {'status': 'unavailable'}, ''


def inspect_file(path: Path, limit: int) -> dict:
    record = {'path': str(path), 'status': 'missing'}
    try:
        if not path.exists():
            return record
        if path.resolve() != path or not path.is_file():
            record['status'] = 'alias_or_non_regular_file_skipped'
            return record
        before = path.stat()
        record['bytes'] = before.st_size
        if before.st_size > limit:
            record['status'] = 'size_limit_exceeded'
            return record
        digest = hashlib.sha256()
        deadline = time.monotonic() + 60
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
                if time.monotonic() > deadline:
                    record['status'] = 'hash_timeout'
                    return record
        after = path.stat()
    except OSError:
        record['status'] = 'read_failed'
        return record
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        record['status'] = 'changed_during_read'
        return record
    record.update(status='read', sha256=digest.hexdigest())
    return record


def safe_public_version(value: object) -> str | None:
    return value if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9._-]{1,64}', value) else None


def probe() -> dict:
    report = {
        'schema_version': 1,
        'checked_at_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
        'workflow_revision': safe_public_version(os.environ.get('GITHUB_SHA')),
        'run_id': safe_public_version(os.environ.get('GITHUB_RUN_ID')),
        'read_only_probe': True,
        'attached_extracted_downloaded_or_mounted': False,
        'xcode_required': '27.1',
        'xcode_check': {'status': 'unsupported_host'},
        'dmgs': [],
        'expanded_manifest': None,
        'limits': {'per_command_seconds': 60, 'max_dmg_bytes': MAX_DMG_BYTES,
                   'max_manifest_bytes': MAX_MANIFEST_BYTES},
        'interpretation': [
            'hdiutil verify checks image integrity; it does not establish Apple origin.',
            'Apple trust is reported only when anchor-apple codesign and image verification both pass.',
            'Global DDI locations are not proven to originate from the selected Xcode installation.',
            'No payload extraction, device compatibility or device mount has been tested.',
        ],
    }
    if platform.system() != 'Darwin':
        return report
    env = dict(os.environ, DEVELOPER_DIR=str(XCODE / 'Contents/Developer'))
    check, output = run_check(['/usr/bin/xcodebuild', '-version'], env)
    lines = output.strip().splitlines()
    exact = check['status'] == 'passed' and len(lines) == 2 and lines[0] == 'Xcode 27.1'
    report['xcode_check'] = dict(check, exact_version_match=exact,
                                 build=safe_public_version(lines[1].removeprefix('Build version '))
                                 if len(lines) == 2 else None)
    if not exact:
        return report
    for path in DMGS:
        record = inspect_file(path, MAX_DMG_BYTES)
        record['apple_verified'] = False
        if record['status'] == 'read':
            record['image_integrity'], _ = run_check(['/usr/bin/hdiutil', 'verify', str(path)], env)
            record['apple_code_signature'], _ = run_check(
                ['/usr/bin/codesign', '--verify', '--strict', '-R=anchor apple', str(path)], env)
            unchanged = inspect_file(path, MAX_DMG_BYTES)
            record['unchanged_after_checks'] = unchanged.get('sha256') == record['sha256']
            record['apple_verified'] = (record['unchanged_after_checks']
                and record['image_integrity']['status'] == 'passed'
                and record['apple_code_signature']['status'] == 'passed')
        report['dmgs'].append(record)
    manifest = inspect_file(MANIFEST, MAX_MANIFEST_BYTES)
    manifest['apple_authenticity_verified'] = False
    if manifest['status'] == 'read':
        try:
            with MANIFEST.open('rb') as stream:
                raw = stream.read(MAX_MANIFEST_BYTES + 1)
            if hashlib.sha256(raw).hexdigest() != manifest['sha256']:
                raise ValueError('Manifest changed after inspection')
            data = plistlib.loads(raw)
            manifest['product_build_version'] = safe_public_version(data.get('ProductBuildVersion'))
            manifest['product_version'] = safe_public_version(data.get('ProductVersion'))
            identities = data.get('BuildIdentities', [])
            manifest['personalized_dmg_identity_present'] = any(
                isinstance(item, dict) and 'PersonalizedDMG' in item.get('Manifest', {})
                for item in identities)
        except (OSError, ValueError, TypeError, AttributeError, plistlib.InvalidFileException):
            manifest['status'] = 'unreadable_plist'
    report['expanded_manifest'] = manifest
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--summary', type=Path)
    args = parser.parse_args()
    report = probe()
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    exact = report['xcode_check'].get('exact_version_match', False)
    verified = sum(item['apple_verified'] for item in report['dmgs'])
    summary = (f'DDI probe: Xcode 27.1 confirmed: {exact}; '
               f'Apple-verified candidate images: {verified}.\n'
               'Read-only metadata/signature checks; no attach, extraction, download or device operation.\n')
    print(summary, end='')
    if args.summary:
        with args.summary.open('a', encoding='utf-8') as stream:
            stream.write(summary)
    return 0 if exact else 2


if __name__ == '__main__':
    raise SystemExit(main())
