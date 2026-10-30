#!/usr/bin/env python3
"""Read-only, portable IPA inspection. No extraction, signing, install or network access.

Binary constants/layouts: Apple xnu mach-o/loader.h, mach/machine.h,
kern/cs_blobs.h and cctools mach-o/fat.h. See README for source links.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import lzma
from pathlib import Path, PurePosixPath
import plistlib
import re
import stat
import struct
import zipfile
import zlib
from xml.parsers.expat import ExpatError

ARM64 = 0x0100000C
PLATFORMS = {1: 'macOS', 2: 'iPhoneOS', 3: 'AppleTVOS', 4: 'WatchOS',
             6: 'MacCatalyst', 7: 'iPhoneSimulator', 8: 'AppleTVSimulator', 9: 'WatchSimulator'}
GROUP_KEYS = ('com.apple.security.application-groups', 'keychain-access-groups')
IDENTIFIER_KEYS = ('application-identifier', 'com.apple.developer.team-identifier')
MAX_MEMBER = 1024 ** 3
MAX_PLIST = 8 * 1024 ** 2


class InvalidArchive(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidArchive(message)


def version(value: str) -> tuple[int, int, int]:
    require(isinstance(value, str) and re.fullmatch(r'\d+(?:\.\d+){0,2}', value) is not None,
            'Invalid OS version metadata')
    parts = [int(part) for part in value.split('.')]
    require(all(part <= 65535 for part in parts), 'OS version exceeds supported range')
    return tuple((parts + [0, 0])[:3])


def encoded_version(number: int) -> str:
    return f'{number >> 16}.{(number >> 8) & 255}.{number & 255}'


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def identifier(value, wildcard: bool = False) -> str:
    # Prevent unrelated profile fields, email addresses or arbitrary text leaking to reports.
    pattern = r'[A-Za-z0-9][A-Za-z0-9.\-]{0,254}' + (r'\*?' if wildcard else '')
    require(isinstance(value, str) and re.fullmatch(pattern, value) is not None,
            'Invalid identifier metadata (value omitted)')
    return value


def entitlement_subset(data: dict, wildcard: bool = False) -> dict:
    require(isinstance(data, dict), 'Entitlements are not a dictionary')
    result = {}
    for key in IDENTIFIER_KEYS:
        if key in data:
            result[key] = identifier(data[key], wildcard)
    for key in GROUP_KEYS:
        if key in data:
            require(isinstance(data[key], list) and len(data[key]) <= 256,
                    f'Invalid entitlement group list for {key} (contents omitted)')
            require(wildcard or not any(isinstance(item, str) and '*' in item for item in data[key]),
                    f'Wildcard not permitted in signed entitlement group {key} (values omitted)')
            result[key] = [identifier(item, wildcard) for item in data[key]]
    return result


def matches(pattern: str, value: str) -> bool:
    return value.startswith(pattern[:-1]) if pattern.endswith('*') else pattern == value


def embedded_entitlements(blob: bytes) -> dict:
    """Parse the indexed XML slot; check its CodeDirectory digest, never CMS trust."""
    require(len(blob) >= 12, 'Truncated code-signature SuperBlob')
    magic, length, count = struct.unpack_from('>III', blob)
    require(magic == 0xFADE0CC0 and 12 <= length <= len(blob), 'Invalid code-signature SuperBlob')
    require(count <= 64 and 12 + count * 8 <= length, 'Invalid signature blob index')
    slots, ranges = {}, []
    for index in range(count):
        slot, offset = struct.unpack_from('>II', blob, 12 + index * 8)
        require(slot not in slots and offset >= 12 + count * 8 and offset + 8 <= length,
                'Invalid or duplicate signature blob slot')
        blob_magic, size = struct.unpack_from('>II', blob, offset)
        require(size >= 8 and offset + size <= length, 'Signature slot outside SuperBlob')
        require(not any(offset < end and start < offset + size for start, end in ranges),
                'Overlapping signature slots')
        ranges.append((offset, offset + size))
        slots[slot] = (blob_magic, blob[offset:offset + size])
    result = {'xml_status': 'absent', 'xml': {}, 'code_directory_xml_hash': 'unknown',
              'der_status': 'present_not_interpreted' if 7 in slots else 'absent',
              'cms_signature_verification': 'not_performed'}
    if 5 not in slots:
        return result
    magic, xml_blob = slots[5]
    require(magic == 0xFADE7171 and len(xml_blob) <= MAX_PLIST, 'Invalid XML entitlement slot')
    try:
        parsed = plistlib.loads(xml_blob[8:])
    except (plistlib.InvalidFileException, ExpatError, ValueError, TypeError, OverflowError) as exc:
        raise InvalidArchive('Unreadable XML entitlements (contents omitted)') from exc
    # A readable plist can still contain invalid signed entitlements. Keep those semantic
    # failures distinct from XML corruption; provisioning-profile wildcards stay separate.
    result['xml'] = entitlement_subset(parsed)
    result['xml_status'] = 'parsed_untrusted'
    checks, unknown = [], False
    for slot, (magic, directory) in slots.items():
        if slot != 0 and not 0x1000 <= slot < 0x1005:
            continue
        require(magic == 0xFADE0C02 and len(directory) >= 44, 'Invalid CodeDirectory')
        hash_offset, _, special_slots = struct.unpack_from('>III', directory, 16)
        hash_size, hash_type = directory[36], directory[37]
        if special_slots < 5:
            unknown = True
            continue
        algorithm = {1: ('sha1', 20), 2: ('sha256', 32), 3: ('sha256', 20), 4: ('sha384', 48)}.get(hash_type)
        if algorithm is None:
            unknown = True
            continue
        require(hash_size == algorithm[1] and special_slots <= 4096,
                'Unsupported CodeDirectory hash layout')
        require(hash_offset - special_slots * hash_size >= 44 and hash_offset <= len(directory),
                'CodeDirectory special-slot hashes outside blob')
        start = hash_offset - 5 * hash_size
        expected = directory[start:start + hash_size]
        actual = hashlib.new(algorithm[0], xml_blob).digest()[:hash_size]
        checks.append(expected == actual)
    if checks:
        result['code_directory_xml_hash'] = ('mismatch' if not all(checks) else
                                              'match_with_unchecked_directories' if unknown else 'match')
    return result


def thin_macho(data: bytes) -> dict:
    require(len(data) >= 28, 'Truncated Mach-O header')
    formats = {b'\xcf\xfa\xed\xfe': ('<', 32), b'\xfe\xed\xfa\xcf': ('>', 32),
               b'\xce\xfa\xed\xfe': ('<', 28), b'\xfe\xed\xfa\xce': ('>', 28)}
    require(data[:4] in formats, 'Executable is not a supported Mach-O file')
    endian, header_size = formats[data[:4]]
    require(len(data) >= header_size, 'Truncated Mach-O header')
    _, cpu, subtype, filetype, count, size, _ = struct.unpack_from(endian + '7I', data)
    require(count <= 16384 and header_size + size <= len(data), 'Mach-O load commands outside file')
    position, end = header_size, header_size + size
    builds, legacy_minimum, signatures = [], None, []
    for _ in range(count):
        require(position + 8 <= end, 'Truncated load command')
        command, command_size = struct.unpack_from(endian + 'II', data, position)
        require(command_size >= 8 and command_size % (8 if header_size == 32 else 4) == 0
                and position + command_size <= end, 'Invalid load-command size')
        if command == 0x32:  # LC_BUILD_VERSION
            require(command_size >= 24, 'Truncated LC_BUILD_VERSION')
            platform_id, minimum, sdk, tools = struct.unpack_from(endian + '4I', data, position + 8)
            require(24 + tools * 8 <= command_size, 'LC_BUILD_VERSION tools exceed command')
            builds.append({'platform_id': platform_id, 'platform': PLATFORMS.get(platform_id, 'unknown'),
                           'minimum_os': encoded_version(minimum), 'sdk': encoded_version(sdk)})
        elif command == 0x25:  # LC_VERSION_MIN_IPHONEOS: insufficient platform evidence alone.
            require(command_size >= 16, 'Truncated LC_VERSION_MIN_IPHONEOS')
            legacy_minimum = encoded_version(struct.unpack_from(endian + 'I', data, position + 8)[0])
        elif command == 0x1D:  # LC_CODE_SIGNATURE, offsets are relative to this Mach-O slice.
            require(command_size >= 16, 'Truncated LC_CODE_SIGNATURE')
            offset, length = struct.unpack_from(endian + 'II', data, position + 8)
            require(offset >= end and length > 0 and offset + length <= len(data), 'Signature outside Mach-O slice')
            signatures.append(embedded_entitlements(data[offset:offset + length]))
        position += command_size
    require(position == end, 'Mach-O command count and total size disagree')
    require(len(signatures) <= 1, 'Multiple LC_CODE_SIGNATURE commands')
    return {'cpu_type': cpu, 'cpu_subtype': subtype, 'file_type': filetype,
            'architecture': 'arm64' if cpu == ARM64 else 'other', 'build_versions': builds,
            'legacy_iphoneos_minimum': legacy_minimum,
            'signature': signatures[0] if signatures else {'xml_status': 'absent', 'xml': {},
                'code_directory_xml_hash': 'unknown', 'der_status': 'unknown', 'cms_signature_verification': 'not_performed'}}


def macho(data: bytes) -> list[dict]:
    fats = {b'\xca\xfe\xba\xbe': ('>', False), b'\xbe\xba\xfe\xca': ('<', False),
            b'\xca\xfe\xba\xbf': ('>', True), b'\xbf\xba\xfe\xca': ('<', True)}
    if data[:4] not in fats:
        return [thin_macho(data)]
    endian, wide = fats[data[:4]]
    require(len(data) >= 8, 'Truncated fat Mach-O')
    count = struct.unpack_from(endian + 'I', data, 4)[0]
    stride = 32 if wide else 20
    require(0 < count <= 32 and 8 + count * stride <= len(data), 'Invalid fat Mach-O architecture table')
    slices, ranges = [], []
    for index in range(count):
        offset = 8 + index * stride
        cpu, subtype, start, size, alignment = struct.unpack_from(endian + ('IIQQI' if wide else 'IIIII'), data, offset)
        require(start >= 8 + count * stride and size >= 28 and start + size <= len(data), 'Fat slice outside file')
        require(alignment < 64 and start % (1 << alignment) == 0, 'Misaligned fat slice')
        require(not any(start < end and previous < start + size for previous, end in ranges), 'Overlapping fat slices')
        ranges.append((start, start + size))
        parsed = thin_macho(data[start:start + size])
        require(parsed['cpu_type'] == cpu and parsed['cpu_subtype'] == subtype, 'Fat and thin CPU metadata disagree')
        slices.append(parsed)
    return slices


def profile_metadata(raw: bytes) -> dict:
    # CMS is deliberately not decoded/trusted. Apple's embedded XML plist is inspected only.
    require(len(raw) <= MAX_PLIST, 'Embedded profile too large')
    start, end = raw.find(b'<?xml'), raw.find(b'</plist>')
    require(start >= 0 and end > start and raw.find(b'<?xml', start + 1) == -1,
            'No unambiguous embedded profile XML')
    try:
        profile = plistlib.loads(raw[start:end + 8])
        require(isinstance(profile, dict), 'Profile plist is not a dictionary')
        expiry = profile.get('ExpirationDate')
        require(isinstance(expiry, dt.datetime), 'Profile expiration missing')
        expiry = expiry.replace(tzinfo=dt.timezone.utc)
        teams = profile.get('TeamIdentifier', [])
        prefixes = profile.get('ApplicationIdentifierPrefix', [])
        require(isinstance(teams, list) and isinstance(prefixes, list), 'Invalid profile identifier lists')
        return {'status': 'embedded_xml_parsed_untrusted', 'cms_signature_verification': 'not_performed',
                'expires_at': expiry.isoformat(), 'expired': expiry <= dt.datetime.now(dt.timezone.utc),
                'team_identifiers': [identifier(item) for item in teams],
                'application_identifier_prefixes': [identifier(item) for item in prefixes],
                'entitlements': entitlement_subset(profile.get('Entitlements', {}), wildcard=True)}
    except (plistlib.InvalidFileException, ExpatError, TypeError, ValueError, OverflowError) as exc:
        raise InvalidArchive('Unreadable profile metadata (contents omitted)') from exc


def issue(report: dict, level: str, code: str, path: str | None = None) -> None:
    entry = {'code': code}
    if path:
        entry['bundle_or_member'] = path
    if entry not in report[level]:
        report[level].append(entry)


def inspect(ipa: Path, manifest: Path, revision: str, target_os: str = '26.0', target: str = 'device') -> dict:
    target_version = version(target_os)
    report = {'audit_version': 1, 'expected_source_revision': revision, 'target': target,
              'target_ios': target_os, 'errors': [], 'warnings': [], 'unknowns': [], 'bundles': [], 'libraries': [],
              'verification': {'cms_and_codesign_trust': 'unknown', 'code_pages_and_resources': 'unknown',
                               'installation': 'unknown', 'runtime_behavior': 'unknown'},
              'read_only': True, 'extracted_files': 0}
    try:
        require(re.fullmatch(r'[0-9a-fA-F]{40}', revision) is not None, 'Expected revision must be a full SHA-1')
        require(manifest.stat().st_size <= MAX_PLIST, 'Manifest exceeds metadata size limit')
        manifest_bytes = manifest.read_bytes()
        encoding = 'utf-16' if manifest_bytes.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig'
        metadata = json.loads(manifest_bytes.decode(encoding))
        require(isinstance(metadata, dict), 'Manifest must be an object')
        actual_hash = sha256(ipa)
        report['artifact_sha256'] = actual_hash
        report['artifact_bytes'] = ipa.stat().st_size
        report['source_revision_matches'] = metadata.get('source_revision') == revision
        report['manifest_hash_matches'] = metadata.get('sha256') == actual_hash
        if not report['source_revision_matches']:
            issue(report, 'errors', 'manifest_source_revision_mismatch')
        if not report['manifest_hash_matches']:
            issue(report, 'errors', 'manifest_sha256_mismatch')
        if metadata.get('bytes') != ipa.stat().st_size:
            issue(report, 'errors', 'manifest_size_mismatch')
        if metadata.get('target') != target:
            issue(report, 'errors', 'manifest_target_mismatch')
        report['provenance_limit'] = 'Matching manifest is self-reported metadata, not signed source attestation.'
        with zipfile.ZipFile(ipa) as archive:
            infos = archive.infolist()
            require(len(infos) <= 100000 and sum(item.file_size for item in infos) <= 8 * 1024 ** 3,
                    'Archive exceeds inspection size limits')
            names, folded = {}, set()
            for item in infos:
                path = item.filename.rstrip('/')
                parts = path.split('/')
                require(path and not path.startswith('/') and '\\' not in path and ':' not in path
                        and all(part not in ('', '.', '..') for part in parts), 'Unsafe ZIP member path (value omitted)')
                require(item.filename not in names and path.casefold() not in folded, 'Duplicate or case-colliding ZIP members')
                require(not item.flag_bits & 1 and item.file_size <= MAX_MEMBER, 'Encrypted or oversized ZIP member')
                names[item.filename] = item
                folded.add(path.casefold())
            require(archive.testzip() is None, 'ZIP CRC check failed')
            report['zip_crc'] = 'pass'

            def read(name: str, limit: int = MAX_MEMBER) -> bytes:
                require(name in names, 'Required archive member missing')
                item = names[name]
                require(item.file_size <= limit and not stat.S_ISLNK(item.external_attr >> 16), 'Inspected member is oversized or a symlink')
                return archive.read(item)

            bundle_paths = set()
            for name in names:
                parts = PurePosixPath(name).parts
                if parts and parts[0] == 'Payload':
                    for index, part in enumerate(parts[1:], 1):
                        if part.endswith(('.app', '.appex', '.framework')):
                            bundle_paths.add('/'.join(parts[:index + 1]))
            main_paths = sorted(path for path in bundle_paths if path.count('/') == 1 and path.endswith('.app'))
            require(len(main_paths) == 1, 'Expected exactly one top-level Payload app')
            main_path = main_paths[0]
            executed = set()
            for path in sorted(bundle_paths, key=lambda value: (value.count('/'), value)):
                record = {'path': path, 'kind': 'main_app' if path == main_path else
                          'extension' if path.endswith('.appex') else 'framework' if path.endswith('.framework') else 'nested_app'}
                report['bundles'].append(record)
                try:
                    info = plistlib.loads(read(path + '/Info.plist', MAX_PLIST))
                    require(isinstance(info, dict), 'Info.plist must be a dictionary')
                    record['bundle_identifier'] = identifier(info.get('CFBundleIdentifier'))
                    supported_platforms = info.get('CFBundleSupportedPlatforms')
                    require(isinstance(supported_platforms, list) and supported_platforms
                            and all(p in PLATFORMS.values() for p in supported_platforms),
                            'Missing or unsupported bundle platform metadata')
                    record['supported_platforms'] = supported_platforms
                    executable = info.get('CFBundleExecutable')
                    require(isinstance(executable, str) and executable not in ('', '.', '..')
                            and '/' not in executable and '\\' not in executable and ':' not in executable,
                            'Invalid CFBundleExecutable')
                    executable_path = path + '/' + executable
                    if executable_path not in names:
                        issue(report, 'errors', 'declared_executable_missing', path)
                        continue
                    executed.add(executable_path)
                    record['executable'] = executable
                    minimum_os = info.get('MinimumOSVersion')
                    if minimum_os is not None:
                        version(minimum_os)
                    record['minimum_os_plist'] = minimum_os
                    record['macho'] = macho(read(executable_path))
                    check_binary(report, record, target_version, target)
                    profile_path = path + '/embedded.mobileprovision'
                    record['profile'] = profile_metadata(read(profile_path, MAX_PLIST)) if profile_path in names else {'status': 'absent'}
                    check_entitlements(report, record)
                except (InvalidArchive, plistlib.InvalidFileException, ExpatError, KeyError, TypeError, struct.error, ValueError) as exc:
                    issue(report, 'errors', 'bundle_inspection_failed', path)
                    record['inspection_error'] = str(exc) if isinstance(exc, InvalidArchive) else type(exc).__name__
            # Inspect loose dylibs as well: a device app with a simulator framework is still invalid.
            for name in sorted(names):
                if name.startswith(main_path + '/') and name.endswith('.dylib') and name not in executed:
                    parents = [item for item in report['bundles'] if name.startswith(item['path'] + '/')]
                    parent = max(parents, key=lambda item: len(item['path'])) if parents else {}
                    record = {'path': name, 'kind': 'dylib', 'supported_platforms': parent.get('supported_platforms'),
                              'minimum_os_plist': None}
                    report['libraries'].append(record)
                    try:
                        record['macho'] = macho(read(name))
                        check_binary(report, record, target_version, target)
                    except (InvalidArchive, struct.error, ValueError) as exc:
                        issue(report, 'errors', 'dylib_inspection_failed', name)
                        record['inspection_error'] = str(exc) if isinstance(exc, InvalidArchive) else type(exc).__name__
            check_bundle_relationships(report, metadata)
    except (OSError, zipfile.BadZipFile, zlib.error, lzma.LZMAError, EOFError,
            RuntimeError, InvalidArchive, UnicodeError, json.JSONDecodeError, NotImplementedError) as exc:
        # Never echo parser contents or arbitrary profile/manifest values.
        issue(report, 'errors', 'archive_or_manifest_invalid')
        report['inspection_error'] = str(exc) if isinstance(exc, InvalidArchive) else type(exc).__name__
    report['static_checks'] = 'fail' if report['errors'] else 'unknown' if report['unknowns'] else 'pass'
    # Signing/installation are mandatory unresolved gates, never an overall pass.
    report['result'] = 'fail' if report['errors'] else 'unknown'
    return report


def check_binary(report: dict, record: dict, target_version: tuple, target: str) -> None:
    path = record['path']
    expected = 2 if target == 'device' else 7
    supported = record.get('supported_platforms')
    companion = record['kind'] != 'main_app' and supported in (['WatchOS'], ['WatchSimulator'])
    if companion:
        expected = 4 if target == 'device' else 9
        issue(report, 'unknowns', 'watchos_companion_compatibility_not_checked_against_ios_target', path)
    if supported and supported != [PLATFORMS[expected]]:
        issue(report, 'errors', 'bundle_platform_not_target_ios', path)
    accepted_cpus = (ARM64, 0x0200000C) if companion else (ARM64,)
    arm_slices = [item for item in record['macho'] if item['cpu_type'] in accepted_cpus]
    if not arm_slices:
        issue(report, 'errors', 'no_arm64_macho_slice', path)
    minimum_plist = record.get('minimum_os_plist')
    if not companion and minimum_plist is not None and version(minimum_plist) > target_version:
        issue(report, 'errors', 'plist_minimum_os_above_target', path)
    if record['kind'] in ('main_app', 'extension', 'nested_app') and minimum_plist is None:
        issue(report, 'unknowns', 'bundle_minimum_os_missing', path)
    for item in record['macho']:
        if item['cpu_type'] != ARM64:
            issue(report, 'warnings', 'additional_non_arm64_slice', path)
        builds = item['build_versions']
        if not builds:
            issue(report, 'unknowns', 'macho_platform_not_proven_by_lc_build_version', path)
            if not companion and item['legacy_iphoneos_minimum'] and version(item['legacy_iphoneos_minimum']) > target_version:
                issue(report, 'errors', 'macho_minimum_os_above_target', path)
        for build in builds:
            if build['platform_id'] != expected:
                issue(report, 'errors', 'macho_platform_mismatch', path)
            if not companion and version(build['minimum_os']) > target_version:
                issue(report, 'errors', 'macho_minimum_os_above_target', path)
            if minimum_plist is not None and version(minimum_plist) < version(build['minimum_os']):
                issue(report, 'errors', 'plist_minimum_below_binary_minimum', path)
        if record['kind'] in ('main_app', 'extension', 'nested_app') and item['file_type'] != 2:
            issue(report, 'errors', 'bundle_macho_not_executable', path)
        if record['kind'] in ('framework', 'dylib') and item['file_type'] != 6:
            issue(report, 'errors', 'library_macho_not_dylib', path)
        signature = item['signature']
        if signature['code_directory_xml_hash'] == 'mismatch':
            issue(report, 'errors', 'xml_entitlements_code_directory_hash_mismatch', path)
        if signature['der_status'] == 'present_not_interpreted':
            issue(report, 'unknowns', 'der_entitlements_not_interpreted_or_compared', path)
        if signature['xml_status'] != 'parsed_untrusted' and record['kind'] in ('main_app', 'extension', 'nested_app'):
            issue(report, 'unknowns', 'signed_xml_entitlements_unavailable', path)
        elif signature['xml_status'] == 'parsed_untrusted' and signature['code_directory_xml_hash'] != 'match':
            issue(report, 'unknowns', 'xml_entitlements_hash_not_fully_verified', path)


def check_entitlements(report: dict, record: dict) -> None:
    path, profile = record['path'], record['profile']
    if record['kind'] == 'framework':
        return
    if profile['status'] == 'absent':
        issue(report, 'unknowns', 'embedded_profile_missing', path)
        return
    if profile['expired']:
        issue(report, 'errors', 'embedded_profile_expired', path)
    allowed = profile['entitlements']
    bundle_id = record['bundle_identifier']
    app_id = allowed.get('application-identifier')
    prefixes = profile['application_identifier_prefixes']
    if not app_id or not any(matches(app_id, prefix + '.' + bundle_id) for prefix in prefixes):
        issue(report, 'errors', 'profile_application_identifier_mismatch', path)
    for item in record['macho']:
        signature = item['signature']
        if signature['xml_status'] != 'parsed_untrusted':
            continue
        signed = signature['xml']
        signed_app_id = signed.get('application-identifier')
        if not signed_app_id or not any(signed_app_id == prefix + '.' + bundle_id for prefix in prefixes):
            issue(report, 'errors', 'signed_application_identifier_mismatch', path)
        signed_team = signed.get('com.apple.developer.team-identifier')
        if not signed_team:
            issue(report, 'unknowns', 'signed_team_identifier_missing', path)
        elif signed_team not in profile['team_identifiers'] or (
                allowed.get('com.apple.developer.team-identifier') not in (None, signed_team)):
            issue(report, 'errors', 'signed_team_profile_mismatch', path)
        for key in GROUP_KEYS:
            for group in signed.get(key, []):
                if not any(matches(pattern, group) for pattern in allowed.get(key, [])):
                    issue(report, 'errors', 'signed_group_not_authorized_by_profile:' + key, path)


def check_bundle_relationships(report: dict, manifest: dict) -> None:
    main = next((item for item in report['bundles'] if item['kind'] == 'main_app'), None)
    if not main or 'bundle_identifier' not in main:
        return
    main_id = main['bundle_identifier']
    if manifest.get('bundle_identifier') != main_id:
        issue(report, 'errors', 'manifest_main_bundle_identifier_mismatch')
    seen = set()
    main_entitlements = next((s['signature']['xml'] for s in main.get('macho', [])
                              if s['signature']['xml_status'] == 'parsed_untrusted'), {})
    main_teams = main.get('profile', {}).get('team_identifiers', [])
    for record in report['bundles']:
        bundle_id = record.get('bundle_identifier')
        if not bundle_id:
            continue
        if bundle_id.casefold() in seen:
            issue(report, 'errors', 'duplicate_bundle_identifier', record['path'])
        seen.add(bundle_id.casefold())
        if record['kind'] not in ('extension', 'nested_app'):
            continue
        if not bundle_id.startswith(main_id + '.'):
            issue(report, 'errors', 'nested_bundle_identifier_not_under_host', record['path'])
        teams = record.get('profile', {}).get('team_identifiers', [])
        if main_teams and teams and set(main_teams).isdisjoint(teams):
            issue(report, 'errors', 'nested_profile_team_differs_from_host', record['path'])
        entitlements = next((s['signature']['xml'] for s in record.get('macho', [])
                              if s['signature']['xml_status'] == 'parsed_untrusted'), {})
        record['groups_shared_with_main'] = {key: sorted(set(entitlements.get(key, [])) &
                                                        set(main_entitlements.get(key, []))) for key in GROUP_KEYS}
        for key in GROUP_KEYS:
            if entitlements.get(key) and main_entitlements.get(key) and not record['groups_shared_with_main'][key]:
                issue(report, 'warnings', 'no_shared_host_group:' + key, record['path'])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ipa', type=Path)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--source-revision', required=True, help='Expected full 40-character commit SHA')
    parser.add_argument('--target-ios', default='26.0')
    parser.add_argument('--target', choices=('device', 'simulator'), default='device')
    parser.add_argument('--output', type=Path, help='Optional privacy-limited JSON report (no archive extraction)')
    args = parser.parse_args()
    try:
        version(args.target_ios)
    except InvalidArchive as exc:
        parser.error(str(exc))
    report = inspect(args.ipa, args.manifest, args.source_revision, args.target_ios, args.target)
    rendered = json.dumps(report, indent=2, ensure_ascii=True) + '\n'
    if args.output:
        # Refuse accidental overwriting of either input; inspect remains read-only.
        if args.output.resolve() in (args.ipa.resolve(), args.manifest.resolve()):
            parser.error('Output must differ from both input files')
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding='utf-8')
    print(rendered, end='')
    return {'pass': 0, 'fail': 1, 'unknown': 2}[report['result']]


if __name__ == '__main__':
    raise SystemExit(main())
