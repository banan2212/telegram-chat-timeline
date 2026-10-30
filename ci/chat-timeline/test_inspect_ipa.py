"""Synthetic archive/parser regression fixtures, not signed or runnable applications."""
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location('inspect_ipa', Path(__file__).with_name('inspect_ipa.py'))
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)
REVISION = 'a' * 40
BUNDLE = 'org.example.timeline'
TEAM = 'TESTTEAM01'


def entitlements(bundle=BUNDLE):
    return {'application-identifier': TEAM + '.' + bundle,
            'com.apple.developer.team-identifier': TEAM,
            'com.apple.security.application-groups': ['group.' + BUNDLE],
            'keychain-access-groups': [TEAM + '.' + BUNDLE]}


def signature(bundle=BUNDLE, wrong_hash=False, xml=None):
    if xml is None:
        xml = plistlib.dumps(entitlements(bundle))
    xml_blob = struct.pack('>II', 0xFADE7171, len(xml) + 8) + xml
    identity = bundle.encode() + b'\0'
    hash_offset = 44 + len(identity) + 5 * 32
    directory = struct.pack('>9I4BI', 0xFADE0C02, hash_offset, 0x20001, 0,
                            hash_offset, 44, 5, 0, 72, 32, 2, 0, 12, 0)
    digest = b'\0' * 32 if wrong_hash else hashlib.sha256(xml_blob).digest()
    directory += identity + digest + b'\0' * (4 * 32)
    length = 28 + len(directory) + len(xml_blob)
    return (struct.pack('>3I4I', 0xFADE0CC0, length, 2, 0, 28, 5, 28 + len(directory)) +
            directory + xml_blob)


def binary(platform_id=2, minimum=26, bundle=BUNDLE, wrong_hash=False, xml=None):
    blob = signature(bundle, wrong_hash, xml)
    header = struct.pack('<8I', 0xFEEDFACF, audit.ARM64, 0, 2, 2, 40, 0, 0)
    build = struct.pack('<6I', 0x32, 24, platform_id, minimum << 16, 27 << 16, 0)
    code_signature = struct.pack('<4I', 0x1D, 16, 72, len(blob))
    return header + build + code_signature + blob


def profile(bundle=BUNDLE):
    allowed = entitlements(bundle)
    allowed['keychain-access-groups'] = [TEAM + '.*']
    return b'synthetic-CMS-not-a-valid-signature' + plistlib.dumps({
        'ExpirationDate': dt.datetime.now() + dt.timedelta(days=2),
        'TeamIdentifier': [TEAM], 'ApplicationIdentifierPrefix': [TEAM], 'Entitlements': allowed,
        'Name': 'PRIVATE-APPLE-ID@example.net', 'ProvisionedDevices': ['PRIVATE-UDID-DO-NOT-PRINT']})


class InspectIPATests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.ipa, self.manifest = self.root / 'candidate.ipa', self.root / 'manifest.json'

    def tearDown(self):
        self.temporary.cleanup()

    def make(self, platform_id=2, minimum=26, plist_minimum='26.0', missing=False,
             wrong_hash=False, extension=False, extra=None, xml=None):
        with zipfile.ZipFile(self.ipa, 'w', compression=zipfile.ZIP_STORED) as archive:
            self.add_bundle(archive, 'Payload/Main.app', BUNDLE, platform_id, minimum,
                            plist_minimum, missing, wrong_hash, xml)
            if extension:
                self.add_bundle(archive, 'Payload/Main.app/PlugIns/Share.appex', BUNDLE + '.Share',
                                2, 26, '26.0', False, False)
            if extra:
                archive.writestr(extra, b'do not extract')
        self.refresh_manifest()

    def add_bundle(self, archive, path, bundle, platform_id, minimum, plist_minimum, missing, wrong_hash, xml=None):
        info = {'CFBundleIdentifier': bundle, 'CFBundleExecutable': 'Executable',
                'CFBundleSupportedPlatforms': ['iPhoneOS'], 'MinimumOSVersion': plist_minimum}
        archive.writestr(path + '/Info.plist', plistlib.dumps(info))
        if not missing:
            archive.writestr(path + '/Executable', binary(platform_id, minimum, bundle, wrong_hash, xml))
        archive.writestr(path + '/embedded.mobileprovision', profile(bundle))

    def refresh_manifest(self):
        self.manifest.write_text(json.dumps({'source_revision': REVISION, 'target': 'device',
            'sha256': audit.sha256(self.ipa), 'bytes': self.ipa.stat().st_size, 'bundle_identifier': BUNDLE}))

    def inspect(self, revision=REVISION):
        return audit.inspect(self.ipa, self.manifest, revision, '26.0')

    def codes(self, report):
        return [item['code'] for item in report['errors']]

    def test_valid_static_metadata_keeps_signing_unknown_and_redacts_profiles(self):
        self.make(extension=True)
        before = audit.sha256(self.ipa)
        report = self.inspect()
        self.assertEqual(report['errors'], [])
        self.assertEqual(report['static_checks'], 'pass')
        self.assertEqual(report['result'], 'unknown')
        self.assertEqual(report['verification']['cms_and_codesign_trust'], 'unknown')
        self.assertEqual(len(report['bundles']), 2)
        self.assertEqual(report['bundles'][0]['macho'][0]['signature']['code_directory_xml_hash'], 'match')
        self.assertTrue(report['bundles'][1]['groups_shared_with_main']['keychain-access-groups'])
        rendered = json.dumps(report)
        self.assertNotIn('PRIVATE-APPLE-ID', rendered)
        self.assertNotIn('PRIVATE-UDID', rendered)
        self.assertEqual(before, audit.sha256(self.ipa))
        self.assertEqual(report['extracted_files'], 0)

    def test_crc_corruption_is_detected_even_with_matching_manifest_hash(self):
        self.make()
        with zipfile.ZipFile(self.ipa) as archive:
            item = archive.getinfo('Payload/Main.app/Executable')
            offset = item.header_offset + 30 + len(item.filename.encode()) + len(item.extra)
        content = bytearray(self.ipa.read_bytes())
        content[offset + 10] ^= 1
        self.ipa.write_bytes(content)
        self.refresh_manifest()
        report = self.inspect()
        self.assertEqual(report['result'], 'fail')
        self.assertIn('archive_or_manifest_invalid', self.codes(report))

    def test_actual_simulator_macho_rejected_despite_device_info_plist(self):
        self.make(platform_id=7)
        self.assertIn('macho_platform_mismatch', self.codes(self.inspect()))

    def test_missing_declared_executable(self):
        self.make(missing=True)
        self.assertIn('declared_executable_missing', self.codes(self.inspect()))

    def test_binary_minimum_os_too_high(self):
        self.make(minimum=27)
        self.assertIn('macho_minimum_os_above_target', self.codes(self.inspect()))

    def test_plist_minimum_os_too_high(self):
        self.make(plist_minimum='27.0')
        self.assertIn('plist_minimum_os_above_target', self.codes(self.inspect()))

    def test_wrong_expected_revision(self):
        self.make()
        self.assertIn('manifest_source_revision_mismatch', self.codes(self.inspect('b' * 40)))

    def test_wrong_manifest_hash(self):
        self.make()
        metadata = json.loads(self.manifest.read_text())
        metadata['sha256'] = '0' * 64
        self.manifest.write_text(json.dumps(metadata))
        self.assertIn('manifest_sha256_mismatch', self.codes(self.inspect()))

    def test_entitlement_code_directory_digest_mismatch(self):
        self.make(wrong_hash=True)
        self.assertIn('xml_entitlements_code_directory_hash_mismatch', self.codes(self.inspect()))

    def test_readable_signed_keychain_wildcard_is_rejected_as_semantic_error(self):
        values = entitlements()
        values['keychain-access-groups'] = ['PRIVATE-SIGNED-GROUP.*']
        xml = plistlib.dumps(values)
        self.assertEqual(plistlib.loads(xml), values)
        self.make(xml=xml)
        before = audit.sha256(self.ipa)
        report = self.inspect()
        self.assertEqual(report['result'], 'fail')
        self.assertEqual(report['static_checks'], 'fail')
        self.assertIn('bundle_inspection_failed', self.codes(report))
        self.assertEqual(report['bundles'][0]['inspection_error'],
                         'Wildcard not permitted in signed entitlement group keychain-access-groups (values omitted)')
        rendered = json.dumps(report)
        self.assertNotIn('Unreadable XML', rendered)
        self.assertNotIn('PRIVATE-SIGNED-GROUP', rendered)
        self.assertEqual(audit.profile_metadata(profile())['entitlements']['keychain-access-groups'],
                         [TEAM + '.*'])
        self.assertEqual(before, audit.sha256(self.ipa))
        self.assertEqual(report['extracted_files'], 0)

    def test_readable_signed_group_with_wrong_type_is_not_xml_corruption(self):
        values = entitlements()
        values['keychain-access-groups'] = 'PRIVATE-GROUP-VALUE'
        self.make(xml=plistlib.dumps(values))
        report = self.inspect()
        self.assertEqual(report['result'], 'fail')
        self.assertEqual(report['bundles'][0]['inspection_error'],
                         'Invalid entitlement group list for keychain-access-groups (contents omitted)')
        self.assertNotIn('PRIVATE-GROUP-VALUE', json.dumps(report))

    def test_malformed_signed_xml_remains_a_parse_failure_without_contents(self):
        self.make(xml=b'<?xml version="1.0"?><plist><dict><key>PRIVATE-XML</dict></plist>')
        report = self.inspect()
        self.assertEqual(report['result'], 'fail')
        self.assertEqual(report['bundles'][0]['inspection_error'],
                         'Unreadable XML entitlements (contents omitted)')
        self.assertNotIn('PRIVATE-XML', json.dumps(report))

    def test_unsafe_path_is_rejected_without_extraction(self):
        self.make(extra='../../escape.txt')
        self.assertEqual(self.inspect()['result'], 'fail')
        self.assertEqual({path.name for path in self.root.iterdir()}, {'candidate.ipa', 'manifest.json'})

    def test_fat_arm64_slice_is_parsed_and_bounds_are_checked(self):
        thin = binary()
        fat = struct.pack('>7I', 0xCAFEBABE, 1, audit.ARM64, 0, 32, len(thin), 2) + b'\0' * 4 + thin
        self.assertEqual(audit.macho(fat)[0]['architecture'], 'arm64')
        with self.assertRaises(audit.InvalidArchive):
            audit.macho(fat[:-1])

    def test_signed_app_group_not_authorized_by_profile(self):
        self.make()
        with zipfile.ZipFile(self.ipa) as archive:
            members = {name: archive.read(name) for name in archive.namelist()}
        raw = members['Payload/Main.app/embedded.mobileprovision']
        raw = raw.replace(b'group.org.example.timeline', b'group.org.example.denied')
        members['Payload/Main.app/embedded.mobileprovision'] = raw
        with zipfile.ZipFile(self.ipa, 'w') as archive:
            for name, contents in members.items():
                archive.writestr(name, contents)
        self.refresh_manifest()
        self.assertIn('signed_group_not_authorized_by_profile:com.apple.security.application-groups',
                      self.codes(self.inspect()))

    def test_legacy_arm64_minimum_without_platform_remains_unknown(self):
        # A legacy minimum-version load command alone is not used to guess simulator/device.
        header = struct.pack('<8I', 0xFEEDFACF, audit.ARM64, 0, 2, 1, 16, 0, 0)
        data = header + struct.pack('<4I', 0x25, 16, 15 << 16, 15 << 16)
        record = {'path': 'synthetic', 'kind': 'main_app', 'macho': audit.macho(data),
                  'supported_platforms': ['iPhoneOS'], 'minimum_os_plist': '15.0'}
        report = {'errors': [], 'warnings': [], 'unknowns': []}
        audit.check_binary(report, record, (26, 0, 0), 'device')
        self.assertEqual(report['errors'], [])
        self.assertIn('macho_platform_not_proven_by_lc_build_version', [item['code'] for item in report['unknowns']])

    def test_cli_unknown_is_not_a_success_exit_code(self):
        self.make()
        completed = subprocess.run([sys.executable, '-B', str(Path(__file__).with_name('inspect_ipa.py')),
            str(self.ipa), '--manifest', str(self.manifest), '--source-revision', REVISION],
            capture_output=True, text=True)
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)['result'], 'unknown')

    def test_corrupt_deflate_stream_is_reported_without_traceback(self):
        with zipfile.ZipFile(self.ipa, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('Payload/Main.app/Info.plist', b'A' * 5000)
        with zipfile.ZipFile(self.ipa) as archive:
            item = archive.infolist()[0]
            offset = item.header_offset + 30 + len(item.filename.encode()) + len(item.extra)
        data = bytearray(self.ipa.read_bytes())
        data[offset] = 0xFF  # Reserved DEFLATE block type.
        self.ipa.write_bytes(data)
        self.refresh_manifest()
        self.assertEqual(self.inspect()['result'], 'fail')

    def test_malformed_profile_xml_is_reported_without_contents(self):
        with self.assertRaisesRegex(audit.InvalidArchive, 'contents omitted'):
            audit.profile_metadata(b'<?xml version="1.0"?><plist><dict><key>SECRET</dict></plist>')

    def test_loose_dylib_cannot_contain_mh_execute(self):
        record = {'path': 'Payload/Main.app/Frameworks/Incorrect.dylib', 'kind': 'dylib',
                  'macho': audit.macho(binary()), 'supported_platforms': ['iPhoneOS'],
                  'minimum_os_plist': None}
        report = {'errors': [], 'warnings': [], 'unknowns': []}
        audit.check_binary(report, record, (26, 0, 0), 'device')
        self.assertIn('library_macho_not_dylib', self.codes(report))

    def test_windows_utf16_manifest_and_invalid_encoding(self):
        self.make()
        data = self.manifest.read_text()
        self.manifest.write_text(data, encoding='utf-16')
        self.assertEqual(self.inspect()['errors'], [])
        self.manifest.write_bytes(b'\xff\xffinvalid encoding')
        self.assertEqual(self.inspect()['result'], 'fail')


if __name__ == '__main__':
    unittest.main()
