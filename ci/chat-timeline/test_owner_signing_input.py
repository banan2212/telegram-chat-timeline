"""Synthetic offline packaging tests; mocked codesign is not native signature proof."""
import copy
import hashlib
import json
import os
from pathlib import Path
import plistlib
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import owner_signing_input as packaging

REVISION = 'a' * 40
TEAM = 'TESTTEAM01'
BUNDLE = packaging.CANONICAL_BUNDLE + '.' + TEAM
PROFILE = b'synthetic verified profile fixture, not CMS or an installable profile'


def binary(platform_id=2, file_type=2):
    return (struct.pack('<8I', 0xFEEDFACF, packaging.ARM64, 0, file_type, 1, 24, 0, 0) +
            struct.pack('<6I', 0x32, 24, platform_id, 15 << 16, 27 << 16, 0))


class OwnerSigningInputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source, self.output = self.root / 'source', self.root / 'private-output'
        self.source.mkdir()
        (self.source / 'versions.json').write_text(json.dumps({'app': '13.1.1'}))
        self.ipa = self.source / 'bazel-bin/Telegram/Telegram.ipa'
        self.ipa.parent.mkdir(parents=True)
        self.info = {
            'CFBundleIdentifier': BUNDLE, 'CFBundleExecutable': 'Telegram',
            'CFBundleSupportedPlatforms': ['iPhoneOS'], 'CFBundlePackageType': 'APPL',
            'CFBundleShortVersionString': '13.1.1', 'CFBundleVersion': '42',
            'BGTaskSchedulerPermittedIdentifiers': [BUNDLE + '.refresh', BUNDLE + '.cleanup', BUNDLE + '.upload.*'],
        }
        self.owner = {
            'team_id': TEAM, 'bundle_id': BUNDLE, 'profile_data': PROFILE,
            'profile_sha256': hashlib.sha256(PROFILE).hexdigest(),
            'public_summary': dict.fromkeys((
                'accepted', 'cms_signature_verified', 'apple_chain_verified',
                'certificate_validity_verified', 'development_profile_verified',
                'bundle_team_group_verified', 'target_device_verified', 'minimum_lifetime_verified'), True),
        }
        self.members = {
            packaging.APP_PATH + '/Info.plist': plistlib.dumps(self.info),
            packaging.APP_PATH + '/Telegram': binary(),
            packaging.APP_PATH + '/embedded.mobileprovision': PROFILE,
            packaging.APP_PATH + '/Frameworks/Sample.framework/Info.plist': plistlib.dumps({
                'CFBundleIdentifier': BUNDLE + '.Sample', 'CFBundleExecutable': 'Sample',
                'CFBundlePackageType': 'FMWK', 'CFBundleSupportedPlatforms': ['iPhoneOS']}),
            packaging.APP_PATH + '/Frameworks/Sample.framework/Sample': binary(file_type=6),
            packaging.APP_PATH + '/Frameworks/libExample.dylib': binary(file_type=6),
        }
        for locale, name in (('ar', '\u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645'), ('ko', '\ud154\ub808\uadf8\ub7a8')):
            self.members[packaging.APP_PATH + '/' + locale + '.lproj/InfoPlist.strings'] = plistlib.dumps({
                'CFBundleDisplayName': name, 'NSCameraUsageDescription': 'Preserve camera explanation ' + locale,
            }, fmt=plistlib.FMT_BINARY)
        self.commands, self.requested = [], None
        self.revision, self.fail_signing, self.wrong_entitlements = REVISION, False, False
        self.mac = patch.object(packaging.platform, 'system', return_value='Darwin')
        self.process = patch.object(packaging.subprocess, 'run', side_effect=self.run_command)
        self.environment = patch.dict(os.environ, {'GITHUB_RUN_NUMBER': '42'})
        for context in (self.mac, self.process, self.environment):
            context.start()
            self.addCleanup(context.stop)
        self.addCleanup(self.temporary.cleanup)

    def run_command(self, arguments, **kwargs):
        self.commands.append(arguments)
        self.assertEqual(kwargs['stdout'], subprocess.PIPE)
        self.assertEqual(kwargs['stderr'], subprocess.PIPE)
        self.assertEqual(kwargs['timeout'], 120)
        output, result = b'', 0
        if arguments[:3] == ['git', 'rev-parse', 'HEAD']:
            output = self.revision.encode('ascii') + b'\n'
        elif arguments[0] == '/usr/bin/codesign':
            if self.fail_signing:
                return subprocess.CompletedProcess(arguments, 2, b'', b'private native failure')
            if '--sign' in arguments:
                self.assertEqual(arguments[arguments.index('--sign') + 1], '-')
                self.assertIn('--timestamp=none', arguments)
                if '--entitlements' in arguments:
                    self.requested = plistlib.loads(Path(arguments[arguments.index('--entitlements') + 1]).read_bytes())
                    sealed_info = plistlib.loads((Path(arguments[-1]) / 'Info.plist').read_bytes())
                    self.assertIs(sealed_info['ChatTimelineQRLoginEnabled'], True)
                    for locale in ('ar', 'ko'):
                        localized = plistlib.loads((Path(arguments[-1]) / (locale + '.lproj') / 'InfoPlist.strings').read_bytes())
                        self.assertEqual(localized['CFBundleDisplayName'], 'Chat Timeline')
            elif '-d' in arguments:
                output = plistlib.dumps({} if self.wrong_entitlements else self.requested)
            else:
                self.assertIn('--verify', arguments)
                self.assertIn('--deep', arguments)
                self.assertIn('--strict', arguments)
        else:
            self.fail('Unexpected subprocess')
        return subprocess.CompletedProcess(arguments, result, output, b'')

    def write_ipa(self, extra=None):
        with zipfile.ZipFile(self.ipa, 'w') as archive:
            for name, value in self.members.items():
                archive.writestr(name, value)
            if extra:
                archive.writestr(*extra)

    def package(self):
        self.write_ipa()
        packaging.package_input(self.source, self.output, self.owner, REVISION)

    def rejected(self):
        with self.assertRaisesRegex(packaging.PackageRejected, '^owner_signing_input_rejected$'):
            packaging.package_input(self.source, self.output, self.owner, REVISION)
        self.assertFalse(self.output.exists())

    def test_canonical_handoff_preserves_final_background_ids_and_removes_profile(self):
        self.package()
        self.assertEqual({path.name for path in self.output.iterdir()}, {packaging.OUTPUT_NAME, 'manifest.json'})
        with zipfile.ZipFile(self.output / packaging.OUTPUT_NAME) as archive:
            info = plistlib.loads(archive.read(packaging.APP_PATH + '/Info.plist'))
            self.assertEqual(info['CFBundleIdentifier'], packaging.CANONICAL_BUNDLE)
            self.assertEqual(info['CFBundleName'], 'Chat Timeline')
            self.assertEqual(info['CFBundleDisplayName'], 'Chat Timeline')
            self.assertIs(info['ChatTimelineAuthDiagnosticsEnabled'], True)
            self.assertIs(info['ChatTimelineQRLoginEnabled'], True)
            self.assertEqual(info['BGTaskSchedulerPermittedIdentifiers'], self.info['BGTaskSchedulerPermittedIdentifiers'])
            self.assertFalse(any('mobileprovision' in name for name in archive.namelist()))
            self.assertFalse(any(PROFILE in archive.read(name) for name in archive.namelist()))
        self.assertEqual(self.requested, {
            'application-identifier': TEAM + '.' + packaging.CANONICAL_BUNDLE,
            'com.apple.developer.team-identifier': TEAM,
            'keychain-access-groups': [TEAM + '.' + packaging.CANONICAL_BUNDLE],
            'com.apple.security.application-groups': ['group.' + packaging.CANONICAL_BUNDLE],
            'get-task-allow': True,
        })
        manifest = json.loads((self.output / 'manifest.json').read_text())
        self.assertEqual(manifest['sha256'], packaging.sha256(self.output / packaging.OUTPUT_NAME))
        self.assertEqual(manifest['source_revision'], REVISION)
        self.assertEqual(manifest['expected_signed_bundle_identifier'], BUNDLE)
        self.assertIs(manifest['auth_diagnostics_enabled'], True)
        self.assertIs(manifest['qr_login_enabled'], True)
        with zipfile.ZipFile(self.ipa) as original:
            original_info = plistlib.loads(original.read(packaging.APP_PATH + '/Info.plist'))
            self.assertNotIn('ChatTimelineQRLoginEnabled', original_info)
            self.assertEqual(original.read(packaging.APP_PATH + '/embedded.mobileprovision'), PROFILE)
        for key in ('embedded_profile_included', 'apple_private_key_used', 'device_installable_directly',
                    'device_tested', 'identity_mapping_runtime_verified'):
            self.assertIs(manifest[key], False)
        signing = [command for command in self.commands if '--sign' in command]
        self.assertEqual(len(signing), 3)
        self.assertTrue(signing[-1][-1].endswith('Telegram.app'))
        self.assertIn('--generate-entitlement-der', signing[-1])

    def test_embedded_profile_must_equal_exact_verified_bytes(self):
        self.members[packaging.APP_PATH + '/embedded.mobileprovision'] = b'different profile'
        self.write_ipa()
        self.rejected()
        self.assertFalse(any('/usr/bin/codesign' in command for command in self.commands))

    def test_localized_names_change_before_sealing_preserving_other_values_and_binary_format(self):
        self.package()
        with zipfile.ZipFile(self.output / packaging.OUTPUT_NAME) as archive:
            for locale in ('ar', 'ko'):
                name = packaging.APP_PATH + '/' + locale + '.lproj/InfoPlist.strings'
                original = plistlib.loads(self.members[name])
                result = archive.read(name)
                self.assertTrue(result.startswith(b'bplist00'))
                self.assertEqual(plistlib.loads(result), dict(original, CFBundleDisplayName='Chat Timeline'))

    def test_localized_xml_format_is_preserved(self):
        name = packaging.APP_PATH + '/ar.lproj/InfoPlist.strings'
        self.members[name] = plistlib.dumps(plistlib.loads(self.members[name]), fmt=plistlib.FMT_XML)
        self.package()
        with zipfile.ZipFile(self.output / packaging.OUTPUT_NAME) as archive:
            self.assertTrue(archive.read(name).startswith(b'<?xml'))

    def test_missing_expected_localized_resource_rejects_before_signing(self):
        del self.members[packaging.APP_PATH + '/ko.lproj/InfoPlist.strings']
        self.write_ipa()
        self.rejected()
        self.assertFalse(any('/usr/bin/codesign' in command for command in self.commands))

    def test_owner_trust_summary_and_hash_required(self):
        valid = copy.deepcopy(self.owner)
        for key in valid['public_summary']:
            with self.subTest(key=key):
                self.owner = copy.deepcopy(valid)
                self.owner['public_summary'][key] = False
                self.rejected()
        self.owner = copy.deepcopy(valid)
        self.owner['profile_sha256'] = '0' * 64
        self.rejected()

    def test_main_metadata_must_match_compiled_identity_version_and_background_ids(self):
        cases = {'CFBundleIdentifier': packaging.CANONICAL_BUNDLE,
                 'CFBundleVersion': '41', 'CFBundleShortVersionString': '13.1.0',
                 'CFBundleSupportedPlatforms': ['iPhoneSimulator'],
                 'BGTaskSchedulerPermittedIdentifiers': [packaging.CANONICAL_BUNDLE + '.cleanup'],
                 'CFBundleExecutable': '../outside'}
        for key, value in cases.items():
            with self.subTest(key=key):
                info = dict(self.info, **{key: value})
                self.members[packaging.APP_PATH + '/Info.plist'] = plistlib.dumps(info)
                self.write_ipa()
                self.rejected()

    def test_every_main_framework_and_dylib_requires_device_platform(self):
        for name in ('Telegram', 'Frameworks/Sample.framework/Sample', 'Frameworks/libExample.dylib'):
            with self.subTest(name=name):
                path = packaging.APP_PATH + '/' + name
                original = self.members[path]
                self.members[path] = binary(platform_id=7, file_type=2 if name == 'Telegram' else 6)
                self.write_ipa()
                self.rejected()
                self.members[path] = original

    def test_wrong_source_revision_rejected(self):
        self.revision = 'b' * 40
        self.rejected()

    def test_revision_rechecked_after_signing(self):
        original = self.run_command
        def change_after_signing(arguments, **kwargs):
            result = original(arguments, **kwargs)
            if '-d' in arguments:
                self.revision = 'b' * 40
            return result
        with patch.object(packaging.subprocess, 'run', side_effect=change_after_signing):
            self.write_ipa()
            self.rejected()

    def test_no_native_actions_on_non_macos(self):
        with patch.object(packaging.platform, 'system', return_value='Windows'):
            self.rejected()
        self.assertEqual(self.commands, [])

    def test_archive_traversal_nested_apps_extensions_and_other_profiles_rejected(self):
        for name in ('../escape', packaging.APP_PATH + '/../escape',
                     packaging.APP_PATH + '/PlugIns/Share.appex/Info.plist',
                     packaging.APP_PATH + '/nested.app/Info.plist',
                     packaging.APP_PATH + '/other.mobileprovision',
                     'Payload/Another.app/Info.plist'):
            with self.subTest(name=name):
                self.write_ipa((name, b'x'))
                self.rejected()

    def test_symlink_archive_member_rejected(self):
        member = zipfile.ZipInfo(packaging.APP_PATH + '/link')
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.write_ipa((member, b'../../outside'))
        self.rejected()

    def test_native_signing_failure_is_sanitized_and_output_removed(self):
        self.fail_signing = True
        self.write_ipa()
        self.rejected()
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), ['source'])

    def test_readback_entitlements_must_equal_requested_template(self):
        self.wrong_entitlements = True
        self.write_ipa()
        self.rejected()

    def test_existing_output_is_never_removed_or_replaced(self):
        self.output.mkdir()
        sentinel = self.output / 'keep'
        sentinel.write_text('untouched')
        with self.assertRaises(packaging.PackageRejected):
            packaging.package_input(self.source, self.output, self.owner, REVISION)
        self.assertEqual(sentinel.read_text(), 'untouched')
        self.assertEqual(self.commands, [])


if __name__ == '__main__':
    unittest.main()
