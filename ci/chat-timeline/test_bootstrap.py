"""Regression checks for CI boundaries, not a replacement for a native build."""
import contextlib
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import tempfile
import types
import sys
import unittest
from unittest.mock import patch
import zipfile

SPEC = importlib.util.spec_from_file_location('timeline_bootstrap', Path(__file__).with_name('bootstrap.py'))
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)
SOURCE = Path(__file__).resolve().parents[2]


class BuildBoundaries(unittest.TestCase):
    def test_public_sample_provenance_and_line_endings(self):
        expected = ci.api_values(SOURCE, 'upstream-test')
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            (source / 'build-system').mkdir()
            original = (SOURCE / 'build-system/appstore-configuration.json').read_bytes()
            config = source / 'build-system/appstore-configuration.json'
            config.write_bytes(original.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
            self.assertEqual(expected, ci.api_values(source, 'upstream-test'))
            config.write_bytes(original + b' ')
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                ci.api_values(source, 'upstream-test')

    def test_secrets_are_not_replaced_by_sample_implicitly(self):
        with patch.dict(os.environ, {'TELEGRAM_API_ID': '', 'TELEGRAM_API_HASH': ''}):
            with self.assertRaisesRegex(ValueError, 'missing or invalid'):
                ci.api_values(SOURCE, 'secrets')

    def probe_with_profiles(self, target, expiry, expected=ci.PIN, **options):
        def fake_command(*args, **kwargs):
            if args[:2] == ('git', 'rev-parse'):
                return ci.PIN
            if args == ('xcodebuild', '-version'):
                return 'Xcode 27.1\nBuild version test'
            if args[:3] == ('xcrun', 'simctl', 'list'):
                return '{"runtimes": []}'
            if args[0] == 'xcrun':
                return '27.1'
            raise AssertionError(args)

        profile = {'ExpirationDate': expiry,
                   'Entitlements': {'aps-environment': 'development',
                                    'application-identifier': 'TEAM.org.example.test'}}
        with tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(ci, 'command', fake_command))
            stack.enter_context(patch.object(ci.platform, 'system', return_value='Darwin'))
            stack.enter_context(patch.object(ci.platform, 'machine', return_value='arm64'))
            stack.enter_context(patch.object(ci.platform, 'mac_ver', return_value=('27.0', (), '')))
            stack.enter_context(patch.object(ci, 'resource_report', return_value={'ram_gib': 7, 'free_disk_gib': 50}))
            stack.enter_context(patch.object(ci, 'read_profile', return_value=profile))
            stack.enter_context(patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': ''}))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            return ci.probe(SOURCE, Path(temporary), target, 'upstream-test', expected, **options)

    def test_owner_mode_requires_actual_verification_and_does_not_emit_identity(self):
        profile_module = types.SimpleNamespace(
            verify_profile=lambda *args, **kwargs: {
                'team_id': 'PRIVATE_TEAM', 'bundle_id': 'PRIVATE_BUNDLE',
                'public_summary': {'signature_verified': True}},
            ProfileRejected=ValueError)
        with patch.dict(sys.modules, {'owner_profile': profile_module}):
            report = self.probe_with_profiles(
                'device', dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1),
                signing_mode='owner-deferred', owner_profile_path=Path('explicit-only.mobileprovision'),
                expected_device='PRIVATE_DEVICE')
        self.assertTrue(report['ready_for_selected_build'])
        self.assertEqual([], report['profiles'])
        self.assertNotIn('PRIVATE_', json.dumps(report))

    def test_owner_failure_is_closed_and_omits_exception_payload(self):
        def reject(*args, **kwargs):
            raise ValueError('PRIVATE_IDENTIFIER_SENTINEL')
        profile_module = types.SimpleNamespace(verify_profile=reject, ProfileRejected=ValueError)
        with patch.dict(sys.modules, {'owner_profile': profile_module}):
            report = self.probe_with_profiles(
                'device', dt.datetime.now(dt.timezone.utc), signing_mode='owner-deferred',
                owner_profile_path=Path('explicit-only.mobileprovision'), expected_device='PRIVATE_DEVICE')
        self.assertFalse(report['ready_for_selected_build'])
        self.assertNotIn('PRIVATE_', json.dumps(report))

    def test_owner_mode_rejects_missing_input_and_simulator(self):
        profile_module = types.SimpleNamespace(verify_profile=lambda *a, **k: {}, ProfileRejected=ValueError)
        with patch.dict(sys.modules, {'owner_profile': profile_module}):
            report = self.probe_with_profiles('simulator', dt.datetime.now(dt.timezone.utc),
                                              signing_mode='owner-deferred')
        self.assertFalse(report['ready_for_selected_build'])

    def test_expired_device_profiles_block_device_only(self):
        expiry = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
        device = self.probe_with_profiles('device', expiry)
        simulator = self.probe_with_profiles('simulator', expiry)
        self.assertFalse(device['ready_for_selected_build'])
        self.assertTrue(any('expired' in item for item in device['blockers']))
        self.assertTrue(simulator['ready_for_selected_build'])
        self.assertTrue(simulator['device_signing_blockers'])

    def test_insufficient_signing_time_blocks_device(self):
        report = self.probe_with_profiles('device', dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2))
        self.assertTrue(any('six hours' in item for item in report['blockers']))

    def test_wrong_source_revision_blocks_build(self):
        report = self.probe_with_profiles('simulator', dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=3), '0' * 40)
        self.assertFalse(report['ready_for_selected_build'])
        self.assertTrue(any('revision' in item for item in report['blockers']))

    def test_simulator_cannot_be_collected_as_device(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / 'source', root / 'output'
            archive_path = source / 'bazel-bin/Telegram/Telegram.ipa'
            archive_path.parent.mkdir(parents=True)
            info = {'CFBundleSupportedPlatforms': ['iPhoneSimulator'], 'CFBundleExecutable': 'Telegram'}
            with zipfile.ZipFile(archive_path, 'w') as archive:
                archive.writestr('Payload/Telegram.app/Info.plist', plistlib.dumps(info))
                archive.writestr('Payload/Telegram.app/Telegram', b'test-fixture-only')
            with patch.object(ci, 'command', return_value=ci.PIN):
                with self.assertRaisesRegex(SystemExit, 'platform'):
                    ci.collect(source, output, 'device', 'upstream-test', ci.PIN)
            self.assertFalse((output / 'artifacts').exists())


if __name__ == '__main__':
    unittest.main()
