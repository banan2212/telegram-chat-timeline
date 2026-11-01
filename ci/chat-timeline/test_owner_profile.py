"""Synthetic policy tests. Native verification is mocked; no live profile claim."""
from __future__ import annotations

import contextlib
import copy
import datetime as dt
import io
from pathlib import Path
import plistlib
import platform
import subprocess
import tempfile
import unittest
from unittest import mock

import owner_profile as owner


class OwnerProfileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='owner-profile-test-')
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / 'synthetic.mobileprovision'
        self.raw = b'SYNTHETIC-CMS-FIXTURE-NOT-A-SIGNED-PROFILE'
        self.path.write_bytes(self.raw)
        self.now = dt.datetime(2030, 1, 2, 12, tzinfo=dt.timezone.utc)
        self.team = 'ABCDE12345'
        self.bundle = 'ph.telegra.Telegraph.' + self.team
        self.device = '00000000-0000000000000000'
        self.profile = {
            'Platform': ['iOS'],
            'CreationDate': (self.now - dt.timedelta(days=1)).replace(tzinfo=None),
            'ExpirationDate': (self.now + dt.timedelta(days=6)).replace(tzinfo=None),
            'TeamIdentifier': [self.team],
            'ApplicationIdentifierPrefix': [self.team],
            'ProvisionedDevices': [self.device],
            'DeveloperCertificates': [b'SYNTHETIC-CERTIFICATE-NOT-A-REAL-CERT'],
            'Entitlements': {
                'application-identifier': self.team + '.' + self.bundle,
                'com.apple.developer.team-identifier': self.team,
                'com.apple.security.application-groups': ['group.' + self.bundle],
                'keychain-access-groups': [self.team + '.*'],
                'get-task-allow': True,
            },
        }

    def verify(self, profile=None, expected_device=None):
        payload = plistlib.dumps(self.profile if profile is None else profile)
        with mock.patch.object(owner, '_verified_payload', return_value=payload):
            return owner.verify_profile(self.path, expected_device or self.device, self.now)

    def rejected(self, profile):
        with self.assertRaises(owner.ProfileRejected) as captured:
            self.verify(profile)
        self.assertEqual(str(captured.exception), 'owner_profile_rejected')
        self.assertTrue(all(type(value) is bool for value in captured.exception.public_summary.values()))
        self.assertFalse(captured.exception.public_summary['accepted'])

    def test_private_config_exact_bytes_and_bool_only_public_summary(self):
        result = self.verify()
        self.assertEqual(result['team_id'], self.team)
        self.assertEqual(result['bundle_id'], self.bundle)
        self.assertEqual(result['profile_data'], self.raw)
        self.assertEqual(Path(result['profile_path']), self.path.resolve())
        self.assertEqual(result['aps_environment'], '')
        summary = result['public_summary']
        self.assertTrue(summary['accepted'])
        self.assertFalse(summary['aps_present'])
        self.assertTrue(all(type(value) is bool for value in summary.values()))
        self.assertNotIn(self.device, repr(summary))
        self.assertNotIn(self.team, repr(summary))
        self.assertNotIn(str(self.path), repr(summary))

    def test_native_trust_failure_cannot_fall_back_to_plist_acceptance(self):
        self.path.write_bytes(plistlib.dumps(self.profile))
        with mock.patch.object(owner, '_verified_payload', side_effect=owner.ProfileRejected()):
            with self.assertRaises(owner.ProfileRejected):
                owner.verify_profile(self.path, self.device, self.now)

    def test_profile_lifetime_boundary_and_creation_sanity(self):
        profile = copy.deepcopy(self.profile)
        profile['ExpirationDate'] = (self.now + dt.timedelta(hours=6)).replace(tzinfo=None)
        self.assertTrue(self.verify(profile)['public_summary']['minimum_lifetime_verified'])
        for creation, expiration in (
            (self.now - dt.timedelta(days=1), self.now + dt.timedelta(hours=6, seconds=-1)),
            (self.now - dt.timedelta(days=1), self.now - dt.timedelta(seconds=1)),
            (self.now + dt.timedelta(minutes=6), self.now + dt.timedelta(days=1)),
            (dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc), self.now + dt.timedelta(days=1)),
            (self.now + dt.timedelta(minutes=1), self.now),
        ):
            with self.subTest(creation=creation, expiration=expiration):
                profile = copy.deepcopy(self.profile)
                profile['CreationDate'] = creation.replace(tzinfo=None)
                profile['ExpirationDate'] = expiration.replace(tzinfo=None)
                self.rejected(profile)
        for key in ('CreationDate', 'ExpirationDate'):
            profile = copy.deepcopy(self.profile)
            del profile[key]
            self.rejected(profile)

    def test_distribution_and_non_ios_profiles_rejected(self):
        for value in (False, 0, 1, 'true'):
            with self.subTest(get_task_allow=value):
                profile = copy.deepcopy(self.profile)
                profile['Entitlements']['get-task-allow'] = value
                self.rejected(profile)
        for platforms in (['OSX'], ['tvOS'], ['iOS', 'OSX'], ['xrOS', 'visionOS'], ['iOS', 'iOS'], 'iOS', []):
            profile = copy.deepcopy(self.profile)
            profile['Platform'] = platforms
            self.rejected(profile)
        profile = copy.deepcopy(self.profile)
        profile['ProvisionsAllDevices'] = True
        self.rejected(profile)

    def test_ios_profile_can_authorize_additional_known_platforms(self):
        profile = copy.deepcopy(self.profile)
        profile['Platform'] = ['iOS', 'xrOS', 'visionOS']
        self.assertTrue(self.verify(profile)['public_summary']['accepted'])
        profile = copy.deepcopy(self.profile)
        del profile['ProvisionedDevices']
        self.rejected(profile)

    def test_exact_bundle_team_prefix_and_group_required(self):
        mutations = [
            ('application-identifier', self.team + '.*'),
            ('application-identifier', self.team + '.ph.telegra.Telegraph'),
            ('application-identifier', self.team + '.org.example.Other'),
            ('com.apple.developer.team-identifier', 'OTHER12345'),
            ('com.apple.security.application-groups', ['group.org.example.Other']),
            ('com.apple.security.application-groups', ['group.*']),
            ('keychain-access-groups', ['OTHER12345.*']),
            ('keychain-access-groups', [self.team + '.org.example.Other']),
        ]
        for key, value in mutations:
            with self.subTest(field=key):
                profile = copy.deepcopy(self.profile)
                profile['Entitlements'][key] = value
                self.rejected(profile)
        for key, value in (
            ('TeamIdentifier', [self.team, 'OTHER12345']),
            ('TeamIdentifier', ['invalid']),
            ('ApplicationIdentifierPrefix', ['OTHER12345']),
        ):
            profile = copy.deepcopy(self.profile)
            profile[key] = value
            self.rejected(profile)

    def test_target_device_requires_exact_private_input_match(self):
        with self.assertRaises(owner.ProfileRejected):
            self.verify(expected_device='00000000-0000000000000001')
        profile = copy.deepcopy(self.profile)
        profile['ProvisionedDevices'] = ['prefix-' + self.device, self.device + '-suffix']
        self.rejected(profile)
        with mock.patch.object(owner, '_verified_payload') as native:
            with self.assertRaises(owner.ProfileRejected):
                owner.verify_profile(self.path, '*', self.now)
            native.assert_not_called()

    def test_aps_absence_is_preserved_and_invalid_values_rejected(self):
        self.assertEqual(self.verify()['aps_environment'], '')
        for value in ('development', 'production'):
            profile = copy.deepcopy(self.profile)
            profile['Entitlements']['aps-environment'] = value
            result = self.verify(profile)
            self.assertEqual(result['aps_environment'], value)
            self.assertTrue(result['public_summary']['aps_present'])
        for value in ('', 'sandbox', True, 1):
            profile = copy.deepcopy(self.profile)
            profile['Entitlements']['aps-environment'] = value
            self.rejected(profile)

    def test_certificate_structure_required_after_native_boundary(self):
        for certificates in ([], ['not DER bytes'], [b''], [b'x' * (64 * 1024 + 1)]):
            profile = copy.deepcopy(self.profile)
            profile['DeveloperCertificates'] = certificates
            self.rejected(profile)

    def test_private_errors_and_native_stderr_are_never_emitted(self):
        sentinel = str(self.path) + ' ' + self.device + ' private certificate subject'
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            with mock.patch.object(owner, '_verified_payload', side_effect=OSError(sentinel)):
                with self.assertRaises(owner.ProfileRejected) as error:
                    owner.verify_profile(self.path, self.device, self.now)
        self.assertEqual(captured.getvalue(), '')
        self.assertEqual(str(error.exception), 'owner_profile_rejected')
        self.assertNotIn(sentinel, repr(error.exception.public_summary))
        failed = subprocess.CompletedProcess(['native'], 2, stdout=b'', stderr=sentinel.encode())
        with mock.patch.object(owner.platform, 'system', return_value='Darwin'), \
                mock.patch.object(owner.subprocess, 'run', return_value=failed), \
                contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            with self.assertRaises(owner.ProfileRejected):
                owner._verified_payload(self.raw, self.now)
        self.assertEqual(captured.getvalue(), '')

    def test_unsupported_native_host_and_oversized_input_fail_closed(self):
        with mock.patch.object(owner.platform, 'system', return_value='Windows'), \
                mock.patch.object(owner.subprocess, 'run') as process:
            with self.assertRaises(owner.ProfileRejected):
                owner._verified_payload(self.raw, self.now)
            process.assert_not_called()
        with mock.patch.object(owner, 'MAX_PROFILE_BYTES', len(self.raw) - 1), \
                mock.patch.object(owner, '_verified_payload') as native:
            with self.assertRaises(owner.ProfileRejected):
                owner.verify_profile(self.path, self.device, self.now)
            native.assert_not_called()

    def test_native_smoke_distinguishes_compile_and_policy_failures(self):
        for code, expected in ((0, False), (1, False), (2, True), (3, False)):
            with self.subTest(returncode=code):
                result = subprocess.CompletedProcess(['native'], code, stdout=b'', stderr=b'')
                with mock.patch.object(owner, '_run_native', return_value=result):
                    self.assertEqual(owner.native_verifier_smoke(), expected)
        result = subprocess.CompletedProcess(['native'], 2, stdout=b'unexpected output', stderr=b'')
        with mock.patch.object(owner, '_run_native', return_value=result):
            self.assertFalse(owner.native_verifier_smoke())

    @unittest.skipUnless(platform.system() == 'Darwin', 'Native Security.framework smoke requires macOS')
    def test_native_compiles_policies_exist_and_empty_cms_is_rejected(self):
        # No account, certificate or profile fixture is supplied to the native process.
        self.assertTrue(owner.native_verifier_smoke())


if __name__ == '__main__':
    unittest.main()
