"""Offline wrapper tests using synthetic profile metadata; no native signing/build."""
import contextlib
import importlib
import io
import os
from pathlib import Path
import plistlib
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch


SOURCE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SOURCE / 'build-system' / 'Make'))
import BuildConfiguration as config

# The unrelated VM runner imports Unix-only fcntl. These tests exercise only the
# local build wrapper and do not invoke a VM, subprocess, keychain or network.
with patch.dict(sys.modules, {'TartBuild': types.ModuleType('TartBuild')} if os.name == 'nt' else {}):
    make = importlib.import_module('Make')

TEAM = 'TESTTEAM01'
BUNDLE = 'ph.telegra.Telegraph.' + TEAM
DEVICE = '00000000-0000000000000000'
RAW = b'synthetic CMS fixture, not a valid profile'


def profile():
    return {
        'TeamIdentifier': [TEAM], 'ApplicationIdentifierPrefix': [TEAM],
        'Platform': ['iOS'],
        'Entitlements': {
            'application-identifier': TEAM + '.' + BUNDLE,
            'com.apple.developer.team-identifier': TEAM,
            'com.apple.security.application-groups': ['group.' + BUNDLE],
        },
    }


def arguments(**changes):
    values = dict(
        deferredOwnerSigning=True, codesigningInformationPath='synthetic-input',
        gitCodesigningRepository=None, xcodeManagedCodesigning=False,
        configuration='release_arm64', target=None, embedWatchApp=False,
        overrideBazelVersion=False, overrideXcodeVersion=False, bazelUserRoot=None,
        lock=False, cacheDir=None, cacheHost=None, buildNumber=1,
        continueOnError=False, showActions=False, sandbox=False, profileSwift=False,
        enableParallelSwiftmoduleGeneration=False, outputBuildArtifactsPath=None,
    )
    values.update(changes)
    return types.SimpleNamespace(**values)


class DeferredOwnerProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.supplied = self.root / 'supplied'
        (self.supplied / 'profiles').mkdir(parents=True)
        self.selected = self.supplied / 'selecteddevice.txt'
        self.selected.write_text(DEVICE + '\n', encoding='ascii')
        self.known_file = self.supplied / 'profiles' / 'Telegram.mobileprovision'
        self.known_file.write_bytes(RAW)
        self.verified = {'team_id': TEAM, 'bundle_id': BUNDLE, 'profile_data': RAW, 'aps_environment': ''}
        self.source = config.DeferredOwnerCodesigningSource(str(self.supplied), TEAM, BUNDLE)

    def load(self, verified=None):
        verifier = Mock(return_value=self.verified if verified is None else verified)
        with patch.object(config, 'load_deferred_owner_profile_verifier', return_value=verifier):
            self.source.load_data('unused')
        verifier.assert_called_once_with(self.known_file, DEVICE)

    def test_only_deferred_mode_accepts_missing_aps(self):
        self.load()
        self.assertEqual(self.source.resolve_aps_environment(), '')
        with patch.object(config, 'run_executable_with_output', return_value=plistlib.dumps(profile())), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                config.resolve_aps_environment_from_directory(str(self.known_file.parent), TEAM, BUNDLE)

    def test_existing_aps_value_is_preserved_in_both_modes(self):
        for aps in ('development', 'production'):
            with self.subTest(aps=aps):
                value = profile()
                value['Entitlements']['aps-environment'] = aps
                self.load(dict(self.verified, aps_environment=aps))
                self.assertEqual(self.source.resolve_aps_environment(), aps)
                with patch.object(config, 'run_executable_with_output', return_value=plistlib.dumps(value)):
                    self.assertEqual(config.resolve_aps_environment_from_directory(str(self.known_file.parent), TEAM, BUNDLE), aps)

    def test_invalid_aps_is_not_treated_as_missing(self):
        for aps in (None, 'unexpected'):
            with self.subTest(aps_type=type(aps).__name__), self.assertRaises(ValueError):
                self.load(dict(self.verified, aps_environment=aps))

    def test_verified_identity_must_match_configuration(self):
        for changes in ({'team_id': 'OTHERTEAM1'}, {'bundle_id': 'org.example.Other'}):
            with self.subTest(field=next(iter(changes))), self.assertRaises(ValueError):
                self.load(dict(self.verified, **changes))

    def test_selected_device_is_one_bounded_ascii_identifier(self):
        for data in (b'', b'A' * 67, b'ABC12345\nABC12345', b' ABC12345', b'ABC12345 ', b'ABC12345\n\n', b'\xff' * 8):
            with self.subTest(size=len(data)):
                self.selected.write_bytes(data)
                with patch.object(config, 'load_deferred_owner_profile_verifier') as loader, self.assertRaises(ValueError):
                    self.source.load_data('unused')
                loader.assert_not_called()
        for ending in ('', '\n', '\r\n'):
            self.selected.write_bytes((DEVICE + ending).encode('ascii'))
            self.load()

    def test_selected_device_symlink_is_rejected_before_verification(self):
        with patch.object(config.Path, 'is_symlink', return_value=True), \
                patch.object(config, 'load_deferred_owner_profile_verifier') as loader, self.assertRaises(ValueError):
            self.source.load_data('unused')
        loader.assert_not_called()

    def test_exact_checkout_native_verifier_is_loaded_without_module_search(self):
        verifier = config.load_deferred_owner_profile_verifier()
        self.assertEqual(Path(verifier.__code__.co_filename).resolve(), SOURCE / 'ci/chat-timeline/owner_profile.py')
        # Mock only the native trust boundary; the actual verify_profile call must
        # be reached and its rejection propagated, never replaced by CMS decoding.
        native = Mock(side_effect=RuntimeError('private native rejection'))
        with patch.dict(verifier.__globals__, {'_verified_payload': native}), \
                patch.object(config, 'load_deferred_owner_profile_verifier', return_value=verifier), \
                self.assertRaisesRegex(ValueError, '^Deferred owner profile or selected device verification failed.$'):
            self.source.load_data('unused')
        self.assertEqual(native.call_count, 1)
        self.assertEqual(native.call_args.args[0], RAW)

    def test_resolution_copies_only_explicit_main_profile_and_never_certificates(self):
        (self.supplied / 'profiles' / 'Other.mobileprovision').write_bytes(b'must not inspect')
        destination, extra = self.root / 'resolved', self.root / 'extra'
        def verify(path, device):
            self.assertEqual((path, device), (self.known_file, DEVICE))
            self.known_file.write_bytes(b'replaced after native verification')
            return self.verified
        with patch.object(config, 'load_deferred_owner_profile_verifier', return_value=verify), \
                patch.object(config, 'run_executable_with_output', side_effect=AssertionError('Decode-only access')), \
                patch.object(config, 'copy_certificates_from_directory', side_effect=AssertionError('Certificate access')):
            result = make.resolve_codesigning(
                arguments(codesigningInformationPath=str(self.supplied)), str(self.root),
                types.SimpleNamespace(team_id=TEAM, bundle_id=BUNDLE), str(destination), str(extra),
            )
        self.assertEqual(result.aps_environment, '')
        self.assertFalse(result.use_xcode_managed_codesigning)
        self.assertEqual([item.name for item in destination.iterdir()], ['Telegram.mobileprovision'])
        self.assertEqual((destination / 'Telegram.mobileprovision').read_bytes(), RAW)
        self.assertEqual((extra / 'profiles' / 'Telegram.mobileprovision').read_bytes(), RAW)
        self.assertFalse((extra / 'certs').exists())

    def test_verification_failure_does_not_expose_raw_error(self):
        verifier = Mock(side_effect=RuntimeError('synthetic-private-detail'))
        with patch.object(config, 'load_deferred_owner_profile_verifier', return_value=verifier):
            with self.assertRaisesRegex(ValueError, '^Deferred owner profile or selected device verification failed.$') as caught:
                self.source.load_data('unused')
        self.assertTrue(caught.exception.__suppress_context__)


class DeferredOwnerWrapperTests(unittest.TestCase):
    def test_invalid_modes_fail_before_configuration_or_build(self):
        invalid = [
            dict(configuration='debug_sim_arm64'), dict(configuration='release_sim_arm64'),
            dict(target='//Unrelated:Target'), dict(embedWatchApp=True),
            dict(disableProvisioningProfiles=True), dict(codesigningInformationPath=None),
            dict(gitCodesigningRepository='unused'), dict(xcodeManagedCodesigning=True),
        ]
        with patch.object(make, 'BazelCommandLine') as bazel, patch.object(make, 'resolve_configuration') as resolve:
            for changes in invalid:
                with self.subTest(changes=sorted(changes)), self.assertRaises(ValueError):
                    make.build('unused-bazel', arguments(**changes))
            bazel.assert_not_called()
            resolve.assert_not_called()

    def run_build(self, deferred):
        with patch.object(make, 'BuildEnvironment', return_value=types.SimpleNamespace(bazel_path='synthetic-bazel')), \
                patch.object(make.PostboxImportCheck, 'run', return_value=0), \
                patch.object(make, 'resolve_configuration') as resolve, \
                patch.object(make, 'call_executable') as execute, contextlib.redirect_stdout(io.StringIO()):
            make.build('synthetic-bazel', arguments(deferredOwnerSigning=deferred))
        resolve.assert_called_once()
        execute.assert_called_once()
        return execute.call_args.args[0]

    def test_actual_build_invocation_retains_profile_and_forces_validation(self):
        command = self.run_build(True)
        self.assertIn('--batch', command)
        self.assertLess(command.index('--batch'), command.index('build'))
        self.assertIn('--features=disable_legacy_signing', command)
        self.assertIn('--//Telegram:disableExtensions=true', command)
        self.assertIn('--//Telegram:embedWatchApp=false', command)
        self.assertIn('--//Telegram:disableProvisioningProfiles=false', command)
        self.assertIn('--output_groups=+dossier', command)
        self.assertNotIn('--//Telegram:disableProvisioningProfiles', command)
        self.assertNotIn('--//Telegram:disableProvisioningProfiles=true', command)
        self.assertIn('--ios_multi_cpus=arm64', command)
        self.assertIn('Telegram/Telegram', command)

    def test_default_build_invocation_has_no_deferred_flags(self):
        command = self.run_build(False)
        self.assertNotIn('--batch', command)
        self.assertNotIn('--features=disable_legacy_signing', command)
        self.assertNotIn('--//Telegram:disableExtensions=true', command)
        self.assertNotIn('--output_groups=+dossier', command)

    def test_command_object_rejects_later_profile_disable(self):
        with patch.object(make, 'BuildEnvironment', return_value=types.SimpleNamespace(bazel_path='synthetic-bazel')):
            command = make.BazelCommandLine('synthetic-bazel', False, False, None)
        command.set_configuration('release_arm64')
        command.set_deferred_owner_signing(True)
        command.set_disable_provisioning_profiles()
        with patch.object(make, 'call_executable') as execute, self.assertRaises(ValueError):
            command.invoke_build()
        execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
