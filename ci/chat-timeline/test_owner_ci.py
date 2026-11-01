"""Private CI envelope and cleanup boundaries; no owner profiles or keys."""
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

import owner_ci as ci


class ApiSourceBoundaries(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, mode, credentials=None, preflight_failure=False):
        # No ambient API environment or real configuration is used by these tests.
        with tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
            root = Path(temporary).resolve()
            source, runner = root / 'source', root / 'runner'
            (source / 'build-system').mkdir(parents=True)
            runner.mkdir()
            private = runner / 'chat-timeline-owner-private'
            output = runner / 'chat-timeline-owner-encrypted'
            sample = json.dumps({'api_id': '777111', 'api_hash': 'a' * 32}).encode()
            (source / 'build-system/appstore-configuration.json').write_bytes(sample)
            owner = {'version': 1, 'profile_der_b64': base64.b64encode(b'fixture' * 100).decode(),
                     'device': '12345678-1234567890ABCDEF',
                     'recipient_certificate_pem': '-----BEGIN CERTIFICATE-----\nFIXTURE\n-----END CERTIFICATE-----\n'}
            environment = {'CHAT_TIMELINE_OWNER_INPUT': json.dumps(owner),
                           'EXPECTED_REVISION': 'a' * 40, 'GITHUB_RUN_NUMBER': '1',
                           'GITHUB_WORKSPACE': str(root), 'RUNNER_TEMP': str(runner)}
            if mode is not None:
                environment['API_SOURCE'] = mode
            environment.update(credentials or {})
            state = {'source': source, 'private': private, 'output': output, 'prepare_modes': [],
                     'stdout': io.StringIO(), 'stderr': io.StringIO()}

            def prepare(source, directory, target, api_source, *args):
                state['prepare_modes'].append(api_source)
                state['validated_values'] = ci.bootstrap.api_values(source, api_source)
                print('PRIVATE_OUTPUT_SENTINEL')
                print('PRIVATE_OUTPUT_SENTINEL', file=sys.stderr)
                if preflight_failure:
                    raise ValueError('PRIVATE_EXCEPTION_SENTINEL')
                directory.mkdir()
                (directory / 'configuration.json').write_text('{"fixture":true}')

            def build(*args, **kwargs):
                self.assertTrue('TELEGRAM_API_ID' not in os.environ)
                self.assertTrue('TELEGRAM_API_HASH' not in os.environ)

            def package(*, output, **kwargs):
                output.mkdir()
                (output / 'fixture.txt').write_text('synthetic packaging fixture')

            stack.enter_context(patch.dict(os.environ, environment, clear=True))
            stack.enter_context(patch.object(ci.os, 'umask'))
            stack.enter_context(patch.object(ci.bootstrap, 'SAMPLE_SHA256', hashlib.sha256(sample).hexdigest()))
            stack.enter_context(patch.object(ci.bootstrap, 'prepare', side_effect=prepare))
            state['build'] = stack.enter_context(patch.object(ci, 'run_private', side_effect=build))
            state['encrypt'] = stack.enter_context(patch.object(ci, 'encrypt_artifact'))
            stack.enter_context(patch('owner_profile.verify_profile', return_value={}))
            stack.enter_context(patch('owner_signing_input.package_input', side_effect=package))
            stack.enter_context(contextlib.redirect_stdout(state['stdout']))
            stack.enter_context(contextlib.redirect_stderr(state['stderr']))
            yield state

    def test_explicit_modes_route_to_the_selected_configuration(self):
        credentials = {'TELEGRAM_API_ID': '777222', 'TELEGRAM_API_HASH': 'b' * 32}
        for mode, expected in (('secrets', ('777222', 'b' * 32)),
                               ('upstream-test', ('777111', 'a' * 32))):
            with self.subTest(mode=mode), self.fixture(mode, credentials) as state:
                ci.execute(state['source'], state['private'], state['output'])
                self.assertEqual([mode], state['prepare_modes'])
                self.assertTrue(expected == state['validated_values'])
                state['build'].assert_called_once()
                state['encrypt'].assert_called_once()
                text = state['stdout'].getvalue() + state['stderr'].getvalue()
                self.assertFalse(any(value in text for value in (*expected, 'PRIVATE_OUTPUT_SENTINEL')))

    def test_missing_or_invalid_secrets_do_not_fall_back_to_available_sample(self):
        for credentials in ({}, {'TELEGRAM_API_ID': '777222'}, {'TELEGRAM_API_HASH': 'b' * 32},
                            {'TELEGRAM_API_ID': 'PRIVATE_INVALID_ID', 'TELEGRAM_API_HASH': 'b' * 32},
                            {'TELEGRAM_API_ID': '777222', 'TELEGRAM_API_HASH': 'PRIVATE_INVALID_HASH'}):
            with self.fixture('secrets', credentials) as state:
                with self.assertRaises(ValueError) as error:
                    ci.execute(state['source'], state['private'], state['output'])
                self.assertEqual(['secrets'], state['prepare_modes'])
                state['build'].assert_not_called()
                state['encrypt'].assert_not_called()
                self.assertTrue('TELEGRAM_API_ID' not in os.environ)
                self.assertTrue('TELEGRAM_API_HASH' not in os.environ)
                text = str(error.exception) + state['stdout'].getvalue() + state['stderr'].getvalue()
                self.assertFalse(any(value and value in text for value in credentials.values()))

    def test_missing_or_malformed_mode_stops_before_private_files_or_preflight(self):
        for mode in (None, '', 'SECRETS', 'secrets ', 'upstream-test\n', 'PRIVATE_INVALID_MODE'):
            with self.fixture(mode) as state:
                with self.assertRaises(ci.PrivateBuildRejected) as error:
                    ci.execute(state['source'], state['private'], state['output'])
                self.assertFalse(state['private'].exists())
                self.assertEqual([], state['prepare_modes'])
                state['build'].assert_not_called()
                self.assertNotIn('PRIVATE_INVALID_MODE', str(error.exception))

    def test_preflight_exception_and_output_stay_private_at_entry_point(self):
        credentials = {'TELEGRAM_API_ID': '777222', 'TELEGRAM_API_HASH': 'b' * 32}
        with self.fixture('secrets', credentials, preflight_failure=True) as state, \
                patch.object(sys, 'argv', ['owner_ci', '--source', str(state['source']),
                                          '--private', str(state['private']), '--output', str(state['output'])]):
            with self.assertRaises(SystemExit) as error:
                ci.main()
            self.assertEqual(1, error.exception.code)
            state['build'].assert_not_called()
            state['encrypt'].assert_not_called()
            text = state['stdout'].getvalue() + state['stderr'].getvalue()
            self.assertIn('Owner build did not finish.', text)
            self.assertFalse(any(value in text for value in (*credentials.values(), 'PRIVATE_OUTPUT_SENTINEL',
                                                             'PRIVATE_EXCEPTION_SENTINEL')))


class InputBoundaries(unittest.TestCase):
    def sample(self):
        return {'version': 1, 'profile_der_b64': base64.b64encode(b'fixture' * 100).decode(),
                'device': '12345678-1234567890ABCDEF',
                'recipient_certificate_pem': '-----BEGIN CERTIFICATE-----\nFIXTURE\n-----END CERTIFICATE-----\n'}

    def test_closed_input_shape(self):
        raw = self.sample()
        profile, device, certificate = ci.decode_input(json.dumps(raw))
        self.assertEqual(b'fixture' * 100, profile)
        self.assertEqual(raw['device'], device)
        self.assertNotIn(b'PRIVATE KEY', certificate)
        for key, value in [('extra', 'PRIVATE_SENTINEL'), ('version', True),
                           ('device', ['PRIVATE_SENTINEL']), ('profile_der_b64', '!'),
                           ('recipient_certificate_pem', '-----BEGIN PRIVATE KEY-----')]:
            changed = dict(raw, **{key: value})
            with self.assertRaises(ci.PrivateBuildRejected) as error:
                ci.decode_input(json.dumps(changed))
            self.assertNotIn('PRIVATE_SENTINEL', str(error.exception))

    def test_size_and_empty_input_fail_closed(self):
        for raw in ('', 'x' * 48_001, '[]', 'null'):
            with self.assertRaises(ci.PrivateBuildRejected):
                ci.decode_input(raw)

    def test_cleanup_only_generated_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            # macOS /var is an alias of /private/var; main() passes a resolved path.
            source = Path(temporary).resolve()
            generated = source / 'build-input/configuration-repository'
            generated.mkdir(parents=True)
            (generated / 'private-fixture.txt').write_text('fixture')
            keep = source / 'build-input/unrelated.txt'
            keep.write_text('keep')
            ci.cleanup_configuration(source)
            self.assertFalse(generated.exists())
            self.assertEqual('keep', keep.read_text())

    @unittest.skipUnless(os.name == 'posix', 'Private cleanup requires POSIX descriptor primitives')
    def test_cleanup_failure_is_redacted_and_private_root_still_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, runner = root / 'source', root / 'runner'
            source.mkdir(); runner.mkdir()
            private, output = runner / 'chat-timeline-owner-private', runner / 'chat-timeline-owner-encrypted'
            def simulated_execute(source, private, output):
                private.mkdir()
            stderr = io.StringIO()
            with patch.dict(os.environ, {'GITHUB_WORKSPACE': str(root), 'RUNNER_TEMP': str(runner)}), \
                    patch.object(sys, 'argv', ['owner_ci', '--source', str(source), '--private', str(private), '--output', str(output)]), \
                    patch.object(ci, 'execute', simulated_execute), \
                    patch.object(ci, 'cleanup_configuration', side_effect=OSError('PRIVATE_SENTINEL')), \
                    contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as error:
                    ci.main()
            self.assertEqual(1, error.exception.code)
            self.assertFalse(private.exists())
            self.assertNotIn('PRIVATE_SENTINEL', stderr.getvalue())

    def test_timeout_stops_build_session_before_returning(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            process = Mock(pid=12345)
            process.wait.side_effect = [subprocess.TimeoutExpired('fixture', 1), 0, 0]
            with patch.object(ci.subprocess, 'Popen', return_value=process) as popen, \
                    patch.object(ci.os, 'killpg', create=True) as killpg, \
                    patch.object(ci.signal, 'SIGKILL', 9, create=True):
                with self.assertRaises(subprocess.TimeoutExpired):
                    ci.run_private(['fixture'], cwd=root, log=root / 'private.log', timeout=1)
            self.assertTrue(popen.call_args.kwargs['start_new_session'])
            self.assertEqual(2, killpg.call_count)
            self.assertTrue(all(call.args[0] == 12345 for call in killpg.call_args_list))

    def test_private_cleanup_failures_emit_only_fixed_labels(self):
        for failure in (ci.PrivateCleanupError('remove_tree', 'permission'), OSError('PRIVATE_SENTINEL')):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                source, runner = root / 'source', root / 'runner'
                source.mkdir(); runner.mkdir()
                private, output = runner / 'chat-timeline-owner-private', runner / 'chat-timeline-owner-encrypted'
                stderr = io.StringIO()
                @contextlib.contextmanager
                def failed_scope(*_):
                    def remove():
                        raise failure
                    yield remove
                with patch.dict(os.environ, {'GITHUB_WORKSPACE': str(root), 'RUNNER_TEMP': str(runner)}), \
                        patch.object(sys, 'argv', ['owner_ci', '--source', str(source), '--private', str(private), '--output', str(output)]), \
                        patch.object(ci, 'execute', side_effect=lambda *_: private.mkdir()), \
                        patch.object(ci, 'private_cleanup_scope', failed_scope), \
                        contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as error:
                        ci.main()
                self.assertEqual(1, error.exception.code)
                self.assertIn('Private temporary directory cleanup failed.', stderr.getvalue())
                self.assertNotIn('PRIVATE_SENTINEL', stderr.getvalue())
                if isinstance(failure, ci.PrivateCleanupError):
                    self.assertIn('stage=remove_tree reason=permission', stderr.getvalue())


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL is needed for actual envelope round trip')
class EncryptionBoundaries(unittest.TestCase):
    def test_round_trip_and_ciphertext_receipt(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {'EXPECTED_REVISION': 'a' * 40}):
            root = Path(temporary)
            key, certificate = root / 'test-key.pem', root / 'test-certificate.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-keyout', str(key), '-out', str(certificate), '-days', '1',
                            '-subj', '/CN=Ephemeral unit test recipient'], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            payload = root / 'private.zip'
            marker = b'PRIVATE_FIXTURE_CONTENT_12345' * 200
            payload.write_bytes(marker)
            output = root / 'encrypted'
            receipt = ci.encrypt_artifact(payload, certificate, output)
            encrypted = output / 'Chat-Timeline-private-result.zip.p7m'
            self.assertNotIn(marker[:27], encrypted.read_bytes())
            self.assertNotIn('PRIVATE_FIXTURE', json.dumps(receipt))
            self.assertEqual(ci.bootstrap.sha256(encrypted), receipt['sha256'])
            decrypted = subprocess.run(['openssl', 'cms', '-decrypt', '-binary', '-inform', 'DER',
                                        '-in', str(encrypted), '-recip', str(certificate),
                                        '-inkey', str(key)], check=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            self.assertEqual(marker, decrypted.stdout)
            self.assertFalse(receipt['device_installable_directly'])
            self.assertEqual({'encrypted-artifact.json', encrypted.name}, {p.name for p in output.iterdir()})

    def test_bad_recipient_never_copies_plaintext(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload, certificate, output = root / 'private.zip', root / 'invalid.pem', root / 'out'
            payload.write_bytes(b'PRIVATE_FIXTURE')
            certificate.write_text('not a certificate')
            with self.assertRaises(ci.PrivateBuildRejected):
                ci.encrypt_artifact(payload, certificate, output)
            self.assertEqual([], list(output.iterdir()))


if __name__ == '__main__':
    unittest.main()
