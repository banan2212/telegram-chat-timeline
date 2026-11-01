"""Private CI envelope and cleanup boundaries; no owner profiles or keys."""
import base64
import contextlib
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
                with patch.dict(os.environ, {'GITHUB_WORKSPACE': str(root), 'RUNNER_TEMP': str(runner)}), \
                        patch.object(sys, 'argv', ['owner_ci', '--source', str(source), '--private', str(private), '--output', str(output)]), \
                        patch.object(ci, 'execute', side_effect=lambda *_: private.mkdir()), \
                        patch.object(ci, 'cleanup_private', side_effect=failure), \
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
