"""Regression checks for timeout evidence, not native simulator acceptance."""
from pathlib import Path
import base64
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import simulator_smoke as smoke


class InstallDiagnosticsChecks(unittest.TestCase):
    def test_timeout_preserves_bounded_partial_output_and_remains_failure(self):
        error = subprocess.TimeoutExpired(['simctl', 'install'], 120,
                                          output=b'x' * 20000 + b'partial stdout\xff', stderr=b'partial stderr')
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            with patch.object(smoke.subprocess, 'run', side_effect=error), \
                    patch.object(smoke.time, 'monotonic', side_effect=[10.0, 132.5]):
                with self.assertRaises(subprocess.TimeoutExpired) as raised:
                    smoke.command(['simctl', 'install'], timeout=120, output=output, label='install')
            self.assertIs(raised.exception, error)
            log = (output / 'native-commands.log').read_text(encoding='utf-8')
            self.assertIn('timeout=120s', log)
            self.assertIn('elapsed=122.500s', log)
            self.assertIn('partial stdout\ufffd', log)
            self.assertIn('partial stderr', log)
            self.assertLess(len(log), 17000)

    def test_timeout_without_output_still_writes_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            with patch.object(smoke.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['test'], 1)):
                with self.assertRaises(subprocess.TimeoutExpired):
                    smoke.command(['test'], timeout=1, output=output)
            self.assertIn('timeout=1s', (output / 'native-commands.log').read_text())

    def test_evidence_write_failure_does_not_replace_timeout(self):
        error = subprocess.TimeoutExpired(['simctl', 'install'], 120, output=b'partial')
        with patch.object(smoke.subprocess, 'run', side_effect=error), \
                patch.object(smoke, 'command_evidence', side_effect=OSError('disk full')):
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                smoke.command(['simctl', 'install'], timeout=120, output=Path('unused'))
        self.assertIs(raised.exception, error)

    def test_diagnostics_never_retry_install_or_mask_original_failure(self):
        for diagnostic_error in (None, RuntimeError('diagnostics unavailable')):
            with self.subTest(diagnostic_error=diagnostic_error), tempfile.TemporaryDirectory() as temporary:
                error = subprocess.TimeoutExpired(['simctl', 'install'], 120)
                with patch.object(smoke, 'command', side_effect=error) as install, \
                        patch.object(smoke, 'install_diagnostics', side_effect=diagnostic_error) as diagnostics:
                    with self.assertRaises(subprocess.TimeoutExpired) as raised:
                        smoke.install_app(Path(temporary), 'device-id', Path('Telegram.app'), 'org.example.app')
                self.assertIs(raised.exception, error)
                self.assertEqual(install.call_count, 1)
                self.assertEqual(install.call_args.kwargs['timeout'], 120)
                diagnostics.assert_called_once()


class ScreenshotChecks(unittest.TestCase):
    PNG = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4////fwAJ+wP9KobjigAAAABJRU5ErkJggg==')

    def test_capture_records_actual_command_window_separately_from_threshold(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / 'startup-02s.png').write_bytes(self.PNG)
            report = {'capture_attempts': [], 'screenshots': []}
            with patch.object(smoke, 'command', return_value='') as capture, \
                    patch.object(smoke.time, 'monotonic', side_effect=[107.1, 147.9]):
                smoke.capture_screenshot(output, 'device-id', 2, 100.0, report)
            self.assertEqual(capture.call_args.kwargs['timeout'], 90)
            self.assertNotIn('acceptable_codes', capture.call_args.kwargs)
            attempt = report['capture_attempts'][0]
            self.assertEqual(attempt['nominal_threshold_seconds'], 2)
            self.assertEqual(attempt['command_started_seconds_after_launch'], 7.1)
            self.assertEqual(attempt['command_ended_seconds_after_launch'], 47.9)
            self.assertEqual(attempt['command_elapsed_seconds'], 40.8)
            self.assertEqual(attempt['command_result'], 'pass')
            self.assertEqual(len(report['screenshots']), 1)

    def test_complete_png_does_not_override_failed_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / 'startup-02s.png').write_bytes(self.PNG)
            report = {'capture_attempts': [], 'screenshots': []}
            error = subprocess.TimeoutExpired(['simctl', 'io'], 90)
            with patch.object(smoke, 'command', side_effect=error), \
                    patch.object(smoke.time, 'monotonic', side_effect=[102.0, 192.5]):
                with self.assertRaises(subprocess.TimeoutExpired) as raised:
                    smoke.capture_screenshot(output, 'device-id', 2, 100.0, report)
            self.assertIs(raised.exception, error)
            self.assertEqual(report['screenshots'], [])
            self.assertEqual(report['capture_attempts'][0]['command_result'], 'fail')
            self.assertEqual(report['capture_attempts'][0]['command_elapsed_seconds'], 90.5)


if __name__ == '__main__':
    unittest.main()
