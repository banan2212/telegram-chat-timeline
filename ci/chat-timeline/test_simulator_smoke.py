"""Regression checks for timeout evidence, not native simulator acceptance."""
from pathlib import Path
import base64
import json
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import simulator_smoke as smoke


def timeout_child(error):
    def spawn(args, stdout, stderr):
        stdout.write(error.stdout or b'')
        stderr.write(error.stderr or b'')
        stdout.flush()
        stderr.flush()
        child = Mock(pid=4321, returncode=None)
        child.wait.side_effect = [error, -9]
        child.poll.return_value = None
        child.kill.side_effect = lambda: setattr(child, 'returncode', -9)
        return child
    return spawn


class InstallDiagnosticsChecks(unittest.TestCase):
    def test_timeout_preserves_bounded_partial_output_and_remains_failure(self):
        error = subprocess.TimeoutExpired(['simctl', 'install'], 120,
                                          output=b'x' * 20000 + b'partial stdout\xff', stderr=b'partial stderr')
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            with patch.object(smoke.subprocess, 'Popen', side_effect=timeout_child(error)), \
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
            with patch.object(smoke.subprocess, 'Popen', side_effect=timeout_child(subprocess.TimeoutExpired(['test'], 1))):
                with self.assertRaises(subprocess.TimeoutExpired):
                    smoke.command(['test'], timeout=1, output=output)
            self.assertIn('timeout=1s', (output / 'native-commands.log').read_text())

    def test_evidence_write_failure_does_not_replace_timeout(self):
        error = subprocess.TimeoutExpired(['simctl', 'install'], 120, output=b'partial')
        with patch.object(smoke.subprocess, 'Popen', side_effect=timeout_child(error)), \
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


class DirectChildChecks(unittest.TestCase):
    def test_finished_child_does_not_wait_for_inherited_output_handles(self):
        script = ("import subprocess,sys; "
                  "subprocess.Popen([sys.executable,'-c','import time; time.sleep(3)'], close_fds=False); "
                  "print('direct child completed', flush=True)")
        try:
            with tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary)
                started = time.monotonic()
                value = smoke.command([sys.executable, '-c', script], timeout=2, output=output)
                self.assertLess(time.monotonic() - started, 2.5,
                                'command() waited for the descendant instead of the direct child')
                self.assertEqual(value, 'direct child completed')
                self.assertIn('direct_child_returncode=0', (output / 'native-commands.log').read_text())
        finally:
            # The intentionally inherited-handle descendant has a bounded self-exit.
            time.sleep(3.1)

    def test_live_direct_child_timeout_stays_failure_and_is_reaped(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            with self.assertRaises(subprocess.TimeoutExpired):
                smoke.command([sys.executable, '-c', "import time; print('started', flush=True); time.sleep(5)"],
                              timeout=0.5, output=output)
            log = (output / 'native-commands.log').read_text()
            self.assertIn('started', log)
            self.assertIn('direct_child_returncode_before_termination=None', log)
            self.assertNotIn('direct_child_returncode_after_termination=None', log)

    def test_nonzero_direct_exit_remains_failure(self):
        with self.assertRaisesRegex(RuntimeError, 'failed with exit 7'):
            smoke.command([sys.executable, '-c', 'import sys; sys.exit(7)'], timeout=2)

    def test_json_return_is_complete_not_evidence_tail(self):
        value = smoke.command([sys.executable, '-c', "import json; print(json.dumps({'payload':'x'*20000}))"], timeout=2)
        self.assertEqual(len(json.loads(value)['payload']), 20000)

    def test_oversized_stdout_is_explicit_failure(self):
        with self.assertRaisesRegex(RuntimeError, '4 MiB full-output limit'):
            smoke.command([sys.executable, '-c', "print('x'*(4*1024*1024+1))"], timeout=2)


class LaunchDiagnosticsChecks(unittest.TestCase):
    def test_launch_requires_original_command_success_without_retries(self):
        for diagnostic_error in (None, OSError('diagnostics unavailable')):
            with self.subTest(diagnostic_error=diagnostic_error), tempfile.TemporaryDirectory() as temporary:
                error = subprocess.TimeoutExpired(['simctl', 'launch'], 120)
                with patch.object(smoke, 'command', side_effect=error) as launch, \
                        patch.object(smoke, 'launch_diagnostics', side_effect=diagnostic_error) as diagnostics:
                    with self.assertRaises(subprocess.TimeoutExpired) as raised:
                        smoke.launch_app(Path(temporary), 'device-id', 'org.example.app', 'Telegram')
                self.assertIs(raised.exception, error)
                self.assertEqual(launch.call_count, 1)
                self.assertEqual(launch.call_args.kwargs['timeout'], 120)
                self.assertNotIn('acceptable_codes', launch.call_args.kwargs)
                diagnostics.assert_called_once()

    def test_launch_preserves_pid_output(self):
        with patch.object(smoke, 'command', return_value='org.example.app: 123') as launch, \
                patch.object(smoke, 'launch_diagnostics') as diagnostics:
            self.assertEqual(smoke.launch_app(Path('unused'), 'device-id', 'org.example.app', 'Telegram'),
                             'org.example.app: 123')
        diagnostics.assert_not_called()

    def test_launch_probes_record_correct_stage_even_when_probe_times_out(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            with patch.object(smoke, 'command', side_effect=[subprocess.TimeoutExpired(['readback'], 15), '', '']) as probes:
                smoke.launch_diagnostics(output, 'device-id', 'org.example.app', 'Telegram')
            report = json.loads((output / 'launch-diagnostics.json').read_text())
            self.assertEqual(report['scope'], 'launch_failure_diagnostics')
            self.assertFalse(report['launch_retried'])
            self.assertEqual([item['result'] for item in report['checks']], ['unknown', 'collected', 'collected'])
            self.assertEqual([item.kwargs['timeout'] for item in probes.call_args_list], [15, 20, 20])
            self.assertFalse((output / 'install-diagnostics.json').exists())
            predicate = probes.call_args_list[1].args[0][-1]
            for value in ('Telegram', 'runningboardd', 'FrontBoard'):
                self.assertIn(value, predicate)


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
