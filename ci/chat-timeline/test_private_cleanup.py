"""Synthetic POSIX deletion boundaries; no owner data or credentials."""
import errno
import contextlib
import io
import multiprocessing
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

import private_cleanup as cleanup
import owner_ci as ci


def _reject_special_lock_process(runner, results):
    try:
        cleanup.cleanup_private(Path(runner) / cleanup.PRIVATE_NAME, Path(runner))
    except cleanup.PrivateCleanupError as error:
        results.put(('rejected', error.stage, error.reason, error.operation))
    except BaseException as error:
        results.put(('error', type(error).__name__))
    else:
        results.put(('accepted',))


def _cleanup_process(runner, source, entered, release, finished, results, *, before_lock=False):
    """Real separate processes reproduce finally/fallback cleanup contention."""
    try:
        if before_lock:
            entered.set()
        with cleanup.private_cleanup_scope(Path(runner) / cleanup.PRIVATE_NAME, Path(runner)) as remove_private:
            if not before_lock:
                entered.set()
            if release is not None and not release.wait(15):
                raise RuntimeError('synthetic_release_timeout')
            ci.cleanup_configuration(Path(source))
            removed = remove_private()
        results.put(('ok', removed))
    except BaseException as error:
        results.put(('error', type(error).__name__))
    finally:
        finished.set()


def _failed_owner_process(runner, source, entered, release, finished, results):
    """Exercise the real main() failure path against a separate fallback cleaner."""
    runner, source = Path(runner), Path(source)
    private = runner / cleanup.PRIVATE_NAME
    output = runner / 'chat-timeline-owner-encrypted'
    def fail_build(*_):
        private.mkdir()
        (private / 'fixture').write_bytes(b'synthetic')
        raise RuntimeError('synthetic_build_failure')
    def save_evidence(*_):
        entered.set()
        if not release.wait(15):
            raise RuntimeError('synthetic_release_timeout')
        # A concurrent cleanup must not remove the directory before this write.
        (private / 'failed-build.zip').write_bytes(b'synthetic_archive')
    try:
        with patch.dict(os.environ, {'GITHUB_WORKSPACE': str(source.parent), 'RUNNER_TEMP': str(runner)}), \
                patch.object(sys, 'argv', ['owner_ci', '--source', str(source), '--private', str(private), '--output', str(output)]), \
                patch.object(ci, 'execute', fail_build), patch.object(ci, 'protect_failure_log', save_evidence), \
                contextlib.redirect_stderr(io.StringIO()) as diagnostics:
            try:
                ci.main()
            except SystemExit as error:
                if error.code != 1 or 'could not be encrypted' in diagnostics.getvalue() or 'cleanup failed' in diagnostics.getvalue():
                    raise RuntimeError('synthetic_owner_cleanup_failed')
            else:
                raise RuntimeError('synthetic_failure_not_reported')
        results.put(('ok', True))
    except BaseException as error:
        results.put(('error', type(error).__name__))
    finally:
        finished.set()


@unittest.skipUnless(cleanup._supported(), 'POSIX descriptor primitives required')
class PrivateCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.runner = self.root / 'runner'
        self.runner.mkdir()
        self.private = self.runner / cleanup.PRIVATE_NAME

    def test_readonly_bazel_tree_reproduces_old_failure_and_is_removed(self):
        directory = self.private / 'bazel/out/tree'
        directory.mkdir(parents=True)
        (directory / 'result').write_bytes(b'fixture')
        for path in (directory, directory.parent, directory.parent.parent):
            path.chmod(0o555)
        if os.geteuid() != 0:
            # Both former cleanup call sites fail on the same non-writable tree.
            for _ in range(2):
                with self.assertRaises(PermissionError):
                    shutil.rmtree(self.private)
        self.assertTrue(cleanup.cleanup_private(self.private, self.runner))
        self.assertFalse(self.private.exists())

    def test_normal_tree_and_missing_tree_are_idempotent(self):
        (self.private / 'signing').mkdir(parents=True)
        (self.private / 'signing/fixture').write_bytes(b'fixture')
        keep = self.runner / 'unrelated'
        keep.write_bytes(b'keep')
        self.assertTrue(cleanup.cleanup_private(self.private, self.runner))
        self.assertFalse(cleanup.cleanup_private(self.private, self.runner))
        self.assertEqual(b'keep', keep.read_bytes())

    def test_external_symlinks_and_hardlinked_file_unchanged(self):
        outside = self.root / 'outside'
        outside.mkdir()
        target = outside / 'keep'
        target.write_bytes(b'outside')
        target.chmod(0o444)
        outside.chmod(0o555)
        before = (stat.S_IMODE(outside.stat().st_mode), stat.S_IMODE(target.stat().st_mode))
        self.private.mkdir()
        (self.private / 'directory-link').symlink_to(outside, target_is_directory=True)
        (self.private / 'file-link').symlink_to(target)
        (self.private / 'dangling-link').symlink_to(self.root / 'absent')
        os.link(target, self.private / 'hard-link')
        self.assertTrue(cleanup.cleanup_private(self.private, self.runner))
        self.assertEqual(b'outside', target.read_bytes())
        self.assertEqual(before, (stat.S_IMODE(outside.stat().st_mode), stat.S_IMODE(target.stat().st_mode)))

    def test_root_symlink_is_rejected_without_touching_target(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'keep').write_bytes(b'keep')
        self.private.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(cleanup.PrivateCleanupError) as error:
            cleanup.cleanup_private(self.private, self.runner)
        self.assertEqual('boundary', error.exception.reason)
        self.assertTrue(self.private.is_symlink())
        self.assertEqual(b'keep', (outside / 'keep').read_bytes())

    def test_wrong_root_alias_and_relative_paths_are_rejected(self):
        self.private.mkdir()
        (self.private / 'keep').write_bytes(b'keep')
        alias = self.root / 'runner-alias'
        alias.symlink_to(self.runner, target_is_directory=True)
        for path, root in ((self.private, self.root),
                           (self.runner / 'wrong-name', self.runner),
                           (alias / cleanup.PRIVATE_NAME, alias),
                           (Path(cleanup.PRIVATE_NAME), self.runner)):
            with self.subTest(path=path.name), self.assertRaises(cleanup.PrivateCleanupError):
                cleanup.cleanup_private(path, root)
        self.assertEqual(b'keep', (self.private / 'keep').read_bytes())

    def test_identity_change_is_rejected_before_permission_change(self):
        self.private.mkdir()
        (self.private / 'keep').write_bytes(b'keep')
        real_fstat = os.fstat
        private_inode = self.private.stat().st_ino
        def changed(fd):
            value = real_fstat(fd)
            if value.st_ino == private_inode:
                fields = list(value)
                fields[1] += 1
                return os.stat_result(fields)
            return value
        with patch.object(cleanup.os, 'fstat', changed), patch.object(cleanup.os, 'fchmod') as chmod:
            with self.assertRaises(cleanup.PrivateCleanupError) as error:
                cleanup.cleanup_private(self.private, self.runner)
        self.assertEqual('changed', error.exception.reason)
        chmod.assert_not_called()
        self.assertEqual(b'keep', (self.private / 'keep').read_bytes())

    def test_unsupported_primitives_fail_closed(self):
        self.private.mkdir()
        with patch.object(cleanup, '_supported', return_value=False):
            with self.assertRaises(cleanup.PrivateCleanupError) as error:
                cleanup.cleanup_private(self.private, self.runner)
        self.assertEqual('unsupported', error.exception.reason)
        self.assertTrue(self.private.is_dir())

    def test_os_error_is_fixed_labels_only(self):
        self.private.mkdir()
        with patch.object(cleanup.os, 'listdir', side_effect=PermissionError(errno.EACCES, 'PRIVATE_SENTINEL')):
            # Patching listdir changes function identity in the capability set.
            with patch.object(cleanup, '_supported', return_value=True):
                with self.assertRaises(cleanup.PrivateCleanupError) as error:
                    cleanup.cleanup_private(self.private, self.runner)
        self.assertEqual('remove_tree', error.exception.stage)
        self.assertEqual('permission', error.exception.reason)
        self.assertNotIn('PRIVATE_SENTINEL', str(error.exception))
        self.assertEqual('list_directory', error.exception.operation)
        self.assertEqual('EACCES', error.exception.errno_name)

    def _concurrent_cleanup(self, *, terminate_first=False, failure_evidence=False):
        if not failure_evidence:
            self.private.mkdir()
            (self.private / 'fixture').write_bytes(b'synthetic')
        source = self.root / 'source'
        configuration = source / 'build-input/configuration-repository'
        configuration.mkdir(parents=True)
        (configuration / 'fixture').write_bytes(b'synthetic')
        keep = source / 'build-input/unrelated'
        keep.write_bytes(b'keep')
        context = multiprocessing.get_context('spawn')
        first_entered, second_started = context.Event(), context.Event()
        release = context.Event()
        first_finished, second_finished = context.Event(), context.Event()
        results = context.Queue()
        first = context.Process(target=_failed_owner_process if failure_evidence else _cleanup_process,
                                args=(str(self.runner), str(source), first_entered,
                                release, first_finished, results))
        second = context.Process(target=_cleanup_process, args=(str(self.runner), str(source), second_started,
                                 None, second_finished, results), kwargs={'before_lock': True})
        started = []
        try:
            first.start(); started.append(first)
            self.assertTrue(first_entered.wait(10), 'First process did not acquire cleanup scope')
            second.start(); started.append(second)
            self.assertTrue(second_started.wait(10), 'Second process did not start')
            self.assertFalse(second_finished.wait(0.3), 'Second cleaner escaped the held scope')
            self.assertTrue(configuration.is_dir(), 'Configuration was deleted outside the shared scope')
            if terminate_first:
                first.terminate()  # Only this test-created process, no broad PID selection.
            else:
                release.set()
            first.join(10); second.join(10)
            self.assertFalse(first.is_alive())
            self.assertFalse(second.is_alive())
            self.assertEqual(0, second.exitcode)
            values = [results.get(timeout=2) for _ in range(1 if terminate_first else 2)]
            self.assertEqual([('ok', True)] if terminate_first else [('ok', False), ('ok', True)], sorted(values))
            self.assertFalse(configuration.exists())
            self.assertFalse(self.private.exists())
            self.assertEqual(b'keep', keep.read_bytes())
            lock = self.runner / cleanup.LOCK_NAME
            self.assertEqual(b'', lock.read_bytes())
            self.assertEqual(0o600, stat.S_IMODE(lock.stat().st_mode))
        finally:
            # Do not notify an Event whose waiting process was terminated:
            # multiprocessing's condition wait count can retain the dead waiter.
            for process in started:
                if process.is_alive():
                    process.terminate()
                process.join(5)
            results.close(); results.join_thread()

    def test_concurrent_finally_and_fallback_serialize_both_cleanup_locations(self):
        self._concurrent_cleanup()

    def test_cancelled_cleanup_process_releases_lock_for_fallback(self):
        self._concurrent_cleanup(terminate_first=True)

    def test_failure_evidence_cannot_overlap_fallback_deletion(self):
        self._concurrent_cleanup(failure_evidence=True)

    def test_lock_symlink_hardlink_or_nonempty_file_is_rejected(self):
        self.private.mkdir()
        keep = self.private / 'keep'
        keep.write_bytes(b'keep')
        outside = self.root / 'outside-lock'
        outside.write_bytes(b'')
        outside.chmod(0o600)
        lock = self.runner / cleanup.LOCK_NAME
        for mode in ('symlink', 'hardlink', 'nonempty'):
            with self.subTest(mode=mode):
                if mode == 'symlink':
                    lock.symlink_to(outside)
                elif mode == 'hardlink':
                    os.link(outside, lock)
                else:
                    lock.write_bytes(b'PRIVATE_SENTINEL')
                    lock.chmod(0o600)
                try:
                    with self.assertRaises(cleanup.PrivateCleanupError) as error:
                        cleanup.cleanup_private(self.private, self.runner)
                    self.assertEqual('lock', error.exception.stage)
                    self.assertNotIn('PRIVATE_SENTINEL', str(error.exception))
                    self.assertEqual(b'keep', keep.read_bytes())
                    self.assertEqual(b'', outside.read_bytes())
                finally:
                    lock.unlink()

    def test_lock_replaced_during_acquisition_is_rejected(self):
        self.private.mkdir()
        (self.private / 'keep').write_bytes(b'keep')
        real_flock = cleanup.fcntl.flock
        lock = self.runner / cleanup.LOCK_NAME
        def replace_lock(fd, flags):
            lock.rename(self.runner / 'old-lock')
            lock.write_bytes(b'')
            lock.chmod(0o600)
            return real_flock(fd, flags)
        with patch.object(cleanup.fcntl, 'flock', replace_lock):
            with self.assertRaises(cleanup.PrivateCleanupError) as error:
                cleanup.cleanup_private(self.private, self.runner)
        self.assertEqual(('lock', 'changed', 'inspect_lock'),
                         (error.exception.stage, error.exception.reason, error.exception.operation))
        self.assertEqual(b'keep', (self.private / 'keep').read_bytes())

    def test_fifo_lock_is_rejected_without_waiting_for_a_peer(self):
        self.private.mkdir()
        keep = self.private / 'keep'
        keep.write_bytes(b'keep')
        lock = self.runner / cleanup.LOCK_NAME
        os.mkfifo(lock, 0o600)
        context = multiprocessing.get_context('spawn')
        results = context.Queue()
        process = context.Process(target=_reject_special_lock_process, args=(str(self.runner), results))
        process.start()
        try:
            process.join(5)
            self.assertFalse(process.is_alive(), 'Opening a FIFO lock waited for a peer')
            self.assertEqual(0, process.exitcode)
            self.assertEqual(('rejected', 'lock', 'boundary', 'inspect_lock'), results.get(timeout=2))
            self.assertTrue(stat.S_ISFIFO(lock.lstat().st_mode))
            self.assertEqual(b'keep', keep.read_bytes())
        finally:
            if process.is_alive():
                process.terminate()  # Only this test-created process.
            process.join(5)
            results.close(); results.join_thread()

    def test_lock_wait_is_bounded_and_scope_callback_expires(self):
        self.private.mkdir()
        with patch.object(cleanup.fcntl, 'flock', side_effect=BlockingIOError(errno.EWOULDBLOCK, 'PRIVATE_SENTINEL')):
            with self.assertRaises(cleanup.PrivateCleanupError) as error:
                with cleanup.private_cleanup_scope(self.private, self.runner, lock_timeout=0):
                    self.fail('Busy lock entered scope')
        self.assertEqual(('lock', 'busy', 'wait_lock'),
                         (error.exception.stage, error.exception.reason, error.exception.operation))
        self.assertNotIn('PRIVATE_SENTINEL', str(error.exception))
        with cleanup.private_cleanup_scope(self.private, self.runner) as remover:
            pass
        with self.assertRaises(cleanup.PrivateCleanupError):
            remover()
        self.assertTrue(self.private.is_dir())


if __name__ == '__main__':
    unittest.main()
