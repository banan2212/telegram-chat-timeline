"""Synthetic POSIX deletion boundaries; no owner data or credentials."""
import errno
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch

import private_cleanup as cleanup


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
        calls = 0
        def changed(fd):
            nonlocal calls
            calls += 1
            value = real_fstat(fd)
            if calls == 2:
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


if __name__ == '__main__':
    unittest.main()
