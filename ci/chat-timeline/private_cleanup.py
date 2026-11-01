"""Remove only the dedicated owner-build tree, without following symlinks."""
from __future__ import annotations

import errno
import os
from pathlib import Path
import stat


PRIVATE_NAME = 'chat-timeline-owner-private'


class PrivateCleanupError(RuntimeError):
    """Only fixed labels may leave the private cleanup boundary."""
    def __init__(self, stage: str, reason: str):
        self.stage = stage if stage in {'validate', 'open_root', 'remove_tree'} else 'validate'
        self.reason = reason if reason in {'boundary', 'unsupported', 'changed', 'permission', 'io'} else 'io'
        super().__init__(f'Private cleanup failed: stage={self.stage} reason={self.reason}')


def _supported() -> bool:
    return (os.name == 'posix' and hasattr(os, 'O_DIRECTORY') and hasattr(os, 'O_NOFOLLOW')
            and hasattr(os, 'fchmod') and hasattr(os, 'geteuid')
            and {os.open, os.stat, os.unlink, os.rmdir}.issubset(os.supports_dir_fd)
            and os.stat in os.supports_follow_symlinks and os.listdir in os.supports_fd)


def _same(expected, actual) -> bool:
    return expected.st_dev == actual.st_dev and expected.st_ino == actual.st_ino


def _remove_directory(parent_fd: int, name: str, expected, device: int) -> None:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        opened = os.fstat(directory_fd)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same(expected, opened) or not _same(opened, current):
            raise PrivateCleanupError('remove_tree', 'changed')
        if opened.st_dev != device or opened.st_uid != os.geteuid():
            raise PrivateCleanupError('remove_tree', 'boundary')
        # Bazel creates read-only directories. Change only this opened directory;
        # never chmod a file (which might have a hard link outside the tree).
        mode = stat.S_IMODE(opened.st_mode)
        if mode & stat.S_IRWXU != stat.S_IRWXU:
            os.fchmod(directory_fd, mode | stat.S_IRWXU)
        for child in os.listdir(directory_fd):
            entry = os.stat(child, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(entry.st_mode):
                _remove_directory(directory_fd, child, entry, device)
            else:
                # A symlink is removed as a directory entry, never traversed.
                os.unlink(child, dir_fd=directory_fd)
        if not _same(opened, os.stat(name, dir_fd=parent_fd, follow_symlinks=False)):
            raise PrivateCleanupError('remove_tree', 'changed')
        os.rmdir(name, dir_fd=parent_fd)
    finally:
        os.close(directory_fd)


def cleanup_private(private: Path, runner_temp: Path) -> bool:
    """Return whether a tree was removed; callers must stop build children first.

    Both arguments must already be absolute and the runner root canonical. This
    handles read-only Bazel output, not concurrent mutation by a live build.
    """
    stage = 'validate'
    try:
        private, runner_temp = Path(private), Path(runner_temp)
        if (not private.is_absolute() or not runner_temp.is_absolute()
                or runner_temp != runner_temp.resolve(strict=True)
                or private != runner_temp / PRIVATE_NAME):
            raise PrivateCleanupError(stage, 'boundary')
        if not _supported():
            raise PrivateCleanupError(stage, 'unsupported')
        stage = 'open_root'
        expected_parent = runner_temp.lstat()
        parent_fd = os.open(runner_temp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            opened_parent = os.fstat(parent_fd)
            if not _same(expected_parent, opened_parent):
                raise PrivateCleanupError(stage, 'changed')
            try:
                entry = os.stat(PRIVATE_NAME, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return False
            if not stat.S_ISDIR(entry.st_mode):
                raise PrivateCleanupError(stage, 'boundary')
            stage = 'remove_tree'
            _remove_directory(parent_fd, PRIVATE_NAME, entry, opened_parent.st_dev)
            return True
        finally:
            os.close(parent_fd)
    except PrivateCleanupError:
        raise
    except OSError as error:
        reason = ('permission' if error.errno in {errno.EACCES, errno.EPERM} else
                  'changed' if error.errno in {errno.ELOOP, errno.ENOTDIR, errno.ENOENT} else 'io')
        raise PrivateCleanupError(stage, reason) from None
    except Exception:
        raise PrivateCleanupError(stage, 'io') from None
