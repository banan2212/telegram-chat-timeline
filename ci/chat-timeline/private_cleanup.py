"""Remove only the dedicated owner-build tree, without following symlinks."""
from __future__ import annotations

import errno
import contextlib
import os
from pathlib import Path
import stat
import time

try:
    import fcntl
except ImportError:
    fcntl = None


PRIVATE_NAME = 'chat-timeline-owner-private'
LOCK_NAME = 'chat-timeline-owner-cleanup.lock'
OPERATIONS = {'none', 'validate', 'open_root', 'inspect_root', 'open_lock', 'inspect_lock',
              'wait_lock', 'open_directory', 'inspect_directory', 'verify_directory',
              'chmod_directory', 'list_directory', 'inspect_entry', 'unlink_entry', 'remove_directory'}
ERRNOS = {value: name for name in ('EACCES', 'EPERM', 'ELOOP', 'ENOTDIR', 'ENOENT', 'ENOTEMPTY',
                                  'EBUSY', 'EAGAIN', 'EWOULDBLOCK')
          if (value := getattr(errno, name, None)) is not None}


class PrivateCleanupError(RuntimeError):
    """Only fixed labels may leave the private cleanup boundary."""
    def __init__(self, stage: str, reason: str, operation: str = 'none', errno_name: str = 'none'):
        self.stage = stage if stage in {'validate', 'open_root', 'lock', 'remove_tree'} else 'validate'
        self.reason = reason if reason in {'boundary', 'unsupported', 'changed', 'permission', 'busy', 'io'} else 'io'
        self.operation = operation if operation in OPERATIONS else 'none'
        self.errno_name = errno_name if errno_name in {*ERRNOS.values(), 'none', 'other'} else 'other'
        self.summary = (f'stage={self.stage} reason={self.reason} '
                        f'operation={self.operation} errno={self.errno_name}')
        super().__init__('Private cleanup failed: ' + self.summary)


def _call(stage, operation, function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except OSError as error:
        reason = ('permission' if error.errno in {errno.EACCES, errno.EPERM} else
                  'changed' if error.errno in {errno.ELOOP, errno.ENOTDIR, errno.ENOENT} else 'io')
        raise PrivateCleanupError(stage, reason, operation, ERRNOS.get(error.errno, 'other')) from None


def _supported() -> bool:
    return (os.name == 'posix' and fcntl is not None and hasattr(os, 'O_DIRECTORY') and hasattr(os, 'O_NOFOLLOW')
            and hasattr(os, 'O_NONBLOCK') and hasattr(os, 'fchmod') and hasattr(os, 'geteuid')
            and {os.open, os.stat, os.unlink, os.rmdir}.issubset(os.supports_dir_fd)
            and os.stat in os.supports_follow_symlinks and os.listdir in os.supports_fd)


def _same(expected, actual) -> bool:
    return expected.st_dev == actual.st_dev and expected.st_ino == actual.st_ino


def _remove_directory(parent_fd: int, name: str, expected, device: int) -> None:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fd = _call('remove_tree', 'open_directory', os.open, name, flags, dir_fd=parent_fd)
    try:
        opened = _call('remove_tree', 'inspect_directory', os.fstat, directory_fd)
        current = _call('remove_tree', 'inspect_directory', os.stat, name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same(expected, opened) or not _same(opened, current):
            raise PrivateCleanupError('remove_tree', 'changed', 'verify_directory')
        if opened.st_dev != device or opened.st_uid != os.geteuid():
            raise PrivateCleanupError('remove_tree', 'boundary', 'verify_directory')
        # Bazel creates read-only directories. Change only this opened directory;
        # never chmod a file (which might have a hard link outside the tree).
        mode = stat.S_IMODE(opened.st_mode)
        if mode & stat.S_IRWXU != stat.S_IRWXU:
            _call('remove_tree', 'chmod_directory', os.fchmod, directory_fd, mode | stat.S_IRWXU)
        for child in _call('remove_tree', 'list_directory', os.listdir, directory_fd):
            entry = _call('remove_tree', 'inspect_entry', os.stat, child, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(entry.st_mode):
                _remove_directory(directory_fd, child, entry, device)
            else:
                # A symlink is removed as a directory entry, never traversed.
                _call('remove_tree', 'unlink_entry', os.unlink, child, dir_fd=directory_fd)
        current = _call('remove_tree', 'inspect_directory', os.stat, name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same(opened, current):
            raise PrivateCleanupError('remove_tree', 'changed', 'verify_directory')
        _call('remove_tree', 'remove_directory', os.rmdir, name, dir_fd=parent_fd)
    finally:
        os.close(directory_fd)


def _open_root(private: Path, runner_temp: Path) -> int:
    try:
        private, runner_temp = Path(private), Path(runner_temp)
        if (not private.is_absolute() or not runner_temp.is_absolute()
                or runner_temp != runner_temp.resolve(strict=True)
                or private != runner_temp / PRIVATE_NAME):
            raise PrivateCleanupError('validate', 'boundary', 'validate')
        if not _supported():
            raise PrivateCleanupError('validate', 'unsupported', 'validate')
    except PrivateCleanupError:
        raise
    except Exception:
        raise PrivateCleanupError('validate', 'io', 'validate') from None
    expected_parent = _call('open_root', 'inspect_root', runner_temp.lstat)
    parent_fd = _call('open_root', 'open_root', os.open, runner_temp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if not _same(expected_parent, _call('open_root', 'inspect_root', os.fstat, parent_fd)):
            raise PrivateCleanupError('open_root', 'changed', 'inspect_root')
        return parent_fd
    except BaseException:
        os.close(parent_fd)
        raise


def _lock(parent_fd: int, timeout: float) -> int:
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, 'O_CLOEXEC', 0)
    lock_fd = _call('lock', 'open_lock', os.open, LOCK_NAME, flags, 0o600, dir_fd=parent_fd)
    try:
        opened = _call('lock', 'inspect_lock', os.fstat, lock_fd)
        current = _call('lock', 'inspect_lock', os.stat, LOCK_NAME, dir_fd=parent_fd, follow_symlinks=False)
        if (not _same(opened, current) or not stat.S_ISREG(opened.st_mode)
                or opened.st_dev != _call('lock', 'inspect_root', os.fstat, parent_fd).st_dev
                or opened.st_uid != os.geteuid() or opened.st_nlink != 1 or opened.st_size != 0
                or stat.S_IMODE(opened.st_mode) & 0o077):
            raise PrivateCleanupError('lock', 'boundary', 'inspect_lock')
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise PrivateCleanupError('lock', 'busy', 'wait_lock') from None
                time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
            except OSError as error:
                raise PrivateCleanupError('lock', 'io', 'wait_lock', ERRNOS.get(error.errno, 'other')) from None
        current = _call('lock', 'inspect_lock', os.stat, LOCK_NAME, dir_fd=parent_fd, follow_symlinks=False)
        if not _same(opened, current):
            raise PrivateCleanupError('lock', 'changed', 'inspect_lock')
        return lock_fd
    except BaseException:
        os.close(lock_fd)
        raise


@contextlib.contextmanager
def private_cleanup_scope(private: Path, runner_temp: Path, *, lock_timeout: float = 30.0):
    """Serialize configuration + tree cleanup across finally and fallback callers.

    The yielded remover is valid only within this scope. Build writers must be
    stopped separately. The empty task-owned lock remains beside the tree so a
    waiting caller never locks an unlinked inode while a new lock is created.
    """
    if not isinstance(lock_timeout, (int, float)) or not 0 <= lock_timeout <= 30:
        raise PrivateCleanupError('validate', 'boundary', 'validate')
    parent_fd = _open_root(private, runner_temp)
    try:
        lock_fd = _lock(parent_fd, lock_timeout)
        active = True
        try:
            def remove_private():
                if not active:
                    raise PrivateCleanupError('validate', 'boundary', 'validate')
                try:
                    entry = os.stat(PRIVATE_NAME, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    return False
                except OSError as error:
                    raise PrivateCleanupError('remove_tree', 'io', 'inspect_entry', ERRNOS.get(error.errno, 'other')) from None
                if not stat.S_ISDIR(entry.st_mode):
                    raise PrivateCleanupError('remove_tree', 'boundary', 'verify_directory')
                device = _call('remove_tree', 'inspect_root', os.fstat, parent_fd).st_dev
                _remove_directory(parent_fd, PRIVATE_NAME, entry, device)
                return True
            yield remove_private
        finally:
            active = False
            os.close(lock_fd)
    finally:
        os.close(parent_fd)


def cleanup_private(private: Path, runner_temp: Path) -> bool:
    """Remove the dedicated tree; callers must stop build writers first."""
    try:
        with private_cleanup_scope(private, runner_temp) as remove_private:
            return remove_private()
    except PrivateCleanupError:
        raise
    except Exception:
        raise PrivateCleanupError('remove_tree', 'io') from None
