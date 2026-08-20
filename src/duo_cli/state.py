"""FD-anchored private state with atomic enrollment and an exclusive lock."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
import secrets
import stat

from .errors import AuthenticationError, BusyError, DuoCliError


ENROLLMENT_FILE = "enrollment.json"
LOCK_FILE = ".lock"
_TEMP_PREFIX = ".tmp-enrollment-"
_MAX_ENROLLMENT_BYTES = 1_000_000


def default_state_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "config"


def _is_current_owner(info: os.stat_result) -> bool:
    return not hasattr(os, "getuid") or info.st_uid == os.getuid()


class StatePaths:
    """A configured state root. File operations require a verified directory FD."""

    def __init__(self, root: Path):
        self.root = root.expanduser()

    def open_directory(self) -> "StateDirectory":
        try:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(os.fspath(self.root), flags)
        except OSError as exc:
            raise DuoCliError("Cannot securely access the configured Duo state directory.") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or not _is_current_owner(info):
                raise DuoCliError("Configured Duo state directory is not a current-user-owned directory.")
            os.fchmod(fd, 0o700)
            info = os.fstat(fd)
            if stat.S_IMODE(info.st_mode) != 0o700:
                raise DuoCliError("Cannot enforce mode 0700 on the Duo state directory.")
            return StateDirectory(self.root, fd)
        except BaseException:
            os.close(fd)
            raise


class StateDirectory:
    """All enrollment file operations are anchored to one verified directory FD."""

    def __init__(self, root: Path, fd: int):
        self.root = root
        self.fd = fd

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def _stat(self, name: str, *, required: bool) -> os.stat_result | None:
        try:
            info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            if required:
                raise AuthenticationError(
                    "No local Duo device enrollment. Use `duo login --qr FILE` only after "
                    "your tenant has authorized a separately enrolled device."
                )
            return None
        except OSError as exc:
            raise AuthenticationError("Cannot inspect local Duo enrollment state.") from exc
        return info

    @staticmethod
    def _assert_private_file(info: os.stat_result) -> None:
        if not stat.S_ISREG(info.st_mode) or not _is_current_owner(info) or stat.S_IMODE(info.st_mode) != 0o600:
            raise AuthenticationError(
                "Duo enrollment state must be a current-user-owned regular file with mode 0600."
            )

    def _open_private_read(self, name: str) -> int:
        expected = self._stat(name, required=True)
        assert expected is not None
        self._assert_private_file(expected)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(name, flags, dir_fd=self.fd)
        except OSError as exc:
            raise AuthenticationError("Cannot securely open local Duo enrollment state.") from exc
        try:
            actual = os.fstat(fd)
            if (
                actual.st_dev != expected.st_dev
                or actual.st_ino != expected.st_ino
                or not stat.S_ISREG(actual.st_mode)
                or not _is_current_owner(actual)
                or stat.S_IMODE(actual.st_mode) != 0o600
            ):
                raise AuthenticationError("Duo enrollment state changed while being opened.")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def read_enrollment(self) -> bytes:
        fd = self._open_private_read(ENROLLMENT_FILE)
        try:
            with os.fdopen(fd, "rb", closefd=True) as handle:
                content = handle.read(_MAX_ENROLLMENT_BYTES + 1)
        except OSError as exc:
            raise AuthenticationError("Cannot read local Duo enrollment state.") from exc
        if len(content) > _MAX_ENROLLMENT_BYTES:
            raise AuthenticationError("Local Duo enrollment state is unexpectedly large.")
        return content

    def _entry_exists(self, name: str) -> bool:
        return self._stat(name, required=False) is not None

    def assert_empty_for_enrollment(self) -> None:
        # Explicitly reject legacy split state too; no migration is performed.
        for name in (ENROLLMENT_FILE, "key.pem", "response.json"):
            if self._entry_exists(name):
                raise AuthenticationError(
                    "Local Duo enrollment state already exists. Refusing to replace it; run `duo logout` "
                    "only if you intend to remove this local device state."
                )

    def _cleanup_orphan_temps(self) -> None:
        """Remove only our verified private temporary files from interrupted writes."""
        try:
            names = os.listdir(self.fd)
        except OSError as exc:
            raise DuoCliError("Cannot inspect Duo state directory for interrupted enrollment writes.") from exc
        for name in names:
            if not name.startswith(_TEMP_PREFIX):
                continue
            info = self._stat(name, required=False)
            if info is None:
                continue
            self._assert_private_file(info)
            try:
                os.unlink(name, dir_fd=self.fd)
            except OSError as exc:
                raise DuoCliError("Cannot clean interrupted private enrollment state.") from exc
        try:
            os.fsync(self.fd)
        except OSError as exc:
            raise DuoCliError("Cannot sync Duo state directory cleanup.") from exc

    def write_enrollment_atomic(self, content: bytes) -> None:
        """Atomically commit one enrollment.json without replacing existing state."""
        if not isinstance(content, bytes) or not content or len(content) > _MAX_ENROLLMENT_BYTES:
            raise DuoCliError("Refusing invalid local enrollment data.")
        self._cleanup_orphan_temps()
        self.assert_empty_for_enrollment()
        temporary = _TEMP_PREFIX + secrets.token_hex(16)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd: int | None = None
        committed = False
        try:
            fd = os.open(temporary, flags, 0o600, dir_fd=self.fd)
            os.fchmod(fd, 0o600)
            view = memoryview(content)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
            os.close(fd)
            fd = None
            # link(2) is atomic and fails if enrollment.json appeared after the
            # preflight; unlike replace(), it can never overwrite another state.
            os.link(
                temporary,
                ENROLLMENT_FILE,
                src_dir_fd=self.fd,
                dst_dir_fd=self.fd,
                follow_symlinks=False,
            )
            committed = True
            os.fsync(self.fd)
            os.unlink(temporary, dir_fd=self.fd)
            os.fsync(self.fd)
        except FileExistsError as exc:
            raise AuthenticationError("Local Duo enrollment state appeared during setup; refusing to replace it.") from exc
        except OSError as exc:
            raise DuoCliError("Cannot atomically save local Duo enrollment state.") from exc
        finally:
            if fd is not None:
                os.close(fd)
            if not committed:
                try:
                    os.unlink(temporary, dir_fd=self.fd)
                    os.fsync(self.fd)
                except FileNotFoundError:
                    pass
                except OSError:
                    # Preserve the original sanitized failure; a subsequent
                    # command will only clean a verified 0600 temporary file.
                    pass

    def remove_enrollment(self) -> bool:
        self._cleanup_orphan_temps()
        removed = False
        # New state is one atomic file. Safely remove any legacy split files too
        # so a failed pre-v2 setup cannot strand a user in an un-log-outable state.
        for name in (ENROLLMENT_FILE, "key.pem", "response.json"):
            info = self._stat(name, required=False)
            if info is None:
                continue
            self._assert_private_file(info)
            try:
                os.unlink(name, dir_fd=self.fd)
            except OSError as exc:
                raise DuoCliError("Cannot remove local Duo enrollment state.") from exc
            removed = True
        if removed:
            try:
                os.fsync(self.fd)
            except OSError as exc:
                raise DuoCliError("Cannot sync local Duo enrollment removal.") from exc
        return removed


class ExclusiveStateLock:
    """Non-blocking exclusive lock and lifetime owner of a StateDirectory FD."""

    def __init__(self, paths: StatePaths):
        self.paths = paths
        self.state: StateDirectory | None = None
        self.lock_fd: int | None = None

    def __enter__(self) -> StateDirectory:
        self.state = self.paths.open_directory()
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            self.lock_fd = os.open(LOCK_FILE, flags, 0o600, dir_fd=self.state.fd)
            os.fchmod(self.lock_fd, 0o600)
            info = os.fstat(self.lock_fd)
            if not stat.S_ISREG(info.st_mode) or not _is_current_owner(info) or stat.S_IMODE(info.st_mode) != 0o600:
                raise DuoCliError("Duo state lock is not a current-user-owned mode-0600 regular file.")
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return self.state
        except BlockingIOError as exc:
            self._close()
            raise BusyError("Another Duo command is using this local device; retry after it exits.") from exc
        except OSError as exc:
            self._close()
            raise DuoCliError("Cannot acquire the exclusive Duo state lock.") from exc
        except BaseException:
            self._close()
            raise

    def _close(self) -> None:
        if self.lock_fd is not None:
            try:
                os.close(self.lock_fd)
            finally:
                self.lock_fd = None
        if self.state is not None:
            self.state.close()
            self.state = None

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.lock_fd is not None:
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
            finally:
                self._close()
        else:
            self._close()
