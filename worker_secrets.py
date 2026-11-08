"""Host-only STOP capability custody; never a worker credential provider.

Windows uses the current user's existing Credential Manager. Linux uses an
exclusive owner-only file in a private directory outside container mounts.
Neither backend falls back to plaintext on Windows or exposes secrets in argv.
"""

import ctypes
from contextlib import contextmanager
import os
from pathlib import Path
import re
import stat
import sys
import uuid


class SecretRefused(ValueError):
    pass


def _require(value):
    if not value:
        raise SecretRefused("worker_secret_refused")


def _runtime_id(value):
    try:
        _require(type(value) is str and str(uuid.UUID(value)) == value)
        return value
    except (ValueError, TypeError, AttributeError):
        raise SecretRefused("worker_secret_refused") from None


def _secret(value):
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value))
    return value


def _intent_operation(backend, records, operation):
    # Imported only at an explicit call, after worker_host finished importing us.
    import worker_host

    _require(type(records) is worker_host.HostRecords and records.backend is backend)
    records._intent_access(operation)


class WindowsSecrets:
    """Generic credential, local-machine persistence for this user only.

    See Microsoft's CREDENTIALW, CredReadW, CredWriteW and CredFree contracts.
    No enterprise roaming, username/password login or container integration.
    """

    def __init__(self):
        _require(sys.platform == "win32")
        from ctypes import wintypes as w

        class Credential(ctypes.Structure):
            _fields_ = [
                ("Flags", w.DWORD),
                ("Type", w.DWORD),
                ("TargetName", w.LPWSTR),
                ("Comment", w.LPWSTR),
                ("LastWritten", w.FILETIME),
                ("CredentialBlobSize", w.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                ("Persist", w.DWORD),
                ("AttributeCount", w.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", w.LPWSTR),
                ("UserName", w.LPWSTR),
            ]

        self.Credential = Credential
        self.api = ctypes.WinDLL("advapi32", use_last_error=True)
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateMutexW.argtypes = [ctypes.c_void_p, w.BOOL, w.LPCWSTR]
        self.kernel.CreateMutexW.restype = w.HANDLE
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        self.kernel.CloseHandle.restype = w.BOOL
        self.kernel.ReleaseMutex.argtypes = [w.HANDLE]
        self.kernel.ReleaseMutex.restype = w.BOOL
        for name, args, result in [
            (
                "CredReadW",
                [
                    w.LPCWSTR,
                    w.DWORD,
                    w.DWORD,
                    ctypes.POINTER(ctypes.POINTER(Credential)),
                ],
                w.BOOL,
            ),
            ("CredWriteW", [ctypes.POINTER(Credential), w.DWORD], w.BOOL),
            ("CredDeleteW", [w.LPCWSTR, w.DWORD, w.DWORD], w.BOOL),
            ("CredFree", [ctypes.c_void_p], None),
        ]:
            function = getattr(self.api, name)
            function.argtypes, function.restype = args, result

    def _target(self, runtime_id):
        return "VardrSec.NewMoon.WorkerStop/v1/" + _runtime_id(runtime_id)

    def _intent_target(self, operation_id):
        return "VardrSec.NewMoon.LifecycleIntent/v1/" + _runtime_id(operation_id)

    @contextmanager
    def _guard(self, runtime_id):
        ctypes.set_last_error(0)
        handle = self.kernel.CreateMutexW(
            None, True, "Local\\VardrSec.WorkerStop.v1." + _runtime_id(runtime_id)
        )
        _require(handle)
        owned = ctypes.get_last_error() != 183
        try:
            _require(owned)
            yield
        finally:
            if owned:
                self.kernel.ReleaseMutex(handle)
            self.kernel.CloseHandle(handle)

    def read(self, runtime_id):
        return self._read_target(self._target(runtime_id))

    def _read_target(self, target):
        pointer = ctypes.POINTER(self.Credential)()
        if not self.api.CredReadW(target, 1, 0, ctypes.byref(pointer)):
            if ctypes.get_last_error() == 1168:
                return None
            raise SecretRefused("worker_secret_refused")
        try:
            value = pointer.contents
            _require(
                value.Type == 1 and value.TargetName == target and value.Persist == 2
            )
            _require(value.CredentialBlobSize == 64 and value.CredentialBlob)
            return _secret(ctypes.string_at(value.CredentialBlob, 64).decode("ascii"))
        except UnicodeError:
            raise SecretRefused("worker_secret_refused") from None
        finally:
            self.api.CredFree(pointer)

    def create(self, runtime_id, secret):
        # CredWriteW has upsert semantics. Serialize this lane and never invoke it
        # for an existing credential, including a previous interrupted operation.
        secret = _secret(secret)
        target = self._target(runtime_id)
        with self._guard(runtime_id):
            _require(self.read(runtime_id) is None)
            self._write_target(target, secret, "VardrSec worker stop only")
            _require(self.read(runtime_id) == secret)

    def _write_target(self, target, secret, description):
        data = (ctypes.c_ubyte * 64).from_buffer_copy(secret.encode("ascii"))
        value = self.Credential()
        value.Type, value.TargetName = 1, target
        value.CredentialBlobSize, value.CredentialBlob = 64, data
        value.Persist, value.UserName = 2, description
        _require(self.api.CredWriteW(ctypes.byref(value), 0))

    def read_intent(self, operation_id, *, records, operation):
        _intent_operation(self, records, operation)
        return self._read_target(self._intent_target(operation_id))

    def create_intent(self, operation_id, secret, *, records, operation):
        _intent_operation(self, records, operation)
        secret = _secret(secret)
        operation_id = _runtime_id(operation_id)
        # Separate fixed purpose; the future runtime's STOP slot stays absent.
        ctypes.set_last_error(0)
        handle = self.kernel.CreateMutexW(
            None, True, "Local\\VardrSec.LifecycleIntent.v1." + operation_id
        )
        _require(handle)
        owned = ctypes.get_last_error() != 183
        try:
            _require(owned)
            _require(self.read_intent(operation_id, records=records, operation=operation) is None)
            self._write_target(self._intent_target(operation_id), secret, "VardrSec lifecycle MAC only")
            _require(self.read_intent(operation_id, records=records, operation=operation) == secret)
        finally:
            if owned:
                self.kernel.ReleaseMutex(handle)
            self.kernel.CloseHandle(handle)

    def delete(self, runtime_id):
        # Explicit retirement only; expiry/failed reconciliation never calls this.
        with self._guard(runtime_id):
            if not self.api.CredDeleteW(self._target(runtime_id), 1, 0):
                _require(ctypes.get_last_error() == 1168)


class PosixSecrets:
    def __init__(self, directory):
        _require(sys.platform.startswith("linux"))
        self.directory = Path(directory).absolute()

    def _directory(self):
        # Pin every directory component against symlink/replacement during access.
        descriptor = os.open(self.directory.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in self.directory.parts[1:]:
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = next_descriptor
            info = os.fstat(descriptor)
            _require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def read(self, runtime_id):
        return self._read_name(_runtime_id(runtime_id) + ".stop")

    def _read_name(self, name):
        try:
            directory = self._directory()
            try:
                try:
                    descriptor = os.open(
                        name,
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                        dir_fd=directory,
                    )
                except FileNotFoundError:
                    return None
                with os.fdopen(descriptor, "rb") as source:
                    info = os.fstat(source.fileno())
                    _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
                    _require(
                        info.st_uid == os.getuid()
                        and stat.S_IMODE(info.st_mode) == 0o600
                    )
                    return _secret(source.read(65).decode("ascii"))
            finally:
                os.close(directory)
        except (OSError, UnicodeError):
            raise SecretRefused("worker_secret_refused") from None

    def create(self, runtime_id, secret):
        return self._create_name(_runtime_id(runtime_id) + ".stop", _secret(secret))

    def _create_name(self, name, secret):
        try:
            directory = self._directory()
            try:
                descriptor = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory,
                )
                with os.fdopen(descriptor, "wb") as output:
                    output.write(secret.encode("ascii"))
                    output.flush()
                    os.fsync(output.fileno())
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            raise SecretRefused("worker_secret_refused") from None

    def read_intent(self, operation_id, *, records, operation):
        _intent_operation(self, records, operation)
        return self._read_name(_runtime_id(operation_id) + ".intent-key")

    def create_intent(self, operation_id, secret, *, records, operation):
        _intent_operation(self, records, operation)
        return self._create_name(_runtime_id(operation_id) + ".intent-key", _secret(secret))

    def delete(self, runtime_id):
        name = _runtime_id(runtime_id) + ".stop"
        try:
            directory = self._directory()
            try:
                try:
                    os.unlink(name, dir_fd=directory)
                    os.fsync(directory)
                except FileNotFoundError:
                    pass
            finally:
                os.close(directory)
        except OSError:
            raise SecretRefused("worker_secret_refused") from None
