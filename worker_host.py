"""Explicit host-only runtime admission and one-shot observed-exit reporting.

No execution, Docker mutation, secret export, implicit replay or authority repair.
"""

from contextlib import contextmanager, ExitStack
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
from pathlib import PurePosixPath, PureWindowsPath
import re
import secrets
import socket
import ssl
import stat
import threading
import time
from urllib.parse import urlsplit
import uuid

import updater
import worker_runtime as runtime
import worker_secrets as custody

_BINDING = {
    "origin",
    "job_id",
    "runner_id",
    "contract_id",
    "attempt_id",
    "fence",
    "contract_sha256",
}
_UNBOUND_INTENT = {"runtime_sha256", "finished_at", "exit_code", "observation_sha256"}
_COOKIE = "__Host-vardrmap.session"
_CAPABILITY = b"VardrSec.WorkerStop.v1\0"
_MAC = b"VardrSec.WorkerHostRecord.v1\0"
_DNS = threading.Lock()
_MOUNT_CUSTODY_CHECKPOINTS = frozenset(
    {
        "mount_managed_metadata",
        "mount_bind_resolution",
        "mount_managed_resolution",
        "mount_private_resolution",
        "mount_separation",
    }
)
_MOUNT_CAPTURE_CHECKPOINTS = frozenset(
    "mount_capture_" + checkpoint for checkpoint in runtime.CAPTURE_CHECKPOINTS
)
_LOCAL_CAPTURE_CHECKPOINTS = frozenset(
    "local_capture_" + checkpoint for checkpoint in runtime.CAPTURE_CHECKPOINTS
)
REGISTRATION_CHECKPOINTS = frozenset(
    {
        "inputs",
        "local_capture",
        "local_identity_changed",
        "mount_custody",
        "secret_store",
        "initial_store",
        "request",
        "ack",
        "final_store",
        "unknown_store",
    }
) | _MOUNT_CUSTODY_CHECKPOINTS | _MOUNT_CAPTURE_CHECKPOINTS | _LOCAL_CAPTURE_CHECKPOINTS
REGISTRATION_REQUEST_STAGES = frozenset(
    {"connect", "tls", "send", "status", "headers", "body", "json"}
)


class HostRefused(ValueError):
    """Fixed value-free failure; unknown writes remain held."""

    def __init__(self, message="worker_host_refused", *, registration_failure=None):
        super().__init__(message)
        self.registration_failure = registration_detail(registration_failure)


def registration_detail(value):
    """Copy only the fixed registration diagnostic, never exception text."""
    if not (
        type(value) is dict
        and set(value) == {"checkpoint", "request_stage", "http_status"}
        and type(value["checkpoint"]) is str
        and value["checkpoint"] in REGISTRATION_CHECKPOINTS
        and (
            value["request_stage"] is None
            or (
                type(value["request_stage"]) is str
                and value["request_stage"] in REGISTRATION_REQUEST_STAGES
            )
        )
        and (
            value["http_status"] is None
            or (
                type(value["http_status"]) is int and 100 <= value["http_status"] <= 599
            )
        )
    ):
        return None
    if value["checkpoint"] != "request" and (
        value["request_stage"] is not None or value["http_status"] is not None
    ):
        return None
    if value["http_status"] is not None and value["request_stage"] not in {
        "status",
        "headers",
        "body",
        "json",
    }:
        return None
    return dict(value)


def _exception_attribute(error, name):
    try:
        attributes = object.__getattribute__(error, "__dict__")
        return attributes.get(name) if type(attributes) is dict else None
    except BaseException:
        # Optional diagnostics must never mask the original failure.
        return None


def registration_diagnostic(error):
    if not isinstance(error, HostRefused):
        return None
    try:
        return registration_detail(_exception_attribute(error, "registration_failure"))
    except BaseException:
        # Malicious metadata keys must not replace the original refusal either.
        return None


@contextmanager
def registration_step(checkpoint):
    """Annotate one existing boundary without changing sends or recovery."""
    try:
        yield
    except Exception as error:
        detail = registration_diagnostic(error)
        if detail is None:
            if checkpoint == "local_capture" and isinstance(error, runtime.RuntimeRefused):
                captured = _exception_attribute(error, "checkpoint")
                if type(captured) is str and captured in runtime.CAPTURE_CHECKPOINTS:
                    checkpoint = "local_capture_" + captured
            elif checkpoint == "mount_custody":
                nested = _exception_attribute(error, "_mount_custody_checkpoint")
                if type(nested) is str and nested in (
                    _MOUNT_CUSTODY_CHECKPOINTS | _MOUNT_CAPTURE_CHECKPOINTS
                ):
                    checkpoint = nested
            detail = registration_detail(
                {"checkpoint": checkpoint, "request_stage": None, "http_status": None}
            )
        raise HostRefused(registration_failure=detail) from None


@contextmanager
def _mount_custody_step(checkpoint):
    """Annotate only; outside registration, rethrow the identical exception."""
    try:
        yield
    except Exception as error:
        try:
            nested = _exception_attribute(error, "_mount_custody_checkpoint")
            if type(nested) is not str or nested not in (
                _MOUNT_CUSTODY_CHECKPOINTS | _MOUNT_CAPTURE_CHECKPOINTS
            ):
                selected = checkpoint if type(checkpoint) is str and checkpoint in _MOUNT_CUSTODY_CHECKPOINTS else None
                captured = (
                    _exception_attribute(error, "checkpoint")
                    if isinstance(error, runtime.RuntimeRefused)
                    else None
                )
                if type(captured) is str and captured in runtime.CAPTURE_CHECKPOINTS:
                    selected = "mount_capture_" + captured
                if selected is not None:
                    error._mount_custody_checkpoint = selected
        except BaseException:
            # Even hostile attribute setters must leave the original error intact.
            pass
        raise


def require(value):
    if not value:
        raise HostRefused("worker_host_refused")


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result

    def constant(_):
        raise HostRefused("worker_host_refused")

    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant
        )
        require(type(value) is dict)
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise HostRefused("worker_host_refused") from None


def _uuid(value):
    try:
        require(type(value) is str and str(uuid.UUID(value)) == value)
        return value
    except (ValueError, TypeError, AttributeError):
        raise HostRefused("worker_host_refused") from None


def _hash(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value))
    return value


def _identifier(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value))
    return value


def _url(value, *, external=False):
    require(type(value) is str and 0 < len(value) <= 500)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise HostRefused("worker_host_refused") from None
    require(
        parsed.scheme == "https"
        and parsed.hostname
        and not parsed.username
        and not parsed.password
    )
    require(
        not parsed.query
        and not parsed.fragment
        and parsed.path in ({"", "/backend"} if external else {""})
    )
    require(
        value == "https://" + parsed.netloc + parsed.path and "@" not in parsed.netloc
    )
    require(all(32 < ord(char) < 127 for char in parsed.netloc))
    name = parsed.hostname
    require(not name.endswith(".") and "\\" not in name and "%" not in name)
    canonical_host = "[" + name + "]" if ":" in name else name
    require(
        parsed.netloc == canonical_host + (":" + str(port) if port is not None else "")
    )
    require(port is None or 0 < port <= 65535)
    return parsed


def _addresses(host, port, deadline):
    # A stuck OS resolver never holds credentials or creates unbounded threads.
    require(_DNS.acquire(blocking=False))
    ready, result = threading.Event(), []

    def resolve():
        try:
            result.extend(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except OSError:
            pass
        finally:
            _DNS.release()
            ready.set()

    threading.Thread(target=resolve, daemon=True, name="vardr-host-dns").start()
    require(ready.wait(max(0, deadline - time.monotonic())) and 0 < len(result) <= 16)
    return result


def _publish(temporary, destination):
    if os.name != "nt":
        os.replace(temporary, destination)
        return
    import ctypes
    from ctypes import wintypes as w

    def wide(path):
        value = str(path.absolute())
        if value.startswith("\\\\?\\"):
            return value
        return (
            "\\\\?\\UNC\\" + value[2:]
            if value.startswith("\\\\")
            else "\\\\?\\" + value
        )

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    move = kernel.MoveFileExW
    move.argtypes, move.restype = [w.LPCWSTR, w.LPCWSTR, w.DWORD], w.BOOL
    # Same-directory rename only: REPLACE_EXISTING | WRITE_THROUGH, no copy,
    # reboot scheduling or cross-volume fallback. File bytes were fsynced first.
    require(move(wide(temporary), wide(destination), 0x1 | 0x8))


def _managed_source(source, *, windows_vm):
    """Called only after direct default-local volume metadata validation."""
    if windows_vm:
        return None
    try:
        return Path(source).resolve(strict=True)
    except PermissionError:
        return source


class HostClient:
    """Fixed HTTPS endpoint; explicit CA, no proxies, redirects or retries."""

    def __init__(self, base_url, ca_file):
        try:
            self._configure(base_url, ca_file)
        except (OSError, ValueError, UnicodeError, RuntimeError):
            raise HostRefused("worker_host_refused") from None

    def _configure(self, base_url, ca_file):
        parsed = _url(base_url, external=True)
        self.base_url, self.origin = base_url, "https://" + parsed.netloc
        self.host, self.port, self.prefix = (
            parsed.hostname,
            parsed.port or 443,
            parsed.path,
        )
        self.ca_file = str(Path(ca_file).resolve(strict=True))
        with open(self.ca_file, "rb") as source:
            raw = source.read(65537)
        require(0 < len(raw) <= 65536)
        self.ca_sha256 = hashlib.sha256(raw).hexdigest()
        # Unlike create_default_context(), this does not honor SSLKEYLOGFILE.
        # Trust exactly the loaded bytes whose hash is authenticated in records.
        self._tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._tls.load_verify_locations(cadata=raw.decode("ascii"))
        self._tls.keylog_filename = None
        require(self._tls.check_hostname and self._tls.verify_mode == ssl.CERT_REQUIRED)

    def pin(self):
        return {
            "base_url": self.base_url,
            "ca_file": self.ca_file,
            "ca_sha256": self.ca_sha256,
        }

    def _request(self, method, path, body=None, headers=None):
        require(method in {"GET", "POST"} and path.startswith("/") and "?" not in path)
        raw = None if body is None else canonical(body)
        require(raw is None or len(raw) <= 8192)
        deadline = time.monotonic() + 10
        connection, secure, timer = None, None, None
        request_stage, http_status = "connect", None
        try:
            for family, kind, protocol, _, address in _addresses(
                self.host, self.port, deadline
            ):
                request_stage = "connect"
                plain = socket.socket(family, kind, protocol)
                try:
                    plain.settimeout(max(0.001, deadline - time.monotonic()))
                    plain.connect(address)
                    require(time.monotonic() < deadline)
                    plain.settimeout(deadline - time.monotonic())
                    request_stage = "tls"
                    secure = self._tls.wrap_socket(plain, server_hostname=self.host)
                    break
                except OSError:
                    plain.close()
            require(secure is not None and time.monotonic() < deadline)

            def expire():
                try:
                    secure.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                secure.close()

            timer = threading.Timer(max(0, deadline - time.monotonic()), expire)
            timer.daemon = True
            timer.start()
            connection = http.client.HTTPConnection(self.host, self.port)
            connection.sock = secure
            selected = {
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Connection": "close",
            }
            if raw is not None:
                selected["Content-Type"] = "application/json"
            selected.update(headers or {})
            request_stage = "send"
            connection.request(method, self.prefix + path, body=raw, headers=selected)
            request_stage = "status"
            response = connection.getresponse()
            if type(response.status) is int and 100 <= response.status <= 599:
                http_status = response.status
            require(response.status == 200)
            request_stage = "headers"
            require(response.getheader("Content-Encoding", "identity") == "identity")
            require(
                response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
                == "application/json"
            )
            length = response.getheader("Content-Length")
            require(length is None or (length.isdecimal() and int(length) <= 16384))
            request_stage = "body"
            chunks, size = [], 0
            while True:
                require(time.monotonic() < deadline)
                block = response.read1(min(1024, 16385 - size))
                if not block:
                    break
                chunks.append(block)
                size += len(block)
                require(size <= 16384)
            require(length is None or size == int(length))
            request_stage = "json"
            return _json(b"".join(chunks)), response.getheaders()
        except (OSError, ValueError, http.client.HTTPException, UnicodeError):
            raise HostRefused(
                registration_failure={
                    "checkpoint": "request",
                    "request_stage": request_stage,
                    "http_status": http_status,
                }
            ) from None
        finally:
            if timer is not None:
                timer.cancel()
            if connection is not None:
                connection.close()
            elif secure is not None:
                secure.close()

    @contextmanager
    def owner_session(self, username, password):
        require(type(username) is str and 0 < len(username) <= 64)
        require(type(password) is str and 0 < len(password) <= 128)
        cookie, csrf, owner = None, None, None
        try:
            reply, headers = self._request(
                "POST",
                "/auth/local/login",
                {"username": username, "password": password},
                {"Origin": self.origin},
            )
            require(reply == {"authenticated": True})
            values = [value for key, value in headers if key.lower() == "set-cookie"]
            require(len(values) == 1)
            jar = SimpleCookie()
            jar.load(values[0])
            require(set(jar) == {_COOKIE})
            entry = jar[_COOKIE]
            require(
                entry["secure"]
                and entry["httponly"]
                and entry["path"] == "/"
                and not entry["domain"]
            )
            require(re.fullmatch(r"[A-Za-z0-9_-]{32,256}", entry.value))
            cookie = _COOKIE + "=" + entry.value
            session, _ = self._request(
                "GET", "/auth/local/session", headers={"Cookie": cookie}
            )
            require(
                set(session) == {"authMethod", "csrfToken", "user"}
                and session["authMethod"] == "local"
            )
            csrf = _hash(session["csrfToken"])
            owner = OwnerSession(self, cookie, csrf)
            yield owner
        finally:
            if cookie is not None and csrf is not None:
                try:
                    self._request(
                        "POST",
                        "/auth/local/logout",
                        {},
                        {"Cookie": cookie, "Origin": self.origin, "X-CSRF-Token": csrf},
                    )
                except HostRefused:
                    pass
            if owner is not None:
                owner._cookie, owner._csrf = None, None

    def receipt(self, runtime_id, runtime_sha256, secret, *, admission_sha256=None):
        return self._request(
            "POST",
            f"/managed/runtimes/{_uuid(runtime_id)}/receipt",
            {
                "runtime_sha256": _hash(runtime_sha256),
                **(
                    {"admission_sha256": _hash(admission_sha256)}
                    if admission_sha256 is not None
                    else {}
                ),
            },
            {"Authorization": "VardrStop " + _hash(secret)},
        )[0]

    def observed_exit(self, runtime_id, body, secret):
        return self._request(
            "POST",
            f"/managed/runtimes/{_uuid(runtime_id)}/observed-exit",
            body,
            {"Authorization": "VardrStop " + _hash(secret)},
        )[0]

    def observed_unbound_exit(self, runtime_id, body, secret):
        return self._request(
            "POST",
            f"/managed/runtimes/{_uuid(runtime_id)}/observed-unbound-exit",
            body,
            {"Authorization": "VardrStop " + _hash(secret)},
        )[0]

    def attempt_receipt(
        self,
        runtime_id,
        runtime_sequence,
        runtime_sha256,
        secret,
        *,
        admission_sha256=None,
    ):
        if admission_sha256 is None:
            require(type(runtime_sequence) is int and 1 <= runtime_sequence <= 32)
        else:
            import worker_host_persistent

            worker_host_persistent.decimal(runtime_sequence, minimum=1)
        return self._request(
            "POST",
            f"/managed/runtimes/{_uuid(runtime_id)}/attempts/{runtime_sequence}/receipt",
            {
                "runtime_sha256": _hash(runtime_sha256),
                **(
                    {"admission_sha256": _hash(admission_sha256)}
                    if admission_sha256 is not None
                    else {}
                ),
            },
            {"Authorization": "VardrStop " + _hash(secret)},
        )[0]

    def disable(self, runtime_id, runtime_sha256, admission_sha256, secret):
        return self._request(
            "POST",
            f"/managed/runtimes/{_uuid(runtime_id)}/disable",
            {
                "runtime_sha256": _hash(runtime_sha256),
                "admission_sha256": _hash(admission_sha256),
            },
            {"Authorization": "VardrStop " + _hash(secret)},
        )[0]


class OwnerSession:
    def __init__(self, client, cookie, csrf):
        self.client, self._cookie, self._csrf = client, cookie, csrf

    def _post(self, runtime_id, action, body):
        require(self._cookie is not None and self._csrf is not None)
        return self.client._request(
            "POST",
            f"/managed/runtimes/{_uuid(runtime_id)}/{action}",
            body,
            {
                "Cookie": self._cookie,
                "Origin": self.client.origin,
                "X-CSRF-Token": self._csrf,
            },
        )[0]

    def register(self, runtime_id, body):
        return self._post(runtime_id, "register", body)

    def revoke(self, runtime_id):
        reply = self._post(runtime_id, "revoke", {})
        require(reply == {"runtime_id": runtime_id, "revoked": True})
        return reply


_OPERATION_PROOF = object()


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class _HostOperation:
    """An opaque live lock owner; never serialized or accepted from CLI input."""

    _owner: object
    _thread: int
    _installation: Path
    _private_root: Path
    _proof: object

    def __post_init__(self):
        require(self._proof is _OPERATION_PROOF)


class HostRecords:
    """Public-only MAC records in a dedicated host-private directory.

    Windows raw STOP values use Credential Manager, never chmod/plaintext files.
    The caller supplies an existing protected installation private root.
    """

    def __init__(self, installation, private_root, *, backend=None):
        self.installation = Path(installation).absolute()
        self.private_root = Path(private_root).absolute()
        self.__operation = None
        require(self.installation.is_dir() and self.private_root.is_dir())
        self.directory = self.private_root / "worker-host"
        self.directory.mkdir(mode=0o700, exist_ok=True)
        self._directory()
        if backend is None:
            if os.name == "nt":
                backend = custody.WindowsSecrets()
            else:
                secret_dir = self.private_root / "worker-stop-secrets"
                secret_dir.mkdir(mode=0o700, exist_ok=True)
                backend = custody.PosixSecrets(secret_dir)
        self.backend = backend

    def _directory(self):
        for path in (self.directory, *self.directory.parents):
            info = path.lstat()
            require(
                not stat.S_ISLNK(info.st_mode)
                and not getattr(info, "st_file_attributes", 0) & 0x400
            )
        if os.name != "nt":
            for path in (self.directory, self.private_root):
                info = path.stat()
                require(
                    info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700
                )

    def _require_operation(self, operation):
        require(
            type(operation) is _HostOperation
            and operation is self.__operation
            and operation._owner is self
            and operation._thread == threading.get_ident()
            and operation._installation == self.installation
            and operation._private_root == self.private_root
        )

    @contextmanager
    def operation(self, existing=None):
        """Own one installation lock, or borrow only its exact live capability."""
        if existing is not None:
            self._require_operation(existing)
            try:
                self._directory()
            except (OSError, ValueError) as error:
                raise HostRefused(
                    registration_failure=registration_diagnostic(error)
                ) from None
            yield existing
            return
        require(self.__operation is None)
        stack = ExitStack()
        try:
            try:
                stack.enter_context(updater.installation_lock(self.installation))
                self._directory()
            except (OSError, ValueError) as error:
                raise HostRefused(
                    registration_failure=registration_diagnostic(error)
                ) from None
            operation = _HostOperation(
                self, threading.get_ident(), self.installation,
                self.private_root, _OPERATION_PROOF,
            )
            self.__operation = operation
            try:
                yield operation
            finally:
                self.__operation = None
        finally:
            # Invalidate first; release/handle-close failure cannot leave a token
            # usable. Translate only the owned lock exit, never body failures.
            try:
                stack.close()
            except (OSError, ValueError) as error:
                raise HostRefused(
                    registration_failure=registration_diagnostic(error)
                ) from None

    @contextmanager
    def locked(self, *, operation=None):
        # Ordinary callers retain one independently acquired lock and no token.
        try:
            with self.operation(operation):
                yield
        except (OSError, ValueError) as error:
            raise HostRefused(
                registration_failure=registration_diagnostic(error)
            ) from None

    def _path(self, runtime_id):
        return self.directory / (_uuid(runtime_id) + ".json")

    def _intent_access(self, operation):
        """Validate a live owner before any lifecycle-intent storage access."""
        self._require_operation(operation)
        self._directory()
        return self.directory

    def secret(self, runtime_id):
        try:
            return _hash(self.backend.read(_uuid(runtime_id)))
        except (OSError, ValueError):
            raise HostRefused("worker_host_refused") from None

    def read(self, runtime_id):
        self._directory()
        path = self._path(runtime_id)
        info = path.lstat()
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and not getattr(info, "st_file_attributes", 0) & 0x400
        )

        if os.name != "nt":
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600)
        with open(path, "rb") as source:
            raw = source.read(65537)
        require(len(raw) <= 65536)
        wrapped = _json(raw)
        require(
            set(wrapped) == {"schema", "payload", "mac"}
            and wrapped["schema"]
            in {
                "vardr.worker-host-record/1",
                "vardr.worker-host-record/2",
                "vardr.worker-host-record/3",
            }
        )
        payload = wrapped["payload"]
        require(type(payload) is dict and payload.get("runtime_id") == runtime_id)
        registration = payload.get("registration")
        require(type(registration) is dict)
        persistent = "mode" in registration
        if persistent:
            import worker_host_persistent

            worker_host_persistent.registration(registration)
        sequenced = "max_attempts" in registration
        if sequenced:
            require(
                type(registration["max_attempts"]) is int
                and 1 <= registration["max_attempts"] <= 32
            )
        require(
            wrapped["schema"]
            == (
                "vardr.worker-host-record/3"
                if persistent
                else "vardr.worker-host-record/2"
                if sequenced
                else "vardr.worker-host-record/1"
            )
        )
        prefix = (
            b"vardr.worker-host-record/3\x00"
            if persistent
            else b"vardr.worker-host-record/2\x00"
            if sequenced
            else _MAC
        )
        expected = hmac.new(
            bytes.fromhex(self.secret(runtime_id)),
            prefix + canonical(payload),
            hashlib.sha256,
        ).hexdigest()
        require(hmac.compare_digest(_hash(wrapped["mac"]), expected))
        require(payload["installation"] == str(self.installation.resolve(strict=True)))
        require(payload["storage_root"] == str(self.private_root.resolve(strict=True)))
        if persistent:
            worker_host_persistent.record_state(payload)
        return payload

    def write(self, payload, *, create=False):
        self._directory()
        path = self._path(payload["runtime_id"])
        if create:
            require(not path.exists() and not path.is_symlink())
        else:
            self.read(payload["runtime_id"])
        secret = self.secret(payload["runtime_id"])
        persistent = "mode" in payload["registration"]
        if persistent:
            import worker_host_persistent

            worker_host_persistent.registration(payload["registration"])
            worker_host_persistent.record_state(payload)
        sequenced = payload["registration"].get("max_attempts") is not None
        prefix = (
            b"vardr.worker-host-record/3\x00"
            if persistent
            else b"vardr.worker-host-record/2\x00"
            if sequenced
            else _MAC
        )
        mac = hmac.new(
            bytes.fromhex(secret), prefix + canonical(payload), hashlib.sha256
        ).hexdigest()
        raw = canonical(
            {
                "schema": "vardr.worker-host-record/3"
                if persistent
                else "vardr.worker-host-record/2"
                if sequenced
                else "vardr.worker-host-record/1",
                "payload": payload,
                "mac": mac,
            }
        )
        require(len(raw) <= 65536)
        temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            _publish(temporary, path)
            if os.name != "nt":
                directory = os.open(
                    self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                )
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)

    def outside_mounts(self, observer, identity):
        with _mount_custody_step("mount_managed_metadata"):
            require(isinstance(observer, runtime.LocalDocker))
            import worker_volumes

            # Validate actual binds and default-local volumes through the selected
            # daemon before any host-path custody comparison.
            managed = worker_volumes.managed_sources(observer, identity)
        with _mount_custody_step("mount_bind_resolution"):
            binds = [observer.layout.trust_source, observer.layout.admission_source]
            sources = []
            for source in binds:
                mapped = runtime.host_bind_path(source)
                require(
                    isinstance(
                        mapped, PureWindowsPath if os.name == "nt" else PurePosixPath
                    )
                )
                sources.append(Path(str(mapped)).resolve(strict=True))
        with _mount_custody_step("mount_managed_resolution"):
            for source in managed:
                resolved = _managed_source(source, windows_vm=os.name == "nt")
                if resolved is not None:
                    sources.append(resolved)
        with _mount_custody_step("mount_private_resolution"):
            locations = [self.directory]
            if isinstance(self.backend, custody.PosixSecrets):
                locations.append(self.backend.directory)
            for location in locations:
                location = location.resolve(strict=True)
                with _mount_custody_step("mount_separation"):
                    for source in sources:
                        mount = Path(source)
                        require(
                            not location.is_relative_to(mount)
                            and not mount.is_relative_to(location)
                        )


def _client(record, client):
    require(isinstance(client, HostClient) and record["client"] == client.pin())


def _observer(record, observer):
    require(isinstance(observer, runtime.LocalDocker))
    if "mode" in record["registration"]:
        require(
            record["context"] == observer.context
            and record["layout"] == asdict(observer.layout)
            and getattr(observer, "protocol", None) == "persistent-v3"
            and getattr(observer, "max_attempts", None) is None
        )
        return
    require(
        record["context"] == observer.context
        and record["layout"] == asdict(observer.layout)
        and record["registration"].get("max_attempts")
        == getattr(observer, "max_attempts", None)
    )


def _admission(record, reply):
    if "mode" in record["registration"]:
        import worker_host_persistent

        return worker_host_persistent.admission(record, reply)
    maximum = record["registration"].get("max_attempts")
    require(
        type(reply) is dict
        and set(reply)
        == {
            "schema",
            "runtime_id",
            "runtime_sha256",
            "enrollment_id",
            "runner_id",
            "origin",
            "capability_sha256",
            "identity",
            "expires_at",
        }
        | ({"max_attempts"} if maximum is not None else set())
    )
    expected = record["registration"]
    require(
        reply["schema"]
        == (
            "vardr.worker-admission/2"
            if maximum is not None
            else "vardr.worker-admission/1"
        )
        and reply["runtime_id"] == record["runtime_id"]
    )
    require(reply["runtime_sha256"] == digest(expected["identity"]))
    if maximum is not None:
        require(
            type(maximum) is int
            and 1 <= maximum <= 32
            and reply["max_attempts"] == maximum
        )
    require(
        all(
            reply[k] == expected[k]
            for k in (
                "enrollment_id",
                "runner_id",
                "origin",
                "capability_sha256",
                "identity",
            )
        )
    )
    require(type(reply["expires_at"]) is str and len(reply["expires_at"]) <= 30)
    expiry = datetime.fromisoformat(reply["expires_at"].replace("Z", "+00:00"))
    require(expiry.tzinfo is not None and expiry > datetime.now(timezone.utc))
    return reply


def _binding(record, value):
    require(type(value) is dict and set(value) == _BINDING)
    require(
        value["origin"] == record["registration"]["origin"]
        and value["runner_id"] == record["registration"]["runner_id"]
    )
    _identifier(value["job_id"])
    for key in ("runner_id", "contract_id", "attempt_id"):
        _uuid(value[key])
    _hash(value["contract_sha256"])
    require(type(value["fence"]) is int and 1 <= value["fence"] <= 2**53 - 1)
    return value


def _terminal(binding, value):
    require(type(value) is dict)
    base = _BINDING | {"schema", "outcome", "receipt_sha256", "capacity_reserved"}
    stop = value.get("schema") == "vardr.managed-stop-receipt/1"
    require(set(value) == base | ({"cause"} if stop else set()))
    require(stop or value["schema"] == "vardr.managed-completion/1")
    require(
        canonical({key: value[key] for key in _BINDING}) == canonical(binding)
        and value["capacity_reserved"] is False
    )
    require(value["outcome"] in {"completed", "failed", "cancelled"})
    _hash(value["receipt_sha256"])
    if stop:
        cancel = {"local_emergency_stop", "remote_stop_requested"}
        failure = {
            "control_cap_unavailable",
            "control_lease_expired",
            "authorization_deadline",
            "tool_timeout",
            "descendants_after_tool_exit",
            "observed_exit",
        }
        require(value["cause"] in cancel | failure)
        require(
            value["outcome"] == ("cancelled" if value["cause"] in cancel else "failed")
        )
        require(
            value["receipt_sha256"]
            == digest(
                {
                    "schema": "vardr.managed-stop/1",
                    **binding,
                    "outcome": value["outcome"],
                    "cause": value["cause"],
                    "termination_confirmed": True,
                }
            )
        )
    return value


def _intent_kind(record):
    intent = record["stop_intent"]
    if intent is None:
        return None
    require(type(intent) is dict)
    if set(intent) == _UNBOUND_INTENT:
        return "unbound"
    require(set(intent) == _UNBOUND_INTENT | _BINDING)
    return "bound"


def _unbound_terminal(record, value):
    require(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "runtime_id",
            "runtime_sha256",
            "origin",
            "runner_id",
            "enrollment_id",
            "report_sha256",
            "bound",
            "retired",
            "receipt_sha256",
        }
    )
    registration = record["registration"]
    require(
        value["schema"] == "vardr.worker-unbound-retirement/1"
        and value["runtime_id"] == record["runtime_id"]
        and value["runtime_sha256"] == digest(registration["identity"])
        and all(
            value[key] == registration[key]
            for key in ("origin", "runner_id", "enrollment_id")
        )
        and value["bound"] is False
        and value["retired"] is True
    )
    _hash(value["report_sha256"])
    require(
        _hash(value["receipt_sha256"])
        == digest({key: item for key, item in value.items() if key != "receipt_sha256"})
    )
    kind = _intent_kind(record)
    require(kind != "bound")
    if kind == "unbound":
        require(
            value["report_sha256"]
            == digest(
                {
                    "schema": "vardr.worker-unbound-exit-report/1",
                    "runtime_id": record["runtime_id"],
                    **record["stop_intent"],
                }
            )
        )
    return value


def _lookup(record, reply):
    require(
        type(reply) is dict
        and set(reply)
        == {"schema", "runtime_id", "runtime_sha256", "binding", "receipt"}
    )
    require(
        reply["schema"] == "vardr.worker-receipt-observation/1"
        and reply["runtime_id"] == record["runtime_id"]
        and reply["runtime_sha256"] == digest(record["registration"]["identity"])
    )
    binding = reply["binding"]
    kind = _intent_kind(record)
    require(kind != "bound" or binding is not None)
    if binding is not None:
        _binding(record, binding)
        if kind == "bound":
            require(all(record["stop_intent"][key] == binding[key] for key in _BINDING))
    if reply["receipt"] is not None:
        if binding is None:
            _unbound_terminal(record, reply["receipt"])
        else:
            _terminal(binding, reply["receipt"])
    require(record["receipt"] is None or reply["receipt"] == record["receipt"])
    return reply


def register_runtime(
    client,
    records,
    session,
    *,
    issuer_origin,
    enrollment_id,
    runner_id,
    identity,
    observer,
    expires_in_seconds=None,
    runtime_id=None,
    max_attempts=None,
    protocol=None,
    limits=None,
    operation=None,
):
    """Persist exact grant/custody before POST; unknown replies never recreate it."""
    if protocol == "persistent-v3":
        import worker_host_persistent

        require(expires_in_seconds is None and max_attempts is None)
        return worker_host_persistent.register_runtime(
            client,
            records,
            session,
            issuer_origin=issuer_origin,
            enrollment_id=enrollment_id,
            runner_id=runner_id,
            identity=identity,
            observer=observer,
            runtime_id=runtime_id,
            selected_limits=limits,
            **({} if operation is None else {"operation": operation}),
        )
    require(
        protocol is None
        or (type(protocol) is str and protocol in {"legacy-v1", "finite-v2"})
    )
    require(
        protocol is None
        or (protocol == "finite-v2" and max_attempts is not None)
        or (protocol == "legacy-v1" and max_attempts is None)
    )
    if protocol is not None:
        require(getattr(observer, "protocol", None) == protocol)
    require(limits is None)
    require(
        isinstance(client, HostClient)
        and isinstance(session, OwnerSession)
        and session.client is client
    )
    require(
        isinstance(identity, runtime.RuntimeIdentity)
        and isinstance(observer, runtime.LocalDocker)
    )
    _url(issuer_origin, external=True)
    _identifier(enrollment_id)
    _uuid(runner_id)
    require(type(expires_in_seconds) is int and 60 <= expires_in_seconds <= 604800)
    require(
        max_attempts is None or (type(max_attempts) is int and 1 <= max_attempts <= 32)
    )
    require(getattr(observer, "max_attempts", None) == max_attempts)
    runtime_id = str(uuid.uuid4()) if runtime_id is None else _uuid(runtime_id)
    with records.locked(**({} if operation is None else {"operation": operation})):
        require(
            not records._path(runtime_id).exists()
            and records.backend.read(runtime_id) is None
        )
        require(
            observer.capture_running(
                container_id=identity.container_id,
                image_id=identity.image_id,
                project=identity.project,
            )
            == identity
        )
        records.outside_mounts(observer, identity)
        secret = secrets.token_hex(32)
        records.backend.create(runtime_id, secret)
        registration = {
            "enrollment_id": enrollment_id,
            "runner_id": runner_id,
            "origin": issuer_origin,
            "identity": asdict(identity),
            "capability_sha256": hashlib.sha256(
                _CAPABILITY + secret.encode("ascii")
            ).hexdigest(),
            "expires_in_seconds": expires_in_seconds,
        }
        if max_attempts is not None:
            registration["max_attempts"] = max_attempts
        record = {
            "runtime_id": runtime_id,
            "installation": str(records.installation.resolve(strict=True)),
            "storage_root": str(records.private_root.resolve(strict=True)),
            "client": client.pin(),
            "context": observer.context,
            "layout": asdict(observer.layout),
            "registration": registration,
            "registration_state": "prepared",
            "admission": None,
            "stop_intent": None,
            "stop_state": "none",
            "receipt": None,
            "revocation_state": "none",
        }
        if max_attempts is not None:
            record["report_cursors"] = []
        records.write(record, create=True)
        try:
            record["admission"] = _admission(
                record, session.register(runtime_id, registration)
            )
            record["registration_state"] = "acknowledged"
            records.write(record)
            return record["admission"]
        except Exception:
            record["registration_state"] = "unknown"
            records.write(record)
            raise HostRefused("worker_host_refused") from None


def replay_registration(client, records, session, runtime_id):
    """Explicit owner recovery only: identical UUID, secret hash, identity and TTL."""
    require(isinstance(session, OwnerSession) and session.client is client)
    with records.locked():
        record = records.read(runtime_id)
        _client(record, client)
        require(record["registration_state"] in {"prepared", "unknown"})
        admission = _admission(
            record, session.register(runtime_id, record["registration"])
        )
        record.update(admission=admission, registration_state="acknowledged")
        records.write(record)
        return admission


def revoke_runtime(client, records, session, runtime_id):
    """Owner-session revocation preserves custody for immutable receipt lookup."""
    require(isinstance(session, OwnerSession) and session.client is client)
    with records.locked():
        record = records.read(runtime_id)
        _client(record, client)
        record["revocation_state"] = "prepared"
        records.write(record)
        try:
            reply = session.revoke(runtime_id)
            record["revocation_state"] = "acknowledged"
            records.write(record)
            return reply
        except Exception:
            record["revocation_state"] = "unknown"
            records.write(record)
            raise HostRefused("worker_host_refused") from None


def reconcile_exit(client, records, runtime_id):
    """Read-only POST lookup; never resend an unknown observed-exit mutation."""
    with records.locked():
        persistent = "mode" in records.read(runtime_id)["registration"]
        sequenced = (
            records.read(runtime_id)["registration"].get("max_attempts") is not None
        )
    if persistent:
        import worker_host_persistent

        return worker_host_persistent.reconcile(client, records, runtime_id)
    if sequenced:
        import worker_host_sequence

        return worker_host_sequence.reconcile(client, records, runtime_id)
    with records.locked():
        record = records.read(runtime_id)
        _client(record, client)
        reply = _lookup(
            record,
            client.receipt(
                runtime_id,
                digest(record["registration"]["identity"]),
                records.secret(runtime_id),
            ),
        )
        if reply["receipt"] is not None:
            record.update(receipt=reply["receipt"], stop_state="observed")
            records.write(record)
        return reply


def report_observed_exit(client, records, runtime_id, proof, observer):
    """Fresh server binding, final direct reinspection, durable intent, one POST."""
    with records.locked():
        persistent = "mode" in records.read(runtime_id)["registration"]
        sequenced = (
            records.read(runtime_id)["registration"].get("max_attempts") is not None
        )
    if persistent:
        import worker_host_persistent

        return worker_host_persistent.report(
            client, records, runtime_id, proof, observer
        )
    if sequenced:
        import worker_host_sequence

        return worker_host_sequence.report(client, records, runtime_id, proof, observer)
    require(isinstance(proof, runtime.ObservedExit))
    with records.locked():
        record = records.read(runtime_id)
        _client(record, client)
        _observer(record, observer)
        require(record["registration"]["identity"] == asdict(proof.identity))
        records.outside_mounts(observer, proof.identity)
        secret = records.secret(runtime_id)
        sha = digest(record["registration"]["identity"])
        reply = _lookup(record, client.receipt(runtime_id, sha, secret))
        if reply["receipt"] is not None:
            record.update(receipt=reply["receipt"], stop_state="observed")
            records.write(record)
            return reply
        require(record["stop_state"] == "none" and record["stop_intent"] is None)
        binding = reply["binding"]
        observation = {
            "identity": asdict(proof.identity),
            "finished_at": proof.finished_at,
            "exit_code": proof.exit_code,
        }
        intent = {
            "runtime_sha256": sha,
            **(binding or {}),
            "finished_at": proof.finished_at,
            "exit_code": proof.exit_code,
            "observation_sha256": digest(observation),
        }
        # No network operation may intervene between this final direct proof and
        # the durable one-shot intent. There is no caller confirmation Boolean.
        observer.confirm_exit(proof)
        record.update(stop_intent=intent, stop_state="prepared")
        records.write(record)
        try:
            ack = (
                client.observed_unbound_exit
                if binding is None
                else client.observed_exit
            )(runtime_id, intent, secret)
            require(
                type(ack) is dict
                and set(ack) == {"schema", "runtime_id", "runtime_sha256", "receipt"}
            )
            require(
                ack["schema"] == "vardr.worker-host-stop/1"
                and ack["runtime_id"] == runtime_id
                and ack["runtime_sha256"] == sha
            )
            if binding is None:
                terminal = _unbound_terminal(record, ack["receipt"])
            else:
                terminal = _terminal(binding, ack["receipt"])
                require(
                    terminal["outcome"] == "failed"
                    and (
                        terminal["schema"] == "vardr.managed-completion/1"
                        or terminal.get("cause") == "observed_exit"
                    )
                )
            record.update(receipt=terminal, stop_state="observed")
            records.write(record)
            return ack
        except Exception:
            record["stop_state"] = "unknown"
            records.write(record)
            raise HostRefused("worker_host_refused") from None


def continue_observed_exit(client, records, runtime_id, proof, observer):
    """Explicit continuation; no caller tuple and no retry of the previous body."""
    with records.locked():
        persistent = "mode" in records.read(runtime_id)["registration"]
    if persistent:
        import worker_host_persistent

        return worker_host_persistent.report(
            client, records, runtime_id, proof, observer, continuation=True
        )
    import worker_host_sequence

    return worker_host_sequence.report(
        client, records, runtime_id, proof, observer, continuation=True
    )
