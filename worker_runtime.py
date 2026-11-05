"""Direct local-daemon observations for the explicit managed worker only.

These observations trust the selected host and Docker daemon. They are not remote
attestation and do not authorize execution or release any server reservation.
"""

from dataclasses import dataclass
from datetime import datetime
import io
import json
from pathlib import PurePosixPath, PureWindowsPath
import re
import subprocess
import tarfile
import threading
import time


class RuntimeRefused(ValueError):
    """A fixed, value-free refusal; unknown state must remain held."""


def require(value):
    if not value:
        raise RuntimeRefused("worker_runtime_refused")


_ID = re.compile(r"[0-9a-f]{64}")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}")
_PROOF = object()
# Deliberately exclude Config.Env and other credential-bearing configuration.
_INSPECT = (
    '{"id":{{json .Id}},"image":{{json .Image}},"state":{{json .State}},'
    '"user":{{json .Config.User}},"labels":{{json .Config.Labels}},'
    '"entrypoint":{{json .Config.Entrypoint}},"command":{{json .Config.Cmd}},'
    '"healthcheck":{{json .Config.Healthcheck}},'
    '"mounts":{{json .Mounts}},"host":{'
    '"pid":{{json .HostConfig.PidMode}},'
    '"privileged":{{json .HostConfig.Privileged}},'
    '"init":{{json .HostConfig.Init}},'
    '"auto_remove":{{json .HostConfig.AutoRemove}},'
    '"readonly_root":{{json .HostConfig.ReadonlyRootfs}},'
    '"ipc":{{json .HostConfig.IpcMode}},"tmpfs":{{json .HostConfig.Tmpfs}},'
    '"restart":{{json .HostConfig.RestartPolicy.Name}},'
    '"cap_add":{{json .HostConfig.CapAdd}},'
    '"cap_drop":{{json .HostConfig.CapDrop}},'
    '"security":{{json .HostConfig.SecurityOpt}}}}'
)


def _timestamp(value):
    require(type(value) is str and len(value) <= 30)
    match = re.fullmatch(
        r"(20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?Z",
        value,
    )
    require(match is not None)
    try:
        return datetime.fromisoformat(match[1]), int((match[2] or "").ljust(9, "0"))
    except ValueError:
        raise RuntimeRefused("worker_runtime_refused") from None


@dataclass(frozen=True)
class RuntimeIdentity:
    daemon_id: str
    container_id: str
    image_id: str
    project: str
    started_at: str
    owner_nonce: str

    def __post_init__(self):
        require(type(self.daemon_id) is str and 1 <= len(self.daemon_id) <= 128)
        require(type(self.container_id) is str and _ID.fullmatch(self.container_id))
        require(type(self.image_id) is str and _IMAGE.fullmatch(self.image_id))
        require(
            type(self.project) is str
            and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", self.project)
        )
        _timestamp(self.started_at)
        require(
            type(self.owner_nonce) is str
            and re.fullmatch(r"[0-9a-f]{64}", self.owner_nonce)
        )


@dataclass(frozen=True)
class WorkerLayout:
    trust_source: str
    admission_source: str
    state_volume: str

    def __post_init__(self):
        for value in (self.trust_source, self.admission_source):
            require(
                type(value) is str
                and 1 <= len(value) <= 4096
                and not any(c in value for c in "\0\r\n")
            )
            path = (
                PureWindowsPath(value)
                if PureWindowsPath(value).is_absolute()
                else PurePosixPath(value)
            )
            require(
                path.is_absolute() and len(path.parts) > 1 and ".." not in path.parts
            )
        require(self.trust_source != self.admission_source)
        require(
            type(self.state_volume) is str
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", self.state_volume)
        )


@dataclass(frozen=True, init=False)
class ObservedExit:
    """Created only by the direct adapter, never loaded from caller JSON."""

    identity: RuntimeIdentity
    finished_at: str
    exit_code: int

    def __init__(self, identity, finished_at, exit_code, *, _proof=None):
        require(_proof is _PROOF)
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "finished_at", finished_at)
        object.__setattr__(self, "exit_code", exit_code)


class LocalDocker:
    """Bounded CLI access to one explicitly selected local Docker context."""

    def __init__(self, context, layout):
        require(
            type(context) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", context)
        )
        self.context = context
        require(isinstance(layout, WorkerLayout))
        self.layout = layout
        self._observation_lock = threading.Lock()
        self._deadline = None

    def _command(self, *args, timeout=15, binary=False):
        try:
            if self._deadline is not None:
                timeout = min(timeout, self._deadline - time.monotonic())
                require(timeout > 0)
            options = (
                {}
                if binary
                else {"text": True, "encoding": "utf-8", "errors": "strict"}
            )
            reply = subprocess.run(
                ["docker", "--context", self.context, *args],
                check=False,
                capture_output=True,
                timeout=timeout,
                **options,
            )
            require(
                reply.returncode == 0
                and len(reply.stdout if binary else reply.stdout.encode("utf-8"))
                <= 1024 * 1024
            )
            return reply.stdout if binary else reply.stdout.strip()
        except (OSError, UnicodeError, subprocess.SubprocessError):
            raise RuntimeRefused("worker_runtime_refused") from None

    def daemon(self):
        try:
            endpoint = json.loads(
                self._command(
                    "context",
                    "inspect",
                    self.context,
                    "--format",
                    "{{json .Endpoints.docker.Host}}",
                )
            )
            # A remote TCP/SSH daemon is outside this host-observation producer.
            require(
                type(endpoint) is str
                and endpoint.startswith(("unix:///", "npipe:////"))
            )
            daemon = json.loads(self._command("info", "--format", "{{json .ID}}"))
            require(type(daemon) is str and 1 <= len(daemon) <= 128)
            return daemon
        except (ValueError, TypeError):
            raise RuntimeRefused("worker_runtime_refused") from None

    def inspect(self, container_id):
        require(type(container_id) is str and _ID.fullmatch(container_id))
        try:
            value = json.loads(
                self._command(
                    "container", "inspect", "--format", _INSPECT, container_id
                )
            )
            require(type(value) is dict and value.get("id") == container_id)
            return value
        except (ValueError, TypeError):
            raise RuntimeRefused("worker_runtime_refused") from None

    def _bound(self, identity):
        require(
            isinstance(identity, RuntimeIdentity)
            and self.daemon() == identity.daemon_id
        )
        value = self.inspect(identity.container_id)
        try:
            host, state, labels = value["host"], value["state"], value["labels"]
            self._mounts(value["mounts"])
            self._tmpfs(host["tmpfs"])
            require(
                value["image"] == identity.image_id
                and value["user"] in {"0", "0:0", "root", "root:root"}
                and value["entrypoint"] == ["/usr/local/bin/vardr-worker-owner"]
                and value["command"] in (None, [])
                and (
                    value["healthcheck"] is None
                    or value["healthcheck"] == {"Test": ["NONE"]}
                )
                and labels["com.docker.compose.project"] == identity.project
                and labels["com.docker.compose.service"] == "managed-worker"
                and labels["io.vardrsec.managed-worker"] == "1"
                and labels.get("com.docker.compose.oneoff") == "False"
                and host["pid"] in {"", "private"}
                and host["privileged"] is False
                and (host["init"] is None or host["init"] is False)
                and host["auto_remove"] is False
                and host["readonly_root"] is True
                and host["ipc"] == "private"
                and host["restart"] in {"", "no"}
                and {v.upper().removeprefix("CAP_") for v in host["cap_add"]}
                == {"SETUID", "SETGID", "SETPCAP"}
                and {v.upper().removeprefix("CAP_") for v in host["cap_drop"]}
                == {"ALL"}
                and any(
                    v in {"no-new-privileges", "no-new-privileges:true"}
                    for v in host["security"]
                )
                and state["StartedAt"] == identity.started_at
                and type(state["Restarting"]) is bool
                and type(state["Running"]) is bool
                and type(state["Paused"]) is bool
                and state["Restarting"] is False
                and state["Paused"] is False
            )
        except (KeyError, TypeError, AttributeError):
            raise RuntimeRefused("worker_runtime_refused") from None
        return value

    def _mounts(self, mounts):
        require(type(mounts) is list)
        expected = {
            "/home/runner/.vardrmap": ("volume", self.layout.state_volume, True),
            "/trust": ("bind", self.layout.trust_source, False),
            "/run/vardr-worker-admission": (
                "bind",
                self.layout.admission_source,
                False,
            ),
        }
        seen = set()
        for mount in mounts:
            require(type(mount) is dict)
            destination = mount.get("Destination")
            require(type(destination) is str and destination not in seen)
            seen.add(destination)
            if destination in {"/tmp", "/run/vardr-worker-ready"}:
                require(mount.get("Type") == "tmpfs" and mount.get("RW") is True)
                continue
            require(destination in expected)
            kind, source, writable = expected[destination]
            require(
                mount.get("Type") == kind
                and mount.get("RW") is writable
                and mount.get("Name" if kind == "volume" else "Source") == source
            )
        require(set(expected) <= seen)

    def _tmpfs(self, definitions):
        require(
            type(definitions) is dict
            and set(definitions) == {"/tmp", "/run/vardr-worker-ready"}
        )
        for path, uid, size in [
            ("/tmp", "10001", "67108864"),
            ("/run/vardr-worker-ready", "10000", "65536"),
        ]:
            options = definitions[path]
            require(type(options) is str and len(options) <= 256)
            parts = options.split(",")
            require(len(parts) == len(set(parts)))
            require(
                set(parts)
                == {
                    "rw",
                    "noexec",
                    "nosuid",
                    "nodev",
                    "size=" + size,
                    "uid=" + uid,
                    "gid=" + uid,
                    "mode=0700",
                }
            )

    def _owner_nonce(self, container_id):
        archive = self._command(
            "container",
            "cp",
            container_id + ":/run/vardr-worker-ready/owner.json",
            "-",
            binary=True,
        )
        require(len(archive) <= 65536)
        try:
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source:
                members = source.getmembers()
                require(len(members) == 1)
                entry = members[0]
                require(
                    entry.isfile()
                    and entry.name in {"owner.json", "./owner.json"}
                    and 0 < entry.size <= 4096
                    and entry.uid == 10000
                    and entry.gid == 10000
                    and entry.mode == 0o400
                )
                stream = source.extractfile(entry)
                require(stream is not None)
                raw = stream.read(4097)

            def pairs(items):
                value = {}
                for key, item in items:
                    require(key not in value)
                    value[key] = item
                return value

            ready = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
            require(
                type(ready) is dict
                and set(ready)
                == {
                    "schema",
                    "owner_nonce",
                    "owner_pid",
                    "owner_uid",
                    "runner_uid",
                    "capabilities",
                    "no_new_privs",
                }
            )
            require(
                ready["schema"] == "vardr.worker-owner-ready/1"
                and type(ready["owner_pid"]) is int
                and ready["owner_pid"] == 1
                and type(ready["owner_uid"]) is int
                and ready["owner_uid"] == 10000
                and type(ready["runner_uid"]) is int
                and ready["runner_uid"] == 10001
                and ready["no_new_privs"] is True
                and ready["capabilities"]
                == {
                    name: "0" * 16
                    for name in (
                        "effective",
                        "permitted",
                        "inheritable",
                        "ambient",
                        "bounding",
                    )
                }
                and type(ready["owner_nonce"]) is str
                and re.fullmatch(r"[0-9a-f]{64}", ready["owner_nonce"])
            )
            return ready["owner_nonce"]
        except (tarfile.TarError, ValueError, UnicodeError, KeyError, TypeError):
            raise RuntimeRefused("worker_runtime_refused") from None

    def capture_running(self, *, container_id, image_id, project):
        """Derive a fresh nonce from the actual owner's file, never caller JSON."""
        require(self._observation_lock.acquire(blocking=False))
        try:
            self._deadline = time.monotonic() + 30
            daemon = self.daemon()
            first = self.inspect(container_id)
            identity = RuntimeIdentity(
                daemon,
                container_id,
                image_id,
                project,
                first["state"]["StartedAt"],
                "0" * 64,
            )
            before = self._bound(identity)
            require(
                before["state"]["Status"] == "running"
                and before["state"]["Running"] is True
            )
            nonce = self._owner_nonce(container_id)
            require(self._bound(identity) == before)
            return RuntimeIdentity(
                daemon, container_id, image_id, project, identity.started_at, nonce
            )
        except (KeyError, TypeError):
            raise RuntimeRefused("worker_runtime_refused") from None
        finally:
            self._deadline = None
            self._observation_lock.release()

    def observe_exit(self, identity):
        """Wait and inspect the exact retained incarnation; never stop/restart it."""
        require(self._observation_lock.acquire(blocking=False))
        try:
            self._deadline = time.monotonic() + 30
            return self._observe_exit(identity)
        finally:
            self._deadline = None
            self._observation_lock.release()

    def _observe_exit(self, identity):
        before = self._bound(identity)
        try:
            code_text = self._command(
                "container", "wait", identity.container_id, timeout=15
            )
            require(re.fullmatch(r"[0-9]{1,3}", code_text) and int(code_text) <= 255)
            after = self._bound(identity)
            state = after["state"]
            require(
                state["Status"] == "exited"
                and state["Running"] is False
                and state.get("Dead", False) is False
                and type(state["ExitCode"]) is int
                and state["ExitCode"] == int(code_text)
                and _timestamp(state["FinishedAt"]) > _timestamp(identity.started_at)
                and after["mounts"] == before["mounts"]
                and after["labels"] == before["labels"]
                and after["host"] == before["host"]
            )
            # Recheck just before returning the only locally constructible proof.
            require(self._bound(identity) == after)
            return ObservedExit(
                identity, state["FinishedAt"], state["ExitCode"], _proof=_PROOF
            )
        except (KeyError, TypeError, AttributeError):
            raise RuntimeRefused("worker_runtime_refused") from None
