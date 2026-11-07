"""Direct local-daemon observations for the explicit managed worker only.

These observations trust the selected host and Docker daemon. They are not remote
attestation and do not authorize execution or release any server reservation.
"""

from dataclasses import dataclass
from datetime import datetime
import hashlib
import io
import ipaddress
import json
from pathlib import PurePosixPath, PureWindowsPath
import re
import subprocess
import tarfile
import threading
import time


class RuntimeRefused(ValueError):
    """A fixed, value-free refusal; unknown state must remain held."""


CAPTURE_CHECKPOINTS = frozenset(
    {
        "daemon",
        "inspect",
        "identity",
        "mounts",
        "tmpfs",
        "profile",
        "volume_metadata",
        "network_binding",
        "running_state",
        "readiness_copy",
        "readiness_archive",
        "readiness_schema",
        "incarnation_recheck",
    }
)


def _capture_refused(error, checkpoint):
    """Attach only a fixed check name; preserve a more specific nested check."""
    if not isinstance(error, RuntimeRefused):
        error = RuntimeRefused("worker_runtime_refused")
    nested = getattr(error, "checkpoint", None)
    if type(nested) is not str or nested not in CAPTURE_CHECKPOINTS:
        require(type(checkpoint) is str and checkpoint in CAPTURE_CHECKPOINTS)
        error.checkpoint = checkpoint
    return error


def require(value):
    if not value:
        raise RuntimeRefused("worker_runtime_refused")


def host_bind_path(value):
    """Recognize only literal native paths and documented Desktop drive maps."""
    require(
        type(value) is str
        and 0 < len(value) <= 4096
        and not any(c in value for c in "\0\r\n")
    )
    windows = PureWindowsPath(value)
    if windows.is_absolute():
        require(".." not in windows.parts)
        return windows
    for prefix in ("/run/desktop/mnt/host/", "/host_mnt/"):
        if value.startswith(prefix):
            parts = value[len(prefix) :].split("/")
            require(
                len(parts) > 1
                and re.fullmatch(r"[a-zA-Z]", parts[0])
                and all(p not in {"", ".", ".."} for p in parts)
            )
            return PureWindowsPath(parts[0] + ":/", *parts[1:])
    path = PurePosixPath(value)
    require(path.is_absolute() and ".." not in path.parts and path.as_posix() == value)
    return path


_ID = re.compile(r"[0-9a-f]{64}")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}")
_PROOF = object()
_CREATED_PROOF = object()
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
    '"cgroup":{{json .HostConfig.CgroupnsMode}},'
    '"devices":{{json .HostConfig.Devices}},"device_requests":{{json .HostConfig.DeviceRequests}},'
    '"port_bindings":{{json .HostConfig.PortBindings}},"publish_all":{{json .HostConfig.PublishAllPorts}},'
    '"memory":{{json .HostConfig.Memory}},"pids":{{json .HostConfig.PidsLimit}},'
    '"nano_cpus":{{json .HostConfig.NanoCpus}},"oom_disable":{{json .HostConfig.OomKillDisable}},'
    '"restart":{{json .HostConfig.RestartPolicy.Name}},'
    '"cap_add":{{json .HostConfig.CapAdd}},'
    '"cap_drop":{{json .HostConfig.CapDrop}},'
    '"security":{{json .HostConfig.SecurityOpt}}}}'
)


# No Env, IP addresses, MACs, aliases or endpoint options cross this projection.
# The final null keeps the range output valid without copying arbitrary fields.
_NETWORK_INSPECT = (
    '{"id":{{json .Id}},"mode":{{json .HostConfig.NetworkMode}},"attachments":['
    "{{range $name, $network := .NetworkSettings.Networks}}"
    '{"name":{{json $name}},"id":{{json $network.NetworkID}}},{{end}}null]}'
)


_NETWORK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_NETWORK_RESOURCE = (
    '{"id":{{json .Id}},"name":{{json .Name}},"driver":{{json .Driver}},'
    '"scope":{{json .Scope}},"internal":{{json .Internal}},"options":{{json .Options}},'
    '"ipam":{{json .IPAM}},"project":{{json (index .Labels "com.docker.compose.project")}},'
    '"logical":{{json (index .Labels "com.docker.compose.network")}}}'
)


def _ipam_sha256(value):
    """Hash only validated public default-driver address allocation metadata."""
    require(type(value) is dict and set(value) == {"Driver", "Options", "Config"})
    require(value["Driver"] == "default" and value["Options"] in (None, {}))
    config = value["Config"]
    require(type(config) is list and bool(config))
    for row in config:
        require(
            type(row) is dict
            and "Subnet" in row
            and set(row) <= {"Subnet", "IPRange", "Gateway", "AuxiliaryAddresses"}
        )
        require(type(row["Subnet"]) is str and "%" not in row["Subnet"])
        subnet = ipaddress.ip_network(row["Subnet"])
        if "IPRange" in row:
            require(type(row["IPRange"]) is str and "%" not in row["IPRange"])
            selected = ipaddress.ip_network(row["IPRange"])
            require(selected.version == subnet.version and selected.subnet_of(subnet))
        if "Gateway" in row:
            require(
                type(row["Gateway"]) is str
                and "%" not in row["Gateway"]
                and ipaddress.ip_address(row["Gateway"]) in subnet
            )
        if "AuxiliaryAddresses" in row:
            aux = row["AuxiliaryAddresses"]
            require(type(aux) is dict)
            for key, address in aux.items():
                require(type(key) is str and _NETWORK_NAME.fullmatch(key))
                require(
                    type(address) is str
                    and "%" not in address
                    and ipaddress.ip_address(address) in subnet
                )
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def _default_runner_network_options(value):
    """Only older empty forms or the exact observed Docker Engine defaults."""
    return value is None or (
        type(value) is dict
        and (
            not value
            or value
            == {
                "com.docker.network.enable_ipv4": "true",
                "com.docker.network.enable_ipv6": "false",
            }
        )
    )


def _network_binding(value):
    if value is not None:
        require(type(value) is tuple and len(value) == 2)
        name, network_id = value
        require(type(name) is str and _NETWORK_NAME.fullmatch(name))
        require(type(network_id) is str and _ID.fullmatch(network_id))
    return value


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
    readiness_volume: str

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
        for volume in (self.state_volume, self.readiness_volume):
            require(
                type(volume) is str
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", volume)
            )
        require(self.state_volume != self.readiness_volume)


@dataclass(frozen=True, init=False)
class ObservedCreated:
    """Direct Created-profile observation, never runtime or never-sent proof.

    Serialized fields cannot be loaded as proof. There is deliberately no
    started timestamp, owner nonce, admission or execution authority here.
    """

    daemon_id: str
    container_id: str
    image_id: str
    project: str
    layout: WorkerLayout

    def __init__(
        self, daemon_id, container_id, image_id, project, layout, *, _proof=None
    ):
        require(_proof is _CREATED_PROOF)
        for name, value in (
            ("daemon_id", daemon_id),
            ("container_id", container_id),
            ("image_id", image_id),
            ("project", project),
            ("layout", layout),
        ):
            object.__setattr__(self, name, value)


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


def _static_profile(value, host, labels, image_id, project):
    """The existing immutable profile predicates, shared by bound/Created reads."""
    require(
        value["image"] == image_id
        and value["user"] in {"0", "0:0", "root", "root:root"}
        and value["entrypoint"] == ["/usr/local/bin/vardr-worker-owner"]
        and value["command"] in (None, [])
        and (value["healthcheck"] is None or value["healthcheck"] == {"Test": ["NONE"]})
        and labels["com.docker.compose.project"] == project
        and labels["com.docker.compose.service"] == "managed-worker"
        and labels["io.vardrsec.managed-worker"] == "1"
        and labels.get("com.docker.compose.oneoff") == "False"
        and host["pid"] in {"", "private"}
        and host["privileged"] is False
        and (host["init"] is None or host["init"] is False)
        and host["auto_remove"] is False
        and host["readonly_root"] is True
        and host["ipc"] == "private"
        and host["cgroup"] == "private"
        and host["devices"] in (None, [])
        and host["device_requests"] in (None, [])
        and host["port_bindings"] in (None, {})
        and host["publish_all"] is False
        and type(host["memory"]) is int
        and host["memory"] == 536870912
        and type(host["pids"]) is int
        and host["pids"] == 64
        and type(host["nano_cpus"]) is int
        and host["nano_cpus"] == 1000000000
        and (host["oom_disable"] is None or host["oom_disable"] is False)
        and host["restart"] in {"", "no"}
        and {v.upper().removeprefix("CAP_") for v in host["cap_add"]}
        == {"SETUID", "SETGID", "SETPCAP"}
        and {v.upper().removeprefix("CAP_") for v in host["cap_drop"]} == {"ALL"}
        and type(host["security"]) is list
        and len(host["security"]) == 1
        and host["security"][0] in {"no-new-privileges", "no-new-privileges:true"}
    )


class LocalDocker:
    """Bounded CLI access to one explicitly selected local Docker context."""

    def __init__(
        self, context, layout, *, max_attempts=None, protocol=None, network_binding=None
    ):
        require(
            type(context) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", context)
        )
        self.context = context
        require(isinstance(layout, WorkerLayout))
        self.layout = layout
        self.network_binding = _network_binding(network_binding)
        require(
            max_attempts is None
            or (type(max_attempts) is int and 1 <= max_attempts <= 32)
        )
        self.max_attempts = max_attempts
        require(protocol is None or type(protocol) is str)
        self.protocol = (
            protocol
            if protocol is not None
            else ("finite-v2" if max_attempts is not None else "legacy-v1")
        )
        require(self.protocol in {"legacy-v1", "finite-v2", "persistent-v3"})
        require(
            (self.protocol == "finite-v2" and max_attempts is not None)
            or (self.protocol != "finite-v2" and max_attempts is None)
        )
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

    def _daemon_binding(self):
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
            return endpoint, daemon
        except (ValueError, TypeError):
            raise RuntimeRefused("worker_runtime_refused") from None

    def daemon(self):
        return self._daemon_binding()[1]

    def _runner_network(self, selection, project):
        require(type(selection) is str and _NETWORK_NAME.fullmatch(selection))
        from worker_volumes import parse_document

        value = parse_document(
            self._command(
                "network", "inspect", "--format", _NETWORK_RESOURCE, selection
            )
        )
        require(
            set(value)
            == {
                "id",
                "name",
                "driver",
                "scope",
                "internal",
                "options",
                "ipam",
                "project",
                "logical",
            }
        )
        _network_binding((value["name"], value["id"]))
        require(
            value["driver"] == "bridge"
            and value["scope"] == "local"
            and value["internal"] is False
            and _default_runner_network_options(value["options"])
            and value["project"] == project
            and value["logical"] == "runner"
        )
        return {
            **{key: value[key] for key in value if key != "ipam"},
            "ipam_sha256": _ipam_sha256(value["ipam"]),
        }

    def capture_runner_network(self, *, name, project):
        """Observe one existing network resource; never attach, start or authorize."""
        require(
            type(name) is str
            and _NETWORK_NAME.fullmatch(name)
            and type(project) is str
            and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project)
        )
        require(self._observation_lock.acquire(blocking=False))
        try:
            self._deadline = time.monotonic() + 30
            context = self.context
            endpoint, daemon = self._daemon_binding()
            network = self._runner_network(name, project)
            require(network["name"] == name)
            require(self._runner_network(network["id"], project) == network)
            require(
                self._daemon_binding() == (endpoint, daemon) and self.context == context
            )
            return {
                "context": context,
                "local_endpoint": endpoint,
                "daemon_id": daemon,
                "network": network,
            }
        except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
            raise RuntimeRefused("worker_runtime_refused") from None
        finally:
            self._deadline = None
            self._observation_lock.release()

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

    def _network(self, container_id):
        """Require one actual attachment to the selected full network identity."""
        selected = _network_binding(self.network_binding)
        require(selected is not None)
        from worker_volumes import parse_document

        value = parse_document(
            self._command(
                "container", "inspect", "--format", _NETWORK_INSPECT, container_id
            )
        )
        require(set(value) == {"id", "mode", "attachments"})
        name, network_id = selected
        require(value["id"] == container_id and value["mode"] == name)
        require(value["attachments"] == [{"name": name, "id": network_id}, None])

    def _bound(self, identity):
        checkpoint = "daemon"
        try:
            require(
                isinstance(identity, RuntimeIdentity)
                and self.daemon() == identity.daemon_id
            )
            checkpoint = "inspect"
            value = self.inspect(identity.container_id)
            checkpoint = "profile"
            host, state, labels = value["host"], value["state"], value["labels"]
            checkpoint = "mounts"
            self._mounts(value["mounts"])
            checkpoint = "tmpfs"
            self._tmpfs(host["tmpfs"])
            checkpoint = "profile"
            _static_profile(value, host, labels, identity.image_id, identity.project)
            require(
                state["StartedAt"] == identity.started_at
                and type(state["Restarting"]) is bool
                and type(state["Running"]) is bool
                and type(state["Paused"]) is bool
                and state["Restarting"] is False
                and state["Paused"] is False
            )
            checkpoint = "volume_metadata"
            self._volume_sources(identity.project, value["mounts"])
            if getattr(self, "network_binding", None) is not None:
                checkpoint = "network_binding"
                self._network(identity.container_id)
        except (RuntimeRefused, KeyError, TypeError, AttributeError) as error:
            raise _capture_refused(error, checkpoint) from None
        return {
            **value,
            "mounts": sorted(value["mounts"], key=lambda mount: mount["Destination"]),
        }

    def _volume_sources(self, project, mounts):
        # Pure validation is shared with host custody; no host-root traversal or
        # recursive observation lock is needed inside this already bounded call.
        import worker_volumes as volumes

        root = volumes.daemon_root(
            self._command("info", "--format", volumes.DAEMON_FORMAT)
        )
        rows = {
            name: volumes.parse_document(
                self._command(
                    "volume", "inspect", "--format", volumes.VOLUME_FORMAT, name
                )
            )
            for name in (self.layout.state_volume, self.layout.readiness_volume)
        }
        return volumes.validate_sources(self.layout, project, mounts, root, rows)

    def _mounts(self, mounts):
        require(type(mounts) is list)
        expected = {
            "/home/runner/.vardrmap": ("volume", self.layout.state_volume, True),
            "/run/vardr-worker-ready": ("volume", self.layout.readiness_volume, True),
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
            if destination == "/tmp":
                require(mount.get("Type") == "tmpfs" and mount.get("RW") is True)
                continue
            require(destination in expected)
            kind, source, writable = expected[destination]
            require(
                mount.get("Type") == kind
                and mount.get("RW") is writable
                and (
                    mount.get("Name") == source
                    if kind == "volume"
                    else host_bind_path(mount.get("Source")) == host_bind_path(source)
                )
            )
        require(set(expected) <= seen)

    def _tmpfs(self, definitions):
        require(type(definitions) is dict and set(definitions) == {"/tmp"})
        for path, uid, size in [
            ("/tmp", "10001", "67108864"),
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
        checkpoint = "readiness_copy"
        try:
            archive = self._command(
                "container",
                "cp",
                container_id + ":/run/vardr-worker-ready/owner.json",
                "-",
                binary=True,
            )
            require(len(archive) <= 65536)
            checkpoint = "readiness_archive"
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

            checkpoint = "readiness_schema"
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
                ready["schema"]
                == (
                    "vardr.worker-owner-ready/3"
                    if self.protocol == "persistent-v3"
                    else "vardr.worker-owner-ready/2"
                    if self.max_attempts is not None
                    else "vardr.worker-owner-ready/1"
                )
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
        except (
            tarfile.TarError,
            ValueError,
            UnicodeError,
            KeyError,
            TypeError,
        ) as error:
            raise _capture_refused(error, checkpoint) from None

    def _created(self, container_id, image_id, project):
        """Read the same profile/mount/volume guards without a runtime identity."""
        value = self.inspect(container_id)
        host, state, labels = value["host"], value["state"], value["labels"]
        self._mounts(value["mounts"])
        self._tmpfs(host["tmpfs"])
        _static_profile(value, host, labels, image_id, project)
        require(
            state["Status"] == "created"
            and state["Running"] is False
            and state["Paused"] is False
            and state["Restarting"] is False
            and state["Dead"] is False
            and state["OOMKilled"] is False
            and type(state["Pid"]) is int
            and state["Pid"] == 0
            and type(state["ExitCode"]) is int
            and state["ExitCode"] == 0
            and state["StartedAt"] == state["FinishedAt"] == "0001-01-01T00:00:00Z"
            and state["Error"] == ""
        )
        self._volume_sources(project, value["mounts"])
        return {
            **value,
            "mounts": sorted(value["mounts"], key=lambda mount: mount["Destination"]),
        }

    def capture_created(self, *, daemon_id, container_id, image_id, project):
        """Observe only a selected Created CID; start/registration are not inferred.

        The lifecycle caller must separately validate replica/network inventory,
        source ownership and its durable never-sent intent before any start.
        """
        require(
            type(daemon_id) is str
            and 1 <= len(daemon_id) <= 128
            and type(container_id) is str
            and _ID.fullmatch(container_id)
            and type(image_id) is str
            and _IMAGE.fullmatch(image_id)
            and type(project) is str
            and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project)
        )
        require(self._observation_lock.acquire(blocking=False))
        try:
            self._deadline = time.monotonic() + 30
            require(self.daemon() == daemon_id)
            before = self._created(container_id, image_id, project)
            require(self._created(container_id, image_id, project) == before)
            require(self.daemon() == daemon_id)
            return ObservedCreated(
                daemon_id,
                container_id,
                image_id,
                project,
                self.layout,
                _proof=_CREATED_PROOF,
            )
        except (RuntimeRefused, KeyError, TypeError, AttributeError):
            raise RuntimeRefused("worker_created_refused") from None
        finally:
            self._deadline = None
            self._observation_lock.release()

    def capture_running(self, *, container_id, image_id, project):
        """Derive a fresh nonce from the actual owner's file, never caller JSON."""
        require(self._observation_lock.acquire(blocking=False))
        checkpoint = "daemon"
        try:
            self._deadline = time.monotonic() + 30
            daemon = self.daemon()
            checkpoint = "inspect"
            first = self.inspect(container_id)
            checkpoint = "identity"
            identity = RuntimeIdentity(
                daemon,
                container_id,
                image_id,
                project,
                first["state"]["StartedAt"],
                "0" * 64,
            )
            checkpoint = "profile"
            before = self._bound(identity)
            checkpoint = "running_state"
            require(
                before["state"]["Status"] == "running"
                and before["state"]["Running"] is True
            )
            checkpoint = "readiness_copy"
            nonce = self._owner_nonce(container_id)
            checkpoint = "incarnation_recheck"
            require(self._bound(identity) == before)
            return RuntimeIdentity(
                daemon, container_id, image_id, project, identity.started_at, nonce
            )
        except (RuntimeRefused, KeyError, TypeError) as error:
            raise _capture_refused(error, checkpoint) from None
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

    def confirm_exit(self, proof):
        """Recheck direct exit immediately before the caller's durable intent."""
        require(isinstance(proof, ObservedExit))
        require(self._observation_lock.acquire(blocking=False))
        try:
            self._deadline = time.monotonic() + 30
            value = self._bound(proof.identity)
            state = value["state"]
            require(
                state["Status"] == "exited"
                and state["Running"] is False
                and state.get("Dead", False) is False
                and type(state["ExitCode"]) is int
                and state["ExitCode"] == proof.exit_code
                and state["FinishedAt"] == proof.finished_at
            )
        except (KeyError, TypeError):
            raise RuntimeRefused("worker_runtime_refused") from None
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
