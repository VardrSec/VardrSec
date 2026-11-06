"""Validate managed volume paths through the selected trusted local daemon.

These are lexical daemon paths, not host realpaths or content/freshness proofs.
Host bind mounts and private custody paths still require their own strict checks.
"""

import json
from pathlib import PurePosixPath
import time

import worker_runtime as runtime


DAEMON_FORMAT = '{"root":{{json .DockerRootDir}},"os":{{json .OSType}}}'
VOLUME_FORMAT = (
    '{"name":{{json .Name}},"driver":{{json .Driver}},'
    '"scope":{{json .Scope}},"options":{{json .Options}},'
    '"source":{{json .Mountpoint}},"project":'
    '{{json (index .Labels "com.docker.compose.project")}},'
    '"volume":{{json (index .Labels "com.docker.compose.volume")}},'
    '"ready":{{json (index .Labels "io.vardrsec.managed-worker-ready")}}}'
)


def parse_document(raw):
    try:
        runtime.require(type(raw) is str and len(raw.encode("utf-8")) <= 16384)
    except UnicodeError:
        raise runtime.RuntimeRefused("worker_runtime_refused") from None

    def pairs(values):
        result = {}
        for key, value in values:
            runtime.require(key not in result)
            result[key] = value
        return result

    def constant(_):
        raise ValueError

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        runtime.require(type(value) is dict)
        return value
    except (ValueError, TypeError, RecursionError):
        raise runtime.RuntimeRefused("worker_runtime_refused") from None


def _path(value):
    runtime.require(
        type(value) is str
        and 1 < len(value) <= 4096
        and not any(ord(c) < 32 or ord(c) == 127 or c == "\\" for c in value)
    )
    path = PurePosixPath(value)
    runtime.require(
        path.is_absolute()
        and path.root == "/"
        and ".." not in path.parts
        and path.as_posix() == value
    )
    return path


def daemon_root(raw):
    value = parse_document(raw)
    runtime.require(set(value) == {"root", "os"} and value["os"] == "linux")
    _path(value["root"])
    return value["root"]


def validate_sources(layout, project, mounts, docker_root_dir, volume_rows):
    """Validate projected metadata; caller must bind it to its local daemon."""
    runtime.require(isinstance(layout, runtime.WorkerLayout))
    runtime.require(type(project) is str and 1 <= len(project) <= 63)
    runtime.require(type(mounts) is list and all(type(m) is dict for m in mounts))
    expected = (
        (layout.state_volume, "/home/runner/.vardrmap", "runner-state"),
        (layout.readiness_volume, "/run/vardr-worker-ready", "worker-ready"),
    )
    runtime.require(
        type(volume_rows) is dict and set(volume_rows) == {v[0] for v in expected}
    )
    root, result = _path(docker_root_dir), []
    for name, destination, logical in expected:
        attached = [m for m in mounts if m.get("Destination") == destination]
        runtime.require(len(attached) == 1)
        mount, volume = attached[0], volume_rows[name]
        runtime.require(
            type(volume) is dict
            and set(volume)
            == {
                "name",
                "driver",
                "scope",
                "options",
                "source",
                "project",
                "volume",
                "ready",
            }
            and volume["name"] == name
            and volume["driver"] == "local"
            and volume["scope"] == "local"
            and volume["options"] in (None, {})
            and volume["project"] == project
            and volume["volume"] == logical
            and (logical != "worker-ready" or volume["ready"] == "1")
            and mount.get("Type") == "volume"
            and mount.get("Name") == name
            and mount.get("RW") is True
        )
        source = _path(volume["source"])
        runtime.require(source == root / "volumes" / name / "_data")
        runtime.require(_path(mount.get("Source")) == source)
        result.append(source)
    names = [m.get("Name") for m in mounts if m.get("Type") == "volume"]
    runtime.require(
        len(names) == 2 and all(type(n) is str and n in volume_rows for n in names)
    )
    return tuple(result)


def managed_sources(observer, identity):
    """Return exact default-local state/ready mountpoints without traversing them.

    No custom local-driver options, plugin/remote volumes or subpaths qualify.
    The selected daemon, full incarnation and attachments must remain unchanged.
    """
    runtime.require(isinstance(observer, runtime.LocalDocker))
    runtime.require(isinstance(identity, runtime.RuntimeIdentity))
    runtime.require(observer._observation_lock.acquire(blocking=False))
    try:
        observer._deadline = time.monotonic() + 30
        before = observer._bound(identity)
        root = daemon_root(observer._command("info", "--format", DAEMON_FORMAT))
        volumes = {
            name: parse_document(
                observer._command("volume", "inspect", "--format", VOLUME_FORMAT, name)
            )
            for name in (observer.layout.state_volume, observer.layout.readiness_volume)
        }
        result = validate_sources(
            observer.layout, identity.project, before["mounts"], root, volumes
        )
        runtime.require(observer._bound(identity) == before)
        runtime.require(
            daemon_root(observer._command("info", "--format", DAEMON_FORMAT)) == root
        )
        return result
    except (KeyError, TypeError, ValueError, UnicodeError):
        raise runtime.RuntimeRefused("worker_runtime_refused") from None
    finally:
        observer._deadline = None
        observer._observation_lock.release()
