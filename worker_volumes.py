"""Validate managed volume paths through the selected trusted local daemon.

These are lexical daemon paths, not host realpaths or content/freshness proofs.
Host bind mounts and private custody paths still require their own strict checks.
"""

import json
from pathlib import PurePosixPath
import re
import time

import worker_runtime as runtime


DAEMON_FORMAT = '{"root":{{json .DockerRootDir}},"os":{{json .OSType}}}'
_VOLUME_COMMON = (
    '{"name":{{json .Name}},"driver":{{json .Driver}},'
    '"scope":{{json .Scope}},"options":{{json .Options}},'
    '"source":{{json .Mountpoint}},"project":'
    '{{json (index .Labels "com.docker.compose.project")}},'
    '"volume":{{json (index .Labels "com.docker.compose.volume")}},'
)
VOLUME_FORMAT = (
    _VOLUME_COMMON
    + '"ready":{{json (index .Labels "io.vardrsec.managed-worker-ready")}}}'
)

# An absent label produces [null]; an explicitly empty one produces ["",null].
# Only these three literal public labels are projected. Do not copy all Labels.
VOLUME_RESOURCE_FORMAT = (
    _VOLUME_COMMON + '"created_at":{{json .CreatedAt}},'
    '"ready":[{{range $k,$v := .Labels}}{{if eq $k "io.vardrsec.managed-worker-ready"}}{{json $v}},{{end}}{{end}}null],'
    '"intent_id":[{{range $k,$v := .Labels}}{{if eq $k "io.vardrsec.managed-worker-intent"}}{{json $v}},{{end}}{{end}}null],'
    '"config_hash":[{{range $k,$v := .Labels}}{{if eq $k "com.docker.compose.config-hash"}}{{json $v}},{{end}}{{end}}null]}'
)
_VOLUME_FIELDS = {
    "name",
    "driver",
    "scope",
    "options",
    "source",
    "project",
    "volume",
    "ready",
}


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


def _volume_source(volume, root, name, project, logical):
    runtime.require(
        type(volume) is dict
        and set(volume) == _VOLUME_FIELDS
        and volume["name"] == name
        and volume["driver"] == volume["scope"] == "local"
        and volume["options"] in (None, {})
        and volume["project"] == project
        and volume["volume"] == logical
        and (logical != "worker-ready" or volume["ready"] == "1")
    )
    source = _path(volume["source"])
    runtime.require(source == root / "volumes" / name / "_data")
    return source


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
        source = _volume_source(volume, root, name, project, logical)
        runtime.require(
            mount.get("Type") == "volume"
            and mount.get("Name") == name
            and mount.get("RW") is True
            and _path(mount.get("Source")) == source
        )
        result.append(source)
    names = [m.get("Name") for m in mounts if m.get("Type") == "volume"]
    runtime.require(
        len(names) == 2 and all(type(n) is str and n in volume_rows for n in names)
    )
    return tuple(result)


def _optional_label(value):
    runtime.require(type(value) is list and len(value) in (1, 2) and value[-1] is None)
    if len(value) == 1:
        return None
    runtime.require(type(value[0]) is str)
    return value[0]


def _resource_row(observer, name):
    row = parse_document(
        observer._command("volume", "inspect", "--format", VOLUME_RESOURCE_FORMAT, name)
    )
    runtime.require(
        set(row) == _VOLUME_FIELDS | {"created_at", "intent_id", "config_hash"}
    )
    return row


def _resource_value(row, root, name, project, logical):
    selected = {key: row[key] for key in _VOLUME_FIELDS}
    selected["ready"] = _optional_label(selected["ready"])
    _volume_source(selected, root, name, project, logical)
    runtime.require(selected["ready"] == ("1" if logical == "worker-ready" else None))
    intent_id = _optional_label(row["intent_id"])
    config_hash = _optional_label(row["config_hash"])
    runtime.require(
        intent_id is None
        or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", intent_id)
    )
    runtime.require(config_hash is None or re.fullmatch(r"[0-9a-f]{64}", config_hash))
    runtime._timestamp(row["created_at"])
    return {
        **{
            key: selected[key]
            for key in ("name", "source", "driver", "scope", "options", "project")
        },
        "logical": logical,
        "ready_marker": selected["ready"],
        "created_at": row["created_at"],
        "intent_id": intent_id,
        "config_hash": config_hash,
    }


def _resource(observer, root, name, project, logical):
    return _resource_value(_resource_row(observer, name), root, name, project, logical)


def _project_readiness(observer, root, project):
    raw = observer._command(
        "volume",
        "ls",
        "--filter",
        "label=com.docker.compose.project=" + project,
        "--format",
        "{{json .Name}}",
    )
    lines = raw.split("\n") if raw else []
    runtime.require(len(lines) <= 256)
    names = set()
    for line in lines:
        value = json.loads(line)
        runtime.require(
            type(value) is str
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value)
            and value not in names
        )
        names.add(value)
    readiness = []
    for name in sorted(names):
        row = _resource_row(observer, name)
        runtime.require(row["name"] == name and row["project"] == project)
        if (
            row["volume"] == "worker-ready"
            or _optional_label(row["ready"]) is not None
            or _optional_label(row["intent_id"]) is not None
        ):
            readiness.append(_resource_value(row, root, name, project, "worker-ready"))
    return sorted(names), readiness


def capture_readiness_inventory(observer, project):
    """Read every same-project readiness resource, even without a container."""
    runtime.require(isinstance(observer, runtime.LocalDocker))
    runtime.require(
        type(project) is str and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project)
    )
    runtime.require(observer._observation_lock.acquire(blocking=False))
    try:
        observer._deadline = time.monotonic() + 30
        context = observer.context
        endpoint, daemon = observer._daemon_binding()
        raw_root = daemon_root(observer._command("info", "--format", DAEMON_FORMAT))
        root = _path(raw_root)
        names, readiness = _project_readiness(observer, root, project)
        runtime.require(
            _project_readiness(observer, root, project) == (names, readiness)
        )
        runtime.require(
            daemon_root(observer._command("info", "--format", DAEMON_FORMAT))
            == raw_root
            and observer._daemon_binding() == (endpoint, daemon)
            and observer.context == context
        )
        return {
            "context": context,
            "local_endpoint": endpoint,
            "daemon_id": daemon,
            "daemon_root": raw_root,
            "readiness": readiness,
        }
    except (
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
        OverflowError,
        RecursionError,
    ):
        raise runtime.RuntimeRefused("worker_runtime_refused") from None
    finally:
        observer._deadline = None
        observer._observation_lock.release()


def capture_volume_resource(observer, project, logical):
    """Read existing resource metadata only; a matching mount remains separate."""
    runtime.require(isinstance(observer, runtime.LocalDocker))
    runtime.require(
        type(project) is str and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project)
    )
    runtime.require(
        type(logical) is str and logical in {"runner-state", "worker-ready"}
    )
    runtime.require(observer._observation_lock.acquire(blocking=False))
    try:
        observer._deadline = time.monotonic() + 30
        context, layout = observer.context, observer.layout
        runtime.require(type(layout) is runtime.WorkerLayout)
        name = (
            layout.state_volume
            if logical == "runner-state"
            else layout.readiness_volume
        )
        endpoint, daemon = observer._daemon_binding()
        raw_root = daemon_root(observer._command("info", "--format", DAEMON_FORMAT))
        root = _path(raw_root)
        volume = _resource(observer, root, name, project, logical)
        runtime.require(_resource(observer, root, name, project, logical) == volume)
        runtime.require(
            daemon_root(observer._command("info", "--format", DAEMON_FORMAT))
            == raw_root
        )
        runtime.require(
            observer._daemon_binding() == (endpoint, daemon)
            and observer.context == context
            and observer.layout == layout
        )
        return {
            "context": context,
            "local_endpoint": endpoint,
            "daemon_id": daemon,
            "daemon_root": raw_root,
            "volume": volume,
        }
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        raise runtime.RuntimeRefused("worker_runtime_refused") from None
    finally:
        observer._deadline = None
        observer._observation_lock.release()


def _observed_profile(observer, identity):
    if type(identity) is runtime.ObservedCreated:
        runtime.require(identity.layout == observer.layout)
        runtime.require(observer.daemon() == identity.daemon_id)
        return observer._created(
            identity.container_id, identity.image_id, identity.project
        )
    return observer._bound(identity)


def managed_sources(observer, identity):
    """Return exact default-local state/ready mountpoints without traversing them.

    No custom local-driver options, plugin/remote volumes or subpaths qualify.
    The selected daemon, full incarnation and attachments must remain unchanged.
    A direct Created observation uses the same custody checks before startup;
    retained JSON is refused and no never-sent or execution proof is inferred.
    """
    runtime.require(isinstance(observer, runtime.LocalDocker))
    runtime.require(
        isinstance(identity, runtime.RuntimeIdentity)
        or type(identity) is runtime.ObservedCreated
    )
    runtime.require(observer._observation_lock.acquire(blocking=False))
    try:
        observer._deadline = time.monotonic() + 30
        before = _observed_profile(observer, identity)
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
        runtime.require(_observed_profile(observer, identity) == before)
        runtime.require(
            daemon_root(observer._command("info", "--format", DAEMON_FORMAT)) == root
        )
        return result
    except (KeyError, TypeError, ValueError, UnicodeError) as error:
        refused = runtime.RuntimeRefused("worker_runtime_refused")
        if isinstance(error, runtime.RuntimeRefused):
            try:
                attributes = object.__getattribute__(error, "__dict__")
                checkpoint = (
                    attributes.get("checkpoint") if type(attributes) is dict else None
                )
                if (
                    type(checkpoint) is str
                    and checkpoint in runtime.CAPTURE_CHECKPOINTS
                ):
                    refused.checkpoint = checkpoint
            except BaseException:
                # Optional diagnostic attributes cannot replace the fixed refusal.
                pass
        raise refused from None
    finally:
        observer._deadline = None
        observer._observation_lock.release()
