"""Exact read-only Compose visibility for worker lifecycle planning."""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from worker_volumes import parse_document

_MODEL_SHA256 = "a7fff3bd476360ce713c02dc123c8d1d5e5ea985244b4e27cd06b7b2bf45a32d"
_VERSION = "5.6.1"
_MAX_OUTPUT = 65536
_PLATFORM_ENV = frozenset(
    {
        "SYSTEMROOT",
        "WINDIR",
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMFILES",
        "PROGRAMDATA",
        "TEMP",
        "TMP",
        "TMPDIR",
    }
)


class ComposeInventoryRefused(ValueError):
    def __init__(self):
        super().__init__("worker_compose_inventory_refused")


def _require(value):
    if not value:
        raise ComposeInventoryRefused()


@dataclass(frozen=True)
class LocalClient:
    docker: Path
    docker_sha256: str
    compose: Path
    compose_sha256: str
    config: Path
    context: str
    endpoint: str


@dataclass(frozen=True)
class WorkerProject:
    name: str
    installation: Path
    override: Path
    empty_env: Path
    image: str
    public_directory: Path
    ready_volume: str
    state_volume: str
    runner_network: str


def _matches(value, pattern):
    _require(type(value) is str and re.fullmatch(pattern, value) is not None)


def _local_path(value):
    _require(isinstance(value, Path) and value.is_absolute())
    text = str(value)
    _require(
        not text.startswith(("//", "\\\\"))
        and not any(ord(ch) < 32 or ord(ch) == 127 for ch in text)
    )
    return value


def _regular(path, maximum):
    checked = _local_path(_local_path(path).resolve(strict=True))
    info = checked.stat()
    _require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum)
    return checked


def _hash_executable(path, digest):
    _matches(digest, r"[0-9a-f]{64}")
    path = _regular(path, 512 * 1024 * 1024)
    with path.open("rb") as file:
        _require(hashlib.file_digest(file, "sha256").hexdigest() == digest)
    return path


def _small(path, limit):
    path = _regular(path, limit)
    with path.open("rb") as file:
        data = file.read(limit + 1)
    _require(len(data) <= limit)
    return path, data


def _files(client, project):
    docker = _hash_executable(client.docker, client.docker_sha256)
    compose = _hash_executable(client.compose, client.compose_sha256)
    config, installation = (
        _local_path(_local_path(path).resolve(strict=True))
        for path in (client.config, project.installation)
    )
    selected = _local_path(project.public_directory)
    parent = _local_path(selected.parent.resolve(strict=True))
    _require(all(path.is_dir() for path in (config, installation, parent)))
    _require(selected.name not in {"", ".", ".."})
    public = parent / selected.name
    try:
        public_info = public.lstat()
    except FileNotFoundError:
        public_info = None
    else:
        _require(
            stat.S_ISDIR(public_info.st_mode) and public.resolve(strict=True) == public
        )
    model, model_bytes = _small(installation / "compose.worker.json", 16384)
    override, override_bytes = _small(project.override, 4096)
    empty, data = _small(project.empty_env, 0)
    _require(model == installation / "compose.worker.json")
    _require(len({docker, compose, model, override, empty}) == 5 and data == b"")
    closed = parse_document(override_bytes.decode("utf-8"))
    _require(
        hashlib.sha256(model_bytes.replace(b"\r\n", b"\n")).hexdigest() == _MODEL_SHA256
        and closed
        == {
            "networks": {"runner": {"external": True, "name": project.runner_network}},
            "volumes": {
                "runner-state": {"external": True, "name": project.state_volume}
            },
        }
        and closed["networks"]["runner"]["external"] is True
        and closed["volumes"]["runner-state"]["external"] is True
    )
    return (
        docker,
        compose,
        config,
        installation,
        public,
        model,
        override,
        empty,
        override_bytes,
        None if public_info is None else (public_info.st_dev, public_info.st_ino),
    )


def _run(argv, *, cwd, env, deadline):
    remaining = deadline - time.monotonic()
    _require(remaining > 0)
    result = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        input=b"",
        capture_output=True,
        check=False,
        timeout=min(12, remaining),
    )
    _require(result.returncode == 0 and len(result.stdout) <= _MAX_OUTPUT)
    return result.stdout


def _ids(raw):
    if raw == b"":
        return []
    rows = raw.decode("ascii").replace("\r\n", "\n").removesuffix("\n").split("\n")
    for row in rows:
        _matches(row, r"[0-9a-f]{64}")
    _require(len(set(rows)) == len(rows))
    return sorted(rows)


def capture_visible_workers(client, project):
    """Read Compose's view only; compare with independent Engine observations.

    The caller must surround this read with direct Engine resource and daemon
    checks under its lifecycle operation. The empty list is not bootstrap proof.
    """
    try:
        _require(type(client) is LocalClient and type(project) is WorkerProject)
        _matches(client.context, r"[A-Za-z0-9_.-]{1,128}")
        _matches(
            client.endpoint, r"(?:unix:///|npipe:////\./pipe/)[^\x00-\x20\x7f]{1,512}"
        )
        _matches(project.name, r"[a-z0-9][a-z0-9_-]{0,62}")
        _matches(project.image, r"sha256:[0-9a-f]{64}")
        for name in (
            project.ready_volume,
            project.state_volume,
            project.runner_network,
        ):
            _matches(name, r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
        _require(project.ready_volume != project.state_volume)
        deadline = time.monotonic() + 30
        original = _files(client, project)
        docker, compose, config, cwd, public, model, override, empty, *_ = original
        platform = {
            key: value
            for key, value in os.environ.items()
            if key.upper() in _PLATFORM_ENV
        }
        env = {**platform, "DOCKER_CONFIG": str(config)}
        inspect = [
            str(docker),
            "--config",
            str(config),
            "--context",
            client.context,
            "context",
            "inspect",
            client.context,
            "--format",
            "{{json .Endpoints.docker.Host}}",
        ]
        prefix = [str(compose), "--context", client.context]

        def read(argv, environment=env):
            return _run(argv, cwd=cwd, env=environment, deadline=deadline)

        _require(json.loads(read(inspect)) == client.endpoint)
        version = read(prefix + ["version", "--short"]).decode("ascii").strip()
        _require(version in (_VERSION, "v" + _VERSION))
        args = prefix + [
            "--project-name",
            project.name,
            "--project-directory",
            str(cwd),
            "--env-file",
            str(empty),
            "-f",
            str(model),
            "-f",
            str(override),
            "--profile",
            "managed-worker",
            "ps",
            "--all",
            "--no-trunc",
            "--quiet",
            "managed-worker",
        ]
        visible = _ids(
            read(
                args,
                {
                    **env,
                    "VARDRSEC_WORKER_IMAGE": project.image,
                    "VARDRSEC_WORKER_PUBLIC_DIR": str(public),
                    "VARDRSEC_WORKER_READY_VOLUME": project.ready_volume,
                    "VARDRSEC_WORKER_CREDENTIAL_FILE": str(empty),
                    "VARDRMAP_API_KEY": "synthetic_read_only_compose_ps",
                },
            )
        )
        _require(json.loads(read(inspect)) == client.endpoint)
        _require(_files(client, project) == original and time.monotonic() < deadline)
        return {
            "context": client.context,
            "local_endpoint": client.endpoint,
            "project": project.name,
            "compose_worker_ids": visible,
        }
    except (
        OSError,
        ValueError,
        TypeError,
        UnicodeError,
        RecursionError,
        subprocess.SubprocessError,
    ):
        raise ComposeInventoryRefused() from None
