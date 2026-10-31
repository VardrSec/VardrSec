"""Explicit local image-set updates, rehearsed against a verified restored copy."""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

import recovery

STATE = ".update-state.json"
PRIVATE = ".update-private.yaml"
WAIT_SECONDS = 180


@contextmanager
def installation_lock(root):
    descriptor = os.open(root / ".update-lock", os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(descriptor, "r+b", buffering=0) as handle:
        try:
            if os.name == "nt":
                import msvcrt

                if os.fstat(handle.fileno()).st_size == 0:
                    handle.write(b"0")
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ValueError("Another installation operation is in progress") from None
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def operation_guard(root, action):
    with installation_lock(root):
        if action in ("install", "start", "build", "bootstrap", "database-role") and (
            root / STATE
        ).exists():
            raise ValueError(
                "An update is pending or failed; use cancel-update before mutation, or restore its backup after mutation"
            )
        yield


def save(path, value):
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    recovery.json_write(temporary, value)
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def image_set(root):
    config = json.loads(
        recovery.compose(
            root,
            "--profile",
            "tools",
            "config",
            "--format",
            "json",
            capture_output=True,
            text=True,
        ).stdout
    )
    images = {
        s: recovery.container(root, s)["Image"] for s in recovery.SERVICES - {"runner"}
    }
    images["runner"] = recovery.command(
        "docker",
        "image",
        "inspect",
        config["services"]["runner"]["image"],
        "--format",
        "{{.Id}}",
        capture_output=True,
        text=True,
    ).stdout.strip()
    return config, images


def candidate_set(path, baseline, origin):
    value = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "public_origin", "images", "components"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
    ):
        raise ValueError("Unsupported candidate manifest")
    if value["public_origin"] != origin:
        raise ValueError(
            "Candidate public origin must match the installed frontend URL"
        )
    images = value["images"]
    if (
        not isinstance(images, dict)
        or set(images) != recovery.SERVICES
        or not all(
            isinstance(i, str) and recovery.IMAGE_ID.fullmatch(i)
            for i in images.values()
        )
    ):
        raise ValueError("Every candidate service requires an immutable local image ID")
    if images["db"] != baseline["db"]:
        raise ValueError(
            "PostgreSQL image changes require a separate major-version/recovery procedure"
        )
    components = value["components"]
    if (
        not isinstance(components, dict)
        or set(components) != {"map", "runner", "gate"}
        or not all(
            isinstance(c, str) and re.fullmatch("[0-9a-f]{40}", c)
            for c in components.values()
        )
    ):
        raise ValueError("Candidate component source commits must be recorded")
    for image in images.values():
        recovery.command("docker", "image", "inspect", image, stdout=subprocess.DEVNULL)
    return value


def set_images(root, images):
    save(
        root / ".active-images.json",
        {"services": {s: {"image": i} for s, i in images.items()}},
    )


def private_proxy(root, *args, **kwargs):
    file = root / PRIVATE
    if not file.exists():
        recovery.private_write(file, b"services:\n  proxy:\n    ports: !reset []\n")
    return recovery.command(
        "docker",
        "compose",
        "-f",
        str(root / "compose.yaml"),
        "-f",
        str(root / ".active-images.json"),
        "-f",
        str(file),
        *args,
        cwd=root,
        **kwargs,
    )


def verify_private(root, project):
    private_proxy(
        root,
        "-p",
        project,
        "up",
        "-d",
        "--no-build",
        "--pull",
        "never",
        "--wait",
        "--wait-timeout",
        str(WAIT_SECONDS),
        "db",
        "api",
        "web",
        "proxy",
    )
    info = recovery.container(root, "proxy", project)
    if any(info["NetworkSettings"]["Ports"].values()):
        raise ValueError("Maintenance proxy must not publish a host port")
    private_proxy(
        root,
        "-p",
        project,
        "cp",
        "proxy:/data/caddy/pki/authorities/local/root.crt",
        "trust/root.crt",
        capture_output=True,
    )
    (root / "trust/root.crt").chmod(0o644)
    result = private_proxy(
        root,
        "-p",
        project,
        "run",
        "--rm",
        "--no-deps",
        "runner",
        "doctor",
        "--platform",
        "--offline",
        "--json",
        capture_output=True,
        text=True,
        check=False,
    )
    report = json.loads(result.stdout)
    # Do not copy a credential or raw exception into update records/logs.
    if result.returncode or report.get("healthy") is not True:
        raise ValueError("Runner diagnostics failed during private update verification")


def assert_quiesced(root, metadata, project):
    if any(
        recovery.container(root, s)["State"]["Running"] for s in ("api", "web", "proxy")
    ):
        raise ValueError("Source applications resumed after backup")
    if recovery.command(
        "docker",
        "ps",
        "-q",
        "--filter",
        f"label=com.docker.compose.project={project}",
        "--filter",
        "label=com.docker.compose.service=runner",
        capture_output=True,
        text=True,
    ).stdout.strip():
        raise ValueError("Runner activity resumed after backup")
    if recovery.database_fingerprint(root) != metadata["database"]:
        raise ValueError("Database changed after backup")
    for name, (service, mount) in recovery.VOLUMES.items():
        volume = recovery.volume_name(recovery.container(root, service), mount)
        if (
            recovery.volume_fingerprint(metadata["images"]["runner"], volume)
            != metadata["volumes"][name]
        ):
            raise ValueError("State changed after backup")
    for name in recovery.FILES:
        if recovery.digest(root / name) != metadata["files"][name]:
            raise ValueError("Installation files changed after backup")


def no_runner(project):
    if recovery.command(
        "docker",
        "ps",
        "-q",
        "--filter",
        f"label=com.docker.compose.project={project}",
        "--filter",
        "label=com.docker.compose.service=runner",
        capture_output=True,
        text=True,
    ).stdout.strip():
        raise ValueError(
            "Finish the explicitly invoked Runner before update or cancellation"
        )


def update(root, candidate, backup, destination, rehearsal_project):
    root, candidate, backup, destination = (
        p.resolve() for p in (root, candidate, backup, destination)
    )
    with installation_lock(root):
        if (root / STATE).exists():
            raise ValueError("Resolve the pending update before starting another")
        if not os.environ.get("VARDRMAP_API_KEY"):
            raise ValueError(
                "Supply a working Runner API key in VARDRMAP_API_KEY for update diagnostics"
            )
        if backup.exists() or destination.exists():
            raise ValueError("Backup and rehearsal destinations must be new")
        if not re.fullmatch(
            r"vardrsec-restore-[a-z0-9][a-z0-9-]{0,40}", rehearsal_project
        ):
            raise ValueError("Use a separate vardrsec-restore-NAME rehearsal project")
        config, baseline = image_set(root)
        candidate = candidate_set(
            candidate, baseline, config["services"]["web"]["environment"]["AUTH_URL"]
        )
        project = config["name"]
        if rehearsal_project == project:
            raise ValueError("Rehearsal must use a different project")
        no_runner(project)
        record = {
            "schema_version": 1,
            "phase": "preparing",
            "status": "running",
            "baseline_images": baseline,
            "candidate": candidate,
            "backup": str(backup.resolve()),
            "rehearsal": str(destination.resolve()),
            "rehearsal_project": rehearsal_project,
            "project": project,
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        save(root / STATE, record)
        try:
            recovery.backup(root, backup)
            metadata = recovery.validate(backup)
            record.update(
                phase="rehearsal",
                snapshot_sha256=recovery.digest(backup / "snapshot.json"),
                baseline_images=metadata["images"],
            )
            save(root / STATE, record)
            recovery.restore(root, backup, destination, rehearsal_project)
            set_images(destination, candidate["images"])
            verify_private(destination, rehearsal_project)
            recovery.compose(
                destination, "--profile", "tools", "stop", project=rehearsal_project
            )
            assert_quiesced(root, metadata, project)
            record["phase"] = "applying"
            save(root / STATE, record)
            set_images(root, candidate["images"])
            verify_private(root, project)
            # Only now publish the normal loopback HTTPS entry point.
            record["phase"] = "publishing"
            save(root / STATE, record)
            recovery.compose(
                root,
                "up",
                "-d",
                "--no-build",
                "--pull",
                "never",
                "--force-recreate",
                "--wait",
                "--wait-timeout",
                str(WAIT_SECONDS),
                "proxy",
            )
            record.update(
                phase="complete",
                status="success",
                finished_at=datetime.now(timezone.utc).isoformat(),
            )
            save(root / ".last-update.json", record)
            (root / STATE).unlink()
            print(
                "Update verified and started. Backup and stopped rehearsal installation retained."
            )
        except BaseException:
            record["status"] = "failed"
            try:
                save(root / STATE, record)
            except OSError:
                # The last durable phase still blocks startup if disk failure
                # prevents the status update. Closing traffic takes precedence.
                pass
            # Close traffic on any failure, including an interrupt after publication.
            for directory, name in ((root, project), (destination, rehearsal_project)):
                if directory == root and record["phase"] == "preparing":
                    continue
                if (directory / "compose.yaml").exists():
                    try:
                        recovery.compose(
                            directory,
                            "stop",
                            "proxy",
                            "web",
                            "api",
                            project=name,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                    except subprocess.CalledProcessError:
                        pass
            raise ValueError(
                "Update stopped. Pending record retained; cancel-update is available only before original mutation, otherwise restore the recorded backup"
            ) from None


def cancel(root):
    with installation_lock(root):
        record = json.loads((root / STATE).read_text(encoding="utf-8"))
        if record["phase"] not in ("preparing", "rehearsal"):
            raise ValueError(
                "Original mutation may have occurred; restore the backup into a fresh installation"
            )
        no_runner(record["project"])
        backup = Path(record["backup"])
        if record["phase"] == "rehearsal":
            metadata = recovery.validate(backup)
            if recovery.digest(backup / "snapshot.json") != record["snapshot_sha256"]:
                raise ValueError("Recorded backup changed")
            assert_quiesced(root, metadata, record["project"])
        set_images(root, record["baseline_images"])
        recovery.compose(
            root,
            "up",
            "-d",
            "--no-build",
            "--pull",
            "never",
            "--wait",
            "--wait-timeout",
            str(WAIT_SECONDS),
            "db",
            "api",
            "web",
            "proxy",
        )
        record.update(
            status="cancelled", finished_at=datetime.now(timezone.utc).isoformat()
        )
        save(root / ".last-update.json", record)
        (root / STATE).unlink()
        print(
            "Update cancelled before original mutation; baseline installation resumed."
        )
