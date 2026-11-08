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
    if recovery.read_mode(root) == "mapless":
        if set(config["services"]) != {"runner"} or config["services"]["runner"].get("environment"):
            raise ValueError("Mapless update requires the uninjected Runner-only model")
        image = recovery.container(root, "runner", config["name"])["Image"]
        if not recovery.IMAGE_ID.fullmatch(image) or config["services"]["runner"]["image"] != image:
            raise ValueError("Mapless selection must match its immutable installed image")
        return config, {"runner": image}
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


def candidate_set(path, baseline, origin, *, mode="full"):
    if mode not in {"full", "mapless"}:
        raise ValueError("Unsupported candidate installation mode")
    mapless = mode == "mapless"
    value = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or set(value) != ({"schema_version", "mode", "images", "components"} if mapless
                          else {"schema_version", "public_origin", "images", "components"})
        or type(value["schema_version"]) is not int
        or value["schema_version"] != (2 if mapless else 1)
    ):
        raise ValueError("Unsupported candidate manifest")
    if mapless and value["mode"] != "mapless":
        raise ValueError("Candidate mode does not match this installation")
    if not mapless and value["public_origin"] != origin:
        raise ValueError(
            "Candidate public origin must match the installed frontend URL"
        )
    images = value["images"]
    if (
        not isinstance(images, dict)
        or set(images) != ({"runner"} if mapless else recovery.SERVICES)
        or not all(
            isinstance(i, str) and recovery.IMAGE_ID.fullmatch(i)
            for i in images.values()
        )
    ):
        raise ValueError("Every candidate service requires an immutable local image ID")
    if not mapless and images["db"] != baseline["db"]:
        raise ValueError(
            "PostgreSQL image changes require a separate major-version/recovery procedure"
        )
    components = value["components"]
    if (
        not isinstance(components, dict)
        or set(components) != ({"runner", "gate"} if mapless else {"map", "runner", "gate"})
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
    mapless = recovery.read_mode(root) == "mapless"
    path = root / (".active-images.mapless.json" if mapless else ".active-images.json")
    if mapless:
        recovery.compose_files(root)  # Retain only the already validated scoped selection.
    previous = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    selection = {key: previous[key] for key in ("name", "networks") if key in previous}
    selection["services"] = {s: {"image": i} for s, i in images.items()}
    save(
        path,
        selection,
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


def verify_mapless(root, project, snapshot):
    if snapshot is None or snapshot.get("mode") != "mapless":
        raise ValueError("Mapless verification requires the original verified state snapshot")
    expected = snapshot["volumes"]["runner-state"]
    original_image = snapshot["images"]["runner"]

    def unchanged():
        no_runner(project)
        info = recovery.container(root, "runner", project)
        volume = recovery.volume_name(info, recovery.VOLUMES["runner-state"][1])
        if recovery.volume_fingerprint(original_image, volume) != expected:
            raise ValueError("Mapless Runner state changed; storage migrations require a separate reviewed procedure")
        return volume

    unchanged()
    recovery.compose(root, "--profile", "tools", "create", "--no-build", "--pull", "never",
                     "runner", project=project)
    volume = unchanged()
    image = image_set(root)[1]["runner"]
    # SQLite readers can change WAL/SHM bytes. Inspect an offline disposable copy,
    # never the preserved original or canonical rehearsal volume. Reuse Runner's
    # noncreating current-schema gate before ordinary diagnostics on that copy.
    code = """
import os, shutil
from vardrrunner import config, identity
from vardrrunner.journal import Journal, journal_path_identity
target = config.CONFIG_DIR
if target.exists() and any(target.iterdir()):
    raise ValueError('Diagnostic image state must be empty')
shutil.copytree('/source', target, dirs_exist_ok=True)
if not identity.identity_file().is_file():
    raise ValueError('Initialize local Runner diagnostics before updating')
Journal.open_existing(config.journal_file(), expected_identity=journal_path_identity(config.journal_file())).list(limit=1)
os.execvp('vardrrunner', ['vardrrunner', 'doctor', '--standalone', '--offline', '--json'])
"""
    result = recovery.command(
        "docker", "run", "--rm", "--network", "none", "--user", "10001:10001",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--pull", "never",
        "--mount", f"type=volume,source={volume},target=/source,readonly",
        "--entrypoint", "python", image, "-c", code,
        capture_output=True, text=True, check=False, timeout=WAIT_SECONDS,
    )
    if result.returncode or json.loads(result.stdout).get("healthy") is not True:
        raise ValueError("Offline Runner diagnostics failed during Mapless update verification")
    unchanged()
    image_set(root)  # The stopped canonical container must use the selected immutable image.


def verify_private(root, project, *, snapshot=None):
    if recovery.read_mode(root) == "mapless":
        return verify_mapless(root, project, snapshot)
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
    if recovery.read_mode(root) == "mapless":
        no_runner(project)
        info = recovery.container(root, "runner", project)
        if info["Image"] != metadata["images"]["runner"]:
            raise ValueError("Mapless source image changed after backup")
        volume = recovery.volume_name(info, recovery.VOLUMES["runner-state"][1])
        if recovery.volume_fingerprint(metadata["images"]["runner"], volume) != metadata["volumes"]["runner-state"]:
            raise ValueError("Mapless source state changed after backup")
        for name in recovery.snapshot_files(metadata["schema_version"]):
            if recovery.digest(root / name) != metadata["files"][name]:
                raise ValueError("Installation files changed after backup")
        return
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
    for name in recovery.snapshot_files(metadata.get("schema_version")):
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
        mapless = recovery.read_mode(root) == "mapless"
        if not mapless and not os.environ.get("VARDRMAP_API_KEY"):
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
        candidate = (candidate_set(candidate, baseline, None, mode="mapless") if mapless else
                     candidate_set(candidate, baseline, config["services"]["web"]["environment"]["AUTH_URL"]))
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
        if mapless:
            record["mode"] = "mapless"
            record["baseline_selection_sha256"] = recovery.digest(root / ".active-images.mapless.json")
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
            verify_private(destination, rehearsal_project, **({"snapshot": metadata} if mapless else {}))
            recovery.compose(
                destination, "--profile", "tools", "stop", project=rehearsal_project
            )
            assert_quiesced(root, metadata, project)
            if mapless and recovery.digest(root / ".active-images.mapless.json") != record["baseline_selection_sha256"]:
                raise ValueError("Mapless image or network selection changed after backup")
            record["phase"] = "applying"
            save(root / STATE, record)
            set_images(root, candidate["images"])
            verify_private(root, project, **({"snapshot": metadata} if mapless else {}))
            if mapless:
                record.update(phase="complete", status="success", finished_at=datetime.now(timezone.utc).isoformat())
                save(root / ".last-update.json", record)
                (root / STATE).unlink()
                print("Mapless update verified; Runner remains stopped. Backup and stopped rehearsal retained.")
                return
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
                if (directory / ("compose.mapless.json" if mapless else "compose.yaml")).exists():
                    try:
                        recovery.compose(
                            directory,
                            "stop",
                            *(["runner"] if mapless else ["proxy", "web", "api"]),
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
        mapless = recovery.read_mode(root) == "mapless"
        if record.get("mode", "full") != ("mapless" if mapless else "full"):
            raise ValueError("Pending update mode differs from this installation")
        no_runner(record["project"])
        if mapless and recovery.digest(root / ".active-images.mapless.json") != record["baseline_selection_sha256"]:
            raise ValueError("Mapless selection changed; preserve state and restore the recorded backup")
        backup = Path(record["backup"])
        if record["phase"] == "rehearsal":
            metadata = recovery.validate(backup)
            if recovery.digest(backup / "snapshot.json") != record["snapshot_sha256"]:
                raise ValueError("Recorded backup changed")
            assert_quiesced(root, metadata, record["project"])
        set_images(root, record["baseline_images"])
        if mapless:
            recovery.compose(root, "--profile", "tools", "create", "--no-build", "--pull", "never",
                             "runner", project=record["project"])
            record.update(status="cancelled", finished_at=datetime.now(timezone.utc).isoformat())
            save(root / ".last-update.json", record)
            (root / STATE).unlink()
            print("Mapless update cancelled before original mutation; baseline Runner remains stopped.")
            return
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
