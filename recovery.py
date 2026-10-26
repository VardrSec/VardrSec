"""Quiesced, portable snapshots and restore into an empty Compose installation."""

import gzip
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import shutil
import subprocess
import tarfile
from datetime import datetime, timezone

FILES = (
    ".env",
    "compose.yaml",
    "Caddyfile",
    "versions.json",
    "vardrsec.py",
    "recovery.py",
)
VOLUMES = {
    "runner-state": ("runner", "/home/runner/.vardrmap"),
    "proxy-data": ("proxy", "/data"),
    "proxy-config": ("proxy", "/config"),
}
SERVICES = {"db", "api", "web", "proxy", "runner"}
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
PERSISTED_ENV = {
    "db": ("POSTGRES_PASSWORD",),
    "api": ("DATABASE_URL", "BACKEND_JWT_SECRET", "ALLOWED_ORIGINS"),
    "web": ("AUTH_SECRET", "BACKEND_JWT_SECRET", "AUTH_URL"),
    "proxy": ("HTTPS_PORT",),
}


def command(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def compose(root, *args, project=None, **kwargs):
    flags = ["-f", str(root / "compose.yaml")]
    active = root / ".active-images.json"
    if active.exists():
        flags += ["-f", str(active)]
    if project:
        flags += ["-p", project]
    return command("docker", "compose", *flags, *args, cwd=root, **kwargs)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def private_write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)


def json_write(path, data):
    private_write(path, (json.dumps(data, indent=2, sort_keys=True) + "\n").encode())


def inspect(container):
    return json.loads(
        command("docker", "inspect", container, capture_output=True, text=True).stdout
    )[0]


def container(root, service, project=None):
    ids = compose(
        root, "ps", "-a", "-q", service, project=project, capture_output=True, text=True
    ).stdout.split()
    if len(ids) != 1:
        raise ValueError(f"Expected exactly one {service} container")
    return inspect(ids[0])


def volume_name(info, destination):
    return next(
        m["Name"]
        for m in info["Mounts"]
        if m["Type"] == "volume" and m["Destination"] == destination
    )


def sql(root, statement, project=None):
    return compose(
        root,
        "exec",
        "-T",
        "db",
        "psql",
        "-X",
        "-v",
        "ON_ERROR_STOP=1",
        "-U",
        "vardrmap",
        "-d",
        "vardrmap",
        "-At",
        "-c",
        statement,
        project=project,
        capture_output=True,
        text=True,
    ).stdout.strip()


def database_fingerprint(root, project=None):
    # Hash sorted row digests inside PostgreSQL: no row values reach backup logs.
    tables = sql(
        root,
        "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename",
        project,
    ).splitlines()
    result = {}
    for table in tables:
        quoted = '"' + table.replace('"', '""') + '"'
        rows = sql(
            root,
            f"SET timezone='UTC'; SELECT encode(sha256(convert_to(row_to_json(t)::text,'UTF8')),'hex') FROM public.{quoted} t ORDER BY 1",
            project,
        )
        result[table] = hashlib.sha256(rows.encode()).hexdigest()
    result["_sequences"] = hashlib.sha256(
        sql(
            root,
            "SELECT sequencename,last_value FROM pg_sequences WHERE schemaname='public' ORDER BY sequencename",
            project,
        ).encode()
    ).hexdigest()
    return result


def safe_archive(path):
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            if (
                name.is_absolute()
                or ".." in name.parts
                or not (member.isfile() or member.isdir())
            ):
                raise ValueError(
                    "State archive contains a link, special file or unsafe path"
                )


def volume_stream(image, volume, action, stream):
    # Helpers are explicit offline maintenance commands, never Runner workers.
    mode = "readonly" if action == "backup" else "volume-nocopy"
    code = (
        "import tarfile,sys; "
        "t=tarfile.open(fileobj=sys.stdout.buffer,mode='w|gz'); t.add('/state',arcname='.'); t.close()"
        if action == "backup"
        else "import tarfile,sys; t=tarfile.open(fileobj=sys.stdin.buffer,mode='r|gz'); t.extractall('/state',filter='fully_trusted')"
    )
    options = {"stdout": stream} if action == "backup" else {"stdin": stream}
    command(
        "docker",
        "run",
        "--rm",
        "-i",
        "--network",
        "none",
        "--user",
        "0",
        "--mount",
        f"type=volume,source={volume},target=/state,{mode}",
        "--entrypoint",
        "python",
        image,
        "-c",
        code,
        **options,
    )


def volume_fingerprint(image, volume):
    code = """
import hashlib, json, os
from pathlib import Path
root = Path('/state')
digest = hashlib.sha256()
for path in [root, *sorted(root.rglob('*'))]:
    if path.is_symlink() or not (path.is_file() or path.is_dir()):
        raise ValueError('Unsupported state entry')
    st = path.stat()
    content = ''
    if path.is_file():
        with path.open('rb') as source:
            content = hashlib.file_digest(source, 'sha256').hexdigest()
    row = [str(path.relative_to(root)), st.st_uid, st.st_gid, st.st_mode, content]
    digest.update((json.dumps(row, separators=(',', ':')) + '\\n').encode())
print(digest.hexdigest())
"""
    return command(
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--user",
        "0",
        "--mount",
        f"type=volume,source={volume},target=/state,readonly",
        "--entrypoint",
        "python",
        image,
        "-c",
        code,
        capture_output=True,
        text=True,
    ).stdout.strip()


def backup(root, destination):
    destination = destination.resolve()
    if destination.exists():
        raise ValueError("Backup destination must not exist")
    configuration = json.loads(
        compose(
            root, "config", "--format", "json", capture_output=True, text=True
        ).stdout
    )
    # A copied .env must reproduce the running secrets and public address. Refuse
    # stale files or shell-only overrides rather than silently creating a broken
    # portable snapshot. Never put the compared values into an exception.
    file_env = {
        k: v
        for k, v in os.environ.items()
        if k
        not in {"POSTGRES_PASSWORD", "BACKEND_JWT_SECRET", "AUTH_SECRET", "HTTPS_PORT"}
    }
    from_file = json.loads(
        compose(
            root,
            "config",
            "--format",
            "json",
            env=file_env,
            capture_output=True,
            text=True,
        ).stdout
    )
    for service, names in PERSISTED_ENV.items():
        runtime = dict(
            v.split("=", 1)
            for v in container(root, service)["Config"]["Env"]
            if "=" in v
        )
        for name in names:
            expected = configuration["services"][service]["environment"][name]
            if expected != from_file["services"][service]["environment"][
                name
            ] or expected != runtime.get(name):
                raise ValueError(
                    f"Persist the matching {service} {name} configuration before backup"
                )
    project = configuration["name"]
    running_runners = command(
        "docker",
        "ps",
        "-q",
        "--filter",
        f"label=com.docker.compose.project={project}",
        "--filter",
        "label=com.docker.compose.service=runner",
        capture_output=True,
        text=True,
    ).stdout.strip()
    if running_runners:
        raise ValueError("Finish or stop the explicitly invoked Runner before backup")
    # Do not restart applications automatically after the snapshot.
    compose(root, "stop", "proxy", "web", "api")
    compose(root, "up", "-d", "--no-build", "--wait", "db")
    compose(root, "create", "--no-build", "runner")
    infos = {name: container(root, name) for name in SERVICES}
    images = {name: info["Image"] for name, info in infos.items()}
    destination.mkdir(parents=True, mode=0o700)
    for name in FILES:
        private_write(destination / name, (root / name).read_bytes())
    for name, (service, mount) in VOLUMES.items():
        path = destination / f"{name}.tar.gz"
        with path.open("xb") as output:
            volume_stream(
                images["runner"], volume_name(infos[service], mount), "backup", output
            )
        path.chmod(0o600)
        safe_archive(path)
    fingerprints = {
        name: volume_fingerprint(images["runner"], volume_name(infos[service], mount))
        for name, (service, mount) in VOLUMES.items()
    }
    fingerprint = database_fingerprint(root)
    with (destination / "database.dump").open("xb") as output:
        compose(
            root,
            "exec",
            "-T",
            "db",
            "pg_dump",
            "-Fc",
            "--no-owner",
            "--no-acl",
            "-U",
            "vardrmap",
            "-d",
            "vardrmap",
            stdout=output,
        )
    # Carry exact images as well as IDs; recovery must not resolve mutable tags.
    with gzip.open(destination / "images.tar.gz", "wb", compresslevel=1) as output:
        with subprocess.Popen(
            ["docker", "image", "save", *sorted(set(images.values()))],
            stdout=subprocess.PIPE,
        ) as process:
            shutil.copyfileobj(process.stdout, output)
            if process.wait() != 0:
                raise ValueError("Could not export recovery images")
    for file in destination.iterdir():
        file.chmod(0o600)
    metadata = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "project": project,
        "images": images,
        "database": fingerprint,
        "volumes": fingerprints,
        "files": {p.name: digest(p) for p in destination.iterdir()},
    }
    json_write(destination / "snapshot.json", metadata)
    print(
        "Backup completed. Applications remain stopped. Treat the entire unencrypted bundle as private key material."
    )


def validate(backup_path):
    metadata = json.loads((backup_path / "snapshot.json").read_text(encoding="utf-8"))
    required = (
        set(FILES)
        | {"database.dump", "images.tar.gz"}
        | {f"{name}.tar.gz" for name in VOLUMES}
    )
    if (
        metadata.get("schema_version") != 1
        or set(metadata.get("files", {})) != required
    ):
        raise ValueError("Unsupported or incomplete snapshot")
    if set(metadata.get("images", {})) != SERVICES or not all(
        IMAGE_ID.fullmatch(i) for i in metadata["images"].values()
    ):
        raise ValueError("Snapshot must pin every service to a local image ID")
    if set(metadata.get("volumes", {})) != set(VOLUMES):
        raise ValueError("Snapshot lacks state volume fingerprints")
    for name in required:
        path = backup_path / name
        if path.is_symlink() or digest(path) != metadata["files"][name]:
            raise ValueError(f"Snapshot integrity check failed: {name}")
    for name in VOLUMES:
        safe_archive(backup_path / f"{name}.tar.gz")
    return metadata


def restore(root, backup_path, destination, project):
    backup_path, destination = backup_path.resolve(), destination.resolve()
    metadata = validate(backup_path)
    if not re.fullmatch(r"vardrsec-restore-[a-z0-9][a-z0-9-]{0,40}", project):
        raise ValueError("Use a separate vardrsec-restore-NAME project")
    if destination.exists():
        raise ValueError("Restore destination must not exist")
    for resource in ("container", "volume", "network"):
        args = [
            "docker",
            resource,
            "ls",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={project}",
        ]
        if resource == "container":
            args.insert(3, "-a")
        if command(*args, capture_output=True, text=True).stdout.strip():
            raise ValueError(
                "Restore project already has resources; refusing to overwrite"
            )
    destination.mkdir(parents=True, mode=0o700)
    for name in FILES:
        private_write(destination / name, (backup_path / name).read_bytes())
    # This public routing file is bind-mounted into a capability-restricted
    # container with a different UID. Secrets stay in .env and state volumes.
    (destination / "Caddyfile").chmod(0o644)
    json_write(
        destination / ".active-images.json",
        {
            "services": {
                name: {"image": image} for name, image in metadata["images"].items()
            }
        },
    )
    # An explicit different network permits retention of the stopped source stack.
    networks = command(
        "docker", "network", "ls", "-q", capture_output=True, text=True
    ).stdout.split()
    import ipaddress

    occupied = []
    if networks:
        for network in json.loads(
            command(
                "docker",
                "network",
                "inspect",
                *networks,
                capture_output=True,
                text=True,
            ).stdout
        ):
            occupied.extend(
                ipaddress.ip_network(c["Subnet"])
                for c in network["IPAM"].get("Config") or []
                if c.get("Subnet")
            )
    subnet = next(
        (
            ipaddress.ip_network(f"172.30.{i}.0/24")
            for i in range(100, 240)
            if not any(
                ipaddress.ip_network(f"172.30.{i}.0/24").overlaps(n)
                for n in occupied
                if n.version == 4
            )
        ),
        None,
    )
    if subnet is None:
        raise ValueError("No unused restore bridge subnet available")
    prefix = str(subnet.network_address).rsplit(".", 1)[0]
    with (destination / ".env").open("a", encoding="utf-8") as output:
        output.write(
            f"\nCOMPOSE_PROJECT_NAME={project}\nAPPLICATION_SUBNET={subnet}\nAPPLICATION_IP_RANGE={prefix}.128/25\nPROXY_IP={prefix}.2\n"
        )
    # Load before creating services; no pull/build or current development tag is used.
    with gzip.open(backup_path / "images.tar.gz", "rb") as source:
        with subprocess.Popen(
            ["docker", "image", "load", "--quiet"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
        ) as process:
            shutil.copyfileobj(source, process.stdin)
            process.stdin.close()
            if process.wait() != 0:
                raise ValueError("Could not load recovery images")
    for image in metadata["images"].values():
        command("docker", "image", "inspect", image, stdout=subprocess.DEVNULL)
    (destination / "trust").mkdir()
    compose(destination, "--profile", "tools", "create", "--no-build", project=project)
    for name, (service, mount) in VOLUMES.items():
        volume = volume_name(container(destination, service, project), mount)
        with (backup_path / f"{name}.tar.gz").open("rb") as source:
            volume_stream(metadata["images"]["runner"], volume, "restore", source)
        if (
            volume_fingerprint(metadata["images"]["runner"], volume)
            != metadata["volumes"][name]
        ):
            raise ValueError(f"Restored {name} contents or ownership differ")
    compose(destination, "up", "-d", "--no-build", "--wait", "db", project=project)
    with (backup_path / "database.dump").open("rb") as source:
        compose(
            destination,
            "exec",
            "-T",
            "db",
            "pg_restore",
            "--exit-on-error",
            "--no-owner",
            "--no-acl",
            "-U",
            "vardrmap",
            "-d",
            "vardrmap",
            project=project,
            stdin=source,
        )
    if database_fingerprint(destination, project) != metadata["database"]:
        raise ValueError(
            "Restored database fingerprint differs; applications remain stopped"
        )
    json_write(
        destination / "restore-receipt.json",
        {
            "snapshot_sha256": digest(backup_path / "snapshot.json"),
            "project": project,
            "database_verified": True,
        },
    )
    print(
        "Restore verified in a separate installation. Applications remain stopped; review recovered credentials before explicit startup."
    )
