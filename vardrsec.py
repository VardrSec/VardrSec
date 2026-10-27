"""Development distribution lifecycle. Diagnostics remain in VardrRunner."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def run(*args, **kwargs):
    if kwargs.get("text"):
        kwargs.setdefault("encoding", "utf-8")
    try:
        return subprocess.run(args, cwd=ROOT, check=kwargs.pop("check", True), **kwargs)
    except FileNotFoundError:
        raise ValueError(
            f"Required command {args[0]!r} is unavailable. Install it and follow docs/installation.md."
        ) from None


def require_command(name):
    if not shutil.which(name):
        raise ValueError(
            f"Required command {name!r} is unavailable. Install it and follow docs/installation.md."
        )


def build_prerequisites():
    require_command("docker")
    try:
        version = run(
            "docker", "compose", "version", "--short", capture_output=True, text=True
        ).stdout.strip()
    except subprocess.CalledProcessError:
        raise ValueError(
            "Docker Compose is unavailable. Install the Compose plugin; see docs/installation.md."
        ) from None
    match = re.match(r"v?(\d+)\.(\d+)", version)
    if not match or tuple(map(int, match.groups())) < (2, 17):
        raise ValueError(
            "Compose 2.17+ is required for named build contexts. Update Compose and retry build."
        )
    try:
        system = run(
            "docker", "info", "--format", "{{.OSType}}", capture_output=True, text=True
        ).stdout.strip()
    except subprocess.CalledProcessError:
        raise ValueError(
            "Cannot access Docker. Check that Engine/Desktop is running and your account has daemon access; see docs/installation.md."
        ) from None
    if system != "linux":
        raise ValueError(
            "VardrSec requires Linux containers. Select Linux containers in Docker Desktop before building."
        )


def compose(*args, **kwargs):
    flags = ["-f", str(ROOT / "compose.yaml")]
    if (ROOT / ".active-images.json").exists():
        flags += ["-f", str(ROOT / ".active-images.json")]
    return run("docker", "compose", *flags, *args, **kwargs)


def configure():
    path = ROOT / ".env"
    # Exclusive creation preserves existing database credentials and signing keys.
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise FileExistsError(
            "Existing .env preserved. Skip configure for an existing installation; do not reset credentials to repair startup. See docs/installation.md."
        ) from None
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        output.write("HTTPS_PORT=8443\n")
        for name in ("POSTGRES_PASSWORD", "BACKEND_JWT_SECRET", "AUTH_SECRET"):
            output.write(f"{name}={secrets.token_hex(32)}\n")
    (ROOT / "trust").mkdir(exist_ok=True)
    print("Created .env without displaying secrets. Keep it private and back it up.")


def sources():
    require_command("git")
    manifest = json.loads((ROOT / "versions.json").read_text(encoding="utf-8"))
    for name in ("map", "runner", "gate"):
        item = manifest["components"][name]
        repo, revision = item["repository"], item["commit"]
        if (
            repo
            != {
                "map": "VardrSec/VardrMap",
                "runner": "VardrSec/VardrRunner",
                "gate": "VardrSec/VardrGate",
            }[name]
        ):
            raise ValueError("Unexpected component repository")
        if not re.fullmatch("[0-9a-f]{40}", revision):
            raise ValueError("A full source commit is required")
        path = ROOT / ".sources" / name
        if path.exists() and not path.is_dir():
            raise ValueError(
                f"{name} source path is not a directory; preserve it and use a fresh source directory"
            )
        if (path / ".git").exists():
            head = run(
                "git",
                "-C",
                str(path),
                "rev-parse",
                "HEAD",
                capture_output=True,
                text=True,
                check=False,
            )
            dirty = run(
                "git",
                "-C",
                str(path),
                "status",
                "--porcelain",
                capture_output=True,
                text=True,
            ).stdout.strip()
            if dirty or (head.returncode == 0 and head.stdout.strip() != revision):
                raise ValueError(
                    f"{name} source differs from the pin; preserve it and use a fresh source directory"
                )
            if head.returncode == 0:
                continue
            # Retry an interrupted initial fetch only when no user files exist.
            if (
                not (path / ".git").is_dir()
                or (path / ".git").is_symlink()
                or any(item.name != ".git" for item in path.iterdir())
            ):
                raise ValueError(
                    f"{name} has no checked-out revision but contains files; preserve it and use a fresh source directory"
                )
        else:
            if path.exists() and any(path.iterdir()):
                raise ValueError(
                    f"{name} source directory is not empty; preserve it and use a fresh source directory"
                )
            path.mkdir(parents=True, exist_ok=True)
            run("git", "-C", str(path), "init")
        run(
            "git",
            "-C",
            str(path),
            "fetch",
            "--depth=1",
            f"https://github.com/{repo}.git",
            revision,
        )
        run("git", "-C", str(path), "checkout", "--detach", "FETCH_HEAD")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "configure",
            "sources",
            "build",
            "start",
            "stop",
            "export-ca",
            "bootstrap",
            "doctor",
            "backup",
            "restore",
            "update",
            "cancel-update",
            "seal-backup",
            "unseal-backup",
        ),
    )
    parser.add_argument("--username", default="operator")
    parser.add_argument(
        "--generate-password",
        action="store_true",
        help="Bootstrap with a securely generated password, shown once",
    )
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--backup", type=Path)
    parser.add_argument("--project")
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--recipient")
    parser.add_argument("--identity", type=Path)
    args = parser.parse_args()
    if args.generate_password and args.action != "bootstrap":
        parser.error("--generate-password is only valid with bootstrap")
    if args.action in ("update", "cancel-update"):
        return dispatch(args, parser)
    import updater

    with updater.operation_guard(ROOT, args.action):
        return dispatch(args, parser)


def dispatch(args, parser):
    if args.action == "configure":
        configure()
    elif args.action == "sources":
        sources()
    elif args.action == "build":
        build_prerequisites()
        compose("--profile", "tools", "build")
    elif args.action == "start":
        compose(
            "up", "-d", "--wait", "--wait-timeout", "180", "db", "api", "web", "proxy"
        )
        print(
            "Services started. Export/enroll the CA before signing in. No scans were started."
        )
    elif args.action == "stop":
        compose("stop")
        print("Services stopped; volumes retained.")
    elif args.action == "export-ca":
        (ROOT / "trust").mkdir(exist_ok=True)
        compose(
            "cp", "proxy:/data/caddy/pki/authorities/local/root.crt", "trust/root.crt"
        )
        # Caddy's public certificate is root-only inside its storage. Runner's
        # different UID must be able to read this public Linux bind-mount export.
        (ROOT / "trust" / "root.crt").chmod(0o644)
        der = ssl.PEM_cert_to_DER_cert(
            (ROOT / "trust/root.crt").read_text(encoding="utf-8")
        )
        fingerprint = hashlib.sha256(der).hexdigest().upper()
        print(
            "Public CA SHA256 fingerprint: "
            + ":".join(fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2))
        )
        print(
            "Exported only the public root certificate. Follow docs/installation.md to enroll trust explicitly."
        )
    elif args.action == "bootstrap":
        generated = args.generate_password
        compose(
            "exec",
            *(["-T"] if generated else []),
            "api",
            "python",
            "-m",
            "local_accounts",
            "init",
            "--username",
            args.username,
            *(["--generate-password"] if generated else []),
        )
    elif args.action == "doctor":
        compose(
            "run",
            "--rm",
            "--no-deps",
            "runner",
            "doctor",
            "--platform",
            "--offline",
            "--json",
        )
        print(
            "Runner diagnostics completed successfully. Sign in at the installation URL shown in docs/installation.md.",
            file=sys.stderr,
        )
    elif args.action in ("backup", "restore"):
        import recovery

        if args.destination is None:
            parser.error("--destination is required")
        if args.action == "backup":
            if args.recipient:
                import backup_crypto

                backup_crypto.encrypted_backup(ROOT, args.destination, args.recipient)
            else:
                recovery.backup(ROOT, args.destination)
        else:
            if args.backup is None or not args.project:
                parser.error(
                    "restore requires --backup and a new --project vardrsec-restore-NAME"
                )
            recovery.restore(ROOT, args.backup, args.destination, args.project)
    elif args.action in ("update", "cancel-update"):
        import updater

        if args.action == "cancel-update":
            updater.cancel(ROOT)
        else:
            if not all((args.candidate, args.backup, args.destination, args.project)):
                parser.error(
                    "update requires --candidate, --backup, --destination and --project"
                )
            updater.update(
                ROOT, args.candidate, args.backup, args.destination, args.project
            )
    elif args.action in ("seal-backup", "unseal-backup"):
        import backup_crypto

        if args.backup is None or args.destination is None:
            parser.error("--backup and --destination are required")
        if args.action == "seal-backup":
            if args.recipient is None:
                parser.error("seal-backup requires --recipient")
            backup_crypto.seal(args.backup, args.destination, args.recipient)
        else:
            if args.identity is None:
                parser.error("unseal-backup requires --identity")
            backup_crypto.unseal(args.backup, args.destination, args.identity)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, FileExistsError) as exc:
        raise SystemExit(str(exc)) from None
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.returncode) from None
