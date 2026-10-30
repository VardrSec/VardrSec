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
            "install",
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
            "runner",
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
    args, extra = parser.parse_known_args()
    if args.action == "runner":
        # Everything after `--` belongs to Runner, so none of its options can be
        # taken as one of ours (for example `--destination`).
        if "--" not in sys.argv[2:]:
            parser.error(
                "separate Runner's arguments with --, for example: "
                "python3 vardrsec.py runner -- jobs run"
            )
        args.runner_args = extra
    elif extra:
        parser.error("unrecognized arguments: " + " ".join(extra))
    if args.generate_password and args.action != "bootstrap":
        parser.error("--generate-password is only valid with bootstrap")
    if args.action in ("update", "cancel-update"):
        return dispatch(args, parser)
    import updater

    with updater.operation_guard(ROOT, args.action):
        return dispatch(args, parser)


INSTALL_STEPS = ("configure", "sources", "build", "start", "export-ca")


_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def runner_invocation(arguments):
    """Split `[--env NAME]... [--] COMMAND...` into Compose `-e` flags and Runner's argv.

    `--env NAME` passes one variable from the caller's environment, such as an
    identity token a reviewed case references. Only the name reaches the command
    line; Compose reads the value from this process's environment.
    """
    flags, rest = [], list(arguments)
    while rest and (rest[0] == "--env" or rest[0].startswith("--env=")):
        item = rest.pop(0)
        if item == "--env":
            if not rest:
                raise ValueError("--env needs a variable name")
            name = rest.pop(0)
        else:
            name = item.split("=", 1)[1]
        if not _ENV_NAME.fullmatch(name):
            raise ValueError(f"--env takes an environment variable name, not {name!r}")
        flags += ["-e", name]
    if rest and rest[0] == "--":
        rest.pop(0)
    return flags, rest


def has_installation_data():
    """True once the database volume exists, i.e. the platform was started before."""
    project = os.environ.get("COMPOSE_PROJECT_NAME") or "vardrsec"
    result = subprocess.run(
        ["docker", "volume", "inspect", f"{project}_database"],
        capture_output=True,
        check=False,
    )
    return result.returncode == 0

INSTALL_NEXT = """
Installed. Remaining manual steps (they change your machine, so they are never automatic):
  1. Trust the public CA after checking the fingerprint above:
       sudo install -m 0644 trust/root.crt /usr/local/share/ca-certificates/vardrsec-local.crt
       sudo update-ca-certificates
     Firefox keeps its own store; see docs/installation.md. Restart the browser.
  2. Create the first account:  python3 vardrsec.py bootstrap --username operator
  3. Open https://localhost:8443 and follow the first-assessment walkthrough in docs/installation.md.
No scans were started."""


def dispatch(args, parser):
    if args.action == "install":
        # One command for a brand-new checkout. It only chains the existing steps, in
        # order, and refuses to run over an existing installation's credentials.
        # Safe to rerun after an interruption: an existing .env is kept (never
        # regenerated), source checkouts are resumed and never reset, and image builds
        # reuse their cache. Once the database volume exists the platform has held
        # data, so install refuses and start/update must be used instead.
        if has_installation_data():
            parser.error(
                "This installation has been started before and may hold data. Use start, "
                "stop or the controlled updater; install is only for a new or interrupted install."
            )
        steps = list(INSTALL_STEPS)
        if (ROOT / ".env").exists():
            print("Resuming: the existing .env is kept and its secrets are not regenerated.")
            steps.remove("configure")
        for step in steps:
            print(f"== {step}", flush=True)
            try:
                dispatch(argparse.Namespace(**{**vars(args), "action": step}), parser)
            except Exception as error:
                print(
                    f"\nInstall stopped at '{step}': {error}\n"
                    "Nothing was deleted and your credentials are untouched. Fix the cause "
                    "(network, disk space, Docker) and run `python3 vardrsec.py install` again "
                    "to resume. If it stopped after the services started, run "
                    "`python3 vardrsec.py export-ca` instead.",
                    file=sys.stderr,
                )
                raise
        print(INSTALL_NEXT)
    elif args.action == "configure":
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
    elif args.action == "runner":
        # The installed image set (.active-images.json after an update or restore)
        # is selected by compose(), unlike a plain `docker compose run`.
        flags, command = runner_invocation(args.runner_args)
        compose("run", "--rm", "--no-deps", *flags, "runner", *command)
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
