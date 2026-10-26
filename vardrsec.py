"""Development distribution lifecycle. Diagnostics remain in VardrRunner."""

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess

ROOT = Path(__file__).resolve().parent


def run(*args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def compose(*args, **kwargs):
    return run("docker", "compose", *args, **kwargs)


def configure():
    path = ROOT / ".env"
    # Exclusive creation preserves existing database credentials and signing keys.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        output.write("HTTPS_PORT=8443\n")
        for name in ("POSTGRES_PASSWORD", "BACKEND_JWT_SECRET", "AUTH_SECRET"):
            output.write(f"{name}={secrets.token_hex(32)}\n")
    (ROOT / "trust").mkdir(exist_ok=True)
    print("Created .env without displaying secrets. Keep it private and back it up.")


def sources():
    manifest = json.loads((ROOT / "versions.json").read_text())
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
        if path.exists():
            actual = run(
                "git",
                "-C",
                str(path),
                "rev-parse",
                "HEAD",
                capture_output=True,
                text=True,
            ).stdout.strip()
            dirty = run(
                "git",
                "-C",
                str(path),
                "status",
                "--porcelain",
                capture_output=True,
                text=True,
            ).stdout.strip()
            if actual != revision or dirty:
                raise ValueError(
                    f"{name} source differs from the pin; preserve it and use a fresh source directory"
                )
            continue
        path.mkdir(parents=True)
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
        ),
    )
    parser.add_argument("--username", default="operator")
    args = parser.parse_args()
    if args.action == "configure":
        configure()
    elif args.action == "sources":
        sources()
    elif args.action == "build":
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
        print(
            "Exported only the public root certificate. Follow docs/installation.md to enroll trust explicitly."
        )
    elif args.action == "bootstrap":
        compose(
            "exec",
            "api",
            "python",
            "-m",
            "local_accounts",
            "init",
            "--username",
            args.username,
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


if __name__ == "__main__":
    try:
        main()
    except (ValueError, FileExistsError) as exc:
        raise SystemExit(str(exc)) from None
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.returncode) from None
