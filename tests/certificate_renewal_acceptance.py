"""Accelerated leaf renewal in an owned, disposable proxy-only Compose project."""

import hashlib
from pathlib import Path
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/renewal/compose.yaml"
CA = "/data/caddy/pki/authorities/local"
BROWSER = "vardrsec-renewal-browser:acceptance"


def run(*args, **kwargs):
    return subprocess.run(args, check=kwargs.pop("check", True), **kwargs)


def main():
    # Unique project/volumes; never operate on the platform's project or trust stores.
    project = "vardrsec-certificate-review-" + uuid.uuid4().hex[:12]

    def compose(*args, **kwargs):
        return run(
            "docker",
            "compose",
            "-f",
            str(FIXTURE),
            "-p",
            project,
            *args,
            cwd=ROOT,
            **kwargs,
        )

    def authority_state():
        return compose(
            "exec",
            "-T",
            "proxy",
            "sha256sum",
            CA + "/root.crt",
            CA + "/intermediate.crt",
            capture_output=True,
        ).stdout

    def private_key_permissions():
        modes = compose(
            "exec",
            "-T",
            "proxy",
            "stat",
            "-c",
            "%a",
            CA + "/root.key",
            CA + "/intermediate.key",
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        assert len(modes) == 2 and all(int(mode, 8) & 0o077 == 0 for mode in modes), (
            "CA private keys must have no group/other permissions"
        )

    (ROOT / "artifacts").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="renewal-", dir=ROOT / "artifacts"
    ) as folder:
        public = Path(folder)
        try:
            run("docker", "build", "-t", BROWSER, str(ROOT / "tests/browser"))
            compose("up", "--build", "-d", "--wait", "--wait-timeout", "60")
            container = compose(
                "ps", "-q", "proxy", capture_output=True, text=True
            ).stdout.strip()
            assert container, "Disposable proxy container is missing"
            compose(
                "cp",
                "proxy:" + CA + "/root.crt",
                str(public / "root.crt"),
                capture_output=True,
            )
            (public / "root.crt").chmod(0o644)
            original_public = hashlib.sha256(
                (public / "root.crt").read_bytes()
            ).digest()
            original_authority = authority_state()
            private_key_permissions()

            def browser(mode):
                name = project + "-browser-" + mode
                try:
                    run(
                        "docker",
                        "run",
                        "--rm",
                        "--name",
                        name,
                        "--network",
                        "container:" + container,
                        "--mount",
                        f"type=bind,source={public},target=/trust,readonly",
                        BROWSER,
                        "node",
                        "renewal.cjs",
                        mode,
                        timeout=240,
                    )
                finally:
                    # Killing the Docker CLI on timeout does not stop its container.
                    run("docker", "rm", "-f", name, check=False, capture_output=True)

            print(
                "Observing automatic renewal through original leaf expiry", flush=True
            )
            browser("renew")
            assert authority_state() == original_authority, "Renewal changed the CA"
            private_key_permissions()
            compose("stop")
            compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "60")
            assert authority_state() == original_authority, "Restart changed the CA"
            assert (
                hashlib.sha256((public / "root.crt").read_bytes()).digest()
                == original_public
            )
            private_key_permissions()
            browser("restart")
            print(
                "PASS: leaf renewal and restart preserve root/intermediate CA and private-key permissions"
            )
        finally:
            compose("down", "--volumes", "--remove-orphans")


if __name__ == "__main__":
    main()
