"""Actual native CA enrollment/removal, restricted to disposable hosted runners."""

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import zipfile

HERE = Path(__file__).resolve().parent


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def tool(root):
    pins = json.loads((HERE / "assets.json").read_text(encoding="utf-8"))
    architecture = (
        "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "amd64"
    )
    asset = pins["platforms"][platform.system() + "-" + architecture]
    archive = root / asset["name"]
    url = f"https://github.com/caddyserver/caddy/releases/download/v{pins['version']}/{asset['name']}"
    with (
        urllib.request.urlopen(url, timeout=60) as source,
        archive.open("xb") as output,
    ):
        shutil.copyfileobj(source, output)
    with archive.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != asset["sha256"]:
            raise ValueError("Official Caddy archive digest mismatch")
    name = "caddy.exe" if os.name == "nt" else "caddy"
    executable = root / name
    if archive.suffix == ".zip":
        with (
            zipfile.ZipFile(archive) as package,
            package.open(name) as source,
            executable.open("xb") as output,
        ):
            shutil.copyfileobj(source, output)
    else:
        with tarfile.open(archive) as package:
            member = package.getmember(name)
            if not member.isfile():
                raise ValueError("Caddy executable is not a regular archive member")
            with package.extractfile(member) as source, executable.open("xb") as output:
                shutil.copyfileobj(source, output)
    executable.chmod(0o755)
    return executable


def store(action, certificate, fingerprint, *, check=True):
    if os.name == "nt":
        return subprocess.run(
            [
                "pwsh",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(HERE / "windows_store.ps1"),
                "-Action",
                action,
                "-Certificate",
                str(certificate),
                "-Thumbprint",
                fingerprint,
            ],
            check=check,
            capture_output=True,
            text=True,
        )
    if action == "enroll":
        return subprocess.run(
            [
                "sudo",
                "-n",
                "security",
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                "/Library/Keychains/System.keychain",
                str(certificate),
            ],
            check=check,
            capture_output=True,
            text=True,
        )
    subprocess.run(
        ["sudo", "-n", "security", "remove-trusted-cert", "-d", str(certificate)],
        check=check,
        capture_output=True,
        text=True,
    )
    return subprocess.run(
        [
            "sudo",
            "-n",
            "security",
            "delete-certificate",
            "-Z",
            fingerprint,
            "/Library/Keychains/System.keychain",
        ],
        check=check,
        capture_output=True,
        text=True,
    )


def probe(expected):
    run("node", str(HERE / "probe.cjs"), expected)


def main():
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise ValueError(
            "Native trust acceptance runs only on disposable GitHub-hosted machines"
        )
    if platform.system() not in ("Windows", "Darwin"):
        raise ValueError(
            "This native-store test targets Windows/macOS; Linux trust is covered by Compose acceptance"
        )
    with tempfile.TemporaryDirectory(prefix="vardrsec-native-trust-") as folder:
        root = Path(folder)
        executable = tool(root)
        env = {
            **os.environ,
            "XDG_DATA_HOME": str(root / "data"),
            "XDG_CONFIG_HOME": str(root / "config"),
        }
        environment = run(
            str(executable), "environ", env=env, capture_output=True, text=True
        ).stdout
        data = next(
            line.split("=", 1)[1]
            for line in environment.splitlines()
            if line.startswith("caddy.AppDataDir=")
        )
        authority = Path(data) / "pki/authorities/local/root.crt"
        config = root / "Caddyfile"
        config.write_text(
            '{\n admin off\n auto_https disable_redirects\n skip_install_trust\n}\nhttps://localhost:8445 {\n tls internal\n respond "VardrSec native trust acceptance"\n}\n',
            encoding="utf-8",
        )
        attempted = False
        fingerprint = None
        with (
            (root / "server.log").open("w") as log,
            subprocess.Popen(
                [
                    str(executable),
                    "run",
                    "--config",
                    str(config),
                    "--adapter",
                    "caddyfile",
                ],
                env=env,
                stdout=log,
                stderr=log,
            ) as server,
        ):
            try:
                deadline = time.monotonic() + 40
                while time.monotonic() < deadline:
                    if server.poll() is not None:
                        raise ValueError("Native Caddy fixture exited before readiness")
                    if authority.exists():
                        try:
                            with socket.create_connection(
                                ("localhost", 8445), timeout=1
                            ):
                                break
                        except OSError:
                            pass
                    time.sleep(0.2)
                else:
                    raise ValueError("Native HTTPS fixture did not become ready")
                # SHA-1 is only the native store's identifier, not an integrity pin.
                fingerprint = (
                    hashlib.sha1(
                        ssl.PEM_cert_to_DER_cert(authority.read_text(encoding="utf-8"))
                    )
                    .hexdigest()
                    .upper()
                )
                probe("untrusted")
                attempted = True
                store("enroll", authority, fingerprint)
                probe("trusted")
                store("remove", authority, fingerprint)
                attempted = False
                probe("untrusted")
                print(
                    f"PASS: {platform.system()} native CA rejection, explicit enrollment, verified browser HTTPS and trust removal"
                )
            finally:
                if attempted and fingerprint:
                    store("remove", authority, fingerprint, check=False)
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()


if __name__ == "__main__":
    main()
