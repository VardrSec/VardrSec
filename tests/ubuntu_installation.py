"""Public-CA lifecycle for the installed stack on a disposable Ubuntu CI host."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "artifacts/installed-gate/ubuntu-installation.json"
CERTS = Path("/usr/local/share/ca-certificates")


def run(*args, **kwargs):
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=kwargs.pop("check", True),
        timeout=60,
        **kwargs,
    )


def save(value):
    RECEIPT.parent.mkdir(parents=True, exist_ok=True)
    RECEIPT.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def host():
    assert (
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    ), "Only disposable GitHub-hosted Ubuntu machines are allowed"
    assert platform.system() == "Linux"
    release = platform.freedesktop_os_release()
    assert release["ID"] == "ubuntu" and release["VERSION_ID"] == "24.04"
    return release


def probe():
    # Use the OS trust store; an inherited explicit CA override cannot pass this test.
    env = {
        k: v
        for k, v in os.environ.items()
        if k
        not in {"CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE"}
    }
    return run(
        "curl",
        "--fail",
        "--silent",
        "--show-error",
        "--noproxy",
        "*",
        "--max-time",
        "10",
        "https://localhost:8443/backend/ready",
        env=env,
        check=False,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("preflight", "enroll", "cleanup"))
    action = parser.parse_args().action
    release = host()
    if action == "preflight":
        assert not (ROOT / ".env").exists() and not (ROOT / ".sources").exists()
        assert not run("docker", "ps", "-aq").stdout.strip(), "Containers already exist"
        assert not run("docker", "volume", "ls", "-q").stdout.strip(), (
            "Volumes already exist"
        )
        existing = run(
            "docker", "image", "ls", "--format", "{{.Repository}}"
        ).stdout.splitlines()
        assert not set(existing) & {
            "vardrmap-api",
            "vardrmap-web",
            "vardrrunner",
            "vardrsec-proxy",
        }
        save(
            {
                "ubuntu": release["VERSION_ID"],
                "architecture": platform.machine(),
                "clean_before_setup": True,
                "containers_before_setup": 0,
                "volumes_before_setup": 0,
                "sources_before_setup": False,
                "docker": run(
                    "docker", "version", "--format", "{{.Server.Version}}"
                ).stdout.strip(),
                "compose": run(
                    "docker", "compose", "version", "--short"
                ).stdout.strip(),
            }
        )
        print(
            "PASS: fresh Ubuntu host has no VardrSec configuration, sources, images, containers or volumes"
        )
        return
    if not RECEIPT.exists():
        assert action == "cleanup"
        return
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    if action == "enroll":
        assert receipt["clean_before_setup"] is True
        assert probe().returncode == 60, (
            "Native curl must reject the untrusted installation CA"
        )
        public_ca = ROOT / "trust/root.crt"
        digest = hashlib.sha256(public_ca.read_bytes()).hexdigest()
        certificate = CERTS / ("vardrsec-alpha-fixture-" + digest[:12] + ".crt")
        assert not certificate.exists(), "Refuse an existing trust entry"
        receipt.update(ca_sha256=digest, certificate=str(certificate))
        # Persist the exact cleanup boundary before changing this disposable store.
        save(receipt)
        run("sudo", "-n", "install", "-m", "0644", str(public_ca), str(certificate))
        run("sudo", "-n", "update-ca-certificates")
        result = probe()
        assert (
            result.returncode == 0 and json.loads(result.stdout)["status"] == "ready"
        ), result.stderr
        receipt.update(native_os_enrollment=True, native_https_verified=True)
        save(receipt)
        print(
            "PASS: explicit Ubuntu CA enrollment enables ordinary native curl HTTPS with default verification"
        )
        return
    if not receipt.get("certificate"):
        return
    digest = receipt["ca_sha256"]
    certificate = Path(receipt["certificate"])
    assert (
        certificate.parent == CERTS
        and certificate.name == "vardrsec-alpha-fixture-" + digest[:12] + ".crt"
    )
    if certificate.exists():
        assert (
            not certificate.is_symlink()
            and hashlib.sha256(certificate.read_bytes()).hexdigest() == digest
        )
        run("sudo", "-n", "rm", "--", str(certificate))
        run("sudo", "-n", "update-ca-certificates", "--fresh")
    assert not certificate.exists()
    rejected = probe().returncode == 60
    receipt.update(native_ca_removed=True, native_https_rejected_after_removal=rejected)
    save(receipt)
    assert rejected, "Fresh native curl must reject HTTPS after exact CA removal"
    print("PASS: exact Ubuntu CA removal restores native HTTPS rejection")


if __name__ == "__main__":
    main()
