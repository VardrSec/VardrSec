"""Explicit synthetic tool/network fixture; no platform or customer targets used."""

import json
from pathlib import Path
import platform
import secrets
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer

from tools.server import Target

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "vardrsec-tools-review"
LABEL = "com.vardrsec.acceptance=tools-network"
IMAGE = "vardrrunner:development"


def docker(*args, **kwargs):
    return subprocess.run(
        ["docker", *args],
        check=kwargs.pop("check", True),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=kwargs.pop("timeout", 60),
        **kwargs,
    )


def main():
    info = json.loads(docker("info", "--format", "{{json .}}").stdout)
    assert info["OSType"] == "linux", "Acceptance requires Linux containers"
    private, outside, state = [
        PREFIX + suffix for suffix in ("-private", "-outside", "-state")
    ]
    target, namespace = [PREFIX + suffix for suffix in ("-target", "-namespace")]
    for kind, names in (
        ("network", (private, outside)),
        ("volume", (state,)),
        ("container", (target, namespace)),
    ):
        for name in names:
            assert docker(kind, "inspect", name, check=False).returncode != 0, (
                f"Disposable fixture already exists: {name}"
            )
    folder = ROOT / "artifacts/tool-network" / ("run-" + secrets.token_hex(6))
    folder.mkdir(parents=True)
    receipt = {
        "host": {
            "os": platform.system(),
            "release": platform.release(),
            "architecture": platform.machine(),
        },
        "docker": {
            k: info[k]
            for k in ("OSType", "Architecture", "ServerVersion", "OperatingSystem")
        },
        "image_id": docker(
            "image", "inspect", IMAGE, "--format", "{{.Id}}"
        ).stdout.strip(),
        "declared_source_pins": json.loads(
            (ROOT / "versions.json").read_text(encoding="utf-8")
        )["components"],
        "genuine_vpn": "not_tested",
        "fresh_host": "CI runner only; local machines are existing installations",
        "checks": {},
    }
    created = []
    server = None

    def create(kind, name, *args):
        result = docker(kind, "create", "--label", LABEL, *args, name)
        created.append((kind, name))
        return result

    def launch(name, network, *command):
        result = docker(
            "run",
            "-d",
            "--name",
            name,
            "--label",
            LABEL,
            "--network",
            network,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--mount",
            f"type=bind,source={ROOT / 'tests/tools'},target=/fixture,readonly",
            "--entrypoint",
            "python",
            IMAGE,
            *command,
        )
        created.append(("container", name))
        return result

    def run(label, network, mode, *args, extra=()):
        result = docker(
            "run",
            "--rm",
            "--network",
            network,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--mount",
            f"type=bind,source={ROOT / 'tests/tools'},target=/fixture,readonly",
            "--mount",
            f"type=volume,source={state},target=/home/runner/.vardrmap",
            "-e",
            "VARDRMAP_API_KEY=",
            "-e",
            "VARDRMAP_URL=",
            "-e",
            "HTTP_PROXY=",
            "-e",
            "HTTPS_PROXY=",
            "-e",
            "ALL_PROXY=",
            "-e",
            "NO_PROXY=*",
            *extra,
            "--entrypoint",
            "python",
            IMAGE,
            "/fixture/runtime.py",
            mode,
            *args,
            timeout=300,
            check=False,
        )
        (folder / (label + ".log")).write_text(
            result.stdout + result.stderr, encoding="utf-8"
        )
        assert result.returncode == 0, (
            f"{label} failed; inspect {folder / (label + '.log')}"
        )
        receipt["checks"][label] = json.loads(result.stdout)
        print("PASS: " + label, flush=True)

    try:
        create("network", private, "--internal")
        create("network", outside, "--internal")
        create("volume", state)
        verified = docker(
            "run",
            "--rm",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            IMAGE,
            "tools",
            "verify",
        )
        (folder / "tools-verify.log").write_text(
            verified.stdout + verified.stderr, encoding="utf-8"
        )
        run("binary-inventory", "none", "inventory", "create")
        launch(target, private, "/fixture/server.py")
        launch(namespace, private, "-c", "import time; time.sleep(600)")
        target_info = json.loads(docker("container", "inspect", target).stdout)[0]
        address = target_info["NetworkSettings"]["Networks"][private]["IPAddress"]
        url = f"http://{address}:8080"
        run(
            "default-private-isolation", outside, "probe", url + "/probe", "unreachable"
        )
        run(
            "explicit-private-namespace",
            "container:" + namespace,
            "probe",
            url + "/probe",
            "reachable",
        )
        run("bounded-tool-modes", "container:" + namespace, "smoke", url)
        # A local host service, bound only to loopback on Desktop or the Linux Docker bridge.
        desktop = "Docker Desktop" in info["OperatingSystem"]
        if desktop:
            bind = "127.0.0.1"
        else:
            assert sys.platform.startswith("linux"), (
                "Host reachability requires a local Linux Engine or Docker Desktop"
            )
            bridge = json.loads(docker("network", "inspect", "bridge").stdout)[0]
            bind = bridge["IPAM"]["Config"][0]["Gateway"]
        server = ThreadingHTTPServer((bind, 0), Target)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        run(
            "container-to-host",
            "bridge",
            "probe",
            f"http://host.docker.internal:{server.server_port}/probe",
            "reachable",
            extra=()
            if desktop
            else ("--add-host", "host.docker.internal:host-gateway"),
        )
        # Container removal/replacement must preserve state without hiding immutable tools.
        run("replacement-inventory", "none", "inventory", "check")
        assert (
            receipt["checks"]["binary-inventory"]["tools"]
            == receipt["checks"]["replacement-inventory"]["tools"]
        )
        (folder / "receipt.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )
        print(
            "PASS: synthetic host/private networking and selected unprivileged tool modes; genuine VPN and broader modes remain unverified",
            flush=True,
        )
    finally:
        if server:
            server.shutdown()
            server.server_close()
        for kind, name in reversed(created):
            data = json.loads(docker(kind, "inspect", name).stdout)[0]
            labels = data["Config"]["Labels"] if kind == "container" else data["Labels"]
            assert labels.get("com.vardrsec.acceptance") == "tools-network"
            docker(kind, "rm", *(["-f"] if kind == "container" else []), name)


if __name__ == "__main__":
    main()
