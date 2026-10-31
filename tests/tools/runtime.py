"""Run inside the actual toolkit image with its ordinary unprivileged baseline."""

import ctypes.util
from dataclasses import asdict
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.request
import urllib.error
from urllib.parse import urlsplit

from vardrrunner import config, runner, toolchain


def baseline():
    fields = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    assert os.geteuid() == 10001
    assert (
        int(fields["CapEff"].strip(), 16) == 0 and fields["NoNewPrivs"].strip() == "1"
    )
    assert not os.access(config.tools_dir(), os.W_OK)
    return {"uid": os.geteuid(), "effective_capabilities": 0, "no_new_privileges": True}


def inventory():
    tools = {
        name: asdict(toolchain.status(name, binary))
        for name, binary in runner.ALLOWED_TOOLS.items()
    }
    assert sum(s["source"] == "managed" for s in tools.values()) == 9
    assert all(s["path"] for s in tools.values())
    assert "nmap" not in tools, "Nmap must not be an inventoried tool"
    assert nmap_absent() == {
        "binary": False,
        "packages": False,
        "files": [],
    }, "Nmap is present in the image"
    assert ctypes.util.find_library("pcap")
    assert (Path.home() / ".config").resolve() == config.config_dir().resolve()
    return tools


def nmap_absent():
    """What the image contains of Nmap: nothing, by design (see docs/release-license-inventory.md)."""
    dpkg = [
        subprocess.run(["dpkg", "-s", name], capture_output=True).returncode == 0
        for name in ("nmap", "nmap-common")
    ]
    found = subprocess.run(
        ["find", "/", "-xdev", "-name", "nmap*", "-not", "-path", "/proc/*"],
        capture_output=True,
        text=True,
    ).stdout.split()
    return {
        "binary": shutil.which("nmap") is not None,
        "packages": any(dpkg),
        "files": found,
    }


def probe(url):
    # Trust ordinary TCP/HTTP for synthetic target reachability, never an API key.
    with urllib.request.urlopen(url, timeout=3) as r:
        return r.status == 200 and b"vardrsec" in r.read(4096)


def smoke(url):
    host = urlsplit(url).hostname
    with tempfile.TemporaryDirectory(dir=config.config_dir()) as folder:
        work = Path(folder)
        runs = {}

        def execute(name, args, expected=0, timeout=40):
            r = subprocess.run(
                [runner.program(name), *args],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            label = name if expected == 0 else name + "-raw"
            runs[label] = {
                "exit_code": r.returncode,
                "stdout": r.stdout,
                "stderr": r.stderr,
            }
            assert (r.returncode == 0) if expected == 0 else (r.returncode != 0), runs[
                label
            ]
            return r

        httpx = execute(
            "httpx",
            [
                "-u",
                url,
                "-json",
                "-silent",
                "-duc",
                "-no-stdin",
                "-timeout",
                "3",
                "-retries",
                "0",
                "-threads",
                "1",
                "-rl",
                "2",
            ],
        )
        rows = [
            json.loads(line)
            for line in httpx.stdout.splitlines()
            if line.startswith("{")
        ]
        assert any(r["status_code"] == 200 and r["url"].startswith(url) for r in rows)
        nuclei = execute(
            "nuclei",
            [
                "-u",
                url,
                "-t",
                "/fixture/marker.yaml",
                "-jsonl",
                "-silent",
                "-duc",
                "-ni",
                "-no-stdin",
                "-timeout",
                "3",
                "-retries",
                "0",
                "-rl",
                "2",
                "-c",
                "1",
                "-bs",
                "1",
            ],
        )
        matches = [
            json.loads(line)
            for line in nuclei.stdout.splitlines()
            if line.startswith("{")
        ]
        assert any(r["template-id"] == "vardrsec-local-marker" for r in matches), runs[
            "nuclei"
        ]
        ffuf = work / "ffuf.json"
        execute(
            "ffuf",
            [
                "-u",
                url + "/FUZZ",
                "-w",
                "/fixture/words.txt",
                "-mc",
                "200",
                "-of",
                "json",
                "-o",
                str(ffuf),
                "-rate",
                "2",
                "-t",
                "1",
                "-noninteractive",
                "-maxtime",
                "10",
                "-timeout",
                "3",
                "-s",
            ],
        )
        assert [r["status"] for r in json.loads(ffuf.read_text())["results"]] == [200]
        naabu = execute(
            "naabu",
            [
                "-host",
                host,
                "-p",
                "8080",
                "-s",
                "CONNECT",
                "-Pn",
                "-json",
                "-silent",
                "-duc",
                "-no-stdin",
                "-retries",
                "1",
                "-rate",
                "2",
            ],
        )
        assert any(
            json.loads(line).get("port") == 8080
            for line in naabu.stdout.splitlines()
            if line.startswith("{")
        ), runs["naabu"]
        katana = execute(
            "katana",
            [
                "-u",
                url,
                "-d",
                "2",
                "-silent",
                "-jsonl",
                "-duc",
                "-timeout",
                "3",
                "-ct",
                "10s",
                "-rl",
                "2",
                "-c",
                "1",
                "-p",
                "1",
            ],
        )
        assert "/probe" in katana.stdout, runs["katana"]
        # Raw sockets stay unavailable without capabilities (the boundary the former Nmap
        # raw-SYN rejection demonstrated); naabu's default connect mode is what was run above.
        try:
            socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP).close()
        except PermissionError:
            raw_sockets = "denied_without_privilege"
        else:
            raise AssertionError("A raw socket opened without privileges")
        # Presence/version checks do not certify headless or provider/DNS-dependent modes.
        return {
            "passed_modes": [
                "httpx-http",
                "nuclei-local-template",
                "ffuf-local-wordlist",
                "naabu-tcp-connect",
                "katana-non-headless",
            ],
            "raw_sockets": raw_sockets,
            "nmap": "absent",
            "headless": "not_provisioned"
            if not any(
                shutil.which(b)
                for b in ("chromium", "chromium-browser", "google-chrome")
            )
            else "not_tested",
            "other_modes": "inventory_only",
            "logs": runs,
        }


if __name__ == "__main__":
    result = {"baseline": baseline()}
    mode = sys.argv[1]
    if mode == "inventory":
        result["tools"] = inventory()
        marker = config.config_dir() / "tool-network-replacement"
        if sys.argv[2] == "create":
            marker.write_text("retained", encoding="utf-8")
        else:
            assert (
                sys.argv[2] == "check"
                and marker.read_text(encoding="utf-8") == "retained"
            )
            assert (config.config_dir() / "katana" / "form-config.yaml").is_file()
            assert (config.config_dir() / "nuclei").is_dir()
        result["persistent_state"] = sys.argv[2]
    elif mode == "probe":
        try:
            reachable = probe(sys.argv[2])
        except (OSError, urllib.error.URLError):
            reachable = False
        assert reachable == (sys.argv[3] == "reachable"), {"reachable": reachable}
        result["reachable"] = reachable
    elif mode == "smoke":
        result["modes"] = smoke(sys.argv[2])
    else:
        raise ValueError("Unknown acceptance mode")
    print(json.dumps(result))
