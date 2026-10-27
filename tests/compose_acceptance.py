"""Explicit destructive-fixture acceptance; use only the named disposable project."""

import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

from gate_acceptance import run_gate_workflow, verify_retained

ROOT = Path(__file__).resolve().parents[1]
PROJECT = "vardrsec-compose-review"
URL = "https://localhost:8443"


def compose(*args, **kwargs):
    return subprocess.run(
        ["docker", "compose", "-p", PROJECT, *args],
        cwd=ROOT,
        check=kwargs.pop("check", True),
        **kwargs,
    )


def main():
    # Explicitly scoped disposable data; never run bootstrap against the default project.
    bootstrap = subprocess.run(
        [
            sys.executable,
            str(ROOT / "vardrsec.py"),
            "bootstrap",
            "--username",
            "operator",
            "--generate-password",
        ],
        cwd=ROOT,
        env={**os.environ, "COMPOSE_PROJECT_NAME": PROJECT},
        check=True,
        capture_output=True,
        text=True,
    )
    password = bootstrap.stdout.split(
        "Generated password (store securely; shown once): ", 1
    )[1].strip()
    trust = ROOT / "trust" / "root.crt"
    original_ca = hashlib.sha256(trust.read_bytes()).digest()
    ctx = ssl.create_default_context(cafile=str(trust))
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx),
    )

    def request(path, data=None, csrf=None, method=None):
        headers = {"Origin": URL}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if csrf:
            headers["X-CSRF-Token"] = csrf
        req = urllib.request.Request(
            URL + "/backend" + path,
            headers=headers,
            data=None if data is None else json.dumps(data).encode(),
            method=method,
        )
        with client.open(req, timeout=20) as response:
            return json.load(response)

    # Exercise the documented first-run UI path instead of creating its key via
    # a fixture API call. Capture the one-time token privately, never in logs.
    browser_command = [
        "docker",
        "run",
        "--rm",
        "--network",
        f"container:{PROJECT}-proxy-1",
        "--mount",
        f"type=bind,source={trust.parent},target=/trust,readonly",
        "-e",
        "FIXTURE_PASSWORD",
        "-e",
        "FIXTURE_CREATE_RUNNER_KEY",
        "vardrsec-browser:acceptance",
    ]
    browser_env = {**os.environ, "FIXTURE_PASSWORD": password}
    generated = subprocess.run(
        browser_command,
        env={**browser_env, "FIXTURE_CREATE_RUNNER_KEY": "1"},
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=True,
    )
    key_info = json.loads(generated.stdout)
    key = key_info["token"]
    assert key_info["scope"] == "runner" and key.startswith("vmap_")
    assert key not in generated.stderr and password not in generated.stderr
    print("PASS: real Settings UI creates and displays a one-time Runner-only key")
    request("/auth/local/login", {"username": "operator", "password": password})
    stored = request("/auth/apikeys")["keys"]
    assert len(stored) == 1 and stored[0]["id"] == key_info["id"]
    assert stored[0]["scope"] == "runner" and "token" not in stored[0]
    env = {**os.environ, "VARDRMAP_API_KEY": key}
    result = subprocess.run(
        [sys.executable, str(ROOT / "vardrsec.py"), "doctor"],
        cwd=ROOT,
        env={**env, "COMPOSE_PROJECT_NAME": PROJECT},
        capture_output=True,
        text=True,
        check=False,
    )
    doctor = json.loads(result.stdout)
    assert key not in result.stdout + result.stderr
    assert result.returncode == 0 and doctor["healthy"] is True, [
        c for c in doctor["checks"] if c["status"] == "fail"
    ]
    for name in ("platform database", "platform migrations", "api auth"):
        assert (
            next(c for c in doctor["checks"] if c["name"] == name)["status"] == "ok"
        ), name
    print(
        "PASS: Runner authenticates over CA-validated HTTPS; database/migrations ready; no API key in output"
    )
    heartbeat = compose(
        "run",
        "--rm",
        "--no-deps",
        "runner",
        "heartbeat",
        env=env,
        capture_output=True,
        text=True,
    )
    assert key not in heartbeat.stdout + heartbeat.stderr
    report = request("/runner/status")
    assert report["schema_version"] == 1 and report["stale_after_seconds"] == 300
    assert any(
        row["freshness"] == "recent" and row["online"] for row in report["runners"]
    )
    print("PASS: explicit one-shot Runner heartbeat reaches Map through verified HTTPS")
    # The browser shares only the proxy's network namespace and receives the public CA.
    subprocess.run(
        browser_command,
        env={**browser_env, "FIXTURE_CREATE_RUNNER_KEY": "0"},
        check=True,
    )
    gate_receipt = run_gate_workflow(compose, request, key, password)
    compose("stop")
    compose(
        "up",
        "-d",
        "--no-build",
        "--wait",
        "--wait-timeout",
        "180",
        "db",
        "api",
        "web",
        "proxy",
    )
    compose(
        "cp",
        "proxy:/data/caddy/pki/authorities/local/root.crt",
        "trust/root.crt",
        capture_output=True,
    )
    trust.chmod(0o644)
    assert hashlib.sha256(trust.read_bytes()).digest() == original_ca
    assert request("/ready")["status"] == "ready"
    assert any(
        e["name"] == "Compose trusted HTTPS acceptance"
        for e in request("/engagements")["programs"]
    )
    # Cookie from the separate API client also survives restart within its normal expiry.
    assert request("/auth/local/session")["authMethod"] == "local"
    verify_retained(request, gate_receipt)
    (ROOT / "artifacts/installed-gate/accepted.json").write_text(
        json.dumps(gate_receipt, indent=2) + "\n", encoding="utf-8"
    )
    services = compose(
        "ps", "--services", "--status", "running", capture_output=True, text=True
    ).stdout.splitlines()
    assert set(services) == {"db", "api", "web", "proxy"}, services
    print(
        "PASS: stop/start retains engagement, session and CA; platform startup runs no Runner worker"
    )


if __name__ == "__main__":
    main()
