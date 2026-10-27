"""Installed Gate workflow, invoked only by the disposable Compose acceptance."""

import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
PROJECT = "vardrsec-compose-review"
ARTIFACTS = ROOT / "artifacts" / "installed-gate"
TARGET = f"{PROJECT}-gate-fixture"
BROWSER = f"{PROJECT}-gate-browser"
ORIGIN = "http://gate-fixture:8080"
CANARIES = ("disposable-private-response-canary", "disposable-response-cookie-canary")


def docker(*args, **kwargs):
    return subprocess.run(
        ["docker", *args],
        check=kwargs.pop("check", True),
        timeout=kwargs.pop("timeout", 60),
        **kwargs,
    )


def reviewed_cases():
    identities = [
        {
            "id": name,
            "role": "user",
            "tenant_id": "fixture-tenant",
            "credential": {
                "type": "bearer",
                "value_env": f"FIXTURE_{name.upper()}_TOKEN",
            },
            "preflight": {
                "url": ORIGIN + "/session",
                "expected_status": 200,
                "json_fields": {"user.id": name},
            },
        }
        for name in ("owner", "peer")
    ] + [
        {
            "id": "anonymous",
            "credential": {"type": "static_header", "header": "", "value": ""},
        }
    ]
    return [
        {
            "name": mode,
            "spec": {
                "id": "installed-" + mode,
                "identities": identities,
                "request": {
                    "method": "GET",
                    "url": f"{ORIGIN}/{mode}/records/42?view=full&include=owner",
                },
                "expected_access": [
                    {
                        "identity_id": i["id"],
                        "decision": "allow" if i["id"] == "owner" else "deny",
                    }
                    for i in identities
                ],
                "resource": {
                    "type": "record",
                    "object_id": "42",
                    "owner_identity": "owner",
                    "tenant_id": "fixture-tenant",
                },
                "deny_status": [401, 403, 404],
            },
        }
        for mode in ("vulnerable", "fixed", "unavailable")
    ]


def observations():
    result = docker(
        "exec",
        TARGET,
        "python",
        "-c",
        "import urllib.request; print(urllib.request.urlopen('http://localhost:8080/observations').read().decode())",
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)["requests"]


def verify_records(request, base, job_id, case_id, scenario):
    job = next(j for j in request(base + "/jobs")["jobs"] if j["id"] == job_id)
    assessment = job["assessment"]
    assert assessment and assessment["case_id"] == case_id
    evidence = request(base + f"/evidence?job_id={job_id}")["evidence"]
    scans = request(base + f"/scans?job_id={job_id}")["scans"]
    if scenario == "blocked":
        assert job["status"] == "failed" and assessment["status"] == "inconclusive"
        assert not scans
    else:
        assert job["status"] == "done", job.get("error_message")
        assert assessment["case_snapshot_verified"] is True
        spec = next(c["spec"] for c in reviewed_cases() if c["name"] == scenario)
        expected_hash = hashlib.sha256(
            json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        assert assessment["case_hash"] == expected_hash
        assert assessment["preflight"]["status"] == "passed"
        assert assessment["candidate_findings"] == len(scans)
        assert len(evidence) == 5  # Two preflight diagnostics plus three executions.
        resource = [e for e in evidence if e["expected_decision"] in ("allow", "deny")]
        assert {e["identity_id"] for e in resource} == {"owner", "peer", "anonymous"}
        if scenario == "unavailable":
            assert (
                assessment["status"] == "inconclusive"
                and assessment["inconclusive"] == 3
            )
            assert assessment["baseline_valid"] is False and not scans
        else:
            assert (
                assessment["status"] == "conclusive"
                and assessment["baseline_valid"] is True
            )
            if scenario == "vulnerable":
                assert {"potential_bola", "missing_authentication"} <= {
                    s["type"] for s in scans
                }
                assert all(s["status"] == "new" for s in scans)
            else:
                assert not scans
    for row in evidence:
        assert (
            row["job_id"] == job_id and row["case_id"] == case_id and row["identity_id"]
        )
        assert hashlib.sha256(row["body"].encode()).hexdigest() == row["content_hash"]
        assert not row["finding_id"]
    assert request(base + "/findings")["total"] == 0
    events = request(f"/jobs/{job_id}/events")["events"]
    assert "policy_warning" in {e["kind"] for e in events}
    if scenario != "blocked":
        assert {"started", "running", "uploaded", "done"} <= {e["kind"] for e in events}
    return {
        "scenario": scenario,
        "job": job_id,
        "case": case_id,
        "status": job["status"],
        "assessment": assessment,
        "evidence": [{"id": e["id"], "hash": e["content_hash"]} for e in evidence],
        "candidates": len(scans),
    }, (job, evidence, scans, events)


def run_gate_workflow(compose, request, key, password):
    # This helper never runs against an arbitrary/default installation or target.
    containers = compose(
        "ps", "--format", "json", capture_output=True, text=True
    ).stdout
    assert containers.strip()
    assert {json.loads(row)["Project"] for row in containers.splitlines()} == {PROJECT}
    for name in (TARGET, BROWSER):
        assert not docker(
            "ps",
            "-a",
            "--filter",
            f"name=^/{name}$",
            "--format",
            "{{.ID}}",
            capture_output=True,
            text=True,
        ).stdout.strip(), f"Fixture already exists: {name}"
    engagement = next(
        e
        for e in request("/engagements")["programs"]
        if e["name"] == "Compose trusted HTTPS acceptance"
    )
    base = "/engagements/" + engagement["id"]
    # The engagement was created by the prior real browser journey.
    assert not request(base + "/jobs")["jobs"]
    assert request(base + "/evidence")["total"] == 0
    tokens = {
        f"FIXTURE_{who.upper()}_TOKEN": secrets.token_urlsafe(32)
        for who in ("owner", "peer")
    }
    secret_values = [key, password, *tokens.values(), *CANARIES]
    env = {
        **os.environ,
        **tokens,
        "VARDRMAP_API_KEY": key,
        "FIXTURE_PASSWORD": password,
        "FIXTURE_ENGAGEMENT": engagement["id"],
        "FIXTURE_CASES": json.dumps(reviewed_cases()),
    }

    def no_secrets(value):
        text = value if isinstance(value, str) else json.dumps(value)
        assert all(secret not in text for secret in secret_values), (
            "Fixture secret/value escaped redaction"
        )

    def runner(*command, allow=False):
        result = compose(
            "run",
            "--rm",
            "--no-deps",
            "-e",
            f"VARDRRUNNER_ALLOW_PRIVATE_TARGETS={int(allow)}",
            "-e",
            "FIXTURE_OWNER_TOKEN",
            "-e",
            "FIXTURE_PEER_TOKEN",
            "runner",
            *command,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
            check=False,
        )
        no_secrets(result.stdout + result.stderr)
        (artifacts / f"runner-{scenario}-{command[0]}.log").write_text(
            result.stdout + result.stderr, encoding="utf-8"
        )
        assert result.returncode == 0, (
            "Runner invocation failed; inspect sanitized fixture logs"
        )

    artifacts = ARTIFACTS / ("run-" + secrets.token_hex(6))
    artifacts.mkdir(parents=True)
    target_started = False
    browser = None
    deadline = None
    receipt = {"engagement": engagement["id"], "jobs": [], "rendered": []}
    try:
        docker(
            "run",
            "-d",
            "--rm",
            "--name",
            TARGET,
            "--network",
            PROJECT + "_runner",
            "--network-alias",
            "gate-fixture",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--mount",
            f"type=bind,source={ROOT / 'tests' / 'gate'},target=/fixture,readonly",
            "-e",
            "FIXTURE_OWNER_TOKEN",
            "-e",
            "FIXTURE_PEER_TOKEN",
            "--entrypoint",
            "python",
            "vardrmap-api:development",
            "/fixture/target.py",
            env=env,
            capture_output=True,
            text=True,
        )
        target_started = True
        for attempt in range(30):
            try:
                assert observations() == []
                break
            except subprocess.CalledProcessError:
                if attempt == 29:
                    raise RuntimeError("Disposable target did not start") from None
                time.sleep(0.2)
        browser = subprocess.Popen(
            [
                "docker",
                "run",
                "--rm",
                "-i",
                "--name",
                BROWSER,
                "--network",
                f"container:{PROJECT}-proxy-1",
                "--mount",
                f"type=bind,source={ROOT / 'trust'},target=/trust,readonly",
                "--mount",
                f"type=bind,source={artifacts},target=/artifacts",
                "-e",
                "FIXTURE_PASSWORD",
                "-e",
                "FIXTURE_ENGAGEMENT",
                "-e",
                "FIXTURE_CASES",
                "vardrsec-browser:acceptance",
                "node",
                "gate.cjs",
            ],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        deadline = threading.Timer(300, browser.kill)
        deadline.start()
        for line in browser.stdout:
            no_secrets(line)
            if not line.startswith("GATE_EVENT "):
                print(line.rstrip(), flush=True)
                continue
            event = json.loads(line.removeprefix("GATE_EVENT "))
            if event["type"] == "reviewed":
                assert len(event["cases"]) == 3
                receipt["cases"] = event["cases"]
                assert observations() == []
                continue
            if event["type"] == "rendered":
                receipt["rendered"].append(event["scenario"])
                continue
            assert event["type"] == "queued"
            scenario, jid = event["scenario"], event["job"]
            mark = observations()
            runner("doctor", "--platform", "--offline", "--json")
            job = next(j for j in request(base + "/jobs")["jobs"] if j["id"] == jid)
            assert job["status"] == "pending" and not job["assessment"]
            assert request(base + f"/evidence?job_id={jid}")["total"] == 0
            assert observations() == mark
            runner("jobs", "run", "--yes", allow=scenario != "blocked")
            records, raw = verify_records(request, base, jid, event["case"], scenario)
            no_secrets(raw)
            receipt["jobs"].append(records)
            contacted = observations()[len(mark) :]
            if scenario == "blocked":
                assert not contacted
            else:
                assert len(contacted) == 5
                assert [r["path"] for r in contacted[:2]] == ["/session", "/session"]
                assert {r["identity"] for r in contacted[2:]} == {
                    "owner",
                    "peer",
                    "anonymous",
                }
                assert all(
                    r["path"] == f"/{scenario}/records/42?view=full&include=owner"
                    for r in contacted[2:]
                )
            print(
                f"PASS: installed {scenario} job; explicit execution, reviewed provenance, hashed redacted evidence and candidate-only results",
                flush=True,
            )
            browser.stdin.write('{"continue":true}\n')
            browser.stdin.flush()
        assert browser.wait(timeout=20) == 0, "Installed browser workflow failed"
        assert receipt["rendered"] == ["blocked", "vulnerable", "fixed", "unavailable"]
        assert len(receipt["jobs"]) == 4
        mark = observations()
        scenario = "empty-queue"
        runner("jobs", "run", "--yes", allow=True)
        assert observations() == mark
        for record in receipt["jobs"]:
            retained, _ = verify_records(
                request, base, record["job"], record["case"], record["scenario"]
            )
            assert retained == record
        print(
            "PASS: explicit empty-queue invocation sends no target requests or duplicate evidence"
        )
        no_secrets(receipt)
        (artifacts / "receipt.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )
        return receipt
    finally:
        if deadline:
            deadline.cancel()
        if browser:
            docker("rm", "-f", BROWSER, check=False, capture_output=True)
            if browser.poll() is None:
                browser.kill()
            browser.wait(timeout=10)
        if target_started:
            docker("rm", "-f", TARGET, check=False, capture_output=True)


def verify_retained(request, receipt):
    base = "/engagements/" + receipt["engagement"]
    for record in receipt["jobs"]:
        retained, _ = verify_records(
            request, base, record["job"], record["case"], record["scenario"]
        )
        assert retained == record
    print(
        "PASS: all installed Gate assessments and evidence hashes survive platform stop/start"
    )
