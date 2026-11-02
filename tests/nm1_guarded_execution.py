"""Explicit real Gate/Runner NM-1 loopback fixture; no external target accepted."""

import argparse
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
from unittest.mock import patch
from urllib.parse import urlsplit


class Target(BaseHTTPRequestHandler):
    value = 0
    calls = 0

    def log_message(self, *_):
        pass

    def respond(self, status, body):
        type(self).calls += 1
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def actor(self):
        return self.headers.get("Authorization", "").removeprefix("Bearer synthetic-")

    def do_GET(self):
        self.respond(
            200,
            {"id": self.actor()} if self.path == "/me" else {"value": type(self).value},
        )

    def do_POST(self):
        type(self).value = 0
        self.respond(200, {"prepared": True})

    def do_PATCH(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.actor() == "owner":
            type(self).value = 1
        self.respond(200 if self.actor() == "owner" else 403, {})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner-source", required=True, type=Path)
    parser.add_argument("--gate-binary", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    sys.path.insert(0, str(args.runner_source))
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from vardrrunner import config, runner
    from vardrrunner.authorization.codec import (
        AuthorizationError,
        TrustAnchor,
        digest,
        encoded,
    )
    from vardrrunner.authorization.contracts import ValidationContext, approve
    from vardrrunner.authorization.ledger import AuthorizationLedger
    from vardrrunner.authorization.plan import compile_gate_plan, origin
    from vardrrunner.authorization.runtime import execute_gate
    from vardrrunner.journal import Journal

    binary = args.gate_binary.resolve()
    tool_hash = digest(binary.read_bytes())
    server = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = "http://127.0.0.1:" + str(server.server_port)
    seed = bytes(range(32))  # public fixture key; never production permission
    issuer = {"id": "fixture-only", "key_id": "public-test-key"}
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    anchor = TrustAnchor(
        issuer["id"],
        issuer["key_id"],
        public,
        frozenset({"approval", "contract"}),
        frozenset({"standalone"}),
    )

    def person(name):
        return {
            "id": name,
            "credential": {"type": "bearer", "value_env": "NM1_" + name.upper()},
            "preflight": {
                "url": base + "/me",
                "expected_status": 200,
                "json_fields": {"id": name},
            },
        }

    case = {
        "id": "guarded-fixture",
        "mutating": True,
        "identities": [person("owner"), person("peer")],
        "setup": [
            {"name": "prepare", "request": {"method": "POST", "url": base + "/prepare"}}
        ],
        "request": {"method": "PATCH", "url": base + "/object", "body": {"value": 1}},
        "expected_access": [
            {"identity_id": "owner", "decision": "allow"},
            {"identity_id": "peer", "decision": "deny"},
        ],
        "write_verification": {
            "strategy": "changed",
            "environment": "synchronous_isolated",
            "identity": person("reader"),
            "request": {"method": "GET", "url": base + "/object"},
            "json_pointer": "/value",
            "changed_to": 1,
            "reset": {
                "as": "owner",
                "request": {"method": "POST", "url": base + "/reset"},
            },
        },
    }
    execution = {"allow_private_targets": True}
    plan = compile_gate_plan(case, execution, tool_sha256=tool_hash)
    now = datetime.now(timezone.utc).replace(microsecond=0)

    def stamp(value):
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")

    grants = [
        {
            "identity_id": name,
            "source": "value_env",
            "name": "NM1_" + name.upper(),
            "revision": 1,
            "expires_at": stamp(now + timedelta(minutes=5)),
        }
        for name in ("owner", "peer", "reader")
    ]
    permission = {
        "runner_id": "fixture-runner",
        "engagement_id": "fixture-engagement",
        "job_id": "fixture-job",
        "authority_revision": 1,
        "authority_sha256": "b" * 64,
        "plan_sha256": digest(encoded(plan)),
        "mode": "strict",
        "scope": [
            {
                "origin": origin(d["request"]["url"]),
                "path": urlsplit(d["request"]["url"]).path,
                "method": d["request"]["method"],
                "excluded": False,
                "reason": "",
            }
            for d in plan["dispatches"]
        ],
        "exceptions": [],
        "not_before": stamp(now),
        "expires_at": stamp(now + timedelta(minutes=5)),
        "testing_start": stamp(now),
        "testing_end": stamp(now + timedelta(minutes=5)),
        "max_executions": 1,
        "max_duration_seconds": 30,
        "max_http_dispatches": 14,
        "max_artifact_bytes": 1000000,
        "credential_grants": grants,
        "control": "local_offline",
    }
    try:
        with tempfile.TemporaryDirectory(prefix="nm1-guarded-") as directory:
            root = Path(directory)
            with (
                patch.object(config, "CONFIG_FILE", root / "config.json"),
                patch.object(runner, "program", lambda _: str(binary)),
                patch.dict(
                    os.environ,
                    {
                        "VARDRRUNNER_ALLOW_PRIVATE_TARGETS": "1",
                        **{
                            "NM1_" + name.upper(): "synthetic-" + name
                            for name in ("owner", "peer", "reader")
                        },
                    },
                ),
            ):
                for grant in grants:
                    config.approve_credential(
                        "fixture-engagement", base, "env", grant["name"]
                    )
                ledger = AuthorizationLedger(Journal(root / "journal.sqlite3"))
                ledger.set_state(
                    issuer["id"],
                    "fixture-engagement",
                    1,
                    False,
                    permission["authority_sha256"],
                )
                approval = approve(
                    permission,
                    issuer,
                    "standalone",
                    "fixture-operator",
                    "fixture-approval",
                    stamp(now),
                    seed,
                )
                context = ValidationContext(
                    "fixture-runner",
                    "fixture-engagement",
                    "fixture-job",
                    "fixture-attempt",
                    1,
                    "standalone",
                    now,
                    1,
                    tool_hash,
                    permission["authority_sha256"],
                )
                contract = ledger.issue(
                    approval,
                    (anchor,),
                    issuer,
                    seed,
                    "fixture-contract",
                    context.attempt_id,
                    context,
                    plan,
                    case,
                    execution,
                )
                output_dir = root / "output"
                output_dir.mkdir()
                output = execute_gate(
                    ledger,
                    contract,
                    approval,
                    plan,
                    case,
                    execution,
                    (anchor,),
                    context,
                    output_dir,
                )
                result = json.loads(output.read_text())
                assert (
                    result["case_hash"] == plan["case_hash"]
                    and len(result["assessments"]) == 2
                    and all(
                        a["decision"] in ("allowed", "denied")
                        for a in result["assessments"]
                    )
                )
                assert Target.calls == 14
                second = root / "replay"
                second.mkdir()
                try:
                    execute_gate(
                        ledger,
                        contract,
                        approval,
                        plan,
                        case,
                        execution,
                        (anchor,),
                        context,
                        second,
                    )
                except AuthorizationError:
                    pass
                else:
                    raise AssertionError("replayed contract executed")
                assert Target.calls == 14
                assert all(
                    "synthetic-" + name not in output.read_text()
                    for name in ("owner", "peer", "reader")
                )
                receipt = {
                    "schema": "vardr.nm1-guarded-execution/1",
                    "tool_sha256": tool_hash,
                    "plan_sha256": digest(encoded(plan)),
                    "target": "ephemeral loopback fixture only",
                    "dispatches": 14,
                    "phases": [
                        "setup",
                        "preflight",
                        "resource",
                        "verification",
                        "reset",
                    ],
                    "case_hash_preserved": True,
                    "replay_additional_requests": 0,
                    "credential_values_in_result": False,
                    "managed_control": "not exercised",
                }
                with args.out.open("x") as out:
                    json.dump(receipt, out, indent=2)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    print(
        "PASS: real guarded Runner/Gate, 14 auxiliary/resource dispatches, preserved case binding, zero replay traffic"
    )


if __name__ == "__main__":
    main()
