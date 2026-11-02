"""Explicit cross-repository NM-1 prototypes; in-memory synthetic data, no HTTP.

Use Map's test Python with the authorization crypto extra available. The public
test seed and injected operator/control state are NEVER production trust evidence.
"""

import argparse
import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--map-source", required=True, type=Path)
    parser.add_argument("--runner-source", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    os.environ["ENV"] = "test"
    os.environ["DATABASE_URL"] = "sqlite://"
    os.environ["PYTHON_DOTENV_DISABLED"] = "1"
    sys.path[:0] = [str(args.map_source / "backend"), str(args.runner_source)]
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from db import Base
    from models import (
        Authorization,
        AuthorizationTestCase,
        Engagement,
        ScanJob,
        ScopeItem,
    )
    from nm1_authorization import IssuanceRefused, prepare_approval_request
    from vardrrunner.authorization.codec import (
        AuthorizationError,
        TrustAnchor,
        digest,
        encoded,
    )
    from vardrrunner.authorization.contracts import ValidationContext, approve
    from vardrrunner.authorization.ledger import AuthorizationLedger
    from vardrrunner.authorization.plan import compile_gate_plan
    from vardrrunner.journal import Journal

    case = json.loads(
        (args.runner_source / "tests/fixtures/authorization/case.json").read_text()
    )
    execution = {}
    plan = compile_gate_plan(case, execution, tool_sha256="a" * 64)
    now = datetime(2026, 11, 1, 18, tzinfo=timezone.utc)
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all(
            [
                Engagement(
                    id="eng-1",
                    owner_github_id="operator-1",
                    name="NM1 synthetic",
                    engagement_type="pentest",
                    engagement_status="active",
                ),
                Authorization(
                    id="authority-1",
                    program_id="eng-1",
                    owner_github_id="operator-1",
                    status="active",
                    permits="Synthetic fixture only",
                    window_start=now - timedelta(hours=1),
                    window_end=now + timedelta(hours=1),
                ),
                AuthorizationTestCase(
                    id="case-1",
                    program_id="eng-1",
                    owner_github_id="operator-1",
                    name="NM1",
                    spec=case,
                ),
                ScanJob(
                    id="job-1",
                    program_id="eng-1",
                    owner_github_id="operator-1",
                    status="pending",
                    tool_type="vardrgate_api_test",
                    target_source="scope",
                    config={"test_case_id": "case-1"},
                ),
                ScopeItem(
                    program_id="eng-1",
                    value="api.example.test",
                    kind="domain",
                    scope_type="in",
                ),
            ]
        )
        db.commit()
        kwargs = dict(
            job_id="job-1",
            authorization_id="authority-1",
            actor={
                "github_id": "operator-1",
                "scope": "full",
                "auth_method": "local_session",
            },
            plan=plan,
            runner_id="runner-1",
            authority_revision=1,
            expires_at=now + timedelta(minutes=10),
            max_executions=2,
            max_duration_seconds=60,
            max_artifact_bytes=1000000,
            credential_grants=[
                {
                    "identity_id": "owner",
                    "source": "value_env",
                    "name": "NM1_OWNER",
                    "revision": 1,
                    "expires_at": "2026-11-01T19:00:00Z",
                }
            ],
            now=now,
        )
        request = prepare_approval_request(db, **kwargs)
        try:
            prepare_approval_request(
                db,
                **{
                    **kwargs,
                    "actor": {
                        "github_id": "operator-1",
                        "scope": "full",
                        "auth_method": "api_key",
                    },
                },
            )
        except IssuanceRefused:
            pass
        else:
            raise AssertionError("API key approved execution")
        assert not db.dirty and db.get(ScanJob, "job-1").status == "pending"
    engine.dispose()
    public = (
        Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        .public_key()
        .public_bytes_raw()
    )
    results = []
    with tempfile.TemporaryDirectory(prefix="nm1-cross-contract-") as directory:
        for kind in ("standalone", "map"):
            issuer = {"id": kind + "-issuer", "key_id": "test-only-key"}
            anchor = TrustAnchor(
                issuer["id"],
                issuer["key_id"],
                public,
                frozenset({"approval", "contract"}),
                frozenset({kind}),
            )
            permission = copy.deepcopy(request["context"])
            permission["control"] = (
                "local_offline" if kind == "standalone" else "managed_online"
            )
            approval = approve(
                permission,
                issuer,
                kind,
                "operator-1",
                "approval-1",
                "2026-11-01T17:59:00Z",
                bytes(range(32)),
            )
            ledger = AuthorizationLedger(Journal(Path(directory) / (kind + ".sqlite3")))
            ledger.set_state(
                issuer["id"], "eng-1", 1, False, permission["authority_sha256"]
            )
            context = ValidationContext(
                "runner-1",
                "eng-1",
                "job-1",
                "attempt-1",
                1,
                kind,
                now,
                1,
                "a" * 64,
                permission["authority_sha256"],
                managed_status_verified=(kind == "map"),
            )
            for ordinal in (1, 2):
                current = replace(
                    context, attempt_id="attempt-" + str(ordinal), fence=ordinal
                )
                contract = ledger.issue(
                    approval,
                    (anchor,),
                    issuer,
                    bytes(range(32)),
                    "contract-" + str(ordinal),
                    current.attempt_id,
                    current,
                    plan,
                    case,
                    execution,
                )
                completed = ledger.consume(
                    contract, approval, plan, case, execution, (anchor,), current
                )
                try:
                    ledger.consume(
                        contract, approval, plan, case, execution, (anchor,), current
                    )
                except AuthorizationError:
                    pass
                else:
                    raise AssertionError("contract replay executed")
                ledger.finish(completed)
            try:
                current = replace(context, attempt_id="attempt-3", fence=3)
                ledger.issue(
                    approval,
                    (anchor,),
                    issuer,
                    bytes(range(32)),
                    "contract-3",
                    current.attempt_id,
                    current,
                    plan,
                    case,
                    execution,
                )
            except AuthorizationError:
                pass
            else:
                raise AssertionError("approval count exceeded")
            results.append(
                {
                    "origin": kind,
                    "approved_executions": 2,
                    "single_use_verified": True,
                    "plan_sha256": digest(encoded(plan)),
                }
            )
    receipt = {
        "schema": "vardr.nm1-conformance-receipt/1",
        "results": results,
        "map_owner_snapshot_verified": True,
        "api_key_approval_denied": True,
        "network_requests": 0,
        "managed_control": "injected fixture only; NOT implemented or certified",
    }
    with args.out.open("x", encoding="utf-8") as out:
        json.dump(receipt, out, indent=2)
    print(
        "PASS: Map/standalone issuance, reusable bounded approval and replay checks; no target traffic"
    )


if __name__ == "__main__":
    main()
