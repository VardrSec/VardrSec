"""Trusted fixture metadata setup after an independently observed worker exit.

This constructor exercises installed SDK storage and recovery. The installed
controller must prove physical exit before calling it. It creates no execution
capability and never invokes a claim callback or native owner.
"""

from datetime import datetime, timezone
import json
import time
import uuid

from vardrrunner.authorization.claim import ClaimStore, PROFILE
from vardrrunner.authorization.codec import digest, encoded, require
from vardrrunner.authorization.plan import compile_gate_plan
from vardrrunner.authorization.reconciliation import local_holds, retire_preclaim
from vardrrunner.authorization.worker_admission import Admission
from vardrrunner.authorization.worker_binding import claim_association
from vardrrunner.authorization.worker_persistent import PersistentStore, parent
from vardrrunner.journal import Phase


COUNTS = {
    "results": "SELECT count(*) FROM managed_result_intents WHERE run_id=?",
    "stops": "SELECT count(*) FROM managed_stop_intents WHERE run_id=?",
    "ledger": "SELECT count(*) FROM authorization_contracts WHERE job=?",
}
TABLES = {
    "results": "managed_result_intents",
    "stops": "managed_stop_intents",
    "ledger": "authorization_contracts",
}


def snapshot(journal, run_id):
    """Read the exact synthetic association without reconstructing permission."""
    with journal._connection() as con:
        run = con.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        claim = con.execute(
            "SELECT * FROM managed_claim_intents WHERE run_id=?", (run_id,)
        ).fetchone()
        selected = con.execute(
            "SELECT * FROM managed_persistent_selections WHERE run_id=?", (run_id,)
        ).fetchone()
        require(
            run is not None and claim is not None and selected is not None,
            "fixture_source_missing",
        )
        runtime = parent(con, selected["runtime_id"])
        counts = {}
        for name, query in COUNTS.items():
            present = con.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (TABLES[name],),
            ).fetchone()
            argument = run["job_id"] if name == "ledger" else run_id
            counts[name] = (
                con.execute(query, (argument,)).fetchone()[0] if present else 0
            )
        return {
            "tombstone_sha256": digest(encoded({"run": dict(run), "claim": dict(claim), "selection": dict(selected)})),
            "run_id": run_id,
            "phase": run["phase"],
            "status": run["status"],
            "failure_reason": run["failure_reason"],
            "last_event": run["last_event"],
            "pid": run["pid"],
            "artifact_sha256": run["artifact_sha256"],
            "claim_state": claim["state"],
            "claim_authority": {
                key: claim[key] for key in ("issuer", "contract", "attempt", "fence")
            },
            "consumption_sent": claim["consumption_sent"],
            "consumption_acknowledged": claim["consumption_acknowledged"],
            "selection_state": selected["state"],
            "selection_sequence": selected["runtime_sequence"],
            "claim_link": claim_association(con, run_id),
            "parent_state": runtime["state"],
            "last_sequence": runtime["last_sequence"],
            "active_sequence": runtime["active_sequence"],
            "issued_attempts": con.execute(
                "SELECT count(*) FROM managed_persistent_attempts WHERE runtime_id=?",
                (runtime["runtime_id"],),
            ).fetchone()[0],
            **counts,
        }


def seed(
    journal,
    admission_document,
    *,
    engagement_id,
    job_id,
    case,
    execution,
    principal_sha256,
    tool_sha256,
):
    admission = Admission.parse(admission_document, now=datetime.now(timezone.utc))
    require(admission.mode == "persistent", "fixture_persistent_required")
    require(local_holds(journal) == 0, "fixture_existing_hold")
    store = PersistentStore(journal)
    with journal._connection() as con:
        runtime = parent(con, admission.runtime_id)
        require(
            runtime["state"] == "idle"
            and runtime["last_sequence"] == 0
            and runtime["active_sequence"] is None
            and runtime["history_head"] is None
            and runtime["admission_snapshot"] == encoded(admission_document).decode(),
            "fixture_original_idle_parent_required",
        )
    plan = compile_gate_plan(case, execution, tool_sha256=tool_sha256)
    fingerprints = {
        "plan_sha256": digest(encoded(plan)),
        "case_sha256": plan["case_hash"],
        "tool_sha256": plan["tool_sha256"],
        "association_sha256": digest(
            encoded(
                {
                    "origin": admission.origin,
                    "runner_id": admission.runner_id,
                    "principal_sha256": principal_sha256,
                }
            )
        ),
    }
    identity = {
        "backend_url": admission.origin,
        "job_id": job_id,
        "engagement_id": engagement_id,
        "job_type": "vardrgate_api_test",
        "tool": "vardrgate_api_test",
        "target_source": "case",
    }
    claim_store = ClaimStore(journal)
    record = journal.begin(
        **identity,
        command_profile={
            "controlled": True,
            "grant_policy": "expiring/1",
            "managed_profile": PROFILE,
            "managed_invocation": uuid.uuid4().hex,
            **fingerprints,
        },
    )
    owner = claim_store.reserve(record.run_id, fingerprints, identity)
    journal.transition(record.run_id, Phase.VALIDATING)
    journal.transition(record.run_id, Phase.TARGETS_RESOLVED)
    claim_store.prepare_send(
        record.run_id,
        owner,
        datetime.now(timezone.utc),
        time.monotonic(),
        lambda con, run_id: store.prepare_selection(
            con,
            run_id,
            runtime_id=admission.runtime_id,
            runtime_sha256=admission.runtime_sha256,
            runtime_sequence=1,
            runner_id=admission.runner_id,
            enrollment_id=admission.enrollment_id,
            admission_sha256=admission.admission_sha256,
        ),
    )
    # This fixture constructor has no claim callback. Preserve its known no-send
    # marker. This caller also knows no native epoch ever entered, so it can use
    # the existing source-only selection close. Parent retirement still requires
    # the original-key observation of physical exit.
    claim_store.hold(record.run_id, owner, "denied_before_rpc")
    require(
        retire_preclaim(journal, record.run_id) == "local_preclaim_retired",
        "fixture_source_retirement",
    )
    selected = snapshot(journal, record.run_id)
    require(local_holds(journal) > 0, "fixture_selected_hold_missing")
    store.retire_selection(record.run_id)
    result = snapshot(journal, record.run_id)
    require(
        result["phase"] == "failed"
        and result["status"] == "not_claimed"
        and result["failure_reason"] == "local_preclaim_denied_before_rpc"
        and result["last_event"] == "managed_preclaim_retired"
        and selected["selection_state"] == "selected"
        and result["selection_state"] == "preclaim_retired"
        and result["pid"] is None
        and result["artifact_sha256"] is None
        and all(value is None for value in result["claim_authority"].values())
        and all(
            result[name] == 0
            for name in (
                "consumption_sent",
                "consumption_acknowledged",
                "issued_attempts",
                "last_sequence",
                "results",
                "stops",
                "ledger",
            )
        )
        and result["active_sequence"] is None
        and local_holds(journal) == 0,
        "fixture_no_send_not_proven",
    )
    return {
        "schema": "vardr.nm2-preclaim-setup/1",
        "kind": "trusted_synthetic",
        "selected": selected,
        "closed": result,
    }


def main():
    import hashlib
    from pathlib import Path
    import sys
    from vardrrunner import config, identity
    from vardrrunner.authorization.codec import decoded
    from vardrrunner.journal import Journal, journal_path_identity

    selection = decoded(sys.stdin.buffer.read(512001), 512000)
    if sys.argv[1:] == ["snapshot"]:
        require(set(selection) == {"run_id"}, "fixture_inputs")
        print(
            json.dumps(
                snapshot(
                    Journal.open_existing(config.journal_file(), expected_identity=journal_path_identity(config.journal_file())), selection["run_id"]
                ),
                sort_keys=True,
            )
        )
        return
    require(not sys.argv[1:], "fixture_inputs")
    require(
        set(selection) == {"admission", "engagement_id", "job_id", "case", "execution"},
        "fixture_inputs",
    )
    url, key = config.require_auth()
    admission = Admission.parse(selection["admission"], now=datetime.now(timezone.utc))
    require(url == admission.origin, "configured_origin_required")
    require(
        identity.read_existing(identity.identity_file()).runner_id
        == admission.runner_id,
        "fixture_original_identity",
    )
    result = seed(
        Journal.open_existing(config.journal_file(), expected_identity=journal_path_identity(config.journal_file())),
        selection["admission"],
        **{
            key: selection[key]
            for key in ("engagement_id", "job_id", "case", "execution")
        },
        principal_sha256=digest(("Bearer " + key).encode()),
        tool_sha256=hashlib.sha256(
            Path("/usr/local/bin/vardrgate").read_bytes()
        ).hexdigest(),
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    import sys

    try:
        main()
    except Exception:
        print("preclaim_fixture_setup_refused", file=sys.stderr)
        raise SystemExit(1) from None
