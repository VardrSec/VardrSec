"""Test-only selected-record PostgreSQL observation; no auth or execution API.

The harness feeds exact fixture engagement/job IDs over stdin and runs this in a
separate existing Map metadata process. No tokens, envelopes or secrets leave
the database. The transaction is explicitly read-only and always rolled back.
"""

import json
import hashlib
import re
import sys
from datetime import timezone

from sqlalchemy import text

from db import SessionLocal
from models import (
    Engagement,
    JobExecution,
    ManagedApproval,
    ManagedContract,
    ManagedResult,
    ManagedRuntime,
    ManagedRuntimeAttempt,
    ManagedStop,
    ScanJob,
)


def stamp(value):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def runtime_projection(db, runtime):
    attempts = (
        db.query(ManagedRuntimeAttempt)
        .filter_by(runtime_id=runtime.id)
        .order_by(ManagedRuntimeAttempt.runtime_sequence)
        .limit(33)
        .all()
    )
    if len(attempts) > 32:
        raise ValueError("fixture_runtime_history_bound")
    return {
        "id": runtime.id,
        "runtime_sha256": runtime.runtime_sha256,
        "runner_id": runtime.runner_id,
        "enrollment_id": runtime.enrollment_id,
        "identity": runtime.identity,
        "max_attempts": runtime.max_attempts,
        "last_sequence": runtime.last_sequence,
        "active_sequence": runtime.active_sequence,
        "retired": runtime.retired,
        "report_sha256": runtime.report_sha256,
        "legacy_binding": {
            key: getattr(runtime, key)
            for key in (
                "job_id",
                "contract_id",
                "attempt_id",
                "fence",
                "contract_sha256",
            )
        }
        | {
            "bound_at": stamp(runtime.bound_at),
            "confirmed_at": stamp(runtime.confirmed_at),
        },
        "attempts": [
            {
                "runtime_id": row.runtime_id,
                "runtime_sequence": row.runtime_sequence,
                "job_id": row.job_id,
                "binding": {
                    "origin": runtime.origin,
                    "runner_id": runtime.runner_id,
                    **{
                        key: getattr(row, key)
                        for key in (
                            "job_id",
                            "contract_id",
                            "attempt_id",
                            "fence",
                            "contract_sha256",
                        )
                    },
                },
                "bound_at": stamp(row.bound_at),
                "confirmed_at": stamp(row.confirmed_at),
                "released_at": stamp(row.released_at),
                "terminal_receipt": row.terminal_receipt,
                "terminal_receipt_sha256": row.terminal_receipt_sha256,
                "native_done_sha256": row.native_done_sha256,
                "release_receipt": row.release_receipt,
            }
            for row in attempts
        ],
    }


def observe(selection):
    if set(selection) != {"engagement_id", "job_id"} or any(
        not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value)
        for value in selection.values()
    ):
        raise ValueError("fixture_selection_refused")
    with SessionLocal() as db:
        try:
            db.execute(text("SET TRANSACTION READ ONLY"))
            engagement = db.get(Engagement, selection["engagement_id"])
            job = db.get(ScanJob, selection["job_id"])
            if engagement is None or job is None or job.program_id != engagement.id:
                raise ValueError("fixture_association_refused")
            execution = db.get(JobExecution, job.id)
            contracts = db.query(ManagedContract).filter_by(job_id=job.id).all()
            approvals = db.query(ManagedApproval).filter_by(job_id=job.id).all()
            results = db.query(ManagedResult).filter_by(job_id=job.id).all()
            stops = db.query(ManagedStop).filter_by(job_id=job.id).all()
            selected_attempts = (
                db.query(ManagedRuntimeAttempt).filter_by(job_id=job.id).all()
            )
            runtimes = [
                db.get(ManagedRuntime, runtime_id)
                for runtime_id in sorted({row.runtime_id for row in selected_attempts})
            ]
            if any(runtime is None for runtime in runtimes):
                raise ValueError("fixture_runtime_history_incomplete")
            return {
                "schema": "vardr.nm2-fixture-inventory/2",
                "schema_revision": db.execute(
                    text("SELECT version_num FROM alembic_version")
                ).scalar_one(),
                "database_user": db.execute(text("SELECT current_user")).scalar_one(),
                **selection,
                "job_status": job.status,
                "targets_spent": engagement.targets_spent,
                "duration_allocated": engagement.duration_allocated,
                "execution": None
                if execution is None
                else {
                    key: getattr(execution, key)
                    for key in (
                        "state",
                        "capacity_reserved",
                        "target_charge",
                        "duration_seconds",
                    )
                },
                "approvals": [
                    {"id": row.id, "issued": row.issued, "revoked": row.revoked}
                    for row in approvals
                ],
                "contracts": [
                    {
                        key: getattr(row, key)
                        for key in ("id", "attempt_id", "ordinal", "fence", "consumed")
                    }
                    | {
                        "contract_sha256": hashlib.sha256(
                            json.dumps(
                                row.envelope, sort_keys=True, separators=(",", ":")
                            ).encode()
                        ).hexdigest()
                    }
                    for row in contracts
                ],
                "results": [
                    {
                        key: getattr(row, key)
                        for key in (
                            "contract_id",
                            "artifact_sha256",
                            "receipt_sha256",
                            "outcome",
                            "evidence_created",
                            "scan_items_created",
                        )
                    }
                    for row in results
                ],
                "stops": [
                    {
                        key: getattr(row, key)
                        for key in ("contract_id", "receipt_sha256", "outcome", "cause")
                    }
                    for row in stops
                ],
                "runtimes": [runtime_projection(db, runtime) for runtime in runtimes],
            }
        finally:
            db.rollback()


if __name__ == "__main__":
    raw = sys.stdin.buffer.read(1025)
    if len(raw) > 1024:
        raise ValueError("fixture_selection_refused")
    print(json.dumps(observe(json.loads(raw))))
