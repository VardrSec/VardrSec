"""Test-only selected-record PostgreSQL observation; no auth or execution API.

The harness feeds exact fixture engagement/job IDs over stdin and runs this in a
separate existing Map metadata process. No tokens, envelopes or secrets leave
the database. The transaction is explicitly read-only and always rolled back.
"""

import json
import re
import sys

from sqlalchemy import text

from db import SessionLocal
from models import (
    Engagement,
    JobExecution,
    ManagedApproval,
    ManagedContract,
    ManagedResult,
    ManagedRuntime,
    ManagedStop,
    ScanJob,
)


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
            runtimes = db.query(ManagedRuntime).filter_by(job_id=job.id).all()
            return {
                "schema": "vardr.nm2-fixture-inventory/1",
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
                "runtimes": [
                    {
                        key: getattr(row, key)
                        for key in (
                            "id",
                            "runtime_sha256",
                            "contract_id",
                            "retired",
                            "report_sha256",
                        )
                    }
                    | {"confirmed": row.confirmed_at is not None}
                    for row in runtimes
                ],
            }
        finally:
            db.rollback()


if __name__ == "__main__":
    raw = sys.stdin.buffer.read(1025)
    if len(raw) > 1024:
        raise ValueError("fixture_selection_refused")
    print(json.dumps(observe(json.loads(raw))))
