"""Synthetic persistent worker records shared by producer and receipt-reader tests."""

from copy import deepcopy

from worker_host import digest
from worker_host_persistent import _purpose


def set_digest(record, field):
    payload = {key: value for key, value in record.items() if key != field}
    record[field] = digest(payload)


def exit_report_digest(physical, *, last_sequence="1"):
    observation = {key: physical[key] for key in ("identity", "finished_at", "exit_code")}
    report = {
        key: physical[key]
        for key in ("runtime_sha256", "admission_sha256", "finished_at", "exit_code")
    }
    report.update(observation_sha256=digest(observation), last_sequence=last_sequence)
    return _purpose({"runtime_id": physical["runtime_id"]}, report)


def retirement_record(admission, report, *, last_sequence="1"):
    binding = {
        key: admission[key]
        for key in ("runtime_id", "runtime_sha256", "admission_sha256", "origin", "runner_id", "enrollment_id")
    }
    receipt = {
        "schema": "vardr.worker-retirement/3",
        **binding,
        "runtime_sequence": None,
        "last_sequence": last_sequence,
        "binding": None,
        "attempt_receipt": None,
        "report_sha256": report,
        "retired": True,
    }
    set_digest(receipt, "receipt_sha256")
    return receipt


def pending_inventory(inventory):
    pending = deepcopy(inventory)
    pending.update(
        job_status="pending",
        execution=None,
        targets_spent=0,
        duration_allocated=0,
        contracts=[],
        results=[],
        stops=[],
        runtimes=[],
    )
    pending["approvals"][0]["issued"] = 0
    return pending


def retained_after_exit(local, retirement):
    retained = deepcopy(local)
    retained.update(state="retired", retirement=retirement)
    retained["attempt"].update(state="physical_retirement_observed", retired_from_state="released")
    return retained
