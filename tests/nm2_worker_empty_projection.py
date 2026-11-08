"""Independent zero-issued-job explicit-stop reader; no execution or SQL.

An empty local parent is not physical or server retirement. Both independent
host proofs remain required; there is no original RunRecord to reconcile.
"""

from datetime import datetime
from pathlib import PurePosixPath, PureWindowsPath
import re

import nm2_worker_acceptance as fixture
import nm2_worker_count_projection as fixed
import nm2_worker_persistent_projection as common
import worker_host as host
import worker_host_persistent as persistent

SCENARIO = "persistent-empty-stop"
CASE = "persistent_empty_stop"
CASES = set(fixture.INITIAL_CASES) | {CASE}
LIMITS = {"max_attempts": None, "idle_timeout_seconds": None}


def envelope(raw, selection, desktop):
    common.require(type(raw) is dict and type(selection) is dict
                   and len(host.canonical(raw)) <= 4 * 1024 * 1024)
    common.require(raw["schema"] == "vardr.nm2-worker-empty-acceptance/1"
        and raw["status"] == "selected_empty_stop_slice_passed"
        and raw["stage"] == "selected_empty_stop_complete"
        and raw["scenario"] == SCENARIO
        and raw["acceptance_scope"] == "persistent_empty_stop_only"
        and raw["nm2_exit_status"] == "incomplete"
        and raw["platform"] == ("win32" if desktop else "linux")
        and raw["retained"] is True)
    common.fields(selection["sources"], fixture.SOURCE_NAMES)
    for row in selection["sources"].values():
        common.fields(row, {"path", "commit"})
        common.require(type(row["path"]) is str and type(row["commit"]) is str
            and re.fullmatch(r"[a-f0-9]{40}", row["commit"]))
        if desktop:
            path = PureWindowsPath(row["path"])
            common.require(path.is_absolute() and ".." not in path.parts)
        else:
            common.require(row["path"].startswith("/"))
    common.fields(selection["images"], fixture.IMAGE_NAMES)
    for image in selection["images"].values():
        common.require(type(image) is str and re.fullmatch(r"sha256:[a-f0-9]{64}", image))
    common.require(type(selection["project"]) is str
        and re.fullmatch(r"vardrsec-nm2-[a-z0-9]{8,24}", selection["project"])
        and type(selection["https_port"]) is int and 1 <= selection["https_port"] <= 65535)
    for key in ("sources", "images", "project"):
        common.same(raw[key], selection[key])
    common.require(raw["readiness_volume"] == selection["project"] + "_worker-ready"
        and raw["expected_database_revision"] == "0041persistentruntime"
        and (desktop or raw["admitted_inventory_diffs"] == []))
    for key in ("before_sha256", "after_sha256", "public_ca_der_sha256"):
        host._hash(raw[key])
    cases = common.fields(raw["cases"], CASES)
    disabled = common.fields(cases["default_disabled"], {"status", "services",
        "managed_pending_status", "csrf_write_status", "unauthenticated_read_status"})
    common.require(disabled["status"] == "passed" and type(disabled["services"]) is list
        and sorted(disabled["services"]) == ["api", "db", "proxy", "web"])
    for key, code in (("managed_pending_status", 404), ("csrf_write_status", 403),
                      ("unauthenticated_read_status", 401)):
        common.integer(disabled[key], code)
    for name in fixture.INITIAL_CASES[1:]:
        common.same(cases[name], {"status": "not_run"})
    return cases[CASE]


def audit(value, admission):
    # Deliberately independent of the fixture's producer validator.
    common.fields(value, {"schema", "status", "reason", "complete", "binding", "parent",
        "counts", "global_holds", "retirement_receipt_sha256"})
    common.require(value["schema"] == "vardr.worker-state-audit/1"
        and value["status"] == "empty_unissued" and value["reason"] is None
        and value["complete"] is True and value["retirement_receipt_sha256"] is None)
    common.same(value["binding"], {key:admission[key] for key in (
        "runner_id", "runtime_id", "runtime_sha256", "admission_sha256")})
    common.same(value["parent"], {"state":"idle", "last_sequence":"0",
        "head_sequence":None, "active_sequence":None})
    counts = common.fields(value["counts"], {"attempts", "selections", "associated_runs", "associated_claims"})
    for number in [*counts.values(), value["global_holds"]]:
        common.integer(number, 0)


def presence(value, *, cursor, state, physical, allow_missing=False, sampled_at=None):
    common.fields(value, {"state", "observed_at", "fresh_until", "cursor"})
    common.require(value["state"] == state)
    common.same(value["cursor"], cursor)
    if value["observed_at"] is None:
        common.require(allow_missing and value["fresh_until"] is None)
    else:
        observed = persistent._stamp(value["observed_at"])
        ending = persistent._stamp(value["fresh_until"])
        common.require(0 < (ending-observed).total_seconds() <= 15)
        common.require(common.stamp(physical["identity"]["started_at"], physical=True)
            <= common.stamp(value["observed_at"], physical=True)
            <= common.stamp(physical["finished_at"], physical=True))
        if sampled_at is not None:
            sample = common.stamp(sampled_at, physical=True)
            common.require(common.stamp(physical["identity"]["started_at"], physical=True)
                <= sample <= common.stamp(physical["finished_at"], physical=True))
            common.require(common.stamp(value["observed_at"], physical=True)
                <= sample < common.stamp(value["fresh_until"], physical=True))


def audit_volumes(values, admission, project):
    common.require(type(values) is list and len(values) == 2)
    original = None
    for pair in values:
        common.fields(pair, {"before", "after"})
        for value in pair.values():
            common.fields(value, {"daemon_id", "endpoint", "root", "name", "driver", "scope",
                "options", "source", "created_at", "project", "volume"})
            common.require(value["daemon_id"] == admission["identity"]["daemon_id"]
                and type(value["endpoint"]) is str and value["endpoint"].startswith(("unix:///", "npipe:////"))
                and value["name"] == project + "_runner-state"
                and value["project"] == project and value["volume"] == "runner-state"
                and value["driver"] == value["scope"] == "local"
                and value["options"] in (None, {}))
            for key in ("source", "root"):
                path = value[key]
                common.require(type(path) is str and 1 < len(path) <= 4096
                    and not any(ord(c) < 32 or ord(c) == 127 or c == "\\" for c in path)
                    and PurePosixPath(path).is_absolute() and PurePosixPath(path).root == "/"
                    and ".." not in PurePosixPath(path).parts and str(PurePosixPath(path)) == path)
            common.require(PurePosixPath(value["source"])
                == PurePosixPath(value["root"]) / "volumes" / value["name"] / "_data"
                and type(value["created_at"]) is str and 1 <= len(value["created_at"]) <= 64)
            common.require(datetime.fromisoformat(value["created_at"].replace("Z", "+00:00")).tzinfo is not None)
            if original is None:
                original = value
            common.same(value, original)


def _project(raw, selection, *, desktop=False):
    case = common.fields(envelope(raw, selection, desktop), {"status", "limits", "physical", "proof"})
    common.require(case["status"] == "passed")
    common.same(case["limits"], LIMITS)
    proof = common.fields(case["proof"], {"admission", "status", "audit_before", "audit_after",
        "engagements_before", "engagements_after", "traffic_before", "traffic_after",
        "operator_stop", "retirement", "host_reconciled", "audit_volumes", "status_observed_at"})
    admission = proof["admission"]
    record = {"runtime_id":admission["runtime_id"],
        "registration":{key:admission[key] for key in persistent.REGISTRATION}}
    persistent.admission(record, admission)
    common.same(admission["limits"], LIMITS)
    common.require(admission["origin"] == f"https://vardrsec.localhost:{selection['https_port']}/backend"
        and admission["identity"]["project"] == selection["project"]
        and admission["identity"]["image_id"] == selection["images"]["worker"])
    physical = common.fields(case["physical"], {"identity", "runtime_id", "runtime_sha256",
        "admission_sha256", "exit_code", "finished_at", "operator_enable_state", "operator_stop_state"})
    common.same(physical["identity"], admission["identity"])
    for key in ("runtime_id", "runtime_sha256", "admission_sha256"):
        common.same(physical[key], admission[key])
    common.require(type(physical["exit_code"]) is int and 0 <= physical["exit_code"] <= 255
        and physical["operator_enable_state"] == "enabled"
        and physical["operator_stop_state"] == "stopped_observed")
    common.require(common.stamp(physical["identity"]["started_at"], physical=True)
                   < common.stamp(physical["finished_at"], physical=True))
    executables, source_inventories = fixed.source_cleanup(raw, selection, physical)
    common.require(physical["identity"]["container_id"] not in raw["fixture_stop"]["stop_requested_ids"])
    stop = common.fields(proof["operator_stop"], {"schema", "state", "runtime_id", "identity",
        "exit_code", "finished_at", "new_work_disable_state", "local_runner_reconciliation"})
    common.require(stop["schema"] == "vardr.worker-cli/1" and stop["state"] == "stopped_observed"
        and stop["new_work_disable_state"] == "acknowledged"
        and stop["local_runner_reconciliation"] == "required")
    for key in ("identity", "runtime_id", "exit_code", "finished_at"):
        common.same(stop[key], physical[key])
    status = common.fields(proof["status"], {"schema", "runtime_id", "protocol", "mode", "limits",
        "identity", "state", "reason", "cursor", "availability", "new_work_disabled",
        "reporting_revoked", "registration_state", "disable_state", "stop_state",
        "revocation_state", "container_state"})
    common.require(status["schema"] == "vardr.worker-status/1" and status["protocol"] == "persistent-v3"
        and status["mode"] == "persistent" and status["state"] == "idle-ready"
        and status["reason"] is None and status["container_state"] == "running"
        and status["runtime_id"] == admission["runtime_id"]
        and status["new_work_disabled"] is False and status["reporting_revoked"] is False
        and status["registration_state"] == "acknowledged"
        and status["disable_state"] == status["stop_state"] == status["revocation_state"] == "none")
    common.same(status["identity"], admission["identity"])
    common.same(status["limits"], LIMITS)
    cursor = {"last_sequence":"0", "phase":"idle"}
    common.same(status["cursor"], cursor)
    common.require(type(proof["status_observed_at"]) is str)
    presence(status["availability"], cursor=cursor, state="idle-ready", physical=physical,
             sampled_at=proof["status_observed_at"])
    for key in ("audit_before", "audit_after"):
        audit(proof[key], admission)
    common.same(proof["audit_before"], proof["audit_after"])
    audit_volumes(proof["audit_volumes"], admission, selection["project"])
    for key in ("engagements_before", "engagements_after"):
        common.same(proof[key], {"engagements":[], "programs":[]})
    for key in ("traffic_before", "traffic_after"):
        common.same(proof[key], [])
    body = {key:physical[key] for key in ("runtime_sha256", "admission_sha256", "finished_at", "exit_code")}
    body.update(last_sequence="0", observation_sha256=host.digest({
        key:physical[key] for key in ("identity", "finished_at", "exit_code")}))
    expected = {"schema":"vardr.worker-retirement/3",
        **{key:admission[key] for key in ("runtime_id", "runtime_sha256", "admission_sha256", "origin", "runner_id", "enrollment_id")},
        "runtime_sequence":None, "last_sequence":"0", "binding":None, "attempt_receipt":None,
        "report_sha256":persistent._purpose(record, body), "retired":True}
    expected["receipt_sha256"] = host.digest(expected)
    persistent.retirement(record, proof["retirement"])
    common.same(proof["retirement"], expected)
    reconciled = common.fields(proof["host_reconciled"], {"schema", "state", "runtime_id", "receipt", "local_runner_reconciliation"})
    common.require(reconciled["schema"] == "vardr.worker-cli/1"
        and reconciled["state"] == "terminal_observed" and reconciled["runtime_id"] == admission["runtime_id"]
        and reconciled["local_runner_reconciliation"] == "required")
    lookup = common.fields(reconciled["receipt"], {"schema", "runtime_id", "runtime_sha256",
        "admission_sha256", "cursor", "active", "retirement", "new_work_disabled", "reporting_revoked", "availability"})
    common.require(lookup["schema"] == "vardr.worker-receipt-observation/3" and lookup["active"] is None
        and lookup["new_work_disabled"] is True and lookup["reporting_revoked"] is False)
    for key in ("runtime_id", "runtime_sha256", "admission_sha256"):
        common.same(lookup[key], admission[key])
    common.same(lookup["retirement"], expected)
    common.same(lookup["cursor"], cursor)
    presence(lookup["availability"], cursor=cursor, state="stopped", physical=physical, allow_missing=True)
    return {"schema":"vardr.nm2-worker-empty-public/1", "status":"selected_empty_stop_slice_passed",
        "nm2_exit_status":"incomplete", "remaining_matrix_status":"not_closed",
        "cases":{name:"passed" if name in {"default_disabled", CASE} else "not_run" for name in sorted(CASES)},
        "measurements":{"issued_attempts":0, "associated_runs":0, "associated_claims":0,
            "target_request_count":0, "engagement_count":0, "remaining_local_holds":0,
            "limits":LIMITS, "last_sequence":"0", "local_retirement":"not_applicable_empty_unissued",
            "operator_stop_requested":True, "stopped_owned_container_count":6,
            "runtime_sha256":admission["runtime_sha256"], "admission_sha256":admission["admission_sha256"],
            "retirement_receipt_sha256":expected["receipt_sha256"], "public_ca_der_sha256":raw["public_ca_der_sha256"]},
        "executables":{"native_owner_sha256":executables["/usr/local/bin/vardr-worker-owner"],
            "gate_sha256":executables["/usr/local/bin/vardrgate"]}, "source_inventories":source_inventories}


def project(raw, selection):
    try:
        return _project(raw, selection)
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, OverflowError, RecursionError):
        raise common.ProjectionRefused("nm2_empty_projection_refused") from None


def project_desktop(raw, selection, before, after):
    try:
        result = _project(raw, selection, desktop=True)
        guard = common._desktop_inventory(raw, selection, before, after, raw["cases"][CASE]["physical"])
        return {**result, "schema":"vardr.nm2-worker-empty-desktop-public/1", "platform":"win32",
                "container_platform":"linux", "inventory_guard":guard}
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, OverflowError, RecursionError):
        raise common.ProjectionRefused("nm2_empty_projection_refused") from None
