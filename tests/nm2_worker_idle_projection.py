"""Strict optional60s idle-control correlation; never35/count proof or execution.

The producer checked evidence bodies; only their measured digests leave this reader.
"""

import math
from pathlib import PureWindowsPath
import re

import nm2_worker_acceptance as fixture
import nm2_worker_count_projection as fixed
import nm2_worker_persistent_projection as common
import worker_host as host
import worker_host_persistent as persistent

SCENARIO = "persistent-idle-limit"
CASE = "persistent_idle_limit"
CASES = set(fixture.INITIAL_CASES) | {CASE}
LIMITS = {"max_attempts": None, "idle_timeout_seconds": 60}


def expected_case():
    # Rebuild exclusively from the reviewed source; never adapt a proof's spec.
    spec = fixed.expected_case("count-a")
    spec["id"] = "nm2-idle-control"
    for request in [spec["request"]] + [
        row["preflight"] for row in spec["identities"] if "preflight" in row
    ]:
        request["url"] = request["url"].replace("nm2_case=count-a", "nm2_case=idle-control")
    return spec


def envelope(raw, selection, desktop):
    common.require(type(raw) is dict and type(selection) is dict
                   and len(host.canonical(raw)) <= 4 * 1024 * 1024)
    common.require(raw["schema"] == "vardr.nm2-worker-idle-acceptance/1"
        and raw["status"] == "selected_idle_control_slice_passed"
        and raw["stage"] == "selected_idle_control_complete"
        and raw["scenario"] == SCENARIO
        and raw["acceptance_scope"] == "persistent_idle_control_only"
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
    disabled = common.fields(cases["default_disabled"], {
        "status", "services", "managed_pending_status", "csrf_write_status",
        "unauthenticated_read_status"})
    common.require(disabled["status"] == "passed" and type(disabled["services"]) is list
        and sorted(disabled["services"]) == ["api", "db", "proxy", "web"])
    for key, code in (("managed_pending_status", 404), ("csrf_write_status", 403),
                      ("unauthenticated_read_status", 401)):
        common.integer(disabled[key], code)
    denied = common.fields(cases["strict_out_of_scope"], {
        "status", "approval_http_status", "inventory", "traffic_delta"})
    common.require(denied["status"] == "passed")
    common.integer(denied["approval_http_status"], 409)
    common.integer(denied["traffic_delta"], 0)
    inv = common.fields(denied["inventory"], common.INVENTORY | {
        "runtimes", "approval_context_sha256"})
    common.require(inv["schema"] == "vardr.nm2-fixture-inventory/4"
        and inv["schema_revision"] == "0041persistentruntime"
        and inv["database_user"] == "vardrmap_app"
        and inv["job_status"] == "pending" and inv["execution"] is None)
    common.integer(inv["runtime_attempt_bound"], 35)
    for key in ("engagement_id", "job_id"):
        host._identifier(inv[key])
    for key in ("approvals", "contracts", "results", "stops", "runtimes"):
        common.same(inv[key], [])
    common.same(inv["approval_context_sha256"], {})
    for key in ("targets_spent", "duration_allocated"):
        common.integer(inv[key], 0)
    for name in fixture.INITIAL_CASES[2:]:
        common.same(cases[name], {"status": "not_run"})
    return cases[CASE]


def statuses(proof, admission, physical):
    fields = {"schema", "runtime_id", "protocol", "mode", "limits", "identity",
        "state", "reason", "cursor", "availability", "new_work_disabled",
        "reporting_revoked", "registration_state", "disable_state", "stop_state",
        "revocation_state", "container_state"}
    before = common.fields(proof["status_before_idle"], fields)
    after = common.fields(proof["status_after_idle"], fields | {"exit_code", "finished_at"})
    for value in (before, after):
        common.require(value["schema"] == "vardr.worker-status/1"
            and value["protocol"] == "persistent-v3" and value["mode"] == "persistent"
            and value["runtime_id"] == admission["runtime_id"]
            and value["registration_state"] == "acknowledged"
            and value["disable_state"] == value["stop_state"]
            == value["revocation_state"] == "none" and value["reason"] is None)
        common.same(value["identity"], admission["identity"])
        common.same(value["limits"], LIMITS)
    common.require(before["state"] == "idle-ready" and before["container_state"] == "running"
        and before["new_work_disabled"] is False and before["reporting_revoked"] is False)
    common.same(before["cursor"], {"last_sequence": "1", "phase": "idle"})
    presence = common.fields(before["availability"], {"state", "observed_at", "fresh_until", "cursor"})
    common.same(presence["cursor"], before["cursor"])
    common.require(presence["state"] == "idle-ready")
    observed, ending = persistent._stamp(presence["observed_at"]), persistent._stamp(presence["fresh_until"])
    common.require(0 < (ending-observed).total_seconds() <= 15)
    common.require(after["state"] == "stopped" and after["container_state"] == "exited")
    common.integer(after["exit_code"], 124)
    for key in ("exit_code", "finished_at"):
        common.same(after[key], physical[key])
    for key in ("cursor", "availability", "new_work_disabled", "reporting_revoked"):
        common.require(after[key] is None)
    elapsed = proof["observation_seconds"]
    common.require(type(elapsed) in {int, float} and math.isfinite(elapsed) and 0 < elapsed <= 75)
    common.require(common.stamp(admission["identity"]["started_at"], physical=True)
                   <= common.stamp(presence["observed_at"], physical=True)
                   <= common.stamp(physical["finished_at"], physical=True))


def _project(raw, selection, *, desktop=False):
    case = common.fields(envelope(raw, selection, desktop), {"status", "limits", "physical", "proof"})
    common.require(case["status"] == "passed")
    common.same(case["limits"], LIMITS)
    proof = common.fields(case["proof"], {"admission", "local", "inventory_before_idle",
        "traffic_before_idle", "status_before_idle", "status_after_idle", "observation_seconds",
        "after_idle", "inventory_after_idle", "traffic_after_idle", "fixed", "measured",
        "inventory", "retirement", "retained", "reconciled", "selection"})
    admission = proof["admission"]
    record = {"runtime_id": admission["runtime_id"],
              "registration": {k: admission[k] for k in persistent.REGISTRATION}}
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
    common.integer(physical["exit_code"], 124)
    common.require(physical["operator_enable_state"] == "enabled"
        and physical["operator_stop_state"] == "not_requested")
    statuses(proof, admission, physical)
    executables, source_inventories = fixed.source_cleanup(raw, selection, physical)
    common.require(physical["identity"]["container_id"] not in raw["fixture_stop"]["stop_requested_ids"])
    original = proof["selection"]
    checked = common.fields(proof["fixed"], {"status", "physical", "before_worker", "inventory",
        "requests", "case_sha256", "evidence_count", "evidence_sha256"})
    _, plan, approval = fixed._review_fixed_spec(original, admission, checked["before_worker"],
        executables["/usr/local/bin/vardrgate"], selection["project"], expected_spec=expected_case())
    common.require(original["case_spec"]["id"] == "nm2-idle-control")
    started = common.stamp(physical["identity"]["started_at"], physical=True)
    common.require(common.stamp(approval["approved_at"], physical=True) <= started)
    inventory = common.fields(proof["inventory"], common.INVENTORY | {"runtimes", "approval_context_sha256"})
    fixture.count_approval_context(inventory, original["review_context"])
    common.require(type(inventory["runtimes"]) is list and len(inventory["runtimes"]) == 1)
    runtime = common.fields(inventory["runtimes"][0], common.RUNTIME)
    for key in ("runtime_sha256", "admission_sha256", "runner_id", "enrollment_id"):
        common.same(runtime[key], admission[key])
    common.same(runtime["identity"], admission["identity"])
    common.same(runtime["admission"], admission)
    common.require(runtime["id"] == admission["runtime_id"] and runtime["mode"] == "persistent"
        and runtime["max_attempts"] is None and runtime["last_sequence"] == runtime["head_sequence"] == "1"
        and runtime["active_sequence"] is None and runtime["retired"] is True
        and runtime["new_work_disabled"] is True and runtime["reporting_revoked"] is False
        and type(runtime["attempts"]) is list and len(runtime["attempts"]) == 1)
    common.fields(runtime["legacy_binding"], {"job_id", "contract_id", "attempt_id", "fence",
        "contract_sha256", "bound_at", "confirmed_at"})
    common.require(all(item is None for item in runtime["legacy_binding"].values()))
    measured = common.fields(proof["measured"], common.ATTEMPT - {"local"})
    value = {**measured, "local": proof["local"]}
    bounds, _ = common._job(value, {k:v for k,v in inventory.items() if k != "runtimes"},
        runtime["attempts"][0], admission, record, 1,
        request_check=lambda: fixed.request_bounds(measured["requests"], plan), count_inventory=True)
    common.require(measured["job_id"] == original["job_id"]
        and measured["engagement_id"] == original["engagement_id"]
        and measured["case_sha256"] == host.digest(expected_case()))
    common.grants(value, inventory, admission, bounds[0], bounds[2])
    for grant in proof["local"]["grants"]["grants"]:
        common.catalog_stamp(grant["issued_at"])
        common.require(common.stamp(grant["issued_at"][:-6]+"Z", physical=True) <= started)
    common.require(started <= common.stamp(measured["bound_at"], physical=True)
        <= common.stamp(measured["released_at"], physical=True)
        <= common.stamp(physical["finished_at"], physical=True))
    common.require(len(inventory["approvals"]) == 1)
    common.same(inventory["approvals"][0], {**approval, "issued": 1})
    before_idle = proof["inventory_before_idle"]
    common.same(before_idle, proof["inventory_after_idle"])
    common.same(before_idle, {**inventory, "runtimes": [{**runtime,
        "retired": False, "new_work_disabled": False, "report_sha256": None}]})
    common.local(proof["after_idle"], admission, 1)
    common.same(proof["after_idle"], {k:v for k,v in proof["local"].items() if k != "grants"})
    for key in ("traffic_before_idle", "traffic_after_idle"):
        common.same(proof[key], measured["requests"])
    common.same(checked, {"status":"passed", "physical":physical,
        "before_worker": checked["before_worker"], "inventory": inventory,
        "requests": measured["requests"], "case_sha256": measured["case_sha256"],
        "evidence_count":5, "evidence_sha256":measured["evidence_sha256"]})
    report_body = {k:physical[k] for k in ("runtime_sha256", "admission_sha256", "finished_at", "exit_code")}
    report_body.update(last_sequence="1", observation_sha256=host.digest({
        k:physical[k] for k in ("identity", "finished_at", "exit_code")}))
    report_hash = persistent._purpose(record, report_body)
    expected_retirement = {"schema":"vardr.worker-retirement/3",
        **{k:admission[k] for k in ("runtime_id", "runtime_sha256", "admission_sha256", "origin", "runner_id", "enrollment_id")},
        "runtime_sequence":None, "last_sequence":"1", "binding":None,
        "attempt_receipt":None, "report_sha256":report_hash, "retired":True}
    expected_retirement["receipt_sha256"] = host.digest(expected_retirement)
    persistent.retirement(record, proof["retirement"])
    common.same(proof["retirement"], expected_retirement)
    common.same(runtime["report_sha256"], report_hash)
    common.local(proof["retained"], admission, 1, retired=True)
    common.same(proof["retained"], {**proof["after_idle"], "state":"retired",
        "retirement":expected_retirement, "attempt":{**proof["after_idle"]["attempt"],
            "state":"physical_retirement_observed", "retired_from_state":"released"}})
    common.fields(proof["reconciled"], {"state", "remaining_local_holds"})
    common.require(type(proof["reconciled"]["state"]) is str
                   and proof["reconciled"]["state"].startswith("terminal_"))
    common.integer(proof["reconciled"]["remaining_local_holds"], 0)
    return {"schema":"vardr.nm2-worker-idle-public/1", "status":"selected_idle_control_slice_passed",
        "nm2_exit_status":"incomplete", "remaining_matrix_status":"not_closed",
        "cases":{name:"passed" if name in {"default_disabled", "strict_out_of_scope", CASE} else "not_run" for name in sorted(CASES)},
        "measurements":{"issued_attempts":1, "target_request_count":5, "evidence_count":5,
            "remaining_local_holds":0, "limits":admission["limits"], "last_sequence":"1",
            "native_exit_code":124, "operator_stop_requested":False,
            "stopped_owned_container_count":6, "runtime_sha256":admission["runtime_sha256"],
            "admission_sha256":admission["admission_sha256"],
            "retirement_receipt_sha256":expected_retirement["receipt_sha256"],
            "public_ca_der_sha256":raw["public_ca_der_sha256"], "case_sha256":measured["case_sha256"],
            "plan_sha256":host.digest(plan), "artifact_sha256":measured["artifact_sha256"],
            "evidence_sha256":measured["evidence_sha256"]},
        "executables":{"native_owner_sha256":executables["/usr/local/bin/vardr-worker-owner"],
            "gate_sha256":executables["/usr/local/bin/vardrgate"]}, "source_inventories":source_inventories}


def project(raw, selection):
    try:
        return _project(raw, selection)
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, OverflowError, RecursionError):
        raise common.ProjectionRefused("nm2_idle_projection_refused") from None


def project_desktop(raw, selection, before, after):
    try:
        result = _project(raw, selection, desktop=True)
        guard = common._desktop_inventory(raw, selection, before, after, raw["cases"][CASE]["physical"])
        return {**result, "schema":"vardr.nm2-worker-idle-desktop-public/1", "platform":"win32",
                "container_platform":"linux", "inventory_guard":guard}
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, OverflowError, RecursionError):
        raise common.ProjectionRefused("nm2_idle_projection_refused") from None
