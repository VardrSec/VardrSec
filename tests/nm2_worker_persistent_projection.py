"""Strict pure projection of the selected persistent fixture, never execution.

Evidence-body digests were verified by the producer; bodies are not retained here.
No raw identity, origin, grant, path, stdout or proof object enters the output.
"""

from datetime import datetime
import math
from pathlib import PureWindowsPath
import re
from urllib.parse import parse_qs, urlsplit

import nm2_worker_acceptance as fixture
import worker_host as host
import worker_host_persistent as persistent

BINDING = host._BINDING
HASHES = {
    "case_sha256",
    "evidence_sha256",
    "artifact_sha256",
    "result_receipt_sha256",
    "terminal_receipt_sha256",
    "release_receipt_sha256",
    "native_done_sha256",
}
ATTEMPT = HASHES | {
    "runtime_sequence",
    "engagement_id",
    "job_id",
    "evidence_count",
    "bound_at",
    "confirmed_at",
    "released_at",
    "binding",
    "terminal_receipt",
    "release_receipt",
    "requests",
    "assessment",
    "target_charge",
    "duration_seconds",
    "capacity_reserved",
    "local",
}
LOCAL = {
    "runtime_id",
    "runtime_sha256",
    "admission_sha256",
    "last_sequence",
    "active_sequence",
    "state",
    "retirement",
    "counts",
    "attempt",
    "remaining_local_holds",
}
LOCAL_ATTEMPT = {
    "run_id",
    "job_id",
    "phase",
    "pid",
    "artifact_sha256",
    "state",
    "retired_from_state",
    "claim_state",
    "consumption_sent",
    "consumption_acknowledged",
    "native_done_sha256",
    "completion",
    "release",
}
HISTORY = {
    "runtime_id",
    "runtime_sequence",
    "previous_sequence",
    "runtime_mode",
    "job_id",
    "binding",
    "bound_at",
    "confirmed_at",
    "released_at",
    "terminal_receipt",
    "terminal_receipt_sha256",
    "native_done_sha256",
    "release_receipt",
}
INVENTORY = {
    "schema",
    "schema_revision",
    "database_user",
    "engagement_id",
    "job_id",
    "runtime_attempt_bound",
    "job_status",
    "targets_spent",
    "duration_allocated",
    "execution",
    "approvals",
    "contracts",
    "results",
    "stops",
}
CASES = set(fixture.INITIAL_CASES) | {"persistent_availability"}
RUNTIME = {
    "id",
    "runtime_sha256",
    "runner_id",
    "enrollment_id",
    "identity",
    "max_attempts",
    "last_sequence",
    "active_sequence",
    "retired",
    "report_sha256",
    "legacy_binding",
    "attempts",
    "mode",
    "admission_sha256",
    "admission",
    "head_sequence",
    "new_work_disabled",
    "reporting_revoked",
}
TARGET = fixture.ORIGIN


class ProjectionRefused(ValueError):
    pass


def require(value):
    if not value:
        raise ProjectionRefused("nm2_persistent_projection_refused")


def fields(value, keys):
    require(type(value) is dict and set(value) == keys)
    return value


def same(first, second):
    require(host.canonical(first) == host.canonical(second))


def integer(value, expected):
    require(type(value) is int and value == expected)


def stamp(value, *, physical=False):
    if not physical:
        return persistent._stamp(value)
    require(type(value) is str)
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z", value)
    require(match is not None)
    datetime.fromisoformat(match[1] + "+00:00")
    return match[1] + "." + (match[2] or "").ljust(9, "0") + "Z"


def catalog_stamp(value):
    """Read the Runner catalogue's exact UTC format without changing its bytes."""
    require(
        type(value) is str
        and re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}\+00:00",
            value,
        )
        is not None
    )
    return datetime.fromisoformat(value)


def local(value, admission, number, *, retired=False, grants=False):
    fields(value, LOCAL | ({"grants"} if grants else set()))
    for key in ("runtime_id", "runtime_sha256", "admission_sha256"):
        same(value[key], admission[key])
    require(value["last_sequence"] == str(number) and value["active_sequence"] is None)
    require(value["state"] == ("retired" if retired else "idle"))
    integer(value["remaining_local_holds"], 0)
    fields(value["counts"], {"runs", "claims", "contracts", "results"})
    for count in value["counts"].values():
        integer(count, number)
    if not retired:
        require(value["retirement"] is None)
    if number == 0:
        require(value["attempt"] is None)
        return
    attempt = fields(value["attempt"], LOCAL_ATTEMPT)
    require(
        type(attempt["run_id"]) is str
        and re.fullmatch(r"[0-9a-f]{32}", attempt["run_id"])
    )
    host._identifier(attempt["job_id"])
    require(attempt["phase"] == "done" and attempt["pid"] is None)
    require(
        attempt["state"] == ("physical_retirement_observed" if retired else "released")
    )
    require(attempt["retired_from_state"] == ("released" if retired else None))
    require(attempt["claim_state"] == "persistent_released")
    for key in ("consumption_sent", "consumption_acknowledged"):
        integer(attempt[key], 1)
    for key in ("artifact_sha256", "native_done_sha256"):
        host._hash(attempt[key])


def requests(value, number):
    require(type(value) is list and len(value) == 5)
    observed, clocks = [], []
    for row in value:
        fields(row, {"identity", "method", "path", "received_monotonic_ns"})
        require(
            row["method"] == "GET" and row["identity"] in {"owner", "peer", "anonymous"}
        )
        require(type(row["path"]) is str and len(row["path"]) <= 2048)
        parsed = urlsplit(row["path"])
        require(not parsed.scheme and not parsed.netloc and not parsed.fragment)
        require(
            parse_qs(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=1,
            )
            == {"nm2_case": [f"persistent-{number:02d}"]}
        )
        observed.append((parsed.path, row["identity"]))
        require(
            type(row["received_monotonic_ns"]) is int
            and row["received_monotonic_ns"] > 0
        )
        clocks.append(row["received_monotonic_ns"])
    require(
        sorted(observed)
        == sorted(
            [
                ("/session", "owner"),
                ("/session", "peer"),
                ("/fixed/records/42", "owner"),
                ("/fixed/records/42", "peer"),
                ("/fixed/records/42", "anonymous"),
            ]
        )
    )
    return min(clocks), max(clocks)


def job(value, inventory, stored, admission, record, number):
    fields(value, ATTEMPT)
    require(value["runtime_sequence"] == str(number))
    for key in ("job_id", "engagement_id"):
        host._identifier(value[key])
    for key in HASHES:
        host._hash(value[key])
    for key, expected in (
        ("evidence_count", 5),
        ("target_charge", 1),
        ("duration_seconds", 30),
    ):
        integer(value[key], expected)
    require(value["capacity_reserved"] is False)
    binding = host._binding(record, value["binding"])
    require(binding["job_id"] == value["job_id"])
    integer(binding["fence"], 1)
    host._terminal(binding, value["terminal_receipt"])
    expected_result = host.digest(
        {
            "schema": "vardr.managed-result/1",
            **binding,
            "artifact_sha256": value["artifact_sha256"],
            "case_sha256": value["case_sha256"],
        }
    )
    same(
        value["terminal_receipt"],
        {
            "schema": "vardr.managed-completion/1",
            **binding,
            "outcome": "completed",
            "capacity_reserved": False,
            "receipt_sha256": expected_result,
        },
    )
    require(value["result_receipt_sha256"] == expected_result)
    require(value["terminal_receipt_sha256"] == host.digest(value["terminal_receipt"]))
    release = {
        "schema": "vardr.worker-idle-release/2",
        **{
            key: admission[key]
            for key in ("runtime_id", "runtime_sha256", "admission_sha256")
        },
        "runtime_sequence": str(number),
        "binding": binding,
        "terminal_receipt_sha256": value["terminal_receipt_sha256"],
        "native_done_sha256": value["native_done_sha256"],
        "released": True,
    }
    release["receipt_sha256"] = host.digest(release)
    same(value["release_receipt"], release)
    require(value["release_receipt_sha256"] == release["receipt_sha256"])
    fields(stored, HISTORY)
    require(
        stored["runtime_id"] == admission["runtime_id"]
        and stored["runtime_mode"] == "persistent"
    )
    require(stored["previous_sequence"] == (str(number - 1) if number > 1 else None))
    for key in HISTORY - {"runtime_id", "runtime_mode", "previous_sequence"}:
        same(stored[key], value[key])
    fields(
        value["assessment"],
        {
            "status",
            "baseline_valid",
            "case_snapshot_verified",
            "preflight",
            "case_hash",
            "candidate_findings",
        },
    )
    same(
        value["assessment"],
        {
            "status": "conclusive",
            "baseline_valid": True,
            "case_snapshot_verified": True,
            "preflight": {"status": "passed"},
            "case_hash": value["case_sha256"],
            "candidate_findings": 0,
        },
    )
    bounds = [stamp(value[key]) for key in ("bound_at", "confirmed_at", "released_at")]
    require(bounds[0] <= bounds[1] <= bounds[2])
    local(value["local"], admission, number, grants=True)
    same(
        {
            key: value["local"]["attempt"][key]
            for key in ("job_id", "artifact_sha256", "native_done_sha256")
        },
        {
            key: value[key]
            for key in ("job_id", "artifact_sha256", "native_done_sha256")
        },
    )
    same(value["local"]["attempt"]["completion"], value["terminal_receipt"])
    same(value["local"]["attempt"]["release"], release)
    fields(inventory, INVENTORY)
    require(
        inventory["schema"] == "vardr.nm2-fixture-inventory/3"
        and inventory["schema_revision"] == "0041persistentruntime"
        and inventory["database_user"] == "vardrmap_app"
    )
    require(
        inventory["job_id"] == value["job_id"]
        and inventory["engagement_id"] == value["engagement_id"]
        and inventory["job_status"] == "done"
        and inventory["stops"] == []
    )
    for key, expected in (
        ("runtime_attempt_bound", 35),
        ("targets_spent", 1),
        ("duration_allocated", 30),
    ):
        integer(inventory[key], expected)
    same(
        inventory["execution"],
        {
            "state": "completed",
            "capacity_reserved": False,
            "target_charge": 1,
            "duration_seconds": 30,
        },
    )
    same(
        inventory["contracts"],
        [
            {
                "id": binding["contract_id"],
                "attempt_id": binding["attempt_id"],
                "ordinal": 1,
                "fence": binding["fence"],
                "consumed": True,
                "contract_sha256": binding["contract_sha256"],
            }
        ],
    )
    same(
        inventory["results"],
        [
            {
                "contract_id": binding["contract_id"],
                "artifact_sha256": value["artifact_sha256"],
                "receipt_sha256": expected_result,
                "outcome": "completed",
                "evidence_created": 5,
                "scan_items_created": 0,
            }
        ],
    )
    return bounds, requests(value["requests"], number)


def grants(value, inventory, admission, bound, released):
    require(type(inventory["approvals"]) is list and len(inventory["approvals"]) == 1)
    approval = fields(
        inventory["approvals"][0],
        {
            "id",
            "issued",
            "revoked",
            "approved_at",
            "expires_at",
            "max_executions",
            "max_duration_seconds",
            "credential_grants",
        },
    )
    host._identifier(approval["id"])
    require(
        approval["revoked"] is False
        and stamp(approval["approved_at"])
        <= bound
        < released
        < stamp(approval["expires_at"])
    )
    for key, expected in (
        ("issued", 1),
        ("max_executions", 1),
        ("max_duration_seconds", 30),
    ):
        integer(approval[key], expected)
    approved = approval["credential_grants"]
    require(type(approved) is list and len(approved) == 2)
    references = set()
    for grant in approved:
        fields(grant, {"identity_id", "source", "name", "revision", "expires_at"})
        require(
            grant["identity_id"] in {"owner", "peer"}
            and grant["source"] == "value_env"
            and grant["name"] == "FIXTURE_" + grant["identity_id"].upper() + "_TOKEN"
        )
        integer(grant["revision"], 1)
        require(stamp(grant["expires_at"]) > released)
        references.add(grant["identity_id"])
    require(references == {"owner", "peer"})
    catalog = fields(value["local"]["grants"], {"policy_reason", "grants"})
    require(
        catalog["policy_reason"] == "granted"
        and type(catalog["grants"]) is list
        and len(catalog["grants"]) == 2
    )
    ids, names = [], set()
    for grant in catalog["grants"]:
        fields(
            grant,
            {
                "issuer",
                "engagement_id",
                "origin",
                "source",
                "name",
                "id",
                "issued_at",
                "expires_at",
                "status",
            },
        )
        ids.append(host._uuid(grant["id"]))
        require(
            grant["issuer"] == admission["origin"]
            and grant["engagement_id"] == value["engagement_id"]
            and grant["origin"] == TARGET
            and grant["source"] == "env"
            and grant["status"] == "active"
        )
        require(grant["name"] in {"FIXTURE_OWNER_TOKEN", "FIXTURE_PEER_TOKEN"})
        names.add(grant["name"])
        require(
            catalog_stamp(grant["issued_at"]) <= bound
            and catalog_stamp(grant["expires_at"]) > released
        )
    require(
        len(set(ids)) == 2 and names == {"FIXTURE_OWNER_TOKEN", "FIXTURE_PEER_TOKEN"}
    )
    return approval["id"], ids


def _project(raw, selection, *, desktop=False):
    require(
        type(raw) is dict
        and type(selection) is dict
        and len(host.canonical(raw)) <= 4 * 1024 * 1024
    )
    require(
        raw["schema"] == "vardr.nm2-worker-persistent-acceptance/1"
        and raw["status"] == "selected_availability_slice_passed"
        and raw["stage"] == "selected_availability_complete"
    )
    require(
        raw["scenario"] == "persistent-availability"
        and raw["acceptance_scope"] == "persistent_availability_only"
        and raw["nm2_exit_status"] == "incomplete"
        and raw["platform"] == ("win32" if desktop else "linux")
        and raw["retained"] is True
    )
    fields(selection["sources"], fixture.SOURCE_NAMES)
    for row in selection["sources"].values():
        fields(row, {"path", "commit"})
        require(
            type(row["path"]) is str
            and type(row["commit"]) is str
            and re.fullmatch(r"[a-f0-9]{40}", row["commit"])
        )
        if desktop:
            source = PureWindowsPath(row["path"])
            require(source.is_absolute() and ".." not in source.parts)
        else:
            require(row["path"].startswith("/"))
    fields(selection["images"], fixture.IMAGE_NAMES)
    for image in selection["images"].values():
        require(type(image) is str and re.fullmatch(r"sha256:[a-f0-9]{64}", image))
    require(
        type(selection["project"]) is str
        and re.fullmatch(r"vardrsec-nm2-[a-z0-9]{8,24}", selection["project"])
    )
    require(
        type(selection["https_port"]) is int and 1 <= selection["https_port"] <= 65535
    )
    for key in ("sources", "images", "project"):
        same(raw[key], selection[key])
    require(raw["readiness_volume"] == selection["project"] + "_worker-ready")
    require(
        raw["expected_database_revision"] == "0041persistentruntime"
        and (desktop or raw["admitted_inventory_diffs"] == [])
    )
    for key in ("before_sha256", "after_sha256", "public_ca_der_sha256"):
        host._hash(raw[key])
    cases = fields(raw["cases"], CASES)
    disabled = fields(
        cases["default_disabled"],
        {
            "status",
            "services",
            "managed_pending_status",
            "csrf_write_status",
            "unauthenticated_read_status",
        },
    )
    require(
        disabled["status"] == "passed"
        and type(disabled["services"]) is list
        and len(disabled["services"]) == 4
        and sorted(disabled["services"]) == ["api", "db", "proxy", "web"]
    )
    for key, expected in (
        ("managed_pending_status", 404),
        ("csrf_write_status", 403),
        ("unauthenticated_read_status", 401),
    ):
        integer(disabled[key], expected)
    denied = fields(
        cases["strict_out_of_scope"],
        {"status", "approval_http_status", "inventory", "traffic_delta"},
    )
    require(denied["status"] == "passed")
    integer(denied["approval_http_status"], 409)
    integer(denied["traffic_delta"], 0)
    denied_inventory = fields(denied["inventory"], INVENTORY | {"runtimes"})
    require(
        denied_inventory["schema"] == "vardr.nm2-fixture-inventory/3"
        and denied_inventory["schema_revision"] == "0041persistentruntime"
        and denied_inventory["database_user"] == "vardrmap_app"
        and denied_inventory["job_status"] == "pending"
        and denied_inventory["execution"] is None
    )
    integer(denied_inventory["runtime_attempt_bound"], 35)
    for key in ("engagement_id", "job_id"):
        host._identifier(denied_inventory[key])
    for key in ("approvals", "contracts", "results", "stops", "runtimes"):
        same(denied_inventory[key], [])
    for key in ("targets_spent", "duration_allocated"):
        integer(denied["inventory"][key], 0)
    for name in fixture.INITIAL_CASES[2:]:
        same(cases[name], {"status": "not_run"})
    case = fields(
        cases["persistent_availability"],
        {
            "status",
            "physical",
            "idle_seconds",
            "idle_target_request_count",
            "limits",
            "admission_sha256",
            "last_sequence",
            "attempts",
            "target_request_count",
            "evidence_count",
            "targets_spent",
            "duration_allocated",
            "remaining_local_holds",
            "retirement_receipt_sha256",
            "runtime_acceptance_scope",
            "proof",
        },
    )
    require(
        case["status"] == "passed"
        and case["runtime_acceptance_scope"] == "persistent_availability_only"
    )
    for key, expected in (
        ("idle_target_request_count", 0),
        ("target_request_count", 175),
        ("evidence_count", 175),
        ("targets_spent", 35),
        ("duration_allocated", 1050),
        ("remaining_local_holds", 0),
    ):
        integer(case[key], expected)
    require(
        type(case["idle_seconds"]) in {int, float}
        and math.isfinite(case["idle_seconds"])
        and case["idle_seconds"] >= 70
    )
    require(case["last_sequence"] == "35")
    same(case["limits"], {"max_attempts": None, "idle_timeout_seconds": None})
    proof = fields(
        case["proof"], {"idle", "runtime", "inventories", "retirement", "retained"}
    )
    idle = fields(
        proof["idle"],
        {"seconds", "before", "after", "status", "target_request_count", "admission"},
    )
    same(idle["seconds"], case["idle_seconds"])
    integer(idle["target_request_count"], 0)
    admission = idle["admission"]
    record = {
        "runtime_id": admission["runtime_id"],
        "registration": {key: admission[key] for key in persistent.REGISTRATION},
    }
    persistent.admission(record, admission)
    require(
        admission["origin"]
        == f"https://vardrsec.localhost:{selection['https_port']}/backend"
        and admission["identity"]["project"] == selection["project"]
        and admission["identity"]["image_id"] == selection["images"]["worker"]
    )
    same(admission["limits"], case["limits"])
    require(case["admission_sha256"] == admission["admission_sha256"])
    local(idle["before"], admission, 0)
    local(idle["after"], admission, 0)
    status = fields(
        idle["status"],
        {
            "schema",
            "runtime_id",
            "protocol",
            "mode",
            "limits",
            "identity",
            "state",
            "reason",
            "cursor",
            "availability",
            "new_work_disabled",
            "reporting_revoked",
            "registration_state",
            "disable_state",
            "stop_state",
            "revocation_state",
            "container_state",
        },
    )
    require(
        status["schema"] == "vardr.worker-status/1"
        and status["protocol"] == "persistent-v3"
        and status["mode"] == "persistent"
        and status["state"] == "idle-ready"
        and status["reason"] is None
        and status["runtime_id"] == admission["runtime_id"]
    )
    same(status["identity"], admission["identity"])
    same(status["limits"], case["limits"])
    same(status["cursor"], {"last_sequence": "0", "phase": "idle"})
    require(
        status["container_state"] == "running"
        and status["registration_state"] == "acknowledged"
        and all(
            status[key] == "none"
            for key in ("disable_state", "stop_state", "revocation_state")
        )
        and status["new_work_disabled"] is False
        and status["reporting_revoked"] is False
    )
    presence = fields(
        status["availability"], {"state", "observed_at", "fresh_until", "cursor"}
    )
    require(presence["state"] == "idle-ready")
    same(presence["cursor"], status["cursor"])
    require(
        0
        < (
            stamp(presence["fresh_until"]) - stamp(presence["observed_at"])
        ).total_seconds()
        <= 15
    )
    physical = fields(
        case["physical"],
        {
            "identity",
            "runtime_id",
            "runtime_sha256",
            "admission_sha256",
            "exit_code",
            "finished_at",
            "operator_enable_state",
            "operator_stop_state",
        },
    )
    same(physical["identity"], admission["identity"])
    for key in ("runtime_id", "runtime_sha256", "admission_sha256"):
        same(physical[key], admission[key])
    require(
        type(physical["exit_code"]) is int
        and 0 <= physical["exit_code"] <= 255
        and physical["operator_enable_state"] == "enabled"
        and physical["operator_stop_state"] == "stopped_observed"
    )
    require(
        stamp(physical["finished_at"], physical=True)
        > stamp(physical["identity"]["started_at"], physical=True)
    )
    runtime = fields(proof["runtime"], RUNTIME)
    require(type(runtime["attempts"]) is list and len(runtime["attempts"]) == 35)
    require(
        runtime["runner_id"] == admission["runner_id"]
        and runtime["enrollment_id"] == admission["enrollment_id"]
    )
    fields(
        runtime["legacy_binding"],
        {
            "job_id",
            "contract_id",
            "attempt_id",
            "fence",
            "contract_sha256",
            "bound_at",
            "confirmed_at",
        },
    )
    persistent.retirement(record, proof["retirement"])
    require(case["retirement_receipt_sha256"] == proof["retirement"]["receipt_sha256"])
    local(proof["retained"], admission, 35, retired=True)
    require(
        type(case["attempts"]) is list
        and type(proof["inventories"]) is list
        and len(case["attempts"]) == len(proof["inventories"]) == 35
    )
    require(
        stamp(physical["identity"]["started_at"], physical=True)
        <= stamp(presence["observed_at"], physical=True)
        <= stamp(case["attempts"][0]["bound_at"], physical=True)
    )
    approvals, grant_ids, contract_ids, attempt_ids, run_ids = (
        set(),
        set(),
        set(),
        set(),
        set(),
    )
    for number, (value, inventory, stored) in enumerate(
        zip(case["attempts"], proof["inventories"], runtime["attempts"], strict=True), 1
    ):
        bounds, _ = job(value, inventory, stored, admission, record, number)
        require(
            stamp(physical["identity"]["started_at"], physical=True)
            <= stamp(value["bound_at"], physical=True)
            <= stamp(value["released_at"], physical=True)
            <= stamp(physical["finished_at"], physical=True)
        )
        approval_id, ids = grants(value, inventory, admission, bounds[0], bounds[2])
        require(approval_id not in approvals and not grant_ids.intersection(ids))
        require(
            value["binding"]["contract_id"] not in contract_ids
            and value["binding"]["attempt_id"] not in attempt_ids
            and value["local"]["attempt"]["run_id"] not in run_ids
        )
        approvals.add(approval_id)
        grant_ids.update(ids)
        contract_ids.add(value["binding"]["contract_id"])
        attempt_ids.add(value["binding"]["attempt_id"])
        run_ids.add(value["local"]["attempt"]["run_id"])
    same(
        proof["retained"]["attempt"],
        {
            **case["attempts"][-1]["local"]["attempt"],
            "state": "physical_retirement_observed",
            "retired_from_state": "released",
        },
    )
    inventories = [{**value, "runtimes": [runtime]} for value in proof["inventories"]]
    oracle = object.__new__(fixture.Fixture)
    verified = oracle.verify_persistent_sequence(
        physical,
        idle,
        case["attempts"],
        inventories,
        proof["retirement"],
        proof["retained"],
    )
    same(
        {key: value for key, value in case.items() if key != "proof"},
        {key: value for key, value in verified.items() if key != "proof"},
    )
    cleanup = fields(
        raw["fixture_stop"], {"status", "container_ids", "stop_requested_ids"}
    )
    require(
        cleanup["status"] == "stopped_retained"
        and type(cleanup["container_ids"]) is list
        and len(cleanup["container_ids"]) == 6
    )
    for value in cleanup["container_ids"]:
        host._hash(value)
    require(
        len(set(cleanup["container_ids"])) == 6
        and physical["identity"]["container_id"] in cleanup["container_ids"]
    )
    require(
        type(cleanup["stop_requested_ids"]) is list
        and len(set(cleanup["stop_requested_ids"]))
        == len(cleanup["stop_requested_ids"])
        and set(cleanup["stop_requested_ids"]) <= set(cleanup["container_ids"])
    )
    sources = fields(raw["image_sources"], {"map", "runner"})
    inventories_public = {}
    for name, image in (("map", "api"), ("runner", "worker")):
        row = fields(
            sources[name],
            {
                "image_id",
                "python_file_count",
                "python_inventory_sha256",
                "executables",
                "line_endings",
            },
        )
        require(
            row["image_id"] == selection["images"][image]
            and type(row["python_file_count"]) is int
            and 0 < row["python_file_count"] < 100000
            and row["line_endings"] == "CRLF-normalized-to-LF"
        )
        host._hash(row["python_inventory_sha256"])
        inventories_public[name] = {
            key: row[key] for key in ("python_file_count", "python_inventory_sha256")
        }
    same(sources["map"]["executables"], {})
    executable = fields(
        sources["runner"]["executables"],
        {"/usr/local/bin/vardr-worker-owner", "/usr/local/bin/vardrgate"},
    )
    for value in executable.values():
        host._hash(value)
    return {
        "schema": "vardr.nm2-worker-persistent-public/1",
        "status": "selected_availability_slice_passed",
        "nm2_exit_status": "incomplete",
        "remaining_matrix_status": "not_closed",
        "cases": {
            name: (
                "passed"
                if name
                in {
                    "default_disabled",
                    "strict_out_of_scope",
                    "persistent_availability",
                }
                else "not_run"
            )
            for name in sorted(CASES)
        },
        "measurements": {
            "idle_seconds": case["idle_seconds"],
            "idle_target_request_count": 0,
            "target_request_count": 175,
            "evidence_count": 175,
            "targets_spent": 35,
            "duration_allocated": 1050,
            "remaining_local_holds": 0,
            "last_sequence": "35",
            "limits": {"max_attempts": None, "idle_timeout_seconds": None},
            "stopped_owned_container_count": 6,
            "runtime_sha256": admission["runtime_sha256"],
            "admission_sha256": admission["admission_sha256"],
            "retirement_receipt_sha256": proof["retirement"]["receipt_sha256"],
            "public_ca_der_sha256": raw["public_ca_der_sha256"],
            "attempts": [
                {
                    "runtime_sequence": str(number),
                    **{key: value[key] for key in sorted(HASHES)},
                }
                for number, value in enumerate(case["attempts"], 1)
            ],
        },
        "executables": {
            "native_owner_sha256": executable["/usr/local/bin/vardr-worker-owner"],
            "gate_sha256": executable["/usr/local/bin/vardrgate"],
        },
        "source_inventories": inventories_public,
    }


def project(raw, selection):
    try:
        return _project(raw, selection)
    except (
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        AttributeError,
        OverflowError,
        RecursionError,
    ):
        raise ProjectionRefused("nm2_persistent_projection_refused") from None


def desktop_inventory(raw, selection, before, after):
    """Recheck supplied snapshot facts; never contact Docker or infer a cause."""
    require(
        selection["docker_context"] == "desktop-linux"
        and type(selection["allow_empty_builtin_bridge_id_change"]) is bool
    )
    shapes = {
        "containers": {
            "id",
            "image",
            "labels",
            "state",
            "restarts",
            "networks",
            "mounts",
        },
        "networks": {
            "id",
            "name",
            "driver",
            "scope",
            "internal",
            "attachable",
            "ipv6",
            "ingress",
            "options",
            "ipam",
            "labels",
            "containers",
        },
        "volumes": {"id", "driver", "labels", "options"},
        "images": {"id", "tags", "digests", "labels"},
    }
    for inventory, digest_key in ((before, "before_sha256"), (after, "after_sha256")):
        fields(inventory, set(shapes))
        require(host.digest(inventory) == raw[digest_key])
        for kind, shape in shapes.items():
            require(type(inventory[kind]) is dict)
            for key, value in inventory[kind].items():
                fields(value, shape)
                require(
                    type(key) is str
                    and value["id"] == key
                    and type(value["labels"]) is dict
                )
    admitted = fixture.unchanged_inventory(
        before,
        after,
        selection["project"],
        admit_bridge=selection["allow_empty_builtin_bridge_id_change"],
    )
    same(raw["admitted_inventory_diffs"], admitted)
    require(len(admitted) <= 1)
    for kind in ("containers", "volumes", "images"):
        for key, value in before[kind].items():
            same(value, after[kind][key])
    replacements = {entry["before"]: entry["after"] for entry in admitted}
    for key, value in before["networks"].items():
        candidate = after["networks"][replacements.get(key, key)]
        if key in replacements:
            require(
                value["name"] == candidate["name"] == "bridge"
                and value["driver"] == candidate["driver"] == "bridge"
                and value["scope"] == candidate["scope"] == "local"
                and value["containers"] == candidate["containers"] == {}
            )
            options = value["options"]
            require(options is None or type(options) is dict)
            if (
                options is not None
                and "com.docker.network.bridge.default_bridge" in options
            ):
                require(options["com.docker.network.bridge.default_bridge"] == "true")
            same(
                {k: v for k, v in value.items() if k != "id"},
                {k: v for k, v in candidate.items() if k != "id"},
            )
        else:
            same(value, candidate)
    owned = set(after["containers"]) - set(before["containers"])
    require(owned == set(raw["fixture_stop"]["container_ids"]) and len(owned) == 6)
    expected = {
        name: selection["images"][name] for name in ("db", "api", "web", "proxy")
    }
    expected.update(
        {
            name: selection["images"]["worker"]
            for name in ("managed-worker", "gate-fixture")
        }
    )
    services = set()
    for container_id in owned:
        host._hash(container_id)
        value = after["containers"][container_id]
        labels = value["labels"]
        service = labels.get("com.docker.compose.service")
        require(
            labels.get("com.docker.compose.project") == selection["project"]
            and type(service) is str
            and service in expected
            and service not in services
            and value["image"] == expected[service]
        )
        services.add(service)
        state = fields(
            value["state"],
            {
                "running",
                "paused",
                "restarting",
                "dead",
                "exit_code",
                "started_at",
                "finished_at",
            },
        )
        require(
            all(
                state[key] is False
                for key in ("running", "paused", "restarting", "dead")
            )
        )
    require(services == set(expected))
    physical = raw["cases"]["persistent_availability"]["physical"]
    worker = after["containers"][physical["identity"]["container_id"]]
    require(worker["labels"]["com.docker.compose.service"] == "managed-worker")
    same(worker["image"], physical["identity"]["image_id"])
    same(worker["state"]["started_at"], physical["identity"]["started_at"])
    for key in ("exit_code", "finished_at"):
        same(worker["state"][key], physical[key])
    return {
        "status": "passed",
        "before_counts": {kind: len(before[kind]) for kind in sorted(shapes)},
        "after_counts": {kind: len(after[kind]) for kind in sorted(shapes)},
        "new_stopped_owned_container_count": 6,
        "semantic_bridge_classification": {
            "empty_builtin_bridge_id_change_count": len(admitted),
            "cause": "unknown",
        },
    }


def project_desktop(raw, selection, before, after):
    """Project original Windows-host/Linux-container proof without relabeling it."""
    try:
        result = _project(raw, selection, desktop=True)
        guard = desktop_inventory(raw, selection, before, after)
        return {
            **result,
            "schema": "vardr.nm2-worker-persistent-desktop-public/1",
            "platform": "win32",
            "container_platform": "linux",
            "inventory_guard": guard,
        }
    except (
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        AttributeError,
        OverflowError,
        RecursionError,
    ):
        raise ProjectionRefused("nm2_persistent_projection_refused") from None
