"""Strict optional count-one receipt correlation; never execution or attestation.

Evidence bodies were checked by the producer and are not retained by this reader.
The separate availability reader still requires 70 seconds, 35 jobs and 175 requests.
"""

from pathlib import PureWindowsPath
from urllib.parse import urlsplit
import re

from gate_acceptance import ORIGIN as REVIEWED_ORIGIN, reviewed_cases
import nm2_worker_acceptance as fixture
import nm2_worker_persistent_projection as common
import worker_host as host
import worker_host_persistent as persistent

SCENARIO = "persistent-count-limit"
CASE = "persistent_count_limit"
CASES = set(fixture.INITIAL_CASES) | {CASE}
APPROVAL = {
    "id",
    "issued",
    "revoked",
    "approved_at",
    "expires_at",
    "max_executions",
    "max_duration_seconds",
    "credential_grants",
}
CONTEXT = {
    "runner_id",
    "engagement_id",
    "job_id",
    "authority_revision",
    "authority_sha256",
    "plan_sha256",
    "mode",
    "scope",
    "exceptions",
    "not_before",
    "expires_at",
    "testing_start",
    "testing_end",
    "max_executions",
    "max_duration_seconds",
    "max_http_dispatches",
    "max_artifact_bytes",
    "credential_grants",
    "control",
}


def require(value):
    common.require(value)


def expected_case(name):
    require(name in {"count-a", "count-b"})
    spec = next(value["spec"] for value in reviewed_cases() if value["name"] == "fixed")
    spec["id"] = "nm2-" + name
    requests = [spec["request"]] + [
        identity["preflight"]
        for identity in spec["identities"]
        if "preflight" in identity
    ]
    for request in requests:
        require(request["url"].startswith(REVIEWED_ORIGIN + "/"))
        request["url"] = fixture.ORIGIN + request["url"][len(REVIEWED_ORIGIN) :]
        request["url"] += ("&" if "?" in request["url"] else "?") + "nm2_case=" + name
    return spec


def fixed_plan(spec, gate_sha256):
    """The one reviewed five-GET fixture shape, not a general plan compiler."""
    dispatches = []
    for identity in spec["identities"]:
        if "preflight" in identity:
            dispatches.append(
                ("preflight", identity["id"], "GET", identity["preflight"]["url"])
            )
    dispatches += [
        ("resource", identity["id"], "GET", spec["request"]["url"])
        for identity in spec["identities"]
    ]
    return {
        "schema": "vardr.execution-plan/1",
        "profile": "gate-fixed-http/1",
        "tool_sha256": gate_sha256,
        "case_hash": host.digest(spec),
        "execution": fixture.EXECUTION,
        "credential_references": [
            {
                "identity_id": who,
                "source": "value_env",
                "name": "FIXTURE_" + who.upper() + "_TOKEN",
            }
            for who in ("owner", "peer")
        ],
        "dispatches": [
            {
                "phase": phase,
                "identity_id": who,
                "request": {
                    "method": method,
                    "url": url,
                    "headers": {},
                    "query_params": {},
                    "body": None,
                },
                "max_dispatches": 1,
            }
            for phase, who, method, url in dispatches
        ],
        "max_http_dispatches": 5,
    }


def request_bounds(rows, plan):
    require(type(rows) is list and len(rows) == 5)
    expected = []
    for entry in plan["dispatches"]:
        parsed = urlsplit(entry["request"]["url"])
        require(
            f"{parsed.scheme}://{parsed.netloc}" == fixture.ORIGIN
            and not parsed.fragment
        )
        expected.append(
            (
                entry["identity_id"],
                entry["request"]["method"],
                parsed.path + ("?" + parsed.query if parsed.query else ""),
            )
        )
    observed, clocks = [], []
    for row in rows:
        common.fields(row, {"identity", "method", "path", "received_monotonic_ns"})
        require(type(row["path"]) is str and len(row["path"]) <= 2048)
        require(
            type(row["received_monotonic_ns"]) is int
            and row["received_monotonic_ns"] > 0
        )
        observed.append((row["identity"], row["method"], row["path"]))
        clocks.append(row["received_monotonic_ns"])
    require(sorted(observed) == sorted(expected))
    return min(clocks), max(clocks)


def before_inventory(value, engagement, job):
    common.fields(value, common.INVENTORY | {"runtimes", "approval_context_sha256"})
    require(
        value["schema"] == "vardr.nm2-fixture-inventory/4"
        and value["schema_revision"] == "0041persistentruntime"
        and value["database_user"] == "vardrmap_app"
    )
    require(
        value["engagement_id"] == engagement
        and value["job_id"] == job
        and value["job_status"] == "pending"
        and value["execution"] is None
    )
    common.integer(
        value["runtime_attempt_bound"], 35
    )  # Existing read cap, not issued count.
    for key in ("targets_spent", "duration_allocated"):
        common.integer(value[key], 0)
    for key in ("contracts", "results", "stops", "runtimes"):
        common.same(value[key], [])
    require(type(value["approvals"]) is list and len(value["approvals"]) == 1)
    approval = common.fields(value["approvals"][0], APPROVAL)
    host._identifier(approval["id"])
    common.integer(approval["issued"], 0)
    require(approval["revoked"] is False)
    return approval


def review(selection, admission, before, gate_sha256, project):
    common.fields(
        selection,
        {
            "engagement_id",
            "job_id",
            "case_spec",
            "review_input",
            "review_context",
            "review_authority",
        },
    )
    for key in ("engagement_id", "job_id"):
        host._identifier(selection[key])
    spec = selection["case_spec"]
    require(type(spec) is dict and type(spec.get("id")) is str)
    name = spec["id"].removeprefix("nm2-")
    common.same(spec, expected_case(name))
    request = common.fields(
        selection["review_input"],
        {
            "enrollment_id",
            "authorization_id",
            "plan",
            "expires_at",
            "max_executions",
            "max_duration_seconds",
            "max_artifact_bytes",
            "credential_grants",
        },
    )
    context = common.fields(selection["review_context"], CONTEXT)
    authority = common.fields(
        selection["review_authority"],
        {
            "schema",
            "origin",
            "authority_revision",
            "authority",
            "owner",
            "engagement_type",
            "engagement_status",
            "limits",
            "enrollment",
        },
    )
    plan = fixed_plan(spec, gate_sha256)
    common.same(request["plan"], plan)
    require(request["enrollment_id"] == admission["enrollment_id"])
    require(
        context["job_id"] == selection["job_id"]
        and context["engagement_id"] == selection["engagement_id"]
        and context["runner_id"] == admission["runner_id"]
    )
    require(context["mode"] == "strict" and context["control"] == "managed_online")
    common.same(context["exceptions"], [])
    require(
        context["plan_sha256"] == host.digest(plan)
        and context["authority_sha256"] == host.digest(authority)
    )
    require(
        authority["schema"] == "vardr.map-managed-authority/1"
        and authority["origin"] == admission["origin"]
        and authority["engagement_type"] == "bug_bounty"
        and authority["engagement_status"] == "active"
    )
    host._identifier(authority["owner"])
    require(
        type(context["authority_revision"]) is int
        and context["authority_revision"] >= 0
    )
    common.same(authority["authority_revision"], context["authority_revision"])
    common.same(authority["limits"], {"concurrency": 1, "targets": 5, "duration": 120})
    enrollment = common.fields(
        authority["enrollment"],
        {"id", "revision", "api_key_id", "principal_sha256", "runner_id"},
    )
    require(
        enrollment["id"] == admission["enrollment_id"]
        and enrollment["runner_id"] == admission["runner_id"]
        and type(enrollment["revision"]) is int
        and enrollment["revision"] >= 1
    )
    host._identifier(enrollment["api_key_id"])
    host._hash(enrollment["principal_sha256"])
    recorded = common.fields(
        authority["authority"], {"authorization", "scope", "engagement_id"}
    )
    require(recorded["engagement_id"] == selection["engagement_id"])
    common.same(
        recorded["scope"],
        [{"value": fixture.ORIGIN + "/", "kind": "url", "scope_type": "in"}],
    )
    permission = common.fields(
        recorded["authorization"],
        {
            "id",
            "status",
            "permits",
            "authorized_by",
            "reference",
            "window_start",
            "window_end",
        },
    )
    require(
        permission["id"] == request["authorization_id"]
        and permission["status"] == "active"
        and permission["permits"] == "Owned synthetic fixture only"
        and permission["authorized_by"] == "Fixture local owner"
        and permission["reference"] == project
    )
    for key, expected in (
        ("max_executions", 1),
        ("max_duration_seconds", 30),
        ("max_artifact_bytes", 1024 * 1024),
    ):
        common.integer(request[key], expected)
        common.integer(context[key], expected)
    common.integer(context["max_http_dispatches"], 5)
    expected_scope = [
        {
            "origin": fixture.ORIGIN,
            "path": urlsplit(entry["request"]["url"]).path,
            "method": "GET",
            "excluded": False,
            "reason": "",
        }
        for entry in plan["dispatches"]
    ]
    common.same(context["scope"], expected_scope)
    require(context["expires_at"] == request["expires_at"])
    require(
        context["testing_start"] == permission["window_start"]
        and context["testing_end"] == permission["window_end"]
    )
    require(
        common.stamp(context["testing_start"])
        <= common.stamp(context["not_before"])
        < common.stamp(context["expires_at"])
        <= common.stamp(context["testing_end"])
    )
    approval = before_inventory(before, selection["engagement_id"], selection["job_id"])
    fixture.count_approval_context(before, context)
    common.fields(approval, APPROVAL)
    for key in (
        "max_executions",
        "max_duration_seconds",
        "expires_at",
        "credential_grants",
    ):
        common.same(approval[key], request[key])
    common.same(context["credential_grants"], request["credential_grants"])
    expected_refs = [
        {**reference, "revision": 1, "expires_at": request["expires_at"]}
        for reference in plan["credential_references"]
    ]
    common.same(request["credential_grants"], expected_refs)
    require(
        common.stamp(context["not_before"])
        <= common.stamp(approval["approved_at"])
        < common.stamp(context["expires_at"])
    )
    return name, plan, approval


def envelope(raw, selection, desktop):
    require(
        type(raw) is dict
        and type(selection) is dict
        and len(host.canonical(raw)) <= 4 * 1024 * 1024
    )
    require(
        raw["schema"] == "vardr.nm2-worker-count-acceptance/1"
        and raw["status"] == "selected_count_control_slice_passed"
        and raw["stage"] == "selected_count_control_complete"
    )
    require(
        raw["scenario"] == SCENARIO
        and raw["acceptance_scope"] == "persistent_count_control_only"
        and raw["nm2_exit_status"] == "incomplete"
        and raw["platform"] == ("win32" if desktop else "linux")
        and raw["retained"] is True
    )
    common.fields(selection["sources"], fixture.SOURCE_NAMES)
    for row in selection["sources"].values():
        common.fields(row, {"path", "commit"})
        require(
            type(row["path"]) is str
            and type(row["commit"]) is str
            and re.fullmatch(r"[a-f0-9]{40}", row["commit"])
        )
        if desktop:
            path = PureWindowsPath(row["path"])
            require(path.is_absolute() and ".." not in path.parts)
        else:
            require(row["path"].startswith("/"))
    common.fields(selection["images"], fixture.IMAGE_NAMES)
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
        common.same(raw[key], selection[key])
    require(
        raw["readiness_volume"] == selection["project"] + "_worker-ready"
        and raw["expected_database_revision"] == "0041persistentruntime"
        and (desktop or raw["admitted_inventory_diffs"] == [])
    )
    for key in ("before_sha256", "after_sha256", "public_ca_der_sha256"):
        host._hash(raw[key])
    cases = common.fields(raw["cases"], CASES)
    disabled = common.fields(
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
        common.integer(disabled[key], expected)
    denied = common.fields(
        cases["strict_out_of_scope"],
        {"status", "approval_http_status", "inventory", "traffic_delta"},
    )
    require(denied["status"] == "passed")
    common.integer(denied["approval_http_status"], 409)
    common.integer(denied["traffic_delta"], 0)
    inv = common.fields(
        denied["inventory"], common.INVENTORY | {"runtimes", "approval_context_sha256"}
    )
    require(
        inv["schema"] == "vardr.nm2-fixture-inventory/4"
        and inv["schema_revision"] == "0041persistentruntime"
        and inv["database_user"] == "vardrmap_app"
        and inv["job_status"] == "pending"
        and inv["execution"] is None
    )
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


def source_cleanup(raw, selection, physical):
    cleanup = common.fields(
        raw["fixture_stop"], {"status", "container_ids", "stop_requested_ids"}
    )
    require(
        cleanup["status"] == "stopped_retained"
        and type(cleanup["container_ids"]) is list
        and len(cleanup["container_ids"]) == len(set(cleanup["container_ids"])) == 6
    )
    for identity in cleanup["container_ids"]:
        host._hash(identity)
    require(physical["identity"]["container_id"] in cleanup["container_ids"])
    require(
        type(cleanup["stop_requested_ids"]) is list
        and len(set(cleanup["stop_requested_ids"]))
        == len(cleanup["stop_requested_ids"])
        and set(cleanup["stop_requested_ids"]) <= set(cleanup["container_ids"])
    )
    sources = common.fields(raw["image_sources"], {"map", "runner"})
    for name, image in (("map", "api"), ("runner", "worker")):
        row = common.fields(
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
    common.same(sources["map"]["executables"], {})
    executables = common.fields(
        sources["runner"]["executables"],
        {"/usr/local/bin/vardr-worker-owner", "/usr/local/bin/vardrgate"},
    )
    for digest in executables.values():
        host._hash(digest)
    return executables, {
        name: {
            key: row[key] for key in ("python_file_count", "python_inventory_sha256")
        }
        for name, row in sources.items()
    }


def _project(raw, selection, *, desktop=False):
    case = common.fields(
        envelope(raw, selection, desktop),
        {
            "status",
            "limits",
            "physical",
            "issued_job_id",
            "unissued_job_id",
            "issued_attempts",
            "unissued_target_charge",
            "unissued_duration_charge",
            "target_request_count",
            "evidence_count",
            "remaining_local_holds",
            "proof",
        },
    )
    proof = common.fields(
        case["proof"],
        {
            "fixed",
            "measured",
            "inventories",
            "local",
            "retirement",
            "retained",
            "eligibility",
            "grants",
            "admission",
            "selections",
            "pending_before",
            "traffic",
        },
    )
    admission = proof["admission"]
    record = {
        "runtime_id": admission["runtime_id"],
        "registration": {key: admission[key] for key in persistent.REGISTRATION},
    }
    persistent.admission(record, admission)
    common.same(
        admission["limits"], {"max_attempts": "1", "idle_timeout_seconds": None}
    )
    require(
        admission["origin"]
        == f"https://vardrsec.localhost:{selection['https_port']}/backend"
        and admission["identity"]["project"] == selection["project"]
        and admission["identity"]["image_id"] == selection["images"]["worker"]
    )
    physical = common.fields(
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
    common.same(physical["identity"], admission["identity"])
    for key in ("runtime_id", "runtime_sha256", "admission_sha256"):
        common.same(physical[key], admission[key])
    common.integer(physical["exit_code"], 0)
    require(
        physical["operator_enable_state"] == "enabled"
        and physical["operator_stop_state"] == "not_requested"
        and common.stamp(physical["finished_at"], physical=True)
        > common.stamp(physical["identity"]["started_at"], physical=True)
    )
    executables, source_inventories = source_cleanup(raw, selection, physical)
    require(
        type(proof["selections"]) is list
        and len(proof["selections"]) == 2
        and type(proof["inventories"]) is list
        and len(proof["inventories"]) == 2
    )
    first, second = proof["selections"]
    fixed = common.fields(
        proof["fixed"],
        {
            "status",
            "physical",
            "before_worker",
            "inventory",
            "requests",
            "case_sha256",
            "evidence_count",
            "evidence_sha256",
        },
    )
    names = []
    plans = []
    approvals = []
    for original, before in (
        (first, fixed["before_worker"]),
        (second, proof["pending_before"]),
    ):
        name, plan, approval = review(
            original,
            admission,
            before,
            executables["/usr/local/bin/vardrgate"],
            selection["project"],
        )
        names.append(name)
        plans.append(plan)
        approvals.append(approval)
    started = common.stamp(physical["identity"]["started_at"], physical=True)
    require(common.stamp(approvals[1]["approved_at"], physical=True) <= started)
    pending_grants = common.fields(proof["grants"], {"policy_reason", "grants"})
    require(
        type(pending_grants["grants"]) is list and len(pending_grants["grants"]) == 2
    )
    for grant in pending_grants["grants"]:
        issued_at = grant["issued_at"]
        common.catalog_stamp(issued_at)
        require(common.stamp(issued_at[:-6] + "Z", physical=True) <= started)
    require(
        set(names) == {"count-a", "count-b"}
        and first["job_id"] < second["job_id"]
        and first["engagement_id"] != second["engagement_id"]
    )
    require(first["review_authority"]["owner"] == second["review_authority"]["owner"])
    common.same(
        first["review_authority"]["enrollment"],
        second["review_authority"]["enrollment"],
    )
    require(approvals[0]["id"] != approvals[1]["id"])
    denied = raw["cases"]["strict_out_of_scope"]["inventory"]
    require(
        all(
            original["job_id"] != denied["job_id"]
            and original["engagement_id"] != denied["engagement_id"]
            for original in (first, second)
        )
    )
    for original, inventory in zip(
        proof["selections"], proof["inventories"], strict=True
    ):
        require(
            inventory["job_id"] == original["job_id"]
            and inventory["engagement_id"] == original["engagement_id"]
        )
    issued, pending = proof["inventories"]
    common.fields(issued, common.INVENTORY | {"runtimes", "approval_context_sha256"})
    common.fields(pending, common.INVENTORY | {"runtimes", "approval_context_sha256"})
    common.same(pending, proof["pending_before"])
    require(type(issued["runtimes"]) is list and len(issued["runtimes"]) == 1)
    runtime = common.fields(issued["runtimes"][0], common.RUNTIME)
    common.same(runtime["identity"], admission["identity"])
    common.fields(
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
    require(
        type(runtime["attempts"]) is list
        and len(runtime["attempts"]) == 1
        and runtime["runner_id"] == admission["runner_id"]
        and runtime["enrollment_id"] == admission["enrollment_id"]
    )
    measured = common.fields(proof["measured"], common.ATTEMPT - {"local"})
    value = {**measured, "local": proof["local"]}
    bounds, _ = common._job(
        value,
        {key: item for key, item in issued.items() if key != "runtimes"},
        runtime["attempts"][0],
        admission,
        record,
        1,
        request_check=lambda: request_bounds(measured["requests"], plans[0]),
        count_inventory=True,
    )
    require(measured["case_sha256"] == host.digest(first["case_spec"]))
    common.grants(value, issued, admission, bounds[0], bounds[2])
    issued_grants = {grant["id"] for grant in proof["local"]["grants"]["grants"]}
    require(
        not issued_grants.intersection(
            grant["id"] for grant in proof["grants"]["grants"]
        )
    )
    require(
        common.stamp(physical["identity"]["started_at"], physical=True)
        <= common.stamp(measured["bound_at"], physical=True)
        <= common.stamp(measured["released_at"], physical=True)
        <= common.stamp(physical["finished_at"], physical=True)
    )
    require(type(issued["approvals"]) is list and len(issued["approvals"]) == 1)
    common.same(
        {key: item for key, item in issued["approvals"][0].items() if key != "issued"},
        {key: item for key, item in approvals[0].items() if key != "issued"},
    )
    traffic = common.fields(proof["traffic"], {"before", "after"})
    common.same(traffic["before"], [])
    common.same(traffic["after"], measured["requests"])
    common.same(
        fixed,
        {
            "status": "passed",
            "physical": physical,
            "before_worker": fixed["before_worker"],
            "inventory": issued,
            "requests": measured["requests"],
            "case_sha256": measured["case_sha256"],
            "evidence_count": 5,
            "evidence_sha256": measured["evidence_sha256"],
        },
    )
    eligibility = common.fields(
        proof["eligibility"],
        {
            "schema",
            "origin",
            "approver_id",
            "authority_snapshot",
            "case",
            "context",
            "original_context",
            "observed_at",
        },
    )
    require(
        eligibility["schema"] == "vardr.map-issuance-request/1"
        and eligibility["origin"] == "map"
        and eligibility["approver_id"] == second["review_authority"]["owner"]
    )
    common.same(eligibility["case"], second["case_spec"])
    common.same(eligibility["original_context"], second["review_context"])
    common.same(eligibility["authority_snapshot"], second["review_authority"])
    common.fields(eligibility["context"], CONTEXT)
    common.local(proof["retained"], admission, 1, retired=True)
    common.fields(proof["grants"], {"policy_reason", "grants"})
    oracle = object.__new__(fixture.Fixture)
    verified = oracle.verify_count_limit(
        physical,
        admission,
        measured,
        proof["inventories"],
        proof["local"],
        proof["retirement"],
        proof["retained"],
        eligibility,
        proof["grants"],
        [row["review_context"] for row in proof["selections"]],
    )
    common.same({key: item for key, item in case.items() if key != "proof"}, verified)
    return {
        "schema": "vardr.nm2-worker-count-public/1",
        "status": "selected_count_control_slice_passed",
        "nm2_exit_status": "incomplete",
        "remaining_matrix_status": "not_closed",
        "cases": {
            name: "passed"
            if name in {"default_disabled", "strict_out_of_scope", CASE}
            else "not_run"
            for name in sorted(CASES)
        },
        "measurements": {
            "issued_attempts": 1,
            "target_request_count": 5,
            "evidence_count": 5,
            "unissued_target_charge": 0,
            "unissued_duration_charge": 0,
            "remaining_local_holds": 0,
            "limits": admission["limits"],
            "last_sequence": "1",
            "stopped_owned_container_count": 6,
            "runtime_sha256": admission["runtime_sha256"],
            "admission_sha256": admission["admission_sha256"],
            "retirement_receipt_sha256": proof["retirement"]["receipt_sha256"],
            "public_ca_der_sha256": raw["public_ca_der_sha256"],
            "case_sha256": measured["case_sha256"],
            "plan_sha256": [host.digest(plan) for plan in plans],
            "artifact_sha256": measured["artifact_sha256"],
            "evidence_sha256": measured["evidence_sha256"],
        },
        "executables": {
            "native_owner_sha256": executables["/usr/local/bin/vardr-worker-owner"],
            "gate_sha256": executables["/usr/local/bin/vardrgate"],
        },
        "source_inventories": source_inventories,
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
        raise common.ProjectionRefused("nm2_count_projection_refused") from None


def project_desktop(raw, selection, before, after):
    try:
        result = _project(raw, selection, desktop=True)
        guard = common._desktop_inventory(
            raw, selection, before, after, raw["cases"][CASE]["physical"]
        )
        return {
            **result,
            "schema": "vardr.nm2-worker-count-desktop-public/1",
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
        raise common.ProjectionRefused("nm2_count_projection_refused") from None
