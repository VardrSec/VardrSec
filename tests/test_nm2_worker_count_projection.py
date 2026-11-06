"""Source-derived production-wire facts through actual V6 producer, mocked I/O.

The fixed five-GET plan is a literal wire fixture, never an actually compiled plan.
No real Runner compiler/signer, network, Docker or target execution occurs here.
"""

import copy
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

import nm2_worker_acceptance as fixture
import nm2_worker_count_projection as projection
import nm2_worker_hosted as hosted
import nm2_worker_persistent_projection as availability
import test_nm2_worker_persistent_projection as original
import test_nm2_worker_hosted as hosted_vectors
import worker_host as host
import worker_host_persistent as persistent


def _case(name):
    owner = object.__new__(fixture.Fixture)
    owner.project = "vardrsec-nm2-casewire"

    def api(path, body=None, **options):
        if path == "/engagements":
            return {"id": "case-engagement"}
        if path.endswith("/authorizations"):
            return {"id": "case-authorization"}
        if path.endswith("/test-cases"):
            return {"id": "case-wire", **copy.deepcopy(body)}
        if path.endswith("/jobs"):
            return {"id": "case-job"}
        return {}

    owner.api = Mock()
    owner.api.request.side_effect = api
    return owner.new_job(name, marker=True)[3]["spec"]


def _wire_plan(spec, gate):
    # Literal five-GET profile from authorization/plan.py's documented wire shape.
    # Intentionally independent of the reader's fixed_plan helper.
    marker = spec["id"].removeprefix("nm2-")
    session = fixture.ORIGIN + "/session?nm2_case=" + marker
    resource = (
        fixture.ORIGIN + "/fixed/records/42?view=full&include=owner&nm2_case=" + marker
    )
    entries = [
        ("preflight", "owner", session),
        ("preflight", "peer", session),
        ("resource", "owner", resource),
        ("resource", "peer", resource),
        ("resource", "anonymous", resource),
    ]
    return {
        "schema": "vardr.execution-plan/1",
        "profile": "gate-fixed-http/1",
        "tool_sha256": gate,
        "case_hash": host.digest(spec),
        "execution": {
            "timeout_seconds": 20,
            "max_response_bytes": 65536,
            "allow_private_targets": True,
        },
        "credential_references": [
            {
                "identity_id": "owner",
                "source": "value_env",
                "name": "FIXTURE_OWNER_TOKEN",
            },
            {
                "identity_id": "peer",
                "source": "value_env",
                "name": "FIXTURE_PEER_TOKEN",
            },
        ],
        "dispatches": [
            {
                "phase": phase,
                "identity_id": who,
                "request": {
                    "method": "GET",
                    "url": url,
                    "headers": {},
                    "query_params": {},
                    "body": None,
                },
                "max_dispatches": 1,
            }
            for phase, who, url in entries
        ],
        "max_http_dispatches": 5,
    }


def vector():
    old, selection = original.vector()
    before_case = old["cases"]["persistent_availability"]
    before_proof = before_case["proof"]
    admission = copy.deepcopy(before_proof["idle"]["admission"])
    admission["identity"]["started_at"] = "2026-11-06T02:00:00.500000000Z"
    admission["runtime_sha256"] = host.digest(admission["identity"])
    admission["limits"] = {"max_attempts": "1", "idle_timeout_seconds": None}
    admission["admission_sha256"] = host.digest(
        {key: item for key, item in admission.items() if key != "admission_sha256"}
    )
    physical = copy.deepcopy(before_case["physical"])
    physical.update(
        exit_code=0,
        operator_stop_state="not_requested",
        admission_sha256=admission["admission_sha256"],
    )
    physical["identity"] = copy.deepcopy(admission["identity"])
    physical["runtime_sha256"] = admission["runtime_sha256"]
    runtime = copy.deepcopy(before_proof["runtime"])
    runtime["identity"] = copy.deepcopy(admission["identity"])
    runtime["runtime_sha256"] = admission["runtime_sha256"]
    runtime.update(
        max_attempts=1,
        last_sequence="1",
        head_sequence="1",
        admission=admission,
        admission_sha256=admission["admission_sha256"],
    )
    runtime["attempts"] = [runtime["attempts"][0]]
    issued, pending = copy.deepcopy(before_proof["inventories"][:2])
    measured = copy.deepcopy(before_case["attempts"][0])
    local = measured.pop("local")
    grants = copy.deepcopy(before_case["attempts"][1]["local"]["grants"])
    for grant in grants["grants"]:
        grant["issued_at"] = "2026-11-06T02:00:00.000000+00:00"
    gate = old["image_sources"]["runner"]["executables"]["/usr/local/bin/vardrgate"]
    specs = [_case("count-a"), _case("count-b")]
    plans = [_wire_plan(spec, gate) for spec in specs]
    expiry, approved = "2026-11-06T02:05:00Z", "2026-11-06T02:00:00Z"
    inputs, contexts, authorities = [], [], []
    for number, (inventory, spec, plan) in enumerate(
        zip((issued, pending), specs, plans, strict=True), 1
    ):
        approval = inventory["approvals"][0]
        refs = [
            {**reference, "revision": 1, "expires_at": expiry}
            for reference in plan["credential_references"]
        ]
        approval.update(approved_at=approved, expires_at=expiry, credential_grants=refs)
        authorization = "authorization-" + str(number)
        authority = {
            "schema": "vardr.map-managed-authority/1",
            "origin": admission["origin"],
            "authority_revision": 1,
            "authority": {
                "authorization": {
                    "id": authorization,
                    "status": "active",
                    "permits": "Owned synthetic fixture only",
                    "authorized_by": "Fixture local owner",
                    "reference": selection["project"],
                    "window_start": "2026-11-06T01:59:00Z",
                    "window_end": "2026-11-06T02:15:00Z",
                },
                "scope": [
                    {"value": fixture.ORIGIN + "/", "kind": "url", "scope_type": "in"}
                ],
                "engagement_id": inventory["engagement_id"],
            },
            "owner": "synthetic-owner",
            "engagement_type": "bug_bounty",
            "engagement_status": "active",
            "limits": {"concurrency": 1, "targets": 5, "duration": 120},
            "enrollment": {
                "id": admission["enrollment_id"],
                "revision": 1,
                "api_key_id": "synthetic-api-key-id",
                "principal_sha256": "8" * 64,
                "runner_id": admission["runner_id"],
            },
        }
        context = {
            "runner_id": admission["runner_id"],
            "engagement_id": inventory["engagement_id"],
            "job_id": inventory["job_id"],
            "authority_revision": 1,
            "authority_sha256": host.digest(authority),
            "plan_sha256": host.digest(plan),
            "mode": "strict",
            "scope": [
                {
                    "origin": fixture.ORIGIN,
                    "path": urlsplit(row["request"]["url"]).path,
                    "method": "GET",
                    "excluded": False,
                    "reason": "",
                }
                for row in plan["dispatches"]
            ],
            "exceptions": [],
            "not_before": approved,
            "expires_at": expiry,
            "testing_start": "2026-11-06T01:59:00Z",
            "testing_end": "2026-11-06T02:15:00Z",
            "max_executions": 1,
            "max_duration_seconds": 30,
            "max_http_dispatches": 5,
            "max_artifact_bytes": 1024 * 1024,
            "credential_grants": refs,
            "control": "managed_online",
        }
        inputs.append(
            {
                "enrollment_id": admission["enrollment_id"],
                "authorization_id": authorization,
                "plan": plan,
                "expires_at": expiry,
                "max_executions": 1,
                "max_duration_seconds": 30,
                "max_artifact_bytes": 1024 * 1024,
                "credential_grants": refs,
            }
        )
        contexts.append(context)
        authorities.append(authority)
    for inventory, context in zip((issued, pending), contexts, strict=True):
        inventory["schema"] = "vardr.nm2-fixture-inventory/4"
        inventory["approval_context_sha256"] = {
            inventory["approvals"][0]["id"]: host.digest(context)
        }
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
    case_hash = host.digest(specs[0])
    binding = runtime["attempts"][0]["binding"]
    result = host.digest(
        {
            "schema": "vardr.managed-result/1",
            **binding,
            "artifact_sha256": measured["artifact_sha256"],
            "case_sha256": case_hash,
        }
    )
    terminal = {
        "schema": "vardr.managed-completion/1",
        **binding,
        "outcome": "completed",
        "capacity_reserved": False,
        "receipt_sha256": result,
    }
    release = {
        "schema": "vardr.worker-idle-release/2",
        **{
            key: admission[key]
            for key in ("runtime_id", "runtime_sha256", "admission_sha256")
        },
        "runtime_sequence": "1",
        "binding": binding,
        "terminal_receipt_sha256": host.digest(terminal),
        "native_done_sha256": measured["native_done_sha256"],
        "released": True,
    }
    release["receipt_sha256"] = host.digest(release)
    runtime["attempts"][0].update(
        terminal_receipt=terminal,
        terminal_receipt_sha256=host.digest(terminal),
        release_receipt=release,
    )
    issued["results"][0]["receipt_sha256"] = result
    issued["runtimes"] = [runtime]
    local.update(
        runtime_sha256=admission["runtime_sha256"],
        admission_sha256=admission["admission_sha256"],
    )
    local["attempt"].update(completion=terminal, release=release)
    report = persistent._purpose(
        {"runtime_id": physical["runtime_id"]},
        {
            **{
                key: physical[key]
                for key in (
                    "runtime_sha256",
                    "admission_sha256",
                    "finished_at",
                    "exit_code",
                )
            },
            "observation_sha256": host.digest(
                {key: physical[key] for key in ("identity", "finished_at", "exit_code")}
            ),
            "last_sequence": "1",
        },
    )
    runtime["report_sha256"] = report
    retirement = {
        "schema": "vardr.worker-retirement/3",
        **{
            key: admission[key]
            for key in (
                "runtime_id",
                "runtime_sha256",
                "admission_sha256",
                "origin",
                "runner_id",
                "enrollment_id",
            )
        },
        "runtime_sequence": None,
        "last_sequence": "1",
        "binding": None,
        "attempt_receipt": None,
        "report_sha256": report,
        "retired": True,
    }
    retirement["receipt_sha256"] = host.digest(retirement)
    retained = copy.deepcopy(local)
    retained.pop("grants")
    retained.update(state="retired", retirement=retirement)
    retained["attempt"].update(
        state="physical_retirement_observed", retired_from_state="released"
    )
    first_before = copy.deepcopy(issued)
    first_before.update(
        job_status="pending",
        execution=None,
        targets_spent=0,
        duration_allocated=0,
        contracts=[],
        results=[],
        stops=[],
        runtimes=[],
    )
    first_before["approvals"][0]["issued"] = 0
    rows = []
    for index, entry in enumerate(plans[0]["dispatches"], 1):
        parsed = urlsplit(entry["request"]["url"])
        rows.append(
            {
                "identity": entry["identity_id"],
                "method": "GET",
                "path": parsed.path + "?" + parsed.query,
                "received_monotonic_ns": index,
            }
        )
    assessment = {
        "status": "conclusive",
        "baseline_valid": True,
        "case_snapshot_verified": True,
        "preflight": {"status": "passed"},
        "case_hash": case_hash,
        "candidate_findings": 0,
    }
    evidence = [
        {
            "body": "synthetic-redacted-evidence-" + str(number),
            "content_hash": fixture.digest(
                ("synthetic-redacted-evidence-" + str(number)).encode()
            ),
        }
        for number in range(5)
    ]
    eligibility = {
        "schema": "vardr.map-issuance-request/1",
        "origin": "map",
        "approver_id": "synthetic-owner",
        "authority_snapshot": copy.deepcopy(authorities[1]),
        "case": copy.deepcopy(specs[1]),
        "context": {**copy.deepcopy(contexts[1]), "not_before": "2026-11-06T02:02:01Z"},
    }
    owner = object.__new__(fixture.Fixture)
    owner.scenario, owner.protocol, owner.database_revision = (
        fixture.COUNT_SCENARIO,
        "persistent-v3",
        "0041persistentruntime",
    )
    owner.issuer_origin, owner.project, owner.secrets = (
        admission["origin"],
        selection["project"],
        [],
    )
    raw = copy.deepcopy(old)
    raw.update(
        schema="vardr.nm2-worker-count-acceptance/1",
        scenario="persistent-count-limit",
        acceptance_scope="persistent_count_control_only",
        status="prepared",
        stage="count_control_setup",
    )
    raw["cases"].pop("persistent_availability")
    raw["cases"]["strict_out_of_scope"]["inventory"].update(
        schema="vardr.nm2-fixture-inventory/4", approval_context_sha256={}
    )
    raw["cases"]["persistent_count_limit"] = {"status": "not_run"}
    owner.receipt = raw
    owner.new_job = Mock(
        side_effect=[
            (
                issued["engagement_id"],
                inputs[0]["authorization_id"],
                issued["job_id"],
                {"spec": specs[0]},
            ),
            (
                pending["engagement_id"],
                inputs[1]["authorization_id"],
                pending["job_id"],
                {"spec": specs[1]},
            ),
        ]
    )

    def approved(_name, _engagement, _authorization, job, _case, **options):
        index = 0 if job == issued["job_id"] else 1
        options["review_snapshot"].update(copy.deepcopy(inputs[index]))
        options["review_context"].update(copy.deepcopy(contexts[index]))
        options["review_authority"].update(copy.deepcopy(authorities[index]))
        return admission["runner_id"], admission["enrollment_id"]

    def api(path, *args, **options):
        if path.endswith("/jobs"):
            return {
                "jobs": [
                    {"id": issued["job_id"], "status": "done", "assessment": assessment}
                ]
            }
        if "/managed/approval/review" in path:
            return copy.deepcopy(eligibility)
        if "/scans?" in path:
            return {"scans": []}
        if "/evidence?" in path:
            return {"evidence": evidence}
        raise AssertionError("unexpected synthetic API route")

    owner.approve = Mock(side_effect=approved)
    owner.api = Mock()
    owner.api.request.side_effect = api
    owner.inventory = Mock(
        side_effect=[first_before, copy.deepcopy(pending), issued, pending]
    )
    owner.traffic = Mock(side_effect=[[], rows])
    owner.worker = Mock(
        side_effect=lambda *_args, on_running: (on_running(admission), physical)[1]
    )
    owner.persistent_metadata = Mock(side_effect=[local, retained])
    owner.grant_snapshot = Mock(side_effect=[local["grants"], grants])
    owner.report_exit = Mock(return_value=retirement)
    owner.worker_action = Mock(
        return_value={
            "state": "terminal_observed",
            "receipt": {"retirement": retirement},
        }
    )
    owner.helper = Mock(
        return_value=b'{"state":"terminal_completed","remaining_local_holds":0}'
    )
    with patch.object(fixture, "datetime", wraps=datetime) as clock:
        clock.now.return_value = datetime(2026, 11, 6, 2, 2, 1, tzinfo=timezone.utc)
        owner.persistent_count_limit([])
    return raw, selection


class CountProjection(unittest.TestCase):
    def test_real_v6_producer_and_fixed_verifier_feed_independent_count_reader(self):
        raw, selection = vector()
        public = projection.project(raw, selection)
        self.assertEqual(public["schema"], "vardr.nm2-worker-count-public/1")
        self.assertEqual(public["measurements"]["target_request_count"], 5)
        self.assertEqual(public["measurements"]["issued_attempts"], 1)
        self.assertEqual(public["measurements"]["unissued_target_charge"], 0)
        self.assertNotIn("idle_seconds", public["measurements"])
        self.assertEqual(hosted.public_projection(raw, selection), public)
        with self.assertRaises(availability.ProjectionRefused):
            availability.project(raw, selection)

    def test_count_dispatch_is_explicit_and_schema0041_only(self):
        self.assertEqual(
            hosted.execution_options({}), ("healthy", "0040runtimesequence")
        )
        self.assertEqual(
            hosted.execution_options(
                {
                    "NM2_SCENARIO": "persistent-count-limit",
                    "NM2_DATABASE_REVISION": "0041persistentruntime",
                }
            ),
            ("persistent-count-limit", "0041persistentruntime"),
        )
        with self.assertRaises(hosted.HostedRefused):
            hosted.execution_options({"NM2_SCENARIO": "persistent-count-limit"})

    def test_count_failure_exports_only_fixed_stage_and_reason(self):
        raw, selection = vector()
        raw.update(
            status="held",
            stage="count_control_eligibility",
            reason="count_second_job_not_eligible",
            stderr="private-canary",
            error="private-canary",
        )
        self.assertEqual(
            hosted.failure_projection(raw, selection),
            {
                "stage": "count_control_eligibility",
                "reason": "count_second_job_not_eligible",
            },
        )

    def test_rehashed_original_case_and_plan_cannot_define_their_own_oracle(self):
        raw, selection = vector()
        proof = raw["cases"]["persistent_count_limit"]["proof"]
        base = proof["selections"][0]
        before = proof["fixed"]["before_worker"]
        gate = raw["image_sources"]["runner"]["executables"]["/usr/local/bin/vardrgate"]
        changes = (
            (
                "case",
                lambda row: row["case_spec"]["expected_access"][1].update(
                    decision="allow"
                ),
            ),
            (
                "method",
                lambda row: row["review_input"]["plan"]["dispatches"][2][
                    "request"
                ].update(method="POST"),
            ),
            (
                "origin",
                lambda row: row["review_input"]["plan"]["dispatches"][2][
                    "request"
                ].update(url="http://foreign.test:8080/fixed/records/42"),
            ),
            (
                "body",
                lambda row: row["review_input"]["plan"]["dispatches"][2][
                    "request"
                ].update(body="unreviewed"),
            ),
            (
                "extra",
                lambda row: row["review_input"]["plan"].update(
                    retention_fixture="mock-plan"
                ),
            ),
            (
                "allowance",
                lambda row: row["review_input"]["plan"].update(max_http_dispatches=6),
            ),
            (
                "tool",
                lambda row: row["review_input"]["plan"].update(tool_sha256="0" * 64),
            ),
        )
        for label, change in changes:
            with self.subTest(label=label):
                original_case = copy.deepcopy(base)
                change(original_case)
                original_case["review_input"]["plan"]["case_hash"] = host.digest(
                    original_case["case_spec"]
                )
                original_case["review_context"]["plan_sha256"] = host.digest(
                    original_case["review_input"]["plan"]
                )
                with self.assertRaises(ValueError):
                    projection.review(
                        original_case,
                        proof["admission"],
                        before,
                        gate,
                        selection["project"],
                    )

    def test_rehashed_original_authority_and_typed_permission_refuse_substitution(self):
        raw, selection = vector()
        proof = raw["cases"]["persistent_count_limit"]["proof"]
        base = proof["selections"][0]
        before = proof["fixed"]["before_worker"]
        gate = raw["image_sources"]["runner"]["executables"]["/usr/local/bin/vardrgate"]
        changes = (
            lambda row: row["review_authority"].update(
                origin="https://foreign.test/backend"
            ),
            lambda row: row["review_authority"]["authority"]["authorization"].update(
                status="revoked"
            ),
            lambda row: row["review_authority"]["authority"]["authorization"].update(
                reference="another-project"
            ),
            lambda row: row["review_authority"]["authority"]["scope"][0].update(
                value="http://foreign.test/"
            ),
            lambda row: row["review_authority"]["enrollment"].update(
                runner_id="another-runner"
            ),
            lambda row: row["review_authority"]["enrollment"].update(revision=True),
            lambda row: row["review_authority"]["limits"].update(concurrency=1.0),
            lambda row: row["review_context"].update(max_executions=True),
        )
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                row = copy.deepcopy(base)
                change(row)
                row["review_context"]["authority_sha256"] = host.digest(
                    row["review_authority"]
                )
                with self.assertRaises(ValueError):
                    projection.review(
                        row, proof["admission"], before, gate, selection["project"]
                    )

    def test_complete_originals_traffic_receipts_and_eligible_second_job_are_required(
        self,
    ):
        changes = (
            (("proof", "selections", 0, "review_authority"), {}),
            (
                ("proof", "selections", 0, "review_input", "plan"),
                {"retention_fixture": "mock-plan"},
            ),
            (("proof", "pending_before", "targets_spent"), 1),
            (("proof", "fixed", "before_worker", "execution"), {"state": "running"}),
            (("proof", "traffic", "before"), [{"path": "/hidden-before"}]),
            (("proof", "traffic", "after"), []),
            (("proof", "local", "remaining_local_holds"), 1),
            (("proof", "local", "attempt", "consumption_acknowledged"), 0),
            (("proof", "local", "attempt", "native_done_sha256"), "0" * 64),
            (("proof", "retained", "attempt", "artifact_sha256"), "0" * 64),
            (("proof", "inventories", 1, "approvals", 0, "issued"), 1),
            (("proof", "inventories", 1, "targets_spent"), 1),
            (
                ("proof", "eligibility", "case", "expected_access", 1, "decision"),
                "allow",
            ),
            (("proof", "eligibility", "original_context", "plan_sha256"), "0" * 64),
            (("proof", "grants", "grants", 0, "status"), "revoked"),
            (("physical", "exit_code"), False),
            (("physical", "operator_stop_state"), "stopped_observed"),
            (("limits", "max_attempts"), None),
            (("issued_attempts",), 1.0),
            (("target_request_count",), 6),
        )
        base, selection = vector()
        for path, replacement in changes:
            with self.subTest(path=path):
                raw = copy.deepcopy(base)
                row = raw["cases"]["persistent_count_limit"]
                for key in path[:-1]:
                    row = row[key]
                row[path[-1]] = replacement
                with self.assertRaises(availability.ProjectionRefused):
                    projection.project(raw, selection)
        raw = copy.deepcopy(base)
        proof = raw["cases"]["persistent_count_limit"]["proof"]
        for rows in (
            proof["measured"]["requests"],
            proof["fixed"]["requests"],
            proof["traffic"]["after"],
        ):
            rows[2]["path"] = (
                "/fixed/records/42?view=other&include=owner&nm2_case=count-a"
            )
        with self.assertRaises(availability.ProjectionRefused):
            projection.project(raw, selection)

    def test_public_count_scope_never_exports_originals_or_becomes_availability(self):
        raw, selection = vector()
        raw["private_extra"] = "private-count-canary"
        public = projection.project(raw, selection)
        text = json.dumps(public)
        self.assertNotIn("private-count-canary", text)
        self.assertNotIn("FIXTURE_OWNER_TOKEN", text)
        self.assertNotIn("case_spec", text)
        self.assertNotIn("review_context", text)
        for schema, status in (
            (
                "vardr.nm2-worker-persistent-acceptance/1",
                "selected_availability_slice_passed",
            ),
            ("vardr.nm2-worker-acceptance/2", "initial_stages_passed"),
        ):
            invalid = copy.deepcopy(raw)
            invalid.update(schema=schema, status=status)
            with self.assertRaises(hosted.HostedRefused):
                hosted.public_projection(invalid, selection)

    def test_count_desktop_wrapper_rechecks_exact_owned_exit_and_inventory(self):
        raw, _selection = vector()
        desktop_raw, selection, before, after = original.desktop_vector()
        raw.update(
            platform="win32",
            sources=copy.deepcopy(selection["sources"]),
            admitted_inventory_diffs=desktop_raw["admitted_inventory_diffs"],
        )
        physical = raw["cases"]["persistent_count_limit"]["physical"]
        worker = after["containers"][physical["identity"]["container_id"]]
        worker["state"].update(
            exit_code=physical["exit_code"],
            finished_at=physical["finished_at"],
            started_at=physical["identity"]["started_at"],
        )
        raw["before_sha256"], raw["after_sha256"] = (
            host.digest(before),
            host.digest(after),
        )
        public = projection.project_desktop(raw, selection, before, after)
        self.assertEqual(public["schema"], "vardr.nm2-worker-count-desktop-public/1")
        self.assertEqual(public["platform"], "win32")
        self.assertEqual(public["measurements"]["issued_attempts"], 1)
        after["containers"][physical["identity"]["container_id"]]["state"][
            "exit_code"
        ] = 125
        raw["after_sha256"] = host.digest(after)
        with self.assertRaises(availability.ProjectionRefused):
            projection.project_desktop(raw, selection, before, after)

    def test_hosted_count_orchestration_uses_persistent_image_and_exact_raw_schema(
        self,
    ):
        for wrong_schema in (False, True):
            with self.subTest(wrong_schema=wrong_schema):
                raw, selection = vector()
                if wrong_schema:
                    raw["schema"] = "vardr.nm2-worker-persistent-acceptance/1"
                with (
                    tempfile.TemporaryDirectory() as temporary,
                    patch.object(hosted, "host_guard", return_value=Path(temporary)),
                    patch.object(hosted.socket, "socket"),
                ):
                    owner = hosted.Hosted(
                        {
                            **hosted_vectors.environment(temporary),
                            "NM2_SCENARIO": "persistent-count-limit",
                            "NM2_DATABASE_REVISION": "0041persistentruntime",
                        }
                    )
                    owner.project = selection["project"]
                    owner.pins = {
                        name: row["commit"]
                        for name, row in selection["sources"].items()
                    }
                    owner.receipt["sources"] = owner.pins
                    owner.sources = {
                        name: PurePosixPath(row["path"])
                        for name, row in selection["sources"].items()
                    }
                    owner.daemon_guard, owner.prepare_sources = Mock(), Mock()
                    toolkit = "sha256:" + "f" * 64
                    owner.build = Mock(
                        side_effect=lambda name, context, **options: (
                            toolkit if name == "toolkit" else selection["images"][name],
                            owner.project + ":" + name,
                        )
                    )
                    owner.docker = Mock(return_value=toolkit)

                    def command(args, **options):
                        if "--execute" not in args:
                            return
                        selected = json.loads((owner.root / "cohort.json").read_text())
                        self.assertEqual(selected["sources"], selection["sources"])
                        self.assertEqual(selected["images"], selection["images"])
                        directory = owner.root / "installation"
                        directory.mkdir()
                        (directory / "nm2-worker-receipt.json").write_bytes(
                            host.canonical(raw)
                        )

                    owner.command = Mock(side_effect=command)
                    if wrong_schema:
                        with self.assertRaises(hosted.HostedRefused):
                            owner.run()
                    else:
                        owner.run()
                    receipt = json.loads((owner.public / "receipt.json").read_text())
                    self.assertEqual(
                        owner.build.call_args_list[-1].kwargs["file"].name,
                        "Dockerfile.worker.persistent",
                    )
                    invocation = next(
                        call.args[0]
                        for call in owner.command.call_args_list
                        if "--execute" in call.args[0]
                    )
                    self.assertEqual(
                        invocation[invocation.index("--scenario") + 1],
                        "persistent-count-limit",
                    )
                    self.assertEqual(
                        invocation[invocation.index("--database-revision") + 1],
                        "0041persistentruntime",
                    )
                    self.assertEqual(receipt["schema"], "vardr.nm2-hosted/4")
                    self.assertNotIn("private-do-not-publish", json.dumps(receipt))
                    if wrong_schema:
                        self.assertEqual(
                            (receipt["status"], receipt["stage"]), ("held", "harness")
                        )
                        self.assertNotIn("measurements", receipt)
                    else:
                        self.assertEqual(
                            receipt["status"], "selected_count_control_slice_passed"
                        )
                        self.assertEqual(receipt["measurements"]["issued_attempts"], 1)

    def test_remote_identity_and_nested_retained_shapes_cannot_be_substituted(self):
        base, selection = vector()
        changes = (
            lambda proof: proof["inventories"][0]["runtimes"][0]["identity"].update(
                container_id="e" * 64
            ),
            lambda proof: proof["retained"].update(unreviewed="private-canary"),
            lambda proof: proof["grants"].update(unreviewed="private-canary"),
        )
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                raw = copy.deepcopy(base)
                change(raw["cases"]["persistent_count_limit"]["proof"])
                with self.assertRaises(availability.ProjectionRefused):
                    projection.project(raw, selection)

    def test_original_first_authority_cannot_drift_from_registered_approval(self):
        raw, selection = vector()
        row = raw["cases"]["persistent_count_limit"]["proof"]["selections"][0]
        row["review_input"]["authorization_id"] = "another-authorization"
        row["review_authority"]["authority"]["authorization"]["id"] = (
            "another-authorization"
        )
        row["review_context"]["authority_sha256"] = host.digest(row["review_authority"])
        with self.assertRaises(availability.ProjectionRefused):
            projection.project(raw, selection)

    def test_physical_exit_one_nanosecond_after_eligibility_refuses(self):
        raw, selection = vector()
        case = raw["cases"]["persistent_count_limit"]
        proof = case["proof"]
        case["physical"]["finished_at"] = "2026-11-06T02:02:01.000000001Z"
        proof["fixed"]["physical"] = case["physical"]
        physical = case["physical"]
        report = persistent._purpose(
            {"runtime_id": physical["runtime_id"]},
            {
                **{
                    key: physical[key]
                    for key in (
                        "runtime_sha256",
                        "admission_sha256",
                        "finished_at",
                        "exit_code",
                    )
                },
                "observation_sha256": host.digest(
                    {
                        key: physical[key]
                        for key in ("identity", "finished_at", "exit_code")
                    }
                ),
                "last_sequence": "1",
            },
        )
        proof["inventories"][0]["runtimes"][0]["report_sha256"] = report
        proof["retirement"]["report_sha256"] = report
        proof["retirement"]["receipt_sha256"] = host.digest(
            {
                key: value
                for key, value in proof["retirement"].items()
                if key != "receipt_sha256"
            }
        )
        proof["retained"]["retirement"] = copy.deepcopy(proof["retirement"])
        with self.assertRaises(availability.ProjectionRefused):
            projection.project(raw, selection)

    def test_second_approval_and_catalog_were_queued_before_worker_started(self):
        base, selection = vector()
        for kind in ("approval", "catalog"):
            with self.subTest(kind=kind):
                raw = copy.deepcopy(base)
                proof = raw["cases"]["persistent_count_limit"]["proof"]
                if kind == "approval":
                    for inventory in (proof["pending_before"], proof["inventories"][1]):
                        inventory["approvals"][0]["approved_at"] = (
                            "2026-11-06T02:02:00.500000Z"
                        )
                else:
                    for grant in proof["grants"]["grants"]:
                        grant["issued_at"] = "2026-11-06T02:02:00.500000+00:00"
                with self.assertRaises(availability.ProjectionRefused):
                    projection.project(raw, selection)

    def test_nine_digit_physical_exit_works_with_py310_parser_contract(self):
        raw, selection = vector()

        def legacy_fromisoformat(value):
            fraction = re.search(r"\.(\d+)", value)
            if fraction is not None and len(fraction[1]) not in (3, 6):
                raise ValueError("modeled_python310_fraction_refusal")
            return datetime.fromisoformat(value)

        with patch.object(fixture, "datetime", wraps=datetime) as clock:
            clock.fromisoformat.side_effect = legacy_fromisoformat
            public = projection.project(raw, selection)
        self.assertEqual(public["measurements"]["issued_attempts"], 1)
        self.assertTrue(
            raw["cases"]["persistent_count_limit"]["physical"]["finished_at"].endswith(
                ".123456789Z"
            )
        )
        for bad in (
            "2026-02-30T02:02:00.123456789Z",
            "2026-11-06T02:02:00.1234567890Z",
            "2026-11-06T02:02:00.123456789+00:00",
        ):
            with self.subTest(bad=bad):
                invalid = copy.deepcopy(raw)
                invalid["cases"]["persistent_count_limit"]["physical"][
                    "finished_at"
                ] = bad
                with self.assertRaises(availability.ProjectionRefused):
                    projection.project(invalid, selection)

    def test_registered_context_map_requires_exact_before_and_post_approval_ids(self):
        base, selection = vector()
        for which in ("first-before", "pending-before", "first-post", "pending-post"):
            for changed in ({}, {"foreign": "0" * 64}, {"original": False}):
                with self.subTest(which=which, changed=changed):
                    raw = copy.deepcopy(base)
                    proof = raw["cases"]["persistent_count_limit"]["proof"]
                    inventory = {
                        "first-before": proof["fixed"]["before_worker"],
                        "pending-before": proof["pending_before"],
                        "first-post": proof["inventories"][0],
                        "pending-post": proof["inventories"][1],
                    }[which]
                    inventory["approval_context_sha256"] = changed
                    with self.assertRaises(availability.ProjectionRefused):
                        projection.project(raw, selection)

    def test_physical_exit_one_nanosecond_before_original_release_refuses(self):
        from worker_runtime import _timestamp

        raw, selection = vector()
        case = raw["cases"]["persistent_count_limit"]
        proof = case["proof"]
        whole, nanos = _timestamp(proof["measured"]["released_at"])
        if nanos:
            nanos -= 1
        else:
            whole -= timedelta(seconds=1)
            nanos = 999999999
        finished = whole.isoformat(timespec="seconds") + f".{nanos:09d}Z"
        case["physical"]["finished_at"] = finished
        proof["fixed"]["physical"] = case["physical"]
        physical = case["physical"]
        report = persistent._purpose(
            {"runtime_id": physical["runtime_id"]},
            {
                **{
                    key: physical[key]
                    for key in (
                        "runtime_sha256",
                        "admission_sha256",
                        "finished_at",
                        "exit_code",
                    )
                },
                "observation_sha256": host.digest(
                    {
                        key: physical[key]
                        for key in ("identity", "finished_at", "exit_code")
                    }
                ),
                "last_sequence": "1",
            },
        )
        proof["inventories"][0]["runtimes"][0]["report_sha256"] = report
        proof["retirement"]["report_sha256"] = report
        proof["retirement"]["receipt_sha256"] = host.digest(
            {
                key: value
                for key, value in proof["retirement"].items()
                if key != "receipt_sha256"
            }
        )
        proof["retained"]["retirement"] = copy.deepcopy(proof["retirement"])
        with self.assertRaises(availability.ProjectionRefused):
            projection.project(raw, selection)
