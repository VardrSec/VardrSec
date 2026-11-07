"""Pure matched-host fixture and projection regressions."""

from contextlib import redirect_stdout
import io
import json
import unittest
from unittest.mock import Mock, call, patch

import nm2_worker_acceptance as fixture
import nm2_worker_hosted as hosted
import nm2_worker_strict_projection as projection


def digest(value):
    return fixture.digest(fixture.canonical(value))


def vector(*, desktop=False, block_positive=False):
    root = "C:/private-canary" if desktop else "/private-canary"
    selection = {
        "project": "vardrsec-nm2-fixture00",
        "sources": {name: {"path": f"{root}/{name}", "commit": "a" * 40}
                    for name in fixture.SOURCE_NAMES},
        "images": {name: "sha256:" + digit * 64 for digit, name in
                   zip("12345", sorted(fixture.IMAGE_NAMES))},
        "docker_context": "desktop-linux" if desktop else "default",
        "allow_empty_builtin_bridge_id_change": False,
    }
    raw = {
        "schema": fixture.STRICT_DRIFT_SCHEMA, "scenario": fixture.STRICT_DRIFT_SCENARIO,
        "acceptance_scope": fixture.STRICT_DRIFT_SCOPE, "nm2_exit_status": "incomplete",
        "platform": "win32" if desktop else "linux", "retained": True,
        "expected_database_revision": "0041persistentruntime",
        "readiness_volume": selection["project"] + "_worker-ready",
        **{key: selection[key] for key in ("sources", "images", "project")},
        "cases": {name: {"status": "not_run"} for name in fixture.INITIAL_CASES},
        "admitted_inventory_diffs": [],
    }
    raw["cases"]["default_disabled"] = {
        "status": "passed", "services": ["api", "db", "proxy", "web"],
        "managed_pending_status": 404, "csrf_write_status": 403, "unauthenticated_read_status": 401,
    }
    before = {"containers": {}, "volumes": {"prior": {"labels": {}, "options": {"test": 0}}},
              "networks": {}, "images": {}}
    after = json.loads(json.dumps(before))
    for digit, service in zip("12345", fixture.STRICT_DRIFT_SERVICES):
        cid = digit * 64
        after["containers"][cid] = {
            "id": cid, "image": selection["images"]["worker" if service == "gate-fixture" else service],
            "labels": {"com.docker.compose.service": service, "com.docker.compose.project": selection["project"]},
            "state": dict.fromkeys(("running", "paused", "restarting", "dead"), False),
        }
    raw.update(before_sha256=digest(before), after_sha256=digest(after),
               fixture_stop={"status": "stopped_retained", "container_ids": sorted(after["containers"]),
                             "stop_requested_ids": sorted(after["containers"])})

    run = object.__new__(fixture.Fixture)
    run.receipt = raw
    run.new_job = Mock(return_value=("private-eng", "private-auth", "private-job", {}))
    run.traffic = Mock(side_effect=[[], [], []])
    run.compose = Mock(return_value=(
        b"managed-worker" if block_positive else " ".join(fixture.STRICT_DRIFT_SERVICES).encode()
    ))
    run.worker = Mock(side_effect=AssertionError("worker must stay disabled"))
    empty = {
        "schema": "vardr.nm2-fixture-inventory/4", "schema_revision": "0041persistentruntime",
        "database_user": "vardrmap_app", "engagement_id": "private-eng", "job_id": "private-job",
        "runtime_attempt_bound": 35, "job_status": "pending", "execution": None,
        "targets_spent": 0, "duration_allocated": 0, "capacity_reserved_count": 0,
        "concurrency_limit": 1, "approvals": [], "contracts": [], "results": [], "stops": [], "runtimes": [],
        "approval_context_sha256": {},
    }
    authority = {
        "schema": "vardr.map-managed-authority/1", "authority_revision": 10,
        "authority": {"engagement_id": "private-eng",
                      "authorization": {"id": "private-auth", "status": "active"}},
    }
    review_input = {"authorization_id": "private-auth", "expires_at": "2026-11-07T20:05:00Z"}
    context = {
        "mode": "strict", "authority_revision": 10, "authority_sha256": digest(authority),
        "engagement_id": "private-eng", "job_id": "private-job",
        "not_before": "2026-11-07T20:00:00Z", "expires_at": review_input["expires_at"],
        "max_executions": 1, "max_duration_seconds": 30, "credential_grants": [],
    }
    registration = {"approval": {"signature": "private-registration-canary"}}

    def approve(*args, **kwargs):
        kwargs["review_snapshot"].update(review_input)
        kwargs["review_context"].update(context)
        kwargs["review_authority"].update(authority)
        kwargs["deferred_registration"].update(registration)

    run.approve = Mock(side_effect=approve)
    fresh_authority = {**authority, "authority_revision": 12}
    fresh_context = {**context, "authority_revision": 12, "authority_sha256": digest(fresh_authority),
                     "not_before": "2026-11-07T20:00:01Z"}
    approval_id = "issuer:fixture-strict-authority-drift-fresh"
    replacement = {"approval": {"signature": "private-replacement-canary"}}
    run.strict_drift_replacement = Mock(
        return_value=(context["not_before"], replacement, approval_id),
    )
    positive = {
        **empty, "approvals": [{
            "id": approval_id, "issued": 0, "revoked": False,
            "approved_at": fresh_context["not_before"], "expires_at": fresh_context["expires_at"],
            "max_executions": 1, "max_duration_seconds": 30, "credential_grants": [],
        }], "approval_context_sha256": {approval_id: digest(fresh_context)},
    }
    run.inventory = Mock(side_effect=[empty, dict(empty), positive])
    run.api = Mock()
    run.api.request.side_effect = [
        {"id": "private-auth", "program_id": "private-eng", "status": state}
        for state in ("revoked", "active")
    ] + [
        {"context": fresh_context, "authority_snapshot": fresh_authority},
        {"detail": "managed_approval_refused"},
        {"approval_record_id": approval_id},
    ]
    if not block_positive:
        run.strict_authority_drift()
    return raw, selection, before, after, run, registration, review_input, replacement


class StrictDriftHosted(unittest.TestCase):
    def test_exact_fixture_actions_and_sanitized_projection_on_both_hosts(self):
        for desktop in (False, True):
            with self.subTest(desktop=desktop):
                raw, selection, before, after, run, registration, review_input, replacement = vector(
                    desktop=desktop,
                )
                self.assertEqual(run.api.request.call_args_list, [
                    call("/engagements/private-eng/authorizations/private-auth", {"status": "revoked"}, method="PATCH"),
                    call("/engagements/private-eng/authorizations/private-auth", {"status": "active"}, method="PATCH"),
                    call("/jobs/private-job/managed/approval/review", review_input),
                    call("/jobs/private-job/managed/approval/register", registration, expected=409),
                    call("/jobs/private-job/managed/approval/register", replacement),
                ])
                self.assertEqual(run.inventory.call_args_list,
                                 [call("private-eng", "private-job", include_capacity=True)] * 3)
                run.strict_drift_replacement.assert_called_once()
                run.worker.assert_not_called()
                if desktop:
                    output = projection.project_desktop(raw, selection, before, after)
                    with self.assertRaises(hosted.HostedRefused):
                        hosted.public_projection(raw, selection, inventories=(before, after))
                else:
                    output = hosted.public_projection(raw, selection, inventories=(before, after))
                self.assertEqual(output["platform"], "win32" if desktop else "linux")
                self.assertEqual(output["stopped_owned_container_count"], 5)
                self.assertEqual(output["nm2_exit_status"], "incomplete")
                self.assertEqual(output["measurements"]["target_request_count"], 0)
                self.assertEqual(output["measurements"]["stale_registration_sha256"], digest(registration))
                self.assertEqual(output["measurements"]["fresh_registration_sha256"], digest(replacement))
                self.assertNotIn("private-", json.dumps(output))

    def test_positive_registration_refuses_if_worker_service_is_present(self):
        _, _, _, _, run, registration, _, replacement = vector(block_positive=True)
        with self.assertRaisesRegex(fixture.AcceptanceRefused, "strict_authority_drift_mutated_or_dispatched"):
            run.strict_authority_drift()
        self.assertIn(call("/jobs/private-job/managed/approval/register", registration, expected=409),
                      run.api.request.call_args_list)
        self.assertNotIn(call("/jobs/private-job/managed/approval/register", replacement),
                         run.api.request.call_args_list)

    def test_public_receipt_rejects_missing_or_inconsistent_observations(self):
        for change in ("revision", "expiry", "signature_time", "capacity", "traffic", "services",
                       "refusal", "positive_issued", "positive_context", "positive_same_hash",
                       "missing_inventory", "old_resource", "running", "proof_extra", "source"):
            with self.subTest(change=change):
                raw, selection, before, after, *_ = vector()
                proof = raw["cases"][fixture.STRICT_DRIFT_CASE]["proof"]
                if change == "revision":
                    proof["fresh"]["context"]["authority_revision"] = 10
                elif change == "expiry":
                    proof["fresh"]["context"]["not_before"] = proof["original"]["context"]["expires_at"]
                elif change == "signature_time":
                    proof["old_approved_at"] = "2026-11-07T20:00:02Z"
                elif change == "positive_issued":
                    proof["positive"]["inventory"]["approvals"][0]["issued"] = 1
                elif change == "positive_context":
                    key = proof["positive"]["approval_record_id"]
                    proof["positive"]["inventory"]["approval_context_sha256"][key] = "9" * 64
                elif change == "positive_same_hash":
                    proof["positive"]["registration_sha256"] = proof["registration_sha256"]
                elif change == "capacity":
                    proof["after"]["capacity_reserved_count"] = False
                elif change == "traffic":
                    proof["traffic_after"] = [{"private": "canary"}]
                elif change == "services":
                    proof["services"].append("managed-worker")
                elif change == "refusal":
                    proof["refusal"]["detail"] = "unrelated"
                elif change == "missing_inventory":
                    after = {}
                elif change == "old_resource":
                    after["volumes"]["prior"]["options"]["test"] = False
                elif change == "running":
                    after["containers"]["1" * 64]["state"]["running"] = True
                elif change == "proof_extra":
                    proof["raw_private"] = "canary"
                elif change == "source":
                    raw["sources"] = {**raw["sources"], "map": {"path": "/private-other", "commit": "b" * 40}}
                raw["after_sha256"] = digest(after)
                with self.assertRaises(hosted.HostedRefused):
                    hosted.public_projection(raw, selection, inventories=(before, after))

    def test_opt_in_routes_same_persistent_schema_without_execution(self):
        scenario = fixture.STRICT_DRIFT_SCENARIO
        self.assertEqual(hosted.execution_options({}), ("healthy", "0040runtimesequence"))
        with self.assertRaises(hosted.HostedRefused):
            hosted.execution_options({"NM2_SCENARIO": scenario})
        self.assertEqual(hosted.execution_options({
            "NM2_SCENARIO": scenario, "NM2_DATABASE_REVISION": "0041persistentruntime",
        }), (scenario, "0041persistentruntime"))
        _, selection, *_ = vector()
        output = io.StringIO()
        with (patch.object(fixture, "manifest", return_value=selection),
              patch.object(fixture.Fixture, "run", side_effect=AssertionError("no execution")),
              redirect_stdout(output)):
            self.assertEqual(fixture.main([
                "--cohort", "unused", "--scenario", scenario,
                "--database-revision", "0041persistentruntime",
            ]), 0)
        receipt = json.loads(output.getvalue())
        self.assertEqual(receipt["docker_calls"], 0)
        self.assertEqual(receipt["initial_cases"], ["default_disabled", fixture.STRICT_DRIFT_CASE])
