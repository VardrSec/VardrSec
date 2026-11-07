"""Pure owned capacity fixture and independent evidence checks."""
import copy
import json
import unittest
from unittest.mock import Mock

import nm2_worker_hosted as hosted
from nm2_worker_acceptance import AcceptanceRefused, ORIGIN, canonical, digest
from nm2_worker_launch_acceptance import LaunchFixture, budget_witness_count

HOLDER = "8fa9c83b-3e1a-491f-ac2d-c40081c34a44"
CONTENDER = "ddd8e594-dfcb-4ca2-83f8-abfda598e1a7"
RUNNER = "63ba16a0-37c6-4c96-a111-80ad0965ae71"
TOKEN = "test-only-control-token" * 2


def retained_inventory():
    return {
        "targets_spent": 1, "duration_allocated": 30, "capacity_reserved_count": 1,
        "concurrency_limit": 1, "job_status": "running",
        "execution": {
            "state": "active", "capacity_reserved": True, "target_charge": 1, "duration_seconds": 30,
        },
        **{key: [] for key in ("approvals", "contracts", "runtimes", "results", "stops")},
    }


class ConcurrencyWitnessTests(unittest.TestCase):
    def test_source_and_fixed_marker_are_distinct(self):
        scenario = hosted.LAUNCH_CONCURRENCY_SCENARIO
        env = {"NM2_SCENARIO": scenario, "NM2_DATABASE_REVISION": "0041persistentruntime",
               "NM2_MAP_SHA": hosted.CONCURRENCY_MAP_COMMIT}
        self.assertEqual(hosted.execution_options(env), (scenario, "0041persistentruntime"))
        with self.assertRaises(hosted.HostedRefused):
            hosted.execution_options({**env, "NM2_MAP_SHA": hosted.TARGET_MAP_COMMIT})
        with self.assertRaises(hosted.HostedRefused):
            hosted.execution_options({**env, "NM2_DATABASE_REVISION": "0040runtimesequence"})
        prefix = b"2026-11-07 11:27:07,387 WARNING managed_http managed_claim_"
        marker = prefix + b"concurrency_exhausted"
        self.assertEqual(budget_witness_count(b"\r\n".join([
            prefix + b"target_exhausted", marker, marker + b" extra", marker,
        ]), "concurrency"), 2)

    def test_reservation_only_claim_returns_original_private_finish_body(self):
        fixture = LaunchFixture.__new__(LaunchFixture)
        fixture.receipt = {}
        fixture.issuer_origin = "https://vardrsec.localhost:28443/backend"
        stored = {"spec": {"id": "synthetic"}}
        fixture.job_in_engagement = Mock(return_value=(HOLDER, stored))
        fixture.traffic = Mock(return_value=[])
        fixture.inventory = Mock(return_value=retained_inventory())

        def post(path, body):
            self.assertEqual(path, f"/jobs/{HOLDER}/claim")
            self.assertNotEqual(body["runner_id"], RUNNER)
            self.assertEqual(body["origin"], fixture.issuer_origin)
            self.assertEqual(canonical(body["target_binding"]), canonical({
                "profile": "gate-fixed-http/1",
                "case_sha256": digest(canonical(stored["spec"])), "origins": [ORIGIN],
            }))
            return {
                "id": HOLDER, "status": "running",
                "execution_control": {
                    "job_id": HOLDER, "runner_id": body["runner_id"], "origin": fixture.issuer_origin,
                    "capacity_reserved": True, "lease_seconds": 10, "token": TOKEN,
                    "target_budget": {
                        "binding": body["target_binding"], "charged": 1, "spent": 1, "limit": 5,
                    },
                    "duration_budget": {
                        "allocated_seconds": 30, "total_allocated_seconds": 30, "limit_seconds": 120,
                    },
                },
            }

        fixture.concurrency_post = Mock(side_effect=post)
        finish = fixture.reserve_legacy_capacity("engagement", CONTENDER, RUNNER)
        fixture.job_in_engagement.assert_called_once_with(
            "launch-concurrency-holder", "engagement", contract_required=False,
        )
        fixture.concurrency_post.assert_called_once()
        self.assertEqual(finish, {**fixture.concurrency_post.call_args.args[1], "token": TOKEN, "outcome": "failed"})
        self.assertNotIn(TOKEN, json.dumps([fixture.receipt, fixture.concurrency_holder]))

    def test_finish_checks_original_hold_before_its_only_post(self):
        fixture = LaunchFixture.__new__(LaunchFixture)
        fixture.receipt = {}
        original = retained_inventory()
        final = copy.deepcopy(original)
        final.update(job_status="failed", capacity_reserved_count=0)
        final["execution"].update(state="failed", capacity_reserved=False)
        fixture.concurrency_holder = HOLDER, original
        fixture.traffic = Mock(return_value=[])
        fixture.inventory = Mock(side_effect=[original, final])
        approval = {"issued": 0, "revoked": False}
        fixture.verify_unclaimed_peer = Mock(return_value=approval)
        fixture.api = Mock()
        fixture.api.request.return_value = {"evidence": []}
        fixture.budget_witnesses = Mock(return_value=1)
        body = {"token": TOKEN, "outcome": "failed"}
        fixture.concurrency_post = Mock(return_value={"state": "failed"})
        case = "engagement", CONTENDER, {}, {"approvals": [approval]}
        self.assertEqual(fixture.finish_legacy_capacity(case, body), (1, final))
        fixture.concurrency_post.assert_called_once_with(f"/jobs/{HOLDER}/execution-finish", body)
        fixture.inventory = Mock(return_value=final)
        fixture.concurrency_post.reset_mock()
        with self.assertRaises(AcceptanceRefused):
            fixture.finish_legacy_capacity(case, body)
        fixture.concurrency_post.assert_not_called()

    def test_original_unbound_parent_zero_requires_exact_local_lineage(self):
        fixture = LaunchFixture.__new__(LaunchFixture)
        fixture.receipt = {}
        binding = {"runner_id": RUNNER, "runtime_id": HOLDER,
                   "runtime_sha256": "a" * 64, "admission_sha256": "b" * 64}
        retirement = {"last_sequence": "0", "binding": None, "receipt_sha256": "c" * 64}
        reply = {
            "schema": "vardr.worker-reconciliation/1", "status": "reconciled", "complete": True,
            "binding": binding, "remaining_local_holds": 0, "retirement_receipt_sha256": "c" * 64,
            "selected_run_id": "d" * 32, "selected_sequence": "1",
            "reconciliation_state": "terminal_runtime_unbound_retired",
        }
        audit = {
            "schema": "vardr.worker-state-audit/1", "status": "retired", "complete": True,
            "binding": binding, "global_holds": 0, "retirement_receipt_sha256": "c" * 64,
            "parent": {"state": "retired", "last_sequence": "0", "head_sequence": None, "active_sequence": None},
            "counts": {"attempts": 0, "selections": 1, "associated_runs": 1, "associated_claims": 1},
        }
        fixture.helper = Mock(return_value=json.dumps(reply))
        fixture.worker_state = Mock(return_value=audit)
        args = {"unissued_run_id": "d" * 32, "unissued_parent_zero": True}
        self.assertEqual(fixture.reconcile_original(binding, retirement, **args), audit)
        audit["counts"]["attempts"] = False
        with self.assertRaises(AcceptanceRefused):
            fixture.reconcile_original(binding, retirement, **args)

    def test_public_projection_requires_continuous_hold_and_original_finish(self):
        selection = {"project": "fixture", "images": {},
                     "sources": {"map": {"commit": hosted.CONCURRENCY_MAP_COMMIT}}}
        launch = {
            "ordinal": 1, "runtime_id": RUNNER, "container_id": "1" * 64,
            "started_at": "2026-11-07T01:00:00Z", "finished_at": "2026-11-07T01:00:01Z",
            "intent_sha256": "a" * 64, "retirement_sha256": "b" * 64, "predecessor_cids": [],
            "bootstrap_audit_sha256": "c" * 64, "runner_state_sha256": "d" * 64,
        }
        proof = {
            "marker": "managed_claim_concurrency_exhausted", "marker_count": 1,
            "legacy_job_id": HOLDER, "managed_job_id": CONTENDER, "legacy_finish_state": "failed",
            "targets_spent": 1, "duration_allocated": 30, "concurrency_limit": 1,
            "capacity_before": 1, "capacity_after_refusal": 1, "capacity_before_finish": 1,
            "capacity_after_finish": 0, "target_requests": 0, "issued_attempts": 0,
            "remaining_local_holds": 0, "selected_sequence": "1", "last_issued_sequence": "0",
            "natural_exit_code": 125, "retirement_sha256": "b" * 64, "audit_sha256": "e" * 64,
        }
        raw = {
            **selection, "schema": hosted.LAUNCH_SCHEMA, "scenario": hosted.LAUNCH_CONCURRENCY_SCENARIO,
            "status": "selected_concurrency_exhaustion_slice_passed",
            "stage": "selected_concurrency_exhaustion_complete",
            "acceptance_scope": "shared_engagement_concurrency_exhaustion",
            "expected_database_revision": "0041persistentruntime",
            "retained": True, "platform": "linux", "nm2_exit_status": "incomplete",
            "launch": launch, "concurrency_exhaustion": proof, "private_canary": TOKEN,
            "fixture_stop": {
                "status": "stopped_retained", "container_ids": [str(n) * 64 for n in range(1, 7)],
                "stop_requested_ids": [str(n) * 64 for n in range(2, 7)],
            },
        }
        public = hosted.public_projection(raw, selection)
        self.assertEqual(public, hosted.concurrency_desktop_projection({**raw, "platform": "win32"}, selection))
        self.assertNotIn(TOKEN, json.dumps(public))
        for field, bad in (
            ("marker", "managed_claim_target_exhausted"), ("capacity_after_refusal", 0),
            ("capacity_before_finish", 0), ("capacity_after_finish", False),
            ("managed_job_id", HOLDER), ("last_issued_sequence", "1"), ("issued_attempts", 1),
            ("natural_exit_code", 0), ("target_requests", 1), ("retirement_sha256", "0" * 64),
        ):
            with self.subTest(field=field), self.assertRaises(hosted.HostedRefused):
                hosted.public_projection({**raw, "concurrency_exhaustion": {**proof, field: bad}}, selection)
        for change in (
            {"fixture_stop": {**raw["fixture_stop"], "stop_requested_ids": raw["fixture_stop"]["container_ids"]}},
            {"platform": "win32"}, {"duration_exhaustion": {}},
        ):
            with self.assertRaises(hosted.HostedRefused):
                hosted.public_projection({**raw, **change}, selection)
        held = {**raw, "status": "held", "stage": "launch_concurrency_finish",
                "reason": "launch_concurrency_release_required"}
        self.assertEqual(hosted.failure_projection(held, selection), {
            "stage": "launch_concurrency_finish", "reason": "launch_concurrency_release_required",
        })
