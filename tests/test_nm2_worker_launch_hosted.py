"""Check only the exact opt-in and sanitized installed launch receipt."""

import copy
import json
import unittest
from unittest.mock import Mock

import nm2_worker_hosted as hosted
from nm2_worker_launch_acceptance import LaunchFixture
from nm2_worker_acceptance import AcceptanceRefused


class HostedLaunchTests(unittest.TestCase):
    def test_completed_fixture_joins_summary_with_separate_retired_audit(self):
        fixture = LaunchFixture.__new__(LaunchFixture)
        fixture.receipt = {}
        fixture.traffic = Mock(return_value=[{}] * 5)
        fixture.inventory = Mock(return_value={})
        fixture.verify_fixed = Mock(return_value=({}, {"evidence_sha256": "e" * 64}))
        admission = {
            "runner_id": "63ba16a0-37c6-4c96-a111-80ad0965ae71",
            "runtime_id": "a5b305a7-b64c-4472-a44e-a4660f49e0c9",
            "runtime_sha256": "a" * 64,
            "admission_sha256": "b" * 64,
        }
        retirement = {"receipt_sha256": "c" * 64}
        fixture.helper = Mock(
            return_value=json.dumps(
                {
                    "schema": "vardr.worker-reconciliation/1",
                    "status": "reconciled",
                    "complete": True,
                    "binding": admission,
                    "remaining_local_holds": 0,
                    "retirement_receipt_sha256": "c" * 64,
                }
            )
        )
        audit = {
            "schema": "vardr.worker-state-audit/1",
            "status": "retired",
            "complete": True,
            "binding": admission,
            "global_holds": 0,
            "retirement_receipt_sha256": "c" * 64,
            "counts": {"attempts": 1},
        }
        fixture.worker_state = Mock(return_value=audit)
        case = ("engagement", "job", {}, {})
        fixture.completed_reconciliation({}, admission, retirement, case)
        fixture.worker_state.assert_called_once_with(admission)
        self.assertEqual(
            fixture.receipt["completed_job"]["retirement_sha256"],
            retirement["receipt_sha256"],
        )
        audit["retirement_receipt_sha256"] = "f" * 64
        with self.assertRaisesRegex(
            AcceptanceRefused, "launch_completed_audit_not_observed"
        ):
            fixture.completed_reconciliation({}, admission, retirement, case)

    def test_launch_requires_the_persistent_map_revision(self):
        selected = {"NM2_SCENARIO": hosted.LAUNCH_SCENARIO}
        with self.assertRaises(hosted.HostedRefused):
            hosted.execution_options(selected)
        selected["NM2_DATABASE_REVISION"] = "0041persistentruntime"
        self.assertEqual(
            hosted.execution_options(selected),
            (hosted.LAUNCH_SCENARIO, "0041persistentruntime"),
        )
        selected["NM2_SCENARIO"] = hosted.LAUNCH_COMPLETED_SCENARIO
        self.assertEqual(
            hosted.execution_options(selected),
            (hosted.LAUNCH_COMPLETED_SCENARIO, "0041persistentruntime"),
        )

    def test_launch_receipt_checks_the_preserved_predecessor_and_only_projects_closed_fields(
        self,
    ):
        selection = {"project": "fixture", "sources": {}, "images": {}}
        first = {
            "ordinal": 1,
            "runtime_id": "63ba16a0-37c6-4c96-a111-80ad0965ae71",
            "container_id": "1" * 64,
            "started_at": "2026-11-07T01:00:00Z",
            "finished_at": "2026-11-07T01:00:01Z",
            "intent_sha256": "a" * 64,
            "retirement_sha256": "b" * 64,
            "predecessor_cids": [],
            "bootstrap_audit_sha256": "c" * 64,
            "runner_state_sha256": "d" * 64,
        }
        second = {
            **first,
            "ordinal": 2,
            "runtime_id": "a5b305a7-b64c-4472-a44e-a4660f49e0c9",
            "container_id": "2" * 64,
            "started_at": "2026-11-07T01:00:02Z",
            "finished_at": "2026-11-07T01:00:03Z",
            "predecessor_cids": [first["container_id"]],
            "bootstrap_audit_sha256": None,
        }
        raw = {
            **selection,
            "schema": hosted.LAUNCH_SCHEMA,
            "scenario": hosted.LAUNCH_SCENARIO,
            "expected_database_revision": "0041persistentruntime",
            "acceptance_scope": "first_and_next_empty_launch",
            "status": "selected_launch_slice_passed",
            "stage": "selected_launch_complete",
            "retained": True,
            "platform": "linux",
            "nm2_exit_status": "incomplete",
            "launch_pair": [first, second],
            "private": "discard this",
        }
        self.assertEqual(
            hosted.public_projection(raw, selection),
            {
                "launch_pair": [first, second],
                "nm2_exit_status": "incomplete",
                "resources_retained": True,
            },
        )
        for changed in (
            {"predecessor_cids": []},
            {"runner_state_sha256": "a" * 64},
            {"started_at": first["started_at"]},
            {"credential": "discard this"},
        ):
            bad = copy.deepcopy(raw)
            bad["launch_pair"][1].update(changed)
            with self.subTest(changed=changed), self.assertRaises(hosted.HostedRefused):
                hosted.public_projection(bad, selection)
        completed = {
            **raw,
            "scenario": hosted.LAUNCH_COMPLETED_SCENARIO,
            "acceptance_scope": "completed_then_next_launch",
            "completed_job": {
                "job_id": "ddd8e594-dfcb-4ca2-83f8-abfda598e1a7",
                "retirement_sha256": first["retirement_sha256"],
                "audit_sha256": "e" * 64,
                "target_requests": 5,
                "fixed_evidence_sha256": "f" * 64,
            },
        }
        self.assertEqual(
            hosted.public_projection(completed, selection)["completed_job"],
            completed["completed_job"],
        )
        completed["completed_job"]["retirement_sha256"] = "0" * 64
        with self.assertRaises(hosted.HostedRefused):
            hosted.public_projection(completed, selection)
