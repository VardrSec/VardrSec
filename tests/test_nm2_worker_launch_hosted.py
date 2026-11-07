"""Check only the exact opt-in and sanitized installed launch receipt."""

import copy
import unittest

import nm2_worker_hosted as hosted


class HostedLaunchTests(unittest.TestCase):
    def test_launch_requires_the_persistent_map_revision(self):
        selected = {"NM2_SCENARIO": hosted.LAUNCH_SCENARIO}
        with self.assertRaises(hosted.HostedRefused):
            hosted.execution_options(selected)
        selected["NM2_DATABASE_REVISION"] = "0041persistentruntime"
        self.assertEqual(
            hosted.execution_options(selected),
            (hosted.LAUNCH_SCENARIO, "0041persistentruntime"),
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
