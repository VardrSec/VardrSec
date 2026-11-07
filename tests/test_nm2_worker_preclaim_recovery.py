"""Inert Distribution wiring and public C02 evidence checks."""

from contextlib import nullcontext
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import nm2_worker_hosted as hosted
import nm2_worker_launch_acceptance as launch
from nm2_worker_acceptance import AcceptanceRefused, canonical
from test_nm2_worker_stopped_predecessor_hosted import evidence


def vector():
    raw, selection, inventories = evidence()
    raw.update(
        scenario=hosted.LAUNCH_PRECLAIM_SCENARIO,
        acceptance_scope=hosted.LAUNCH_SCOPES[hosted.LAUNCH_PRECLAIM_SCENARIO],
    )
    raw.pop("stopped_predecessor")
    raw["preclaim_recovery"] = {
        "setup_kind": "trusted_synthetic",
        "marker": "local_preclaim_denied_before_rpc",
        "failure_phase": "launch_catalog",
        "failure_code": "validation_refused",
        "refused_runtime_id": raw["launch_pair"][1]["runtime_id"],
        "new_resources": 0,
        "target_requests": 0,
        "targets_spent": 0,
        "duration_allocated": 0,
        "capacity_before": 0,
        "capacity_after": 0,
        "issued_attempts": 0,
        "retained_tombstones": 1,
        "last_sequence": "0",
        "remaining_local_holds": 0,
        "reconciliation_state": "terminal_preclaim_parent_retired",
        "tombstone_before_sha256": "a" * 64,
        "tombstone_after_sha256": "a" * 64,
        "audit_sha256": "b" * 64,
        "retirement_sha256": raw["launch_pair"][0]["retirement_sha256"],
        "host_retirement_sha256": "c" * 64,
    }
    for name, commit in launch.MAP_DISCONNECT_SOURCES.items():
        selection["sources"][name]["commit"] = commit
        raw["sources"][name]["commit"] = commit
    return raw, selection, inventories


class PreclaimRecoveryTests(unittest.TestCase):
    def test_linux_and_desktop_projection_preserve_scope_and_only_public_measurements(
        self,
    ):
        for desktop in (False, True):
            raw, selection, inventories = vector()
            if desktop:
                raw["platform"] = "win32"
                selection["docker_context"] = "desktop-linux"
            raw["unsafe_private"] = "credential-canary"
            value = hosted.launch_projection(
                raw, selection, inventories=inventories, desktop=desktop
            )
            proof = value["preclaim_recovery"]
            self.assertEqual(proof["setup_kind"], "trusted_synthetic")
            self.assertEqual(proof["retained_tombstones"], 1)
            self.assertEqual(proof["owned_stopped_container_count"], 7)
            self.assertEqual(proof["target_requests"], 0)
            self.assertTrue(proof["same_runner_state_volume"])
            self.assertEqual(value["nm2_exit_status"], "incomplete")
            self.assertNotIn("credential-canary", json.dumps(value))
            self.assertNotIn("refused_runtime_id", proof)
            self.assertNotIn("launch_pair", value)

    def test_incomplete_changed_or_unsafe_recovery_proof_cannot_pass(self):
        for key, value in (
            ("issued_attempts", 1),
            ("capacity_before", True),
            ("targets_spent", 0.0),
            ("retained_tombstones", 0),
            ("setup_kind", "actual-crash"),
            ("reconciliation_state", "local_preclaim_retired"),
            ("tombstone_after_sha256", "d" * 64),
            ("last_sequence", 0),
            ("retirement_sha256", "f" * 64),
            ("unsafe", "credential-canary"),
        ):
            with self.subTest(key=key):
                raw, selection, inventories = vector()
                raw["preclaim_recovery"][key] = value
                with self.assertRaises(hosted.HostedRefused):
                    hosted.launch_projection(raw, selection, inventories=inventories)
        raw, selection, inventories = vector()
        del raw["preclaim_recovery"]["tombstone_before_sha256"]
        with self.assertRaises(hosted.HostedRefused):
            hosted.public_projection(raw, selection, inventories=inventories)

    def test_existing_retention_guard_rejects_running_owned_and_changed_old_resources(
        self,
    ):
        for change in ("running", "old"):
            raw, selection, inventories = vector()
            if change == "running":
                inventories[1]["containers"][raw["launch_pair"][0]["container_id"]][
                    "state"
                ]["running"] = True
            else:
                inventories[1]["volumes"]["old-volume"]["labels"] = {"changed": "true"}
            raw["after_sha256"] = hashlib.sha256(canonical(inventories[1])).hexdigest()
            with self.assertRaises(hosted.HostedRefused):
                hosted.launch_projection(raw, selection, inventories=inventories)

    def test_original_reconciliation_keeps_nonzero_tombstones_and_requires_exact_branch(
        self,
    ):
        fixture = launch.LaunchFixture.__new__(launch.LaunchFixture)
        binding = dict(
            runner_id="runner",
            runtime_id="runtime",
            runtime_sha256="a" * 64,
            admission_sha256="b" * 64,
        )
        retired = dict(
            receipt_sha256="c" * 64,
            last_sequence="0",
            runtime_sequence=None,
            binding=None,
            attempt_receipt=None,
        )
        fixture.preclaim_run_id, fixture.preclaim_tombstone = "a" * 32, "d" * 64
        fixture.receipt = {"preclaim_recovery": {}}
        fixture.preclaim_inventory = {"unchanged": True}
        fixture.preclaim_unissued = Mock(return_value=fixture.preclaim_inventory)
        fixture.read_preclaim_snapshot = Mock(
            return_value={"tombstone_sha256": fixture.preclaim_tombstone}
        )
        reply = dict(
            schema="vardr.worker-reconciliation/1",
            status="reconciled",
            complete=True,
            binding=binding,
            selected_run_id=fixture.preclaim_run_id,
            selected_sequence="1",
            reconciliation_state="terminal_preclaim_parent_retired",
            remaining_local_holds=0,
            retirement_receipt_sha256=retired["receipt_sha256"],
        )
        fixture.helper = Mock(side_effect=lambda *args: json.dumps(reply))
        audit = dict(
            status="retired",
            complete=True,
            binding=binding,
            global_holds=0,
            retirement_receipt_sha256=retired["receipt_sha256"],
            parent=dict(
                state="retired",
                last_sequence="0",
                head_sequence=None,
                active_sequence=None,
            ),
            counts=dict(
                attempts=0, selections=1, associated_runs=1, associated_claims=1
            ),
        )
        fixture.worker_state = Mock(return_value=audit)
        fixture.reconcile_preclaim_recovery(binding, retired)
        self.assertEqual(fixture.helper.call_args.args[0], "worker-reconcile")
        self.assertEqual(
            fixture.receipt["preclaim_recovery"]["tombstone_after_sha256"], "d" * 64
        )
        reply["reconciliation_state"] = "local_preclaim_retired"
        with self.assertRaisesRegex(
            AcceptanceRefused, "launch_preclaim_original_reconciliation_missing"
        ):
            fixture.reconcile_preclaim_recovery(binding, retired)

    def test_seed_is_unreachable_without_typed_exact_exit(self):
        fixture = launch.LaunchFixture.__new__(launch.LaunchFixture)
        fixture.receipt, fixture.helper = {}, Mock()
        with self.assertRaisesRegex(
            AcceptanceRefused, "launch_preclaim_exit_not_bound"
        ):
            fixture.prepare_preclaim_recovery(
                Mock(), object(), {"identity": {}}, None, None, None
            )
        fixture.helper.assert_not_called()

    def test_prepare_uses_separate_helper_after_confirmation_and_refuses_successor_before_report(
        self,
    ):
        from worker_runtime import RuntimeIdentity

        fixture = launch.LaunchFixture.__new__(launch.LaunchFixture)
        identity = RuntimeIdentity(
            "fixture-daemon",
            "1" * 64,
            "sha256:" + "2" * 64,
            "vardrsec-nm2-fixture",
            "2026-11-07T01:00:00.000001Z",
            "3" * 64,
        )

        class TestExit:
            def __init__(self):
                self.identity = identity

        proof, observer = TestExit(), Mock()
        fixture.receipt, fixture.preclaim_case = (
            {},
            ("engagement", "job", {"spec": {"id": "case"}}),
        )
        fixture.preclaim_inventory, fixture.preclaim_unissued = (
            {"unchanged": True},
            Mock(return_value={"unchanged": True}),
        )
        fixture.successor_id, fixture.password = (
            "980d0f49-75c3-4f02-84cc-3fba35ff2e3d",
            "fixture-password",
        )
        fixture.environment, fixture.public_root = {}, Path("public")
        fixture.snapshot = Mock(return_value={"unchanged": "resources"})
        fixture.launch_arguments = Mock(
            return_value=["python", "vardrsec.py", "worker", "launch"]
        )
        closed = dict(
            phase="failed",
            status="not_claimed",
            claim_state="preclaim_retired",
            selection_state="preclaim_retired",
            failure_reason="local_preclaim_denied_before_rpc",
            run_id="a" * 32,
            tombstone_sha256="d" * 64,
        )
        fixture.worker_state = Mock(
            return_value=dict(
                status="held",
                reason="runtime_unretired",
                complete=True,
                global_holds=0,
                parent=dict(
                    state="idle",
                    last_sequence="0",
                    head_sequence=None,
                    active_sequence=None,
                ),
                counts=dict(
                    attempts=0, selections=1, associated_runs=1, associated_claims=1
                ),
            )
        )
        fixture.read_preclaim_snapshot = Mock(return_value=closed)
        records = SimpleNamespace(operation=lambda: nullcontext("operation"))
        catalog = Mock(inventory=Mock(return_value={"records": "unchanged"}))
        with TemporaryDirectory() as temporary:
            fixture.install = fixture.private = Path(temporary)
            (fixture.install / "tests").mkdir()
            (fixture.install / "tests/nm2_worker_preclaim_fixture.py").write_text(
                "trusted-setup-source"
            )
            fixture.helper = Mock(
                return_value=json.dumps(
                    dict(
                        schema="vardr.nm2-preclaim-setup/1",
                        kind="trusted_synthetic",
                        selected={},
                        closed=closed,
                    )
                )
            )
            with (
                patch("worker_runtime.ObservedExit", TestExit),
                patch("worker_cli.records_for", return_value=records),
                patch("worker_lifecycle_intent.IntentStore", return_value=catalog),
                patch("worker_launch._public_inventory"),
                patch.object(launch, "expect_unresolved_launch") as refuse,
            ):
                fixture.prepare_preclaim_recovery(
                    observer, proof, {"identity": asdict(identity)}, None, None, None
                )
            self.assertEqual(
                fixture.helper.call_args.args[:3], ("-I", "-c", "trusted-setup-source")
            )
            self.assertTrue(fixture.helper.call_args.kwargs["python"])
            self.assertEqual(observer.confirm_exit.call_count, 2)
            refuse.assert_called_once()
            self.assertEqual(refuse.call_args.kwargs["stdin"], "fixture-password\n")
            self.assertEqual(
                fixture.receipt["preclaim_recovery"]["retained_tombstones"], 1
            )

    def test_hosted_opt_in_routes_only_the_explicit_mode_with_reviewed_sources(self):
        env = dict(
            NM2_SCENARIO=hosted.LAUNCH_PRECLAIM_SCENARIO,
            NM2_DATABASE_REVISION="0041persistentruntime",
            NM2_RUNNER_SHA="5ecc869d80f53ae7fdbca25b971838976a6c41e9",
            NM2_MAP_SHA="05dc78cf9a385255de459c8a5b833842d6528a63",
            NM2_GATE_SHA="d80d4730b8486b75be72431b5af88e0ddb45020b",
        )
        self.assertEqual(
            hosted.execution_options(env),
            (hosted.LAUNCH_PRECLAIM_SCENARIO, "0041persistentruntime"),
        )
        for key in ("NM2_RUNNER_SHA", "NM2_DATABASE_REVISION"):
            with self.subTest(key=key), self.assertRaises(hosted.HostedRefused):
                hosted.execution_options({**env, key: "unknown"})
        with TemporaryDirectory() as temporary:
            obj = hosted.Hosted.__new__(hosted.Hosted)
            obj.root, obj.receipt, obj.scenario = (
                Path(temporary),
                {},
                hosted.LAUNCH_PRECLAIM_SCENARIO,
            )
            (obj.root / "home").mkdir()

            def command(args, **kwargs):
                Path(args[args.index("--output") + 1]).write_bytes(b"compose-fixture")

            obj.command = Mock(side_effect=command)
            with (
                patch.object(hosted, "COMPOSE_BYTES", len(b"compose-fixture")),
                patch.object(
                    hosted,
                    "COMPOSE_SHA256",
                    hashlib.sha256(b"compose-fixture").hexdigest(),
                ),
            ):
                arguments = obj.launch_harness(Path(temporary) / "cohort.json")
            self.assertIn("--preclaim-recovery", arguments)
            self.assertNotIn("--stopped-predecessor", arguments)
        scenario = SimpleNamespace(
            receipt={"status": "selected_launch_slice_passed"}, run=Mock()
        )
        with (
            patch.object(launch, "LaunchFixture", return_value=scenario) as constructor,
            patch.object(launch, "manifest", return_value={}),
        ):
            self.assertEqual(
                launch.main(
                    [
                        "--cohort",
                        "cohort.json",
                        "--compose-executable",
                        "compose",
                        "--compose-sha256",
                        "a" * 64,
                        "--docker-config",
                        "config",
                        "--preclaim-recovery",
                        "--execute",
                    ]
                ),
                0,
            )
            self.assertTrue(constructor.call_args.kwargs["preclaim_recovery"])
        source = (hosted.SOURCE / ".github/workflows/compose.yml").read_text()
        self.assertIn("persistent-launch-preclaim-recovery", source)
        self.assertIn("default: false", source)


if __name__ == "__main__":
    unittest.main()
