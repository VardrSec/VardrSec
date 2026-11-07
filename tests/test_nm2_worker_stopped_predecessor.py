"""Inert regressions for the stopped-predecessor launch witness."""

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from nm2_worker_launch_acceptance import (
    AcceptanceRefused,
    LaunchFixture,
    canonical,
    digest,
    expect_unresolved_launch,
)


SELECTED = "e4a346a6-3982-4a13-a0a5-5b025bedbde0"
OTHER = "980d0f49-75c3-4f02-84cc-3fba35ff2e3da"
REFUSAL = {
    "schema": "vardr.worker-cli/1",
    "state": "held",
    "runtime_id": SELECTED,
    "failure_phase": "launch_catalog",
    "failure_code": "validation_refused",
}


def reply(value):
    return json.dumps(value, sort_keys=True).encode() + b"\r\n"


class StoppedPredecessorTests(unittest.TestCase):
    def test_one_exact_command_refusal(self):
        arguments = ["python", "vardrsec.py", "worker", "launch", "--runtime-id", SELECTED]
        env = {"VARDRMAP_API_KEY": "opaque-fixture"}
        with patch("nm2_worker_launch_acceptance.subprocess.run") as child:
            child.return_value = SimpleNamespace(returncode=1, stdout=reply(REFUSAL))
            expect_unresolved_launch(arguments, SELECTED, cwd=Path("."), env=env, stdin="fixture\n")
        child.assert_called_once_with(
            arguments, cwd=Path("."), env=env, input=b"fixture\n", capture_output=True,
            timeout=240, check=False,
        )

    def test_wrong_status_identity_or_refusal_is_not_evidence(self):
        for code, raw in (
            (0, reply(REFUSAL)),
            (130, reply(REFUSAL)),
            (1, reply({**REFUSAL, "runtime_id": OTHER})),
            (1, reply({**REFUSAL, "failure_phase": "launch_preflight"})),
            (1, reply({**REFUSAL, "failure_code": "host_refused"})),
            (1, reply({**REFUSAL, "raw": "secret-canary"})),
            (1, b'{"runtime_id": "duplicate", ' + reply(REFUSAL)[1:]),
        ):
            with self.subTest(code=code), patch("nm2_worker_launch_acceptance.subprocess.run") as child:
                child.return_value = SimpleNamespace(returncode=code, stdout=raw)
                with self.assertRaisesRegex(
                    AcceptanceRefused, "^launch_unresolved_predecessor_refusal_missing$"
                ):
                    expect_unresolved_launch(
                        [], SELECTED, cwd=Path("."), env={}, stdin="fixture\n"
                    )
                child.assert_called_once()

    def test_only_host_failed_terminal_can_close_reservation_without_refund(self):
        fixture = object.__new__(LaunchFixture)
        fixture.receipt = {"stopped_predecessor": {}}
        fixture.reconcile_original = Mock(return_value={"global_holds": 0})
        binding = {
            "origin": "https://vardrsec.localhost:8443/backend",
            "runner_id": OTHER,
            "job_id": SELECTED,
            "contract_id": OTHER,
            "attempt_id": SELECTED,
            "fence": 1,
            "contract_sha256": "a" * 64,
        }
        terminal = {
            **binding, "schema": "vardr.managed-stop-receipt/1",
            "cause": "observed_exit", "outcome": "failed", "capacity_reserved": False,
            "receipt_sha256": digest(canonical({
                **binding, "schema": "vardr.managed-stop/1", "cause": "observed_exit",
                "outcome": "failed", "termination_confirmed": True,
            })),
        }
        runtime = {"attempts": [{"binding": binding}], "retired": False, "report_sha256": None}
        before = {
            "job_status": "running", "execution": {"state": "active", "capacity_reserved": True},
            "capacity_reserved_count": 1, "targets_spent": 1, "duration_allocated": 30,
            "runtimes": [runtime], "stops": [], "results": [],
        }
        retired = {
            "admission_sha256": "b" * 64, "report_sha256": "c" * 64, "receipt_sha256": "d" * 64,
            "binding": binding, "attempt_receipt": terminal,
        }
        admission = {"admission_sha256": retired["admission_sha256"]}
        after = {
            **before, "job_status": "failed",
            "execution": {"state": "failed", "capacity_reserved": False},
            "capacity_reserved_count": 0,
            "runtimes": [{**runtime, "retired": True, "report_sha256": retired["report_sha256"]}],
            "stops": [{key: terminal[key] for key in ("contract_id", "receipt_sha256", "outcome", "cause")}],
        }
        for name, value in (
            ("capacity_reserved_count", 1), ("duration_allocated", 0), ("targets_spent", 0),
            ("runtimes", [{**after["runtimes"][0], "attempts": []}]),
        ):
            with self.subTest(name=name):
                fixture.inventory = Mock(return_value={**after, name: value})
                with self.assertRaisesRegex(AcceptanceRefused, "launch_host_exit_budget_or_history_changed"):
                    fixture.verify_host_exit_reconciliation(admission, retired, ("engagement", SELECTED), "run", before)
                fixture.reconcile_original.assert_not_called()
        fixture.inventory = Mock(return_value=deepcopy(after))
        fixture.verify_host_exit_reconciliation(admission, retired, ("engagement", SELECTED), "run", before)
        fixture.reconcile_original.assert_called_once_with(admission, retired, host_exit_run_id="run")
        self.assertEqual(fixture.retired_predecessor_inventory, after)
        self.assertEqual(fixture.receipt["stopped_predecessor"]["host_retirement_sha256"], digest(canonical(retired)))
