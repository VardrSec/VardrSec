"""Product status-to-fixture wire checks; all storage, HTTP and Docker I/O mocked.

These are scheduling/correlation models, never physical exit or platform evidence.
"""

import contextlib
import copy
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import subprocess
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import nm2_worker_acceptance as fixture
import nm2_worker_hosted as hosted
import nm2_worker_idle_projection as reader
import test_nm2_worker_idle_limit as vectors
import worker_cli
import worker_host as host
import worker_host_persistent as persistent
import worker_runtime as runtime


NOW = datetime(2026, 11, 6, 2, 0, 6, tzinfo=timezone.utc)
NULL_MAP_FIELDS = ("cursor", "availability", "new_work_disabled", "reporting_revoked")


def product_status(*, unavailable=False):
    """Run the actual product producer and CLI serializer with mocked I/O only."""
    _, _, _, admission, ready, _ = vectors.vector(run=False)
    record = {
        "runtime_id": admission["runtime_id"],
        "registration": {key: copy.deepcopy(admission[key]) for key in persistent.REGISTRATION},
        "registration_state": "acknowledged",
        "disable_state": "none",
        "stop_state": "none",
        "revocation_state": "none",
        "receipt": None,
    }
    records = SimpleNamespace(
        locked=contextlib.nullcontext,
        read=Mock(return_value=record),
        secret=Mock(return_value="synthetic-unused-status-custody"),
        write=Mock(side_effect=AssertionError("status_write_forbidden")),
    )
    observer = SimpleNamespace(
        _observation_lock=threading.Lock(),
        _deadline=None,
        _bound=Mock(return_value={"state": {"Status": "running", "Running": True}}),
    )
    current = {
        "schema": "vardr.worker-receipt-observation/3",
        **{key: admission[key] for key in ("runtime_id", "runtime_sha256", "admission_sha256")},
        "cursor": copy.deepcopy(ready["cursor"]),
        "active": None,
        "retirement": None,
        "new_work_disabled": False,
        "reporting_revoked": False,
        "availability": copy.deepcopy(ready["availability"]),
    }
    client = Mock()
    client.receipt = Mock(
        side_effect=host.HostRefused("synthetic-status-lookup-refused") if unavailable else None,
        return_value=current,
    )
    with (
        patch.object(host, "_observer"),
        patch.object(host, "_client"),
        patch.object(persistent, "_reports", return_value=[]),
        patch.object(persistent, "datetime", wraps=datetime) as clock,
    ):
        clock.now.return_value = NOW
        value = persistent.status(records, admission["runtime_id"], observer,
            runtime.RuntimeIdentity(**admission["identity"]), client=client)
    records.write.assert_not_called()
    client.receipt.assert_called_once()
    assert observer._bound.call_count == (1 if unavailable else 2)
    assert observer._deadline is None
    output = io.StringIO()
    with patch.object(worker_cli, "dispatch", return_value=value), contextlib.redirect_stdout(output):
        code = worker_cli.main(["status", "--runtime-id", admission["runtime_id"],
            "--private-root", str(Path(__file__).parent / "unused-custody")],
            installation=Path(__file__).resolve().parents[1])
    return json.loads(output.getvalue()), code, admission


class IdleStatusProducer(unittest.TestCase):
    def test_idle_wrapper_fixed_checkpoints_share_existing_strict_projection(self):
        value, code, admission = product_status(unavailable=True)
        malformed = {**value, "reason": "physical_unconfirmed"}
        cases = (
            (OSError("synthetic-private-canary"), None, "subprocess"),
            (None, subprocess.CompletedProcess([], 0, b"", b""), "output"),
            (None, subprocess.CompletedProcess([], code, host.canonical(malformed), b""), "lookup"),
        )
        for error, result, checkpoint in cases:
            with self.subTest(checkpoint=checkpoint), patch.object(fixture.subprocess,
                "run", side_effect=error, return_value=result) as run:
                with self.assertRaises(fixture.IdleStatusRefused) as refused:
                    fixture.worker_idle_status_command([], cwd=Path.cwd(), env={},
                        timeout=3, expected_admission=admission)
            run.assert_called_once()
            self.assertIsInstance(refused.exception, fixture.WorkerStatusRefused)
            self.assertEqual(str(refused.exception), "idle_status_refused")
            self.assertEqual(refused.exception.public, {"checkpoint": checkpoint})
            raw, selection, *_ = vectors.vector(run=False)
            raw.update(status="held", stage="idle_control_observation",
                reason=str(refused.exception), status_failure=refused.exception.public,
                stdout="synthetic-private-canary", dto=malformed)
            public = hosted.failure_projection(raw, selection)
            self.assertEqual(public, {"stage": "idle_control_observation",
                "reason": "idle_status_refused", "status_failure": {"checkpoint": checkpoint}})
            self.assertNotIn("synthetic-private-canary", json.dumps(public))

        raw, selection, *_ = vectors.vector(run=False)
        raw.update(status="held", stage="idle_control_observation", reason="idle_status_refused")
        for invalid in (None, [], {}, {"checkpoint": []}, {"checkpoint": "synthetic-private-canary"},
            {"checkpoint": "lookup", "dto": "synthetic-private-canary"}):
            with self.subTest(invalid=type(invalid).__name__):
                raw["status_failure"] = invalid
                self.assertNotIn("status_failure", hosted.failure_projection(raw, selection))
        raw.update(reason="idle_initial_readiness_missing", status_failure={"checkpoint": "lookup"})
        self.assertNotIn("status_failure", hosted.failure_projection(raw, selection))
        self.assertEqual(fixture.IdleStatusRefused("synthetic-private-canary").public,
            {"checkpoint": "unclassified"})

    def test_actual_product_ready_shape_still_requires_fresh_ready(self):
        value, code, admission = product_status()
        self.assertEqual((value["state"], code), ("idle-ready", 0))
        with patch.object(fixture, "datetime", wraps=datetime) as clock:
            clock.now.return_value = NOW
            self.assertEqual(fixture.idle_status_value(value, code, admission), value)

    def test_actual_product_null_map_advisory_is_a_valid_poll_only(self):
        value, code, admission = product_status(unavailable=True)
        self.assertEqual((value["state"], value["reason"], code),
            ("held", "availability_unconfirmed", 1))
        self.assertEqual(value["container_state"], "running")
        self.assertTrue(all(value[key] is None for key in NULL_MAP_FIELDS))
        self.assertEqual(fixture.idle_status_value(value, code, admission), value)
        result = subprocess.CompletedProcess([], code, host.canonical(value), b"")
        with patch.object(fixture.subprocess, "run", return_value=result) as run:
            actual = fixture.worker_idle_status_command([], cwd=Path.cwd(), env={},
                timeout=3, expected_admission=admission)
        run.assert_called_once()
        self.assertEqual(json.loads(actual), value)

    def test_null_map_advisory_cannot_hide_partial_scope_or_physical_failures(self):
        original, _, admission = product_status(unavailable=True)
        changes = [
            ("reason", "physical_unconfirmed"), ("reason", "availability_stale"),
            ("state", "idle-ready"), ("container_state", "exited"),
            ("registration_state", "unknown"), ("disable_state", "prepared"),
            ("stop_state", "observed"), ("revocation_state", "acknowledged"),
            ("runtime_id", "33333333-3333-4333-8333-333333333333"),
            ("identity", {**original["identity"], "owner_nonce": "f" * 64}),
            ("cursor", {"last_sequence": "1", "phase": "idle"}),
            ("availability", {}), ("new_work_disabled", False),
            ("reporting_revoked", False), ("extra", "synthetic-private-canary"),
        ]
        for key, value in changes:
            with self.subTest(key=key), self.assertRaises(ValueError):
                fixture.idle_status_value({**original, key: value}, 1, admission)
        for code in (0, 2, True, 1.0):
            with self.subTest(code=code), self.assertRaises(ValueError):
                fixture.idle_status_value(original, code, admission)
        with self.assertRaises(ValueError):
            fixture.idle_status_value({k: v for k, v in original.items()
                if k != "container_state"}, 1, admission)

    def test_advisory_poll_never_substitutes_for_initial_readiness_or_native_exit(self):
        advisory, code, admission = product_status(unavailable=True)
        fixture.idle_status_value(advisory, code, admission)
        _, _, owner, _, ready, stopped = vectors.vector(run=False)
        owner.worker_action.side_effect = [advisory]
        with self.assertRaisesRegex(fixture.AcceptanceRefused, "idle_initial_readiness_missing"):
            vectors.run_owner(owner)
        owner.report_exit.assert_not_called()

        raw, selection, owner, _, ready, stopped = vectors.vector(run=False)
        reconcile = {"state": "terminal_observed", "receipt": {
            "retirement": owner.report_exit.return_value}}
        owner.worker_action.side_effect = [ready, advisory, stopped, reconcile]
        vectors.run_owner(owner)
        public = reader.project(raw, selection)
        self.assertEqual(public["measurements"]["native_exit_code"], 124)
        self.assertEqual(public["measurements"]["issued_attempts"], 1)
        self.assertEqual(public["measurements"]["target_request_count"], 5)
        self.assertEqual([call.args[0] for call in owner.worker_action.call_args_list],
            ["status", "status", "status", "reconcile"])


if __name__ == "__main__":
    unittest.main()
