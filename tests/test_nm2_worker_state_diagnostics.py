"""Inert worker-state failure checkpoints; no SDK or Docker execution."""

from copy import deepcopy
import json
import subprocess
import unittest
from unittest.mock import Mock, patch

import nm2_worker_hosted as hosted
from nm2_worker_acceptance import AcceptanceRefused, Fixture, canonical, worker_state_failure


def model():
    fixture = Fixture.__new__(Fixture)
    fixture.receipt, fixture.environment = {}, {}
    fixture.project, fixture.m = "vardrsec-nm2-inert", {"docker_context": "default"}
    fixture.images, fixture.empty_audit_volumes = {"worker": "sha256:" + "a" * 64}, []
    fixture.empty_audit_volume = Mock(return_value={"bound": True})
    admission = {"runner_id": "e4a346a6-3982-4a13-a0a5-5b025bedbde0",
                 "runtime_id": "980d0f49-75c3-4f02-84cc-3fba35ff2e3d",
                 "runtime_sha256": "b" * 64, "admission_sha256": "c" * 64}
    sdk = {"schema": "vardr.worker-state-audit/1", "status": "held",
           "reason": "journal_unavailable", "complete": False, "binding": admission,
           "parent": None, "counts": None, "global_holds": None,
           "retirement_receipt_sha256": None}
    return fixture, admission, sdk


def projection(detail):
    selection = {"sources": {}, "images": {}, "project": "vardrsec-nm2-inert"}
    raw = {"schema": "vardr.nm2-worker-acceptance/2", "status": "held",
           **selection, "platform": "linux", "stage": "launch_audit_retired",
           "reason": "fixture_command_failed", "worker_state_failure": detail,
           "stdout": "private-canary", "stderr": "private-canary"}
    return hosted.failure_projection(raw, selection)


class WorkerStateDiagnosticTests(unittest.TestCase):
    def test_cli_exit1_keeps_failure_and_fixed_sdk_reason_without_output(self):
        fixture, admission, sdk = model()
        error = subprocess.CalledProcessError(1, ["private-canary"],
                                             output=canonical(sdk), stderr=b"private-canary")
        with patch("nm2_worker_acceptance.subprocess.run", side_effect=error) as run:
            with self.assertRaisesRegex(AcceptanceRefused, "fixture_command_failed"):
                fixture.worker_state(admission)
        self.assertTrue(run.call_args.kwargs["check"])
        self.assertEqual(run.call_args.kwargs["timeout"], 45)
        self.assertEqual(fixture.empty_audit_volume.call_count, 1)
        detail = {"phase": "offline_cli", "cli_returncode": 1,
                  "sdk_reason": "journal_unavailable"}
        self.assertEqual(fixture.receipt["worker_state_failure"], detail)
        public = projection(detail)
        self.assertEqual(public["worker_state_failure"], detail)
        self.assertNotIn("private-canary", json.dumps(public))
        self.assertNotIn(admission["runtime_id"], json.dumps(public))

    def test_before_and_after_volume_failure_keep_exact_checkpoint(self):
        for phase in ("before_volume_metadata", "after_volume_metadata"):
            fixture, admission, sdk = model()
            failure = AcceptanceRefused("empty_audit_volume_not_bound")
            fixture.empty_audit_volume.side_effect = (
                failure if phase.startswith("before") else [{"bound": True}, failure])
            reply = subprocess.CompletedProcess([], 0, canonical(sdk), b"")
            with patch("nm2_worker_acceptance.subprocess.run", return_value=reply) as run:
                with self.assertRaisesRegex(AcceptanceRefused, "empty_audit_volume_not_bound"):
                    fixture.worker_state(admission)
            self.assertEqual(run.call_count, int(phase.startswith("after")))
            self.assertEqual(fixture.receipt["worker_state_failure"], {
                "phase": phase, "cli_returncode": 0 if phase.startswith("after") else None,
                "sdk_reason": None})
            self.assertEqual(fixture.empty_audit_volumes, [])

    def test_success_clears_diagnostic_and_preserves_expected_held_contract(self):
        fixture, admission, sdk = model()
        sdk.update(reason="runtime_unretired", complete=True,
                   parent={"state": "idle", "last_sequence": "0", "head_sequence": None,
                           "active_sequence": None},
                   counts={"attempts": 0, "selections": 1, "associated_runs": 1,
                           "associated_claims": 1}, global_holds=0)
        for mode, code in ((None, 0), ("closed_preclaim", 1)):
            fixture.empty_audit_volume.reset_mock()
            with patch("nm2_worker_acceptance.subprocess.run", return_value=
                       subprocess.CompletedProcess([], code, canonical(sdk), b"")) as run:
                self.assertEqual(fixture.worker_state(admission, expected_held=mode), sdk)
            self.assertEqual(run.call_args.kwargs["check"], mode is None)
            self.assertNotIn("worker_state_failure", fixture.receipt)
            self.assertEqual(fixture.empty_audit_volume.call_count, 2)
        sdk["binding"] = {**admission, "runtime_sha256": "f" * 64}
        with patch("nm2_worker_acceptance.subprocess.run", return_value=
                   subprocess.CompletedProcess([], 1, canonical(sdk), b"")):
            with self.assertRaisesRegex(AcceptanceRefused, "launch_preclaim_parent_not_held"):
                fixture.worker_state(admission, expected_held="closed_preclaim")

    def test_malformed_or_unsafe_sdk_output_never_becomes_a_reason(self):
        _, _, sdk = model()
        unsafe = []
        for change in ("reason", "extra", "schema", "status", "complete", "reason_type"):
            value = deepcopy(sdk)
            if change == "extra": value["private-canary"] = "private-canary"
            elif change == "reason_type": value["reason"] = {"private-canary": []}
            else: value[change] = "private-canary"
            unsafe.append(canonical(value))
        unsafe.extend((b"\xff", b" " * 32769, canonical(sdk) + b"private-canary",
                       canonical(sdk)[:-1] + b',"reason":"local_holds"}',
                       b'{"reason":NaN}', b"[]"))
        for stdout in unsafe:
            with self.subTest(stdout_length=len(stdout)):
                result = subprocess.CompletedProcess([], 1, stdout, b"private-canary")
                detail = worker_state_failure("offline_cli", result)
                self.assertEqual(detail, {"phase": "offline_cli", "cli_returncode": 1,
                                          "sdk_reason": None})
                self.assertNotIn("private-canary", json.dumps(projection(detail)))

    def test_public_reader_drops_extra_untyped_or_unbounded_diagnostics(self):
        valid = {"phase": "offline_cli", "cli_returncode": 1, "sdk_reason": "local_holds"}
        bad = [None, [], "private-canary", {**valid, "stdout": "private-canary"}]
        for key, value in (("phase", {}), ("phase", "private-canary"),
                           ("cli_returncode", True), ("cli_returncode", 2**32),
                           ("cli_returncode", -(2**31)-1), ("cli_returncode", {}),
                           ("sdk_reason", []), ("sdk_reason", "private-canary"),
                           ("cli_returncode", 0), ("phase", "before_volume_metadata")):
            bad.append({**valid, key: value})
        for detail in bad:
            with self.subTest(detail_type=type(detail).__name__):
                public = projection(detail)
                self.assertNotIn("worker_state_failure", public)
                self.assertNotIn("private-canary", json.dumps(public))
        for code in (-9, 0, 1, 125, -(2**31), 2**32-1):
            detail = {**valid, "cli_returncode": code, "sdk_reason": None}
            self.assertEqual(projection(detail)["worker_state_failure"], detail)

    def test_offline_launch_exception_remains_refused_with_no_invented_exit(self):
        fixture, admission, _ = model()
        with patch("nm2_worker_acceptance.subprocess.run", side_effect=OSError("private-canary")):
            with self.assertRaisesRegex(AcceptanceRefused, "fixture_command_failed"):
                fixture.worker_state(admission)
        self.assertEqual(fixture.receipt["worker_state_failure"], {
            "phase": "offline_cli", "cli_returncode": None, "sdk_reason": None})
        self.assertNotIn("private-canary", json.dumps(projection(fixture.receipt["worker_state_failure"])))
