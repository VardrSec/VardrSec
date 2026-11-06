"""Read-only advisory status decoding; no Docker, network or credential access."""

import contextlib
import copy
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import nm2_worker_acceptance as fixture
import worker_cli


PRIVATE = "private-canary-password-path-header-body"


class WorkerStatusDecode(unittest.TestCase):
    def setUp(self):
        identity = {
            "daemon_id": "owned-daemon",
            "container_id": "a" * 64,
            "image_id": "sha256:" + "b" * 64,
            "project": "owned-fixture",
            "started_at": "2026-11-06T00:00:00.123456789Z",
            "owner_nonce": "c" * 64,
        }
        self.admission = {
            "schema": "vardr.worker-admission/3",
            "runtime_id": "11111111-1111-4111-8111-111111111111",
            "runtime_sha256": fixture.digest(fixture.canonical(identity)),
            "enrollment_id": "enrollment-1",
            "runner_id": "22222222-2222-4222-8222-222222222222",
            "origin": "https://map.internal/backend",
            "capability_sha256": "d" * 64,
            "identity": identity,
            "mode": "persistent",
            "limits": {"max_attempts": None, "idle_timeout_seconds": None},
            "reporting_authority": {"purpose": "worker-stop-only", "expires_at": None},
        }
        self.admission["admission_sha256"] = fixture.digest(
            fixture.canonical(self.admission)
        )
        self.value = {
            "schema": "vardr.worker-status/1",
            "runtime_id": self.admission["runtime_id"],
            "protocol": "persistent-v3",
            "mode": "persistent",
            "limits": self.admission["limits"],
            "identity": identity,
            "state": "held",
            "reason": "availability_stale",
            "cursor": {"last_sequence": "0", "phase": "idle"},
            "availability": {
                "state": "held",
                "observed_at": None,
                "fresh_until": None,
                "cursor": {"last_sequence": "0", "phase": "idle"},
            },
            "new_work_disabled": False,
            "reporting_revoked": False,
            "registration_state": "acknowledged",
            "disable_state": "none",
            "stop_state": "none",
            "revocation_state": "none",
            "container_state": "running",
        }

    def decode(self, *, value=None, code=1, raw=None, stderr=b""):
        if raw is None:
            raw = fixture.canonical(self.value if value is None else value)
        with patch.object(
            fixture.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], code, raw, stderr),
        ) as run:
            result = fixture.worker_status_command(
                ["python", "vardrsec.py", "worker", "status"],
                cwd=Path.cwd(),
                env={},
                timeout=3,
                expected_admission=self.admission,
            )
        self.assertEqual(run.call_count, 1)
        self.assertEqual(result, raw)
        return json.loads(result)

    def fresh(self, state):
        value = copy.deepcopy(self.value)
        now = datetime.now(timezone.utc) - timedelta(seconds=1)
        value["availability"].update(
            state=state,
            observed_at=now.isoformat().replace("+00:00", "Z"),
            fresh_until=(now + timedelta(seconds=15))
            .isoformat()
            .replace("+00:00", "Z"),
        )
        if state != "held":
            value.update(state=state, reason=None)
        else:
            value["reason"] = "availability_unconfirmed"
        if state == "active":
            value["cursor"] = {"last_sequence": "1", "phase": "active"}
            value["availability"]["cursor"] = dict(value["cursor"])
        return value

    def test_product_cli_held_status_returncode_one_is_a_valid_poll_result(self):
        output = io.StringIO()
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(worker_cli, "dispatch", return_value=self.value),
            contextlib.redirect_stdout(output),
        ):
            code = worker_cli.main(
                [
                    "status",
                    "--runtime-id",
                    self.admission["runtime_id"],
                    "--private-root",
                    temporary,
                ],
                installation=Path(temporary),
            )
        self.assertEqual(code, 1)
        self.assertEqual(
            self.decode(code=code, raw=output.getvalue().encode()), self.value
        )

    def test_only_fresh_valid_success_and_advisory_held_statuses_are_accepted(self):
        self.assertEqual(self.decode(), self.value)
        for state in ("idle-ready", "active", "held"):
            with self.subTest(state=state):
                value = self.fresh(state)
                self.assertEqual(
                    self.decode(value=value, code=1 if state == "held" else 0), value
                )

    def test_producer_presence_can_age_during_final_inspect_or_cli_transport(self):
        for state in ("idle-ready", "active", "held"):
            with self.subTest(presence=state):
                value = self.fresh(state)
                observed = datetime.now(timezone.utc) - timedelta(seconds=20)
                value["availability"].update(
                    observed_at=observed.isoformat().replace("+00:00", "Z"),
                    fresh_until=(observed + timedelta(seconds=15))
                    .isoformat()
                    .replace("+00:00", "Z"),
                )
                value.update(
                    state="held",
                    reason="availability_unconfirmed"
                    if state == "held"
                    else "availability_stale",
                )
                self.assertEqual(self.decode(value=value), value)

    def test_future_invalid_span_or_guard_shaped_presence_is_never_poll_success(self):
        for change in ("future", "wide", "reverse", "malformed", "guard", "phase"):
            with self.subTest(change=change):
                value = self.fresh("held")
                observed = datetime.now(timezone.utc) - timedelta(seconds=1)
                ending = observed + timedelta(seconds=15)
                if change == "future":
                    observed, ending = (
                        observed + timedelta(minutes=1),
                        ending + timedelta(minutes=1),
                    )
                    value["reason"] = "availability_stale"
                elif change == "wide":
                    ending = observed + timedelta(seconds=16)
                elif change == "reverse":
                    ending = observed - timedelta(seconds=1)
                elif change == "guard":
                    value["availability"]["state"] = "idle-ready"
                elif change == "phase":
                    value["reason"] = "availability_stale"
                    observed -= timedelta(seconds=20)
                    ending -= timedelta(seconds=20)
                    value["availability"]["state"] = "active"
                value["availability"].update(
                    observed_at=observed.isoformat().replace("+00:00", "Z"),
                    fresh_until=ending.isoformat().replace("+00:00", "Z"),
                )
                if change == "malformed":
                    value["availability"]["observed_at"] = "not-a-timestamp"
                with self.assertRaises(fixture.AcceptanceRefused):
                    self.decode(value=value)

    def test_worker_action_status_uses_narrow_decoder_but_mutations_stay_strict(self):
        selected = object.__new__(fixture.Fixture)
        selected.install, selected.private, selected.environment = (
            Path.cwd(),
            Path.cwd(),
            {},
        )
        completed = subprocess.CompletedProcess(
            [], 1, fixture.canonical(self.value), b""
        )
        with patch.object(fixture.subprocess, "run", return_value=completed):
            self.assertEqual(
                selected.worker_action(
                    "status",
                    self.admission["runtime_id"],
                    expected_admission=self.admission,
                ),
                self.value,
            )
            with self.assertRaises(fixture.AcceptanceRefused):
                selected.worker_action("stop", self.admission["runtime_id"])

    def test_changed_identity_policy_or_guard_states_never_become_poll_success(self):
        changes = (
            ("identity", {**self.value["identity"], "owner_nonce": "e" * 64}),
            ("runtime_id", "33333333-3333-4333-8333-333333333333"),
            ("limits", {"max_attempts": "35", "idle_timeout_seconds": None}),
            ("protocol", "finite-v2"),
            ("reason", "physical_unconfirmed"),
            ("reason", PRIVATE),
            ("reason", [PRIVATE]),
            ("reason", {PRIVATE: True}),
            ("container_state", "exited"),
            ("registration_state", "unknown"),
            ("disable_state", "unknown"),
            ("stop_state", "prepared"),
            ("revocation_state", "unknown"),
            ("new_work_disabled", True),
            ("reporting_revoked", True),
            ("availability", None),
            ("extra", PRIVATE),
        )
        for key, changed in changes:
            with self.subTest(key=key, kind=type(changed).__name__):
                value = {**self.value, key: changed}
                with self.assertRaises(fixture.AcceptanceRefused) as error:
                    self.decode(value=value)
                self.assertEqual(error.exception.args, ("persistent_status_refused",))

    def test_malformed_raw_output_and_exit_status_are_never_success(self):
        ordinary_failure = {
            "schema": "vardr.worker-cli/1",
            "state": "held",
            "runtime_id": self.admission["runtime_id"],
            "failure_phase": "dispatch",
            "failure_code": "runtime_refused",
        }
        raw = fixture.canonical(self.value)
        for bad in (
            b"",
            b"not-json",
            b"x" * 4097,
            b"[]",
            b"null",
            raw[:-1] + b',"state":"held"}',
            fixture.canonical(ordinary_failure),
            b'{"raw":NaN}',
        ):
            with (
                self.subTest(size=len(bad)),
                self.assertRaises(fixture.AcceptanceRefused),
            ):
                self.decode(raw=bad)
        for code in (0, 2, 130, True):
            with self.subTest(code=code), self.assertRaises(fixture.AcceptanceRefused):
                self.decode(code=code)
        with self.assertRaises(fixture.AcceptanceRefused):
            self.decode(stderr=PRIVATE.encode())

    def test_cursor_and_presence_cannot_downgrade_or_disagree(self):
        for changed in (
            {"cursor": {"last_sequence": 0, "phase": "idle"}},
            {"cursor": {"last_sequence": "00", "phase": "idle"}},
            {
                "availability": {
                    **self.value["availability"],
                    "cursor": {"last_sequence": "1", "phase": "active"},
                }
            },
            {"availability": {**self.value["availability"], "state": "idle-ready"}},
        ):
            with (
                self.subTest(changed=next(iter(changed))),
                self.assertRaises(fixture.AcceptanceRefused),
            ):
                self.decode(value={**self.value, **changed})


if __name__ == "__main__":
    unittest.main()
