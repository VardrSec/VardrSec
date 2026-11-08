"""Baseline branch inventory: real status/CLI, entirely mocked external I/O.

Only closed held responses may continue an already bounded post-job poll.
This never creates physical proof or product execution authority.
"""

import contextlib
import copy
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import subprocess
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import nm2_worker_acceptance as fixture
import test_nm2_worker_idle_limit as vectors
import worker_cli
import worker_host as host
import worker_host_persistent as persistent
import worker_runtime as runtime

NOW = datetime(2026, 11, 6, 2, 0, 6, tzinfo=timezone.utc)
MAP_FIELDS = ("cursor", "availability", "new_work_disabled", "reporting_revoked")


def produce(case):
    _, _, owner, admission, ready, stopped = vectors.vector(run=False)
    local = next(owner.persistent_metadata.side_effect)
    record = {"runtime_id": admission["runtime_id"],
        "registration": {key: copy.deepcopy(admission[key]) for key in persistent.REGISTRATION},
        "admission": admission, "registration_state": "acknowledged",
        "disable_state": "none", "disable_intent": None, "disable_receipt": None,
        "stop_state": "none", "revocation_state": "none", "receipt": None,
        "client": {"base_url": "https://model.invalid", "ca_file": "/model-unused-ca"}}
    current = {"schema": "vardr.worker-receipt-observation/3",
        **{key: admission[key] for key in ("runtime_id", "runtime_sha256", "admission_sha256")},
        "cursor": copy.deepcopy(ready["cursor"]), "active": None, "retirement": None,
        "new_work_disabled": False, "reporting_revoked": False,
        "availability": copy.deepcopy(ready["availability"])}
    running = {"state": {"Status": "running", "Running": True}}
    exited = {"state": {"Status": "exited", "Running": False}}
    bound = [running, running]
    identity = runtime.RuntimeIdentity(**admission["identity"])
    # Typed synthetic observer output only; never physical/native evidence.
    proof = runtime.ObservedExit(identity, stopped["finished_at"], 124, _proof=runtime._PROOF)
    receipt_error = read_error = reports_error = observer_error = client_error = None
    if case.startswith("initial-") or case.startswith("final-") or case.startswith("exit-refusal-"):
        kind = case.rsplit("-", 1)[1]
        error = {"host": host.HostRefused, "runtime": runtime.RuntimeRefused,
            "os": OSError, "value": ValueError}[kind]("synthetic-private-canary")
        if case.startswith("initial-"): bound = [error]
        elif case.startswith("final-"): bound = [running, error]
        else: bound, proof = [exited], error
    elif case == "running-to-exited": bound = [running, exited]
    elif case in {"exited124", "exited125", "exit-wrong-proof"}:
        bound = [exited]
        if case == "exited125": proof = runtime.ObservedExit(identity, stopped["finished_at"], 125, _proof=runtime._PROOF)
        elif case == "exit-wrong-proof": proof = object()
    elif case in {"paused", "restarting", "dead", "removing"}:
        bound = [{"state": {"Status": case, "Running": False}}]
    elif case == "lookup-error": receipt_error = host.HostRefused("synthetic-private-canary")
    elif case == "lookup-malformed": current = None
    elif case == "client-construction": client_error = host.HostRefused("synthetic-private-canary")
    elif case == "stale":
        current["availability"].update(observed_at="2026-11-06T01:59:36Z", fresh_until="2026-11-06T01:59:51Z")
    elif case == "held-presence": current["availability"]["state"] = "held"
    elif case == "never-observed": current["availability"].update(state="held", observed_at=None, fresh_until=None)
    elif case == "future-presence":
        current["availability"].update(observed_at="2026-11-06T02:00:07Z", fresh_until="2026-11-06T02:00:22Z")
    elif case == "active":
        current["cursor"]["phase"] = "active"
        current["availability"].update(state="active", cursor=copy.deepcopy(current["cursor"]))
        current["active"] = {"runtime_sequence": "1", "binding": {
            key: local["attempt"]["completion"][key] for key in host._BINDING}, "receipt": None}
    elif case in {"disabled", "revoked"}:
        current["new_work_disabled" if case == "disabled" else "reporting_revoked"] = True
    elif case == "registration-unknown": record.update(registration_state="unknown", admission=None)
    elif case == "stop-unknown": record["stop_state"] = "unknown"
    elif case == "disable-unknown":
        record.update(disable_state="unknown", disable_intent={key: admission[key] for key in ("runtime_sha256", "admission_sha256")})
    elif case == "revocation-unknown": record["revocation_state"] = "unknown"
    elif case == "record-read-error": read_error = OSError("synthetic-private-canary")
    elif case == "reports-error": reports_error = host.HostRefused("synthetic-private-canary")
    elif case == "observer-error": observer_error = host.HostRefused("synthetic-private-canary")
    elif case == "identity-mismatch": identity = runtime.RuntimeIdentity(**{**admission["identity"], "owner_nonce": "f" * 64})
    elif case == "missing-bound-state": bound = [{}]
    else: assert case == "ready"
    persistent.record_state(record)
    records = SimpleNamespace(locked=contextlib.nullcontext,
        read=Mock(return_value=record, side_effect=read_error),
        secret=Mock(return_value="synthetic-unused-custody"),
        write=Mock(side_effect=AssertionError("status_write_forbidden")))
    observer = SimpleNamespace(_observation_lock=threading.Lock(), _deadline=None,
        _bound=Mock(side_effect=bound), observe_exit=Mock(return_value=proof,
            side_effect=proof if isinstance(proof, BaseException) else None))
    client = Mock()
    client.receipt = Mock(return_value=current, side_effect=receipt_error)
    output = io.StringIO()
    with patch.object(host, "_observer", side_effect=observer_error), patch.object(host, "_client"), \
        patch.object(host, "HostClient", side_effect=client_error), \
        patch.object(persistent, "_reports", return_value=[], side_effect=reports_error), \
        patch.object(persistent, "datetime", wraps=datetime) as clock, \
        patch.object(worker_cli, "dispatch", side_effect=lambda *_: persistent.status(records,
            admission["runtime_id"], observer, identity, client=None if client_error else client)), \
        contextlib.redirect_stdout(output):
        clock.now.return_value = NOW
        code = worker_cli.main(["status", "--runtime-id", admission["runtime_id"],
            "--private-root", str(Path(__file__).parent / "unused-custody")],
            installation=Path(__file__).resolve().parents[1])
    records.write.assert_not_called()
    assert observer._deadline is None
    return json.loads(output.getvalue()), code, admission


CASES = (
    "ready", "stale", "held-presence", "never-observed", "future-presence", "active",
    "lookup-error", "lookup-malformed", "client-construction", "disabled", "revoked",
    "registration-unknown", "stop-unknown", "disable-unknown", "revocation-unknown",
    "running-to-exited", "exited124", "exited125", "exit-wrong-proof",
    "paused", "restarting", "dead", "removing", "record-read-error", "reports-error",
    "observer-error", "identity-mismatch", "missing-bound-state",
    *("initial-" + kind for kind in ("host", "runtime", "os", "value")),
    *("final-" + kind for kind in ("host", "runtime", "os", "value")),
    *("exit-refusal-" + kind for kind in ("host", "runtime", "os", "value")),
)
BASE_ACCEPTED = {"ready", "stale", "held-presence", "never-observed", "lookup-error", "lookup-malformed", "client-construction", "exited124"}
PHYSICAL_ADVISORY = {case for case in CASES if case.startswith(("initial-", "final-", "exit-refusal-"))} | {"running-to-exited", "exit-wrong-proof"}
ACCEPTED = BASE_ACCEPTED | PHYSICAL_ADVISORY


def decode(value, code, admission):
    with patch.object(fixture, "datetime", wraps=datetime) as clock:
        clock.now.return_value = NOW
        return fixture.idle_status_value(value, code, admission)


class ProductBranchInventory(unittest.TestCase):
    def test_all_current_producer_branches_and_decoder_dispositions(self):
        for case in CASES:
            with self.subTest(case=case):
                value, code, admission = produce(case)
                result = subprocess.CompletedProcess([], code, host.canonical(value), b"")
                accepted, checkpoint = True, None
                with patch.object(fixture.subprocess, "run", return_value=result) as run, \
                    patch.object(fixture, "datetime", wraps=datetime) as clock:
                    clock.now.return_value = NOW
                    try:
                        fixture.worker_idle_status_command([], cwd=Path.cwd(), env={}, timeout=3,
                            expected_admission=admission)
                    except fixture.IdleStatusRefused as error:
                        accepted, checkpoint = False, error.public["checkpoint"]
                run.assert_called_once()
                is_status = value["schema"] == "vardr.worker-status/1"
                if is_status:
                    fields = "null" if all(value[key] is None for key in MAP_FIELDS) else "full"
                    shape = fields + ("_container" if "container_state" in value else "_no_container")
                else:
                    shape = "cli_error"
                row = {"case": case, "shape": shape, "code": code,
                    "decoder_accepts": accepted, "checkpoint": checkpoint}
                self.assertNotIn("synthetic-private-canary", json.dumps(row))
                self.assertEqual(accepted, case in ACCEPTED)

    def test_closed_physical_advisory_refuses_tampering_and_impossible_cross_products(self):
        full, _, admission = produce("running-to-exited")
        empty, _, _ = produce("initial-host")
        exited, _, _ = produce("exit-refusal-host")
        changes = [
            (full, "container_state", "exited"), (empty, "container_state", "running"),
            (empty, "container_state", "paused"), (full, "new_work_disabled", True),
            (full, "reporting_revoked", True), (empty, "new_work_disabled", False),
            (empty, "cursor", {"last_sequence": "1", "phase": "idle"}),
            (full, "cursor", {"last_sequence": "2", "phase": "idle"}),
            (full, "cursor", {"last_sequence": "1", "phase": "active"}),
            (full, "availability", None), (full, "availability", {}),
            (full, "registration_state", "unknown"), (full, "stop_state", "unknown"),
            (full, "disable_state", "unknown"), (full, "revocation_state", "unknown"),
            (full, "identity", {**full["identity"], "owner_nonce": "f" * 64}),
            (full, "limits", {"max_attempts": None, "idle_timeout_seconds": 59}),
            (full, "extra", "synthetic-private-canary"), (exited, "exit_code", 124),
        ]
        for original, key, value in changes:
            with self.subTest(key=key), self.assertRaises(fixture.IdleStatusRefused):
                decode({**original, key: value}, 1, admission)
        for key in fixture.IDLE_STATUS_FIELDS - {"container_state"}:
            with self.subTest(missing=key), self.assertRaises(fixture.IdleStatusRefused):
                decode({k: v for k, v in full.items() if k != key}, 1, admission)
        for code in (0, 2, True, 1.0):
            with self.subTest(code=code), self.assertRaises(fixture.IdleStatusRefused):
                decode(full, code, admission)

    def test_internal_predicate_checkpoints_are_closed_and_wrapper_preserves_them(self):
        full, _, admission = produce("running-to-exited")
        stopped, _, _ = produce("exited124")
        bad_admission = copy.deepcopy(admission)
        bad_admission["limits"]["idle_timeout_seconds"] = "60"
        cases = [
            (full, 1, bad_admission, "admission"),
            ({**full, "extra": "synthetic-private-canary"}, 1, admission, "output"),
            ({**full, "limits": {"max_attempts": None, "idle_timeout_seconds": 59}}, 1, admission, "identity"),
            ({**full, "cursor": {"last_sequence": "2", "phase": "idle"}}, 1, admission, "cursor"),
            ({**full, "availability": {}}, 1, admission, "presence"),
            ({**full, "availability": {**full["availability"], "state": "active"}}, 1, admission, "presence"),
            ({**full, "availability": {**full["availability"], "observed_at": "2026-11-06T02:00:07Z", "fresh_until": "2026-11-06T02:00:22Z"}}, 1, admission, "freshness"),
            ({**full, "availability": {**full["availability"], "observed_at": "synthetic-private-canary"}}, 1, admission, "freshness"),
            ({**full, "availability": {**full["availability"], "fresh_until": "2026-11-06T02:00:04Z"}}, 1, admission, "freshness"),
            ({**full, "availability": {**full["availability"], "fresh_until": "2026-11-06T02:00:21Z"}}, 1, admission, "freshness"),
            ({**full, "availability": {**full["availability"], "observed_at": None, "fresh_until": None}}, 1, admission, "freshness"),
            ({**full, "new_work_disabled": True}, 1, admission, "advisory"),
            ({**stopped, "exit_code": 125}, 0, admission, "readiness"),
        ]
        for value, code, selected, checkpoint in cases:
            with self.subTest(checkpoint=checkpoint), self.assertRaises(fixture.IdleStatusRefused) as refused:
                decode(value, code, selected)
            self.assertEqual(refused.exception.public, {"checkpoint": checkpoint})
            self.assertEqual(str(refused.exception), "idle_status_refused")
        typed = fixture.IdleStatusRefused("cursor")
        result = subprocess.CompletedProcess([], 1, host.canonical(full), b"")
        with patch.object(fixture.subprocess, "run", return_value=result) as run, \
            patch.object(fixture, "idle_status_value", side_effect=typed):
            with self.assertRaises(fixture.IdleStatusRefused) as refused:
                fixture.worker_idle_status_command([], cwd=Path.cwd(), env={}, timeout=3,
                    expected_admission=admission)
        self.assertIs(refused.exception, typed)
        run.assert_called_once()

    def test_physical_advisory_never_gives_initial_readiness_or_extends75_seconds(self):
        for case in ("initial-host", "running-to-exited", "exit-refusal-host"):
            advisory, code, admission = produce(case)
            decode(advisory, code, admission)
            _, _, owner, _, ready, _ = vectors.vector(run=False)
            owner.worker_action.side_effect = [advisory]
            with self.subTest(case=case), self.assertRaisesRegex(fixture.AcceptanceRefused, "idle_initial_readiness_missing"):
                vectors.run_owner(owner)
            owner.report_exit.assert_not_called()
            _, _, owner, _, ready, _ = vectors.vector(run=False)
            owner.worker_action.side_effect = [ready, advisory]
            with patch.object(fixture.time, "monotonic", side_effect=[100, 101, 102, 103, 104, 176]), \
                patch.object(fixture.time, "sleep"):
                with self.assertRaisesRegex(fixture.AcceptanceRefused, "idle_native_exit_not_observed"):
                    owner.persistent_idle_limit([])
            self.assertEqual([call.args[0] for call in owner.worker_action.call_args_list], ["status", "status"])
            owner.report_exit.assert_not_called()

    def test_later_stopped_status_still_needs_original_independent_physical_proof(self):
        for case in ("initial-host", "running-to-exited", "exit-refusal-host"):
            advisory, code, admission = produce(case)
            decode(advisory, code, admission)
            raw, selection, owner, _, ready, stopped = vectors.vector(run=False)
            owner.worker_action.side_effect = [ready, advisory, stopped,
                {"state": "terminal_observed", "receipt": {"retirement": owner.report_exit.return_value}}]
            vectors.run_owner(owner)
            public = vectors.reader.project(raw, selection)
            self.assertEqual(public["measurements"]["native_exit_code"], 124)
            self.assertEqual(public["measurements"]["issued_attempts"], 1)
            self.assertEqual(public["measurements"]["target_request_count"], 5)
            self.assertEqual(public["measurements"]["remaining_local_holds"], 0)
            self.assertEqual([call.args[0] for call in owner.worker_action.call_args_list],
                ["status", "status", "status", "reconcile"])
            owner.report_exit.assert_called_once()
        advisory, code, admission = produce("running-to-exited")
        decode(advisory, code, admission)
        for key, value in (("exit_code", 125), ("finished_at", "2026-11-06T02:03:00Z"),
            ("operator_stop_state", "stopped_observed"),
            ("identity", {**admission["identity"], "owner_nonce": "f" * 64})):
            _, _, owner, _, ready, stopped = vectors.vector(run=False)
            original_worker = owner.worker.side_effect
            def changed_worker(*args, **kwargs):
                return {**original_worker(*args, **kwargs), key: value}
            owner.worker.side_effect = changed_worker
            owner.worker_action.side_effect = [ready, advisory, stopped]
            with self.subTest(key=key), self.assertRaisesRegex(fixture.AcceptanceRefused, "idle_native_exit_not_proven"):
                vectors.run_owner(owner)
            owner.report_exit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
