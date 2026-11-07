"""Inactive v3 component protocol tests; no network, Docker or real custody."""

import copy
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
import unittest
from unittest.mock import Mock, patch

import test_worker_host as fixtures
import test_worker_runtime as runtime_fixtures
import worker_host as host
import worker_host_persistent as persistent
import worker_runtime as runtime


class PersistentHostTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.HostTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.addCleanup(self.f.tearDown)
        self.f.observer.protocol = "persistent-v3"
        self.f.session.register = Mock(
            side_effect=lambda selected, body: persistent.expected_admission(
                {"runtime_id": selected, "registration": body}
            )
        )

    def register(self, selected_limits=None):
        f = self.f
        return host.register_runtime(
            f.client,
            f.records,
            f.session,
            issuer_origin=f.binding["origin"],
            enrollment_id="enrolled-1",
            runner_id=f.runner_id,
            identity=f.identity,
            observer=f.observer,
            runtime_id=f.runtime_id,
            protocol="persistent-v3",
            limits=selected_limits
            or {"max_attempts": None, "idle_timeout_seconds": None},
        )

    def observation(self, sequence="9007199254740993", active=True, receipt=None):
        f = self.f
        admission = persistent.expected_admission(f.records.read(f.runtime_id))
        cursor = {"last_sequence": sequence, "phase": "active" if active else "idle"}
        return {
            "schema": "vardr.worker-receipt-observation/3",
            **{
                key: admission[key]
                for key in ("runtime_id", "runtime_sha256", "admission_sha256")
            },
            "cursor": cursor,
            "active": {
                "runtime_sequence": sequence,
                "binding": f.binding,
                "receipt": receipt,
            }
            if active
            else None,
            "retirement": None,
            "new_work_disabled": False,
            "reporting_revoked": False,
            "availability": {
                "state": "held",
                "observed_at": None,
                "fresh_until": None,
                "cursor": dict(cursor),
            },
        }

    def ack(self, body):
        f = self.f
        admission = persistent.expected_admission(f.records.read(f.runtime_id))
        active = "runtime_sequence" in body
        payload = {
            "schema": "vardr.worker-retirement/3",
            **{
                key: admission[key]
                for key in (
                    "runtime_id",
                    "runtime_sha256",
                    "admission_sha256",
                    "origin",
                    "runner_id",
                    "enrollment_id",
                )
            },
            "runtime_sequence": body["runtime_sequence"] if active else None,
            "last_sequence": body["runtime_sequence"]
            if active
            else body["last_sequence"],
            "binding": f.binding if active else None,
            "attempt_receipt": f.terminal() if active else None,
            "report_sha256": persistent._purpose(f.records.read(f.runtime_id), body),
            "retired": True,
        }
        closed = {**payload, "receipt_sha256": host.digest(payload)}
        return {
            "schema": "vardr.worker-host-stop/1",
            "runtime_id": f.runtime_id,
            "runtime_sha256": admission["runtime_sha256"],
            "receipt": closed,
        }

    def history(self, sequence="9007199254740993", *, outcome="completed"):
        f = self.f
        admission = persistent.expected_admission(f.records.read(f.runtime_id))
        terminal = {
            "schema": "vardr.managed-completion/1",
            **f.binding,
            "outcome": outcome,
            "receipt_sha256": "d" * 64,
            "capacity_reserved": False,
        }
        payload = {
            "schema": "vardr.worker-idle-release/2",
            **{
                key: admission[key]
                for key in ("runtime_id", "runtime_sha256", "admission_sha256")
            },
            "runtime_sequence": sequence,
            "binding": f.binding,
            "terminal_receipt_sha256": host.digest(terminal),
            "native_done_sha256": "e" * 64,
            "released": True,
        }
        return {
            "schema": "vardr.worker-attempt-observation/2",
            **{
                key: admission[key]
                for key in ("runtime_id", "runtime_sha256", "admission_sha256")
            },
            "runtime_sequence": sequence,
            "binding": f.binding,
            "receipt": terminal,
            "release": {**payload, "receipt_sha256": host.digest(payload)},
        }

    def test_registration_has_explicit_policy_digest_and_distinct_mac(self):
        f = self.f
        admission = self.register()
        self.assertEqual(admission["schema"], "vardr.worker-admission/3")
        self.assertEqual(
            admission["reporting_authority"],
            {"purpose": "worker-stop-only", "expires_at": None},
        )
        self.assertNotIn("expires_at", admission)
        self.assertNotIn("max_attempts", admission)
        self.assertEqual(
            admission["admission_sha256"],
            host.digest(
                {
                    key: item
                    for key, item in admission.items()
                    if key != "admission_sha256"
                }
            ),
        )
        raw = f.records._path(f.runtime_id).read_text()
        self.assertEqual(json.loads(raw)["schema"], "vardr.worker-host-record/3")
        self.assertNotIn(f.records.secret(f.runtime_id), raw)
        f.session.register.assert_called_once()

    def test_decimal_limits_refuse_ambiguous_numbers_and_keep_signed64_range(self):
        self.assertEqual(persistent.decimal(str(2**63 - 1)), 2**63 - 1)
        for value in (0, True, "00", "01", "+1", "-1", "1e3", "1.0", " 1", str(2**63)):
            with self.subTest(value=value), self.assertRaises(host.HostRefused):
                persistent.decimal(value)
        self.assertEqual(
            persistent.cursor_key({"last_sequence": "10", "phase": "active"}), (10, 0)
        )
        for selected in (
            {"max_attempts": "0", "idle_timeout_seconds": None},
            {"max_attempts": None, "idle_timeout_seconds": True},
            {"max_attempts": None, "idle_timeout_seconds": 86401},
        ):
            with self.subTest(selected=selected), self.assertRaises(host.HostRefused):
                persistent.limits(selected)

    def test_admission_policy_tamper_and_legacy_version_are_refused(self):
        f = self.f
        original = self.register()
        for mutation in ("schema", "limits", "reporting", "hash"):
            value = copy.deepcopy(original)
            if mutation == "schema":
                value["schema"] = "vardr.worker-admission/2"
            elif mutation == "limits":
                value["limits"]["idle_timeout_seconds"] = 60
            elif mutation == "reporting":
                value["reporting_authority"]["expires_at"] = "2026-11-06T00:00:00Z"
            else:
                value["admission_sha256"] = "f" * 64
            with self.subTest(mutation=mutation), self.assertRaises(host.HostRefused):
                persistent.admission(f.records.read(f.runtime_id), value)

    def test_large_sequence_uses_report_ordinal_zero_not_job_count(self):
        f = self.f
        self.register()
        f.client.receipt = Mock(return_value=self.observation())
        f.client.observed_exit = Mock(
            side_effect=lambda selected, body, secret: self.ack(body)
        )
        reply = host.report_observed_exit(
            f.client, f.records, f.runtime_id, f.proof, f.observer
        )
        self.assertTrue(reply["receipt"]["retired"])
        record = f.records.read(f.runtime_id)
        self.assertEqual(record["report_cursors"][0]["ordinal"], 0)
        self.assertEqual(
            record["report_cursors"][0]["cursor"]["last_sequence"], "9007199254740993"
        )
        self.assertEqual(
            len(list(f.records.directory.glob(f.runtime_id + ".report-v3-*.json"))), 1
        )
        f.client.observed_exit.assert_called_once()

    def test_final_physical_refusal_prevents_intent_and_post(self):
        f = self.f
        self.register()
        f.client.receipt = Mock(return_value=self.observation())
        f.client.observed_exit = Mock()
        f.observer.failed_confirmation = True
        with self.assertRaises(host.HostRefused):
            host.report_observed_exit(
                f.client, f.records, f.runtime_id, f.proof, f.observer
            )
        record = f.records.read(f.runtime_id)
        self.assertEqual(record["report_cursors"], [])
        self.assertEqual(record["stop_state"], "none")
        self.assertEqual(
            list(f.records.directory.glob(f.runtime_id + ".report-v3-*.json")), []
        )
        f.client.observed_exit.assert_not_called()

    def test_continuation_requires_the_original_exit_measurement(self):
        f = self.f
        self.register()
        f.client.receipt = Mock(return_value=self.observation())
        f.client.observed_exit = Mock(side_effect=host.HostRefused())
        with self.assertRaises(host.HostRefused):
            host.report_observed_exit(
                f.client, f.records, f.runtime_id, f.proof, f.observer
            )
        f.client.receipt.return_value = self.observation(active=False)
        f.client.attempt_receipt = Mock(return_value=self.history())
        f.client.observed_unbound_exit = Mock()
        changed = runtime.ObservedExit(
            f.identity, f.proof.finished_at, 17, _proof=runtime._PROOF
        )
        with self.assertRaises(host.HostRefused):
            host.continue_observed_exit(
                f.client, f.records, f.runtime_id, changed, f.observer
            )
        self.assertEqual(len(f.records.read(f.runtime_id)["report_cursors"]), 1)
        f.client.observed_unbound_exit.assert_not_called()

    def test_unknown_report_has_no_automatic_resend_and_selected_release_allows_continuation(
        self,
    ):
        f = self.f
        self.register()
        f.client.receipt = Mock(return_value=self.observation())
        f.client.observed_exit = Mock(side_effect=host.HostRefused())
        for _ in range(2):
            with self.assertRaises(host.HostRefused):
                host.report_observed_exit(
                    f.client, f.records, f.runtime_id, f.proof, f.observer
                )
        f.client.observed_exit.assert_called_once()
        old = f.records.read(f.runtime_id)["stop_intent"]
        f.client.receipt.return_value = self.observation(active=False)
        f.client.attempt_receipt = Mock(return_value=self.history())
        f.client.observed_unbound_exit = Mock(
            side_effect=lambda selected, body, secret: self.ack(body)
        )
        host.continue_observed_exit(
            f.client, f.records, f.runtime_id, f.proof, f.observer
        )
        record = f.records.read(f.runtime_id)
        self.assertEqual(record["stop_intent"], old)
        self.assertEqual([item["ordinal"] for item in record["report_cursors"]], [0, 1])
        self.assertEqual(
            persistent._load_report(f.records, f.runtime_id, 0)["state"], "unknown"
        )
        f.client.attempt_receipt.assert_called_once_with(
            f.runtime_id,
            "9007199254740993",
            host.digest(asdict(f.identity)),
            f.records.secret(f.runtime_id),
            admission_sha256=record["admission"]["admission_sha256"],
        )

    def test_changed_terminal_at_same_cursor_does_not_permit_new_post(self):
        f = self.f
        self.register()
        f.client.receipt = Mock(return_value=self.observation())
        f.client.observed_exit = Mock(side_effect=host.HostRefused())
        with self.assertRaises(host.HostRefused):
            host.report_observed_exit(
                f.client, f.records, f.runtime_id, f.proof, f.observer
            )
        f.client.receipt.return_value = self.observation(
            receipt=self.history()["receipt"]
        )
        with self.assertRaises(host.HostRefused):
            host.continue_observed_exit(
                f.client, f.records, f.runtime_id, f.proof, f.observer
            )
        f.client.observed_exit.assert_called_once()

    def test_report_ack_cannot_replace_existing_terminal_with_failed_receipt(self):
        f = self.f
        self.register()
        completed = self.history()["receipt"]
        f.client.receipt = Mock(return_value=self.observation(receipt=completed))
        f.client.observed_exit = Mock(
            side_effect=lambda selected, body, secret: self.ack(body)
        )
        with self.assertRaises(host.HostRefused):
            host.report_observed_exit(
                f.client, f.records, f.runtime_id, f.proof, f.observer
            )
        self.assertEqual(f.records.read(f.runtime_id)["stop_state"], "unknown")
        self.assertIsNone(f.records.read(f.runtime_id)["receipt"])
        f.client.observed_exit.assert_called_once()

    def test_malformed_transition_metadata_is_refused_before_publication(self):
        f = self.f
        self.register()
        original = f.records._path(f.runtime_id).read_bytes()
        for mutation in (
            "disable_without_intent",
            "invented_disable_ack",
            "observed_without_receipt",
            "unsupported_state",
        ):
            record = f.records.read(f.runtime_id)
            if mutation == "disable_without_intent":
                record["disable_state"] = "unknown"
            elif mutation == "invented_disable_ack":
                record["disable_receipt"] = {"new_work_disabled": True}
            elif mutation == "observed_without_receipt":
                record["stop_state"] = "observed"
            else:
                record["registration_state"] = "ready"
            with self.subTest(mutation=mutation), self.assertRaises(host.HostRefused):
                f.records.write(record)
            self.assertEqual(f.records._path(f.runtime_id).read_bytes(), original)

    def test_missing_or_tampered_report_sidecar_never_reaches_read_or_send(self):
        f = self.f
        self.register()
        f.client.receipt = Mock(return_value=self.observation())
        f.client.observed_exit = Mock(side_effect=host.HostRefused())
        with self.assertRaises(host.HostRefused):
            host.report_observed_exit(
                f.client, f.records, f.runtime_id, f.proof, f.observer
            )
        path = persistent._report_path(f.records, f.runtime_id, 0)
        original = path.read_bytes()
        for mutation in ("tampered", "missing"):
            if mutation == "tampered":
                wrapped = json.loads(original)
                wrapped["payload"]["intent"]["exit_code"] = 17
                path.write_bytes(host.canonical(wrapped))
            else:
                path.unlink()
            f.client.receipt.reset_mock()
            with (
                self.subTest(mutation=mutation),
                self.assertRaises((host.HostRefused, OSError)),
            ):
                host.reconcile_exit(f.client, f.records, f.runtime_id)
            f.client.receipt.assert_not_called()
        f.client.observed_exit.assert_called_once()

    def test_unknown_disable_resolves_by_read_without_inventing_ack(self):
        f = self.f
        self.register()
        f.client.disable = Mock(side_effect=host.HostRefused())
        for _ in range(2):
            with self.assertRaises(host.HostRefused):
                persistent.disable(f.client, f.records, f.runtime_id)
        f.client.disable.assert_called_once()
        observation = self.observation("0", False)
        observation["new_work_disabled"] = True
        f.client.receipt = Mock(return_value=observation)
        host.reconcile_exit(f.client, f.records, f.runtime_id)
        record = f.records.read(f.runtime_id)
        self.assertEqual(record["disable_state"], "observed")
        self.assertIsNone(record["disable_receipt"])
        self.assertEqual(record["revocation_state"], "none")

    def test_disable_ack_is_cached_and_reporting_still_works(self):
        f = self.f
        self.register()
        admission = persistent.expected_admission(f.records.read(f.runtime_id))
        value = {
            "schema": "vardr.worker-disable/1",
            **{
                key: admission[key]
                for key in ("runtime_id", "runtime_sha256", "admission_sha256")
            },
            "new_work_disabled": True,
        }
        f.client.disable = Mock(
            return_value={**value, "receipt_sha256": host.digest(value)}
        )
        self.assertEqual(
            persistent.disable(f.client, f.records, f.runtime_id),
            persistent.disable(f.client, f.records, f.runtime_id),
        )
        f.client.disable.assert_called_once()
        current = self.observation()
        current["new_work_disabled"] = True
        f.client.receipt = Mock(return_value=current)
        f.client.observed_exit = Mock(
            side_effect=lambda selected, body, secret: self.ack(body)
        )
        self.assertTrue(
            host.report_observed_exit(
                f.client, f.records, f.runtime_id, f.proof, f.observer
            )["receipt"]["retired"]
        )

    def test_orphan_report_sidecar_refuses_before_server_lookup(self):
        f = self.f
        self.register()
        record = f.records.read(f.runtime_id)
        expected = persistent.expected_admission(record)
        body = {
            "runtime_sha256": expected["runtime_sha256"],
            "admission_sha256": expected["admission_sha256"],
            "last_sequence": "0",
            "finished_at": f.proof.finished_at,
            "exit_code": f.proof.exit_code,
            "observation_sha256": "e" * 64,
        }
        persistent._store_report(
            f.records,
            {
                "runtime_id": f.runtime_id,
                "ordinal": 0,
                "cursor": {"last_sequence": "0", "phase": "idle"},
                "intent": body,
                "state": "prepared",
                "receipt": None,
            },
            create=True,
        )
        f.client.receipt = Mock()
        with self.assertRaises(host.HostRefused):
            host.reconcile_exit(f.client, f.records, f.runtime_id)
        f.client.receipt.assert_not_called()

    def test_report_limit_holds_without_eviction_and_does_not_limit_job_sequence(self):
        f = self.f
        self.register()
        record = f.records.read(f.runtime_id)
        expected = persistent.expected_admission(record)
        for ordinal in range(65):
            number, phase = (
                ((ordinal + 1) // 2, "active")
                if ordinal % 2
                else (ordinal // 2, "idle")
            )
            body = {
                "runtime_sha256": expected["runtime_sha256"],
                "admission_sha256": expected["admission_sha256"],
                "finished_at": f.proof.finished_at,
                "exit_code": f.proof.exit_code,
                "observation_sha256": host.digest(
                    {
                        "identity": asdict(f.identity),
                        "finished_at": f.proof.finished_at,
                        "exit_code": f.proof.exit_code,
                    }
                ),
                **(
                    {**f.binding, "runtime_sequence": str(number)}
                    if phase == "active"
                    else {"last_sequence": str(number)}
                ),
            }
            cursor = {"last_sequence": str(number), "phase": phase}
            persistent._store_report(
                f.records,
                {
                    "runtime_id": f.runtime_id,
                    "ordinal": ordinal,
                    "cursor": cursor,
                    "intent": body,
                    "state": "unknown",
                    "receipt": None,
                },
                create=True,
            )
            record["report_cursors"].append(
                {
                    "ordinal": ordinal,
                    "cursor": cursor,
                    "intent_sha256": host.digest(body),
                }
            )
            if ordinal == 0:
                record["stop_intent"] = body
        record["stop_state"] = "unknown"
        f.records.write(record)
        before = {
            path.name: path.read_bytes()
            for path in f.records.directory.glob(f.runtime_id + ".report-v3-*.json")
        }
        f.client.receipt = Mock(return_value=self.observation("33"))
        f.client.attempt_receipt = Mock(return_value=self.history("33"))
        f.client.observed_exit = Mock()
        with self.assertRaises(host.HostRefused):
            host.continue_observed_exit(
                f.client, f.records, f.runtime_id, f.proof, f.observer
            )
        self.assertEqual(
            before,
            {
                path.name: path.read_bytes()
                for path in f.records.directory.glob(f.runtime_id + ".report-v3-*.json")
            },
        )
        f.client.observed_exit.assert_not_called()

    def test_fresh_status_is_advisory_and_stale_or_disabled_is_held(self):
        f = self.f
        self.register()
        original_bound = f.observer._bound
        f.observer._bound = lambda identity: {
            **original_bound(identity),
            "state": {"Status": "running", "Running": True},
        }
        observation = self.observation("33", False)
        now = datetime.now(timezone.utc)
        observation["availability"].update(
            state="idle-ready",
            observed_at=now.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            fresh_until=(now + timedelta(seconds=15))
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
        )
        f.client.receipt = Mock(return_value=observation)
        with (
            patch.object(
                f.records, "write", side_effect=AssertionError("status is read only")
            ),
        ):
            ready = persistent.status(
                f.records, f.runtime_id, f.observer, f.identity, client=f.client
            )
            self.assertEqual(ready["state"], "idle-ready")
            observation["new_work_disabled"] = True
            self.assertEqual(
                persistent.status(
                    f.records, f.runtime_id, f.observer, f.identity, client=f.client
                )["state"],
                "held",
            )
            observation["new_work_disabled"] = False
            observation["availability"].update(
                observed_at=(now - timedelta(seconds=30))
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z"),
                fresh_until=(now - timedelta(seconds=15))
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z"),
            )
            self.assertEqual(
                persistent.status(
                    f.records, f.runtime_id, f.observer, f.identity, client=f.client
                )["state"],
                "held",
            )
        self.assertIsNone(f.observer._deadline)
        self.assertTrue(f.observer._observation_lock.acquire(blocking=False))
        f.observer._observation_lock.release()

    def test_actual_stopped_status_needs_no_map_connection(self):
        f = self.f
        self.register()
        original_bound = f.observer._bound
        f.observer._bound = lambda identity: {
            **original_bound(identity),
            "state": {"Status": "exited", "Running": False},
        }
        f.observer.observe_exit = Mock(return_value=f.proof)
        with patch.object(
            host, "HostClient", side_effect=AssertionError("no Map connection")
        ):
            value = persistent.status(f.records, f.runtime_id, f.observer, f.identity)
        self.assertEqual(value["state"], "stopped")
        self.assertEqual(value["exit_code"], f.proof.exit_code)

    def test_final_physical_failure_is_never_an_advisory_availability_hold(self):
        f = self.f
        self.register()
        running = {
            **f.observer._bound(f.identity),
            "state": {"Status": "running", "Running": True},
        }
        stopped = {**running, "state": {"Status": "exited", "Running": False}}
        f.client.receipt = Mock(return_value=self.observation("35", False))
        for failure in (
            runtime.RuntimeRefused("worker_runtime_refused"),
            OSError("private-canary-physical-path"),
            ValueError("private-canary-malformed-inspection"),
            stopped,
        ):
            with (
                self.subTest(kind=type(failure).__name__),
                patch.object(
                    f.observer, "_bound", side_effect=[running, failure]
                ) as inspect,
                patch.object(
                    f.records,
                    "write",
                    side_effect=AssertionError("status is read only"),
                ),
            ):
                value = persistent.status(
                    f.records, f.runtime_id, f.observer, f.identity, client=f.client
                )
            self.assertEqual(
                (value["state"], value["reason"]), ("held", "physical_unconfirmed")
            )
            self.assertEqual(value["availability"]["state"], "held")
            self.assertNotIn("private-canary", json.dumps(value))
            self.assertEqual(inspect.call_count, 2)
            self.assertIsNone(f.observer._deadline)
            self.assertTrue(f.observer._observation_lock.acquire(blocking=False))
            f.observer._observation_lock.release()

    def test_api_availability_failure_remains_advisory_and_read_only(self):
        f = self.f
        self.register()
        running = {
            **f.observer._bound(f.identity),
            "state": {"Status": "running", "Running": True},
        }
        f.client.receipt = Mock(side_effect=host.HostRefused("worker_host_refused"))
        with (
            patch.object(f.observer, "_bound", return_value=running) as inspect,
            patch.object(
                f.records, "write", side_effect=AssertionError("status is read only")
            ),
        ):
            value = persistent.status(
                f.records, f.runtime_id, f.observer, f.identity, client=f.client
            )
        self.assertEqual(
            (value["state"], value["reason"]), ("held", "availability_unconfirmed")
        )
        self.assertIsNone(value["availability"])
        self.assertEqual(inspect.call_count, 1)
        self.assertIsNone(f.observer._deadline)

    def test_status_rejects_another_exact_incarnation_before_inspection(self):
        f = self.f
        self.register()
        other = runtime.RuntimeIdentity(
            **{**asdict(f.identity), "owner_nonce": "f" * 64}
        )
        with (
            patch.object(f.observer, "_bound") as inspect,
            self.assertRaises(host.HostRefused),
        ):
            persistent.status(
                f.records, f.runtime_id, f.observer, other, client=f.client
            )
        inspect.assert_not_called()

    def test_transport_selects_v3_exact_string_sequence_and_admission_hash(self):
        client = object.__new__(host.HostClient)
        client._request = Mock(return_value=({"decoded": True}, []))
        f = self.f
        self.assertEqual(
            client.attempt_receipt(
                f.runtime_id,
                str(2**63 - 1),
                "a" * 64,
                "b" * 64,
                admission_sha256="c" * 64,
            ),
            {"decoded": True},
        )
        self.assertEqual(
            client._request.call_args.args[1],
            f"/managed/runtimes/{f.runtime_id}/attempts/{2**63 - 1}/receipt",
        )
        self.assertEqual(
            client._request.call_args.args[2],
            {"runtime_sha256": "a" * 64, "admission_sha256": "c" * 64},
        )
        with self.assertRaises(host.HostRefused):
            client.attempt_receipt(f.runtime_id, 33, "a" * 64, "b" * 64)

    def test_history_rejects_nested_boolean_or_float_fence_even_with_rehashed_release(
        self,
    ):
        f = self.f
        f.binding["fence"] = 1
        self.register()
        record = f.records.read(f.runtime_id)
        value = self.history("1")
        f.client.attempt_receipt = Mock(return_value=value)
        self.assertEqual(
            persistent.history(f.client, record, "1", f.records.secret(f.runtime_id)),
            value,
        )
        for malformed in (True, 1.0):
            with self.subTest(kind=type(malformed).__name__):
                changed = copy.deepcopy(value)
                changed["receipt"]["fence"] = malformed
                release = changed["release"]
                release["terminal_receipt_sha256"] = host.digest(changed["receipt"])
                release["receipt_sha256"] = host.digest(
                    {
                        key: item
                        for key, item in release.items()
                        if key != "receipt_sha256"
                    }
                )
                f.client.attempt_receipt.return_value = changed
                with self.assertRaises(host.HostRefused):
                    persistent.history(
                        f.client, record, "1", f.records.secret(f.runtime_id)
                    )

    def test_retirement_rejects_nested_boolean_or_float_fence_even_with_rehashed_receipt(
        self,
    ):
        f = self.f
        f.binding["fence"] = 1
        self.register()
        record = f.records.read(f.runtime_id)
        admitted = persistent.expected_admission(record)
        value = {
            "schema": "vardr.worker-retirement/3",
            **{
                key: admitted[key]
                for key in (
                    "runtime_id",
                    "runtime_sha256",
                    "admission_sha256",
                    "origin",
                    "runner_id",
                    "enrollment_id",
                )
            },
            "runtime_sequence": "1",
            "last_sequence": "1",
            "binding": f.binding,
            "attempt_receipt": self.history("1")["receipt"],
            "report_sha256": "e" * 64,
            "retired": True,
        }
        value["receipt_sha256"] = host.digest(value)
        self.assertEqual(persistent.retirement(record, value), value)
        for malformed in (True, 1.0):
            with self.subTest(kind=type(malformed).__name__):
                changed = copy.deepcopy(value)
                changed["attempt_receipt"]["fence"] = malformed
                changed["receipt_sha256"] = host.digest(
                    {
                        key: item
                        for key, item in changed.items()
                        if key != "receipt_sha256"
                    }
                )
                with self.assertRaises(host.HostRefused):
                    persistent.retirement(record, changed)

    def test_v3_runtime_requires_actual_ready3_and_never_downgrades(self):
        data = runtime_fixtures.WorkerRuntimeTests()
        data.setUp()
        self.addCleanup(data.doCleanups)
        self.addCleanup(data.tearDown)
        data.info["state"].update(Status="running", Running=True)
        observer = runtime.LocalDocker(
            "desktop-linux", data.layout, protocol="persistent-v3"
        )
        with patch.object(runtime.subprocess, "run", data.command):
            for schema in ("vardr.worker-owner-ready/1", "vardr.worker-owner-ready/2"):
                data.ready["schema"] = schema
                with (
                    self.subTest(schema=schema),
                    self.assertRaises(runtime.RuntimeRefused),
                ):
                    observer.capture_running(
                        container_id=data.identity.container_id,
                        image_id=data.identity.image_id,
                        project=data.identity.project,
                    )
            data.ready["schema"] = "vardr.worker-owner-ready/3"
            self.assertEqual(
                observer.capture_running(
                    container_id=data.identity.container_id,
                    image_id=data.identity.image_id,
                    project=data.identity.project,
                ),
                data.identity,
            )
        self.assertFalse(any("exec" in arguments for arguments, _ in data.calls))

    def test_explicit_legacy_registration_cannot_select_a_different_protocol(self):
        f = self.f
        for protocol, maximum in (
            ("legacy-v1", 2),
            ("finite-v2", None),
            ("finite-v2", 2),
        ):
            with (
                self.subTest(protocol=protocol, maximum=maximum),
                self.assertRaises(host.HostRefused),
            ):
                host.register_runtime(
                    f.client,
                    f.records,
                    f.session,
                    issuer_origin=f.binding["origin"],
                    enrollment_id="enrolled-1",
                    runner_id=f.runner_id,
                    identity=f.identity,
                    observer=f.observer,
                    runtime_id=f.runtime_id,
                    protocol=protocol,
                    max_attempts=maximum,
                    expires_in_seconds=900,
                )
        f.session.register.assert_not_called()
        self.assertIsNone(f.backend.read(f.runtime_id))


class OriginalAuditJoinTests(unittest.TestCase):
    def fixture(self, *, last="2", kind="retired"):
        record = {
            "runtime_id": "11111111-1111-4111-8111-111111111111",
            "registration_state": "acknowledged",
            "stop_state": "observed",
            "disable_state": "none",
            "revocation_state": "none",
            "registration": {
                "enrollment_id": "fixture-enrollment",
                "runner_id": "22222222-2222-4222-8222-222222222222",
                "origin": "https://owned.example/backend",
                "mode": "persistent",
                "capability_sha256": "a" * 64,
                "limits": {"max_attempts": None, "idle_timeout_seconds": None},
                "reporting_authority": dict(persistent.REPORTING_AUTHORITY),
                "identity": {
                    "daemon_id": "fixture-daemon",
                    "container_id": "b" * 64,
                    "image_id": "sha256:" + "c" * 64,
                    "project": "owned-fixture",
                    "started_at": "2026-11-05T20:00:00Z",
                    "owner_nonce": "d" * 64,
                },
            },
        }
        record["admission"] = original = persistent.expected_admission(record)
        binding = {
            key: original[key]
            for key in ("runner_id", "runtime_id", "runtime_sha256", "admission_sha256")
        }
        receipt = {
            "schema": "vardr.worker-retirement/3",
            **binding,
            "origin": original["origin"],
            "enrollment_id": original["enrollment_id"],
            "runtime_sequence": None,
            "last_sequence": last,
            "binding": None,
            "attempt_receipt": None,
            "report_sha256": "e" * 64,
            "retired": True,
        }
        receipt["receipt_sha256"] = host.digest(receipt)
        record["receipt"] = copy.deepcopy(receipt)
        cursor = {"last_sequence": last, "phase": "idle"}
        observed = {
            "schema": "vardr.worker-receipt-observation/3",
            **{k: binding[k] for k in binding if k != "runner_id"},
            "cursor": cursor,
            "active": None,
            "retirement": receipt,
            "new_work_disabled": True,
            "reporting_revoked": False,
            "availability": {
                "state": "stopped",
                "observed_at": None,
                "fresh_until": None,
                "cursor": dict(cursor),
            },
        }
        selections = 0 if kind == "empty_unissued" else int(last) + 1
        audit = {
            "schema": "vardr.worker-state-audit/1",
            "status": kind,
            "reason": None,
            "complete": True,
            "binding": binding,
            "parent": {
                "state": "idle" if kind == "empty_unissued" else "retired",
                "last_sequence": last,
                "head_sequence": None if last == "0" else last,
                "active_sequence": None,
            },
            "counts": {
                "attempts": int(last),
                "selections": selections,
                "associated_runs": selections,
                "associated_claims": selections,
            },
            "global_holds": 0,
            "retirement_receipt_sha256": None
            if kind == "empty_unissued"
            else receipt["receipt_sha256"],
        }
        return record, observed, audit

    def join(self, record, observed, audit, *, output=None, returncode=0):
        return persistent.original_local_audit(
            record,
            observed,
            output=host.canonical(audit) if output is None else output,
            returncode=returncode,
        )

    def test_original_audit_joins_retired_positive_history_and_reconciled_parent_zero(
        self,
    ):
        for last in ("2", "0"):
            with self.subTest(last=last):
                record, observed, audit = self.fixture(last=last)
                self.assertEqual(
                    self.join(record, observed, audit),
                    {
                        "kind": "retired",
                        "last_sequence": last,
                        "original_local_audit_sha256": host.digest(audit),
                    },
                )

    def test_empty_unissued_requires_positive_zero_map_retirement_and_no_local_retirement(
        self,
    ):
        record, observed, audit = self.fixture(last="0", kind="empty_unissued")
        result = self.join(record, observed, audit)
        self.assertEqual(
            result,
            {
                "kind": "empty_unissued",
                "last_sequence": "0",
                "original_local_audit_sha256": host.digest(audit),
            },
        )
        self.assertIsNone(audit["retirement_receipt_sha256"])
        self.assertFalse(any(audit["counts"].values()))
        for row in (
            dict(audit, retirement_receipt_sha256=record["receipt"]["receipt_sha256"]),
            dict(audit, status="retired"),
        ):
            with self.assertRaises(host.HostRefused):
                self.join(record, observed, row)
        other_record, other_observed, _ = self.fixture(last="1")
        with self.assertRaises(host.HostRefused):
            self.join(other_record, other_observed, audit)

    def test_missing_original_host_or_map_retirement_does_not_use_local_audit_as_authority(
        self,
    ):
        for change in (
            "host_unacknowledged",
            "host_not_observed",
            "map_missing",
            "map_disabled_false",
            "map_not_stopped",
            "map_changed",
        ):
            with self.subTest(change=change):
                record, observed, audit = self.fixture()
                if change == "host_unacknowledged":
                    record["registration_state"] = "unknown"
                elif change == "host_not_observed":
                    record["stop_state"] = "prepared"
                elif change == "map_missing":
                    observed["retirement"] = None
                elif change == "map_disabled_false":
                    observed["new_work_disabled"] = False
                elif change == "map_not_stopped":
                    observed["availability"]["state"] = "held"
                else:
                    observed["retirement"]["report_sha256"] = "f" * 64
                    value = {
                        k: v
                        for k, v in observed["retirement"].items()
                        if k != "receipt_sha256"
                    }
                    observed["retirement"]["receipt_sha256"] = host.digest(value)
                with self.assertRaisesRegex(
                    host.HostRefused, "^worker_predecessor_refused$"
                ):
                    self.join(record, observed, audit)

    def test_incomplete_held_or_cross_bound_original_audits_are_refused(self):
        changes = [
            dict(status="held"),
            dict(complete=1),
            dict(reason="private-canary"),
            dict(global_holds=1),
            dict(global_holds=False),
            dict(schema="vardr.worker-state-audit/2"),
            dict(unselected="private-canary"),
            dict(retirement_receipt_sha256="f" * 64),
            dict(binding={}),
        ]
        for change in changes:
            with self.subTest(fields=sorted(change)):
                record, observed, audit = self.fixture()
                with self.assertRaisesRegex(
                    host.HostRefused, "^worker_predecessor_refused$"
                ):
                    self.join(record, observed, {**audit, **change})
        for key in ("runner_id", "runtime_id", "runtime_sha256", "admission_sha256"):
            record, observed, audit = self.fixture()
            audit["binding"][key] = "foreign"
            with self.assertRaises(host.HostRefused):
                self.join(record, observed, audit)

    def test_parent_cursor_and_count_types_and_relationships_are_exact(self):
        changes = (
            ("parent", "active_sequence", "2"),
            ("parent", "last_sequence", "02"),
            ("parent", "head_sequence", "1"),
            ("counts", "attempts", 1),
            ("counts", "selections", True),
            ("counts", "associated_claims", -1),
            ("counts", "associated_runs", 0),
            ("counts", "associated_runs", 6),
            ("counts", "extra", 0),
        )
        for container, key, value in changes:
            with self.subTest(container=container, key=key):
                record, observed, audit = self.fixture()
                audit[container][key] = value
                with self.assertRaises(host.HostRefused):
                    self.join(record, observed, audit)

    def test_exit_status_and_bounded_strict_original_json_are_required(self):
        record, observed, audit = self.fixture()
        for code in (1, False, "0", None):
            with self.assertRaisesRegex(
                host.HostRefused, "^worker_predecessor_refused$"
            ):
                self.join(record, observed, audit, returncode=code)
        for raw in (
            b"",
            b'{"status":"held","status":"private-canary"}',
            b'{"counts":NaN}',
            b"[]",
            b"x" * 65537,
            "not bytes",
        ):
            with self.assertRaisesRegex(
                host.HostRefused, "^worker_predecessor_refused$"
            ):
                self.join(record, observed, audit, output=raw)

if __name__ == "__main__":
    unittest.main()
