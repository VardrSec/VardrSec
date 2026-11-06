"""Bounded host sequence tests; no Docker, Vault or real network requests."""

from dataclasses import asdict
import json
import unittest
from unittest.mock import Mock

import test_worker_host as fixtures
import worker_host as host
import worker_host_sequence as sequence


class SequenceHostTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.HostTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.addCleanup(self.f.tearDown)

    def register(self, maximum=2):
        f = self.f
        f.observer.max_attempts = maximum
        original = f.session.register

        def register(runtime_id, body):
            reply = original(runtime_id, body)
            reply.update(
                schema="vardr.worker-admission/2", max_attempts=body["max_attempts"]
            )
            return reply

        f.session.register = register
        return host.register_runtime(
            f.client,
            f.records,
            f.session,
            issuer_origin=f.binding["origin"],
            enrollment_id="enrolled-1",
            runner_id=f.runner_id,
            identity=f.identity,
            observer=f.observer,
            expires_in_seconds=900,
            runtime_id=f.runtime_id,
            max_attempts=maximum,
        )

    def observation(self, last=1, active=True, receipt=None):
        f = self.f
        return {
            "schema": "vardr.worker-receipt-observation/2",
            "runtime_id": f.runtime_id,
            "runtime_sha256": host.digest(asdict(f.identity)),
            "last_sequence": last,
            "active": {
                "runtime_sequence": last,
                "binding": f.binding,
                "receipt": receipt,
            }
            if active
            else None,
            "retirement": None,
        }

    def ack(self, body, *, active=True, last=1):
        f = self.f
        record = f.records.read(f.runtime_id)
        value = {
            "schema": "vardr.worker-retirement/2",
            "runtime_id": f.runtime_id,
            "runtime_sha256": host.digest(asdict(f.identity)),
            "origin": f.binding["origin"],
            "runner_id": f.runner_id,
            "enrollment_id": "enrolled-1",
            "runtime_sequence": last if active else None,
            "last_sequence": last,
            "binding": f.binding if active else None,
            "attempt_receipt": f.terminal() if active else None,
            "report_sha256": sequence._purpose(record, body),
            "retired": True,
        }
        value["receipt_sha256"] = host.digest(value)
        return {
            "schema": "vardr.worker-host-stop/1",
            "runtime_id": f.runtime_id,
            "runtime_sha256": value["runtime_sha256"],
            "receipt": value,
        }

    def history(self, number=1):
        f = self.f
        terminal = {
            "schema": "vardr.managed-completion/1",
            **f.binding,
            "outcome": "completed",
            "capacity_reserved": False,
            "receipt_sha256": "a1" * 32,
        }
        release = {
            "schema": "vardr.worker-idle-release/1",
            "runtime_id": f.runtime_id,
            "runtime_sha256": host.digest(asdict(f.identity)),
            "runtime_sequence": number,
            "binding": f.binding,
            "terminal_receipt_sha256": host.digest(terminal),
            "native_done_sha256": "b2" * 32,
            "released": True,
        }
        release["receipt_sha256"] = host.digest(release)
        return {
            "schema": "vardr.worker-attempt-observation/1",
            "runtime_id": f.runtime_id,
            "runtime_sha256": release["runtime_sha256"],
            "runtime_sequence": number,
            "binding": f.binding,
            "receipt": terminal,
            "release": release,
        }

    def test_explicit_mode_has_distinct_mac_and_admission_without_raw_secret(self):
        f = self.f
        admission = self.register(32)
        self.assertEqual(admission["max_attempts"], 32)
        wrapped = json.loads(f.records._path(f.runtime_id).read_text())
        self.assertEqual(wrapped["schema"], "vardr.worker-host-record/2")
        self.assertNotIn(
            f.records.secret(f.runtime_id), f.records._path(f.runtime_id).read_text()
        )

    def test_bound_report_proves_incarnation_retirement_and_preserves_original_intent(
        self,
    ):
        f = self.f
        self.register()
        f.client.receipt = Mock(return_value=self.observation())
        f.client.observed_exit = Mock(
            side_effect=lambda runtime_id, body, secret: self.ack(body)
        )
        reply = host.report_observed_exit(
            f.client, f.records, f.runtime_id, f.proof, f.observer
        )
        record = f.records.read(f.runtime_id)
        self.assertTrue(reply["receipt"]["retired"])
        self.assertEqual(record["receipt"]["schema"], "vardr.worker-retirement/2")
        self.assertEqual(record["stop_intent"]["runtime_sequence"], 1)
        self.assertEqual(len(record["report_cursors"]), 1)
        self.assertEqual(f.client.observed_exit.call_count, 1)

    def test_idle_report_pins_last_sequence_and_has_no_job_tuple(self):
        f = self.f
        self.register()
        f.client.receipt = Mock(return_value=self.observation(0, False))
        f.client.observed_unbound_exit = Mock(
            side_effect=lambda runtime_id, body, secret: self.ack(
                body, active=False, last=0
            )
        )
        host.report_observed_exit(
            f.client, f.records, f.runtime_id, f.proof, f.observer
        )
        body = f.client.observed_unbound_exit.call_args.args[1]
        self.assertEqual(body["last_sequence"], 0)
        self.assertNotIn("job_id", body)
        self.assertNotIn("runtime_sequence", body)

    def test_unknown_reply_never_automatically_resends(self):
        f = self.f
        self.register()
        f.client.receipt = Mock(return_value=self.observation())
        f.client.observed_exit = Mock(side_effect=host.HostRefused())
        for _ in range(2):
            with self.assertRaises(host.HostRefused):
                host.report_observed_exit(
                    f.client, f.records, f.runtime_id, f.proof, f.observer
                )
        host.reconcile_exit(f.client, f.records, f.runtime_id)
        self.assertEqual(f.client.observed_exit.call_count, 1)
        self.assertEqual(f.records.read(f.runtime_id)["stop_state"], "unknown")

    def test_explicit_bound_to_idle_continuation_retains_both_mac_intents(self):
        f = self.f
        self.register()
        f.client.receipt = Mock(return_value=self.observation())
        f.client.observed_exit = Mock(side_effect=host.HostRefused())
        with self.assertRaises(host.HostRefused):
            host.report_observed_exit(
                f.client, f.records, f.runtime_id, f.proof, f.observer
            )
        original = f.records.read(f.runtime_id)["stop_intent"]
        f.client.receipt.return_value = self.observation(1, False)
        f.client.attempt_receipt = Mock(return_value=self.history())
        f.client.observed_unbound_exit = Mock(
            side_effect=lambda runtime_id, body, secret: self.ack(body, active=False)
        )
        host.continue_observed_exit(
            f.client, f.records, f.runtime_id, f.proof, f.observer
        )
        record = f.records.read(f.runtime_id)
        self.assertEqual(record["stop_intent"], original)
        self.assertEqual([row["cursor"] for row in record["report_cursors"]], [1, 2])
        self.assertEqual(sequence._load(f.records, f.runtime_id, 1)["state"], "unknown")
        self.assertEqual(f.client.observed_exit.call_count, 1)
        self.assertEqual(f.client.observed_unbound_exit.call_count, 1)

    def test_same_cursor_terminal_change_does_not_authorize_continuation(self):
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
        self.assertEqual(f.client.observed_exit.call_count, 1)

    def test_stale_physical_proof_refuses_before_intent_or_post(self):
        f = self.f
        self.register()
        f.client.receipt = Mock(return_value=self.observation())
        f.client.observed_exit = Mock()
        f.observer.failed_confirmation = True
        with self.assertRaises(ValueError):
            host.report_observed_exit(
                f.client, f.records, f.runtime_id, f.proof, f.observer
            )
        self.assertEqual(f.records.read(f.runtime_id)["report_cursors"], [])
        f.client.observed_exit.assert_not_called()

    def test_oversized_index_is_refused_without_truncation_or_network(self):
        f = self.f
        self.register()
        record = f.records.read(f.runtime_id)
        record["report_cursors"] = [{}] * 6
        f.records.write(record)
        f.client.receipt = Mock()
        with self.assertRaises(host.HostRefused):
            host.reconcile_exit(f.client, f.records, f.runtime_id)
        f.client.receipt.assert_not_called()

    def test_v1_unknown_unbound_may_only_explicitly_continue_to_bound_once(self):
        f = self.f
        f.register()
        f.client.receipt = Mock(return_value=f.lookup(binding=False))
        f.client.observed_unbound_exit = Mock(side_effect=host.HostRefused())
        with self.assertRaises(host.HostRefused):
            host.report_observed_exit(
                f.client, f.records, f.runtime_id, f.proof, f.observer
            )
        original = f.records.read(f.runtime_id)["stop_intent"]
        f.client.receipt.return_value = f.lookup()
        f.client.observed_exit = Mock(side_effect=host.HostRefused())
        with self.assertRaises(host.HostRefused):
            host.continue_observed_exit(
                f.client, f.records, f.runtime_id, f.proof, f.observer
            )
        with self.assertRaises(host.HostRefused):
            host.continue_observed_exit(
                f.client, f.records, f.runtime_id, f.proof, f.observer
            )
        record = f.records.read(f.runtime_id)
        self.assertEqual(record["stop_intent"], original)
        self.assertEqual(len(record["report_cursors"]), 2)
        self.assertEqual(f.client.observed_unbound_exit.call_count, 1)
        self.assertEqual(f.client.observed_exit.call_count, 1)

    def test_bound_to_later_active_requires_released_exact_old_history(self):
        f = self.f
        self.register()
        f.client.receipt = Mock(return_value=self.observation())
        f.client.observed_exit = Mock(side_effect=host.HostRefused())
        with self.assertRaises(host.HostRefused):
            host.report_observed_exit(
                f.client, f.records, f.runtime_id, f.proof, f.observer
            )
        old_history = self.history()
        f.binding = {
            **f.binding,
            "job_id": "job-2",
            "attempt_id": "22222222-2222-4222-8222-222222222222",
        }
        f.client.receipt.return_value = self.observation(2)
        f.client.attempt_receipt = Mock(return_value=old_history)
        f.client.observed_exit.side_effect = lambda runtime_id, body, secret: self.ack(
            body, last=2
        )
        host.continue_observed_exit(
            f.client, f.records, f.runtime_id, f.proof, f.observer
        )
        record = f.records.read(f.runtime_id)
        self.assertEqual(
            [entry["cursor"] for entry in record["report_cursors"]], [1, 3]
        )
        self.assertEqual(record["stop_intent"]["job_id"], "job-1")
        self.assertEqual(f.client.observed_exit.call_count, 2)

    def test_recurring_idle_is_distinguished_by_last_sequence(self):
        f = self.f
        self.register()
        f.client.receipt = Mock(return_value=self.observation(1, False))
        f.client.observed_unbound_exit = Mock(side_effect=host.HostRefused())
        with self.assertRaises(host.HostRefused):
            host.report_observed_exit(
                f.client, f.records, f.runtime_id, f.proof, f.observer
            )
        original = f.records.read(f.runtime_id)["stop_intent"]
        f.client.receipt.return_value = self.observation(2, False)
        f.client.attempt_receipt = Mock(return_value=self.history(2))
        f.client.observed_unbound_exit.side_effect = lambda runtime_id, body, secret: (
            self.ack(body, active=False, last=2)
        )
        host.continue_observed_exit(
            f.client, f.records, f.runtime_id, f.proof, f.observer
        )
        record = f.records.read(f.runtime_id)
        self.assertEqual(original["last_sequence"], 1)
        self.assertEqual(record["stop_intent"], original)
        self.assertEqual(
            [entry["cursor"] for entry in record["report_cursors"]], [2, 4]
        )
        self.assertEqual(f.client.observed_unbound_exit.call_count, 2)

    def test_job_completion_does_not_become_physical_retirement(self):
        f = self.f
        self.register()
        completed = self.history()["receipt"]
        f.client.receipt = Mock(return_value=self.observation(receipt=completed))
        host.reconcile_exit(f.client, f.records, f.runtime_id)
        self.assertIsNone(f.records.read(f.runtime_id)["receipt"])
        self.assertEqual(f.records.read(f.runtime_id)["stop_state"], "none")

    def test_existing_completed_receipt_is_preserved_inside_new_retirement(self):
        f = self.f
        self.register()
        completed = self.history()["receipt"]
        f.client.receipt = Mock(return_value=self.observation(receipt=completed))

        def retire(runtime_id, body, secret):
            reply = self.ack(body)
            value = reply["receipt"]
            value["attempt_receipt"] = completed
            value["receipt_sha256"] = host.digest(
                {key: item for key, item in value.items() if key != "receipt_sha256"}
            )
            return reply

        f.client.observed_exit = Mock(side_effect=retire)
        reply = host.report_observed_exit(
            f.client, f.records, f.runtime_id, f.proof, f.observer
        )
        self.assertEqual(reply["receipt"]["attempt_receipt"], completed)
        self.assertTrue(reply["receipt"]["retired"])

    def test_sidecar_tamper_holds_before_any_network(self):
        f = self.f
        self.register()
        f.client.receipt = Mock(return_value=self.observation())
        f.client.observed_exit = Mock(side_effect=host.HostRefused())
        with self.assertRaises(host.HostRefused):
            host.report_observed_exit(
                f.client, f.records, f.runtime_id, f.proof, f.observer
            )
        path = sequence._path(f.records, f.runtime_id, 1)
        path.write_text(path.read_text().replace("job-1", "job-2"), encoding="utf-8")
        f.client.receipt.reset_mock()
        with self.assertRaises(host.HostRefused):
            host.reconcile_exit(f.client, f.records, f.runtime_id)
        f.client.receipt.assert_not_called()

    def test_all_65_cursor_records_fit_without_truncation(self):
        f = self.f
        self.register(32)
        record = f.records.read(f.runtime_id)
        for cursor in range(65):
            body = {
                "runtime_sha256": host.digest(asdict(f.identity)),
                "finished_at": f.proof.finished_at,
                "exit_code": f.proof.exit_code,
                "observation_sha256": "ab" * 32,
            }
            body.update(
                {**f.binding, "runtime_sequence": (cursor + 1) // 2}
                if cursor % 2
                else {"last_sequence": cursor // 2}
            )
            value = {
                "runtime_id": f.runtime_id,
                "cursor": cursor,
                "intent": body,
                "state": "unknown",
                "receipt": None,
            }
            sequence._store(f.records, value, create=True)
            record["report_cursors"].append(
                {"cursor": cursor, "intent_sha256": host.digest(body)}
            )
            if cursor == 0:
                record["stop_intent"] = body
        f.records.write(record)
        self.assertEqual(
            len(sequence._reports(f.records, f.records.read(f.runtime_id))), 65
        )
        self.assertLess(f.records._path(f.runtime_id).stat().st_size, 65536)

    def test_retirement_exact_shape_rejects_maximum_and_boolean_sequence(self):
        f = self.f
        self.register()
        body = {"runtime_sequence": 1}
        value = self.ack(body)["receipt"]
        for change in (
            {"max_attempts": 2},
            {"runtime_sequence": True},
            {"last_sequence": 3},
        ):
            candidate = {**value, **change}
            candidate["receipt_sha256"] = host.digest(
                {
                    key: item
                    for key, item in candidate.items()
                    if key != "receipt_sha256"
                }
            )
            with self.subTest(change=change), self.assertRaises(host.HostRefused):
                sequence.retirement(f.records.read(f.runtime_id), candidate)

    def test_release_digest_covers_full_completion_not_nested_result_binding_hash(self):
        f = self.f
        self.register()
        history = self.history()
        record = f.records.read(f.runtime_id)
        f.client.attempt_receipt = Mock(return_value=history)
        self.assertNotEqual(
            history["receipt"]["receipt_sha256"], host.digest(history["receipt"])
        )
        self.assertEqual(
            sequence._history(f.client, record, 1, f.records.secret(f.runtime_id)),
            history,
        )
        history["release"]["terminal_receipt_sha256"] = history["receipt"][
            "receipt_sha256"
        ]
        history["release"]["receipt_sha256"] = host.digest(
            {
                key: value
                for key, value in history["release"].items()
                if key != "receipt_sha256"
            }
        )
        with self.assertRaises(host.HostRefused):
            sequence._history(f.client, record, 1, f.records.secret(f.runtime_id))

    def test_boolean_sequence_and_nested_fence_cannot_equal_integer_history(self):
        f = self.f
        self.register()
        f.binding = {**f.binding, "fence": 1}
        record = f.records.read(f.runtime_id)
        for change in ("echo_sequence", "release_sequence", "nested_fence"):
            history = self.history()
            if change == "echo_sequence":
                history["runtime_sequence"] = True
            elif change == "release_sequence":
                history["release"]["runtime_sequence"] = True
            else:
                history["release"]["binding"] = {**history["binding"], "fence": True}
            history["release"]["receipt_sha256"] = host.digest(
                {
                    key: value
                    for key, value in history["release"].items()
                    if key != "receipt_sha256"
                }
            )
            f.client.attempt_receipt = Mock(return_value=history)
            with self.subTest(change=change), self.assertRaises(host.HostRefused):
                sequence._history(f.client, record, 1, f.records.secret(f.runtime_id))
