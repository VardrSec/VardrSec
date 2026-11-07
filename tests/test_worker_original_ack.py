"""Original-call ACK scopes with actual private stores and synthetic custody."""

import builtins
import copy
import pickle
import unittest
from unittest.mock import patch

import test_worker_registration_fence as fixtures
import worker_host as host
import worker_lifecycle_intent as intent


MODES = ("legacy-v1", "finite-v2", "persistent-v3")


class OriginalAcknowledgementTests(unittest.TestCase):
    prepared = fixtures.RegistrationFenceTests.prepared
    mint = fixtures.RegistrationFenceTests.mint
    register = fixtures.RegistrationFenceTests.register

    def test_success_commits_only_after_original_ack_final_store_and_normal_exit(self):
        for mode in MODES:
            with self.subTest(mode=mode), self.prepared(mode) as state:
                f, store, operation, current, cap, options, _ = state
                write = f.records.write
                stages = []

                def save(record, *, create=False):
                    self.assertIsNone(cap._acknowledged)
                    if not create:
                        self.assertTrue(cap._attempt._entered)
                        self.assertFalse(cap._attempt._closed)
                        stages.append(record["registration_state"])
                    write(record, create=create)

                with patch.object(f.records, "write", side_effect=save):
                    admission = self.register(f, operation, cap, options)
                self.assertEqual(stages, ["acknowledged"])
                self.assertEqual(
                    cap._acknowledged,
                    (host.digest(f.records.read(f.runtime_id)), host.digest(admission)),
                )
                self.assertTrue(cap._attempt._closed)
                self.assertEqual(f.session.register.call_count, 1)
                observed = store.read(current["operation_id"], operation=operation)
                self.assertIsNone(observed["observations"]["host_record_sha256"])
                self.assertIsNone(observed["observations"]["admission_sha256"])
                self.assertFalse(observed["effects"]["publication_may_have_happened"])

    def test_missing_invalid_and_lost_ack_never_mark_or_remint(self):
        for mode in MODES:
            for outcome in ("missing", "invalid", "lost"):
                with (
                    self.subTest(mode=mode, outcome=outcome),
                    self.prepared(mode) as state,
                ):
                    f, store, operation, current, cap, options, _ = state
                    if outcome == "lost":
                        f.session.register.side_effect = host.HostRefused()
                    else:
                        f.session.register.side_effect = None
                        f.session.register.return_value = (
                            None if outcome == "missing" else {}
                        )
                    with self.assertRaises(host.HostRefused):
                        self.register(f, operation, cap, options)
                    self.assertIsNone(cap._acknowledged)
                    self.assertTrue(cap._attempt._closed)
                    self.assertEqual(f.session.register.call_count, 1)
                    observed = store.read(current["operation_id"], operation=operation)
                    self.assertTrue(observed["effects"]["registration_may_have_sent"])
                    with self.assertRaises(intent.IntentRefused):
                        self.mint(f, store, operation, observed)

    def test_final_store_failure_or_interruption_has_no_marker_even_if_committed(self):
        for mode in MODES:
            for committed in (False, True):
                for interrupted in (False, True):
                    with (
                        self.subTest(
                            mode=mode, committed=committed, interrupted=interrupted
                        ),
                        self.prepared(mode) as state,
                    ):
                        f, _, operation, _, cap, options, _ = state
                        write = f.records.write
                        failure = KeyboardInterrupt() if interrupted else OSError()

                        def save(record, *, create=False):
                            if record["registration_state"] == "acknowledged":
                                if committed:
                                    write(record, create=create)
                                raise failure
                            write(record, create=create)

                        expected = (
                            KeyboardInterrupt if interrupted else host.HostRefused
                        )
                        with patch.object(f.records, "write", side_effect=save):
                            with self.assertRaises(expected) as caught:
                                self.register(f, operation, cap, options)
                        if interrupted:
                            self.assertIs(caught.exception, failure)
                        self.assertIsNone(cap._acknowledged)
                        self.assertTrue(cap._attempt._closed)
                        self.assertEqual(f.session.register.call_count, 1)

    def test_post_ack_binding_drift_refuses_before_staging(self):
        for change in ("client", "observer", "intent", "record"):
            with self.subTest(change=change), self.prepared() as state:
                f, store, operation, current, cap, options, _ = state
                write = f.records.write

                def save(record, *, create=False):
                    write(record, create=create)
                    if record["registration_state"] != "acknowledged":
                        return
                    if change == "client":
                        f.client.ca_sha256 = "0" * 64
                    elif change == "observer":
                        f.observer.context = "changed-context"
                    elif change == "record":
                        other = copy.deepcopy(record)
                        other["revocation_state"] = "acknowledged"
                        write(other)
                    else:
                        previous = store.read(
                            current["operation_id"], operation=operation
                        )
                        following = copy.deepcopy(previous)
                        following.update(
                            revision=previous["revision"] + 1,
                            previous_sha256=host.digest(previous),
                        )
                        store.advance(
                            following,
                            expected_revision=previous["revision"],
                            expected_sha256=host.digest(previous),
                            operation=operation,
                        )

                with patch.object(f.records, "write", side_effect=save):
                    with self.assertRaises(host.HostRefused):
                        self.register(f, operation, cap, options)
                self.assertIsNone(cap._acknowledged)
                self.assertTrue(cap._attempt._closed)

    def test_authenticated_readback_failure_keeps_original_send_held(self):
        with self.prepared() as state:
            f, _, operation, _, cap, options, _ = state
            original = intent.stage_original_ack

            def stage(attempt, **kwargs):
                with patch.object(f.records, "read", side_effect=OSError):
                    original(attempt, **kwargs)

            with patch.object(intent, "stage_original_ack", side_effect=stage):
                with self.assertRaises(host.HostRefused):
                    self.register(f, operation, cap, options)
            self.assertIsNone(cap._acknowledged)
            self.assertTrue(cap._attempt._closed)
            self.assertEqual(f.session.register.call_count, 1)

    def test_exception_after_staging_aborts_without_io_or_exception_replacement(self):
        for mode in MODES:
            with self.subTest(mode=mode), self.prepared(mode) as state:
                f, _, operation, _, cap, options, _ = state
                original = intent.stage_original_ack
                failure = KeyboardInterrupt()

                def stage(attempt, **kwargs):
                    original(attempt, **kwargs)
                    self.assertIsNotNone(attempt._staged)
                    self.assertIsNone(cap._acknowledged)
                    raise failure

                with patch.object(intent, "stage_original_ack", side_effect=stage):
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        self.register(f, operation, cap, options)
                self.assertIs(caught.exception, failure)
                self.assertIsNone(cap._acknowledged)
                self.assertIsNone(cap._attempt._staged)
                with patch.object(
                    f.records, "read", side_effect=AssertionError
                ) as read:
                    self.assertFalse(
                        cap._attempt.__exit__(KeyboardInterrupt, failure, None)
                    )
                read.assert_not_called()

    def test_closed_scope_rejects_restaging_before_storage_access(self):
        for success in (False, True):
            with self.subTest(success=success), self.prepared() as state:
                f, _, operation, _, cap, options, _ = state
                if success:
                    self.register(f, operation, cap, options)
                else:
                    f.session.register.side_effect = host.HostRefused()
                    with self.assertRaises(host.HostRefused):
                        self.register(f, operation, cap, options)
                marker = cap._acknowledged
                with patch.object(
                    f.records, "read", side_effect=AssertionError
                ) as read:
                    with self.assertRaises(intent.IntentRefused):
                        intent.stage_original_ack(cap._attempt, record={}, admission={})
                    with self.assertRaises(intent.IntentRefused):
                        cap._attempt.__enter__()
                read.assert_not_called()
                self.assertEqual(cap._acknowledged, marker)

    def test_wrong_thread_after_ack_cannot_stage(self):
        with self.prepared() as state:
            f, _, operation, _, cap, options, _ = state
            original = intent.stage_original_ack

            def stage(attempt, **kwargs):
                with patch.object(
                    host.threading, "get_ident", return_value=operation._thread + 1
                ):
                    original(attempt, **kwargs)

            with patch.object(intent, "stage_original_ack", side_effect=stage):
                with self.assertRaises(host.HostRefused):
                    self.register(f, operation, cap, options)
            self.assertIsNone(cap._acknowledged)
            self.assertTrue(cap._attempt._closed)

    def test_scope_cannot_be_copied_serialized_or_reset(self):
        with self.prepared() as state:
            f, _, operation, _, cap, options, _ = state
            self.register(f, operation, cap, options)
            for action in (
                lambda: copy.copy(cap._attempt),
                lambda: copy.deepcopy(cap._attempt),
                lambda: pickle.dumps(cap._attempt),
                lambda: setattr(cap._attempt, "_closed", False),
            ):
                with self.assertRaises(intent.IntentRefused):
                    action()
            with self.assertRaises(intent.IntentRefused):
                intent.stage_original_ack(object(), record={}, admission={})

    def test_default_none_has_no_lifecycle_import_or_stage_call(self):
        for mode in MODES:
            with self.subTest(mode=mode), self.prepared(mode) as state:
                f, _, operation, _, _, options, _ = state
                original = builtins.__import__
                attempted = []

                def imported(name, *args, **kwargs):
                    if name == "worker_lifecycle_intent":
                        attempted.append(name)
                    return original(name, *args, **kwargs)

                with (
                    patch.object(builtins, "__import__", side_effect=imported),
                    patch.object(intent, "stage_original_ack") as stage,
                ):
                    host.register_runtime(
                        f.client, f.records, f.session, **options, operation=operation
                    )
                self.assertEqual(attempted, [])
                stage.assert_not_called()
                self.assertEqual(f.session.register.call_count, 1)


if __name__ == "__main__":
    unittest.main()
