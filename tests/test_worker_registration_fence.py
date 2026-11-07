"""Registration fences in the existing engines; private files/synthetic custody only."""

from contextlib import contextmanager
import builtins
import copy
from dataclasses import asdict, replace
import json
import pickle
import unittest
from unittest.mock import Mock, patch

import test_worker_host as fixtures
import test_worker_lifecycle_intent as intent_fixtures
import worker_host as host
import worker_host_persistent as persistent
import worker_lifecycle_intent as intent


class RegistrationFenceTests(unittest.TestCase):
    @contextmanager
    def prepared(self, mode="persistent-v3", *, generic_none=False, bounded=False):
        f = fixtures.HostTests()
        f.setUp()
        f.observer.protocol = mode
        f.observer.max_attempts = 2 if mode == "finite-v2" else None
        keys, key_calls = {}, []

        def read_intent(selected, *, records, operation):
            self.assertIs(records, f.records)
            records._intent_access(operation)
            key_calls.append(("read_intent", selected))
            return keys.get(selected)

        def create_intent(selected, value, *, records, operation):
            self.assertIs(records, f.records)
            records._intent_access(operation)
            key_calls.append(("create_intent", selected))
            self.assertNotIn(selected, keys)
            keys[selected] = value

        f.backend.read_intent, f.backend.create_intent = read_intent, create_intent

        @contextmanager
        def lock(_installation):
            yield

        original_reply = f.session.register
        limits = {
            "max_attempts": "2" if bounded else None,
            "idle_timeout_seconds": 60 if bounded else None,
        }
        options = {
            "issuer_origin": f.binding["origin"],
            "enrollment_id": "enrolled-1",
            "runner_id": f.runner_id,
            "identity": f.identity,
            "observer": f.observer,
            "runtime_id": f.runtime_id,
            "protocol": None if generic_none else mode,
        }
        if mode == "persistent-v3":
            options["limits"] = limits
        else:
            options["expires_in_seconds"] = 300
            if mode == "finite-v2":
                options["max_attempts"] = 2

        def response(selected, body):
            if mode == "persistent-v3":
                return persistent.expected_admission(
                    {"runtime_id": selected, "registration": body}
                )
            reply = original_reply(selected, body)
            if mode == "finite-v2":
                reply.update(
                    schema="vardr.worker-admission/2", max_attempts=body["max_attempts"]
                )
            return reply

        f.session.register = Mock(side_effect=response)
        try:
            with (
                patch.object(host.updater, "installation_lock", lock),
                patch.object(
                    intent, "_publish_new", intent_fixtures.exclusive_test_publish
                ),
                patch.object(
                    host,
                    "_publish",
                    side_effect=lambda source, target: source.replace(target),
                ),
            ):
                with f.records.operation() as operation:
                    store = intent.IntentStore(f.records)
                    row = intent_fixtures.payload(f.records)
                    row["future_runtime_id"] = f.runtime_id
                    row["registration_policy"].update(
                        origin=f.binding["origin"],
                        enrollment_id="enrolled-1",
                        runner_id=f.runner_id,
                        protocol=mode,
                        expires_in_seconds=None if mode == "persistent-v3" else 300,
                        limits=limits
                        if mode == "persistent-v3"
                        else {
                            "max_attempts": 2 if mode == "finite-v2" else None,
                            "idle_timeout_seconds": None,
                        },
                        reporting_authority=dict(persistent.REPORTING_AUTHORITY)
                        if mode == "persistent-v3"
                        else None,
                    )
                    row["binding"].update(
                        context=f.observer.context,
                        daemon_id=f.identity.daemon_id,
                        project=f.identity.project,
                    )
                    row["source"]["runner_image"] = f.identity.image_id
                    row["resources"].update(
                        trust_source=f.layout.trust_source,
                        public_directory=f.layout.admission_source,
                        readiness_volume=f.layout.readiness_volume,
                    )
                    row["resources"]["runner_state"]["name"] = f.layout.state_volume
                    current = store.create(row, operation=operation)
                    for running in (False, True):
                        following = copy.deepcopy(current)
                        following.update(
                            revision=current["revision"] + 1,
                            previous_sha256=host.digest(current),
                        )
                        following["effects"].update(
                            public_directory_may_have_been_created=True,
                            readiness_may_have_been_created=True,
                            container_create_may_have_sent=True,
                        )
                        following["observations"]["created"] = {
                            "container_id": f.identity.container_id,
                            "image_id": f.identity.image_id,
                            "project": f.identity.project,
                            "daemon_id": f.identity.daemon_id,
                            "ordinal": following["resources"]["expected_ordinal"],
                            "readiness_volume": f.layout.readiness_volume,
                        }
                        if running:
                            following["effects"]["start_may_have_sent"] = True
                            following["observations"]["running"] = asdict(f.identity)
                        current = store.advance(
                            following,
                            expected_revision=current["revision"],
                            expected_sha256=host.digest(current),
                            operation=operation,
                        )
                    cap = store.registration_capability(
                        current["operation_id"],
                        f.identity,
                        f.client,
                        f.observer,
                        expected_revision=current["revision"],
                        expected_sha256=host.digest(current),
                        operation=operation,
                    )
                    yield f, store, operation, current, cap, options, key_calls
        finally:
            f.tearDown()
            f.doCleanups()

    def mint(self, f, store, operation, current):
        return store.registration_capability(
            current["operation_id"],
            f.identity,
            f.client,
            f.observer,
            expected_revision=current["revision"],
            expected_sha256=host.digest(current),
            operation=operation,
        )

    def register(self, f, operation, cap, options):
        return host.register_runtime(
            f.client,
            f.records,
            f.session,
            **options,
            operation=operation,
            registration_capability=cap,
        )

    def test_each_existing_engine_reads_back_sticky_marker_before_one_actual_send(self):
        for mode, generic_none in (
            ("legacy-v1", False),
            ("legacy-v1", True),
            ("finite-v2", False),
            ("finite-v2", True),
            ("persistent-v3", False),
        ):
            with (
                self.subTest(mode=mode, generic_none=generic_none),
                self.prepared(mode, generic_none=generic_none) as state,
            ):
                f, store, operation, current, cap, options, _ = state
                respond = f.session.register.side_effect

                def send(selected, body):
                    observed = store.read(current["operation_id"], operation=operation)
                    self.assertTrue(observed["effects"]["registration_may_have_sent"])
                    self.assertEqual(
                        observed["observations"]["registration_sha256"],
                        host.digest(body),
                    )
                    self.assertIsNone(observed["observations"]["host_record_sha256"])
                    self.assertIsNone(observed["observations"]["admission_sha256"])
                    self.assertEqual(cap._fenced_digest, host.digest(observed))
                    self.assertTrue(cap._used)
                    self.assertEqual(
                        f.records.read(selected)["registration_state"], "prepared"
                    )
                    return respond(selected, body)

                f.session.register.side_effect = send
                self.register(f, operation, cap, options)
                self.assertEqual(f.session.register.call_count, 1)
                self.assertEqual(
                    f.records.read(f.runtime_id)["registration_state"], "acknowledged"
                )

    def test_persistent_optional_limits_stay_explicit_and_have_no_lifetime(self):
        with self.prepared(bounded=True) as state:
            f, store, operation, current, cap, options, _ = state
            self.register(f, operation, cap, options)
            selected = f.records.read(f.runtime_id)["registration"]
            self.assertEqual(
                selected["limits"], {"max_attempts": "2", "idle_timeout_seconds": 60}
            )
            self.assertNotIn("expires_in_seconds", selected)
            self.assertTrue(
                store.read(current["operation_id"], operation=operation)["effects"][
                    "registration_may_have_sent"
                ]
            )

    def test_default_none_calls_no_fence_or_capability_module_import(self):
        for mode in ("legacy-v1", "finite-v2", "persistent-v3"):
            with self.subTest(mode=mode), self.prepared(mode) as state:
                f, _, operation, _, _, options, _ = state
                original_import = builtins.__import__
                attempted = []

                def imported(name, *args, **kwargs):
                    if name == "worker_lifecycle_intent":
                        attempted.append(name)
                    return original_import(name, *args, **kwargs)

                with (
                    patch.object(intent, "registration_fence") as fence,
                    patch.object(builtins, "__import__", side_effect=imported),
                ):
                    host.register_runtime(
                        f.client, f.records, f.session, **options, operation=operation
                    )
                fence.assert_not_called()
                self.assertEqual(attempted, [])
                self.assertEqual(f.session.register.call_count, 1)

    def test_recorded_or_caller_constructed_identity_does_not_bypass_fresh_capture(
        self,
    ):
        with self.prepared() as state:
            f, store, operation, current, cap, options, _ = state
            options["identity"] = replace(f.identity)
            with patch.object(
                f.observer, "capture_running", side_effect=host.HostRefused()
            ):
                with self.assertRaises(host.HostRefused):
                    self.register(f, operation, cap, options)
            f.session.register.assert_not_called()
            self.assertFalse(f.records._path(f.runtime_id).exists())
            self.assertFalse(
                store.read(current["operation_id"], operation=operation)["effects"][
                    "registration_may_have_sent"
                ]
            )

    def test_capability_cannot_be_copied_serialized_or_reset(self):
        with self.prepared() as state:
            _, _, _, _, cap, _, _ = state
            for action in (
                lambda: copy.copy(cap),
                lambda: copy.deepcopy(cap),
                lambda: pickle.dumps(cap),
                lambda: setattr(cap, "_used", False),
            ):
                with self.assertRaises(intent.IntentRefused):
                    action()
            for action in (lambda: json.dumps(cap), lambda: asdict(cap)):
                with self.assertRaises(TypeError):
                    action()

    def test_malformed_and_wrong_bound_attempts_burn_before_storage_io(self):
        with self.prepared() as state:
            f, store, operation, current, _, _, calls = state
            for change in (
                "missing",
                "records",
                "operation",
                "client",
                "observer",
                "thread",
            ):
                cap = self.mint(f, store, operation, current)
                before = list(calls)
                arguments = {
                    "records": f.records,
                    "operation": operation,
                    "client": f.client,
                    "observer": f.observer,
                    "identity": f.identity,
                    "runtime_id": f.runtime_id,
                    "protocol": "persistent-v3",
                    "selected": None,
                    "record": None,
                }
                if change == "missing":
                    arguments = {}
                elif change != "thread":
                    arguments[change] = object()
                with self.subTest(change=change):
                    if change == "thread":
                        with patch.object(
                            host.threading,
                            "get_ident",
                            return_value=operation._thread + 1,
                        ):
                            with self.assertRaises(intent.IntentRefused):
                                intent.registration_fence(cap, **arguments)
                    else:
                        with self.assertRaises(intent.IntentRefused):
                            intent.registration_fence(cap, **arguments)
                    self.assertEqual(calls, before)
                    with self.assertRaises(intent.IntentRefused):
                        intent.registration_fence(cap, **arguments)
                    self.assertEqual(calls, before)
                    self.assertIsNone(cap._fenced_digest)

    def test_valid_but_wrong_actual_policy_prevents_send_and_remint(self):
        for field, value in (
            ("issuer_origin", "https://different.example"),
            ("enrollment_id", "different-enrollment"),
            ("runner_id", "55555555-5555-4555-8555-555555555555"),
        ):
            with self.subTest(field=field), self.prepared() as state:
                f, store, operation, current, cap, options, _ = state
                options[field] = value
                with self.assertRaises(host.HostRefused):
                    self.register(f, operation, cap, options)
                f.session.register.assert_not_called()
                observed = store.read(current["operation_id"], operation=operation)
                self.assertFalse(observed["effects"]["registration_may_have_sent"])
                self.assertIsNone(observed["observations"]["host_record_sha256"])
                with self.assertRaises(intent.IntentRefused):
                    self.mint(f, store, operation, current)

    def test_exact_client_and_observer_pins_are_rechecked_before_fence_io(self):
        with self.prepared() as state:
            f, store, operation, current, _, _, calls = state
            changes = (
                (f.client, "base_url", "https://different.example"),
                (f.observer, "context", "different-context"),
                (
                    f.observer,
                    "layout",
                    replace(f.layout, state_volume="different-state"),
                ),
                (f.observer, "protocol", "finite-v2"),
                (f.observer, "max_attempts", 2),
            )
            for selected, name, value in changes:
                cap = self.mint(f, store, operation, current)
                before = list(calls)
                arguments = {
                    "records": f.records,
                    "operation": operation,
                    "client": f.client,
                    "observer": f.observer,
                    "identity": f.identity,
                    "runtime_id": f.runtime_id,
                    "protocol": "persistent-v3",
                    "selected": None,
                    "record": None,
                }
                with self.subTest(name=name), patch.object(selected, name, value):
                    with self.assertRaises(intent.IntentRefused):
                        intent.registration_fence(cap, **arguments)
                self.assertEqual(calls, before)
                with self.assertRaises(intent.IntentRefused):
                    intent.registration_fence(cap, **arguments)
                self.assertEqual(calls, before)

    def test_factory_checks_explicit_revision_digest_identity_and_active_state(self):
        with self.prepared() as state:
            f, store, operation, current, _, _, _ = state
            options = {
                "expected_revision": current["revision"],
                "expected_sha256": host.digest(current),
                "operation": operation,
            }
            for change in (
                {"expected_revision": True},
                {"expected_revision": 1},
                {"expected_sha256": "0" * 64},
            ):
                with (
                    self.subTest(change=change),
                    self.assertRaises(intent.IntentRefused),
                ):
                    store.registration_capability(
                        current["operation_id"],
                        f.identity,
                        f.client,
                        f.observer,
                        **dict(options, **change),
                    )
            with self.assertRaises(intent.IntentRefused):
                store.registration_capability(
                    current["operation_id"],
                    replace(f.identity, owner_nonce="f" * 64),
                    f.client,
                    f.observer,
                    **options,
                )
            following = copy.deepcopy(current)
            following.update(
                revision=current["revision"] + 1,
                previous_sha256=host.digest(current),
                disposition="held",
            )
            held = store.advance(
                following,
                expected_revision=current["revision"],
                expected_sha256=host.digest(current),
                operation=operation,
            )
            with self.assertRaises(intent.IntentRefused):
                self.mint(f, store, operation, held)
            self.assertFalse(f.records._path(f.runtime_id).exists())
            self.assertEqual(f.backend.values, {})

    def test_prepared_record_cannot_mint_replacement_even_before_first_send(self):
        with self.prepared() as state:
            f, store, operation, current, cap, options, _ = state
            original = f.records.write

            def write(record, *, create=False):
                original(record, create=create)
                if create:
                    self.assertEqual(
                        f.records.read(f.runtime_id)["registration_state"], "prepared"
                    )
                    with self.assertRaises(intent.IntentRefused):
                        self.mint(f, store, operation, current)

            with patch.object(f.records, "write", side_effect=write):
                self.register(f, operation, cap, options)
            self.assertEqual(f.session.register.call_count, 1)

    def test_prepared_record_mac_or_actual_registration_mismatch_prevents_send(self):
        for malformed in (False, True):
            with self.subTest(malformed=malformed), self.prepared() as state:
                f, _, operation, _, cap, options, _ = state
                original = f.records.write

                def write(record, *, create=False):
                    if create and not malformed:
                        record = copy.deepcopy(record)
                        record["registration"]["origin"] = "https://different.example"
                    original(record, create=create)
                    if create and malformed:
                        f.records._path(f.runtime_id).write_bytes(
                            b"malformed-private-record"
                        )

                with patch.object(f.records, "write", side_effect=write):
                    with self.assertRaises(host.HostRefused):
                        self.register(f, operation, cap, options)
                f.session.register.assert_not_called()
                self.assertIsNone(cap._fenced_digest)

    def test_cas_and_committed_readback_failure_never_send_or_enable_remint(self):
        for after_commit in (False, True):
            with self.subTest(after_commit=after_commit), self.prepared() as state:
                f, store, operation, current, cap, options, _ = state
                original = store.advance

                def advance(*args, **kwargs):
                    if after_commit:
                        original(*args, **kwargs)
                    raise OSError("fixed-test-storage-failure")

                with patch.object(store, "advance", side_effect=advance):
                    with self.assertRaises(host.HostRefused):
                        self.register(f, operation, cap, options)
                f.session.register.assert_not_called()
                observed = store.read(current["operation_id"], operation=operation)
                self.assertEqual(
                    observed["effects"]["registration_may_have_sent"], after_commit
                )
                self.assertIsNone(observed["observations"]["host_record_sha256"])
                self.assertIsNone(cap._fenced_digest)
                with self.assertRaises(intent.IntentRefused):
                    self.mint(f, store, operation, observed)

    def test_intent_revision_drift_is_not_accepted_before_send(self):
        with self.prepared() as state:
            f, store, operation, current, cap, options, _ = state
            following = copy.deepcopy(current)
            following.update(
                revision=current["revision"] + 1, previous_sha256=host.digest(current)
            )
            store.advance(
                following,
                expected_revision=current["revision"],
                expected_sha256=host.digest(current),
                operation=operation,
            )
            with self.assertRaises(host.HostRefused):
                self.register(f, operation, cap, options)
            f.session.register.assert_not_called()
            self.assertIsNone(cap._fenced_digest)

    def test_interrupt_at_fence_leaves_prepared_record_and_spent_capability(self):
        with self.prepared() as state:
            f, store, operation, current, cap, options, _ = state
            with patch.object(store, "advance", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    self.register(f, operation, cap, options)
            f.session.register.assert_not_called()
            self.assertTrue(cap._used)
            self.assertIsNone(cap._fenced_digest)
            self.assertEqual(
                f.records.read(f.runtime_id)["registration_state"], "prepared"
            )
            with self.assertRaises(intent.IntentRefused):
                self.mint(f, store, operation, current)

    def test_lost_ack_keeps_true_marker_but_never_replays_or_remints(self):
        with self.prepared() as state:
            f, store, operation, current, cap, options, _ = state
            f.session.register.side_effect = host.HostRefused()
            with patch.object(host, "replay_registration") as replay:
                with self.assertRaises(host.HostRefused):
                    self.register(f, operation, cap, options)
            replay.assert_not_called()
            self.assertEqual(f.session.register.call_count, 1)
            self.assertEqual(
                f.records.read(f.runtime_id)["registration_state"], "unknown"
            )
            observed = store.read(current["operation_id"], operation=operation)
            self.assertTrue(observed["effects"]["registration_may_have_sent"])
            self.assertIsNotNone(cap._fenced_digest)
            with self.assertRaises(intent.IntentRefused):
                self.mint(f, store, operation, observed)

    def test_acknowledged_record_does_not_mint_capability_or_ack_observation(self):
        with self.prepared() as state:
            f, store, operation, current, cap, options, _ = state
            self.register(f, operation, cap, options)
            observed = store.read(current["operation_id"], operation=operation)
            self.assertEqual(
                f.records.read(f.runtime_id)["registration_state"], "acknowledged"
            )
            self.assertIsNone(observed["observations"]["host_record_sha256"])
            self.assertIsNone(observed["observations"]["admission_sha256"])
            with self.assertRaises(intent.IntentRefused):
                self.mint(f, store, operation, observed)

    def test_final_client_pin_change_after_cas_prevents_send_and_success_marker(self):
        with self.prepared() as state:
            f, store, operation, current, cap, options, _ = state
            original = store.advance

            def advance(*args, **kwargs):
                value = original(*args, **kwargs)
                f.client.base_url = "https://different.example"
                return value

            with patch.object(store, "advance", side_effect=advance):
                with self.assertRaises(host.HostRefused):
                    self.register(f, operation, cap, options)
            f.session.register.assert_not_called()
            self.assertIsNone(cap._fenced_digest)
            self.assertTrue(
                store.read(current["operation_id"], operation=operation)["effects"][
                    "registration_may_have_sent"
                ]
            )

    def test_recorded_true_flag_without_host_record_is_not_capability_authority(self):
        with self.prepared() as state:
            f, store, operation, current, _, _, _ = state
            following = copy.deepcopy(current)
            following.update(
                revision=current["revision"] + 1, previous_sha256=host.digest(current)
            )
            following["effects"]["registration_may_have_sent"] = True
            following["observations"]["registration_sha256"] = "e" * 64
            observed = store.advance(
                following,
                expected_revision=current["revision"],
                expected_sha256=host.digest(current),
                operation=operation,
            )
            self.assertFalse(f.records._path(f.runtime_id).exists())
            with self.assertRaises(intent.IntentRefused):
                self.mint(f, store, operation, observed)
            f.session.register.assert_not_called()

    def test_two_preparation_caps_cannot_send_twice_after_success_unknown_or_failure(
        self,
    ):
        for mode in ("legacy-v1", "finite-v2", "persistent-v3"):
            for outcome in (
                "ack",
                "unknown_ack",
                "fence_failure",
                "committed_fence_failure",
                "fence_interrupt",
            ):
                with (
                    self.subTest(mode=mode, outcome=outcome),
                    self.prepared(mode) as state,
                ):
                    f, store, operation, current, first, options, _ = state
                    second = self.mint(f, store, operation, current)
                    self.assertIsNot(first, second)
                    with patch.object(host, "replay_registration") as replay:
                        if outcome == "ack":
                            self.register(f, operation, first, options)
                        elif outcome == "unknown_ack":
                            f.session.register.side_effect = host.HostRefused()
                            with self.assertRaises(host.HostRefused):
                                self.register(f, operation, first, options)
                        else:
                            original = store.advance

                            def advance(*args, **kwargs):
                                if outcome == "committed_fence_failure":
                                    original(*args, **kwargs)
                                if outcome == "fence_interrupt":
                                    raise KeyboardInterrupt
                                raise OSError("fixed-test-fence-failure")

                            with patch.object(store, "advance", side_effect=advance):
                                expected = (
                                    KeyboardInterrupt
                                    if outcome == "fence_interrupt"
                                    else host.HostRefused
                                )
                                with self.assertRaises(expected):
                                    self.register(f, operation, first, options)
                        expected_calls = 1 if outcome in {"ack", "unknown_ack"} else 0
                        self.assertEqual(f.session.register.call_count, expected_calls)
                        before = store.read(
                            current["operation_id"], operation=operation
                        )
                        with self.assertRaises(host.HostRefused):
                            self.register(f, operation, second, options)
                        self.assertEqual(f.session.register.call_count, expected_calls)
                        self.assertEqual(
                            store.read(current["operation_id"], operation=operation),
                            before,
                        )
                        self.assertTrue(first._used)
                        self.assertFalse(
                            second._used
                        )  # Existing preparation gate refused before the fence.
                        replay.assert_not_called()

    def test_fresh_object_after_pure_malformed_preparation_attempt_has_no_prior_effect(
        self,
    ):
        with self.prepared() as state:
            f, store, operation, current, first, options, calls = state
            before = list(calls)
            with self.assertRaises(intent.IntentRefused):
                intent.registration_fence(first)
            self.assertEqual(calls, before)
            self.assertTrue(first._used)
            self.assertIsNone(first._fenced_digest)
            self.assertFalse(f.records._path(f.runtime_id).exists())
            self.assertEqual(f.backend.values, {})
            self.assertEqual(
                store.read(current["operation_id"], operation=operation), current
            )
            second = self.mint(f, store, operation, current)
            self.assertIsNot(first, second)
            self.register(f, operation, second, options)
            self.assertEqual(f.session.register.call_count, 1)
            with self.assertRaises(intent.IntentRefused):
                intent.registration_fence(first)
            self.assertEqual(f.session.register.call_count, 1)


if __name__ == "__main__":
    unittest.main()
