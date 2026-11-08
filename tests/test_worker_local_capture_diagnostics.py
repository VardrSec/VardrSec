"""Synthetic local recapture diagnostics; no live owner, daemon or providers."""

from contextlib import contextmanager
from dataclasses import replace
import json
import unittest
from unittest.mock import Mock, patch

import test_worker_host_persistent as fixtures
import worker_host as host
import worker_host_persistent as persistent
import worker_runtime as runtime

PRIVATE = "private-nonce-cookie-path-body-canary"


def detail(checkpoint):
    return {"checkpoint": checkpoint, "request_stage": None, "http_status": None}


class LocalCaptureDiagnostics(unittest.TestCase):
    @contextmanager
    def fixture(self):
        selected = fixtures.PersistentHostTests()
        selected.setUp()
        try:
            yield selected, selected.f
        finally:
            selected.doCleanups()

    def refused(self, selected, f, error, checkpoint):
        with (
            patch.object(f.observer, "capture_running", side_effect=error) as capture,
            patch.object(f.records, "outside_mounts") as mounts,
            patch.object(f.backend, "create") as create,
            patch.object(f.records, "write") as write,
            patch.object(persistent.secrets, "token_hex") as secret,
        ):
            with self.assertRaises(host.HostRefused) as caught:
                selected.register({"max_attempts": "1", "idle_timeout_seconds": None})
        capture.assert_called_once_with(
            container_id=f.identity.container_id,
            image_id=f.identity.image_id,
            project=f.identity.project,
        )
        for action in (mounts, create, write, secret, f.session.register):
            action.assert_not_called()
        self.assertEqual(
            host.registration_diagnostic(caught.exception), detail(checkpoint)
        )
        self.assertEqual(str(caught.exception), "worker_host_refused")
        self.assertNotIn(
            PRIVATE, json.dumps(host.registration_diagnostic(caught.exception))
        )
        self.assertFalse(f.records._path(f.runtime_id).exists())

    def test_every_closed_capture_failure_keeps_its_specific_checkpoint(self):
        for checkpoint in runtime.CAPTURE_CHECKPOINTS:
            with self.subTest(checkpoint=checkpoint), self.fixture() as (selected, f):
                error = runtime.RuntimeRefused(PRIVATE)
                error.checkpoint = checkpoint
                self.refused(selected, f, error, "local_capture_" + checkpoint)

    def test_different_valid_identity_has_a_distinct_fixed_refusal(self):
        for field, value in (
            ("daemon_id", "other-owned-daemon"),
            ("started_at", "2026-11-05T20:00:01.123456789Z"),
            ("owner_nonce", "e" * 64),
        ):
            with self.subTest(field=field), self.fixture() as (selected, f):
                changed = replace(f.identity, **{field: value})
                with (
                    patch.object(
                        f.observer, "capture_running", return_value=changed
                    ) as capture,
                    patch.object(f.records, "outside_mounts") as mounts,
                    patch.object(f.backend, "create") as create,
                    patch.object(f.records, "write") as write,
                    patch.object(persistent.secrets, "token_hex") as secret,
                ):
                    with self.assertRaises(host.HostRefused) as caught:
                        selected.register(
                            {"max_attempts": "1", "idle_timeout_seconds": None}
                        )
                capture.assert_called_once()
                self.assertEqual(
                    host.registration_diagnostic(caught.exception),
                    detail("local_identity_changed"),
                )
                for action in (mounts, create, write, secret, f.session.register):
                    action.assert_not_called()
                self.assertFalse(f.records._path(f.runtime_id).exists())

    def test_unknown_secret_and_typed_aliases_keep_generic_capture_refusal(self):
        class StringAlias(str):
            pass

        for value in (None, False, 1, [], {}, PRIVATE, StringAlias("daemon")):
            with (
                self.subTest(kind=type(value).__name__),
                self.fixture() as (selected, f),
            ):
                error = runtime.RuntimeRefused(PRIVATE)
                error.checkpoint = value
                self.refused(selected, f, error, "local_capture")

    def test_hostile_capture_properties_cannot_mask_the_original_refusal(self):
        seen = []

        class CheckpointProperty(runtime.RuntimeRefused):
            @property
            def checkpoint(self):
                seen.append("dynamic_checkpoint")
                raise RuntimeError(PRIVATE)

        class DictionaryProperty(runtime.RuntimeRefused):
            @property
            def __dict__(self):
                raise RuntimeError(PRIVATE)

        for kind in (CheckpointProperty, DictionaryProperty):
            with self.subTest(kind=kind.__name__), self.fixture() as (selected, f):
                self.refused(selected, f, kind(PRIVATE), "local_capture")
        self.assertEqual(seen, [])

    def test_valid_inner_host_detail_retains_priority(self):
        inner = {"checkpoint": "request", "request_stage": "status", "http_status": 503}
        with self.fixture() as (selected, f):
            error = host.HostRefused(PRIVATE, registration_failure=inner)
            error.checkpoint = "daemon"
            with (
                patch.object(f.observer, "capture_running", side_effect=error),
                patch.object(f.records, "outside_mounts") as mounts,
            ):
                with self.assertRaises(host.HostRefused) as caught:
                    selected.register()
            self.assertEqual(host.registration_diagnostic(caught.exception), inner)
            self.assertNotIn(
                PRIVATE, json.dumps(host.registration_diagnostic(caught.exception))
            )
            mounts.assert_not_called()
            f.session.register.assert_not_called()
            self.assertFalse(f.records._path(f.runtime_id).exists())

    def test_unchanged_identity_preserves_existing_single_send_and_call_order(self):
        with self.fixture() as (selected, f):
            events = Mock()
            with (
                patch.object(
                    f.observer, "capture_running", wraps=f.observer.capture_running
                ) as capture,
                patch.object(
                    f.records, "outside_mounts", wraps=f.records.outside_mounts
                ) as mounts,
                patch.object(
                    persistent.secrets, "token_hex", return_value="ab" * 32
                ) as secret,
                patch.object(f.backend, "create", wraps=f.backend.create) as create,
                patch.object(f.records, "write", wraps=f.records.write) as write,
            ):
                for name, action in (
                    ("capture", capture),
                    ("mounts", mounts),
                    ("secret", secret),
                    ("create", create),
                    ("write", write),
                    ("register", f.session.register),
                ):
                    events.attach_mock(action, name)
                result = selected.register(
                    {"max_attempts": "1", "idle_timeout_seconds": None}
                )
            self.assertEqual(
                [call[0] for call in events.mock_calls],
                ["capture", "mounts", "secret", "create", "write", "register", "write"],
            )
            self.assertEqual(result["schema"], "vardr.worker-admission/3")
            capture.assert_called_once()
            f.session.register.assert_called_once()
            self.assertEqual(
                f.records.read(f.runtime_id)["registration_state"], "acknowledged"
            )


if __name__ == "__main__":
    unittest.main()
