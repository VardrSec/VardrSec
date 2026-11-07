"""Actual closed storage with private temporary files and synthetic custody only."""

from contextlib import contextmanager
import copy
import ctypes
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

import worker_host as host
import worker_lifecycle_intent as intent
import worker_secrets as custody


OPERATION = "11111111-1111-4111-8111-111111111111"
FUTURE = "22222222-2222-4222-8222-222222222222"
PREVIOUS = "33333333-3333-4333-8333-333333333333"


def exclusive_test_publish(source, target, **_kwargs):
    """Model atomic destination refusal using this platform's existing primitive."""
    if sys.platform == "win32":
        os.rename(source, target)
    else:
        os.link(source, target)


def reviewed_policy(protocol):
    return {
        "origin": "https://issuer.example",
        "enrollment_id": "reviewed-enrollment",
        "runner_id": "44444444-4444-4444-8444-444444444444",
        "protocol": protocol,
        "expires_in_seconds": None if protocol == "persistent-v3" else 900,
        "limits": {
            "max_attempts": 2 if protocol == "finite-v2" else None,
            "idle_timeout_seconds": None,
        },
        "reporting_authority": {"purpose": "worker-stop-only", "expires_at": None}
        if protocol == "persistent-v3"
        else None,
    }


class SyntheticBackend:
    def __init__(self):
        self.intents, self.stops, self.calls = {}, {}, []

    def read_intent(self, key, *, records, operation):
        records._intent_access(operation)
        self.calls.append(("read_intent", key))
        return self.intents.get(key)

    def create_intent(self, key, value, *, records, operation):
        records._intent_access(operation)
        self.calls.append(("create_intent", key))
        if key in self.intents:
            raise custody.SecretRefused("synthetic_refusal")
        self.intents[key] = value

    def read(self, key):
        self.calls.append(("read_stop", key))
        return self.stops.get(key)


def payload(records):
    return {
        "operation_id": OPERATION,
        "future_runtime_id": FUTURE,
        "registration_policy": reviewed_policy("persistent-v3"),
        "installation": str(records.installation.resolve()),
        "storage_root": str(records.private_root.resolve()),
        "revision": 1,
        "previous_sha256": None,
        "source": {
            **{
                name: "a" * 40
                for name in (
                    "distribution_commit",
                    "distribution_tree",
                    "runner_commit",
                    "map_commit",
                    "gate_commit",
                )
            },
            "runner_image": "sha256:" + "b" * 64,
            "compose_version": "5.6.1",
            **{
                name: "c" * 64
                for name in (
                    "compose_executable_sha256",
                    "unresolved_model_sha256",
                    "closed_override_sha256",
                    "environment_contract_sha256",
                    "core_image_set_sha256",
                )
            },
        },
        "binding": {
            "context": "synthetic",
            "local_endpoint": "npipe:////synthetic",
            "daemon_id": "synthetic-daemon",
            "project": "owned-project",
        },
        "predecessors": [
            {
                "ordinal": 1,
                "container_id": "d" * 64,
                "image_id": "sha256:" + "b" * 64,
                "runtime_id": PREVIOUS,
                **{
                    name: "e" * 64
                    for name in (
                        "runtime_sha256",
                        "admission_sha256",
                        "host_retirement_sha256",
                        "original_local_audit_sha256",
                    )
                },
            }
        ],
        "resources": {
            "core_containers": [
                {
                    "service": name,
                    "container_id": str(i) * 64,
                    "image_id": "sha256:" + "b" * 64,
                }
                for i, name in enumerate(("db", "api", "web", "proxy"), 1)
            ],
            "runner_network": {
                "id": "f" * 64,
                "name": "owned_runner",
                "metadata_sha256": "e" * 64,
            },
            "runner_state": {
                "name": "owned_state",
                "source": "/synthetic/volumes/owned_state/_data",
                "created_at": "2026-11-06T00:00:00Z",
                "metadata_sha256": "e" * 64,
            },
            "trust_source": "synthetic-trust",
            "trust_sha256": "e" * 64,
            "public_directory": "synthetic-new-public",
            "readiness_volume": "synthetic-new-ready",
            "readiness_marker": "synthetic-marker",
            "expected_ordinal": 2,
        },
        "effects": {name: False for name in intent._FLAGS},
        "observations": {name: None for name in intent._OBSERVATIONS},
        "disposition": "active",
    }


class LifecycleIntentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        installation, private = self.root / "installation", self.root / "private"
        installation.mkdir(mode=0o700)
        private.mkdir(mode=0o700)
        self.backend = SyntheticBackend()
        self.records = host.HostRecords(installation, private, backend=self.backend)
        self.store = intent.IntentStore(self.records)
        self.row = payload(self.records)
        self.locks = []

        @contextmanager
        def lock(path):
            self.locks.append(("lock", path))
            try:
                yield
            finally:
                self.locks.append(("unlock", path))

        self.lock_patch = patch.object(host.updater, "installation_lock", lock)
        self.lock_patch.start()
        self.addCleanup(self.lock_patch.stop)
        # Native MoveFileEx/credential APIs are NOT exercised by this pure suite.
        self.new_patch = patch.object(
            intent,
            "_publish_new",
            exclusive_test_publish,
        )
        self.old_patch = patch.object(
            host, "_publish", lambda source, target: os.replace(source, target)
        )
        self.new_patch.start()
        self.old_patch.start()
        self.addCleanup(self.new_patch.stop)
        self.addCleanup(self.old_patch.stop)

    @property
    def path(self):
        return self.records.directory / (OPERATION + ".intent.json")

    def next(self, old, operation, change):
        new = copy.deepcopy(old)
        new.update(revision=old["revision"] + 1, previous_sha256=host.digest(old))
        change(new)
        return self.store.advance(
            new,
            expected_revision=old["revision"],
            expected_sha256=host.digest(old),
            operation=operation,
        )

    def created(self):
        return {
            "container_id": "9" * 64,
            "image_id": self.row["source"]["runner_image"],
            "project": "owned-project",
            "daemon_id": "synthetic-daemon",
            "ordinal": 2,
            "readiness_volume": "synthetic-new-ready",
        }

    def test_constructor_is_inert_and_invalid_owner_refuses_before_io(self):
        inert = intent.IntentStore(object())
        with self.assertRaises(intent.IntentRefused):
            inert.read(OPERATION, operation=object())
        with patch.object(
            self.records, "_directory", side_effect=AssertionError("no I/O")
        ):
            for call in (
                lambda: self.store.read(OPERATION, operation=object()),
                lambda: self.store.create(self.row, operation=None),
            ):
                with self.assertRaises(intent.IntentRefused):
                    call()
        self.assertEqual(self.backend.calls, [])
        self.assertFalse(self.path.exists())

    def test_real_live_token_foreign_copied_stale_and_other_thread_refuse(self):
        with self.records.operation() as operation:
            other = host.HostRecords(
                self.records.installation,
                self.records.private_root,
                backend=self.backend,
            )
            for target, token in (
                (self.store, copy.copy(operation)),
                (intent.IntentStore(other), operation),
            ):
                with self.assertRaises(intent.IntentRefused):
                    target.create(self.row, operation=token)
            with patch.object(
                host.threading, "get_ident", return_value=operation._thread + 1
            ):
                self.assertTrue(self._thread_refusal(operation))
        with self.assertRaises(intent.IntentRefused):
            self.store.create(self.row, operation=operation)
        self.assertEqual(self.backend.calls, [])

    def _thread_refusal(self, operation):
        try:
            self.store.create(self.row, operation=operation)
        except intent.IntentRefused:
            return True
        return False

    def test_exclusive_mac_roundtrip_uses_only_distinct_intent_slot_and_copies(self):
        with self.records.operation() as operation:
            result = self.store.create(self.row, operation=operation)
            self.assertEqual(result, self.row)
            result["source"]["runner_commit"] = "0" * 40
            self.assertEqual(self.store.read(OPERATION, operation=operation), self.row)
            with self.assertRaises(intent.IntentRefused):
                self.store.create(self.row, operation=operation)
        self.assertEqual(set(self.backend.intents), {OPERATION})
        self.assertEqual(self.backend.stops, {})
        self.assertFalse(any(kind == "read_stop" for kind, _ in self.backend.calls))
        wrapped = json.loads(self.path.read_bytes())
        self.assertEqual(set(wrapped), {"schema", "payload", "mac"})
        self.assertEqual(wrapped["schema"], intent.SCHEMA)
        self.assertNotIn(self.backend.intents[OPERATION], self.path.read_text())

    def test_actual_fixed_purpose_wrappers_preserve_stop_targets_and_require_owner(
        self,
    ):
        windows = object.__new__(custody.WindowsSecrets)
        windows._read_target = Mock(return_value=None)
        posix = object.__new__(custody.PosixSecrets)
        posix._read_name = Mock(return_value=None)
        posix._create_name = Mock()
        windows.read(FUTURE)
        self.assertEqual(
            windows._read_target.call_args.args,
            ("VardrSec.NewMoon.WorkerStop/v1/" + FUTURE,),
        )
        posix.read(FUTURE)
        self.assertEqual(posix._read_name.call_args.args, (FUTURE + ".stop",))
        posix.create(FUTURE, "a" * 64)
        self.assertEqual(
            posix._create_name.call_args.args, (FUTURE + ".stop", "a" * 64)
        )
        with self.records.operation() as operation:
            with patch.object(self.records, "backend", windows):
                windows.read_intent(
                    OPERATION, records=self.records, operation=operation
                )
            self.assertEqual(
                windows._read_target.call_args.args,
                ("VardrSec.NewMoon.LifecycleIntent/v1/" + OPERATION,),
            )
            with patch.object(self.records, "backend", posix):
                posix.create_intent(
                    OPERATION, "b" * 64, records=self.records, operation=operation
                )
            self.assertEqual(
                posix._create_name.call_args.args, (OPERATION + ".intent-key", "b" * 64)
            )
        before = windows._read_target.call_count
        with (
            patch.object(self.records, "backend", windows),
            self.assertRaises(host.HostRefused),
        ):
            windows.read_intent(OPERATION, records=self.records, operation=operation)
        self.assertEqual(windows._read_target.call_count, before)

    def test_windows_intent_create_is_mocked_distinct_and_preserves_stop_policy(self):
        windows = object.__new__(custody.WindowsSecrets)
        windows.kernel = SimpleNamespace(
            CreateMutexW=Mock(return_value=1), ReleaseMutex=Mock(), CloseHandle=Mock()
        )
        windows._write_target = Mock()
        with (
            self.records.operation() as operation,
            patch.object(self.records, "backend", windows),
        ):
            with (
                patch.object(ctypes, "set_last_error", create=True),
                patch.object(ctypes, "get_last_error", return_value=0, create=True),
            ):
                with patch.object(windows, "read_intent", side_effect=[None, "a" * 64]):
                    windows.create_intent(
                        OPERATION, "a" * 64, records=self.records, operation=operation
                    )
            self.assertEqual(
                windows._write_target.call_args.args,
                (
                    "VardrSec.NewMoon.LifecycleIntent/v1/" + OPERATION,
                    "a" * 64,
                    "VardrSec lifecycle MAC only",
                ),
            )
            self.assertEqual(
                windows.kernel.CreateMutexW.call_args.args,
                (None, True, "Local\\VardrSec.LifecycleIntent.v1." + OPERATION),
            )
        windows.kernel.ReleaseMutex.assert_called_once_with(1)
        windows.kernel.CloseHandle.assert_called_once_with(1)
        with (
            patch.object(
                windows,
                "_guard",
                return_value=self.lock_patch.new(self.records.installation),
            ),
            patch.object(windows, "read", side_effect=[None, "b" * 64]),
        ):
            windows.create(FUTURE, "b" * 64)
        self.assertEqual(
            windows._write_target.call_args.args,
            (
                "VardrSec.NewMoon.WorkerStop/v1/" + FUTURE,
                "b" * 64,
                "VardrSec worker stop only",
            ),
        )

    def test_windows_initial_publication_uses_nonreplace_write_through_without_native_call(
        self,
    ):
        move = Mock(return_value=1)
        with (
            self.records.operation() as operation,
            patch.object(intent, "os", SimpleNamespace(name="nt")),
            patch.object(
                ctypes,
                "WinDLL",
                return_value=SimpleNamespace(MoveFileExW=move),
                create=True,
            ),
        ):
            # Reach the actual function, not the storage test's OS mock.
            self.new_patch.stop()
            try:
                intent._publish_new(
                    self.records.directory / "temporary",
                    self.records.directory / "destination",
                    records=self.records,
                    operation=operation,
                )
            finally:
                self.new_patch.start()
        self.assertEqual(move.call_args.args[2], 0x8)
        self.assertTrue(
            all(value.startswith("\\\\?\\") for value in move.call_args.args[:2])
        )

    def test_sticky_cas_additive_metadata_and_enabled_sequence(self):
        with self.records.operation() as operation:
            old = self.store.create(self.row, operation=operation)
            old = self.next(
                old,
                operation,
                lambda row: row["effects"].update(
                    public_directory_may_have_been_created=True,
                    readiness_may_have_been_created=True,
                ),
            )

            def created(row):
                row["effects"]["container_create_may_have_sent"] = True
                row["observations"]["created"] = self.created()

            old = self.next(old, operation, created)

            def running(row):
                row["effects"]["start_may_have_sent"] = True
                row["observations"]["running"] = {
                    key: value
                    for key, value in self.created().items()
                    if key in {"container_id", "image_id", "project", "daemon_id"}
                }
                row["observations"]["running"].update(
                    started_at="2026-11-06T00:00:00.000000001Z", owner_nonce="a" * 64
                )

            old = self.next(old, operation, running)

            def registered(row):
                row["effects"]["registration_may_have_sent"] = True
                row["observations"]["registration_sha256"] = "e" * 64

            old = self.next(old, operation, registered)

            def published(row):
                row["effects"]["publication_may_have_happened"] = True
                row["observations"].update(
                    host_record_sha256="e" * 64, admission_sha256="f" * 64
                )
                row["disposition"] = "enabled"

            final = self.next(old, operation, published)
            self.assertTrue(all(final["effects"].values()))
            self.assertEqual(final["disposition"], "enabled")
            self.assertEqual(self.store.read(OPERATION, operation=operation), final)

    def test_stale_revision_wrong_digest_immutable_changes_and_flag_regression_refuse(
        self,
    ):
        with self.records.operation() as operation:
            old = self.store.create(self.row, operation=operation)
            old = self.next(
                old,
                operation,
                lambda row: row["effects"].update(readiness_may_have_been_created=True),
            )
            before = self.path.read_bytes()
            for change in (
                lambda row: row["effects"].update(
                    readiness_may_have_been_created=False
                ),
                lambda row: row["source"].update(runner_commit="0" * 40),
                lambda row: row.update(future_runtime_id=OPERATION),
                lambda row: row.update(revision=True),
                lambda row: row["effects"].update(start_may_have_sent=True),
                lambda row: row.update(unexpected="canary"),
            ):
                with (
                    self.subTest(change=change.__code__.co_firstlineno),
                    self.assertRaises(intent.IntentRefused),
                ):
                    self.next(old, operation, change)
                self.assertEqual(self.path.read_bytes(), before)
            new = copy.deepcopy(old)
            new.update(revision=old["revision"] + 1, previous_sha256=host.digest(old))
            for revision, digest in (
                (True, host.digest(old)),
                (1, host.digest(old)),
                (old["revision"], "0" * 64),
            ):
                with self.assertRaises(intent.IntentRefused):
                    self.store.advance(
                        new,
                        expected_revision=revision,
                        expected_sha256=digest,
                        operation=operation,
                    )
            self.assertEqual(self.path.read_bytes(), before)

    def test_held_cannot_resume_and_observation_cannot_be_rewritten_or_removed(self):
        with self.records.operation() as operation:
            old = self.store.create(self.row, operation=operation)
            old = self.next(old, operation, lambda row: row.update(disposition="held"))
            with self.assertRaises(intent.IntentRefused):
                self.next(old, operation, lambda row: row.update(disposition="active"))
            old = self.next(
                old,
                operation,
                lambda row: row["observations"].update(registration_sha256="e" * 64),
            )
            for value in (None, "f" * 64):
                with self.assertRaises(intent.IntentRefused):
                    self.next(
                        old,
                        operation,
                        lambda row: row["observations"].update(
                            registration_sha256=value
                        ),
                    )

    def test_malformed_mac_domain_duplicate_nonfinite_and_missing_files_are_held(self):
        with self.records.operation() as operation:
            with self.assertRaises(intent.IntentRefused):
                self.store.read(OPERATION, operation=operation)
            self.store.create(self.row, operation=operation)
            original = self.path.read_bytes()
            variants = [
                b"{",
                original.replace(b'"schema":', b'"schema":"duplicate","schema":', 1),
                original.replace(b'"revision":1', b'"revision":NaN'),
                original.replace(
                    b'"vardr.worker-lifecycle-intent/2"',
                    b'"vardr.worker-host-record/3"',
                ),
                original.replace(b'"mac":"', b'"mac":"0', 1),
            ]
            for raw in variants:
                self.path.write_bytes(raw)
                with self.assertRaises(intent.IntentRefused):
                    self.store.read(OPERATION, operation=operation)
            self.path.write_bytes(original)
            del self.backend.intents[OPERATION]
            with self.assertRaises(intent.IntentRefused):
                self.store.read(OPERATION, operation=operation)

    def test_bounded_record_exhaustion_never_truncates_history_or_creates_key(self):
        large = copy.deepcopy(self.row)
        large["predecessors"] = []
        for index in range(500):
            row = copy.deepcopy(self.row["predecessors"][0])
            row.update(
                ordinal=index + 1,
                container_id=f"{10000 + index:064x}",
                runtime_id=str(uuid.UUID(int=10000 + index)),
            )
            large["predecessors"].append(row)
        large["resources"]["expected_ordinal"] = 501
        with (
            self.records.operation() as operation,
            self.assertRaises(intent.IntentRefused),
        ):
            self.store.create(large, operation=operation)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.backend.intents, {})

    def test_destination_collision_is_never_overwritten_or_adopted(self):
        def collide(source, target, **_kwargs):
            target.write_bytes(b"retained-collision")
            exclusive_test_publish(source, target)

        with (
            self.records.operation() as operation,
            patch.object(intent, "_publish_new", collide),
        ):
            with self.assertRaises(intent.IntentRefused):
                self.store.create(self.row, operation=operation)
            self.assertEqual(self.path.read_bytes(), b"retained-collision")
            with self.assertRaises(intent.IntentRefused):
                self.store.create(self.row, operation=operation)
        self.assertEqual(
            sum(kind == "create_intent" for kind, _ in self.backend.calls), 1
        )

    def test_fsync_or_publication_failure_retains_artifacts_and_never_retries_key(self):
        for boundary in ("fsync", "publish"):
            with self.subTest(boundary=boundary):
                row = copy.deepcopy(self.row)
                row["operation_id"] = str(uuid.uuid4())
                with self.records.operation() as operation:
                    with (
                        patch.object(
                            intent.os, "fsync", side_effect=OSError("private-canary")
                        )
                        if boundary == "fsync"
                        else patch.object(
                            intent,
                            "_publish_new",
                            side_effect=OSError("private-canary"),
                        )
                    ):
                        with self.assertRaises(intent.IntentRefused) as caught:
                            self.store.create(row, operation=operation)
                    self.assertEqual(
                        str(caught.exception), "worker_lifecycle_intent_refused"
                    )
                    with self.assertRaises(intent.IntentRefused):
                        self.store.create(row, operation=operation)
                self.assertTrue(
                    list(
                        self.records.directory.glob(
                            row["operation_id"] + ".intent.json.*.tmp"
                        )
                    )
                )
                self.assertEqual(
                    sum(
                        kind == "create_intent" and key == row["operation_id"]
                        for kind, key in self.backend.calls
                    ),
                    1,
                )

    def test_readback_failure_keeps_published_intent_and_does_not_recreate(self):
        original_read = self.store._read
        with self.records.operation() as operation:
            with patch.object(
                self.store, "_read", side_effect=OSError("private-canary")
            ):
                with self.assertRaises(intent.IntentRefused):
                    self.store.create(self.row, operation=operation)
            self.assertTrue(self.path.exists())
            with self.assertRaises(intent.IntentRefused):
                self.store.create(self.row, operation=operation)
            self.assertEqual(original_read(self.path, OPERATION, operation), self.row)

    def test_short_write_or_flush_failure_never_reaches_publication(self):
        real_fdopen = os.fdopen
        for boundary in ("write", "flush"):
            row = copy.deepcopy(self.row)
            row["operation_id"] = str(uuid.uuid4())

            class FaultyFile:
                def __init__(self, descriptor, mode):
                    self.stream = real_fdopen(descriptor, mode)

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return self.stream.__exit__(*args)

                def write(self, data):
                    return 0 if boundary == "write" else self.stream.write(data)

                def flush(self):
                    raise OSError("synthetic-private-failure")

                def fileno(self):
                    return self.stream.fileno()

            with self.subTest(boundary=boundary), self.records.operation() as operation:
                with (
                    patch.object(intent.os, "fdopen", FaultyFile),
                    patch.object(intent, "_publish_new") as publish,
                ):
                    with self.assertRaises(intent.IntentRefused):
                        self.store.create(row, operation=operation)
                    publish.assert_not_called()
                self.assertTrue(
                    list(
                        self.records.directory.glob(
                            row["operation_id"] + ".intent.json.*.tmp"
                        )
                    )
                )

    def test_posix_directory_fsync_failure_is_not_reported_as_success(self):
        # Actual writer ordering, synthetic directory descriptor; no POSIX or
        # Windows directory API is invoked by this model on the Desktop host.
        directory_descriptor = object()
        calls = []
        real_os = os

        def opened(path, flags, *args):
            if Path(path) == self.records.directory:
                calls.append("directory_open")
                return directory_descriptor
            return real_os.open(path, flags, *args)

        def synced(descriptor):
            if descriptor is directory_descriptor:
                calls.append("directory_fsync")
                raise OSError("synthetic-directory-failure")
            calls.append("file_fsync")
            real_os.fsync(descriptor)

        proxy = SimpleNamespace(
            name="posix",
            open=opened,
            fdopen=real_os.fdopen,
            fsync=synced,
            close=lambda descriptor: calls.append("directory_close"),
            O_WRONLY=real_os.O_WRONLY,
            O_CREAT=real_os.O_CREAT,
            O_EXCL=real_os.O_EXCL,
            O_RDONLY=real_os.O_RDONLY,
            O_DIRECTORY=0,
            O_NOFOLLOW=0,
        )
        target = self.records.directory / "synthetic-directory-fault.intent.json"
        with self.records.operation() as operation, patch.object(intent, "os", proxy):
            with self.assertRaises(OSError):
                intent._write(
                    target,
                    b"synthetic-private-metadata",
                    create=True,
                    records=self.records,
                    operation=operation,
                )
        self.assertEqual(
            calls,
            ["file_fsync", "directory_open", "directory_fsync", "directory_close"],
        )
        self.assertEqual(target.read_bytes(), b"synthetic-private-metadata")

    def test_linked_reparse_or_nonregular_record_refuses_before_key_lookup(self):
        with self.records.operation() as operation:
            self.store.create(self.row, operation=operation)
            original = self.path.lstat()
            real_lstat = type(self.path).lstat
            before = len(self.backend.calls)
            for change in ("linked", "reparse", "nonregular"):
                info = SimpleNamespace(
                    **{
                        name: getattr(original, name)
                        for name in (
                            "st_mode",
                            "st_nlink",
                            "st_dev",
                            "st_ino",
                            "st_size",
                            "st_mtime_ns",
                        )
                    }
                )
                info.st_file_attributes = 0x400 if change == "reparse" else 0
                if change == "linked":
                    info.st_nlink = 2
                if change == "nonregular":
                    info.st_mode = 0

                def changed(path, *args, **kwargs):
                    return (
                        info if path == self.path else real_lstat(path, *args, **kwargs)
                    )

                with (
                    self.subTest(change=change),
                    patch.object(type(self.path), "lstat", changed),
                ):
                    with self.assertRaises(intent.IntentRefused):
                        self.store.read(OPERATION, operation=operation)
                self.assertEqual(len(self.backend.calls), before)

    def test_old_intent1_is_held_before_key_access_without_migration_or_overwrite(self):
        with self.records.operation() as operation:
            self.store.create(self.row, operation=operation)
            old = copy.deepcopy(self.row)
            del old["registration_policy"]
            key = self.backend.intents[OPERATION]
            raw = host.canonical(
                {
                    "schema": "vardr.worker-lifecycle-intent/1",
                    "payload": old,
                    "mac": hmac.new(
                        bytes.fromhex(key),
                        b"vardr.worker-lifecycle-intent/1\0" + host.canonical(old),
                        hashlib.sha256,
                    ).hexdigest(),
                }
            )
            self.path.write_bytes(raw)
            self.backend.calls.clear()
            advanced = copy.deepcopy(self.row)
            advanced.update(revision=2, previous_sha256=host.digest(old))
            for action in (
                lambda: self.store.read(OPERATION, operation=operation),
                lambda: self.store.create(self.row, operation=operation),
                lambda: self.store.advance(
                    advanced,
                    expected_revision=1,
                    expected_sha256=host.digest(old),
                    operation=operation,
                ),
            ):
                with self.assertRaises(intent.IntentRefused):
                    action()
                self.assertEqual(self.path.read_bytes(), raw)
            self.assertEqual(self.backend.calls, [])
            self.assertEqual(self.backend.intents, {OPERATION: key})

    def test_old_mac_domain_cannot_authenticate_relabelled_intent2(self):
        with self.records.operation() as operation:
            self.store.create(self.row, operation=operation)
            key = self.backend.intents[OPERATION]
            raw = host.canonical(
                {
                    "schema": intent.SCHEMA,
                    "payload": self.row,
                    "mac": hmac.new(
                        bytes.fromhex(key),
                        b"vardr.worker-lifecycle-intent/1\0" + host.canonical(self.row),
                        hashlib.sha256,
                    ).hexdigest(),
                }
            )
            self.path.write_bytes(raw)
            self.backend.calls.clear()
            with self.assertRaises(intent.IntentRefused):
                self.store.read(OPERATION, operation=operation)
            self.assertEqual(self.backend.calls, [("read_intent", OPERATION)])
            self.assertEqual(self.path.read_bytes(), raw)

    def test_three_reviewed_named_modes_preserve_explicit_types_and_nulls(self):
        policies = [
            reviewed_policy(name)
            for name in ("legacy-v1", "finite-v2", "persistent-v3")
        ]
        bounded = reviewed_policy("persistent-v3")
        bounded["limits"] = {"max_attempts": "1", "idle_timeout_seconds": 60}
        policies.append(bounded)
        with self.records.operation() as operation:
            for policy in policies:
                row = copy.deepcopy(self.row)
                row.update(operation_id=str(uuid.uuid4()), registration_policy=policy)
                saved = self.store.create(row, operation=operation)
                self.assertEqual(saved["registration_policy"], policy)
                self.assertEqual(
                    self.store.read(row["operation_id"], operation=operation), saved
                )
        self.assertEqual(self.backend.stops, {})

    def test_policy_missing_extra_mixed_or_coerced_values_refuse_before_key_creation(
        self,
    ):
        changes = [
            lambda p: p.pop("runner_id"),
            lambda p: p.update(unexpected=True),
            lambda p: p.update(protocol=None),
            lambda p: p.update(protocol="sequence-v2"),
            lambda p: p.update(expires_in_seconds=900),
            lambda p: p["limits"].update(max_attempts=1),
            lambda p: p["limits"].update(max_attempts="01"),
            lambda p: p["limits"].update(idle_timeout_seconds=True),
            lambda p: p["limits"].update(idle_timeout_seconds=86401),
            lambda p: p["limits"].update(extra=None),
            lambda p: p.update(reporting_authority=None),
            lambda p: p["reporting_authority"].update(purpose="execution"),
            lambda p: p["reporting_authority"].update(
                expires_at="2027-01-01T00:00:00Z"
            ),
            lambda p: p.update(origin="http://issuer.example"),
            lambda p: p.update(runner_id="wrong"),
            lambda p: p.update(enrollment_id="wrong\n"),
        ]
        with self.records.operation() as operation:
            for change in changes:
                row = copy.deepcopy(self.row)
                change(row["registration_policy"])
                with (
                    self.subTest(line=change.__code__.co_firstlineno),
                    self.assertRaises(intent.IntentRefused),
                ):
                    self.store.create(row, operation=operation)
            for mode, expiry in (
                ("finite-v2", True),
                ("finite-v2", None),
                ("legacy-v1", 59),
            ):
                row = copy.deepcopy(self.row)
                row["registration_policy"] = reviewed_policy(mode)
                row["registration_policy"]["expires_in_seconds"] = expiry
                with self.assertRaises(intent.IntentRefused):
                    self.store.create(row, operation=operation)
            for mode, limits in (
                ("finite-v2", {"max_attempts": "2", "idle_timeout_seconds": None}),
                ("finite-v2", {"max_attempts": 2, "idle_timeout_seconds": 60}),
                ("legacy-v1", {"max_attempts": 1, "idle_timeout_seconds": None}),
            ):
                row = copy.deepcopy(self.row)
                row["registration_policy"] = reviewed_policy(mode)
                row["registration_policy"]["limits"] = limits
                with self.assertRaises(intent.IntentRefused):
                    self.store.create(row, operation=operation)
        self.assertEqual(self.backend.calls, [])
        self.assertEqual(self.backend.intents, {})
        self.assertFalse(self.path.exists())

    def test_valid_but_changed_public_registration_policy_is_immutable_under_cas(self):
        with self.records.operation() as operation:
            old = self.store.create(self.row, operation=operation)
            before = self.path.read_bytes()
            changed = [reviewed_policy("finite-v2"), reviewed_policy("legacy-v1")]
            different_origin = reviewed_policy("persistent-v3")
            different_origin["origin"] = "https://different.example"
            changed.append(different_origin)
            bounded = reviewed_policy("persistent-v3")
            bounded["limits"] = {"max_attempts": "2", "idle_timeout_seconds": 60}
            changed.append(bounded)
            for policy in changed:
                with self.assertRaises(intent.IntentRefused):
                    self.next(
                        old,
                        operation,
                        lambda row: row.update(registration_policy=policy),
                    )
                self.assertEqual(self.path.read_bytes(), before)

    def test_schema2_never_adopts_existing_purpose_key_when_intent_file_is_absent(self):
        self.backend.intents[OPERATION] = "a" * 64
        with (
            self.records.operation() as operation,
            self.assertRaises(intent.IntentRefused),
        ):
            self.store.create(self.row, operation=operation)
        self.assertEqual(self.backend.calls, [("read_intent", OPERATION)])
        self.assertEqual(self.backend.intents, {OPERATION: "a" * 64})
        self.assertEqual(self.backend.stops, {})
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
