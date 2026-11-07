"""Default-local volume custody protocol fixtures; never contact a daemon."""

import copy
import json
from pathlib import PurePosixPath
import subprocess
import unittest
from unittest.mock import Mock, patch

import worker_runtime as runtime
import worker_volumes as volumes


class ManagedVolumeTests(unittest.TestCase):
    def setUp(self):
        self.layout = runtime.WorkerLayout(
            "/owned/trust", "/owned/admission", "fixture-state", "fixture-ready-fresh"
        )
        self.identity = runtime.RuntimeIdentity(
            "daemon-fixture",
            "a" * 64,
            "sha256:" + "b" * 64,
            "fixture",
            "2026-11-05T20:00:00.123456789Z",
            "c" * 64,
        )
        self.root = "/var/lib/docker"
        self.mounts, self.rows = [], {}
        for name, target, logical in (
            (self.layout.state_volume, "/home/runner/.vardrmap", "runner-state"),
            (self.layout.readiness_volume, "/run/vardr-worker-ready", "worker-ready"),
        ):
            source = f"{self.root}/volumes/{name}/_data"
            self.mounts.append(
                dict(
                    Type="volume", Name=name, Source=source, Destination=target, RW=True
                )
            )
            self.rows[name] = dict(
                name=name,
                driver="local",
                scope="local",
                options=None,
                source=source,
                project="fixture",
                volume=logical,
                ready="1" if logical == "worker-ready" else None,
            )

    def validate(self):
        return volumes.validate_sources(
            self.layout, "fixture", self.mounts, self.root, self.rows
        )

    def observer(self):
        observer = runtime.LocalDocker("fixture-local", self.layout)
        observer._bound = Mock(side_effect=[{"mounts": copy.deepcopy(self.mounts)}] * 2)
        return observer

    def command(self, argv, **options):
        self.calls.append((argv, options))
        self.assertEqual(argv[:3], ["docker", "--context", "fixture-local"])
        args = argv[3:]
        if args == ["info", "--format", volumes.DAEMON_FORMAT]:
            raw = json.dumps({"root": self.root, "os": "linux"})
        elif args[:4] == ["volume", "inspect", "--format", volumes.VOLUME_FORMAT]:
            self.assertEqual(len(args), 5)
            raw = json.dumps(self.rows[args[4]])
        else:
            self.fail("Unexpected Docker operation")
        return subprocess.CompletedProcess(argv, 0, raw, "")

    def test_inaccessible_managed_paths_use_exact_daemon_metadata_without_host_traversal(
        self,
    ):
        observer, self.calls = self.observer(), []
        with (
            patch.object(runtime.subprocess, "run", self.command),
            patch(
                "pathlib.Path.resolve",
                side_effect=PermissionError("untraversable fixture"),
            ) as resolve,
            patch("pathlib.Path.stat") as stat,
        ):
            result = volumes.managed_sources(observer, self.identity)
        self.assertEqual(result, tuple(PurePosixPath(m["Source"]) for m in self.mounts))
        resolve.assert_not_called()
        stat.assert_not_called()
        self.assertEqual(
            observer._bound.call_args_list, [((self.identity,),), ((self.identity,),)]
        )
        self.assertEqual(len(self.calls), 4)
        self.assertTrue(all(0 < options["timeout"] <= 15 for _, options in self.calls))
        self.assertIsNone(observer._deadline)
        self.assertFalse(observer._observation_lock.locked())

    def test_explicit_default_local_data_root_and_empty_options_are_supported(self):
        self.root = "/owned/docker-data"
        for mount in self.mounts:
            source = self.root + "/volumes/" + mount["Name"] + "/_data"
            mount["Source"] = self.rows[mount["Name"]]["source"] = source
            self.rows[mount["Name"]]["options"] = {}
        self.assertEqual(self.validate()[0], PurePosixPath(self.mounts[0]["Source"]))

    def test_custom_remote_or_ambiguous_volume_metadata_is_refused(self):
        changes = [
            ("name", "another-volume"),
            ("driver", "nfs-plugin"),
            ("scope", "global"),
            ("options", {"type": "none", "o": "bind", "device": "/private"}),
            ("options", {"type": "nfs", "device": ":/remote"}),
            ("options", []),
            ("project", "foreign-project"),
            ("volume", "other-role"),
            ("ready", None),
            ("source", "/private"),
            ("source", None),
        ]
        name = self.layout.readiness_volume
        original = self.rows[name].copy()
        for field, value in changes:
            with self.subTest(field=field, value=value):
                self.rows[name] = {**original, field: value}
                with self.assertRaisesRegex(
                    runtime.RuntimeRefused, "^worker_runtime_refused$"
                ):
                    self.validate()
        self.rows[name] = {**original, "unrecognized": "synthetic_do_not_echo"}
        with self.assertRaises(runtime.RuntimeRefused):
            self.validate()

    def test_actual_attachment_name_source_target_and_permissions_must_match(self):
        original = copy.deepcopy(self.mounts)
        changes = [
            ("Type", "bind"),
            ("Name", "foreign"),
            ("RW", False),
            ("RW", 1),
            ("Source", self.mounts[0]["Source"] + "/subpath"),
            ("Source", "/private"),
            ("Destination", "/elsewhere"),
        ]
        for field, value in changes:
            with self.subTest(field=field):
                self.mounts = copy.deepcopy(original)
                self.mounts[0][field] = value
                with self.assertRaises(runtime.RuntimeRefused):
                    self.validate()

    def test_missing_duplicate_or_additional_volume_attachments_are_refused(self):
        original = copy.deepcopy(self.mounts)
        for changed in (
            original[:1],
            original + original[:1],
            original + [{**original[0], "Destination": "/extra"}],
            original + [{"Type": "volume", "Name": []}],
        ):
            with self.subTest(mounts=len(changed)):
                self.mounts = changed
                with self.assertRaises(runtime.RuntimeRefused):
                    self.validate()

    def test_only_canonical_absolute_posix_daemon_paths_qualify(self):
        for value in (
            "/",
            "relative",
            "//daemon/root",
            "/var/./docker",
            "/var//docker",
            "/var/lib/docker/",
            "/var/lib/../docker",
            "C:\\docker",
            "/var/\\docker",
            "/var/\ndocker",
        ):
            with self.subTest(value=value):
                with self.assertRaises(runtime.RuntimeRefused):
                    volumes.daemon_root(json.dumps({"root": value, "os": "linux"}))
        for value in (
            {"root": self.root, "os": "windows"},
            {"root": self.root, "os": "linux", "extra": True},
        ):
            with self.assertRaises(runtime.RuntimeRefused):
                volumes.daemon_root(json.dumps(value))

    def test_strict_bounded_metadata_parser_has_fixed_errors(self):
        for raw in (
            '{"name":"one","name":"synthetic_do_not_echo"}',
            '{"options":NaN}',
            "[{}]",
            "{broken",
            "x" * 16385,
            "[" * 1500 + "]" * 1500,
            "\ud800",
            None,
        ):
            with self.subTest(kind=type(raw).__name__):
                with self.assertRaisesRegex(
                    runtime.RuntimeRefused, "^worker_runtime_refused$"
                ):
                    volumes.parse_document(raw)

    def test_changed_container_or_daemon_root_refuses_and_releases_observation_lock(
        self,
    ):
        for change in ("container", "root"):
            with self.subTest(change=change):
                observer, self.calls = self.observer(), []
                if change == "container":
                    observer._bound.side_effect = [
                        {"mounts": self.mounts},
                        {"mounts": []},
                    ]
                original = self.command

                def changing(argv, **options):
                    reply = original(argv, **options)
                    if change == "root" and len(self.calls) == 4:
                        reply.stdout = json.dumps(
                            {"root": "/other/docker", "os": "linux"}
                        )
                    return reply

                with patch.object(runtime.subprocess, "run", changing):
                    with self.assertRaises(runtime.RuntimeRefused):
                        volumes.managed_sources(observer, self.identity)
                self.assertIsNone(observer._deadline)
                self.assertFalse(observer._observation_lock.locked())

    def test_busy_observer_or_failed_cli_is_not_a_pathname_fallback(self):
        observer = self.observer()
        observer._observation_lock.acquire()
        observer._deadline = 123
        try:
            with patch.object(runtime.subprocess, "run") as command:
                with self.assertRaises(runtime.RuntimeRefused):
                    volumes.managed_sources(observer, self.identity)
            command.assert_not_called()
            self.assertEqual(observer._deadline, 123)
        finally:
            observer._observation_lock.release()
        with patch.object(
            runtime.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                [], 1, "synthetic_do_not_echo", "synthetic_do_not_echo"
            ),
        ):
            with self.assertRaisesRegex(
                runtime.RuntimeRefused, "^worker_runtime_refused$"
            ):
                volumes.managed_sources(self.observer(), self.identity)

    def created_observer(self):
        observer = self.observer()
        observer._created = Mock(
            side_effect=[{"mounts": copy.deepcopy(self.mounts)}] * 2
        )
        observer.daemon = Mock(return_value=self.identity.daemon_id)
        # Explicit synthetic direct-observation model, never loaded from JSON.
        created = runtime.ObservedCreated(
            self.identity.daemon_id,
            self.identity.container_id,
            self.identity.image_id,
            self.identity.project,
            self.layout,
            _proof=runtime._CREATED_PROOF,
        )
        return observer, created

    def test_created_custody_reuses_volume_guards_without_running_identity(self):
        observer, created = self.created_observer()
        self.calls = []
        with (
            patch.object(runtime.subprocess, "run", self.command),
            patch("pathlib.Path.resolve") as resolve,
            patch("pathlib.Path.stat") as stat,
        ):
            result = volumes.managed_sources(observer, created)
        self.assertEqual(result, tuple(PurePosixPath(m["Source"]) for m in self.mounts))
        resolve.assert_not_called()
        stat.assert_not_called()
        observer._bound.assert_not_called()
        self.assertEqual(observer.daemon.call_count, 2)
        self.assertEqual(
            observer._created.call_args_list,
            [
                ((created.container_id, created.image_id, created.project),),
                ((created.container_id, created.image_id, created.project),),
            ],
        )
        self.assertEqual(len(self.calls), 4)
        self.assertTrue(all(0 < options["timeout"] <= 15 for _, options in self.calls))
        self.assertIsNone(observer._deadline)
        self.assertFalse(observer._observation_lock.locked())

    def test_created_serialized_lookalike_or_subclass_is_refused_before_observation(
        self,
    ):
        from types import SimpleNamespace

        class CreatedSubclass(runtime.ObservedCreated):
            pass

        observer, created = self.created_observer()
        fields = vars(created)
        subclass = CreatedSubclass(**fields, _proof=runtime._CREATED_PROOF)
        for value in (fields, SimpleNamespace(**fields), subclass):
            with self.subTest(kind=type(value).__name__):
                with patch.object(runtime.subprocess, "run") as command:
                    with self.assertRaises(runtime.RuntimeRefused):
                        volumes.managed_sources(observer, value)
                command.assert_not_called()
        observer._created.assert_not_called()
        observer.daemon.assert_not_called()
        observer._bound.assert_not_called()
        self.assertIsNone(observer._deadline)
        self.assertFalse(observer._observation_lock.locked())

    def test_created_layout_or_daemon_mismatch_stops_before_profile_and_volume_reads(
        self,
    ):
        for changed in ("layout", "daemon"):
            with self.subTest(changed=changed):
                observer, created = self.created_observer()
                if changed == "layout":
                    observer.layout = runtime.WorkerLayout(
                        "/foreign/trust",
                        "/foreign/admission",
                        "other-state",
                        "other-ready",
                    )
                else:
                    observer.daemon.return_value = "other-daemon"
                with patch.object(runtime.subprocess, "run") as command:
                    with self.assertRaises(runtime.RuntimeRefused):
                        volumes.managed_sources(observer, created)
                command.assert_not_called()
                observer._created.assert_not_called()
                observer._bound.assert_not_called()
                self.assertIsNone(observer._deadline)
                self.assertFalse(observer._observation_lock.locked())

    def test_created_second_read_rejects_profile_state_or_daemon_drift(self):
        for changed in ("profile", "state", "daemon"):
            with self.subTest(changed=changed):
                observer, created = self.created_observer()
                self.calls = []
                if changed == "profile":
                    observer._created.side_effect = [
                        {"mounts": self.mounts},
                        {"mounts": self.mounts, "changed": True},
                    ]
                elif changed == "state":
                    observer._created.side_effect = [
                        {"mounts": self.mounts},
                        runtime.RuntimeRefused("worker_runtime_refused"),
                    ]
                else:
                    observer.daemon.side_effect = [created.daemon_id, "other-daemon"]
                with patch.object(runtime.subprocess, "run", self.command):
                    with self.assertRaisesRegex(
                        runtime.RuntimeRefused, "^worker_runtime_refused$"
                    ):
                        volumes.managed_sources(observer, created)
                self.assertEqual(len(self.calls), 3)
                observer._bound.assert_not_called()
                self.assertIsNone(observer._deadline)
                self.assertFalse(observer._observation_lock.locked())

    def test_created_still_refuses_remote_volumes_and_changed_daemon_root(self):
        for changed in ("volume", "root"):
            with self.subTest(changed=changed):
                observer, created = self.created_observer()
                self.calls = []
                row = self.rows[self.layout.state_volume]
                if changed == "volume":
                    row["options"] = {"type": "nfs", "device": ":/private"}
                original = self.command

                def changing(argv, **options):
                    reply = original(argv, **options)
                    if changed == "root" and len(self.calls) == 4:
                        reply.stdout = json.dumps(
                            {"root": "/other/docker", "os": "linux"}
                        )
                    return reply

                with patch.object(runtime.subprocess, "run", changing):
                    with self.assertRaises(runtime.RuntimeRefused):
                        volumes.managed_sources(observer, created)
                row["options"] = None
                observer._bound.assert_not_called()
                self.assertIsNone(observer._deadline)
                self.assertFalse(observer._observation_lock.locked())

    def test_created_failure_preserves_fixed_checkpoint_and_releases_lock(self):
        observer, created = self.created_observer()
        error = runtime.RuntimeRefused("synthetic_do_not_echo")
        error.checkpoint = "volume_metadata"
        observer._created.side_effect = error
        with patch.object(runtime.subprocess, "run") as command:
            with self.assertRaisesRegex(
                runtime.RuntimeRefused, "^worker_runtime_refused$"
            ) as caught:
                volumes.managed_sources(observer, created)
        self.assertEqual(caught.exception.checkpoint, "volume_metadata")
        command.assert_not_called()
        self.assertEqual(observer._created.call_count, 1)
        self.assertIsNone(observer._deadline)
        self.assertFalse(observer._observation_lock.locked())


if __name__ == "__main__":
    unittest.main()
