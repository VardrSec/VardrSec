"""Refusal tests for the trusted-host observer; no container or tool execution."""

import copy
from dataclasses import FrozenInstanceError, replace
import json
import io
import subprocess
import tarfile
import unittest
from unittest.mock import patch

import worker_runtime as runtime
import worker_volumes as volumes


class WorkerRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.identity = runtime.RuntimeIdentity(
            "daemon-id",
            "a" * 64,
            "sha256:" + "b" * 64,
            "owned-fixture",
            "2026-11-05T20:00:00.123456789Z",
            "c" * 64,
        )
        self.layout = runtime.WorkerLayout(
            "/owned/trust",
            "/owned/admission",
            "owned-fixture_runner-state",
            "owned-fixture_ready-fresh",
        )
        self.info = {
            "id": self.identity.container_id,
            "image": self.identity.image_id,
            "user": "0:0",
            "entrypoint": ["/usr/local/bin/vardr-worker-owner"],
            "command": [],
            "healthcheck": None,
            "labels": {
                "com.docker.compose.project": "owned-fixture",
                "com.docker.compose.service": "managed-worker",
                "com.docker.compose.oneoff": "False",
                "io.vardrsec.managed-worker": "1",
            },
            "mounts": [
                {
                    "Type": "volume",
                    "Name": self.layout.readiness_volume,
                    "Source": "/var/lib/docker/volumes/"
                    + self.layout.readiness_volume
                    + "/_data",
                    "Destination": "/run/vardr-worker-ready",
                    "RW": True,
                },
                {
                    "Type": "volume",
                    "Name": self.layout.state_volume,
                    "Source": "/var/lib/docker/volumes/"
                    + self.layout.state_volume
                    + "/_data",
                    "Destination": "/home/runner/.vardrmap",
                    "RW": True,
                },
                {
                    "Type": "bind",
                    "Source": self.layout.trust_source,
                    "Destination": "/trust",
                    "RW": False,
                },
                {
                    "Type": "bind",
                    "Source": self.layout.admission_source,
                    "Destination": "/run/vardr-worker-admission",
                    "RW": False,
                },
            ],
            "state": {
                "Status": "exited",
                "Running": False,
                "Paused": False,
                "Restarting": False,
                "Dead": False,
                "ExitCode": 137,
                "StartedAt": self.identity.started_at,
                "FinishedAt": "2026-11-05T20:00:30.123456789Z",
            },
            "host": {
                "pid": "",
                "privileged": False,
                "init": False,
                "auto_remove": False,
                "readonly_root": True,
                "ipc": "private",
                "cgroup": "private",
                "devices": [],
                "device_requests": [],
                "port_bindings": {},
                "publish_all": False,
                "memory": 536870912,
                "pids": 64,
                "nano_cpus": 1000000000,
                "oom_disable": False,
                "tmpfs": {
                    "/tmp": "rw,noexec,nosuid,nodev,size=67108864,uid=10001,gid=10001,mode=0700",
                },
                "restart": "no",
                "cap_add": ["SETUID", "SETGID", "SETPCAP"],
                "cap_drop": ["ALL"],
                "security": ["no-new-privileges:true"],
            },
        }
        self.calls = []
        self.inspect_count = 0
        self.endpoint = "npipe:////./pipe/dockerDesktopLinuxEngine"
        self.daemon = "daemon-id"
        self.wait = "137"
        self.change_final = False
        self.ready = {
            "schema": "vardr.worker-owner-ready/1",
            "owner_nonce": "c" * 64,
            "owner_pid": 1,
            "owner_uid": 10000,
            "runner_uid": 10001,
            "no_new_privs": True,
            "capabilities": {
                name: "0" * 16
                for name in (
                    "effective",
                    "permitted",
                    "inheritable",
                    "ambient",
                    "bounding",
                )
            },
        }
        self.archive_uid, self.archive_mode = 10000, 0o400
        self.archive_type = tarfile.REGTYPE
        self.volume_rows = {
            name: {
                "name": name,
                "driver": "local",
                "scope": "local",
                "options": None,
                "source": "/var/lib/docker/volumes/" + name + "/_data",
                "project": self.identity.project,
                "volume": logical,
                "ready": "1" if logical == "worker-ready" else None,
            }
            for name, logical in (
                (self.layout.state_volume, "runner-state"),
                (self.layout.readiness_volume, "worker-ready"),
            )
        }

    def command(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        args = argv[3:]
        if args[:2] == ["context", "inspect"]:
            value = json.dumps(self.endpoint)
        elif args[0] == "info":
            value = (
                json.dumps({"root": "/var/lib/docker", "os": "linux"})
                if args[-1] == volumes.DAEMON_FORMAT
                else json.dumps(self.daemon)
            )
        elif args[:2] == ["volume", "inspect"]:
            value = json.dumps(self.volume_rows[args[-1]])
        elif args[:2] == ["container", "wait"]:
            value = self.wait
        elif args[:2] == ["container", "cp"]:
            raw = json.dumps(self.ready).encode()
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w:") as target:
                entry = tarfile.TarInfo("owner.json")
                entry.uid, entry.gid, entry.mode = (
                    self.archive_uid,
                    10000,
                    self.archive_mode,
                )
                entry.type = self.archive_type
                entry.size = len(raw) if entry.isfile() else 0
                entry.linkname = "/untrusted" if entry.issym() else ""
                target.addfile(entry, io.BytesIO(raw) if entry.isfile() else None)
            value = archive.getvalue()
        elif args[:2] == ["container", "inspect"]:
            self.inspect_count += 1
            info = copy.deepcopy(self.info)
            if self.change_final and self.inspect_count == 3:
                info["state"]["StartedAt"] = "2026-11-05T20:01:00Z"
            value = json.dumps(info)
        else:
            self.fail("unexpected CLI operation")
        return subprocess.CompletedProcess(argv, 0, value, "")

    def observe(self):
        with patch.object(runtime.subprocess, "run", self.command):
            return runtime.LocalDocker("desktop-linux", self.layout).observe_exit(
                self.identity
            )

    def test_exact_retained_exit_is_observed_without_mutating_daemon(self):
        proof = self.observe()
        self.assertEqual(proof.identity, self.identity)
        self.assertEqual(proof.exit_code, 137)
        self.assertEqual(self.inspect_count, 3)
        self.assertTrue(all(0 < kw["timeout"] <= 15 for _, kw in self.calls))
        self.assertTrue(
            all(
                argv[:3] == ["docker", "--context", "desktop-linux"]
                for argv, _ in self.calls
            )
        )
        self.assertFalse(
            any("Config.Env" in arg for argv, _ in self.calls for arg in argv)
        )
        with self.assertRaises(FrozenInstanceError):
            proof.exit_code = 0

    def test_arbitrary_inspection_document_cannot_construct_proof(self):
        with self.assertRaises(runtime.RuntimeRefused):
            runtime.ObservedExit(self.identity, self.info["state"]["FinishedAt"], 137)
        with self.assertRaises(runtime.RuntimeRefused):
            runtime.LocalDocker("desktop-linux", self.layout).observe_exit(
                dict(self.info)
            )

    def test_remote_daemon_or_changed_selected_engine_is_refused(self):
        for endpoint, daemon in [
            ("tcp://localhost:2375", "daemon-id"),
            ("ssh://host", "daemon-id"),
            (self.endpoint, "other-daemon"),
        ]:
            with self.subTest(endpoint=endpoint):
                self.endpoint, self.daemon = endpoint, daemon
                with self.assertRaises(runtime.RuntimeRefused):
                    self.observe()

    def test_wrong_incarnation_image_owner_or_pid_boundary_remains_held(self):
        alterations = [
            ("image", "sha256:" + "d" * 64),
            ("id", "d" * 64),
            ("user", "10001:10001"),
            ("entrypoint", ["sh"]),
            ("command", ["unreviewed"]),
            ("healthcheck", {"Test": ["CMD", "python", "-c", "pass"]}),
            ("state.StartedAt", "2026-11-05T19:59:59Z"),
            ("host.pid", "host"),
            ("host.privileged", True),
            ("host.init", True),
            ("host.auto_remove", True),
            ("host.readonly_root", False),
            ("host.ipc", "host"),
            ("host.restart", "unless-stopped"),
            ("host.cap_add", ["SETUID", "SETGID", "SETPCAP", "KILL"]),
            ("host.cap_drop", []),
            ("host.security", []),
            ("host.security", ["no-new-privileges:true", "seccomp=unconfined"]),
            ("host.cgroup", "host"),
            ("host.memory", 0),
            ("host.pids", -1),
            ("host.nano_cpus", 0),
            ("host.oom_disable", True),
            ("host.devices", [{"PathOnHost": "/dev/mem"}]),
            ("host.port_bindings", {"80/tcp": [{"HostPort": "8080"}]}),
            ("labels.com.docker.compose.project", "somebody-else"),
        ]
        original = copy.deepcopy(self.info)
        for key, value in alterations:
            with self.subTest(key=key):
                self.info = copy.deepcopy(original)
                section, _, field = key.partition(".")
                if field:
                    self.info[section][field] = value
                else:
                    self.info[key] = value
                with self.assertRaises(runtime.RuntimeRefused):
                    self.observe()

    def test_ambiguous_or_inconsistent_daemon_state_is_never_exit_proof(self):
        original = copy.deepcopy(self.info["state"])
        changes = [
            ("Status", "created"),
            ("Status", "dead"),
            ("Running", True),
            ("Paused", True),
            ("Restarting", True),
            ("Dead", True),
            ("ExitCode", 1),
            ("ExitCode", True),
            ("FinishedAt", "0001-01-01T00:00:00Z"),
            ("FinishedAt", "2026-99-99T20:00:30Z"),
            ("FinishedAt", "2026-11-05T20:00:00.123456788Z"),
        ]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                self.info["state"] = {**original, key: value}
                with self.assertRaises(runtime.RuntimeRefused):
                    self.observe()

    def test_restart_on_final_inspection_refuses_before_intent(self):
        self.change_final = True
        with self.assertRaises(runtime.RuntimeRefused):
            self.observe()

    def test_timeout_missing_container_and_malformed_reply_do_not_create_proof(self):
        for error in [
            subprocess.TimeoutExpired(["docker"], 15),
            OSError("private failure"),
        ]:
            with self.subTest(kind=type(error).__name__):
                with patch.object(runtime.subprocess, "run", side_effect=error):
                    with self.assertRaisesRegex(
                        runtime.RuntimeRefused, "^worker_runtime_refused$"
                    ):
                        runtime.LocalDocker("desktop-linux", self.layout).observe_exit(
                            self.identity
                        )
        for value in ["", "[]", "null", "not-json", "x" * (1024 * 1024 + 1)]:
            with self.subTest(length=len(value)):
                with patch.object(
                    runtime.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, value, ""),
                ):
                    with self.assertRaises(runtime.RuntimeRefused):
                        runtime.LocalDocker("desktop-linux", self.layout).observe_exit(
                            self.identity
                        )

    def test_identity_rejects_short_ids_invalid_timestamps_and_nonces(self):
        for change in [
            {"container_id": "a" * 12},
            {"started_at": "2026-13-01T00:00:00Z"},
            {"owner_nonce": "true"},
        ]:
            with self.subTest(change=change):
                with self.assertRaises(runtime.RuntimeRefused):
                    replace(self.identity, **change)

    def capture(self):
        with patch.object(runtime.subprocess, "run", self.command):
            return runtime.LocalDocker("desktop-linux", self.layout).capture_running(
                container_id=self.identity.container_id,
                image_id=self.identity.image_id,
                project=self.identity.project,
            )

    def capture_with_final_change(self, change, *, protocol="persistent-v3"):
        self.info["state"].update(
            Status="running",
            Running=True,
            ExitCode=0,
            FinishedAt="0001-01-01T00:00:00Z",
            Pid=314,
        )
        self.ready["schema"] = {
            "legacy-v1": "vardr.worker-owner-ready/1",
            "finite-v2": "vardr.worker-owner-ready/2",
            "persistent-v3": "vardr.worker-owner-ready/3",
        }[protocol]

        def command(argv, **options):
            result = self.command(argv, **options)
            if argv[3:5] == ["container", "inspect"] and self.inspect_count == 3:
                value = json.loads(result.stdout)
                change(value)
                result.stdout = json.dumps(value)
            return result

        with patch.object(runtime.subprocess, "run", command):
            return runtime.LocalDocker(
                "desktop-linux",
                self.layout,
                protocol=protocol,
                max_attempts=2 if protocol == "finite-v2" else None,
            ).capture_running(
                container_id=self.identity.container_id,
                image_id=self.identity.image_id,
                project=self.identity.project,
            )

    def test_mount_order_only_preserves_capture_in_every_protocol(self):
        for protocol in ("legacy-v1", "finite-v2", "persistent-v3"):
            with self.subTest(protocol=protocol):
                self.setUp()
                self.assertEqual(
                    self.capture_with_final_change(
                        lambda value: value["mounts"].reverse(), protocol=protocol
                    ),
                    self.identity,
                )
                self.assertEqual(self.inspect_count, 3)
                self.assertEqual(len(self.calls), 16)

    def test_bound_mount_order_is_copied_without_dropping_fields_or_mutating_input(
        self,
    ):
        self.info["FutureInspectField"] = {"public-fixture": True}
        self.info["mounts"][0]["FutureMountField"] = {"public-fixture": True}
        original = copy.deepcopy(self.info)
        observer = runtime.LocalDocker("desktop-linux", self.layout)
        with (
            patch.object(runtime.subprocess, "run", self.command),
            patch.object(observer, "inspect", return_value=self.info),
        ):
            bound = observer._bound(self.identity)
        self.assertEqual(self.info, original)
        self.assertIsNot(bound, self.info)
        self.assertIsNot(bound["mounts"], self.info["mounts"])
        self.assertEqual(
            bound,
            {
                **original,
                "mounts": sorted(
                    original["mounts"], key=lambda row: row["Destination"]
                ),
            },
        )
        self.assertTrue(
            all(
                any(row is source for source in self.info["mounts"])
                for row in bound["mounts"]
            )
        )

    def test_mount_permutation_cannot_hide_other_inspect_changes(self):
        changes = [
            (
                "Source",
                "volume_metadata",
                lambda value: value["mounts"][0].update(Source="/untrusted"),
            ),
            ("RW", "mounts", lambda value: value["mounts"][0].update(RW=False)),
            (
                "Name",
                "mounts",
                lambda value: value["mounts"][0].update(Name="another-volume"),
            ),
            (
                "unknown_mount_field",
                "incarnation_recheck",
                lambda value: value["mounts"][0].update(FutureMountField=True),
            ),
            (
                "propagation",
                "incarnation_recheck",
                lambda value: value["mounts"][0].update(Propagation="rshared"),
            ),
            (
                "Pid",
                "incarnation_recheck",
                lambda value: value["state"].update(Pid=315),
            ),
            (
                "ExitCode",
                "incarnation_recheck",
                lambda value: value["state"].update(ExitCode=1),
            ),
            (
                "FinishedAt",
                "incarnation_recheck",
                lambda value: value["state"].update(FinishedAt="2026-11-05T20:01:00Z"),
            ),
            (
                "StartedAt",
                "profile",
                lambda value: value["state"].update(StartedAt="2026-11-05T20:01:00Z"),
            ),
            (
                "unknown_state_field",
                "incarnation_recheck",
                lambda value: value["state"].update(FutureStateField=True),
            ),
            (
                "image",
                "profile",
                lambda value: value.update(image="sha256:" + "d" * 64),
            ),
            (
                "privileged",
                "profile",
                lambda value: value["host"].update(privileged=True),
            ),
            (
                "cap_add_order",
                "incarnation_recheck",
                lambda value: value["host"]["cap_add"].reverse(),
            ),
        ]
        for name, checkpoint, change in changes:
            with self.subTest(field=name):
                self.setUp()

                def changed(value):
                    change(value)
                    value["mounts"].reverse()

                with self.assertRaises(runtime.RuntimeRefused) as caught:
                    self.capture_with_final_change(changed)
                self.assertEqual(caught.exception.checkpoint, checkpoint)

    def test_duplicate_missing_or_untyped_mount_destination_still_refuses(self):
        for change in (
            lambda value: value["mounts"].append(copy.deepcopy(value["mounts"][0])),
            lambda value: value["mounts"].pop(),
            lambda value: value["mounts"][0].update(Destination=None),
        ):
            with self.subTest(change=change):
                self.setUp()
                with self.assertRaises(runtime.RuntimeRefused) as caught:
                    self.capture_with_final_change(change)
                self.assertEqual(caught.exception.checkpoint, "mounts")

    def test_mount_order_only_preserves_exact_exit_rechecks(self):
        def command(argv, **options):
            result = self.command(argv, **options)
            if argv[3:5] == ["container", "inspect"] and self.inspect_count == 2:
                value = json.loads(result.stdout)
                value["mounts"].reverse()
                result.stdout = json.dumps(value)
            return result

        with patch.object(runtime.subprocess, "run", command):
            proof = runtime.LocalDocker("desktop-linux", self.layout).observe_exit(
                self.identity
            )
        self.assertEqual(proof.identity, self.identity)
        self.assertEqual(proof.exit_code, 137)
        self.assertEqual(self.inspect_count, 3)

    def test_runtime_admission_nonce_is_derived_from_actual_owner_archive(self):
        self.info["state"].update(Status="running", Running=True)
        self.assertEqual(self.capture(), self.identity)
        self.assertEqual(self.inspect_count, 3)
        self.assertTrue(any(argv[3:5] == ["container", "cp"] for argv, _ in self.calls))
        self.assertFalse(any("exec" in argv for argv, _ in self.calls))

    def test_capture_refusals_identify_only_the_fixed_failed_check(self):
        for checkpoint in sorted(runtime.CAPTURE_CHECKPOINTS):
            with self.subTest(checkpoint=checkpoint):
                self.setUp()
                self.info["state"].update(Status="running", Running=True)
                if checkpoint == "daemon":
                    self.endpoint = "ssh://private-canary-host"
                elif checkpoint == "identity":
                    self.info["state"]["StartedAt"] = "private-canary-timestamp"
                elif checkpoint == "mounts":
                    self.info["mounts"][0]["RW"] = False
                elif checkpoint == "tmpfs":
                    self.info["host"]["tmpfs"]["/tmp"] = "private-canary-options"
                elif checkpoint == "profile":
                    self.info["user"] = "10001:10001"
                elif checkpoint == "volume_metadata":
                    self.volume_rows[self.layout.state_volume]["options"] = {
                        "device": "/private-canary-path"
                    }
                elif checkpoint == "running_state":
                    self.info["state"].update(Status="exited", Running=False)
                elif checkpoint == "readiness_archive":
                    self.archive_uid = 10001
                elif checkpoint == "readiness_schema":
                    self.ready["owner_uid"] = 10001

                def command(argv, **kwargs):
                    if (
                        checkpoint == "network_binding"
                        and runtime._NETWORK_INSPECT in argv
                    ):
                        return subprocess.CompletedProcess(
                            argv, 0, '{"id":"private-canary"}', ""
                        )
                    if checkpoint == "inspect" and argv[3:5] == [
                        "container",
                        "inspect",
                    ]:
                        return subprocess.CompletedProcess(
                            argv, 0, "private-canary-invalid-json", ""
                        )
                    if checkpoint == "readiness_copy" and argv[3:5] == [
                        "container",
                        "cp",
                    ]:
                        return subprocess.CompletedProcess(
                            argv, 1, b"private-canary-output", b"private-canary-error"
                        )
                    result = self.command(argv, **kwargs)
                    if (
                        checkpoint == "incarnation_recheck"
                        and argv[3:5] == ["container", "inspect"]
                        and self.inspect_count == 3
                    ):
                        value = json.loads(result.stdout)
                        value["state"]["Pid"] = 314
                        result.stdout = json.dumps(value)
                    return result

                with (
                    patch.object(runtime.subprocess, "run", command),
                    self.assertRaises(runtime.RuntimeRefused) as caught,
                ):
                    observer = runtime.LocalDocker("desktop-linux", self.layout)
                    if checkpoint == "network_binding":
                        observer.network_binding = ("owned_runner", "f" * 64)
                    observer.capture_running(
                        container_id=self.identity.container_id,
                        image_id=self.identity.image_id,
                        project=self.identity.project,
                    )
                self.assertEqual(caught.exception.args, ("worker_runtime_refused",))
                self.assertEqual(caught.exception.checkpoint, checkpoint)

    def test_nested_capture_metadata_preserves_only_known_fixed_checks(self):
        error = runtime.RuntimeRefused("worker_runtime_refused")
        error.checkpoint = "readiness_archive"
        self.assertIs(runtime._capture_refused(error, "readiness_copy"), error)
        self.assertEqual(error.checkpoint, "readiness_archive")
        for value in ("private-canary-check", ["private-canary"], {"private": True}):
            with self.subTest(kind=type(value).__name__):
                error.checkpoint = value
                self.assertIs(runtime._capture_refused(error, "profile"), error)
                self.assertEqual(error.checkpoint, "profile")
                self.assertEqual(error.args, ("worker_runtime_refused",))

    def test_sequence_mode_requires_actual_v2_owner_without_downgrade(self):
        self.info["state"].update(Status="running", Running=True)
        observer = runtime.LocalDocker("desktop-linux", self.layout, max_attempts=2)
        with patch.object(runtime.subprocess, "run", self.command):
            with self.assertRaises(runtime.RuntimeRefused):
                observer.capture_running(
                    container_id=self.identity.container_id,
                    image_id=self.identity.image_id,
                    project=self.identity.project,
                )
            self.ready["schema"] = "vardr.worker-owner-ready/2"
            self.assertEqual(
                observer.capture_running(
                    container_id=self.identity.container_id,
                    image_id=self.identity.image_id,
                    project=self.identity.project,
                ),
                self.identity,
            )
            with self.assertRaises(runtime.RuntimeRefused):
                self.capture()

    def test_unready_or_wrong_owner_file_never_produces_runtime_admission(self):
        self.info["state"].update(Status="running", Running=True)
        original = copy.deepcopy(self.ready)
        for key, value in [
            ("owner_uid", 10001),
            ("owner_pid", 2),
            ("no_new_privs", False),
            ("owner_nonce", "short"),
            ("extra", "untrusted"),
            ("capabilities", {**original["capabilities"], "bounding": "1" * 16}),
        ]:
            with self.subTest(key=key):
                self.ready = {**original, key: value}
                with self.assertRaises(runtime.RuntimeRefused):
                    self.capture()
        self.ready = original
        for uid, mode, kind in [
            (10001, 0o400, tarfile.REGTYPE),
            (10000, 0o600, tarfile.REGTYPE),
            (10000, 0o400, tarfile.SYMTYPE),
        ]:
            with self.subTest(uid=uid, mode=mode, kind=kind):
                self.archive_uid, self.archive_mode, self.archive_type = uid, mode, kind
                with self.assertRaises(runtime.RuntimeRefused):
                    self.capture()

    def test_code_socket_or_extra_mounts_and_writable_admission_refuse(self):
        original = copy.deepcopy(self.info["mounts"])
        for destination in [
            "/usr/local/bin/vardr-worker-owner",
            "/var/run/docker.sock",
            "/unreviewed",
        ]:
            with self.subTest(destination=destination):
                self.info["mounts"] = original + [
                    {
                        "Type": "bind",
                        "Source": "/untrusted",
                        "Destination": destination,
                        "RW": False,
                    }
                ]
                with self.assertRaises(runtime.RuntimeRefused):
                    self.observe()
        self.info["mounts"] = copy.deepcopy(original)
        next(
            m
            for m in self.info["mounts"]
            if m["Destination"] == "/run/vardr-worker-admission"
        )["RW"] = True
        with self.assertRaises(runtime.RuntimeRefused):
            self.observe()

    def test_ready_volume_must_be_distinct_exact_and_not_tmpfs_or_bind(self):
        with self.assertRaises(runtime.RuntimeRefused):
            replace(self.layout, readiness_volume=self.layout.state_volume)
        original = copy.deepcopy(self.info["mounts"])
        for change in (
            {"Type": "tmpfs"},
            {"Type": "bind", "Source": "/untrusted"},
            {"Name": "stale-other-volume"},
            {"RW": False},
        ):
            with self.subTest(change=change):
                self.info["mounts"] = copy.deepcopy(original)
                mount = next(
                    m
                    for m in self.info["mounts"]
                    if m["Destination"] == "/run/vardr-worker-ready"
                )
                mount.update(change)
                with self.assertRaises(runtime.RuntimeRefused):
                    self.observe()
        self.info["mounts"] = original
        self.info["host"]["tmpfs"]["/run/vardr-worker-ready"] = (
            "rw,noexec,nosuid,nodev,size=65536,uid=10000,gid=10000,mode=0700"
        )
        with self.assertRaises(runtime.RuntimeRefused):
            self.observe()

    def test_nondefault_ready_volume_is_refused_before_copy(self):
        self.info["state"].update(Status="running", Running=True)
        self.volume_rows[self.layout.readiness_volume]["options"] = {
            "type": "none",
            "o": "bind",
            "device": "/unreviewed",
        }
        with self.assertRaises(runtime.RuntimeRefused):
            self.capture()
        self.assertFalse(
            any(argv[3:5] == ["container", "cp"] for argv, _ in self.calls)
        )

    def test_only_reviewed_desktop_drive_translation_matches_host_bind(self):
        self.layout = replace(
            self.layout,
            trust_source="C:/owned/trust",
            admission_source="C:/owned/admission",
        )
        for mount in self.info["mounts"]:
            if mount["Destination"] == "/trust":
                mount["Source"] = "/run/desktop/mnt/host/c/owned/trust"
            if mount["Destination"] == "/run/vardr-worker-admission":
                mount["Source"] = "/host_mnt/c/owned/admission"
        self.assertEqual(self.observe().identity, self.identity)
        next(m for m in self.info["mounts"] if m["Destination"] == "/trust")[
            "Source"
        ] = "/run/desktop/mnt/host/c/elsewhere"
        with self.assertRaises(runtime.RuntimeRefused):
            self.observe()

    def test_direct_recheck_rejects_restart_between_observation_and_report_intent(self):
        proof = self.observe()
        with patch.object(runtime.subprocess, "run", self.command):
            runtime.LocalDocker("desktop-linux", self.layout).confirm_exit(proof)
            self.info["state"]["StartedAt"] = "2026-11-05T20:01:00Z"
            with self.assertRaises(runtime.RuntimeRefused):
                runtime.LocalDocker("desktop-linux", self.layout).confirm_exit(proof)

    def network_capture(self, projection=None, *, changed=False, raw=None):
        self.info["state"].update(Status="running", Running=True)
        selected = ("owned_runner", "f" * 64)
        self.network_reads = 0
        observer = runtime.LocalDocker(
            "desktop-linux", self.layout, network_binding=selected
        )
        original = self.command

        def command(argv, **options):
            if (
                argv[3:6] == ["container", "inspect", "--format"]
                and argv[6] == runtime._NETWORK_INSPECT
            ):
                self.network_reads += 1
                value = (
                    projection
                    if projection is not None
                    else {
                        "id": self.identity.container_id,
                        "mode": selected[0],
                        "attachments": [{"name": selected[0], "id": selected[1]}, None],
                    }
                )
                if changed and self.network_reads == 2:
                    value = {
                        **value,
                        "attachments": [{"name": selected[0], "id": "e" * 64}, None],
                    }
                self.calls.append((argv, options))
                return subprocess.CompletedProcess(
                    argv, 0, raw if raw is not None else json.dumps(value), ""
                )
            return original(argv, **options)

        with patch.object(runtime.subprocess, "run", command):
            return observer.capture_running(
                container_id=self.identity.container_id,
                image_id=self.identity.image_id,
                project=self.identity.project,
            )

    def test_network_pin_accepts_only_closed_literal_name_and_full_id_tuple(self):
        for value in (
            [],
            {},
            ("runner",),
            ("runner", "f" * 12),
            ["runner", "f" * 64],
            ("--flag", "f" * 64),
            ("runner", True),
            ("runner\nprivate", "f" * 64),
        ):
            with (
                self.subTest(kind=type(value).__name__),
                patch.object(runtime.subprocess, "run") as command,
            ):
                with self.assertRaises(runtime.RuntimeRefused):
                    runtime.LocalDocker(
                        "desktop-linux", self.layout, network_binding=value
                    )
                command.assert_not_called()
        self.assertIsNone(
            runtime.LocalDocker("desktop-linux", self.layout).network_binding
        )

    def test_network_pin_joins_both_actual_bound_reads_to_owner_nonce_capture(self):
        self.assertEqual(self.network_capture(), self.identity)
        self.assertEqual(self.network_reads, 2)
        self.assertEqual(self.inspect_count, 3)
        network_calls = [
            argv for argv, _ in self.calls if runtime._NETWORK_INSPECT in argv
        ]
        self.assertEqual(
            network_calls,
            [
                [
                    "docker",
                    "--context",
                    "desktop-linux",
                    "container",
                    "inspect",
                    "--format",
                    runtime._NETWORK_INSPECT,
                    self.identity.container_id,
                ]
            ]
            * 2,
        )
        self.assertNotIn(".Config.Env", runtime._NETWORK_INSPECT)
        self.assertNotIn("IPAddress", runtime._NETWORK_INSPECT)
        self.assertFalse(any("exec" in argv for argv, _ in self.calls))

    def test_network_pin_refuses_unallocated_missing_foreign_extra_or_ambiguous_slots(
        self,
    ):
        good = {
            "id": self.identity.container_id,
            "mode": "owned_runner",
            "attachments": [{"name": "owned_runner", "id": "f" * 64}, None],
        }
        changes = [
            dict(mode="bridge"),
            dict(id="e" * 64),
            dict(attachments=[]),
            dict(attachments=None),
            dict(attachments=[None]),
            dict(attachments=[{"name": "owned_runner", "id": ""}, None]),
            dict(attachments=[{"name": "foreign", "id": "f" * 64}, None]),
            dict(attachments=[{"name": "owned_runner", "id": "e" * 64}, None]),
            dict(
                attachments=[
                    {"name": "owned_runner", "id": "f" * 64, "extra": True},
                    None,
                ]
            ),
            dict(attachments=[good["attachments"][0], good["attachments"][0], None]),
            dict(extra="private-canary"),
        ]
        for change in changes:
            with self.subTest(change=sorted(change)):
                self.setUp()
                with self.assertRaises(runtime.RuntimeRefused) as caught:
                    self.network_capture({**good, **change})
                self.assertEqual(caught.exception.args, ("worker_runtime_refused",))
                self.assertEqual(caught.exception.checkpoint, "network_binding")
                self.assertFalse(
                    any(argv[3:5] == ["container", "cp"] for argv, _ in self.calls)
                )

    def test_network_projection_rejects_duplicate_malformed_and_oversized_documents(
        self,
    ):
        for raw in (
            '{"id":"one","id":"private-canary"}',
            '{"mode":NaN}',
            "[]",
            "{broken",
            "x" * 16385,
        ):
            with self.subTest(length=len(raw)):
                self.setUp()
                with self.assertRaises(runtime.RuntimeRefused) as caught:
                    self.network_capture(raw=raw)
                self.assertEqual(caught.exception.args, ("worker_runtime_refused",))
                self.assertEqual(caught.exception.checkpoint, "network_binding")

    def test_network_drift_after_readiness_copy_never_returns_running_identity(self):
        with self.assertRaises(runtime.RuntimeRefused) as caught:
            self.network_capture(changed=True)
        self.assertEqual(caught.exception.checkpoint, "network_binding")
        self.assertEqual(self.network_reads, 2)
        self.assertTrue(any(argv[3:5] == ["container", "cp"] for argv, _ in self.calls))

    def test_created_observation_with_network_pin_does_not_claim_actual_attachment(
        self,
    ):
        self.info["state"].update(
            Status="created",
            Running=False,
            Paused=False,
            Restarting=False,
            Dead=False,
            OOMKilled=False,
            Pid=0,
            ExitCode=0,
            Error="",
            StartedAt="0001-01-01T00:00:00Z",
            FinishedAt="0001-01-01T00:00:00Z",
        )
        observer = runtime.LocalDocker(
            "desktop-linux", self.layout, network_binding=("owned_runner", "f" * 64)
        )
        with patch.object(runtime.subprocess, "run", self.command):
            observed = observer.capture_created(
                daemon_id=self.identity.daemon_id,
                container_id=self.identity.container_id,
                image_id=self.identity.image_id,
                project=self.identity.project,
            )
        self.assertIs(type(observed), runtime.ObservedCreated)
        self.assertFalse(
            any(runtime._NETWORK_INSPECT in argv for argv, _ in self.calls)
        )
        self.assertFalse(
            any(argv[3:5] == ["container", "cp"] for argv, _ in self.calls)
        )
        self.assertFalse(hasattr(observed, "owner_nonce"))

    def runner_network_fixture(self):
        return {
            "id": "f" * 64,
            "name": "owned_runner",
            "driver": "bridge",
            "scope": "local",
            "internal": False,
            "options": {},
            "project": self.identity.project,
            "logical": "runner",
            "ipam": {
                "Driver": "default",
                "Options": None,
                "Config": [
                    {
                        "Subnet": "192.0.2.0/24",
                        "IPRange": "192.0.2.128/25",
                        "Gateway": "192.0.2.1",
                    },
                    {
                        "Subnet": "2001:db8::/64",
                        "Gateway": "2001:db8::1",
                        "AuxiliaryAddresses": {"fixture": "2001:db8::2"},
                    },
                ],
            },
        }

    def runner_network_capture(self, row=None, *, drift=None, raw=None):
        row = row if row is not None else self.runner_network_fixture()
        self.net_reads = 0
        self.net_observer = runtime.LocalDocker("desktop-linux", self.layout)
        original = self.command

        def command(argv, **options):
            args = argv[3:]
            if args[:3] == ["network", "inspect", "--format"]:
                self.assertEqual(len(args), 5)
                self.assertEqual(args[3], runtime._NETWORK_RESOURCE)
                self.net_reads += 1
                value = copy.deepcopy(row)
                if self.net_reads == 2 and drift == "ipam":
                    value["ipam"]["Config"][0]["Gateway"] = "192.0.2.2"
                if self.net_reads == 2 and drift == "network_id":
                    value["id"] = "e" * 64
                self.calls.append((argv, options))
                return subprocess.CompletedProcess(
                    argv, 0, raw if raw is not None else json.dumps(value), ""
                )
            reply = original(argv, **options)
            if self.net_reads == 2 and drift == "endpoint" and args[0] == "context":
                reply.stdout = json.dumps("unix:///owned/changed.sock")
            if self.net_reads == 2 and drift == "daemon" and args[0] == "info":
                reply.stdout = json.dumps("other-daemon")
            return reply

        with patch.object(runtime.subprocess, "run", command):
            return self.net_observer.capture_runner_network(
                name="owned_runner", project=self.identity.project
            )

    def test_resource_capture_binds_name_full_id_local_endpoint_daemon_and_closed_ipam(
        self,
    ):
        from hashlib import sha256

        for endpoint in (
            "npipe:////./pipe/dockerDesktopLinuxEngine",
            "unix:///var/run/docker.sock",
        ):
            with self.subTest(endpoint=endpoint):
                self.setUp()
                self.endpoint = endpoint
                row = self.runner_network_fixture()
                if endpoint.startswith("npipe:"):
                    row["options"] = {
                        "com.docker.network.enable_ipv4": "true",
                        "com.docker.network.enable_ipv6": "false",
                    }
                    row["ipam"]["Config"] = row["ipam"]["Config"][:1]
                ipam = row["ipam"]
                original = copy.deepcopy(row)
                report = self.runner_network_capture(row)
                digest = sha256(
                    json.dumps(ipam, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                expected = {key: row[key] for key in row if key != "ipam"}
                expected["ipam_sha256"] = digest
                self.assertEqual(
                    report,
                    {
                        "context": "desktop-linux",
                        "local_endpoint": endpoint,
                        "daemon_id": self.daemon,
                        "network": expected,
                    },
                )
                self.assertEqual(row, original)
                self.assertEqual(
                    [argv[3] for argv, _ in self.calls],
                    ["context", "info", "network", "network", "context", "info"],
                )
                self.assertEqual(
                    [argv[-1] for argv, _ in self.calls if argv[3] == "network"],
                    ["owned_runner", "f" * 64],
                )
                self.assertTrue(
                    all(0 < kwargs["timeout"] <= 15 for _, kwargs in self.calls)
                )
                self.assertNotIn(".Containers", runtime._NETWORK_RESOURCE)
                self.assertIsNone(self.net_observer._deadline)
                self.assertFalse(self.net_observer._observation_lock.locked())

    def test_resource_capture_refuses_invalid_selectors_and_busy_observer_before_commands(
        self,
    ):
        observer = runtime.LocalDocker("desktop-linux", self.layout)
        with patch.object(runtime.subprocess, "run") as command:
            for name, project in (
                ("--flag", "owned"),
                ("", "owned"),
                (True, "owned"),
                ("owned", "BadProject"),
                ("owned", "x" * 64),
            ):
                with (
                    self.subTest(name_type=type(name).__name__),
                    self.assertRaises(runtime.RuntimeRefused),
                ):
                    observer.capture_runner_network(name=name, project=project)
            observer._observation_lock.acquire()
            observer._deadline = 17
            try:
                with self.assertRaises(runtime.RuntimeRefused):
                    observer.capture_runner_network(name="owned", project="owned")
                self.assertEqual(observer._deadline, 17)
            finally:
                observer._observation_lock.release()
            command.assert_not_called()

    def test_resource_capture_requires_exact_owned_default_local_runner_bridge(self):
        for key, replacement in (
            ("id", "f" * 12),
            ("name", "foreign"),
            ("driver", "overlay"),
            ("scope", "global"),
            ("internal", 0),
            ("internal", True),
            ("options", {"custom": "private-canary"}),
            (
                "options",
                {
                    "com.docker.network.enable_ipv4": "false",
                    "com.docker.network.enable_ipv6": "false",
                },
            ),
            (
                "options",
                {
                    "com.docker.network.enable_ipv4": "true",
                    "com.docker.network.enable_ipv6": "true",
                },
            ),
            (
                "options",
                {
                    "com.docker.network.enable_ipv4": True,
                    "com.docker.network.enable_ipv6": "false",
                },
            ),
            ("project", "foreign"),
            ("logical", "application"),
            ("extra", "private-canary"),
        ):
            with self.subTest(key=key):
                self.setUp()
                row = self.runner_network_fixture()
                row[key] = replacement
                with self.assertRaisesRegex(
                    runtime.RuntimeRefused, "^worker_runtime_refused$"
                ):
                    self.runner_network_capture(row)
                self.assertEqual(self.net_reads, 1)
                self.assertIsNone(self.net_observer._deadline)
                self.assertFalse(self.net_observer._observation_lock.locked())

    def test_resource_capture_rejects_outside_subnet_or_nonpublic_ipam_shapes(self):
        changes = (
            lambda ipam: ipam.update(Driver="foreign"),
            lambda ipam: ipam.update(Options={"custom": "private-canary"}),
            lambda ipam: ipam.update(Config=[]),
            lambda ipam: ipam["Config"][0].update(Subnet=True),
            lambda ipam: ipam["Config"][0].update(IPRange="198.51.100.0/24"),
            lambda ipam: ipam["Config"][0].update(Gateway="198.51.100.1"),
            lambda ipam: ipam["Config"][1].update(Gateway="2001:db8::1%private-canary"),
            lambda ipam: ipam["Config"][1].update(
                AuxiliaryAddresses={"foreign": "192.0.2.1"}
            ),
            lambda ipam: ipam["Config"][0].update(extra="private-canary"),
        )
        for index, mutate in enumerate(changes):
            with self.subTest(case=index):
                self.setUp()
                row = self.runner_network_fixture()
                mutate(row["ipam"])
                with self.assertRaisesRegex(
                    runtime.RuntimeRefused, "^worker_runtime_refused$"
                ):
                    self.runner_network_capture(row)
                self.assertEqual(self.net_reads, 1)

    def test_resource_capture_fails_closed_on_drift_without_another_lookup(self):
        for drift in ("network_id", "ipam", "endpoint", "daemon"):
            with self.subTest(drift=drift):
                self.setUp()
                with self.assertRaisesRegex(
                    runtime.RuntimeRefused, "^worker_runtime_refused$"
                ):
                    self.runner_network_capture(drift=drift)
                self.assertEqual(self.net_reads, 2)
                self.assertIsNone(self.net_observer._deadline)
                self.assertFalse(self.net_observer._observation_lock.locked())

    def test_resource_capture_refuses_duplicate_or_malformed_network_documents(self):
        for raw in (
            '{"id":"f","id":"private-canary"}',
            '{"ipam":NaN}',
            "[]",
            "{broken",
            "x" * 16385,
        ):
            with self.subTest(length=len(raw)):
                self.setUp()
                with self.assertRaisesRegex(
                    runtime.RuntimeRefused, "^worker_runtime_refused$"
                ):
                    self.runner_network_capture(raw=raw)
                self.assertEqual(self.net_reads, 1)

    def project_vectors(self):
        cores, rows = [], []
        for number, service in enumerate(("api", "db", "proxy", "web"), 1):
            cid = str(number) * 64
            labels = {
                "id": cid,
                "project": self.identity.project,
                "service": service,
                "oneoff": "False",
            }
            rows.append({**labels, "managed": ""})
            cores.append(
                {
                    **labels,
                    "image": self.identity.image_id,
                    "started_at": self.identity.started_at,
                    "status": "running",
                    "running": True,
                    "paused": False,
                    "restarting": False,
                    "dead": False,
                    "health": "healthy",
                }
            )
        for cid in ("e" * 64, "f" * 64):
            rows.append(
                {
                    "id": cid,
                    "project": self.identity.project,
                    "service": "managed-worker",
                    "oneoff": "False",
                    "managed": "1",
                }
            )
        rows.append(
            {
                "id": "d" * 64,
                "project": self.identity.project,
                "service": "fixture-target",
                "oneoff": "",
                "managed": "",
            }
        )
        return rows, cores

    def capture_project(self, rows=None, cores=None, *, drift=None, raw=None):
        default_rows, default_cores = self.project_vectors()
        rows = default_rows if rows is None else rows
        cores = default_cores if cores is None else cores
        self.project_lists = self.core_inspects = 0
        observer = self.project_observer = runtime.LocalDocker(
            "desktop-linux", self.layout
        )
        original = self.command
        expected_project = self.identity.project

        def command(argv, **options):
            args = argv[3:]
            if args[:2] == ["container", "ls"]:
                self.assertEqual(
                    args,
                    [
                        "container",
                        "ls",
                        "--all",
                        "--no-trunc",
                        "--filter",
                        "label=com.docker.compose.project=" + expected_project,
                        "--format",
                        runtime._PROJECT_LIST,
                    ],
                )
                self.project_lists += 1
                selected = copy.deepcopy(rows)
                if self.project_lists == 2:
                    selected.reverse()
                    if drift == "worker":
                        selected.append({**default_rows[-2], "id": "c" * 64})
                text = (
                    raw
                    if raw is not None
                    else "\n".join(json.dumps(row) for row in selected)
                )
            elif args[:2] == ["container", "inspect"]:
                self.assertEqual(
                    args[:4],
                    ["container", "inspect", "--format", runtime._CORE_INSPECT],
                )
                self.assertEqual(args[4:], [str(n) * 64 for n in range(1, 5)])
                self.core_inspects += 1
                selected = copy.deepcopy(cores)
                if self.core_inspects == 2:
                    selected.reverse()
                    if drift == "start":
                        selected[0]["started_at"] = "2026-11-05T20:01:00Z"
                text = "\n".join(json.dumps(row) for row in selected)
            else:
                reply = original(argv, **options)
                if (
                    self.core_inspects == 2
                    and drift == "endpoint"
                    and args[0] == "context"
                ):
                    reply.stdout = json.dumps("unix:///changed.sock")
                if self.core_inspects == 2 and drift == "daemon" and args[0] == "info":
                    reply.stdout = json.dumps("changed-daemon")
                return reply
            self.calls.append((argv, options))
            return subprocess.CompletedProcess(argv, 0, text, "")

        with patch.object(runtime.subprocess, "run", command):
            return observer.capture_project_containers(expected_project)

    def test_project_capture_independently_binds_all_worker_ids_and_four_healthy_cores(
        self,
    ):
        report = self.capture_project()
        self.assertEqual(
            set(report),
            {"context", "local_endpoint", "daemon_id", "core", "all_worker_ids"},
        )
        self.assertEqual(report["context"], "desktop-linux")
        self.assertEqual(report["local_endpoint"], self.endpoint)
        self.assertEqual(report["daemon_id"], self.daemon)
        self.assertEqual(report["all_worker_ids"], ["e" * 64, "f" * 64])
        self.assertEqual(
            report["core"],
            [
                {
                    "service": service,
                    "container_id": str(n) * 64,
                    "image_id": self.identity.image_id,
                    "started_at": self.identity.started_at,
                    "status": "running",
                    "health": "healthy",
                }
                for n, service in enumerate(("api", "db", "proxy", "web"), 1)
            ],
        )
        self.assertEqual(
            [argv[3] for argv, _ in self.calls],
            [
                "context",
                "info",
                "container",
                "container",
                "container",
                "container",
                "context",
                "info",
            ],
        )
        self.assertTrue(all(0 < opts["timeout"] <= 15 for _, opts in self.calls))
        self.assertNotIn("config-hash", runtime._PROJECT_LIST)
        self.assertNotIn(".Config.Env", runtime._CORE_INSPECT)
        self.assertIsNone(self.project_observer._deadline)
        self.assertFalse(self.project_observer._observation_lock.locked())

    def test_project_capture_zero_workers_is_only_an_observation_and_rejects_invalid_selector(
        self,
    ):
        rows, cores = self.project_vectors()
        report = self.capture_project(
            [row for row in rows if row["service"] != "managed-worker"], cores
        )
        self.assertEqual(report["all_worker_ids"], [])
        self.assertNotIn("first_installation", report)
        with patch.object(runtime.subprocess, "run") as command:
            for value in ("--flag", "Upper", False, "a" * 64):
                with self.assertRaises(runtime.RuntimeRefused):
                    self.project_observer.capture_project_containers(value)
            command.assert_not_called()

    def test_project_capture_refuses_missing_duplicate_or_foreign_rows_before_core_inspection(
        self,
    ):
        mutations = (
            lambda rows: rows.pop(0),
            lambda rows: rows.append({**rows[0], "id": "c" * 64}),
            lambda rows: rows.append(rows[0]),
            lambda rows: rows[0].update(project="foreign"),
            lambda rows: rows[4].update(oneoff="True"),
            lambda rows: rows[4].update(managed=""),
            lambda rows: rows[-1].update(managed="1"),
            lambda rows: rows[0].update(id="1" * 12),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                self.setUp()
                rows, cores = self.project_vectors()
                mutate(rows)
                with self.assertRaisesRegex(
                    runtime.RuntimeRefused, "^worker_runtime_refused$"
                ):
                    self.capture_project(rows, cores)
                self.assertEqual(self.core_inspects, 0)
                self.assertEqual(self.project_lists, 1)

    def test_project_capture_core_requires_actual_healthy_running_identity_and_labels(
        self,
    ):
        for field, value in (
            ("id", "c" * 64),
            ("service", "wrong"),
            ("image", "sha256:short"),
            ("started_at", "0001-01-01T00:00:00Z"),
            ("status", "exited"),
            ("running", 1),
            ("paused", True),
            ("restarting", True),
            ("dead", True),
            ("health", None),
            ("health", "unhealthy"),
            ("oneoff", "True"),
            ("project", "foreign"),
            ("extra", "private-canary"),
        ):
            with self.subTest(field=field):
                self.setUp()
                rows, cores = self.project_vectors()
                cores[0][field] = value
                with self.assertRaisesRegex(
                    runtime.RuntimeRefused, "^worker_runtime_refused$"
                ):
                    self.capture_project(rows, cores)
                self.assertEqual(self.core_inspects, 1)
                self.assertEqual(self.project_lists, 1)

    def test_project_capture_rejects_worker_core_or_daemon_drift_without_retry(self):
        for drift in ("worker", "start", "endpoint", "daemon"):
            with self.subTest(drift=drift):
                self.setUp()
                with self.assertRaisesRegex(
                    runtime.RuntimeRefused, "^worker_runtime_refused$"
                ):
                    self.capture_project(drift=drift)
                self.assertEqual(self.project_lists, 2)
                self.assertEqual(self.core_inspects, 1 if drift == "worker" else 2)
                self.assertIsNone(self.project_observer._deadline)
                self.assertFalse(self.project_observer._observation_lock.locked())

    def test_project_capture_malformed_or_duplicate_json_lines_are_fixed_refusals(self):
        for raw in (
            "",
            "[]",
            '{"id":"one","id":"private-canary"}',
            '{"id":NaN}',
            "{broken",
            "x" * 16385,
        ):
            with self.subTest(length=len(raw)):
                self.setUp()
                with self.assertRaisesRegex(
                    runtime.RuntimeRefused, "^worker_runtime_refused$"
                ):
                    self.capture_project(raw=raw)
                self.assertEqual(self.project_lists, 1)
                self.assertEqual(self.core_inspects, 0)


if __name__ == "__main__":
    unittest.main()
