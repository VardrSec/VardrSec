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
                    runtime.LocalDocker("desktop-linux", self.layout).capture_running(
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


if __name__ == "__main__":
    unittest.main()
