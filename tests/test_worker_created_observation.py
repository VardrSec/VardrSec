"""Synthetic Created reads; no container, process, provider or lifecycle action."""

import copy
from dataclasses import FrozenInstanceError
import json
import subprocess
import unittest
from unittest.mock import patch

import test_worker_runtime as vectors
import worker_runtime as runtime


def fixture(*, created):
    result = vectors.WorkerRuntimeTests(
        "test_exact_retained_exit_is_observed_without_mutating_daemon"
    )
    result.setUp()
    if created:
        result.info["state"].update(
            Status="created",
            Running=False,
            Paused=False,
            Restarting=False,
            Dead=False,
            OOMKilled=False,
            Pid=0,
            ExitCode=0,
            StartedAt="0001-01-01T00:00:00Z",
            FinishedAt="0001-01-01T00:00:00Z",
            Error="",
        )
    return result


def observe(source, *, command=None, daemon=None):
    observer = runtime.LocalDocker(
        "desktop-linux", source.layout, protocol="persistent-v3"
    )
    with (
        patch.object(
            runtime.subprocess, "run", source.command if command is None else command
        ),
        patch.object(
            observer,
            "_owner_nonce",
            side_effect=AssertionError("Created must not read readiness"),
        ),
    ):
        proof = observer.capture_created(
            daemon_id=source.daemon if daemon is None else daemon,
            container_id=source.identity.container_id,
            image_id=source.identity.image_id,
            project=source.identity.project,
        )
    return observer, proof


class CreatedObservationTests(unittest.TestCase):
    def test_exact_created_is_distinct_frozen_direct_observation(self):
        self.assertTrue(callable(getattr(runtime.LocalDocker, "capture_created", None)))
        source = fixture(created=True)
        observer, proof = observe(source)
        self.assertIsInstance(proof, runtime.ObservedCreated)
        self.assertNotIsInstance(proof, (runtime.RuntimeIdentity, runtime.ObservedExit))
        self.assertEqual(
            (
                proof.daemon_id,
                proof.container_id,
                proof.image_id,
                proof.project,
                proof.layout,
            ),
            (
                source.daemon,
                source.identity.container_id,
                source.identity.image_id,
                source.identity.project,
                source.layout,
            ),
        )
        self.assertFalse(hasattr(proof, "started_at"))
        self.assertFalse(hasattr(proof, "owner_nonce"))
        self.assertEqual(source.inspect_count, 2)
        self.assertIsNone(observer._deadline)
        self.assertFalse(observer._observation_lock.locked())
        with self.assertRaises(FrozenInstanceError):
            proof.container_id = "f" * 64
        with self.assertRaises(runtime.RuntimeRefused):
            runtime.ObservedCreated(
                source.daemon,
                source.identity.container_id,
                source.identity.image_id,
                source.identity.project,
                source.layout,
            )
        with patch.object(
            runtime.subprocess, "run", side_effect=AssertionError("no metadata call")
        ):
            with self.assertRaises(runtime.RuntimeRefused):
                observer._bound(proof)

    def test_both_real_profile_callers_refuse_the_same_static_profile_drift(self):
        mutations = [
            (("user",), "10001"),
            (("entrypoint",), ["/bin/sh"]),
            (("command",), ["job"]),
            (("healthcheck",), {"Test": ["CMD", "true"]}),
            (("labels", "com.docker.compose.service"), "runner"),
            (("labels", "com.docker.compose.oneoff"), "True"),
            (("labels", "io.vardrsec.managed-worker"), "0"),
            (("host", "privileged"), True),
            (("host", "readonly_root"), False),
            (("host", "cap_add"), ["SYS_ADMIN"]),
            (("host", "cap_drop"), []),
            (("host", "port_bindings"), {"80/tcp": []}),
            (("host", "pids"), True),
            (("host", "security"), []),
            (("host", "restart"), "always"),
        ]
        for path, value in mutations:
            for created in (False, True):
                source = fixture(created=created)
                node = source.info
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = copy.deepcopy(value)
                with (
                    self.subTest(path=path, created=created),
                    self.assertRaises(runtime.RuntimeRefused),
                ):
                    if created:
                        observe(source)
                    else:
                        with patch.object(runtime.subprocess, "run", source.command):
                            runtime.LocalDocker("desktop-linux", source.layout)._bound(
                                source.identity
                            )

    def test_created_state_requires_exact_unarmed_zero_state_not_runtime_identity(self):
        for name, value in [
            ("Status", "exited"),
            ("Running", 0),
            ("Paused", True),
            ("Restarting", True),
            ("Dead", True),
            ("OOMKilled", True),
            ("Pid", True),
            ("Pid", 1),
            ("ExitCode", False),
            ("StartedAt", "2026-11-06T00:00:00Z"),
            ("FinishedAt", "2026-11-06T00:00:00Z"),
            ("Error", "private-error-canary"),
        ]:
            source = fixture(created=True)
            source.info["state"][name] = value
            with (
                self.subTest(field=name),
                self.assertRaisesRegex(
                    runtime.RuntimeRefused, "^worker_created_refused$"
                ),
            ):
                observe(source)

    def test_second_profile_or_daemon_change_cannot_return_created_proof(self):
        for change in ("state", "daemon"):
            source = fixture(created=True)

            def altered(argv, **kwargs):
                response = source.command(argv, **kwargs)
                args = argv[3:]
                if args[:2] == ["container", "inspect"] and source.inspect_count == 2:
                    if change == "state":
                        value = json.loads(response.stdout)
                        value["state"]["Running"] = True
                        return subprocess.CompletedProcess(
                            argv, 0, json.dumps(value), ""
                        )
                    source.daemon = "changed-daemon"
                return response

            with self.subTest(change=change), self.assertRaises(runtime.RuntimeRefused):
                observe(source, command=altered, daemon="daemon-id")

    def test_mount_tmpfs_and_default_local_volume_guards_still_apply(self):
        for change in ("mount", "tmpfs", "volume"):
            source = fixture(created=True)
            if change == "mount":
                source.info["mounts"].append(
                    {
                        "Type": "bind",
                        "Source": "/var/run/docker.sock",
                        "Destination": "/socket",
                        "RW": True,
                    }
                )
            elif change == "tmpfs":
                source.info["host"]["tmpfs"]["/tmp"] += ",exec"
            else:
                source.volume_rows[source.layout.state_volume]["options"] = {
                    "device": "/host"
                }
            with self.subTest(change=change), self.assertRaises(runtime.RuntimeRefused):
                observe(source)

    def test_observation_is_readonly_and_never_reads_owner_or_starts_anything(self):
        source = fixture(created=True)
        observe(source)
        allowed = {
            ("context", "inspect"),
            ("container", "inspect"),
            ("volume", "inspect"),
        }
        for argv, options in source.calls:
            self.assertTrue(tuple(argv[3:5]) in allowed or argv[3] == "info")
            self.assertTrue(0 < options["timeout"] <= 15)
            self.assertFalse(any("Config.Env" in argument for argument in argv))

    def test_failed_or_concurrent_observation_releases_only_its_owned_lock(self):
        source = fixture(created=True)
        observer = runtime.LocalDocker("desktop-linux", source.layout)
        observer._observation_lock.acquire()
        try:
            with self.assertRaises(runtime.RuntimeRefused):
                observer.capture_created(
                    daemon_id=source.daemon,
                    container_id=source.identity.container_id,
                    image_id=source.identity.image_id,
                    project=source.identity.project,
                )
            self.assertTrue(observer._observation_lock.locked())
        finally:
            observer._observation_lock.release()
        with patch.object(runtime.subprocess, "run", source.command):
            with self.assertRaises(runtime.RuntimeRefused):
                observer.capture_created(
                    daemon_id="wrong-daemon",
                    container_id=source.identity.container_id,
                    image_id=source.identity.image_id,
                    project=source.identity.project,
                )
        self.assertFalse(observer._observation_lock.locked())
        self.assertIsNone(observer._deadline)
        self.assertEqual(source.inspect_count, 0)
