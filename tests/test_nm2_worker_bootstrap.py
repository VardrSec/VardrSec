"""Bootstrap protocol/retention tests only; Docker is never contacted."""

import argparse
import copy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest.mock import patch

import nm2_worker_bootstrap as bootstrap

BINARY = b"public synthetic owner binary fixture"
IMAGE = "sha256:" + "a" * 64


def archive(*, ready=True, extra=False):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as tar:
        member = tarfile.TarInfo(
            "vardr-worker-ready" if ready else "vardr-worker-owner"
        )
        if ready:
            member.type, member.uid, member.gid, member.mode = (
                tarfile.DIRTYPE,
                10000,
                10000,
                0o700,
            )
            tar.addfile(member)
        else:
            member.size = len(BINARY)
            tar.addfile(member, io.BytesIO(BINARY))
        if extra:
            member = tarfile.TarInfo("vardr-worker-ready/owner.json")
            member.size = 2
            tar.addfile(member, io.BytesIO(b"{}"))
    return result.getvalue()


class Engine:
    """Coherent create/start/wait/inspect model, not a lifecycle proof substitute."""

    def __init__(self, fixture, fault=None):
        self.fixture, self.fault, self.calls, self.containers = fixture, fault, [], {}
        self.image = {
            "id": IMAGE,
            "entrypoint": [bootstrap.OWNER],
            "cmd": [],
            "volumes": None,
            "env": ["PATH=/usr/bin"],
        }
        self.before = {
            "containers": {},
            "networks": {},
            "volumes": {},
            "images": {IMAGE: {"id": IMAGE, "tags": ["retained-tag"]}},
        }
        self.before["containers"]["f" * 64] = {
            "id": "f" * 64,
            "labels": {"owner": "old"},
            "state": {"running": False},
        }

    def snapshot(self):
        value = copy.deepcopy(self.before)
        for key, row in self.containers.items():
            value["containers"][key] = {
                "id": key,
                "image": IMAGE,
                "labels": row["labels"],
                "state": {
                    "running": row["state"]["Running"],
                    "paused": False,
                    "restarting": False,
                    "dead": False,
                    "exit_code": row["state"]["ExitCode"],
                },
            }
        if self.fault == "old_tag" and self.containers:
            value["images"][IMAGE]["tags"] = ["changed-tag"]
        return value

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if args[:2] == ("context", "inspect"):
            return json.dumps(
                "ssh://unrelated"
                if self.fault == "remote"
                else "unix:///var/run/docker.sock"
            ).encode()
        if args[0] == "info":
            return b'{"id":"owned-daemon","os":"linux"}'
        if args[:2] == ("image", "inspect"):
            return json.dumps(self.image).encode()
        if args[:2] == ("container", "ls"):
            return b"a" * 64 if self.fault == "collision" else b""
        if args[:2] == ("container", "create"):
            case = next(
                value.split("=", 1)[1]
                for value in args
                if value.startswith(bootstrap.LABEL + "=")
            )
            user, caps = bootstrap.CASES[case]
            key = str(len(self.containers) + 1) * 64
            self.containers[key] = {
                "id": key,
                "image": IMAGE,
                "name": "/" + self.fixture.project + "-" + case.replace("_", "-"),
                "labels": {
                    "com.docker.compose.project": self.fixture.project,
                    bootstrap.LABEL: case,
                },
                "entrypoint": [bootstrap.OWNER],
                "cmd": [],
                "health": {"Test": ["NONE"]},
                "user": user,
                "restarts": 0,
                "host": {
                    "network": "none",
                    "readonly": True,
                    "privileged": False,
                    "init": False,
                    "restart": "no",
                    "caps": ["CAP_" + value for value in caps] or None,
                    "drop": ["ALL"],
                    "security": ["no-new-privileges:true"],
                    "memory": 536870912,
                    "pids": 64,
                    "cpus": 1000000000,
                    "ipc": "private",
                    "cgroup": "private",
                    "tmpfs": {"/tmp": bootstrap.TMPFS},
                },
                "mounts": [{"Type": "tmpfs", "Destination": "/tmp", "RW": True}],
                "state": {
                    "Status": "created",
                    "Running": False,
                    "Paused": False,
                    "Restarting": False,
                    "Dead": False,
                    "OOMKilled": False,
                    "ExitCode": 0,
                    "Pid": 0,
                    "Error": "",
                    "StartedAt": "0001-01-01T00:00:00Z",
                    "FinishedAt": "0001-01-01T00:00:00Z",
                },
            }
            return key.encode()
        if args[:2] == ("container", "inspect"):
            return json.dumps(self.containers[args[-1]]).encode()
        if args[:2] in (("container", "start"), ("container", "stop")):
            row = self.containers[args[-1]]
            row["state"].update(
                Status="exited",
                Running=False,
                ExitCode=125,
                StartedAt="2026-11-06T04:00:00.123456789Z",
                FinishedAt="2026-11-06T04:00:00.223456789Z",
            )
            if args[1] == "start" and self.fault == "wait_unknown":
                row["state"].update(Status="running", Running=True, Pid=100)
            return args[-1].encode()
        if args[:2] == ("container", "wait"):
            if self.fault == "wait_unknown":
                raise bootstrap.shared.AcceptanceRefused("fixture_command_failed")
            if self.fault == "wrong_exit":
                return b"0"
            return b"125"
        if args[:2] == ("container", "cp"):
            return archive(
                ready=not args[2].endswith(bootstrap.OWNER),
                extra=self.fault == "ready_exists",
            )
        raise AssertionError("unexpected command")


class BootstrapTests(unittest.TestCase):
    def arguments(self, root):
        build = root / "build.json"
        build.write_text(
            json.dumps(
                {
                    "status": "passed_frozen_build_dependency_probe",
                    "image": IMAGE,
                    "source_commit": "b" * 40,
                    "source_tree": "c" * 40,
                    "source_manifest_sha256": "d" * 64,
                    "source_hashes": {"container/worker_owner.c": "e" * 64},
                }
            ),
            encoding="utf-8",
        )
        return argparse.Namespace(
            build_receipt=build,
            image=IMAGE,
            owner_sha256=bootstrap.shared.digest(BINARY),
            docker_context="default",
            project="vardrsec-nm2-12345678",
            output=root / "new-output",
            allow_empty_builtin_bridge_id_change=False,
        )

    def fixture(self, root, fault=None):
        fixture = bootstrap.Bootstrap(bootstrap.validate(self.arguments(root)))
        engine = Engine(fixture, fault)
        fixture.docker, fixture.snapshot = engine, engine.snapshot
        return fixture, engine

    def run_fixture(self, fixture):
        with patch.object(
            bootstrap.shared,
            "private_directory",
            side_effect=lambda path: path.mkdir(mode=0o700),
        ):
            return fixture.run()

    def test_default_validates_without_docker_or_output_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.arguments(Path(temporary))
            flags = [
                "--build-receipt",
                str(args.build_receipt),
                "--image",
                args.image,
                "--owner-sha256",
                args.owner_sha256,
                "--docker-context",
                args.docker_context,
                "--project",
                args.project,
                "--output",
                str(args.output),
            ]
            with (
                patch.object(
                    bootstrap.shared,
                    "command",
                    side_effect=AssertionError("Docker must remain inert"),
                ),
                redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(bootstrap.main(flags), 0)
            self.assertEqual(json.loads(output.getvalue())["docker_calls"], 0)
            self.assertFalse(args.output.exists())

    def test_isolated_standalone_help_and_validation_need_no_pythonpath_or_docker(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.arguments(Path(temporary))
            command = [sys.executable, "-I", str(Path(bootstrap.__file__).resolve())]
            environment = {**os.environ, "PATH": "", "PYTHONPATH": "/not-used"}
            help_result = subprocess.run(
                command + ["--help"],
                env=environment,
                cwd=temporary,
                capture_output=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(help_result.returncode, 0)
            self.assertIn(b"--execute", help_result.stdout)
            flags = [
                "--build-receipt",
                str(args.build_receipt),
                "--image",
                args.image,
                "--owner-sha256",
                args.owner_sha256,
                "--docker-context",
                args.docker_context,
                "--project",
                args.project,
                "--output",
                str(args.output),
            ]
            result = subprocess.run(
                command + flags,
                env=environment,
                cwd=temporary,
                capture_output=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(json.loads(result.stdout)["docker_calls"], 0)
            self.assertFalse(args.output.exists())

    def test_two_refusals_use_only_reviewed_command_caps_and_retain_stopped_resources(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            fixture, engine = self.fixture(Path(temporary))
            result = self.run_fixture(fixture)
            self.assertEqual(result["status"], "passed_configuration_refusals")
            self.assertEqual(set(result["cases"]), set(bootstrap.CASES))
            for name, row in result["cases"].items():
                self.assertEqual(row["status"], "passed")
                self.assertEqual(row["exit_code"], 125)
                self.assertTrue(row["readiness_absent"])
                self.assertEqual(
                    row["descendant_absence"], "not_independently_observed"
                )
            creates = [
                args for args, _ in engine.calls if args[:2] == ("container", "create")
            ]
            self.assertEqual(len(creates), 2)
            for args, (user, caps) in zip(creates, bootstrap.CASES.values()):
                self.assertEqual(args[-1], IMAGE)
                self.assertEqual(args[args.index("--user") + 1], user)
                self.assertEqual(
                    [
                        args[index + 1]
                        for index, value in enumerate(args)
                        if value == "--cap-add"
                    ],
                    caps,
                )
                for denied in (
                    "--entrypoint",
                    "--env",
                    "--env-file",
                    "--volume",
                    "--mount",
                    "--privileged",
                    "--pid",
                ):
                    self.assertNotIn(denied, args)
                self.assertEqual(args[args.index("--network") + 1], "none")
                self.assertIn("--read-only", args)
            self.assertFalse(
                any(
                    args[:2]
                    in {
                        ("container", "stop"),
                        ("container", "rm"),
                        ("container", "exec"),
                    }
                    for args, _ in engine.calls
                )
            )
            self.assertEqual(len(result["inventory_checks"]), 3)

    def test_readiness_absence_requires_positive_empty_directory_copy(self):
        self.assertRegex(bootstrap.empty_readiness(archive()), r"^[a-f0-9]{64}$")
        for raw in (b"", b"not a tar", archive(extra=True), archive(ready=False)):
            with (
                self.subTest(raw_size=len(raw)),
                self.assertRaises(bootstrap.shared.AcceptanceRefused),
            ):
                bootstrap.empty_readiness(raw)
        with self.assertRaisesRegex(
            bootstrap.shared.AcceptanceRefused, "owner_binary_changed"
        ):
            bootstrap.owner_binary(archive(ready=False), "f" * 64)

    def test_optional_image_keys_are_projected_as_null_without_allowing_payloads(self):
        # Docker29 omits unset Config map keys; direct field selectors error
        # before JSON is emitted. Keep nullable fields nullable in the projection.
        for template, names in (
            (bootstrap.IMAGE_FORMAT, ("Cmd", "Volumes")),
            (bootstrap.CONTAINER_FORMAT, ("Cmd", "Healthcheck")),
        ):
            for name in names:
                self.assertNotIn(".Config." + name, template)
                self.assertIn('index .Config "' + name + '"', template)
        with tempfile.TemporaryDirectory() as temporary:
            fixture, engine = self.fixture(Path(temporary))
            engine.image["cmd"] = None
            self.assertEqual(
                self.run_fixture(fixture)["status"], "passed_configuration_refusals"
            )
        with tempfile.TemporaryDirectory() as temporary:
            fixture, engine = self.fixture(Path(temporary))
            engine.image["cmd"] = ["unapproved-payload"]
            self.assertEqual(self.run_fixture(fixture)["status"], "held")
            self.assertFalse(engine.containers)

    def test_preflight_refuses_remote_name_collision_or_changed_image_before_create(
        self,
    ):
        for fault in ("remote", "collision", "entrypoint", "volumes", "auth"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                fixture, engine = self.fixture(Path(temporary), fault)
                if fault == "entrypoint":
                    engine.image["entrypoint"] = ["/bin/false"]
                elif fault == "volumes":
                    engine.image["volumes"] = {"/state": {}}
                elif fault == "auth":
                    engine.image["env"] = ["VARDRMAP_API_KEY=private-canary"]
                result = self.run_fixture(fixture)
                self.assertEqual(result["status"], "held")
                self.assertFalse(engine.containers)
                self.assertNotIn("private-canary", json.dumps(result))

    def test_wrong_exit_existing_readiness_or_old_tag_change_cannot_pass(self):
        for fault in ("wrong_exit", "ready_exists", "old_tag"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                fixture, engine = self.fixture(Path(temporary), fault)
                result = self.run_fixture(fixture)
                self.assertEqual(result["status"], "held")
                self.assertEqual(len(engine.containers), 1)
                self.assertEqual(
                    result["cases"]["missing_setpcap"]["status"], "not_run"
                )

    def test_unknown_wait_stops_only_exact_owned_container_and_stays_held(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture, engine = self.fixture(Path(temporary), "wait_unknown")
            result = self.run_fixture(fixture)
            stops = [
                args for args, _ in engine.calls if args[:2] == ("container", "stop")
            ]
            self.assertEqual(result["status"], "held")
            self.assertEqual(stops, [("container", "stop", "-t", "1", "1" * 64)])
            self.assertTrue(
                all(
                    row["state"]["Running"] is False
                    for row in engine.containers.values()
                )
            )

    def test_input_identity_and_existing_output_refuse_before_runtime(self):
        for change in ("tag", "binary_hash", "source_hash", "output"):
            with (
                self.subTest(change=change),
                tempfile.TemporaryDirectory() as temporary,
            ):
                args = self.arguments(Path(temporary))
                if change == "tag":
                    args.image = "worker:latest"
                elif change == "binary_hash":
                    args.owner_sha256 = "unknown"
                elif change == "source_hash":
                    value = json.loads(args.build_receipt.read_text())
                    value["source_hashes"] = {}
                    args.build_receipt.write_text(json.dumps(value), encoding="utf-8")
                else:
                    args.output.mkdir()
                with self.assertRaises(bootstrap.shared.AcceptanceRefused):
                    bootstrap.validate(args)


if __name__ == "__main__":
    unittest.main()
