"""Bootstrap-only hosted routing and genuine qualification; all I/O is mocked."""

import copy
import hashlib
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import nm2_worker_acceptance as shared
import nm2_worker_bootstrap as bootstrap
import nm2_worker_hosted as hosted

IMAGE = "sha256:" + "a" * 64
OWNER = "b" * 64


class BootstrapHostedTests(unittest.TestCase):
    def setUp(self):
        publisher = patch.object(
            shared, "publish", side_effect=lambda path, data: path.write_bytes(data)
        )
        publisher.start()
        self.addCleanup(publisher.stop)

    def fixture(self, temporary):
        value = object.__new__(hosted.Hosted)
        value.root = Path(temporary).resolve()
        value.project = "vardrsec-nm2-12345678"
        value.pins = {
            "distribution": "a" * 40,
            "runner": hosted.BOOTSTRAP_RUNNER,
            "gate": hosted.BOOTSTRAP_GATE,
            "map": "d" * 40,
        }
        value.sources = {"distribution": hosted.SOURCE}
        for name, files in {
            "runner": {
                "container/worker_owner.c": b"synthetic owner source\n",
                "vardrrunner/__init__.py": b"synthetic Python source\n",
            },
            "gate": {"go.mod": b"module synthetic\n"},
        }.items():
            source = value.root / name
            for relative, raw in files.items():
                target = source / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            value.sources[name] = source
        value.receipt = {}

        def sources(*, names):
            self.assertEqual(names, ("runner", "gate"))
            value.receipt["source_trees"] = {
                n: ("e" if n == "distribution" else "f") * 40
                for n in ("distribution", "runner", "gate")
            }

        value.prepare_sources = Mock(side_effect=sources)

        def build(*, persistent):
            self.assertIs(persistent, True)
            value.receipt["images"]["worker"] = IMAGE
            value.receipt["toolkit_image"] = "sha256:" + "c" * 64

        value.build_worker_images = Mock(side_effect=build)

        def command(args, **kwargs):
            source = next(
                n for n in ("runner", "gate") if str(value.sources[n]) in args
            )
            if args[-2:] == ["rev-parse", "HEAD"]:
                return value.pins[source]
            if "status" in args:
                return ""
            self.assertEqual(args[-2:], ["ls-files", "-z"])
            return "\0".join(
                p.relative_to(value.sources[source]).as_posix()
                for p in value.sources[source].rglob("*")
                if p.is_file()
            )

        value.command = Mock(side_effect=command)
        value.docker = Mock(return_value="")
        measurement = {
            "image_id": IMAGE,
            "python_inventory_sha256": "d" * 64,
            "executables": {bootstrap.OWNER: OWNER},
        }
        raw = {
            "schema": "vardr.nm2-worker-bootstrap/1",
            "status": "passed_configuration_refusals",
            "image": IMAGE,
            "owner_binary_sha256": OWNER,
            "source_commit": hosted.BOOTSTRAP_RUNNER,
            "source_tree": "f" * 40,
            "cases": {
                name: {
                    "status": "passed",
                    "exit_code": 125,
                    "readiness_absent": True,
                    "descendant_absence": "not_independently_observed",
                    "private_value": "private-canary",
                }
                for name in bootstrap.CASES
            },
        }
        return value, measurement, raw

    def test_default_cli_is_inert(self):
        with patch.object(hosted, "Hosted") as fixture, redirect_stdout(io.StringIO()):
            self.assertEqual(hosted.main([]), 2)
        fixture.assert_not_called()

    def test_new_scenario_requires_exact_runner_and_gate_without_changing_default(self):
        self.assertEqual(
            hosted.execution_options({}), ("healthy", "0040runtimesequence")
        )
        env = {
            "NM2_SCENARIO": hosted.BOOTSTRAP_SCENARIO,
            "NM2_RUNNER_SHA": hosted.BOOTSTRAP_RUNNER,
            "NM2_GATE_SHA": hosted.BOOTSTRAP_GATE,
        }
        self.assertEqual(hosted.execution_options(env)[0], hosted.BOOTSTRAP_SCENARIO)
        for name in ("NM2_RUNNER_SHA", "NM2_GATE_SHA"):
            with self.subTest(name=name), self.assertRaises(hosted.HostedRefused):
                hosted.execution_options({**env, name: "0" * 40})

    def test_early_branch_never_reaches_core_port_or_dependency_setup(self):
        with tempfile.TemporaryDirectory() as temporary:
            value = object.__new__(hosted.Hosted)
            value.scenario, value.public = hosted.BOOTSTRAP_SCENARIO, Path(temporary)
            value.receipt = {"stage": "host"}
            value.daemon_guard = Mock()
            value.run_bootstrap = Mock(
                side_effect=lambda: value.receipt.update(stage="complete")
            )
            value.command = Mock(side_effect=AssertionError("ordinary path reached"))
            with patch.object(
                hosted.socket,
                "socket",
                side_effect=AssertionError("port probe reached"),
            ):
                value.run()
            value.daemon_guard.assert_called_once_with()
            value.run_bootstrap.assert_called_once_with()
            value.command.assert_not_called()

    def test_selected_source_fetch_does_not_fetch_map(self):
        with tempfile.TemporaryDirectory() as temporary:
            value = object.__new__(hosted.Hosted)
            value.root, value.sources = Path(temporary), {"distribution": hosted.SOURCE}
            value.pins = {
                n: c * 40
                for n, c in (
                    ("distribution", "a"),
                    ("map", "b"),
                    ("runner", "c"),
                    ("gate", "d"),
                )
            }
            value.receipt = {"source_trees": {}}

            def command(args, **kwargs):
                if args[-1] == "HEAD":
                    if "-C" not in args:
                        return value.pins["distribution"]
                    source = Path(args[args.index("-C") + 1])
                    name = "distribution" if source == hosted.SOURCE else source.name
                    return value.pins[name]
                if args[-1] == "HEAD^{tree}":
                    return "e" * 40
                return ""

            value.command = Mock(side_effect=command)
            value.prepare_sources(names=("runner", "gate"))
            flattened = repr(value.command.call_args_list)
            self.assertNotIn("VardrMap", flattened)
            self.assertIn("VardrRunner", flattened)
            self.assertIn("VardrGate", flattened)
            self.assertEqual(set(value.sources), {"distribution", "runner", "gate"})

    def test_worker_build_uses_only_toolkit_and_persistent_worker(self):
        value = object.__new__(hosted.Hosted)
        value.sources = {"runner": Path("runner"), "gate": Path("gate")}
        value.project, value.receipt = "project", {"images": {}}
        value.build = Mock(
            side_effect=[
                ("sha256:" + "c" * 64, "project:toolkit"),
                (IMAGE, "project:worker"),
            ]
        )
        value.build_worker_images(persistent=True)
        calls = value.build.call_args_list
        self.assertEqual([c.args[0] for c in calls], ["toolkit", "worker"])
        self.assertEqual(
            calls[1].kwargs["file"], Path("runner/Dockerfile.worker.persistent")
        )
        self.assertEqual(
            calls[1].kwargs["extra"],
            ("--build-arg", "RUNNER_BASE_IMAGE=project:toolkit"),
        )

    def test_real_measurement_matches_source_and_reuses_restricted_helper(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            (source / "vardrrunner").mkdir()
            raw = b"synthetic\r\n"
            (source / "vardrrunner/__init__.py").write_bytes(raw)
            files = {"__init__.py": shared.digest(raw.replace(b"\r\n", b"\n"))}
            docker = Mock(
                return_value=json.dumps(
                    {"files": files, "executables": {bootstrap.OWNER: OWNER}}
                )
            )
            with patch.object(
                shared, "command", return_value=b"vardrrunner/__init__.py\0"
            ):
                measured = shared.image_source(
                    "runner", source, IMAGE, "project", docker
                )
            self.assertEqual(
                measured["python_inventory_sha256"],
                shared.digest(shared.canonical(files)),
            )
            argv = docker.call_args.args
            self.assertEqual(argv[argv.index("--network") + 1], "none")
            self.assertEqual(argv[argv.index("--user") + 1], "10001:10001")
            self.assertIn("--read-only", argv)
            self.assertIn("--cap-drop", argv)
            self.assertEqual(
                argv[argv.index("--entrypoint") + 1], "/usr/local/bin/python"
            )
            docker.return_value = json.dumps(
                {"files": {"wrong.py": "0" * 64}, "executables": {}}
            )
            with patch.object(
                shared, "command", return_value=b"vardrrunner/__init__.py\0"
            ):
                with self.assertRaises(shared.AcceptanceRefused):
                    shared.image_source("runner", source, IMAGE, "project", docker)

    def test_qualification_is_genuine_and_public_fields_are_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            value, measurement, raw = self.fixture(temporary)
            with (
                patch.object(shared, "image_source", return_value=measurement),
                patch.object(bootstrap, "Bootstrap") as fixture,
            ):
                fixture.return_value.run.return_value = raw
                value.run_bootstrap()
            self.assertEqual(value.receipt["status"], "passed_configuration_refusals")
            self.assertEqual(
                set(value.receipt["sources"]), {"distribution", "runner", "gate"}
            )
            self.assertEqual(value.receipt["owned_stopped_container_count"], 2)
            self.assertEqual(value.receipt["nm2_exit_status"], "incomplete")
            self.assertNotIn("private-canary", json.dumps(value.receipt))
            qualified = json.loads((value.root / "bootstrap-build.json").read_bytes())
            self.assertEqual(
                qualified["status"], "passed_frozen_build_dependency_probe"
            )
            self.assertEqual(
                qualified["source_hashes"]["container/worker_owner.c"],
                hashlib.sha256(b"synthetic owner source\n").hexdigest(),
            )
            self.assertEqual(qualified["owner_binary_sha256"], OWNER)
            argv = value.docker.call_args.args
            self.assertEqual(argv[-4:], ("-I", "-m", "pip", "check"))
            self.assertEqual(argv[argv.index("--network") + 1], "none")
            self.assertIn("--read-only", argv)

    def test_failed_dependency_probe_never_runs_cases(self):
        with tempfile.TemporaryDirectory() as temporary:
            value, measurement, _ = self.fixture(temporary)
            value.docker.side_effect = hosted.HostedRefused("fixed")
            with (
                patch.object(shared, "image_source", return_value=measurement),
                patch.object(bootstrap, "Bootstrap") as fixture,
            ):
                with self.assertRaises(hosted.HostedRefused):
                    value.run_bootstrap()
            fixture.assert_not_called()
            self.assertFalse((value.root / "bootstrap-build.json").exists())

    def test_source_change_during_build_refuses_before_cases(self):
        with tempfile.TemporaryDirectory() as temporary:
            value, measurement, _ = self.fixture(temporary)

            def drift(*args, **kwargs):
                (value.sources["runner"] / "container/worker_owner.c").write_bytes(
                    b"changed"
                )
                return ""

            value.docker.side_effect = drift
            with (
                patch.object(shared, "image_source", return_value=measurement),
                patch.object(bootstrap, "Bootstrap") as fixture,
            ):
                with self.assertRaises(hosted.HostedRefused):
                    value.run_bootstrap()
            fixture.assert_not_called()

    def test_wrong_owner_or_case_result_cannot_become_public_pass(self):
        for fault in ("owner", "bool_exit", "readiness", "held"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                value, measurement, raw = self.fixture(temporary)
                raw = copy.deepcopy(raw)
                if fault == "owner":
                    raw["owner_binary_sha256"] = "0" * 64
                elif fault == "bool_exit":
                    raw["cases"]["unprivileged_user"]["exit_code"] = True
                elif fault == "readiness":
                    raw["cases"]["missing_setpcap"]["readiness_absent"] = False
                else:
                    raw["status"] = "held"
                with (
                    patch.object(shared, "image_source", return_value=measurement),
                    patch.object(bootstrap, "Bootstrap") as fixture,
                ):
                    fixture.return_value.run.return_value = raw
                    with self.assertRaises(hosted.HostedRefused):
                        value.run_bootstrap()
                self.assertEqual(value.receipt["status"], "held")
