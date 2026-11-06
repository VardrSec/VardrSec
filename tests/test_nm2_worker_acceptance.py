"""Source/protocol guards only; no Docker calls, real keys or target traffic."""

from contextlib import redirect_stdout
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import nm2_worker_acceptance as acceptance
import worker_runtime


class AcceptanceGuards(unittest.TestCase):
    def stop_fixture(self):
        fixture = object.__new__(acceptance.Fixture)
        fixture.project = "vardrsec-nm2-12345678"
        fixture.receipt = {}
        before = {"containers": {"a" * 64: {}}}
        current = {
            "containers": {
                key: {
                    "id": key,
                    "image": "sha256:" + "d" * 64,
                    "labels": {"com.docker.compose.project": project},
                    "state": {"running": True},
                }
                for key, project in (
                    ("a" * 64, fixture.project),
                    ("b" * 64, fixture.project),
                    ("c" * 64, "unrelated"),
                )
            }
        }
        stopped = copy.deepcopy(current)
        stopped["containers"]["b" * 64]["state"]["running"] = False
        fixture.snapshot = Mock(side_effect=[current, stopped])
        return fixture, before

    def test_cleanup_stops_only_new_exact_project_ids_and_retains_old_containers(self):
        fixture, before = self.stop_fixture()

        def docker(*arguments, **kwargs):
            if arguments[:2] == ("container", "inspect"):
                self.assertEqual(arguments[-1], "b" * 64)
                return acceptance.canonical(
                    {
                        "id": "b" * 64,
                        "image": "sha256:" + "d" * 64,
                        "project": fixture.project,
                    }
                )
            self.assertEqual(arguments, ("container", "stop", "-t", "10", "b" * 64))
            return b"bounded owned stop"

        fixture.docker = Mock(side_effect=docker)
        fixture.stop_owned(before)
        self.assertEqual(fixture.receipt["fixture_stop"]["container_ids"], ["b" * 64])
        self.assertEqual(fixture.snapshot.call_count, 2)
        self.assertEqual(fixture.docker.call_count, 2)

    def test_cleanup_refuses_changed_identity_before_stop(self):
        fixture, before = self.stop_fixture()
        fixture.docker = Mock(
            return_value=acceptance.canonical(
                {"id": "b" * 64, "image": "changed-image", "project": fixture.project}
            )
        )
        with self.assertRaisesRegex(
            acceptance.AcceptanceRefused, "fixture_stop_identity_changed"
        ):
            fixture.stop_owned(before)
        self.assertEqual(fixture.docker.call_count, 1)

    def selection(self, directory):
        sources = {}
        for name in acceptance.SOURCE_NAMES:
            source = directory / "sources" / name
            source.mkdir(parents=True)
            sources[name] = {"path": str(source), "commit": "a" * 40}
        distribution = Path(sources["distribution"]["path"])
        for name in (
            "compose.yaml",
            "compose.worker.json",
            "vardrsec.py",
            "database_roles.py",
            "worker_host.py",
            "worker_runtime.py",
            "worker_secrets.py",
            "worker_volumes.py",
            "worker_cli.py",
            "tests/gate/target.py",
            "tests/nm2_worker_acceptance.py",
            "tests/nm2_worker_inventory.py",
            "tests/nm2_worker_target.py",
        ):
            target = distribution / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("public fixture source")
        return {
            "schema": "vardr.nm2-worker-cohort/1",
            "sources": sources,
            "images": {name: "sha256:" + "b" * 64 for name in acceptance.IMAGE_NAMES},
            "docker_context": "desktop-linux",
            "project": "vardrsec-nm2-12345678",
            "installation": str(directory / "installation"),
            "private_root": str(directory / "private"),
            "https_port": 28443,
            "application_subnet": "172.29.217.0/24",
            "allow_empty_builtin_bridge_id_change": False,
        }

    @staticmethod
    def git_only(arguments, **kwargs):
        if arguments[0] != "git":
            raise AssertionError("Source validation must not use Docker")
        return b"a" * 40 + b"\n" if "rev-parse" in arguments else b""

    def test_default_validates_sources_without_creating_or_contacting_docker(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            selection = self.selection(directory)
            path = directory / "cohort.json"
            path.write_text(json.dumps(selection))
            output = io.StringIO()
            with (
                patch.object(acceptance, "command", side_effect=self.git_only),
                patch.object(
                    acceptance.Fixture,
                    "run",
                    side_effect=AssertionError("execution is explicit"),
                ),
                redirect_stdout(output),
            ):
                self.assertEqual(acceptance.main(["--cohort", str(path)]), 0)
            receipt = json.loads(output.getvalue())
            self.assertEqual(receipt["status"], "sources_validated_runtime_not_run")
            self.assertEqual(receipt["docker_calls"], 0)
            self.assertFalse(Path(selection["installation"]).exists())
            self.assertFalse(Path(selection["private_root"]).exists())

    def test_mutable_or_existing_selections_fail_before_docker(self):
        for mutation in (
            "mutable_image",
            "existing_installation",
            "shared_private_root",
            "old_project",
            "source_mismatch",
            "dirty_source",
            "public_helper_untracked",
        ):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                directory = Path(temporary)
                selection = self.selection(directory)
                if mutation == "mutable_image":
                    selection["images"]["worker"] = "worker:latest"
                elif mutation == "existing_installation":
                    Path(selection["installation"]).mkdir()
                elif mutation == "shared_private_root":
                    selection["private_root"] = selection["installation"]
                elif mutation == "old_project":
                    selection["project"] = "vardrsec-compose-review"
                path = directory / "cohort.json"
                path.write_text(json.dumps(selection))

                def selected_git(arguments, **kwargs):
                    result = self.git_only(arguments)
                    if mutation == "source_mismatch" and "rev-parse" in arguments:
                        return b"c" * 40
                    if mutation == "dirty_source" and "status" in arguments:
                        return b" M managed_worker.py\n"
                    if (
                        mutation == "public_helper_untracked"
                        and "--error-unmatch" in arguments
                    ):
                        raise acceptance.AcceptanceRefused("fixture_command_failed")
                    return result

                with (
                    patch.object(acceptance, "command", side_effect=selected_git),
                    self.assertRaises(acceptance.AcceptanceRefused),
                ):
                    acceptance.manifest(path)

    def test_exact_old_state_and_tags_are_preserved(self):
        before = {
            "containers": {
                "old-stopped": {"id": "old-stopped", "state": "stopped", "labels": {}}
            },
            "networks": {
                "old-network": {
                    "id": "old-network",
                    "name": "owned-old",
                    "labels": {},
                    "containers": {},
                }
            },
            "volumes": {"old-volume": {"labels": {}}},
            "images": {"old-image": {"tags": ["development"]}},
        }
        after = copy.deepcopy(before)
        after["containers"]["fixture"] = {
            "id": "fixture",
            "labels": {"com.docker.compose.project": "vardrsec-nm2-12345678"},
        }
        self.assertEqual(
            acceptance.unchanged_inventory(before, after, "vardrsec-nm2-12345678"), []
        )
        for kind, key, change in (
            ("containers", "old-stopped", {"state": "running"}),
            ("volumes", "old-volume", {"changed": True}),
            ("images", "old-image", {"tags": []}),
        ):
            bad = copy.deepcopy(after)
            bad[kind][key].update(change)
            with (
                self.subTest(kind=kind),
                self.assertRaises(acceptance.AcceptanceRefused),
            ):
                acceptance.unchanged_inventory(before, bad, "vardrsec-nm2-12345678")
        after["containers"]["unowned"] = {"id": "unowned", "labels": {}}
        with self.assertRaisesRegex(
            acceptance.AcceptanceRefused, "unowned_new_resource"
        ):
            acceptance.unchanged_inventory(before, after, "vardrsec-nm2-12345678")

    def test_remote_or_unknown_context_refuses_before_creating_resources(self):
        with tempfile.TemporaryDirectory() as temporary:
            selection = self.selection(Path(temporary))
            fixture = acceptance.Fixture(selection)
            with (
                patch("sys.path", list(sys.path)),
                patch.object(
                    worker_runtime.LocalDocker,
                    "daemon",
                    side_effect=worker_runtime.RuntimeRefused("worker_runtime_refused"),
                ),
                patch.object(fixture, "docker") as docker,
                patch.object(fixture, "snapshot") as snapshot,
                patch.object(fixture, "stage") as stage,
            ):
                with self.assertRaises(worker_runtime.RuntimeRefused):
                    fixture.run()
            docker.assert_not_called()
            snapshot.assert_not_called()
            stage.assert_not_called()

    def test_mismatched_image_source_refuses_before_platform_setup(self):
        with tempfile.TemporaryDirectory() as temporary:
            selection = self.selection(Path(temporary))
            source = Path(selection["sources"]["map"]["path"]) / "backend" / "main.py"
            source.parent.mkdir()
            source.write_bytes(b"# approved source\r\n")
            fixture = acceptance.Fixture(selection)
            with (
                patch.object(acceptance, "command", return_value=b"backend/main.py\0"),
                patch.object(
                    fixture,
                    "docker",
                    return_value=json.dumps(
                        {
                            "files": {"main.py": "different-image-source"},
                            "executables": {},
                        }
                    ).encode(),
                ) as docker,
                self.assertRaisesRegex(
                    acceptance.AcceptanceRefused, "image_source_inventory_mismatch"
                ),
            ):
                fixture.image_sources()
            arguments = docker.call_args.args
            self.assertEqual(arguments[arguments.index("--network") + 1], "none")
            self.assertEqual(arguments[arguments.index("--user") + 1], "10001:10001")
            self.assertEqual(arguments[arguments.index("--cap-drop") + 1], "ALL")
            self.assertIn("--read-only", arguments)

    def test_empty_builtin_bridge_id_admission_is_explicit_and_semantic(self):
        before = {kind: {} for kind in ("containers", "networks", "volumes", "images")}
        before["networks"]["old"] = {
            "id": "old",
            "name": "bridge",
            "driver": "bridge",
            "containers": {},
            "labels": {},
        }
        after = copy.deepcopy(before)
        after["networks"] = {"new": {**before["networks"]["old"], "id": "new"}}
        with self.assertRaises(acceptance.AcceptanceRefused):
            acceptance.unchanged_inventory(before, after, "vardrsec-nm2-12345678")
        self.assertEqual(
            acceptance.unchanged_inventory(
                before, after, "vardrsec-nm2-12345678", admit_bridge=True
            ),
            [{"kind": "empty_builtin_bridge_id", "before": "old", "after": "new"}],
        )
        after["networks"]["new"]["containers"] = {"unexpected": {}}
        with self.assertRaises(acceptance.AcceptanceRefused):
            acceptance.unchanged_inventory(
                before, after, "vardrsec-nm2-12345678", admit_bridge=True
            )

    def test_http_delay_stays_bounded_without_process_fixtures(self):
        source = Path(acceptance.__file__).with_name("nm2_worker_target.py")
        spec = importlib.util.spec_from_file_location("controlled_nm2_target", source)
        module = importlib.util.module_from_spec(spec)
        environment = {
            f"FIXTURE_{name}_TOKEN": name for name in ("OWNER", "PEER", "READER")
        }
        with (
            patch.dict("os.environ", environment),
            patch.dict(sys.modules),
            patch("sys.path", [str(source.parent / "gate"), *sys.path]),
        ):
            spec.loader.exec_module(module)
        for value in ("0", "15"):
            self.assertEqual(module.response_delay(value), int(value))
        for value in ("-1", "16", "900", "1", "nan"):
            with self.assertRaises(ValueError):
                module.response_delay(value)
        instance = object.__new__(module.ControlledTarget)
        instance.command, instance.path, instance.delay = "GET", "/fixed/records/42", 15
        with (
            patch.object(module.time, "sleep") as sleep,
            patch.object(module.Target, "reply", side_effect=BrokenPipeError),
        ):
            self.assertIsNone(instance.reply(200, {}))
        sleep.assert_called_once_with(15)


if __name__ == "__main__":
    unittest.main()
