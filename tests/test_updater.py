import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import recovery
import updater


class UpdaterTests(unittest.TestCase):
    def candidate(self):
        return {
            "schema_version": 1,
            "public_origin": "https://localhost:8443",
            "images": {s: "sha256:" + "a" * 64 for s in recovery.SERVICES},
            "components": {s: "b" * 40 for s in ("map", "runner", "gate")},
        }

    def test_mutable_image_and_database_changes_fail_before_docker(self):
        for service, image in (("api", "latest"), ("db", "sha256:" + "c" * 64)):
            with (
                self.subTest(service=service),
                tempfile.TemporaryDirectory() as directory,
                patch.object(recovery, "command") as command,
            ):
                value = self.candidate()
                baseline = dict(value["images"])
                value["images"][service] = image
                path = Path(directory) / "candidate.json"
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    updater.candidate_set(path, baseline, value["public_origin"])
                command.assert_not_called()

    def test_valid_candidate_is_inspected_without_pulling(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(recovery, "command") as command,
        ):
            value = self.candidate()
            path = Path(directory) / "candidate.json"
            path.write_text(json.dumps(value))
            self.assertEqual(
                updater.candidate_set(path, value["images"], value["public_origin"]),
                value,
            )
            self.assertEqual(command.call_count, 5)
            self.assertTrue(
                all(c.args[1:3] == ("image", "inspect") for c in command.call_args_list)
            )

    def test_lock_excludes_a_second_operation_and_releases_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with updater.installation_lock(root):
                with self.assertRaisesRegex(ValueError, "Another installation"):
                    with updater.installation_lock(root):
                        self.fail("Concurrent operation entered")
            with self.assertRaises(RuntimeError):
                with updater.installation_lock(root):
                    raise RuntimeError("fixture interruption")
            with updater.installation_lock(root):
                pass

    def test_pending_mutation_blocks_start_and_unsafe_cancel(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(recovery, "compose") as compose,
        ):
            root = Path(directory)
            updater.save(root / updater.STATE, {"phase": "applying"})
            with self.assertRaisesRegex(ValueError, "pending or failed"):
                with updater.operation_guard(root, "start"):
                    self.fail("Pending update must block startup")
            with self.assertRaisesRegex(ValueError, "mutation may have occurred"):
                updater.cancel(root)
            compose.assert_not_called()
            self.assertTrue((root / updater.STATE).exists())

    def test_private_proxy_refuses_an_accidentally_published_port(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(updater, "private_proxy"),
            patch.object(
                recovery,
                "container",
                return_value={
                    "NetworkSettings": {"Ports": {"8443/tcp": [{"HostPort": "8443"}]}}
                },
            ),
        ):
            with self.assertRaisesRegex(ValueError, "must not publish"):
                updater.verify_private(Path(directory), "fixture")


if __name__ == "__main__":
    unittest.main()
