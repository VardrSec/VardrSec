"""Exercise the installed Full image gate with fixed IDs and fake Docker results."""

from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import acl_runtime_acceptance as acl


class InstalledACLRuntime(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.ids = {name: "sha256:" + str(i) * 64 for i, name in enumerate(("db", "api", "web", "runner", "proxy"))}
        frozen = {"services": {name: {"image": image} for name, image in self.ids.items()}, "networks": {}}
        self.active = self.root / ".active-images.json"
        self.active.write_text(json.dumps(frozen))
        (self.root / "versions.json").write_text("{}")
        self.model = {"name": "installed-test", "services": frozen["services"]}
        mocks = ExitStack()
        self.addCleanup(mocks.close)
        mocks.enter_context(patch.object(acl.updater, "image_set", return_value=(self.model, self.ids)))
        self.aliases = {name: name + ":local-build" for name in acl.SERVICES}
        self.built = {alias: self.ids[name] for name, alias in self.aliases.items()}
        mocks.enter_context(patch.object(acl.recovery, "command", side_effect=self.build_command))
        self.docker = mocks.enter_context(patch.object(acl.subprocess, "run"))
        self.joint = self.root / acl.JOINT_RECEIPT
        self.joint.parent.mkdir(parents=True)

    def build_command(self, *args, **kwargs):
        if args[:2] == ("docker", "compose"):
            self.assertEqual(args[2:], ("--env-file", str(self.root / ".env"), "-f", str(self.root / "compose.yaml"),
                                        "--profile", "tools", "config", "--format", "json"))
            services = {name: {"image": alias, "build": {"context": "."}} for name, alias in self.aliases.items()}
            return subprocess.CompletedProcess(args, 0, json.dumps({"services": services}))
        self.assertEqual(args[:-1], ("docker", "image", "inspect", "--format", "{{.Id}}"))
        return subprocess.CompletedProcess(args, 0, self.built[args[-1]] + "\n")

    def test_rejects_stale_build_alias_even_when_installed_runner_matches(self):
        alias = self.aliases["runner"]
        self.built[alias] = "sha256:" + "e" * 64
        with self.assertRaisesRegex(ValueError, "Build alias.*runner"):
            acl.capture(self.root)
        self.built[alias] = self.ids["runner"]
        acl.capture(self.root)
        self.accept_joint()
        self.built[alias] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(ValueError, "Build alias.*runner"):
            acl.verify(self.root)
        self.docker.assert_not_called()

    def accept_joint(self):
        self.joint.write_text(json.dumps({"jobs": [{"scenario": "installed"}]}))

    def test_each_image_can_block_the_release_and_preserves_diagnostics(self):
        for failed in ("db", "api", "web", "runner", None):
            with self.subTest(failed=failed):
                public = self.root / (failed or "passing")
                with patch.object(acl, "OUTPUT", public):
                    acl.capture(self.root)
                    self.accept_joint()
                    results = [
                        subprocess.CompletedProcess([], 17, b"payload failed\n", b"hash mismatch\n")
                        if name == failed else subprocess.CompletedProcess([], 0, b"payload OK\n", b"")
                        for name in ("db", "api", "web", "runner")
                    ]
                    self.docker.reset_mock()
                    self.docker.side_effect = results
                    if failed:
                        with self.assertRaisesRegex(ValueError, failed):
                            acl.verify(self.root)
                    else:
                        acl.verify(self.root)
                    self.joint.unlink()

                verdict = json.loads((public / "verdict.json").read_bytes())
                self.assertEqual(verdict["status"], "FAIL" if failed else "PASS")
                self.assertEqual(set(verdict["images"]), {"db", "api", "web", "runner"})
                self.assertEqual(self.docker.call_count, 4)
                for name, result, call in zip(("db", "api", "web", "runner"), results, self.docker.call_args_list):
                    self.assertEqual(call.args[0], [
                        "docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL",
                        "--security-opt", "no-new-privileges", "--entrypoint", "sh", self.ids[name], "-ec", acl.RUNTIME_CHECK,
                    ])
                    self.assertEqual((public / f"{name}-acl.log").read_bytes(), result.stdout)
                    self.assertEqual((public / f"{name}-acl.stderr.log").read_bytes(), result.stderr)
                    row = json.loads((public / f"{name}-acl.result.json").read_bytes())
                    self.assertEqual(row, verdict["images"][name])
                    self.assertEqual(row["returncode"], result.returncode)
                    self.assertEqual(row["image_id"], self.ids[name])
                    self.assertEqual(row["stderr_sha256"], hashlib.sha256(result.stderr).hexdigest())

    def test_fresh_joint_receipt_is_required(self):
        self.accept_joint()
        with self.assertRaisesRegex(ValueError, "already exists"):
            acl.capture(self.root)
        self.joint.unlink()
        acl.capture(self.root)
        with self.assertRaisesRegex(ValueError, "missing"):
            acl.verify(self.root)
        self.joint.write_text("{}")
        with self.assertRaisesRegex(ValueError, "no jobs"):
            acl.verify(self.root)
        self.docker.assert_not_called()

    def test_rejects_changed_selection_or_installed_image(self):
        acl.capture(self.root)
        self.accept_joint()
        original = self.active.read_bytes()
        self.active.write_bytes(original + b"\n")
        with self.assertRaisesRegex(ValueError, "changed during smoke"):
            acl.verify(self.root)
        self.active.write_bytes(original)
        self.ids["web"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(ValueError, "differ from the frozen selection"):
            acl.verify(self.root)
        self.docker.assert_not_called()

    def test_rejects_mutable_runner_even_if_docker_resolves_it(self):
        self.ids["runner"] = "runner:local"
        self.model["services"]["runner"]["image"] = self.ids["runner"]
        self.active.write_text(json.dumps({"services": self.model["services"], "networks": {}}))
        with self.assertRaisesRegex(ValueError, "immutable"):
            acl.capture(self.root)
        self.docker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
