"""Pure fail-closed cohort checks; no network, containers or hosted fixtures."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import hashlib
import unittest
import tempfile

import acl_cohort_acceptance as cohort


class CohortGuards(unittest.TestCase):
    def test_host_boundary(self):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
        release = {"ID": "ubuntu", "VERSION_ID": "24.04"}
        cohort.validate_environment(env, "Linux", release)
        for key in cohort.OVERRIDES | {"GIT_CONFIG_COUNT"}:
            with self.subTest(key=key), self.assertRaises(ValueError):
                cohort.validate_environment({**env, key: ""}, "Linux", release)
        for changed in ({}, {**env, "RUNNER_ENVIRONMENT": "self-hosted"}):
            with self.assertRaises(ValueError):
                cohort.validate_environment(changed, "Linux", release)
        for system, version in (("Windows", "24.04"), ("Linux", "22.04")):
            with self.assertRaises(ValueError):
                cohort.validate_environment(env, system, {**release, "VERSION_ID": version})

    def test_exact_trigger(self):
        event = {"number": 114, "repository": {"full_name": "VardrSec/VardrSec"}, "pull_request": {"head": {"ref": "codex/acl-caller-security", "sha": "a" * 40, "repo": {"full_name": "VardrSec/VardrSec"}}}}
        self.assertEqual(cohort.expected_head(event, "pull_request"), "a" * 40)
        for bad in ("main", "a" * 39, "A" * 40):
            changed = copy.deepcopy(event)
            changed["pull_request"]["head"]["sha"] = bad
            with self.assertRaises(ValueError):
                cohort.expected_head(changed, "pull_request")
        changed = copy.deepcopy(event)
        changed["pull_request"]["head"]["repo"]["full_name"] = "other/fork"
        with self.assertRaises(ValueError):
            cohort.expected_head(changed, "pull_request")
        with self.assertRaises(ValueError):
            cohort.expected_head(event, "workflow_dispatch")
        push = {"repository": event["repository"], "ref": "refs/heads/main", "after": "b" * 40}
        with self.assertRaises(ValueError):
            cohort.expected_head(push, "push")
        with self.assertRaises(ValueError):
            cohort.expected_head({**event, "number": 115}, "pull_request")
        changed = copy.deepcopy(event)
        changed["pull_request"]["head"]["ref"] = "other-branch"
        with self.assertRaises(ValueError):
            cohort.expected_head(changed, "pull_request")
        with self.assertRaises(ValueError):
            cohort.expected_head({**push, "ref": "refs/heads/unreviewed"}, "push")

    def test_delta_hash_and_paths(self):
        patch = b"fixed reviewed delta"
        spec = {"patch_sha256": hashlib.sha256(patch).hexdigest(), "paths": ["Dockerfile"]}
        cohort.verify_patch(patch, ["Dockerfile"], spec)
        for body, paths in ((patch + b"\n", ["Dockerfile"]), (patch, ["Dockerfile", "requirements.txt"]), (patch, [])):
            with self.assertRaises(ValueError):
                cohort.verify_patch(body, paths, spec)

    def test_exact_tree_entries_and_untouched_files(self):
        old = {"Dockerfile": "100644 blob old", "requirements.txt": "100644 blob pinned"}
        new = {**old, "Dockerfile": "100644 blob reviewed"}
        cohort.verify_trees(old, new, new, ["Dockerfile"])
        for entry in ("100755 blob reviewed", "120000 blob reviewed", "160000 commit reviewed", "100644 blob different"):
            with self.assertRaises(ValueError):
                cohort.verify_trees(old, new, {**new, "Dockerfile": entry}, ["Dockerfile"])
        for changed in ({"Dockerfile": new["Dockerfile"]}, {**new, "requirements.txt": "100644 blob newer"}, {**new, "extra": "100644 blob added"}):
            with self.assertRaises(ValueError):
                cohort.verify_trees(old, new, changed, ["Dockerfile"])
        for path in ("../escape", "/absolute", ".git/config", "a/../escape", "a//b"):
            with self.assertRaises(ValueError):
                cohort.verify_trees({}, {path: "100644 blob new"}, {path: "100644 blob new"}, [path])

    def test_generated_local_build_aliases(self):
        suffix = "local-" + "a" * 32
        tags = {name: repo + ":" + suffix for name, repo in cohort.IMAGE_REPOSITORIES.items()}
        model = {"services": {name: {"image": tag} for name, tag in tags.items()}}
        model["services"]["proxy"] = {"image": "vardrsec-proxy:" + suffix}
        self.assertEqual(cohort.build_image_tags(model), tags)
        for name in tags:
            for bad in (cohort.IMAGE_REPOSITORIES[name] + ":development", "unreviewed:local-" + "a" * 32, "sha256:" + "a" * 64, cohort.IMAGE_REPOSITORIES[name] + ":local-" + "b" * 32):
                changed = copy.deepcopy(model)
                changed["services"][name]["image"] = bad
                with self.subTest(name=name, alias=bad), self.assertRaises(ValueError):
                    cohort.build_image_tags(changed)
        del model["services"]["runner"]
        with self.assertRaises(ValueError):
            cohort.build_image_tags(model)

    def test_resolves_build_aliases_without_frozen_overlay(self):
        suffix = "local-" + "a" * 32
        model = {"services": {name: {"image": repo + ":" + suffix} for name, repo in cohort.IMAGE_REPOSITORIES.items()}}
        model["services"]["proxy"] = {"image": "vardrsec-proxy:" + suffix}
        # Credentials stay in the captured configuration, never in the result.
        model["services"]["api"]["environment"] = {"SECRET": "private-fixture-value"}
        ids = {name: "sha256:" + str(i) * 64 for i, name in enumerate(cohort.IMAGE_REPOSITORIES)}
        replies = [SimpleNamespace(stdout=json.dumps(model))] + [SimpleNamespace(stdout=value + "\n") for value in ids.values()]
        fixture = Path("/disposable/distribution")
        with patch.object(cohort, "run", side_effect=replies) as mocked:
            actual, tags = cohort.image_ids(fixture)
        self.assertEqual(actual, ids)
        self.assertNotIn("private-fixture-value", repr((actual, tags)))
        config = mocked.call_args_list[0]
        self.assertEqual(config.args, ("docker", "compose", "--env-file", str(fixture / ".env"), "-f", str(fixture / "compose.yaml"), "--profile", "tools", "config", "--format", "json"))
        self.assertTrue(config.kwargs["capture_output"])
        self.assertEqual(config.kwargs["cwd"], fixture)
        for call, tag in zip(mocked.call_args_list[1:], tags.values()):
            self.assertEqual(call.args[:4], ("docker", "image", "inspect", tag))

    def test_frozen_image_binding(self):
        built = {name: "sha256:" + str(i) * 64 for i, name in enumerate(cohort.IMAGE_REPOSITORIES)}
        selection = {"services": {name: {"image": image} for name, image in built.items()}, "networks": {}}
        selection["services"]["proxy"] = {"image": "sha256:" + "f" * 64}
        self.assertEqual(cohort.selected_images(selection, built), built)
        for name in cohort.IMAGE_REPOSITORIES:
            changed = copy.deepcopy(selection)
            changed["services"][name]["image"] = "sha256:" + "e" * 64
            with self.subTest(name=name), self.assertRaises(ValueError):
                cohort.selected_images(changed, built)
        changed = copy.deepcopy(selection)
        changed["services"]["runner"]["image"] = "vardrrunner:development"
        with self.assertRaises(ValueError):
            cohort.selected_images(changed, built)
        del changed["services"]["runner"]
        with self.assertRaises(ValueError):
            cohort.selected_images(changed, built)

    def test_failed_runtime_evidence_retained_and_all_images_checked(self):
        ids = {name: "sha256:" + str(i) * 64 for i, name in enumerate(cohort.IMAGE_REPOSITORIES)}
        results = [SimpleNamespace(stdout=b"source: FAILED open or read\n", stderr=b"sha256sum: Permission denied\n", returncode=1)] + [SimpleNamespace(stdout=b"payload: OK\n", stderr=b"", returncode=0) for _ in range(3)]
        with tempfile.TemporaryDirectory() as folder:
            public = Path(folder)
            with patch.object(cohort.subprocess, "run", side_effect=results) as mocked:
                images = cohort.collect_runtime_evidence(public, ids)
            self.assertEqual(mocked.call_count, 4)
            for (name, image), result, call in zip(ids.items(), results, mocked.call_args_list):
                self.assertEqual((public / (name + "-acl.log")).read_bytes(), result.stdout)
                self.assertEqual((public / (name + "-acl.stderr.log")).read_bytes(), result.stderr)
                saved = json.loads((public / (name + "-acl.result.json")).read_text())
                self.assertEqual(saved["returncode"], result.returncode)
                self.assertEqual(saved["image_id"], image)
                self.assertEqual(saved["stderr_sha256"], cohort.digest(result.stderr))
                self.assertFalse(call.kwargs["check"])
                self.assertIn("--cap-drop", call.args[0])
                self.assertIn("ALL", call.args[0])
                self.assertEqual(call.args[0][-1], cohort.RUNTIME_CHECK)
            receipt = {"status": "built-not-qualified"}
            with self.assertRaises(ValueError):
                cohort.finish_runtime_verdict(public, receipt, images, b"joint smoke passed")
            self.assertEqual(receipt["status"], "FAIL")
            self.assertEqual(json.loads((public / "provenance.json").read_text())["status"], "FAIL")

    def test_runtime_verdict_requires_all_four_successes(self):
        with tempfile.TemporaryDirectory() as folder:
            public = Path(folder)
            images = {name: {"returncode": 0} for name in cohort.IMAGE_REPOSITORIES}
            receipt = {}
            cohort.finish_runtime_verdict(public, receipt, images, b"joint smoke passed")
            self.assertEqual(receipt["status"], "PASS")
            for name in cohort.IMAGE_REPOSITORIES:
                incomplete = {key: value for key, value in images.items() if key != name}
                with self.subTest(missing=name), self.assertRaises(ValueError):
                    cohort.finish_runtime_verdict(public, receipt, incomplete, b"joint smoke passed")
                self.assertEqual(receipt["status"], "FAIL")

    def candidate_selection(self, mutation=None, empty_history=False):
        # Exercise real Git trees offline; only the network transport is replaced.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            real_git = cohort.git
            real_git(source, "init")
            (source / "Dockerfile").write_text("FROM stock\n")
            real_git(source, "add", ".")
            tree = cohort.text(source, "write-tree")
            env = {**cohort.os.environ, "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.invalid", "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.invalid"}
            pin = cohort.run("git", "-C", str(source), "commit-tree", tree, input=b"pin\n", env=env, capture_output=True).stdout.decode().strip()
            real_git(source, "checkout", "--detach", pin)
            base = pin
            if not empty_history:
                (source / "requirements.txt").write_text("dependency==2\n")
                real_git(source, "add", ".")
                base, _ = cohort.commit_fixture(source, pin, "reviewed history")
            (source / "Dockerfile").write_text("FROM fixed\n")
            real_git(source, "add", ".")
            head, expected_tree = cohort.commit_fixture(source, base, "ACL delta")
            diff = lambda a, b: real_git(source, "diff", "--binary", "--full-index", "--no-ext-diff", a, b, "--")
            spec = {"repository": "example/offline", "pin": pin, "base": base, "head": head,
                    "patch_sha256": cohort.digest(diff(base, head)), "paths": ["Dockerfile"],
                    "history_sha256": cohort.digest(diff(pin, base)), "history_paths": [] if empty_history else ["requirements.txt"]}
            if mutation:
                spec.update(mutation)
            def offline_fetch(path, repository, sha):
                cohort.run("git", "clone", "--no-hardlinks", str(source), str(path), capture_output=True)
                real_git(path, "checkout", "--detach", sha)
            def offline_git(path, *args, **kwargs):
                if args[0] == "fetch":
                    return b""
                return real_git(path, *args, **kwargs)
            selected = root / "selected"
            with patch.object(cohort, "fetch_source", side_effect=offline_fetch), patch.object(cohort, "git", side_effect=offline_git):
                result = cohort.apply_cohort(selected, spec)
            self.assertEqual(result["selected_commit"], head)
            self.assertEqual(result["selected_tree"], expected_tree)
            self.assertEqual(cohort.text(selected, "rev-parse", "HEAD"), head)
            self.assertNotIn("fixture_commit", result)
            if not empty_history:
                self.assertEqual((selected / "requirements.txt").read_text(), "dependency==2\n")

    def test_exact_newer_head_is_selected(self):
        self.candidate_selection()

    def test_exact_head_with_empty_history_is_selected(self):
        self.candidate_selection(empty_history=True)

    def test_unreviewed_history_hash_refused(self):
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.candidate_selection({"history_sha256": "0" * 64})

    def test_unreviewed_history_path_refused(self):
        with self.assertRaisesRegex(ValueError, "Unreviewed delta path"):
            self.candidate_selection({"history_paths": ["unexpected"]})

    def test_unreviewed_acl_hash_refused_after_history(self):
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.candidate_selection({"patch_sha256": "0" * 64})

    def test_constant_scope(self):
        self.assertEqual(len(cohort.COHORT["map"]["paths"]), 18)
        self.assertEqual(len(cohort.COHORT["runner"]["paths"]), 10)
        for spec in cohort.COHORT.values():
            self.assertEqual(len(spec["patch_sha256"]), 64)
            self.assertEqual(len(spec["history_sha256"]), 64)
            self.assertEqual(spec["history_paths"], sorted(spec["history_paths"]))
            for key in ("head", "base", "pin"):
                self.assertRegex(spec[key], r"^[0-9a-f]{40}$")
            self.assertNotIn("versions.json", spec["paths"])
            self.assertFalse(any("package.json" in p or "requirements" in p for p in spec["paths"]))


if __name__ == "__main__":
    unittest.main()
