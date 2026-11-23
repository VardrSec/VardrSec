import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import database_image as db


IMAGE = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
ALIAS = "vardrsec-db:local-test"


def image_archive(path, layout, command="postgres"):
    blobs = {}

    def blob(value):
        payload = json.dumps(value).encode()
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        blobs[digest] = payload
        return digest

    config_id = blob({"os": "linux", "architecture": "amd64", "config": {"Cmd": [command]},
                      "rootfs": {"type": "layers", "diff_ids": [IMAGE, OTHER]}})
    image_id = config_id
    if layout != "classic":
        image_id = blob({"config": {"digest": config_id}})
        if layout == "oci":
            image_id = blob({"manifests": [{"platform": {"os": "linux", "architecture": "amd64"}, "digest": image_id}]})
    with tarfile.open(path, "w") as archive:
        for digest, payload in blobs.items():
            name = digest.split(":")[1]
            member = tarfile.TarInfo(name + ".json" if layout == "classic" else "blobs/sha256/" + name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    return image_id, config_id


class DatabaseImageTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.root = Path(work.name) / "repo"
        self.root.mkdir()
        self.receipt = Path(work.name) / "receipt.json"
        (self.root / "db").mkdir()
        (self.root / "db" / "Dockerfile").write_text("FROM scratch\n")
        checks = self.root / db.VERIFY_DIR
        checks.mkdir(parents=True)
        for name in db.SCRIPTS:
            (checks / name).write_bytes(b"exit 0\n")
        self.git("init", "-q")
        self.git("config", "core.autocrlf", "false")
        self.git("add", ".")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "commit", "--no-gpg-sign", "-qm", "inputs")
        self.service = {"build": {"context": str(self.root / "db")}, "image": ALIAS}
        self.model = {"services": {"db": self.service}}

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.root), *args], check=True)

    def receipt_data(self):
        return {"schema": db.RECEIPT_SCHEMA, "platform": db.PLATFORM, "inputs": db.build_inputs(self.root), "image_id": IMAGE}

    def test_localize_proves_identical_config_between_classic_and_containerd_stores(self):
        for producer, local in [("classic", "oci"), ("oci", "classic"), ("oci", "manifest"), ("classic", "classic")]:
            with self.subTest(producer=producer, local=local):
                source = self.receipt.parent / "producer.tar"
                producer_id, config = image_archive(source, producer)
                saved = self.receipt.parent / "engine.tar"
                local_id, _ = image_archive(saved, local)
                self.receipt.write_text(json.dumps({**self.receipt_data(), "image_id": producer_id}))
                output = self.receipt.parent / f"{producer}-{local}.json"
                with patch.object(db, "subprocess") as docker:
                    docker.check_output.return_value = json.dumps({"Id": local_id, "Os": "linux", "Architecture": "amd64",
                                                                  "RootFS": {"Type": "layers", "Layers": [IMAGE, OTHER]}})
                    def local_save(command, check):
                        self.assertEqual(command[:4], ["docker", "image", "save", "--output"])
                        self.assertEqual(command[5], local_id)
                        Path(command[4]).write_bytes(saved.read_bytes())
                    docker.run.side_effect = local_save
                    self.assertEqual(db.localize_receipt(self.root, self.receipt, source, local_id, output), local_id)
                    self.assertEqual(docker.run.call_count, int(local == "oci"))
                self.assertEqual(db.validate_receipt(self.root, output), local_id)
                self.assertEqual(json.loads(output.read_text())["origin"], {"image_id": producer_id, "config_id": config})

    def test_localize_rejects_substitution_even_with_identical_layers(self):
        source = self.receipt.parent / "producer.tar"
        qualified, _ = image_archive(source, "oci")
        self.receipt.write_text(json.dumps({**self.receipt_data(), "image_id": qualified}))
        alternate = self.receipt.parent / "different.tar"
        wrong_id, _ = image_archive(alternate, "classic", command="altered-entrypoint")
        output = self.receipt.parent / "local.json"
        with patch.object(db, "subprocess") as docker:
            docker.check_output.return_value = json.dumps({"Id": wrong_id, "Os": "linux", "Architecture": "amd64",
                                                           "RootFS": {"Type": "layers", "Layers": [IMAGE, OTHER]}})
            docker.run.side_effect = lambda command, check: Path(command[4]).write_bytes(alternate.read_bytes())
            with self.assertRaisesRegex(ValueError, "differs from the qualified image configuration"):
                db.localize_receipt(self.root, self.receipt, source, wrong_id, output)
            with self.assertRaisesRegex(ValueError, "immutable"):
                db.localize_receipt(self.root, self.receipt, source, ALIAS, output)
            docker.check_output.return_value = json.dumps({"Id": qualified, "Os": "linux", "Architecture": "amd64",
                                                           "RootFS": {"Type": "layers", "Layers": [OTHER, IMAGE]}})
            with self.assertRaisesRegex(ValueError, "layer identity"):
                db.localize_receipt(self.root, self.receipt, source, qualified, output)
        self.assertFalse(output.exists())

    def test_select_tags_absent_alias_and_checks_immutable_id(self):
        self.receipt.write_text(json.dumps(self.receipt_data()))
        with patch.object(db, "inspect_local", return_value=IMAGE) as inspect, \
             patch.object(db.subprocess, "check_output", return_value=""), \
             patch.object(db, "build_inputs", return_value=json.loads(self.receipt.read_text())["inputs"]), \
             patch.object(db.subprocess, "run") as run:
            self.assertEqual(db.select_verified(self.root, self.receipt, self.model), IMAGE)
        self.assertEqual([c.args[0] for c in inspect.call_args_list], [IMAGE, ALIAS])
        run.assert_called_once_with(["docker", "image", "tag", IMAGE, ALIAS], check=True)

    def test_existing_different_alias_is_preserved(self):
        receipt = self.receipt_data()
        self.receipt.write_text(json.dumps(receipt))
        with patch.object(db, "inspect_local", side_effect=[IMAGE, OTHER]), \
             patch.object(db, "build_inputs", return_value=receipt["inputs"]), \
             patch.object(db.subprocess, "check_output", return_value=OTHER + "\n"), \
             patch.object(db.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "different image"):
                db.select_verified(self.root, self.receipt, self.model)
            run.assert_not_called()

    def test_matching_existing_alias_needs_no_tag(self):
        receipt = self.receipt_data()
        self.receipt.write_text(json.dumps(receipt))
        with patch.object(db, "inspect_local", return_value=IMAGE), \
             patch.object(db, "build_inputs", return_value=receipt["inputs"]), \
             patch.object(db.subprocess, "check_output", return_value="a" * 12 + "\n"), \
             patch.object(db.subprocess, "run") as run:
            self.assertEqual(db.select_verified(self.root, self.receipt, self.model), IMAGE)
            run.assert_not_called()

    def test_unavailable_immutable_image_fails_before_tag_or_build(self):
        receipt = self.receipt_data()
        self.receipt.write_text(json.dumps(receipt))
        with patch.object(db, "inspect_local") as inspect:
            self.assertEqual(db.validate_receipt(self.root, self.receipt), IMAGE)
            inspect.assert_not_called()
        missing = subprocess.CalledProcessError(1, ["docker", "image", "inspect", IMAGE])
        with patch.object(db, "inspect_local", side_effect=missing), \
             patch.object(db, "build_inputs", return_value=receipt["inputs"]), \
             patch.object(db.subprocess, "run") as run:
            for action in (lambda: db.select_verified(self.root, self.receipt, self.model),
                           lambda: db.prepare(self.root, self.receipt)):
                with self.assertRaises(subprocess.CalledProcessError):
                    action()
            run.assert_not_called()

    def test_rejects_dirty_changed_and_untracked_inputs(self):
        receipt = self.receipt_data()
        self.receipt.write_text(json.dumps(receipt))
        for path in [self.root / "db" / "Dockerfile", self.root / db.VERIFY_DIR / "acl-runtime-check.sh"]:
            with self.subTest(path=path.name):
                path.write_text("changed\n")
                with self.assertRaisesRegex(ValueError, "local changes"):
                    db.read_receipt(self.root, self.receipt)
                self.git("restore", "--", str(path))
        (self.root / "db" / "extra").write_text("untracked")
        with self.assertRaisesRegex(ValueError, "local changes"):
            db.read_receipt(self.root, self.receipt)
        self.git("add", "db/extra")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "commit", "--no-gpg-sign", "-qm", "new tree")
        with self.assertRaisesRegex(ValueError, "different build"):
            db.read_receipt(self.root, self.receipt)

    def test_refuses_untrusted_alias_build_override_and_mutable_receipt_id(self):
        for changes in [{"image": "example.invalid/db:test"}, {"platform": "linux/arm64"},
                        {"build": {**self.service["build"], "args": {"x": "y"}}}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                db.select_verified(self.root, self.receipt, {"services": {"db": {**self.service, **changes}}})
        item = self.receipt_data()
        for changes in [{"image_id": ALIAS}, {"schema": True}, {"schema": 1}, {"platform": "linux/arm64"}]:
            self.receipt.write_text(json.dumps({**item, **changes}))
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "Invalid local"):
                db.read_receipt(self.root, self.receipt)
        with patch.object(db.subprocess, "check_output", return_value=IMAGE + " linux/arm64\n"):
            with self.assertRaisesRegex(ValueError, "linux/amd64"):
                db.inspect_local(IMAGE)

    def test_rejects_ignored_files_in_the_docker_context(self):
        receipt = self.receipt_data()
        self.receipt.write_text(json.dumps(receipt))
        (self.root / ".gitignore").write_text("*.local\n")
        (self.root / "db" / "build.local").write_text("local build input")
        with self.assertRaisesRegex(ValueError, "local changes"):
            db.validate_receipt(self.root, self.receipt)

    def test_prepare_runs_verifier_on_built_id_then_reuses_receipt(self):
        helper = self.root / "db" / "tools" / "build.sh"
        helper.parent.mkdir()
        helper.write_bytes(b"#!/bin/sh\n")
        helper.chmod(0o755)
        self.git("add", "--chmod=+x", "db/tools/build.sh")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "commit", "--no-gpg-sign", "-qm", "add executable build helper")
        self.git("config", "tar.umask", "0077")
        original = subprocess.run
        invocations = []
        def run(argv, **kwargs):
            if argv[:3] == ["docker", "buildx", "build"]:
                self.assertIn("--load", argv)
                with tarfile.open(fileobj=kwargs["stdin"]) as context:
                    self.assertEqual({m.name: m.mode for m in context}, {
                        "Dockerfile": 0o644, "tools": 0o755, "tools/build.sh": 0o755,
                    })
                invocations.append("build")
            elif argv[0] == "bash":
                self.assertEqual(argv[2], IMAGE)
                self.assertEqual(Path(argv[1]).read_bytes(), b"exit 0\n")
                self.assertEqual(Path(argv[1]).with_name("acl-runtime-check.sh").read_bytes(), b"exit 0\n")
                invocations.append("verify")
            elif argv[0] == "docker":
                self.fail(f"Unexpected Docker operation: {argv}")
            else:
                return original(argv, **kwargs)
        with patch.object(db.subprocess, "run", side_effect=run), patch.object(db, "inspect_local", return_value=IMAGE):
            self.assertEqual(db.prepare(self.root, self.receipt), IMAGE)
            self.assertEqual(db.prepare(self.root, self.receipt), IMAGE)
        self.assertEqual(invocations, ["build", "verify"])
        self.assertEqual(json.loads(self.receipt.read_text()), self.receipt_data())

    def test_failed_qualification_discards_only_its_tag_and_keeps_diagnostics(self):
        original = subprocess.run
        evidence = self.receipt.parent / "failure-diagnostics"
        candidate = []
        removed = []
        failure = subprocess.CalledProcessError(17, "verify.sh")

        def fail_verification(argv, **kwargs):
            if argv[:3] == ["docker", "buildx", "build"]:
                candidate.append(argv[argv.index("--tag") + 1])
                return
            if argv[0] == "bash":
                (evidence / "check.log").write_text("failed")
                raise failure
            if argv[:3] == ["docker", "image", "rm"]:
                self.assertEqual(argv[3], "--no-prune")
                removed.append(argv[4])
                # A cleanup failure must also preserve the original verifier error.
                raise OSError("cleanup unavailable")
            return original(argv, **kwargs)

        with patch.object(db.subprocess, "run", side_effect=fail_verification), \
             patch.object(db, "inspect_local", return_value=IMAGE), self.assertRaises(subprocess.CalledProcessError) as caught:
            db.prepare(self.root, self.receipt, evidence)
        self.assertIs(caught.exception, failure)
        self.assertEqual(len(candidate), 1)
        self.assertRegex(candidate[0], r"^vardrsec-qualified-db:[a-f0-9]{32}$")
        self.assertEqual(removed, candidate)
        self.assertEqual((evidence / "check.log").read_text(), "failed")
        self.assertFalse(self.receipt.exists())

    def test_failure_cleanup_preserves_a_retargeted_candidate(self):
        candidate = "vardrsec-qualified-db:" + "c" * 32
        with patch.object(db, "inspect_local", return_value=OTHER) as inspect, \
             patch.object(db.subprocess, "run") as run:
            db.discard_candidate(candidate, IMAGE)
        inspect.assert_called_once_with(candidate)
        run.assert_not_called()
