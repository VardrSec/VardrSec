import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts.ci import database_bundle as bundle


IMAGE = "sha256:" + "a" * 64
MANIFEST = {"Config": "blobs/sha256/" + "a" * 64, "Layers": [], "RepoTags": None}


class TransportTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.archive = Path(temp.name) / "image.tar"
        self.producer = Path(temp.name) / "producer.json"
        self.local = Path(temp.name) / "local.json"

    def test_cache_key_binds_the_public_reference_and_config(self):
        pin = {"reference": "ghcr.io/vardrsec/vardrsec-db@" + IMAGE, "config_id": IMAGE}
        alternative = "sha256:" + "b" * 64
        with (
            patch.dict(os.environ, {"PASSPHRASE": "test-only", "GITHUB_REPOSITORY": "review/example"}),
            patch.object(bundle.database_image, "build_inputs", return_value={"db": "a" * 40}),
            patch.object(bundle.subprocess, "check_output", return_value=b"same Git objects"),
            patch.object(bundle.database_release, "release_pin", side_effect=[
                None, pin, dict(pin, config_id=alternative),
                dict(pin, reference="ghcr.io/vardrsec/vardrsec-db@" + alternative), pin]),
        ):
            source, approved, changed_config, changed_manifest, same = [bundle.cache_key() for _ in range(5)]
        self.assertEqual(approved, same)
        self.assertEqual(len({source, approved, changed_config, changed_manifest}), 4)

    def test_cacheless_job_exports_only_a_verified_release_receipt(self):
        selected = {"image_id": IMAGE}
        github_env = self.local.parent / "github-env"
        with (
            patch.dict(os.environ, {"RUNNER_TEMP": str(self.local.parent), "GITHUB_ENV": str(github_env)}),
            patch.object(bundle.database_release, "prepare", side_effect=[None, selected]),
        ):
            bundle.select_for_job()
            self.assertFalse(github_env.exists())
            bundle.select_for_job()
        receipt = self.local.parent / "release-database.json"
        self.assertEqual(json.loads(receipt.read_text()), selected)
        self.assertEqual(github_env.read_text().strip(), f"VARDRSEC_DATABASE_RECEIPT={receipt}")

    def test_cache_miss_qualifies_either_the_published_image_or_the_shipped_source(self):
        evidence = self.local.parent / "diagnostics"
        for released in (None, {"image_id": IMAGE}):
            with (
                self.subTest(released=released),
                patch.object(bundle.database_release, "prepare", return_value=released),
                patch.object(bundle.database_image, "prepare") as verifier,
            ):
                bundle.qualify(self.producer, evidence)
                verifier.assert_called_once_with(bundle.ROOT, self.producer, evidence, published=released)

    def test_producer_does_not_fall_back_after_a_rejected_pin(self):
        with (
            patch.object(bundle.database_release, "prepare", side_effect=ValueError("bad pin")),
            patch.object(bundle.database_image, "prepare") as qualify,
            self.assertRaisesRegex(ValueError, "bad pin"),
        ):
            bundle.qualify(self.producer, self.local.parent / "evidence")
        qualify.assert_not_called()

    def write_archive(self, entries):
        with tarfile.open(self.archive, "w:") as archive:
            for name, content in entries:
                data = json.dumps(content).encode()
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))

    def test_single_untagged_legacy_and_oci_archives_pass_the_reported_id_to_verification(self):
        index = {"schemaVersion": 2, "manifests": [{"digest": IMAGE, "annotations": {}}]}
        for extra in ([], [("index.json", index), ("repositories", {})]):
            with self.subTest(extra=extra):
                self.write_archive([("manifest.json", [MANIFEST]), *extra])
                with patch.object(bundle.subprocess, "check_output", return_value=f"Loaded image ID: {IMAGE}\n"), \
                     patch.object(bundle.database_image, "localize_receipt") as verify:
                    bundle.load_archive(self.archive, self.producer, self.local)
                verify.assert_called_once_with(bundle.ROOT, self.producer, self.archive, IMAGE, self.local)

    def test_ambiguous_archives_and_repository_tags_are_rejected_before_docker(self):
        plain = ("manifest.json", [MANIFEST])
        name_keys = ("org.opencontainers.image.ref.name", "io.containerd.image.name")
        invalid = [
            [("manifest.json", [MANIFEST, MANIFEST])], [("manifest.json", [{**MANIFEST, "RepoTags": ["db:local"]}])],
            [("manifest.json", [{**MANIFEST, "repotags": ["db:local"]}])],
            [plain, ("repositories", {"db": {"local": IMAGE}})], [plain, ("./manifest.json", [MANIFEST])],
            [plain, ("index.json", {"manifests": [{"digest": IMAGE}, {"digest": IMAGE}]})],
            [plain, ("index.json", {"manifests": [{"digest": IMAGE, "ANNOTATIONS": {"io.containerd.image.name": "db:local"}}]})],
            *[[plain, ("index.json", {"manifests": [{"digest": IMAGE, "annotations": {key: "db:local"}}]})]
              for key in name_keys],
        ]
        with patch.object(bundle.subprocess, "check_output") as load:
            for entries in invalid:
                self.write_archive(entries)
                with self.subTest(entries=entries), self.assertRaises(ValueError):
                    bundle.load_archive(self.archive, self.producer, self.local)
            load.assert_not_called()

    def test_load_must_report_one_immutable_id_and_no_unpack_error(self):
        self.write_archive([("manifest.json", [MANIFEST])])
        line = f"Loaded image ID: {IMAGE}"
        invalid = ("", f"Loaded image: {IMAGE}", "Loaded image ID: short", line + "\n" + line,
                   line + "\nError unpacking image: broken layer\n")
        with patch.object(bundle.database_image, "localize_receipt") as verify:
            for output in invalid:
                with self.subTest(output=output), patch.object(bundle.subprocess, "check_output", return_value=output):
                    with self.assertRaisesRegex(ValueError, "exactly one untagged image ID"):
                        bundle.load_archive(self.archive, self.producer, self.local)
            verify.assert_not_called()
