import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import database_release as release
import vardrsec
from test_database_image import IMAGE, OTHER, image_archive


class PublishedDatabaseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.path = self.root / "versions.json"
        (self.root / ".git").mkdir()
        self.pin = {"reference": release.REPOSITORY + "@" + IMAGE, "config_id": OTHER,
                    "platform": "linux/amd64", "inputs": {"db": "a" * 40}}

    def manifest(self, images):
        data = json.dumps({"images": images}).encode()
        self.path.write_bytes(data)
        return data

    def test_only_the_tracked_pin_can_select_the_published_database(self):
        dev = self.manifest({})
        with patch.object(release, "git", return_value=dev), patch.object(release, "subprocess") as docker:
            self.assertIsNone(release.prepare(self.root))
            self.manifest({"db": self.pin})
            with self.assertRaisesRegex(ValueError, "unchanged versions.json"):
                release.prepare(self.root)
            docker.run.assert_not_called()
        original = self.path.read_bytes()
        self.manifest({})
        with patch.object(release, "git", return_value=original), self.assertRaisesRegex(ValueError, "unchanged"):
            release.prepare(self.root)
        self.path.unlink()
        with patch.object(release, "git", return_value=original), self.assertRaisesRegex(ValueError, "unchanged"):
            release.prepare(self.root)

    def test_invalid_pin_or_recipe_never_reaches_docker(self):
        for change in ({"reference": release.REPOSITORY + ":latest"},
                       {"reference": "example.org/db@" + IMAGE}, {"config_id": "latest"},
                       {"platform": "linux/arm64"}, {"inputs": {"db": "b" * 40}}):
            data = self.manifest({"db": dict(self.pin, **change)})
            with self.subTest(change=change), patch.object(release, "git", return_value=data), \
                    patch.object(release, "build_inputs", return_value=self.pin["inputs"]), \
                    patch.object(release, "subprocess") as docker, self.assertRaises(ValueError):
                release.prepare(self.root)
            docker.run.assert_not_called()

    def test_pull_on_miss_and_reuse_the_exact_local_config(self):
        source = self.manifest({"db": self.pin})
        with patch.object(release, "git", return_value=source), \
                patch.object(release, "build_inputs", return_value=self.pin["inputs"]):
            self.assertEqual(release.release_pin(self.root), self.pin)
        image = {"Id": OTHER, "Os": "linux", "Architecture": "amd64", "RepoDigests": [self.pin["reference"]],
                 "RootFS": {"Type": "layers", "Layers": [IMAGE, OTHER]}}
        for available in (False, True):
            ok = Mock(returncode=0, stdout=json.dumps(image))
            results = [ok] if available else [Mock(returncode=1), Mock(returncode=0), ok]
            with self.subTest(available=available), patch.object(release, "release_pin", return_value=self.pin), \
                    patch.object(release.subprocess, "run", side_effect=results) as docker:
                receipt = release.prepare(self.root)
            self.assertEqual(receipt, {"schema": 2, "platform": "linux/amd64", "inputs": self.pin["inputs"],
                                       "image_id": OTHER})
            if not available:
                self.assertEqual(docker.call_args_list[1].args[0],
                                 ["docker", "pull", "--platform", "linux/amd64", self.pin["reference"]])
            self.assertEqual(docker.call_count, len(results))
        for change in ({"RepoDigests": []}, {"Architecture": "arm64"}):
            with patch.object(release, "release_pin", return_value=self.pin), \
                    patch.object(release.subprocess, "run", return_value=Mock(
                        returncode=0, stdout=json.dumps(dict(image, **change)))), self.assertRaises(ValueError):
                release.prepare(self.root)

    def test_containerd_id_must_resolve_to_reviewed_config_and_layers(self):
        saved = self.root / "image.tar"
        image_id, config_id = image_archive(saved, "oci")
        self.pin["config_id"] = config_id
        image = {"Id": image_id, "Os": "linux", "Architecture": "amd64", "RepoDigests": [self.pin["reference"]],
                 "RootFS": {"Type": "layers", "Layers": [IMAGE, OTHER]}}

        def docker(command, **kwargs):
            if command[:3] == ["docker", "image", "inspect"]:
                return Mock(returncode=0, stdout=json.dumps(image))
            self.assertEqual(command[:4], ["docker", "image", "save", "--output"])
            self.assertEqual(command[-1], image_id)
            Path(command[4]).write_bytes(saved.read_bytes())

        with patch.object(release, "release_pin", return_value=self.pin), \
                patch.object(release.subprocess, "run", side_effect=docker):
            self.assertEqual(release.prepare(self.root)["image_id"], image_id)
            self.pin["config_id"] = IMAGE
            with self.assertRaisesRegex(ValueError, "configuration differs"):
                release.prepare(self.root)
            image["RootFS"]["Layers"].reverse()
            with self.assertRaisesRegex(ValueError, "layer identity"):
                release.prepare(self.root)

    def test_pull_failure_stops_fresh_install_before_writes_or_source_fetch(self):
        with patch.object(vardrsec, "ROOT", self.root), patch.dict(vardrsec.os.environ, {}, clear=True), \
                patch.object(vardrsec, "require_standard_fresh_layout"), patch.object(vardrsec, "require_command"), \
                patch.object(vardrsec, "build_prerequisites"), patch.object(vardrsec, "standard_full_compose", return_value=True), \
                patch.object(vardrsec, "has_installation_data", return_value=False), patch.object(vardrsec, "sources") as fetch, \
                patch.object(release, "prepare", side_effect=subprocess.CalledProcessError(1, ["docker", "pull"])):
            with self.assertRaises(subprocess.CalledProcessError):
                vardrsec.dispatch(argparse.Namespace(action="install"), None)
        self.assertFalse((self.root / ".env").exists())
        self.assertFalse((self.root / ".sources").exists())
        fetch.assert_not_called()

    def test_normal_install_rechecks_and_freezes_the_pulled_selection(self):
        selected = {"schema": 2, "platform": "linux/amd64", "inputs": self.pin["inputs"], "image_id": OTHER}
        paths = []
        original = vardrsec.dispatch

        def route(args, parser):
            if args.action in ("install", "build"):
                return original(args, parser)

        def build(*, mapless, environment):
            self.assertFalse(mapless)
            paths.append(Path(environment["VARDRSEC_DATABASE_RECEIPT"]))
            self.assertEqual(json.loads(paths[-1].read_text()), selected)
            return selected["image_id"]

        with patch.object(vardrsec, "ROOT", self.root), patch.dict(vardrsec.os.environ, {}, clear=True), \
                patch.object(vardrsec, "require_standard_fresh_layout"), patch.object(vardrsec, "require_command"), \
                patch.object(vardrsec, "build_prerequisites"), patch.object(vardrsec, "standard_full_compose", return_value=True), \
                patch.object(vardrsec, "has_installation_data", return_value=False), \
                patch.object(release, "prepare", return_value=selected) as pull, \
                patch.object(vardrsec, "map_source_revision", return_value=""), \
                patch.object(vardrsec, "dispatch", side_effect=route), patch.object(vardrsec, "build_images", side_effect=build), \
                patch.object(vardrsec, "select_full_installation", return_value="https://localhost") as freeze, \
                patch("builtins.print"):
            vardrsec.dispatch(argparse.Namespace(action="install"), None)
            pull.assert_called_once_with(self.root)
            freeze.assert_called_once_with(verified_db=OTHER)
        self.assertFalse(paths[0].exists())
