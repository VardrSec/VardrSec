"""Isolated image inventory checks for the bootstrap fixture."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import nm2_worker_acceptance as shared
import nm2_worker_bootstrap as bootstrap

IMAGE = "sha256:" + "a" * 64
OWNER = "b" * 64


class BootstrapHostedTests(unittest.TestCase):
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
