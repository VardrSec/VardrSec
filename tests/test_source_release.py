"""Offline source snapshot reproducibility and refusal tests."""
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import source_notices
import source_release


class SourceReleaseTests(unittest.TestCase):
    def fixture(self, root):
        repos, pins = {}, {}
        for name in [*source_notices.REPOSITORIES, "distribution"]:
            repo = root / name
            repo.mkdir()
            subprocess.run(["git", "init", "--template=", str(repo)], check=True, capture_output=True)
            (repo / "LICENSE").write_text("Synthetic license\n")
            (repo / "script.sh").write_text("#!/bin/sh\necho test\n")
            (repo / "script.sh").chmod(0o755)
            if name == "distribution":
                (repo / "versions.json").write_text(json.dumps({"components": pins}))
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture", "-c", "user.email=test@example.invalid", "commit", "-m", "fixture"], check=True, capture_output=True)
            commit = source_notices.revision(repo, "HEAD^{commit}")
            repos[name] = repo
            if name != "distribution":
                pins[name] = {"repository": source_notices.REPOSITORIES[name], "commit": commit}
        return repos

    def test_reproducible_and_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repos = self.fixture(root)
            first, second = root / "a.tar.gz", root / "b.tar.gz"
            digest = source_release.create(repos["distribution"], repos, first)
            time.sleep(1.1)  # Git tree archive uses wall clock unless normalized.
            (repos["map"] / "LICENSE").write_text("Uncommitted data must not enter artifact")
            self.assertEqual(digest, source_release.create(repos["distribution"], repos, second))
            commit = source_notices.revision(repos["distribution"], "HEAD^{commit}")
            result = source_release.verify(first, digest, commit)
            self.assertEqual(set(result["components"]), set(repos))
            with self.assertRaises(ValueError):
                source_release.verify(first, "0" * 64, commit)
            with self.assertRaises(ValueError):
                source_release.verify(first, digest, "0" * 40)
            with self.assertRaises(FileExistsError):
                source_release.create(repos["distribution"], repos, first)

    def test_reject_unsafe_or_uninventoried_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repos = self.fixture(root)
            original = root / "original.tar.gz"
            source_release.create(repos["distribution"], repos, original)
            commit = source_notices.revision(repos["distribution"], "HEAD^{commit}")
            for name in ("../escape", "extra", "manifest.json"):
                artifact = root / (str(len(name)) + name.replace("/", "_") + ".tar.gz")
                with tarfile.open(original, "r:gz") as source, tarfile.open(artifact, "w:gz") as target:
                    for member in source:
                        target.addfile(member, source.extractfile(member))
                    entry = tarfile.TarInfo(name)
                    entry.size = 1
                    target.addfile(entry, io.BytesIO(b"x"))
                with self.assertRaises(ValueError):
                    source_release.verify(artifact, source_release.sha256(artifact), commit)


if __name__ == "__main__":
    unittest.main()
