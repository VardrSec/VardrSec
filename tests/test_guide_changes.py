"""Exercise the guide-only classifier with the two-parent checkout Actions provides."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CLASSIFIER = Path(__file__).resolve().parents[1] / "scripts/ci/guide_changes.py"


class GuideChangesTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.invalid")
        (self.repo / "install.sh").write_text("base\n")
        self.commit("base")
        self.base = self.git("rev-parse", "HEAD")
        self.git("switch", "-qc", "topic")

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.repo, text=True).strip()

    def commit(self, message):
        self.git("add", "-A")
        self.git("-c", "commit.gpgSign=false", "commit", "-qm", message)

    def merge(self):
        head = self.git("rev-parse", "HEAD")
        self.git("switch", "-q", "main")
        self.git("-c", "commit.gpgSign=false", "merge", "--no-ff", "--no-edit", "topic")
        return head

    def classify(self, base, head):
        return subprocess.check_output(
            [sys.executable, str(CLASSIFIER), base, head], cwd=self.repo, text=True
        ).strip()

    def test_guide_only(self):
        (self.repo / "README.md").write_text("install guide\n")
        self.commit("guide")
        head = self.merge()
        self.assertEqual(self.classify(self.base, head), "guide_only=true")
        self.assertEqual(self.classify(head, self.base), "guide_only=false")

    def test_installer_rename_followed_by_guide_edit(self):
        self.git("mv", "install.sh", "README.md")
        self.commit("move installer")
        (self.repo / "CHANGELOG.md").write_text("guide update\n")
        self.commit("guide")
        self.assertEqual(self.classify(self.base, self.merge()), "guide_only=false")

    def test_release_inputs_under_docs(self):
        evidence = self.repo / "docs" / "release" / "sources.lock.json"
        evidence.parent.mkdir(parents=True)
        evidence.write_text("{}\n")
        (self.repo / "README.md").write_text("guide\n")
        self.commit("guide and source lock")
        self.assertEqual(self.classify(self.base, self.merge()), "guide_only=false")
