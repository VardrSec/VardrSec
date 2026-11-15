"""Bounded shell harness tests; fake Docker only, no real container operations."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import acl_cohort_acceptance

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "qualification/kerberos-image/verify.sh"
FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with Path(os.environ["MOCK_CALLS"]).open("a") as stream:
    stream.write(json.dumps(args) + "\n")
if args[:2] == ["image", "inspect"]:
    print("sha256:" + "a" * 64 if "--format" in args else "{}")
elif args[:1] == ["run"] and "--cap-drop" in args:
    print("public-source: OK" if os.environ["MOCK_ACL_STATUS"] == "0" else "public-source: FAILED open or read")
    if os.environ["MOCK_ACL_STATUS"] != "0":
        print("sha256sum: public-source: Permission denied", file=sys.stderr)
    sys.exit(int(os.environ["MOCK_ACL_STATUS"]))
elif args[:2] == ["run", "-d"]:
    print("disposable-container")
elif "psql" in args:
    print("1")
elif "pg_isready" in args or args[:1] in (["logs"], ["rm"]):
    pass
elif args[:1] == ["run"]:
    print("kerberos-custody: OK")
else:
    raise SystemExit("Unexpected fake Docker command")
'''


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "POSIX Bash required for Linux image qualification fixture")
class DatabaseACLQualification(unittest.TestCase):
    def invoke(self, status):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        binary = root / "bin"
        binary.mkdir()
        docker = binary / "docker"
        docker.write_text(FAKE_DOCKER)
        docker.chmod(0o755)
        calls = root / "calls.jsonl"
        result = subprocess.run(["bash", str(SCRIPT), "fixture-image"], cwd=root, env={**os.environ, "PATH": str(binary) + os.pathsep + os.environ["PATH"], "MOCK_CALLS": str(calls), "MOCK_ACL_STATUS": str(status)}, capture_output=True, text=True)
        return result, root / "artifacts/kerberos-image", [json.loads(row) for row in calls.read_text().splitlines()]

    def test_failure_preserves_diagnostics_and_blocks_success(self):
        result, artifacts, calls = self.invoke(17)
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertEqual((artifacts / "acl-installed-custody.exit-code.txt").read_text(), "17\n")
        self.assertEqual((artifacts / "acl-installed-custody.txt").read_text(), "public-source: FAILED open or read\n")
        self.assertEqual((artifacts / "acl-installed-custody.stderr.txt").read_text(), "sha256sum: public-source: Permission denied\n")
        self.assertTrue((artifacts / "result.txt").read_text().startswith("FAIL:"))
        self.assertFalse(any(call[:2] == ["run", "-d"] for call in calls))
        self.assertEqual((artifacts / "acl-runtime-check.sh").read_text(), acl_cohort_acceptance.RUNTIME_CHECK)
        restricted = next(call for call in calls if "--cap-drop" in call)
        self.assertEqual(restricted[restricted.index("--cap-drop") + 1], "ALL")
        self.assertEqual(restricted[restricted.index("--security-opt") + 1], "no-new-privileges")
        self.assertEqual(restricted[restricted.index("--network") + 1], "none")
        self.assertEqual(restricted[-1], acl_cohort_acceptance.RUNTIME_CHECK.rstrip("\n"))

    def test_success_preserves_kerberos_and_postgres_checks(self):
        result, artifacts, calls = self.invoke(0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((artifacts / "acl-installed-custody.exit-code.txt").read_text(), "0\n")
        self.assertEqual((artifacts / "acl-installed-custody.stderr.txt").read_bytes(), b"")
        self.assertIn("kerberos-custody: OK", (artifacts / "installed-custody.txt").read_text())
        self.assertEqual((artifacts / "postgres-smoke.txt").read_text(), "1\n")
        self.assertTrue(any("pg_isready" in call for call in calls))
        self.assertTrue(any("psql" in call for call in calls))
        self.assertIn("PASS: qualified Kerberos and ACL", (artifacts / "result.txt").read_text())


if __name__ == "__main__":
    unittest.main()
