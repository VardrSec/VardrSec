"""Assert hosted checkouts match the CI-only pins and record value-free provenance."""

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def git(directory, *args):
    return subprocess.check_output(
        ["git", "-C", str(directory), *args], text=True
    ).strip()


# Explicitly reviewed release-gate candidate manifest; do not derive this expected
# value from the checkout being checked. An intentional pin update must review it.
REVIEWED_DISTRIBUTION_MANIFEST_SHA256 = (
    "8848f139e016f43ed518998eb2172ac52a2e538ca531051ebc89569d0823dc82"
)


def verify_distribution_manifest(root):
    actual = hashlib.sha256(
        (root / "versions.json").read_bytes().replace(b"\r\n", b"\n")
    ).hexdigest()
    assert actual == REVIEWED_DISTRIBUTION_MANIFEST_SHA256, "distribution manifest differs from reviewed candidate baseline"
    return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--expected-distribution", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    pins = json.loads((root / ".github/nm1-sources.json").read_text())
    sources = {}
    selections = [("distribution", root, args.expected_distribution)] + [
        (name, root / ".nm1" / name, pins[name]["commit"])
        for name in ("map", "runner", "gate")
    ]
    for name, directory, expected in selections:
        assert re.fullmatch("[a-f0-9]{40}", expected)
        actual = git(directory, "rev-parse", "HEAD")
        assert actual == expected, f"{name}: unexpected checkout revision"
        subprocess.run(
            ["git", "-C", str(directory), "diff", "HEAD", "--exit-code"], check=True
        )
        sources[name] = {
            "commit": actual,
            "tree": git(directory, "rev-parse", "HEAD^{tree}"),
            "selection": "explicit reviewed commit",
        }
    assert "VardrSec_New_Moon_Roadmap.md" not in git(root, "ls-files").splitlines()
    # NM-1 source pins remain a separate reviewed conformance matrix. Record the
    # deliberately updated distribution candidate without claiming its pins did
    # not change from the historical product baseline.
    manifest_sha256 = verify_distribution_manifest(root)
    packages = {}
    for name in ("vardrrunner", "cryptography", "fastapi", "sqlalchemy", "pytest"):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = None
    receipt = {
        "schema": "vardr.nm1-hosted-sources/1",
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "event": os.environ.get("GITHUB_EVENT_NAME"),
        "sources": sources,
        "python": sys.version,
        "go": subprocess.check_output(["go", "version"], text=True).strip(),
        "packages": packages,
        "distribution_manifest_matches_reviewed_baseline": True,
        "distribution_manifest_sha256": manifest_sha256,
    }
    with args.out.open("x", encoding="utf-8") as output:
        json.dump(receipt, output, indent=2)
        output.write("\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
