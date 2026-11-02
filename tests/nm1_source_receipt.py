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
    # Exact Git-normalized versions.json from the approved distribution baseline.
    assert hashlib.sha256(
        (root / "versions.json").read_bytes().replace(b"\r\n", b"\n")
    ).hexdigest() == (
        "feb56aea9a23e5b7b5e3a534cbe5dc2e2e205b3ea5355a46751aa7aa7d04fefb"
    )
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
        "distribution_pins_unchanged": True,
    }
    with args.out.open("x", encoding="utf-8") as output:
        json.dump(receipt, output, indent=2)
        output.write("\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
