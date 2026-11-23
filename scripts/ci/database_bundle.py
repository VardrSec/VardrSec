"""Bind a private CI database bundle to its exact build and qualification inputs."""

from datetime import datetime, timezone
import hashlib
import hmac
import os
from pathlib import Path
import subprocess
import sys
import tarfile


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import database_image


def cache_key():
    password = os.environ["PASSPHRASE"]
    if not password:
        return ""
    if "\n" in password or "\r" in password:
        raise ValueError("The database cache requires a single-line passphrase")
    files = [
        "database_image.py", "scripts/ci/database_bundle.py", "scripts/ci/database_bundle.sh",
        ".github/workflows/database-cache.yml", ".github/actions/load-database/action.yml",
    ]
    inputs = database_image.build_inputs(ROOT)
    objects = subprocess.check_output(["git", "rev-parse", *["HEAD:" + f for f in files]], cwd=ROOT)
    week = datetime.now(timezone.utc).strftime("%G-%V")
    identity = "\n".join([os.environ["GITHUB_REPOSITORY"], database_image.PLATFORM, week,
                          *inputs.values()]).encode() + b"\n" + objects
    # Isolate key rotations as well as recipe changes, without printing the secret.
    digest = hmac.new(password.encode(), identity, hashlib.sha256).hexdigest()
    return f"qualified-db-v1-{digest}"


def unpack_receipt(bundle, receipt, expected_key):
    with tarfile.open(bundle, "r:") as archive:
        members = archive.getmembers()
        if ([m.name for m in members] != ["cache-key", "receipt.json", "image.tar.zst"]
                or not all(m.isfile() for m in members) or members[0].size > 256
                or members[1].size > 8192 or members[2].size == 0):
            raise ValueError("Unexpected database bundle contents")
        expected = (expected_key + "\n").encode()
        if archive.extractfile(members[0]).read() != expected:
            raise ValueError("Database bundle belongs to a different cache key")
        with receipt.open("xb") as destination:
            destination.write(archive.extractfile(members[1]).read())
    database_image.validate_receipt(ROOT, receipt)


if __name__ == "__main__":
    if sys.argv[1:] == ["key"]:
        print("cache_key=" + cache_key())
    elif len(sys.argv) == 4 and sys.argv[1] == "unpack-receipt":
        unpack_receipt(Path(sys.argv[2]), Path(sys.argv[3]), os.environ["CACHE_KEY"])
    elif len(sys.argv) == 3 and sys.argv[1] == "verify-local":
        print("Verified local database", database_image.read_receipt(ROOT, Path(sys.argv[2])))
    else:
        raise SystemExit("Expected key, unpack-receipt BUNDLE RECEIPT, or verify-local RECEIPT")
