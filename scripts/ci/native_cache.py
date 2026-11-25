"""Identity and authenticated OCI cache transport for the CI retry builder."""

from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile


ROOT = Path(__file__).resolve().parents[2]
MAX_BYTES = 2 * 1024**3


def map_pin():
    component = json.loads((ROOT / "versions.json").read_bytes())["components"]["map"]
    if component["repository"] != "VardrSec/VardrMap" or not re.fullmatch("[0-9a-f]{40}", component["commit"]):
        raise ValueError("Expected the pinned VardrMap source")
    return component["commit"]


def cache_key():
    password = os.environ["PASSPHRASE"]
    if not password:
        raise ValueError("Missing private cache passphrase")
    digest = hmac.new(password.encode(), digestmod=hashlib.sha256)
    for field in (os.environ["GITHUB_REPOSITORY"], os.environ["RUNNER_ARCH"], "linux/amd64",
                  os.environ["ImageOS"], datetime.now(timezone.utc).strftime("%G-%V"), map_pin()):
        digest.update(field.encode() + b"\0")
    for path in ("scripts/ci/native_cache.py", "scripts/ci/native_cache.sh", "scripts/ci/database_bundle.sh"):
        digest.update((ROOT / path).read_bytes())
    return "full-native-v1-" + digest.hexdigest()


def unpack(archive_path, destination, key):
    # The caller has authenticated the complete ciphertext. Accept only the
    # exact cache identity and regular OCI blobs inside a fresh directory.
    if not re.fullmatch(r"full-native-v1-[0-9a-f]{64}", key):
        raise ValueError("Invalid native cache identity")
    destination = Path(destination)
    store = destination / key
    store.mkdir()
    (store / "blobs" / "sha256").mkdir(parents=True)
    directories = {key + "/blobs/sha256"}
    metadata = {key + "/index.json", key + "/oci-layout"}
    total = 0
    seen = set()
    with tarfile.open(archive_path, "r:") as archive:
        for member in archive:
            total += member.size
            if member.name in seen or member.size < 0 or total > MAX_BYTES or len(seen) >= 4096:
                raise ValueError("Oversized or duplicate native cache entry")
            seen.add(member.name)
            if member.name in directories and member.isdir():
                continue
            if not member.isfile() or (member.name not in metadata and
                    not re.fullmatch(key + r"/blobs/sha256/[0-9a-f]{64}", member.name)):
                raise ValueError("Unexpected native cache entry")
            with archive.extractfile(member) as source, (destination / member.name).open("xb") as output:
                shutil.copyfileobj(source, output)
    if not metadata <= seen:
        raise ValueError("Missing native OCI cache metadata")


if __name__ == "__main__":
    if sys.argv[1:] == ["key"]:
        print("key=" + cache_key())
        print("pin=" + map_pin())
    elif len(sys.argv) == 5 and sys.argv[1] == "unpack":
        unpack(*sys.argv[2:])
    else:
        raise SystemExit("Expected key or unpack ARCHIVE DESTINATION KEY")
