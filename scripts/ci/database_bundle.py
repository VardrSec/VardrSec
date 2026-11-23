"""Bind a private CI database bundle to its exact build and qualification inputs."""

from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
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
        "database_image.py", "image_evidence.py", "source_notices.py",
        "scripts/ci/database_bundle.py", "scripts/ci/database_bundle.sh",
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


def require_untagged_archive(path):
    """A load may update tags before it prints its result. Check both archive formats first."""
    def fields(pairs):
        # Docker decodes metadata field names case-insensitively.
        result = {key.casefold(): value for key, value in pairs}
        if len(result) != len(pairs):
            raise ValueError("Duplicate Docker archive metadata field")
        return result

    with tarfile.open(path, "r:") as archive:
        members = {}
        for member in archive:
            name = PurePosixPath(member.name)
            if (name.is_absolute() or ".." in name.parts or str(name) in members
                    or not (member.isfile() or member.isdir())):
                raise ValueError("Unsafe or duplicate Docker archive entry")
            members[str(name)] = member

        def document(name):
            item = members.get(name)
            if item is None or not item.isfile() or item.size > 4 * 1024 * 1024:
                raise ValueError("Missing or invalid Docker archive metadata: " + name)
            return json.load(archive.extractfile(item), object_pairs_hook=fields)

        manifest = document("manifest.json")
        if (not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict)
                or manifest[0].get("repotags") not in (None, [])):
            raise ValueError("Database archive must contain exactly one untagged image")
        if "repositories" in members and document("repositories") != {}:
            raise ValueError("Database archive contains a repository tag")
        if "index.json" in members:
            index = document("index.json")
            descriptors = index.get("manifests") if isinstance(index, dict) else None
            if (not isinstance(descriptors, list) or len(descriptors) != 1
                    or not isinstance(descriptors[0], dict)):
                raise ValueError("Database archive must contain exactly one OCI image")
            annotations = descriptors[0].get("annotations", {})
            if (not isinstance(annotations, dict)
                    or {"io.containerd.image.name", "org.opencontainers.image.ref.name"} & annotations.keys()):
                raise ValueError("Database OCI archive contains a repository tag")


def load_archive(archive, producer_receipt, local_receipt):
    require_untagged_archive(archive)
    output = subprocess.check_output(["docker", "image", "load", "--input", str(archive)], text=True)
    loaded = re.fullmatch(r"Loaded image ID: (sha256:[0-9a-f]{64})\n?", output)
    if not loaded:
        raise ValueError("Docker did not report exactly one untagged image ID")
    local_id = loaded.group(1)
    database_image.localize_receipt(ROOT, producer_receipt, archive, local_id, local_receipt)
    print("Verified local database", local_id)


if __name__ == "__main__":
    if sys.argv[1:] == ["key"]:
        print("cache_key=" + cache_key())
    elif len(sys.argv) == 4 and sys.argv[1] == "unpack-receipt":
        unpack_receipt(Path(sys.argv[2]), Path(sys.argv[3]), os.environ["CACHE_KEY"])
    elif len(sys.argv) == 5 and sys.argv[1] == "load-archive":
        load_archive(*map(Path, sys.argv[2:]))
    else:
        raise SystemExit("Expected key, unpack-receipt BUNDLE RECEIPT, or load-archive IMAGE PRODUCER LOCAL")
