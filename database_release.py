"""Select the reviewed PostgreSQL image pinned by the distribution checkout."""

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

from database_image import IMAGE_ID, PLATFORM, RECEIPT_SCHEMA, build_inputs
from image_evidence import archive_config_id
from source_notices import git


REPOSITORY = "ghcr.io/vardrsec/vardrsec-db"


def _images(manifest):
    document = json.loads(manifest)
    if not isinstance(document, dict) or not isinstance(document.get("images", {}), dict):
        raise ValueError("Invalid distribution image manifest")
    return document.get("images", {})


def release_pin(root):
    path = root / "versions.json"
    working = b"{}"
    if os.path.lexists(path):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("The distribution manifest must be a regular file")
        working = path.read_bytes()
    local = _images(working)
    if not (root / ".git").exists():
        if "db" in local:
            raise ValueError("A published database pin requires a trusted Git checkout")
        return None
    recorded = git(root, "cat-file", "blob", "HEAD:versions.json")
    committed = _images(recorded)
    if "db" not in committed and "db" not in local:
        return None
    if working.replace(b"\r\n", b"\n") != recorded.replace(b"\r\n", b"\n"):
        raise ValueError("The published database pin requires an unchanged versions.json")
    pin = committed["db"]
    if (not isinstance(pin, dict) or set(pin) != {"reference", "config_id", "platform", "inputs"}
            or pin["platform"] != PLATFORM or not isinstance(pin["reference"], str)
            or not pin["reference"].startswith(REPOSITORY + "@")
            or not IMAGE_ID.fullmatch(pin["reference"][len(REPOSITORY) + 1:])
            or not isinstance(pin["config_id"], str) or not IMAGE_ID.fullmatch(pin["config_id"])):
        raise ValueError("Invalid published PostgreSQL reference or platform")
    if pin["inputs"] != build_inputs(root):
        raise ValueError("Published PostgreSQL image differs from the checkout's database or verifier inputs")
    return pin


def prepare(root):
    pin = release_pin(root)
    if pin is None:
        return None
    reference = pin["reference"]
    inspect = ["docker", "image", "inspect", "--format", "{{json .}}", reference]
    local = subprocess.run(inspect, capture_output=True, text=True)
    if local.returncode:
        print(f"Pulling verified PostgreSQL image {reference}", flush=True)
        subprocess.run(["docker", "pull", "--platform", PLATFORM, reference], check=True)
        local = subprocess.run(inspect, capture_output=True, text=True, check=True)
    image = json.loads(local.stdout)
    image_id = image.get("Id")
    digests = image.get("RepoDigests")
    filesystem = image.get("RootFS") or {}
    layers = filesystem.get("Layers")
    if (not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id)
            or not isinstance(digests, list) or reference not in digests
            or (image.get("Os"), image.get("Architecture")) != ("linux", "amd64")
            or filesystem.get("Type") != "layers" or not isinstance(layers, list) or not layers
            or not all(isinstance(layer, str) and IMAGE_ID.fullmatch(layer) for layer in layers)):
        raise ValueError("Local PostgreSQL image does not match the published digest and platform")
    if image_id != pin["config_id"]:
        # Some Docker stores expose the immutable manifest/index ID. Resolve its
        # config and filesystem layers in the same manner as the release scan.
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "db.tar"
            subprocess.run(["docker", "image", "save", "--output", str(archive), image_id], check=True)
            try:
                config_id = archive_config_id(archive, image)
            except KeyError as err:
                raise ValueError("Docker archive is missing the published PostgreSQL metadata") from err
            if config_id != pin["config_id"]:
                raise ValueError("Local PostgreSQL configuration differs from the reviewed image")
    return {"schema": RECEIPT_SCHEMA, "platform": PLATFORM, "inputs": pin["inputs"], "image_id": image_id}
