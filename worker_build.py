"""Explicit local persistent-worker build; no source acquisition or queue work."""

import json
from pathlib import Path
import re
import tempfile
import uuid

import vardrsec
import worker_lifecycle_intent as intent
import worker_prepare as preparation


def require(value):
    if not value:
        raise ValueError("worker_build_refused")


def _source(path, expected):
    for selected in (path.parent, path, path / ".git", path / "Dockerfile.worker.persistent"):
        vardrsec._refuse_source_link(selected)
    require(path.is_dir() and (path / ".git").is_dir())
    vardrsec._require_source_git_binding(path)

    def git(*args):
        return vardrsec.run(
            "git", "--no-optional-locks", "-C", str(path), *args,
            capture_output=True, text=True, timeout=15,
        ).stdout.strip()

    require(git("rev-parse", "HEAD") == expected
            and not git("status", "--porcelain", "--untracked-files=all"))
    return git("rev-parse", "HEAD^{tree}")


def build(installation, *, client):
    """Return the built immutable image ID; caller owns the installation lock.

    Uses the separately reviewed Runner recipe, including its existing compile
    checks. It never modifies/fetches/resets .sources, replaces an image tag, starts a
    worker, enrolls a principal or creates job authority. Build failure preserves
    Docker's build evidence/cache; no image or source cleanup is attempted.
    """
    root = Path(installation).resolve(strict=True)
    versions, frozen = root / "versions.json", root / ".active-images.json"
    for selected in (versions, frozen):
        vardrsec._refuse_source_link(selected)
    versions_raw, frozen_raw = versions.read_bytes(), frozen.read_bytes()
    pin = json.loads(versions_raw)["components"]["runner"]
    require(pin["repository"] == "VardrSec/VardrRunner"
            and type(pin["commit"]) is str
            and re.fullmatch(r"[0-9a-f]{40}", pin["commit"]))
    base = json.loads(frozen_raw)["services"]["runner"]["image"]
    intent.image(base)
    require(json.loads(preparation._docker(client, root, "image", "inspect", base,
                                          "--format", "{{json .Id}}")) == base)
    source = root / ".sources" / "runner"
    tree = _source(source, pin["commit"])
    # BuildKit interprets a bare sha256 ID as a registry repository. Give the
    # verified local image its own fresh build-only alias; never replace a tag.
    alias = "vardrsec-worker-base:" + uuid.uuid4().hex
    require(not preparation._docker(client, root, "image", "ls", "--quiet", alias).strip())
    preparation._docker(client, root, "image", "tag", base, alias)
    require(json.loads(preparation._docker(client, root, "image", "inspect", alias,
                                          "--format", "{{json .Id}}")) == base)
    with tempfile.TemporaryDirectory(prefix="vardr-worker-build-") as directory:
        iid = Path(directory) / "image.id"
        preparation._docker(
            client, root, "build", "--pull=false", "--network", "none",
            "--build-arg", "RUNNER_BASE_IMAGE=" + alias, "--iidfile", str(iid),
            "--file", str(source / "Dockerfile.worker.persistent"), str(source),
            timeout=1800,
        )
        with iid.open("rb") as result:
            image = result.read(128).decode("ascii").strip()
        intent.image(image)
    require(_source(source, pin["commit"]) == tree
            and versions.read_bytes() == versions_raw and frozen.read_bytes() == frozen_raw)
    require(json.loads(preparation._docker(client, root, "image", "inspect", alias,
                                          "--format", "{{json .Id}}")) == base)
    require(json.loads(preparation._docker(client, root, "image", "inspect", image,
                                          "--format", "{{json .Id}}")) == image)
    return image
