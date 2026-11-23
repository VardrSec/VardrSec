"""Prepare and reuse an operator-trusted, locally qualified PostgreSQL image."""

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import uuid

from source_notices import git


ROOT = Path(__file__).resolve().parent
VERIFY_DIR = "qualification/kerberos-image"
SCRIPTS = ("verify.sh", "acl-runtime-check.sh")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
DB_ALIAS = re.compile(r"vardrsec-db:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
PLATFORM = "linux/amd64"


def build_inputs(root):
    """Bind the producer and verifier to tracked Git objects across distribution commits."""
    paths = ["db", *(f"{VERIFY_DIR}/{name}" for name in SCRIPTS)]
    changes = git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=matching",
                  "--", *paths)
    if changes:
        raise ValueError("Database build or qualification inputs have local changes")
    objects = git(root, "rev-parse", *(f"HEAD:{path}" for path in paths)).decode("ascii").splitlines()
    if len(objects) != len(paths) or not all(re.fullmatch("[0-9a-f]{40}", obj) for obj in objects):
        raise ValueError("Cannot identify the database build and qualification inputs")
    return dict(zip(paths, objects))


def inspect_local(reference):
    details = subprocess.check_output(
        ["docker", "image", "inspect", "--format", "{{.Id}} {{.Os}}/{{.Architecture}}", reference],
        text=True,
    ).strip().split()
    if len(details) != 2 or not IMAGE_ID.fullmatch(details[0]) or details[1] != PLATFORM:
        raise ValueError("Qualified database image must be a local linux/amd64 image")
    return details[0]


def validate_receipt(root, path):
    """Check the trusted receipt against this checkout before inspecting or loading an image."""
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("Database qualification receipt must be a regular file")
    with path.open("rb") as stream:
        data = stream.read(8193)
    if len(data) > 8192:
        raise ValueError("Database qualification receipt is too large")
    item = json.loads(data)
    if (not isinstance(item, dict) or set(item) != {"schema", "platform", "inputs", "image_id"}
            or type(item["schema"]) is not int or item["schema"] != 1
            or item["platform"] != PLATFORM or not isinstance(item["image_id"], str)
            or not IMAGE_ID.fullmatch(item["image_id"])):
        raise ValueError("Invalid local database qualification receipt")
    if item["inputs"] != build_inputs(root):
        raise ValueError("Database receipt is for different build or qualification inputs")
    return item["image_id"]


def read_receipt(root, path):
    image_id = validate_receipt(root, path)
    if inspect_local(image_id) != image_id:
        raise ValueError("Local database image differs from the qualification receipt")
    return image_id


def select_verified(root, receipt_path, compose_model):
    """Select the exact qualified image under this installation's resolved local alias."""
    db = compose_model["services"]["db"]
    build = db.get("build")
    if (not isinstance(build, dict) or set(build) - {"context", "dockerfile"}
            or build.get("dockerfile", "Dockerfile") != "Dockerfile"
            or not isinstance(build.get("context"), str)
            or not Path(build["context"]).is_absolute()
            or Path(build["context"]).resolve() != Path(root).resolve() / "db"
            or db.get("platform", PLATFORM) != PLATFORM):
        raise ValueError("Database image reuse requires the standard local db build context")
    alias = db.get("image")
    if not isinstance(alias, str) or not DB_ALIAS.fullmatch(alias):
        raise ValueError("Unexpected database image alias for this installation")
    image_id = read_receipt(root, receipt_path)
    listed = subprocess.check_output(["docker", "image", "ls", "--quiet", alias], text=True).strip()
    if listed:
        if inspect_local(alias) != image_id:
            raise ValueError("The installation's database image alias already selects a different image")
        return image_id
    subprocess.run(["docker", "image", "tag", image_id, alias], check=True)
    if inspect_local(alias) != image_id:
        raise ValueError("Database image alias changed during selection")
    return image_id


def discard_candidate(alias, image_id):
    try:
        if inspect_local(alias) == image_id:
            subprocess.run(["docker", "image", "rm", "--no-prune", alias], check=False)
    except (OSError, ValueError, subprocess.SubprocessError):
        # Cleanup must preserve the original qualification error.
        pass


def prepare(root, receipt_path, evidence_dir=None):
    receipt_path = Path(receipt_path).absolute()
    if os.path.lexists(receipt_path):
        return read_receipt(root, receipt_path)
    inputs = build_inputs(root)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    if evidence_dir is None:
        evidence_dir = Path(tempfile.mkdtemp(prefix="db-qualification-", dir=receipt_path.parent))
    else:
        evidence_dir = Path(evidence_dir).absolute()
        evidence_dir.mkdir(parents=True, exist_ok=False)
    print(f"Database qualification evidence: {evidence_dir}", flush=True)
    with ExitStack() as cleanup, tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        context = work / "db.tar"
        with context.open("xb") as archive:
            git(root, "archive", "--format=tar", inputs["db"], output=archive)
        alias = "vardrsec-qualified-db:" + uuid.uuid4().hex
        with context.open("rb") as archive:
            subprocess.run(
                ["docker", "buildx", "build", "--load", "--platform", PLATFORM, "--tag", alias, "-"],
                cwd=root, stdin=archive, check=True,
            )
        image_id = inspect_local(alias)
        cleanup.callback(discard_candidate, alias, image_id)
        for name in SCRIPTS:
            with (work / name).open("xb") as script:
                git(root, "cat-file", "blob", inputs[f"{VERIFY_DIR}/{name}"], output=script)
        subprocess.run(["bash", str(work / "verify.sh"), image_id], cwd=evidence_dir, check=True)
        if build_inputs(root) != inputs:
            raise ValueError("Database inputs changed during qualification")
        receipt = {"schema": 1, "platform": PLATFORM, "inputs": inputs, "image_id": image_id}
        # Publish a complete receipt without replacing an existing caller's selection.
        out = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=receipt_path.parent, delete=False)
        try:
            with out:
                json.dump(receipt, out, indent=2)
                out.write("\n")
            os.link(out.name, receipt_path)
            cleanup.pop_all()
        finally:
            Path(out.name).unlink()
    return image_id


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("prepare", help="Build and qualify the shipped database for local reuse")
    command.add_argument("--receipt", required=True, type=Path, help="Trusted local receipt to create or reuse")
    command.add_argument("--evidence-dir", type=Path, help="New directory for qualification diagnostics")
    args = parser.parse_args()
    try:
        print(f"Qualified local database {prepare(ROOT, args.receipt, args.evidence_dir)}")
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        raise SystemExit(str(exc)) from None
