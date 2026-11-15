"""Build and verify deterministic, unpublished source snapshot artifacts offline."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import tempfile

from source_notices import REPOSITORIES, assemble

MAX_BYTES = 2 * 1024**3


def sha256(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            result.update(chunk)
    return result.hexdigest()


def pack(directory, output):
    """Archive only collector output, with normalized metadata and gzip header."""
    with Path(output).open("xb") as destination:
        with gzip.GzipFile(filename="", mode="wb", fileobj=destination, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                for path in sorted(Path(directory).rglob("*")):
                    if path.is_symlink():
                        raise ValueError("Refuse symlink in collector output")
                    if path.is_file():
                        info = tarfile.TarInfo(path.relative_to(directory).as_posix())
                        info.size = path.stat().st_size
                        info.mode = 0o644
                        with path.open("rb") as stream:
                            archive.addfile(info, stream)


def create(root, repositories, output):
    output = Path(output)
    # Reuse committed-object collection and complete tracked-blob verification.
    with tempfile.TemporaryDirectory(prefix="vardr-source-") as workspace:
        directory = Path(workspace) / "bundle"
        assemble(root, directory, repositories, include_sources=True)
        pack(directory, output)
    return sha256(output)


def verify(artifact, expected_sha256, expected_commit):
    """Verify integrity against a separately trusted digest; never extract files."""
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("A full expected SHA-256 is required")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
        raise ValueError("A full expected distribution commit is required")
    if sha256(artifact) != expected_sha256:
        raise ValueError("Artifact checksum mismatch")
    contents, total = {}, 0
    with tarfile.open(artifact, "r:gz") as archive:
        for member in archive:
            path = member.name
            if (not member.isfile() or path in contents or PurePosixPath(path).is_absolute()
                    or "\\" in path or any(part in ("", ".", "..") for part in path.split("/"))):
                raise ValueError("Unsafe or duplicate artifact member")
            total += member.size
            if member.size < 0 or total > MAX_BYTES:
                raise ValueError("Artifact exceeds verification size limit")
            with archive.extractfile(member) as stream:
                contents[path] = stream.read()
    manifest = json.loads(contents["manifest.json"])
    if manifest["schema"] != "vardr.source-notices/1":
        raise ValueError("Unsupported manifest")
    components = manifest["components"]
    if set(components) != {"distribution", *REPOSITORIES}:
        raise ValueError("Unexpected source set")
    if components["distribution"]["commit"] != expected_commit:
        raise ValueError("Distribution commit mismatch")
    versions = contents["versions.json"]
    if hashlib.sha256(versions).hexdigest() != manifest["versions_sha256"]:
        raise ValueError("Versions checksum mismatch")
    pins = json.loads(versions)["components"]
    if set(pins) != set(REPOSITORIES):
        raise ValueError("Unexpected pin set")
    expected = {"manifest.json", "versions.json"}
    for name, component in components.items():
        repository = "VardrSec/VardrSec" if name == "distribution" else REPOSITORIES[name]
        if component["repository"] != repository:
            raise ValueError("Repository mismatch")
        for key in ("commit", "tree"):
            if not re.fullmatch(r"[0-9a-f]{40}", component[key]):
                raise ValueError("Invalid Git identity")
        if name != "distribution" and any(pins[name][key] != component[key] for key in ("repository", "commit")):
            raise ValueError("Component pin mismatch")
        records = [*component["files"], component["source_archive"]]
        for record in records:
            path = record["path"]
            if path in expected or not path.startswith(name + "/"):
                raise ValueError("Unexpected inventory path")
            expected.add(path)
            data = contents[path]
            if len(data) != record["bytes"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
                raise ValueError("Inventory checksum mismatch")
    if expected != set(contents):
        raise ValueError("Uninventoried files")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    build = subcommands.add_parser("create")
    build.add_argument("--root", type=Path, default=Path(__file__).parent)
    build.add_argument("--output", type=Path, required=True)
    for name in REPOSITORIES:
        build.add_argument("--" + name + "-repo", type=Path, required=True)
    check = subcommands.add_parser("verify")
    check.add_argument("artifact", type=Path)
    check.add_argument("--sha256", required=True)
    check.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        if args.command == "create":
            digest = create(args.root, {name: getattr(args, name + "_repo") for name in REPOSITORIES}, args.output)
            print(f"{digest}  {args.output.name}")
        else:
            manifest = verify(args.artifact, args.sha256, args.commit)
            print("Verified source snapshot for " + manifest["components"]["distribution"]["commit"])
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, tarfile.TarError) as error:
        parser.exit(1, f"Source snapshot failed: {error}\n")


if __name__ == "__main__":
    main()
