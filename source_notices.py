"""Offline collection of top-level component notices from committed Git objects."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


REPOSITORIES = {
    "map": "VardrSec/VardrMap",
    "runner": "VardrSec/VardrRunner",
    "gate": "VardrSec/VardrGate",
}
NOTICE_NAME = re.compile(
    r"(?:licen[cs]e|notice|copying|copyright)(?:[._-][a-z0-9._-]+)?", re.I
)
OID = re.compile(r"[0-9a-f]{40}")
MAX_FILE_BYTES = 1024 * 1024


def git(repo, *arguments, data=None):
    # Ignore ambient repository selection and replacements. Missing promisor
    # objects must fail locally, never acquire objects or request credentials.
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    env.update(
        GIT_ALLOW_PROTOCOL="",
        GIT_NO_LAZY_FETCH="1",
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_OPTIONAL_LOCKS="0",
        GIT_TERMINAL_PROMPT="0",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_SYSTEM=os.devnull,
    )
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=15,
            env=env,
        )
    except (OSError, subprocess.SubprocessError):
        raise ValueError(
            "Required local Git objects are unavailable; nothing was fetched"
        ) from None
    return result.stdout


def revision(repo, value):
    result = git(repo, "rev-parse", "--verify", value).decode("ascii").strip()
    if not OID.fullmatch(result):
        raise ValueError("A complete SHA-1 Git object is required")
    return result


def tree_entries(repo, commit):
    result = {}
    for entry in git(repo, "ls-tree", "-z", commit).split(b"\0"):
        if entry:
            header, name = entry.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split()
            result[name.decode("utf-8")] = (mode, kind, oid)
    return result


def blobs(repo, entries):
    """Read a small batch without checkout filters or worktree file contents."""
    raw = git(
        repo,
        "cat-file",
        "--batch",
        data="".join(oid + "\n" for oid in entries).encode("ascii"),
    )
    output, position = {}, 0
    for oid in entries:
        end = raw.index(b"\n", position)
        observed, kind, size = raw[position:end].decode("ascii").split()
        size = int(size)
        if observed != oid or kind != "blob" or not 0 <= size <= MAX_FILE_BYTES:
            raise ValueError("Unsupported notice Git object")
        position = end + 1
        data = raw[position : position + size]
        position += size
        if raw[position : position + 1] != b"\n":
            raise ValueError("Incomplete notice Git object")
        position += 1
        framed = b"blob " + str(size).encode("ascii") + b"\0" + data
        if hashlib.sha1(framed, usedforsecurity=False).hexdigest() != oid:
            raise ValueError("Notice Git object hash mismatch")
        output[oid] = data
    if position != len(raw):
        raise ValueError("Unexpected notice Git object data")
    return output


def assemble(root, destination, repositories):
    root, destination = Path(root).resolve(), Path(destination).absolute()
    destination = destination.parent.resolve(strict=True) / destination.name
    locations = {
        "distribution": root,
        **{name: Path(repositories[name]).resolve() for name in REPOSITORIES},
    }
    if os.path.lexists(destination) or any(
        destination.is_relative_to(path) for path in locations.values()
    ):
        raise ValueError("Use a new destination outside the input repositories")
    commit = revision(root, "HEAD^{commit}")
    distribution_tree = tree_entries(root, commit)
    mode, kind, manifest_oid = distribution_tree["versions.json"]
    if mode != "100644" or kind != "blob":
        raise ValueError("Committed versions.json must be an ordinary Git file")
    manifest_bytes = blobs(root, [manifest_oid])[manifest_oid]
    pins = json.loads(manifest_bytes)["components"]
    if not isinstance(pins, dict) or set(pins) != set(REPOSITORIES):
        raise ValueError("Expected the three pinned Community components")
    selected = {
        "distribution": {"repository": "VardrSec/VardrSec", "commit": commit},
        **pins,
    }
    planned, components = {"versions.json": manifest_bytes}, {}
    for name, source in selected.items():
        expected = "VardrSec/VardrSec" if name == "distribution" else REPOSITORIES[name]
        if (
            not isinstance(source, dict)
            or source.get("repository") != expected
            or not isinstance(source.get("commit"), str)
            or not OID.fullmatch(source["commit"])
        ):
            raise ValueError("Unexpected pinned component or incomplete commit")
        repo, pinned = locations[name], source["commit"]
        if revision(repo, pinned + "^{commit}") != pinned:
            raise ValueError("Pinned component commit mismatch")
        entries = (
            distribution_tree if name == "distribution" else tree_entries(repo, pinned)
        )
        notices = sorted(path for path in entries if NOTICE_NAME.fullmatch(path))
        if (
            not notices
            or len(notices) > 32
            or len({path.casefold() for path in notices}) != len(notices)
        ):
            raise ValueError(
                "Missing, ambiguous or excessive top-level component notices"
            )
        if not any(
            path.lower().startswith(("license", "licence", "copying"))
            for path in notices
        ):
            raise ValueError("A top-level component license is required")
        if any(
            entries[path][0] not in ("100644", "100755") or entries[path][1] != "blob"
            for path in notices
        ):
            raise ValueError("Component notices must be ordinary Git files")
        content = blobs(repo, [entries[path][2] for path in notices])
        files = []
        for path in notices:
            data, oid = content[entries[path][2]], entries[path][2]
            output = name + "/" + path
            planned[output] = data
            files.append(
                {
                    "path": output,
                    "source_path": path,
                    "git_blob": oid,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "bytes": len(data),
                    "source_url": f"https://github.com/{expected}/blob/{pinned}/{path}",
                }
            )
        components[name] = {
            "repository": expected,
            "commit": pinned,
            "tree": revision(repo, pinned + "^{tree}"),
            "files": files,
        }
    manifest = {
        "schema": "vardr.source-notices/1",
        "input_basis": "committed_git_objects",
        "versions_blob": manifest_oid,
        "versions_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "scope": "Top-level component notices only; no transitive/tool/base-image inventory, source archive, source offer or compliance assertion",
        "components": components,
    }
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    # All inputs are resolved before this exclusive publication. On I/O failure,
    # preserve partial output; manifest.json is written last, never overwrite it.
    destination.mkdir(mode=0o700)
    for name, data in {**planned, "manifest.json": encoded}.items():
        target = destination / name
        target.parent.mkdir(exist_ok=True)
        with target.open("xb") as output:
            output.write(data)
    return hashlib.sha256(encoded).hexdigest()


def main(argv, *, root):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--destination",
        type=Path,
        required=True,
        help="New directory outside the input repositories",
    )
    for name in REPOSITORIES:
        parser.add_argument(
            "--" + name + "-repo", type=Path, default=Path(root) / ".sources" / name
        )
    args = parser.parse_args(argv)
    try:
        digest = assemble(
            root,
            args.destination,
            {name: getattr(args, name + "_repo") for name in REPOSITORIES},
        )
    except (OSError, KeyError, TypeError, UnicodeError, ValueError):
        raise ValueError(
            "Cannot collect pinned notices; check local Git objects and use a new output directory. No sources were fetched"
        ) from None
    print("Collected top-level component notices; manifest SHA-256 " + digest)
