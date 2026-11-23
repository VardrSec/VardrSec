"""Classify the entire pull request against the merge commit checked out by Actions."""

import subprocess
import sys


# Release evidence, inventories and unrecognized paths require full checks.
GUIDES = {
    b"README.md",
    b"CHANGELOG.md",
    b"docs/assessment-example.md",
    b"docs/database-roles.md",
    b"docs/encrypted-backups.md",
    b"docs/installation.md",
    b"docs/limitations.md",
    b"docs/local-managed-setup.md",
    b"docs/managed-worker-operator.md",
    b"docs/mapless.md",
    b"docs/networking.md",
    b"docs/platforms.md",
    b"docs/recovery.md",
    b"docs/updates.md",
}


def guide_only(base, head):
    parents = subprocess.check_output(["git", "show", "-s", "--format=%P", "HEAD"]).split()
    if parents != [base.encode(), head.encode()]:
        return False
    # Report both sides of a rename and preserve unusual filenames.
    diff = subprocess.check_output([
        "git", "diff", "--no-renames", "--ignore-submodules=none", "--name-only",
        "-z", "HEAD^1", "HEAD", "--",
    ])
    paths = set(diff.split(b"\0")[:-1])
    return bool(paths) and paths <= GUIDES


if __name__ == "__main__":
    print("guide_only=" + str(guide_only(*sys.argv[1:])).lower())
