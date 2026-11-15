"""One immutable ACL-only cohort on a fresh hosted VM, never a production override."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
QUALIFIED_DB = "0ea1d326c61183dda3dab81c49945c7f94205809"
PRODUCTION_MANIFEST_SHA256 = "4ba8bb97a8dd1638f65eabc7af66938e051321ad52960f99058a017d5f8e28b6"
RECIPE = ("README.md", "build.sh", "coreutils-descriptor-acl.patch", "regression.py", "swap-acl.c", "tar-descriptor-acl.patch")
COHORT = {
    "map": {
        "repository": "VardrSec/VardrMap",
        "pin": "4a5211c2bcef5b89ba3d8a12244c3acffb55f188",
        "base": "a73a988dbbbab7d07e90dc8cf67212200162e1d5",
        "head": "90595da2b5e1eeff4112dde1802ee637b9b972bb",
        "patch_sha256": "6872b71fe1dcc77959d71dc91cd0395228a9a56e7dd3f2d4e4d7d448fea74834",
        "paths": sorted([".gitattributes", ".github/workflows/containers.yml"] + [f"{context}/{name}" for context in ("backend", "frontend") for name in (".dockerignore", "Dockerfile")] + [f"{context}/acl/{name}" for context in ("backend", "frontend") for name in RECIPE]),
    },
    "runner": {
        "repository": "VardrSec/VardrRunner",
        "pin": "f57ea3a95dd01837043eaf61a54cb2f73d9ab265",
        "base": "f57ea3a95dd01837043eaf61a54cb2f73d9ab265",
        "head": "6d24206734ee6efa39bee2494428d4ebce857c3a",
        "patch_sha256": "a0507baf32a34034b6d79f968f96e3941e49d9de6eff3c146734fc763bbc073f",
        "paths": sorted([".dockerignore", ".gitattributes", ".github/workflows/container.yml", "Dockerfile"] + [f"container/acl/{name}" for name in RECIPE]),
    },
}
GATE_PIN = "2474296597b6ccd082e2e405662fd1f2cada69f4"
OVERRIDES = {"MAP_SOURCE", "RUNNER_SOURCE", "GATE_SOURCE", "VARDRSEC_IMAGE_TAG", "VARDRMAP_SOURCE_REVISION", "COMPOSE_FILE", "COMPOSE_PROJECT_NAME", "DOCKER_HOST", "DOCKER_CONTEXT", "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_OBJECT_DIRECTORY"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(*args, cwd=None, **kwargs):
    return subprocess.run(args, cwd=cwd, check=True, **kwargs)


def git(path, *args, input=None):
    return run("git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-C", str(path), *args, input=input, capture_output=True).stdout


def text(path, *args):
    return git(path, *args).decode().strip()


def validate_environment(env, system, release):
    require(env.get("GITHUB_ACTIONS") == "true" and env.get("RUNNER_ENVIRONMENT") == "github-hosted", "Only fresh GitHub-hosted runners are allowed")
    require(system == "Linux" and release.get("ID") == "ubuntu" and release.get("VERSION_ID") == "24.04", "Only Ubuntu 24.04 is qualified")
    require(not OVERRIDES.intersection(env), "Source, Docker or Compose overrides refused")
    require(not any(k.startswith("GIT_CONFIG_") for k in env), "Git configuration injection refused")


def expected_head(event, event_name):
    require(event.get("repository", {}).get("full_name") == "VardrSec/VardrSec", "Unexpected distribution repository")
    require(event_name == "pull_request" and event.get("number") == 114, "Only reviewed PR 114 may qualify this cohort")
    pr = event.get("pull_request", {})
    require(pr.get("head", {}).get("repo", {}).get("full_name") == "VardrSec/VardrSec", "Fork cohort execution refused")
    require(pr.get("head", {}).get("ref") == "codex/acl-caller-security", "Unexpected cohort branch")
    sha = pr.get("head", {}).get("sha", "")
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None, "Exact distribution SHA required")
    return sha


def verify_patch(patch, paths, spec):
    require(digest(patch) == spec["patch_sha256"], "Reviewed ACL delta hash mismatch")
    require(sorted(paths) == spec["paths"], "Unreviewed delta path")


def clean(path):
    require(not text(path, "status", "--porcelain", "--untracked-files=all"), "Dirty fixture/source checkout refused")
    require((path / ".git").is_dir() and not (path / ".git").is_symlink(), "External Git metadata refused")
    require(Path(text(path, "rev-parse", "--show-toplevel")).resolve() == path.resolve(), "Git root binding mismatch")
    require(Path(text(path, "rev-parse", "--absolute-git-dir")).resolve() == (path / ".git").resolve(), "Git metadata binding mismatch")


def commit_fixture(path, parent, message):
    tree = text(path, "write-tree")
    env = {**os.environ, "GIT_AUTHOR_NAME": "ACL CI fixture", "GIT_AUTHOR_EMAIL": "acl-fixture@example.invalid", "GIT_COMMITTER_NAME": "ACL CI fixture", "GIT_COMMITTER_EMAIL": "acl-fixture@example.invalid", "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00", "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00"}
    sha = run("git", "-c", "commit.gpgsign=false", "-C", str(path), "commit-tree", tree, "-p", parent, input=(message + "\n").encode(), env=env, capture_output=True).stdout.decode().strip()
    git(path, "checkout", "--detach", sha)
    clean(path)
    return sha, tree


def fetch_source(path, repository, sha):
    path.mkdir()
    git(path, "init")
    git(path, "fetch", "--depth=1", "https://github.com/" + repository + ".git", sha)
    git(path, "checkout", "--detach", sha)
    clean(path)
    require(text(path, "rev-parse", "HEAD") == sha, "Fetched source mismatch")


def tree_entries(path, ref):
    result = {}
    for row in git(path, "ls-tree", "-rz", ref).split(b"\0"):
        if row:
            metadata, name = row.split(b"\t", 1)
            result[name.decode()] = metadata.decode()
    return result


def verify_trees(before, reviewed, applied, paths):
    changed = sorted(name for name in set(before) | set(applied) if before.get(name) != applied.get(name))
    require(changed == paths, "Applied tree changes exceed reviewed paths")
    for name in paths:
        require(not name.startswith("/") and all(part not in ("", ".", "..", ".git") for part in name.split("/")), "Unsafe delta path")
        entry = applied.get(name, "")
        require(entry.startswith("100644 blob ") and entry == reviewed.get(name), "Applied file mode/type/blob differs from review")


def apply_cohort(path, spec):
    fetch_source(path, spec["repository"], spec["pin"])
    for sha in (spec["base"], spec["head"]):
        git(path, "fetch", "--depth=1", "https://github.com/" + spec["repository"] + ".git", sha)
    patch = git(path, "diff", "--binary", "--full-index", "--no-ext-diff", spec["base"], spec["head"], "--")
    paths = text(path, "diff", "--name-only", spec["base"], spec["head"]).splitlines()
    verify_patch(patch, paths, spec)
    git(path, "apply", "--check", "--index", "-", input=patch)
    git(path, "apply", "--index", "-", input=patch)
    require(text(path, "diff", "--cached", "--name-only", spec["pin"]).splitlines() == spec["paths"], "Applied paths differ from reviewed ACL delta")
    for file in paths:
        require(text(path, "ls-files", "--stage", "--", file).split()[0] == "100644", "Nonregular fixture input refused")
        require(git(path, "show", ":" + file) == git(path, "show", spec["head"] + ":" + file), "Result does not match reviewed ACL file")
    verify_trees(tree_entries(path, spec["pin"]), tree_entries(path, spec["head"]), tree_entries(path, text(path, "write-tree")), paths)
    sha, tree = commit_fixture(path, spec["pin"], "Test-only pinned base plus reviewed ACL delta " + spec["head"])
    require(not text(path, "status", "--porcelain", "--untracked-files=all", "--ignored"), "Ignored source inputs refused")
    return {**{k: v for k, v in spec.items() if k != "paths"}, "paths": paths, "fixture_commit": sha, "fixture_tree": tree}


def boundaries():
    validate_environment(os.environ, platform.system(), platform.freedesktop_os_release())
    temp = Path(os.environ["RUNNER_TEMP"])
    require(temp.is_absolute() and temp.is_dir() and not temp.is_symlink(), "Invalid hosted temporary directory")
    return temp / "acl-cohort", temp / "acl-cohort-public"


def prepare():
    workspace, public = boundaries()
    sha = expected_head(json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text()), os.environ["GITHUB_EVENT_NAME"])
    require(text(ROOT, "rev-parse", "HEAD") == sha, "Checkout differs from triggering head")
    clean(ROOT)
    require(not workspace.exists() and not public.exists(), "Existing fixture/evidence must be preserved")
    original = (ROOT / "versions.json").read_bytes()
    require(digest(original) == PRODUCTION_MANIFEST_SHA256, "Production pins changed; cohort requires explicit re-review")
    require(text(ROOT, "rev-parse", "HEAD:db") == text(ROOT, "rev-parse", QUALIFIED_DB + ":db"), "Database differs from qualified recipe")
    for name in (".env", ".sources", ".active-images.json", ".installation-mode.json"):
        require(not (ROOT / name).exists(), "Existing installation refused")
    workspace.mkdir()
    public.mkdir()
    fixture = workspace / "distribution"
    run("git", "clone", "--no-local", "--no-hardlinks", "--no-checkout", str(ROOT), str(fixture), capture_output=True)
    git(fixture, "checkout", "--detach", sha)
    git(fixture, "remote", "remove", "origin")
    run(sys.executable, "tests/ubuntu_installation.py", "preflight", cwd=fixture)
    sources = fixture / ".sources"
    sources.mkdir()
    manifest = json.loads(original)
    provenance = {}
    for name, spec in COHORT.items():
        require(manifest["components"][name]["commit"] == spec["pin"], "Unexpected production component pin")
        provenance[name] = apply_cohort(sources / name, spec)
        manifest["components"][name]["commit"] = provenance[name]["fixture_commit"]
    require(manifest["components"]["gate"]["commit"] == GATE_PIN, "Gate pin changed")
    fetch_source(sources / "gate", "VardrSec/VardrGate", GATE_PIN)
    tested = (json.dumps(manifest, indent=2) + "\n").encode()
    (fixture / "versions.json").write_bytes(tested)
    git(fixture, "add", "--", "versions.json")
    fixture_sha, fixture_tree = commit_fixture(fixture, sha, "Test-only exact ACL cohort manifest; not release pins")
    # Run production guards unchanged, against clean exact synthetic commits.
    run(sys.executable, "vardrsec.py", "sources", cwd=fixture)
    require((ROOT / "versions.json").read_bytes() == original, "Original production manifest mutated")
    receipt = {"schema": "vardr.acl-test-cohort/1", "status": "prepared-not-qualified", "distribution_head": sha, "qualified_database": QUALIFIED_DB, "production_manifest_sha256": digest(original), "fixture_distribution_commit": fixture_sha, "fixture_distribution_tree": fixture_tree, "tested_manifest_sha256": digest(tested), "tested_manifest": manifest, "components": provenance, "gate_pin": GATE_PIN}
    (public / "provenance.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("Prepared immutable ACL-only fixture; production manifest unchanged")


RUNTIME_CHECK = r'''set -eu
source=/usr/share/doc/libacl1/vardr-source
(cd "$source" && sha256sum -c SHA256SUMS)
grep -Fx "cp-path-substitution: EXPECTED_VULNERABLE" "$source/evidence/negative-controls.log"
grep -Fx "tar-path-substitution: EXPECTED_VULNERABLE" "$source/evidence/negative-controls.log"
grep -Fx "cp-path-substitution: PASS" "$source/evidence/stripped-payload-regressions.log"
grep -Fx "tar-path-substitution: PASS" "$source/evidence/stripped-payload-regressions.log"
cd /
grep -hE "  ./usr/(bin/(cp|tar)|lib/[^/]+/libacl[.]so[.][0-9.]+)$" "$source"/*.files-SHA256SUMS > /tmp/acl-runtime-hashes
test "$(wc -l < /tmp/acl-runtime-hashes)" -eq 3
sha256sum -c /tmp/acl-runtime-hashes
'''


IMAGE_TAGS = {"db": "vardrsec-db:development", "api": "vardrmap-api:development", "web": "vardrmap-web:development", "runner": "vardrrunner:development"}


def image_ids():
    ids = {}
    for service, tag in IMAGE_TAGS.items():
        image = run("docker", "image", "inspect", tag, "--format", "{{.Id}}", capture_output=True, text=True).stdout.strip()
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", image) is not None, "Invalid image identity")
        ids[service] = image
    return ids


def selected_images(selection, built):
    require(isinstance(selection, dict) and set(selection) == {"services", "networks"}, "Unexpected frozen selection")
    services = selection["services"]
    require(isinstance(services, dict) and set(services) == set(IMAGE_TAGS) | {"proxy"}, "Unexpected selected services")
    for definition in services.values():
        require(isinstance(definition, dict) and set(definition) == {"image"} and isinstance(definition["image"], str) and re.fullmatch(r"sha256:[0-9a-f]{64}", definition["image"]) is not None, "Frozen selection requires immutable image IDs")
    selected = {name: services[name]["image"] for name in IMAGE_TAGS}
    require(selected == built, "Frozen selection differs from qualified built images")
    return selected


def selection_bytes(fixture):
    path = fixture / ".active-images.json"
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16384, "Invalid frozen selection file")
    return path.read_bytes()


def capture():
    workspace, public = boundaries()
    receipt = json.loads((public / "provenance.json").read_text())
    require(receipt["status"] == "prepared-not-qualified", "Invalid pre-smoke receipt")
    ids = image_ids()
    selected = selection_bytes(workspace / "distribution")
    selection = selected_images(json.loads(selected), ids)
    receipt.update(status="built-not-qualified", built_image_ids=ids, selected_image_ids=selection, active_images_sha256=digest(selected))
    (public / "provenance.json").write_text(json.dumps(receipt, indent=2) + "\n")


def verify():
    workspace, public = boundaries()
    fixture = workspace / "distribution"
    receipt = json.loads((public / "provenance.json").read_text())
    require(receipt["status"] == "built-not-qualified", "Receipt already finalized or invalid")
    require(text(ROOT, "rev-parse", "HEAD") == receipt["distribution_head"], "Distribution head changed")
    require(digest((ROOT / "versions.json").read_bytes()) == PRODUCTION_MANIFEST_SHA256, "Production manifest changed")
    require(text(fixture, "rev-parse", "HEAD") == receipt["fixture_distribution_commit"], "Fixture head changed")
    require(digest((fixture / "versions.json").read_bytes()) == receipt["tested_manifest_sha256"], "Tested manifest changed")
    clean(fixture)
    run(sys.executable, "vardrsec.py", "sources", cwd=fixture)
    run(sys.executable, "-c", "import vardrsec; assert vardrsec.map_source_revision() == " + repr(receipt["components"]["map"]["fixture_commit"]), cwd=fixture)
    require((fixture / "artifacts/installed-gate/accepted.json").is_file(), "Joint acceptance receipt missing")
    images = {}
    ids = image_ids()
    require(ids == receipt["built_image_ids"], "Images changed during joint smoke")
    selected = selection_bytes(fixture)
    require(digest(selected) == receipt["active_images_sha256"], "Frozen image selection changed during smoke")
    require(selected_images(json.loads(selected), ids) == receipt["selected_image_ids"], "Selected image identities changed")
    for service, image in ids.items():
        if service != "runner":
            used = run(sys.executable, "-c", "from pathlib import Path; import recovery; print(recovery.container(Path.cwd(), " + repr(service) + ", 'vardrsec-compose-review')['Image'])", cwd=fixture, capture_output=True, text=True).stdout.strip()
            require(used == image, "Runtime image differs from exercised stack")
        result = run("docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--entrypoint", "sh", image, "-ec", RUNTIME_CHECK, capture_output=True)
        (public / (service + "-acl.log")).write_bytes(result.stdout)
        images[service] = {"image_id": image, "evidence_sha256": digest(result.stdout)}
    accepted = (fixture / "artifacts/installed-gate/accepted.json").read_bytes()
    receipt.update(status="PASS", images=images, joint_acceptance_sha256=digest(accepted))
    (public / "provenance.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("PASS: joint workflow and all four ACL runtime payloads qualified")


if __name__ == "__main__":
    require(sys.argv[1:] in (["prepare"], ["capture"], ["verify"]), "Expected prepare, capture or verify")
    {"prepare": prepare, "capture": capture, "verify": verify}[sys.argv[1]]()
