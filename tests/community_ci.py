"""Exact-source Community verification on a NEW authorized GitHub Ubuntu job.

No dispatch, publication, deletion or private artifact export is performed here.
The runner's eventual disposal is a platform lifecycle, not durable retention.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

SOURCE = Path(__file__).resolve().parents[1]
PINS = {
    "baseline": {
        "map": "41d3ef6475f1b81f973dd4a73944b6e549500fd6",
        "runner": "668dc56f8685dc6a6225438ad443e26901828069",
        "gate": "7f82e499ec407eba072e129e3f3b94f1a4eabe94",
    },
    "current": {
        "map": "9f1f5d50d2b3c4aeb4c27ec0a53e077adf758045",
        "runner": "602a5423dcede0e37dacad52aab3bdad900c9021",
        "gate": "7f82e499ec407eba072e129e3f3b94f1a4eabe94",
    },
}
IMAGES = {
    "db": "vardrsec-db:development", "api": "vardrmap-api:development",
    "web": "vardrmap-web:development", "proxy": "vardrsec-proxy:development",
    "runner": "vardrrunner:development",
}


class CapacityError(ValueError):
    def __init__(self, free, required):
        super().__init__("Insufficient retained-cohort disk capacity; no pruning is allowed")
        self.free, self.required = free, required


def host_guard():
    release = platform.freedesktop_os_release()
    if not (
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_REPOSITORY") == "VardrSec/VardrSec"
        and os.environ.get("GITHUB_REF") == "refs/heads/codex/nm2-community-verification"
        and platform.system() == "Linux" and platform.machine() == "x86_64"
        and release.get("ID") == "ubuntu" and release.get("VERSION_ID") == "24.04"
        and os.environ.get("VARDRSEC_CI_RETAIN") == "1"
    ):
        raise ValueError("Only the authorized fresh GitHub Ubuntu verification branch is allowed")
    if any(os.environ.get(k) for k in ("DOCKER_HOST", "DOCKER_CONTEXT", "COMPOSE_FILE",
                                       "MAP_SOURCE", "RUNNER_SOURCE", "GATE_SOURCE")):
        raise ValueError("Remote Docker and source/config overrides are forbidden")


def new_copy(destination, cohort):
    if destination.exists() or destination.is_symlink():
        raise ValueError("Verification destination must be new; existing data is preserved")
    # Only tracked source is copied: no credentials, prior artifacts or snapshots.
    tracked = subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=SOURCE
    ).decode().split("\0")
    destination.mkdir(mode=0o700)
    for name in filter(None, tracked):
        src = SOURCE / name
        if src.is_symlink() or not src.is_file():
            raise ValueError("Only regular tracked verification source is supported")
        dst = destination / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    path = destination / "versions.json"
    manifest = json.loads(path.read_text())
    for name, commit in PINS[cohort].items():
        manifest["components"][name]["commit"] = commit
    # This is an owned verification copy; installed repository pins are not adopted.
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    (destination / ".community-ci-owned.json").write_text(json.dumps({
        k: os.environ.get(k) for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")
    }) + "\n")


def disk_guard(path, required):
    free = shutil.disk_usage(path).free
    if free < required:
        raise CapacityError(free, required)
    return free


def source_receipt(root, cohort):
    actual = {}
    for name, expected in PINS[cohort].items():
        path = root / ".sources" / name
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()
        dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=path, text=True)
        if head != expected or dirty:
            raise ValueError("Acquired source differs from exact reviewed commit")
        actual[name] = head
    return actual


def recovery_capacity(root, generations=1):
    # Uncompressed image sizes deliberately overcount shared layers. Preserve
    # plaintext, ciphertext and unsealed copies, plus retained restore volumes.
    total = 0
    for image in IMAGES.values():
        total += int(subprocess.check_output(
            ["docker", "image", "inspect", image, "--format", "{{.Size}}"], text=True
        ).strip())
    required = generations * 4 * total + 2 * 1024**3
    return {"required_free_bytes": required, "free_bytes": disk_guard(root, required)}


def build_candidate(root, destination, stage):
    new_copy(destination, "current")
    # Resolve sources through the supported acquisition code, but do not configure,
    # start or overwrite any old installation state.
    stage("candidate-sources", [sys.executable, "vardrsec.py", "sources"], destination)
    source_receipt(destination, "current")
    # Compose needs values even for build. Reuse PRIVATE synthetic configuration;
    # this file is never logged/exported and old configuration remains unchanged.
    shutil.copy2(root / ".env", destination / ".env")
    (destination / ".env").chmod(0o600)
    tags = {s: f"vardrsec-nm2-candidate-{s}:verification" for s in IMAGES}
    override = destination / "candidate-build.json"
    override.write_text(json.dumps({"services": {s: {"image": t} for s, t in tags.items()}}))
    stage("candidate-images", ["docker", "compose", "-f", "compose.yaml", "-f",
          str(override), "--profile", "tools", "build", "api", "web", "proxy", "runner"], destination)
    images = {s: subprocess.check_output(
        ["docker", "image", "inspect", tag, "--format", "{{.Id}}"], text=True
    ).strip() for s, tag in tags.items() if s != "db"}
    # Same supported PostgreSQL image: normal updater explicitly refuses DB-image changes.
    images["db"] = subprocess.check_output(
        ["docker", "image", "inspect", IMAGES["db"], "--format", "{{.Id}}"], text=True
    ).strip()
    if not all(re.fullmatch(r"sha256:[0-9a-f]{64}", x) for x in images.values()):
        raise ValueError("Invalid candidate image identity")
    manifest = destination / "candidate.json"
    manifest.write_text(json.dumps({"schema_version": 1,
        "public_origin": "https://localhost:8443", "images": images,
        "components": PINS["current"]}, indent=2) + "\n")
    return manifest


def stop_owned(root):
    """Stop only Compose containers whose recorded working directory is ours."""
    ids = subprocess.check_output(["docker", "ps", "-q"], text=True).split()
    stopped = 0
    for container in ids:
        info = json.loads(subprocess.check_output(["docker", "inspect", container], text=True))[0]
        labels = info.get("Config", {}).get("Labels") or {}
        directory = labels.get("com.docker.compose.project.working_dir", "")
        if directory and Path(directory).resolve().is_relative_to(root.resolve()):
            subprocess.run(["docker", "stop", "--time", "10", container], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            stopped += 1
    return stopped


def run(kind, destination, evidence):
    host_guard()
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve()
    if (destination != temporary / "community-run" or evidence != temporary / "community-public-evidence"
            or SOURCE.resolve() != Path(os.environ["GITHUB_WORKSPACE"]).resolve()):
        raise ValueError("Use only the exact new run-owned fixture and evidence paths")
    if evidence.exists() or evidence.is_symlink():
        raise ValueError("Public evidence destination must be new")
    evidence.mkdir(mode=0o700)
    summary = {"schema_version": 1, "kind": kind, "status": "running", "stages": [],
               "source_pins": PINS, "managed_worker": "disabled_unsupported",
               "native_ca_cleanup": "unrun_retention", "raw_private_artifacts_exported": False,
               "ephemeral_disposal": "GitHub discards unexported state after job completion"}
    private = evidence.parent / (evidence.name + "-private")
    if private.exists():
        raise ValueError("Private log destination must be new")
    private.mkdir(mode=0o700)
    owned = False

    def stage(name, args, cwd=destination):
        log = private / (name + ".log")
        with log.open("x") as out:
            log.chmod(0o600)
            result = subprocess.run(args, cwd=cwd, stdout=out, stderr=subprocess.STDOUT,
                                    env={**os.environ, "COMPOSE_PROJECT_NAME": "vardrsec-compose-review"})
        summary["stages"].append({"name": name, "passed": result.returncode == 0,
            "private_log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()})
        (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(name + (": PASS" if result.returncode == 0 else ": FAIL; private log retained"), flush=True)
        if result.returncode:
            raise ValueError("Verification stage failed")

    try:
        summary["initial_free_bytes"] = disk_guard(destination.parent, 8 * 1024**3)
        new_copy(destination, "current" if kind == "clean" else "baseline")
        owned = True
        stage("clean-host", [sys.executable, "tests/ubuntu_installation.py", "preflight"])
        stage("install", [sys.executable, "vardrsec.py", "install"])
        summary["installed_sources"] = source_receipt(destination, "current" if kind == "clean" else "baseline")
        summary["installed_images"] = {s: subprocess.check_output(
            ["docker", "image", "inspect", tag, "--format", "{{.Id}}"], text=True
        ).strip() for s, tag in IMAGES.items()}
        stage("browser-build", ["docker", "build", "-t", "vardrsec-browser:acceptance", "tests/browser"])
        stage("native-trust", [sys.executable, "tests/ubuntu_installation.py", "enroll"])
        stage("installed-interoperability", [sys.executable, "tests/compose_acceptance.py"])
        stage("container-security", [sys.executable, "tests/container_capabilities_acceptance.py"])
        stage("locale-security", [sys.executable, "tests/glibc_locale_acceptance.py"])
        if kind == "clean":
            summary["recovery_capacity"] = recovery_capacity(destination)
            stage("database-role", [sys.executable, "tests/database_role_acceptance.py"])
            summary["recovery_capacity"] = recovery_capacity(destination)
            stage("encrypted-whole-install-restore", [sys.executable, "tests/recovery_acceptance.py",
                  "--expected-installed-head", "0038managedstops"])
        else:
            summary["upgrade_capacity"] = recovery_capacity(destination, generations=2)
            candidate = build_candidate(destination, destination.parent / "community-candidate", stage)
            summary["candidate_build"] = json.loads(candidate.read_text())
            summary["candidate_acquired_sources"] = source_receipt(candidate.parent, "current")
            summary["candidate_manifest_sha256"] = hashlib.sha256(candidate.read_bytes()).hexdigest()
            summary["upgrade_capacity"] = recovery_capacity(destination, generations=2)
            stage("actual-0031-to-0038", [sys.executable, "tests/community_upgrade_acceptance.py",
                  "--candidate", str(candidate), "--output", str(destination / "artifacts/actual-upgrade"),
                  "--rehearsal-project", "vardrsec-restore-nm2-community-upgrade"])
            result = destination / "artifacts/actual-upgrade/result.json"
            receipt = json.loads(result.read_text())
            allowed = ("status", "initial_revision", "final_revision", "original_column_rows_preserved",
                       "sequences_preserved", "application_role_verified", "ca_preserved", "state_preserved",
                       "old_gate_journey_readback_verified", "baseline_table_count", "baseline_row_count",
                       "original_columns_sha256", "backup_snapshot_sha256", "updater_receipt_sha256")
            summary["actual_upgrade"] = {k: receipt[k] for k in allowed if k in receipt}
            summary["actual_upgrade_receipt_sha256"] = hashlib.sha256(result.read_bytes()).hexdigest()
        summary["status"] = "passed"
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        summary["status"] = "failed_or_unproven"
        summary["failure_type"] = type(error).__name__
        if isinstance(error, CapacityError):
            summary["capacity_shortfall"] = {"free_bytes": error.free,
                                             "required_free_bytes": error.required}
        print("Community verification incomplete; no acceptance claimed", flush=True)
    finally:
        try:
            summary["owned_containers_stopped"] = stop_owned(destination) if owned else 0
        except (OSError, ValueError, subprocess.SubprocessError):
            summary["status"] = "failed_or_unproven"
            summary["stop_status"] = "unproven"
        # Explicit allowlist: no recursive upload, DB/env/identity/CA-key contents.
        if destination.exists():
            for relative in ("artifacts/installed-gate/accepted.json", "artifacts/role-receipt/receipt.json"):
                receipt = destination / relative
                if receipt.is_file():
                    summary.setdefault("retained_receipt_sha256", {})[relative] = hashlib.sha256(receipt.read_bytes()).hexdigest()
        (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("clean", "upgrade"), required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.kind, args.destination, args.evidence))
