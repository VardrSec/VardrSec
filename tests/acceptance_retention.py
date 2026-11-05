"""Test-only retention adapter; never imported by product lifecycle commands.

Opt in only in a fresh GitHub-hosted Ubuntu checkout. Retained fixture containers
carry a run-scoped ownership label; project stops require Compose ownership and
working-directory labels. No logs, environment values or credentials are dumped.
"""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
LABEL = "org.vardrsec.acceptance.run"


def enabled():
    value = os.environ.get("VARDRSEC_CI_RETAIN", "0")
    if value == "0":
        return False
    if value != "1":
        raise RuntimeError("VARDRSEC_CI_RETAIN must be 0 or 1")
    required = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Linux"}
    if any(os.environ.get(k) != v for k, v in required.items()):
        raise RuntimeError("Retention requires fresh GitHub-hosted Ubuntu CI")
    if 'ID=ubuntu' not in Path("/etc/os-release").read_text().splitlines():
        raise RuntimeError("Retention requires Ubuntu")
    if any(not os.environ.get(k) for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")):
        raise RuntimeError("Retention requires a scoped GitHub run")
    if any(p.is_symlink() for p in (ROOT, *ROOT.parents)):
        raise RuntimeError("Retention checkout path must not contain symlinks")
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", ""))
    if ROOT.resolve() != workspace.resolve():
        runner_temp = os.environ.get("RUNNER_TEMP")
        if not runner_temp or ROOT != Path(runner_temp) / "community-run":
            raise RuntimeError("Retention requires the current GitHub checkout or owned copy")
        marker = ROOT / ".community-ci-owned.json"
        if marker.is_symlink() or not marker.is_file():
            raise RuntimeError("Retained copy ownership marker is missing")
        owned = json.loads(marker.read_text())
        if any(owned.get(k) != os.environ[k] for k in
               ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")):
            raise RuntimeError("Retained copy belongs to another CI run")
    return True


def scope():
    if not enabled():
        raise RuntimeError("Retention is disabled")
    return hashlib.sha256("\n".join(os.environ[k] for k in
        ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "GITHUB_WORKSPACE")
    ).encode()).hexdigest()[:24]


def fixture_name(name):
    return name + "-" + uuid.uuid4().hex[:12] if enabled() else name


def docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          timeout=30, check=True)


def run_flags(name):
    if not enabled():
        return ["--rm"]
    existing = docker("ps", "-a", "--filter", f"name=^/{name}$", "--format", "{{.ID}}")
    if existing.stdout.strip():
        raise RuntimeError("Refusing an existing fixture container")
    return ["--name", name, "--label", f"{LABEL}={scope()}"]


def stop_container(name):
    """Stop/kill only this run's labeled fixture; never remove its container."""
    if not enabled():
        raise RuntimeError("Retained container stop requires retention mode")
    ids = docker("ps", "-a", "--filter", f"name=^/{name}$", "--format", "{{.ID}}").stdout.split()
    if not ids:
        return
    if len(ids) != 1:
        raise RuntimeError("Ambiguous fixture ownership")
    container = ids[0]
    labels = json.loads(docker("inspect", "--format", "{{json .Config.Labels}}", container).stdout)
    if (labels or {}).get(LABEL) != scope():
        raise RuntimeError("Refusing to stop an unowned fixture")
    try:
        docker("stop", "--time", "3", container)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass  # The independent forced-stop check still runs.
    running = docker("inspect", "--format", "{{.State.Running}}", container).stdout.strip()
    if running == "true":
        docker("kill", container)


def docker_fixture_run(command, *, project, purpose, **kwargs):
    if not enabled():
        return subprocess.run(command, **kwargs)
    command = list(command)
    if command[:3] != ["docker", "run", "--rm"]:
        raise RuntimeError("Expected disposable Docker test one-shot")
    name = fixture_name(project + "-" + purpose)
    command[2:3] = run_flags(name)
    try:
        return subprocess.run(command, **kwargs)
    finally:
        stop_container(name)


def compose_fixture_run(compose, *args, project, purpose, **kwargs):
    """Adapt only explicit test one-shots, preserving default invocation exactly."""
    if not enabled() or "run" not in args:
        return compose(*args, **kwargs)
    index = args.index("run")
    if "--rm" not in args[index + 1:]:
        raise RuntimeError("Expected disposable test one-shot")
    name = fixture_name(project + "-" + purpose)
    command = list(args)
    command[command.index("--rm", index + 1):command.index("--rm", index + 1) + 1] = run_flags(name)
    try:
        return compose(*command, **kwargs)
    finally:
        stop_container(name)


def fresh_work(path):
    if not enabled():
        raise RuntimeError("Fresh retained work requires retention mode")
    path = Path(path)
    if not path.resolve().is_relative_to((ROOT / "artifacts").resolve()):
        raise RuntimeError("Retained work must be inside checkout artifacts")
    if path.exists() or path.is_symlink():
        raise RuntimeError("Refusing existing acceptance work directory")
    path.mkdir(parents=True, mode=0o700)


def require_new_project(project):
    scope()
    for command in [("ps", "-a"), ("volume", "ls"), ("network", "ls")]:
        if docker(*command, "--filter", f"label=com.docker.compose.project={project}",
                  "--format", "{{.ID}}" if command[0] != "volume" else "{{.Name}}").stdout.strip():
            raise RuntimeError("Refusing existing acceptance project resources")


def stop_project(directory, project):
    """Validate every project container before stopping; retain volumes/networks."""
    scope()  # validates the opt-in environment even if the project is empty
    if not Path(directory).resolve().is_relative_to(ROOT.resolve()):
        raise RuntimeError("Refusing a project outside the current checkout")
    ids = docker("ps", "-a", "--filter", f"label=com.docker.compose.project={project}",
                 "--format", "{{.ID}}").stdout.split()
    for container in ids:
        labels = json.loads(docker("inspect", "--format", "{{json .Config.Labels}}", container).stdout)
        if ((labels or {}).get("com.docker.compose.project") != project
            or Path((labels or {}).get("com.docker.compose.project.working_dir", "")).resolve()
            != Path(directory).resolve()):
            raise RuntimeError("Refusing to stop an unowned Compose project")
    if ids:
        # Stop immutable, verified IDs, not a project selection that might expand.
        docker("stop", "--time", "10", *ids)
