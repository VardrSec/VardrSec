"""Opt-in fresh GitHub-hosted Ubuntu execution of the existing NM-2 harness.

No execution occurs without --execute. Inputs select exact public source commits,
not product pins. Raw output and fixture custody never enter the public receipt.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import socket
import stat
import subprocess
import sys
import time

SOURCE = Path(__file__).resolve().parents[1]
BRANCH = "refs/heads/codex/nm1-nm2-closeout"
REPOSITORIES = {
    name: "VardrSec/" + repo
    for name, repo in (
        ("map", "VardrMap"),
        ("runner", "VardrRunner"),
        ("gate", "VardrGate"),
    )
}
SHA = re.compile(r"[0-9a-f]{40}")
IMAGE = re.compile(r"sha256:[0-9a-f]{64}")
CASES = {
    "default_disabled",
    "strict_out_of_scope",
    "happy_fixed",
    "missing_local_grant",
}
STAGES = {
    "host",
    "sources",
    "dependencies",
    "build_db",
    "build_api",
    "build_web",
    "build_proxy",
    "build_toolkit",
    "build_worker",
    "harness",
    "complete",
}


class HostedRefused(ValueError):
    pass


def require(value):
    if not value:
        raise HostedRefused("nm2_hosted_prerequisite_refused")


def cohort(env):
    values = {
        name: env.get("NM2_" + name.upper() + "_SHA", "")
        for name in ("distribution", *REPOSITORIES)
    }
    require(
        all(type(value) is str and SHA.fullmatch(value) for value in values.values())
    )
    require(values["distribution"] == env.get("GITHUB_SHA"))
    return values


def host_guard(env):
    release = platform.freedesktop_os_release()
    require(
        env.get("GITHUB_ACTIONS") == "true"
        and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and env.get("GITHUB_REPOSITORY") == "VardrSec/VardrSec"
        and env.get("GITHUB_REF") == BRANCH
        and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and env.get("NM2_COUPLED") == "true"
        and platform.system() == "Linux"
        and platform.machine() == "x86_64"
        and release.get("ID") == "ubuntu"
        and release.get("VERSION_ID") == "24.04"
    )
    require(
        not any(
            key.startswith(("DOCKER_", "COMPOSE_", "VARDRMAP_", "VARDRRUNNER_"))
            for key in env
        )
    )
    require(SOURCE.resolve() == Path(env["GITHUB_WORKSPACE"]).resolve())
    temporary = Path(env["RUNNER_TEMP"])
    require(
        temporary.is_absolute()
        and temporary.is_dir()
        and not temporary.is_symlink()
        and SOURCE not in temporary.parents
        and temporary != SOURCE
    )
    info = Path("/var/run/docker.sock").stat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0)
    return temporary


def public_projection(raw, selection):
    """Project only fixed statuses and measured hashes, never raw nested data."""
    require(
        type(raw) is dict
        and raw.get("schema") == "vardr.nm2-worker-acceptance/1"
        and raw.get("status") == "initial_stages_passed"
    )
    require(
        raw.get("sources") == selection["sources"]
        and raw.get("images") == selection["images"]
        and raw.get("project") == selection["project"]
        and raw.get("readiness_volume") == selection["project"] + "_worker-ready"
        and raw.get("platform") == "linux"
        and raw.get("retained") is True
    )
    cases = raw.get("cases")
    require(type(cases) is dict and set(cases) == CASES)
    observed = {}
    for name in sorted(CASES):
        require(
            type(cases[name]) is dict
            and cases[name].get("status") in {"passed", "not_run"}
        )
        observed[name] = cases[name]["status"]
    require(all(observed[name] == "passed" for name in CASES - {"missing_local_grant"}))
    happy = cases["happy_fixed"]
    requests = happy.get("requests")
    require(
        type(requests) is list
        and len(requests) == 5
        and all(
            type(row) is dict and type(row.get("identity")) is str for row in requests
        )
        and {row.get("identity") for row in requests} == {"owner", "peer", "anonymous"}
    )
    require(type(happy.get("evidence_count")) is int and happy["evidence_count"] == 5)
    inventory = happy.get("inventory")
    require(
        type(inventory) is dict
        and type(inventory.get("results")) is list
        and len(inventory["results"]) == 1
    )
    result = inventory["results"][0]
    require(
        type(result) is dict
        and result.get("outcome") == "completed"
        and type(result.get("evidence_created")) is int
        and result["evidence_created"] == 5
        and type(result.get("scan_items_created")) is int
        and result["scan_items_created"] == 0
    )
    stopped = raw.get("fixture_stop")
    require(type(stopped) is dict and stopped.get("status") == "stopped_retained")
    containers = stopped.get("container_ids")
    require(
        type(containers) is list
        and 0 < len(containers) <= 64
        and all(
            type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value)
            for value in containers
        )
        and len(set(containers)) == len(containers)
    )
    measurements = {
        "target_request_count": len(requests),
        "evidence_count": happy["evidence_count"],
        "case_sha256": happy.get("case_sha256"),
        "evidence_sha256": happy.get("evidence_sha256"),
        "result_artifact_sha256": result.get("artifact_sha256"),
        "result_receipt_sha256": result.get("receipt_sha256"),
        "public_ca_der_sha256": raw.get("public_ca_der_sha256"),
        "stopped_owned_container_count": len(containers),
    }
    require(
        all(
            type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value)
            for key, value in measurements.items()
            if key.endswith("_sha256")
        )
    )
    executables = raw.get("image_sources", {}).get("runner", {}).get("executables", {})
    require(
        type(executables) is dict
        and set(executables)
        == {"/usr/local/bin/vardr-worker-owner", "/usr/local/bin/vardrgate"}
        and all(
            type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value)
            for value in executables.values()
        )
    )
    inventories = {}
    for name, image in (("map", "api"), ("runner", "worker")):
        row = raw.get("image_sources", {}).get(name, {})
        require(
            row.get("image_id") == selection["images"][image]
            and type(row.get("python_file_count")) is int
            and 0 < row["python_file_count"] < 100000
            and type(row.get("python_inventory_sha256")) is str
            and re.fullmatch(r"[0-9a-f]{64}", row["python_inventory_sha256"])
        )
        inventories[name] = {
            key: row[key] for key in ("python_file_count", "python_inventory_sha256")
        }
    return {
        "cases": observed,
        "measurements": measurements,
        "executables": dict(executables),
        "source_inventories": inventories,
    }


class Hosted:
    def __init__(self, env):
        self.pins = cohort(env)
        temporary = host_guard(env)
        self.root = temporary / "nm2-hosted-private"
        self.public = temporary / "nm2-hosted-public"
        require(not os.path.lexists(self.root) and not os.path.lexists(self.public))
        self.root.mkdir(mode=0o700)
        self.public.mkdir(mode=0o700)
        self.environment = {
            key: value
            for key, value in env.items()
            if key in {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP"}
        }
        self.environment.update(
            GIT_TERMINAL_PROMPT="0",
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=os.devnull,
            PYTHON_DOTENV_DISABLED="1",
            PYTHONNOUSERSITE="1",
        )
        home = self.root / "home"
        home.mkdir(mode=0o700)
        self.environment["HOME"] = str(home)
        self.deadline = time.monotonic() + 90 * 60
        self.sources = {"distribution": SOURCE}
        self.project = (
            "vardrsec-nm2-"
            + hashlib.sha256(
                (env["GITHUB_RUN_ID"] + ":" + env["GITHUB_RUN_ATTEMPT"]).encode()
            ).hexdigest()[:16]
        )
        self.receipt = {
            "schema": "vardr.nm2-hosted/1",
            "status": "held",
            "stage": "host",
            "sources": self.pins,
            "source_trees": {},
            "images": {},
            "scope": "Same explicit initial NM2 harness; remaining cases are not acceptance",
        }

    def command(self, args, *, capture=False, timeout=60):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0)
        try:
            with (self.root / "private.log").open("ab") as log:
                os.chmod(log.name, 0o600)
                result = subprocess.run(
                    args,
                    cwd=SOURCE,
                    env=self.environment,
                    stdout=subprocess.PIPE if capture else log,
                    stderr=log,
                    timeout=min(timeout, remaining),
                    check=False,
                )
            require(result.returncode == 0)
            if capture:
                require(len(result.stdout) <= 131072)
                return result.stdout.decode("utf-8", errors="strict").strip()
        except (OSError, UnicodeError, subprocess.SubprocessError):
            raise HostedRefused("nm2_hosted_command_refused") from None

    def docker(self, *args, **kwargs):
        return self.command(["docker", "--context", "default", *args], **kwargs)

    def daemon_guard(self):
        endpoint = json.loads(
            self.docker(
                "context",
                "inspect",
                "default",
                "--format",
                "{{json .Endpoints.docker.Host}}",
                capture=True,
            )
        )
        require(endpoint == "unix:///var/run/docker.sock")
        info = json.loads(
            self.docker(
                "info",
                "--format",
                '{"os":{{json .OSType}},"name":{{json .Name}},"root":{{json .DockerRootDir}},"swarm":{{json .Swarm.LocalNodeState}}}',
                capture=True,
            )
        )
        require(
            info
            == {
                "os": "linux",
                "name": socket.gethostname(),
                "root": "/var/lib/docker",
                "swarm": "inactive",
            }
        )
        require(
            not self.docker("ps", "-aq", capture=True)
            and not self.docker("volume", "ls", "-q", capture=True)
        )
        require(
            set(
                self.docker(
                    "network", "ls", "--format", "{{.Name}}", capture=True
                ).splitlines()
            )
            <= {"bridge", "host", "none"}
        )

    def prepare_sources(self):
        self.receipt["stage"] = "sources"
        require(
            self.command(["git", "rev-parse", "HEAD"], capture=True)
            == self.pins["distribution"]
        )
        for name, repository in REPOSITORIES.items():
            path = self.root / name
            self.command(["git", "init", str(path)])
            self.command(
                [
                    "git",
                    "-C",
                    str(path),
                    "remote",
                    "add",
                    "origin",
                    "https://github.com/" + repository + ".git",
                ]
            )
            self.command(
                [
                    "git",
                    "-C",
                    str(path),
                    "fetch",
                    "--depth=1",
                    "--no-tags",
                    "origin",
                    self.pins[name],
                ],
                timeout=180,
            )
            self.command(["git", "-C", str(path), "checkout", "--detach", "FETCH_HEAD"])
            self.sources[name] = path
        for name, path in self.sources.items():
            require(
                self.command(
                    ["git", "-C", str(path), "rev-parse", "HEAD"], capture=True
                )
                == self.pins[name]
            )
            require(
                not self.command(
                    [
                        "git",
                        "-C",
                        str(path),
                        "status",
                        "--porcelain",
                        "--untracked-files=no",
                    ],
                    capture=True,
                )
            )
            tree = self.command(
                ["git", "-C", str(path), "rev-parse", "HEAD^{tree}"], capture=True
            )
            require(SHA.fullmatch(tree))
            self.receipt["source_trees"][name] = tree

    def build(self, name, context, *, file=None, extra=()):
        self.receipt["stage"] = "build_" + name
        iid = self.root / (name + ".iid")
        tag = self.project + ":" + name
        require(
            not self.docker(
                "image",
                "ls",
                "--filter",
                "reference=" + tag,
                "--format",
                "{{.ID}}",
                capture=True,
            )
        )
        self.docker(
            "build",
            "--iidfile",
            str(iid),
            "-t",
            tag,
            *(["-f", str(file)] if file else []),
            *extra,
            str(context),
            timeout=1800,
        )
        value = iid.read_text().strip()
        require(IMAGE.fullmatch(value))
        require(
            self.docker("image", "inspect", "--format", "{{.Id}}", tag, capture=True)
            == value
        )
        return value, tag

    def run(self):
        try:
            self.daemon_guard()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", 28443))
            self.prepare_sources()
            self.receipt["stage"] = "dependencies"
            tools = self.root / "tools"
            self.command([sys.executable, "-m", "venv", str(tools)])
            python = tools / "bin" / "python"
            self.command(
                [
                    str(python),
                    "-m",
                    "pip",
                    "install",
                    "--disable-pip-version-check",
                    str(self.sources["runner"]) + "[authorization]",
                ],
                timeout=300,
            )
            for name, context in (
                ("db", SOURCE / "db"),
                ("api", self.sources["map"] / "backend"),
                ("web", self.sources["map"] / "frontend"),
                ("proxy", SOURCE / "proxy"),
            ):
                extra = (
                    (
                        "--build-arg",
                        "NEXT_PUBLIC_API_URL=https://localhost:28443/backend",
                    )
                    if name == "web"
                    else ()
                )
                self.receipt["images"][name] = self.build(name, context, extra=extra)[0]
            toolkit, tag = self.build(
                "toolkit",
                self.sources["runner"],
                extra=(
                    "--target",
                    "toolkit",
                    "--build-context",
                    "gate=" + str(self.sources["gate"]),
                ),
            )
            self.receipt["toolkit_image"] = toolkit
            self.receipt["images"]["worker"] = self.build(
                "worker",
                self.sources["runner"],
                file=self.sources["runner"] / "Dockerfile.worker",
                extra=("--build-arg", "RUNNER_BASE_IMAGE=" + tag),
            )[0]
            require(
                self.docker(
                    "image", "inspect", "--format", "{{.Id}}", tag, capture=True
                )
                == toolkit
            )
            selection = {
                "schema": "vardr.nm2-worker-cohort/1",
                "sources": {
                    name: {"path": str(path), "commit": self.pins[name]}
                    for name, path in self.sources.items()
                },
                "images": self.receipt["images"],
                "docker_context": "default",
                "project": self.project,
                "installation": str(self.root / "installation"),
                "private_root": str(self.root / "custody"),
                "https_port": 28443,
                "application_subnet": "172.29.217.0/24",
                "allow_empty_builtin_bridge_id_change": False,
            }
            path = self.root / "cohort.json"
            path.write_text(json.dumps(selection))
            path.chmod(0o600)
            self.receipt["stage"] = "harness"
            self.command(
                [
                    str(python),
                    str(SOURCE / "tests/nm2_worker_acceptance.py"),
                    "--cohort",
                    str(path),
                    "--execute",
                ],
                timeout=900,
            )
            raw = (self.root / "installation/nm2-worker-receipt.json").read_bytes()
            require(len(raw) <= 4 * 1024 * 1024)
            self.receipt.update(public_projection(json.loads(raw), selection))
            self.receipt.update(stage="complete", status="initial_stages_passed")
        finally:
            require(self.receipt["stage"] in STAGES)
            output = self.public / "receipt.json"
            output.write_text(json.dumps(self.receipt, indent=2) + "\n")
            output.chmod(0o600)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print("NM2 hosted execution requires explicit --execute; no commands run")
        return 2
    try:
        Hosted(dict(os.environ)).run()
        print("NM2 hosted initial stages passed; remaining acceptance stays open")
        return 0
    except Exception:
        print("NM2 hosted held; no acceptance claimed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
