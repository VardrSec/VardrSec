"""Opt-in, target-free bootstrap configuration checks; default makes no Docker calls.

Only an unprivileged initial user and a missing bootstrap SETPCAP are tested.
These ordinary misconfigurations are not adversarial containment acceptance.
"""

import argparse
from dataclasses import dataclass
import io
import importlib
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
# Also work under python -I, which omits the script directory from sys.path.
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
shared = importlib.import_module("nm2_worker_acceptance")
docker_timestamp = importlib.import_module("worker_runtime")._timestamp
OWNER = "/usr/local/bin/vardr-worker-owner"
LABEL = "io.vardrsec.nm2-bootstrap"
CASES = {
    "unprivileged_user": ("10001:10001", []),
    "missing_setpcap": ("0:0", ["SETUID", "SETGID"]),
}
TMPFS = "rw,noexec,nosuid,nodev,size=67108864,uid=10001,gid=10001,mode=0700"
IMAGE_FORMAT = '{"id":{{json .Id}},"entrypoint":{{json .Config.Entrypoint}},"cmd":{{json (index .Config "Cmd")}},"volumes":{{json (index .Config "Volumes")}},"env":{{json .Config.Env}}}'
CONTAINER_FORMAT = '{"id":{{json .Id}},"image":{{json .Image}},"name":{{json .Name}},"labels":{{json .Config.Labels}},"entrypoint":{{json .Config.Entrypoint}},"cmd":{{json (index .Config "Cmd")}},"health":{{json (index .Config "Healthcheck")}},"user":{{json .Config.User}},"state":{{json .State}},"restarts":{{json .RestartCount}},"host":{"network":{{json .HostConfig.NetworkMode}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"privileged":{{json .HostConfig.Privileged}},"init":{{json .HostConfig.Init}},"restart":{{json .HostConfig.RestartPolicy.Name}},"caps":{{json .HostConfig.CapAdd}},"drop":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},"memory":{{json .HostConfig.Memory}},"pids":{{json .HostConfig.PidsLimit}},"cpus":{{json .HostConfig.NanoCpus}},"ipc":{{json .HostConfig.IpcMode}},"cgroup":{{json .HostConfig.CgroupnsMode}},"tmpfs":{{json .HostConfig.Tmpfs}}},"mounts":{{json .Mounts}}}'


def require(value, reason):
    shared.require(value, "bootstrap_" + reason)


def validate(args):
    require(
        re.fullmatch(r"sha256:[0-9a-f]{64}", args.image or ""),
        "immutable_image_required",
    )
    require(
        re.fullmatch(r"[0-9a-f]{64}", args.owner_sha256 or ""), "owner_hash_required"
    )
    require(
        re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", args.docker_context or ""),
        "context_required",
    )
    require(
        re.fullmatch(r"vardrsec-nm2-[a-z0-9]{8,24}", args.project or ""),
        "fresh_project_required",
    )
    build = args.build_receipt
    require(
        build.is_absolute() and build.is_file() and not build.is_symlink(),
        "build_receipt_required",
    )
    raw = build.read_bytes()
    require(len(raw) <= 1024 * 1024, "build_receipt_bound")
    receipt = json.loads(raw)
    require(
        receipt.get("status") == "passed_frozen_build_dependency_probe"
        and receipt.get("image") == args.image,
        "reviewed_build_required",
    )
    for name, size in (
        ("source_commit", 40),
        ("source_tree", 40),
        ("source_manifest_sha256", 64),
    ):
        require(
            re.fullmatch("[0-9a-f]{" + str(size) + "}", receipt.get(name, "")),
            "build_identity_required",
        )
    owner_source = receipt.get("source_hashes", {}).get("container/worker_owner.c", "")
    require(re.fullmatch(r"[0-9a-f]{64}", owner_source), "owner_source_required")
    output = args.output
    require(output.is_absolute() and not os.path.lexists(output), "new_output_required")
    require(
        output.parent.is_dir() and output.parent.resolve(strict=True) == output.parent,
        "output_parent_required",
    )
    require(
        ROOT != output and ROOT not in output.parents, "output_outside_source_required"
    )
    return {
        "image": args.image,
        "context": args.docker_context,
        "project": args.project,
        "output": output,
        "admit_bridge": args.allow_empty_builtin_bridge_id_change,
        "build_receipt_sha256": shared.digest(raw),
        "owner_binary_sha256": args.owner_sha256,
        "owner_source_sha256": owner_source,
        **{
            name: receipt[name]
            for name in ("source_commit", "source_tree", "source_manifest_sha256")
        },
    }


def empty_readiness(archive):
    """A successful copy of an empty directory proves absence; failed cp does not."""
    require(0 < len(archive) <= 16384, "readiness_archive_bound")
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source:
            members = source.getmembers()
            require(len(members) == 1, "readiness_not_empty")
            member = members[0]
            require(
                member.name.rstrip("/") == "vardr-worker-ready"
                and member.isdir()
                and member.size == 0
                and member.uid == member.gid == 10000
                and member.mode == 0o700,
                "readiness_metadata_changed",
            )
    except (tarfile.TarError, OSError):
        raise shared.AcceptanceRefused("bootstrap_readiness_copy_refused") from None
    return shared.digest(archive)


def owner_binary(archive, expected):
    require(0 < len(archive) <= 4 * 1024 * 1024, "binary_archive_bound")
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source:
            members = source.getmembers()
            require(len(members) == 1, "binary_archive_changed")
            member = members[0]
            require(
                member.name == "vardr-worker-owner"
                and member.isfile()
                and 0 < member.size <= 3 * 1024 * 1024,
                "binary_archive_changed",
            )
            with source.extractfile(member) as stream:
                require(
                    shared.digest(stream.read()) == expected, "owner_binary_changed"
                )
    except (tarfile.TarError, OSError):
        raise shared.AcceptanceRefused("bootstrap_binary_copy_refused") from None


@dataclass
class Bootstrap:
    selection: dict

    def __post_init__(self):
        self.project, self.image = self.selection["project"], self.selection["image"]
        self.output = self.selection["output"]
        self.environment = {
            key: value
            for key, value in os.environ.items()
            if key.upper()
            in {
                "PATH",
                "SYSTEMROOT",
                "WINDIR",
                "SYSTEMDRIVE",
                "COMSPEC",
                "PATHEXT",
                "HOME",
                "USERPROFILE",
                "APPDATA",
                "LOCALAPPDATA",
                "TEMP",
                "TMP",
            }
        }
        self.deadline = time.monotonic() + 90
        self.created = {}
        self.receipt = {
            "schema": "vardr.nm2-worker-bootstrap/1",
            "status": "held",
            "project": self.project,
            "image": self.image,
            "retained": True,
            "platform": sys.platform,
            "scope": "Two target-free configuration refusals only; no authorization, admission, tools or adversarial containment acceptance",
            "cases": {name: {"status": "not_run"} for name in CASES},
            "inventory_checks": [],
            **{
                key: self.selection[key]
                for key in (
                    "build_receipt_sha256",
                    "source_commit",
                    "source_tree",
                    "source_manifest_sha256",
                    "owner_binary_sha256",
                    "owner_source_sha256",
                )
            },
        }

    def docker(self, *args, timeout=15):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "time_bound")
        return shared.command(
            ["docker", "--context", self.selection["context"], *args],
            env=self.environment,
            timeout=min(timeout, remaining),
        )

    snapshot = shared.Fixture.snapshot

    def engine(self):
        endpoint = json.loads(
            self.docker(
                "context",
                "inspect",
                self.selection["context"],
                "--format",
                "{{json .Endpoints.docker.Host}}",
            )
        )
        require(
            type(endpoint) is str and endpoint.startswith(("unix:///", "npipe:////")),
            "local_daemon_required",
        )
        daemon = json.loads(
            self.docker("info", "--format", '{"id":{{json .ID}},"os":{{json .OSType}}}')
        )
        require(
            daemon["os"] == "linux"
            and type(daemon["id"]) is str
            and 0 < len(daemon["id"]) <= 128,
            "linux_daemon_required",
        )
        return daemon["id"]

    def inspect(self, container_id, case):
        value = json.loads(
            self.docker(
                "container", "inspect", "--format", CONTAINER_FORMAT, container_id
            )
        )
        user, caps = CASES[case]
        require(
            value["id"] == container_id
            and value["image"] == self.image
            and value["name"] == "/" + self.project + "-" + case.replace("_", "-"),
            "container_identity_changed",
        )
        require(
            value["labels"].get("com.docker.compose.project") == self.project
            and value["labels"].get(LABEL) == case,
            "container_owner_changed",
        )
        require(
            value["entrypoint"] == [OWNER]
            and value["cmd"] in (None, [])
            and value["health"] == {"Test": ["NONE"]}
            and value["user"] == user
            and value["restarts"] == 0,
            "container_command_changed",
        )
        host = value["host"]
        require(
            type(host["caps"]) is list or host["caps"] is None,
            "container_profile_changed",
        )
        require(
            {cap.removeprefix("CAP_") for cap in host["caps"] or []} == set(caps),
            "container_profile_changed",
        )
        host = {key: entry for key, entry in host.items() if key != "caps"}
        require(
            host
            == {
                "network": "none",
                "readonly": True,
                "privileged": False,
                "init": False,
                "restart": "no",
                "drop": ["ALL"],
                "security": ["no-new-privileges:true"],
                "memory": 536870912,
                "pids": 64,
                "cpus": 1000000000,
                "ipc": "private",
                "cgroup": "private",
                "tmpfs": {"/tmp": TMPFS},
            },
            "container_profile_changed",
        )
        require(
            all(
                mount.get("Type") == "tmpfs"
                and mount.get("Destination") == "/tmp"
                and mount.get("RW") is True
                for mount in value["mounts"]
            )
            and len(value["mounts"]) <= 1,
            "unexpected_data_mount",
        )
        return value

    def guard(self, before, suffix):
        require(self.engine() == self.receipt["daemon_id"], "daemon_changed")
        after = self.snapshot()
        admitted = shared.unchanged_inventory(
            before, after, self.project, admit_bridge=self.selection["admit_bridge"]
        )
        require(
            set(after["containers"]) - set(before["containers"]) == set(self.created),
            "unexpected_container",
        )
        require(
            all(
                all(
                    after["containers"][key]["state"][flag] is False
                    for flag in ("running", "paused", "restarting", "dead")
                )
                and after["containers"][key]["state"]["exit_code"] == 125
                for key in self.created
            ),
            "retained_container_not_stopped",
        )
        require(
            after["images"] == before["images"]
            and after["volumes"] == before["volumes"],
            "unexpected_image_or_volume",
        )
        require(
            set(after["networks"]) - set(before["networks"])
            == {item["after"] for item in admitted},
            "unexpected_network",
        )
        shared.publish(self.output / (suffix + ".json"), shared.canonical(after))
        self.receipt["inventory_checks"].append(
            {
                "checkpoint": suffix,
                "sha256": shared.digest(shared.canonical(after)),
                "admitted_diffs": admitted,
            }
        )
        return after

    def one(self, case):
        user, caps = CASES[case]
        require(self.engine() == self.receipt["daemon_id"], "daemon_changed")
        self.receipt["stage"] = case + "_create"
        arguments = [
            "container",
            "create",
            "--name",
            self.project + "-" + case.replace("_", "-"),
            "--label",
            "com.docker.compose.project=" + self.project,
            "--label",
            LABEL + "=" + case,
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--user",
            user,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--init=false",
            "--no-healthcheck",
            "--restart",
            "no",
            "--memory",
            "512m",
            "--pids-limit",
            "64",
            "--cpus",
            "1",
            "--ipc",
            "private",
            "--cgroupns",
            "private",
            "--tmpfs",
            "/tmp:" + TMPFS,
        ]
        for cap in caps:
            arguments.extend(("--cap-add", cap))
        arguments.append(self.image)  # Image's reviewed fixed entrypoint, no argv.
        container_id = self.docker(*arguments).decode("ascii").strip()
        require(re.fullmatch(r"[0-9a-f]{64}", container_id), "container_id_required")
        self.created[container_id] = case
        require(
            self.inspect(container_id, case)["state"]["Status"] == "created",
            "unexpected_created_state",
        )
        entered = time.monotonic()
        self.receipt["stage"] = case + "_start_wait"
        self.docker("container", "start", container_id)
        require(
            self.docker("container", "wait", container_id, timeout=10).strip()
            == b"125",
            "unexpected_exit",
        )
        value = self.inspect(container_id, case)
        state = value["state"]
        require(
            state["Status"] == "exited"
            and all(
                state[name] is False
                for name in ("Running", "Paused", "Restarting", "Dead", "OOMKilled")
            )
            and type(state["ExitCode"]) is int
            and state["ExitCode"] == 125
            and state["Pid"] == 0
            and state["Error"] == "",
            "exit_not_proven",
        )
        require(
            docker_timestamp(state["FinishedAt"])
            > docker_timestamp(state["StartedAt"]),
            "exit_identity_required",
        )
        self.receipt["stage"] = case + "_copies"
        archive = self.docker(
            "container", "cp", container_id + ":/run/vardr-worker-ready", "-"
        )
        owner_binary(
            self.docker("container", "cp", container_id + ":" + OWNER, "-"),
            self.selection["owner_binary_sha256"],
        )
        self.receipt["cases"][case] = {
            "status": "passed",
            "container_id": container_id,
            "exit_code": 125,
            "started_at": state["StartedAt"],
            "finished_at": state["FinishedAt"],
            "elapsed_seconds": time.monotonic() - entered,
            "startup_wait_bound_seconds": 10,
            "readiness_absent": True,
            "readiness_archive_sha256": empty_readiness(archive),
            "namespace_init_pid": 0,
            "descendant_absence": "not_independently_observed",
            "basis": "Reviewed source guard refuses before fork; no descendant-count inference from an exited PID",
        }

    def run(self):
        shared.private_directory(self.output)
        before = None
        try:
            self.receipt["stage"] = "image_preflight"
            self.receipt["daemon_id"] = self.engine()
            image = json.loads(
                self.docker("image", "inspect", "--format", IMAGE_FORMAT, self.image)
            )
            require(
                image["id"] == self.image
                and image["entrypoint"] == [OWNER]
                and image["cmd"] in (None, [])
                and not image["volumes"],
                "image_profile_changed",
            )
            require(
                all(
                    not entry.partition("=")[0]
                    .upper()
                    .startswith(("VARDRMAP_", "VARDRRUNNER_WORKER_", "FIXTURE_"))
                    for entry in image["env"] or []
                ),
                "image_auth_configuration_refused",
            )
            before = self.snapshot()
            require(self.image in before["images"], "reviewed_image_missing")
            require(
                not any(
                    row.get("labels", {}).get("com.docker.compose.project")
                    == self.project
                    for kind in ("containers", "networks", "volumes")
                    for row in before[kind].values()
                ),
                "project_exists",
            )
            for case in CASES:
                name = self.project + "-" + case.replace("_", "-")
                require(
                    not self.docker(
                        "container",
                        "ls",
                        "-aq",
                        "--no-trunc",
                        "--filter",
                        "name=^/" + name + "$",
                    ).strip(),
                    "container_name_exists",
                )
            shared.publish(self.output / "before.json", shared.canonical(before))
            self.receipt["before_sha256"] = shared.digest(shared.canonical(before))
            self.receipt["inventory_checks"] = []
            for case in CASES:
                self.one(case)
                self.guard(before, "after-" + case)
            self.receipt["status"] = "passed_configuration_refusals"
            self.receipt["stage"] = "complete"
        except Exception as error:
            reason = str(error) if isinstance(error, shared.AcceptanceRefused) else ""
            self.receipt["status"], self.receipt["reason"] = (
                "held",
                reason
                if re.fullmatch(r"bootstrap_[a-z_]+", reason)
                else "bootstrap_verification_refused",
            )
        finally:
            for container_id, case in self.created.items():
                try:
                    require(
                        self.engine() == self.receipt["daemon_id"], "daemon_changed"
                    )
                    if self.inspect(container_id, case)["state"]["Running"]:
                        self.docker("container", "stop", "-t", "1", container_id)
                        self.receipt["status"], self.receipt["reason"] = (
                            "held",
                            "bootstrap_cleanup_stop_required",
                        )
                except Exception:
                    self.receipt["status"], self.receipt["reason"] = (
                        "held",
                        "bootstrap_cleanup_unconfirmed",
                    )
            if before is not None:
                try:
                    self.guard(before, "after-final")
                except Exception:
                    self.receipt["status"], self.receipt["reason"] = (
                        "held",
                        "bootstrap_final_inventory_refused",
                    )
            shared.publish(self.output / "receipt.json", shared.canonical(self.receipt))
        return self.receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--owner-sha256", required=True)
    parser.add_argument("--docker-context", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-empty-builtin-bridge-id-change", action="store_true")
    parser.add_argument("--execute", action="store_true")
    try:
        args = parser.parse_args(argv)
        selection = validate(args)
        if not args.execute:
            print(
                json.dumps(
                    {
                        "schema": "vardr.nm2-worker-bootstrap-validation/1",
                        "status": "inputs_validated_runtime_not_run",
                        "docker_calls": 0,
                        "cases": list(CASES),
                    }
                )
            )
            return 0
        result = Bootstrap(selection).run()
        print(
            json.dumps(
                {
                    "schema": result["schema"],
                    "status": result["status"],
                    "cases": {
                        name: value["status"] for name, value in result["cases"].items()
                    },
                }
            )
        )
        return 0 if result["status"] == "passed_configuration_refusals" else 1
    except Exception:
        print("bootstrap_inputs_refused", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
