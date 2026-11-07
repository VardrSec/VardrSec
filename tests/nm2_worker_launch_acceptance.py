"""Opt-in same-installation first and next zero-job worker launch on Docker."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import shutil
import sys

from nm2_worker_acceptance import (
    EMPTY_SCENARIO,
    Fixture,
    canonical,
    command,
    digest,
    manifest,
    publish,
    require,
    worker_cli_command,
)


class LaunchFixture(Fixture):
    def __init__(self, selection, *, compose, compose_sha256, docker_config):
        super().__init__(
            selection,
            scenario=EMPTY_SCENARIO,
            database_revision="0041persistentruntime",
        )
        self.compose_executable = compose.resolve(strict=True)
        self.docker_executable = Path(shutil.which("docker")).resolve(strict=True)
        self.docker_config = docker_config.resolve(strict=True)
        require(
            compose.is_absolute()
            and docker_config.is_absolute()
            and self.docker_config.is_dir()
            and digest(self.compose_executable.read_bytes()) == compose_sha256,
            "launch_client_pin_refused",
        )
        self.compose_sha256 = compose_sha256
        self.receipt.update(
            schema="vardr.nm2-worker-launch-acceptance/1",
            scenario="persistent-launch-empty",
            acceptance_scope="first_and_next_empty_launch",
        )

    def launch_config(self, observer, core):
        self.public_root = self.install / "worker-admissions"
        self.public_root.mkdir(mode=0o755)
        signing = self.install / "launch-signing-trust.json"
        publish(signing, canonical(self.trust), mode=0o444)
        override = self.private / "launch-override.json"
        raw = canonical(
            {
                "networks": {
                    "runner": {"external": True, "name": self.project + "_runner"}
                },
                "volumes": {
                    "runner-state": {
                        "external": True,
                        "name": self.project + "_runner-state",
                    }
                },
            }
        )
        publish(override, raw)
        empty = self.private / "launch-empty.env"
        publish(empty, b"")
        names = ["FIXTURE_OWNER_TOKEN", "FIXTURE_PEER_TOKEN"]
        port = self.m["https_port"]
        endpoint, daemon = observer._daemon_binding()
        source = {name: item["commit"] for name, item in self.m["sources"].items()}
        tree = (
            command(["git", "-C", str(self.source), "rev-parse", "HEAD^{tree}"])
            .decode()
            .strip()
        )
        core_images = {row["service"]: row["image_id"] for row in core["core"]}
        config = self.private / "launch-config.json"
        publish(
            config,
            canonical(
                {
                    "docker": str(self.docker_executable),
                    "docker_sha256": digest(self.docker_executable.read_bytes()),
                    "compose": str(self.compose_executable),
                    "compose_sha256": self.compose_sha256,
                    "docker_config": str(self.docker_config),
                    "local_endpoint": endpoint,
                    "daemon_id": daemon,
                    "override": str(override),
                    "empty_env": str(empty),
                    "credential_file": str(self.private / "worker.env"),
                    "credential_names": names,
                    "https_port": port,
                    "core_images": core_images,
                    "source": {
                        "distribution_commit": source["distribution"],
                        "distribution_tree": tree,
                        "runner_commit": source["runner"],
                        "map_commit": source["map"],
                        "gate_commit": source["gate"],
                        "runner_image": self.images["worker"],
                        "compose_version": "5.6.1",
                        "compose_executable_sha256": self.compose_sha256,
                        "unresolved_model_sha256": digest(
                            (self.install / "compose.worker.json")
                            .read_bytes()
                            .replace(b"\r\n", b"\n")
                        ),
                        "closed_override_sha256": digest(raw),
                        "environment_contract_sha256": digest(
                            canonical({"credential_names": names, "https_port": port})
                        ),
                        "core_image_set_sha256": digest(canonical(core_images)),
                    },
                }
            ),
        )
        return config, signing

    def launch_and_retire(self, config, signing, binding, ordinal, predecessor):
        from worker_runtime import LocalDocker, RuntimeIdentity, WorkerLayout

        runner, enrollment = binding
        self.receipt["stage"] = f"launch_{ordinal}"
        enabled = json.loads(
            worker_cli_command(
                [
                    sys.executable,
                    str(self.install / "vardrsec.py"),
                    "worker",
                    "launch",
                    "--api-url",
                    self.url + "/backend",
                    "--ca",
                    str(self.install / "trust" / "root.crt"),
                    "--private-root",
                    str(self.private),
                    "--context",
                    self.m["docker_context"],
                    "--image-id",
                    self.images["worker"],
                    "--project",
                    self.project,
                    "--state-volume",
                    self.project + "_runner-state",
                    "--runner-network",
                    self.project + "_runner",
                    "--enrollment-id",
                    enrollment,
                    "--runner-id",
                    runner,
                    "--origin",
                    self.issuer_origin,
                    "--public-trust",
                    str(signing),
                    "--admission-root",
                    str(self.public_root),
                    "--launch-config",
                    str(config),
                    "--username",
                    "operator",
                    "--password-stdin",
                ],
                cwd=self.install,
                env=self.environment,
                stdin=self.password + "\n",
                timeout=240,
            )
        )
        require(enabled["state"] == "enabled", "launch_enable_not_observed")
        selected = enabled["runtime_id"]
        identity = RuntimeIdentity(**enabled["identity"])
        public = self.public_root / selected
        ready = f"{self.project}_worker-ready-{selected}"
        admission = json.loads((public / "admission.json").read_bytes())
        require(
            admission["schema"] == "vardr.worker-admission/3"
            and admission["runtime_id"] == selected
            and admission["runner_id"] == runner
            and admission["runtime_sha256"] == enabled["runtime_sha256"]
            and admission["identity"] == asdict(identity),
            "launch_admission_not_bound",
        )
        observer = LocalDocker(
            self.m["docker_context"],
            WorkerLayout(
                str(self.install / "trust"),
                str(public),
                self.project + "_runner-state",
                ready,
            ),
            protocol="persistent-v3",
        )
        intents = []
        for path in (self.private / "worker-host").glob("*.intent.json"):
            envelope = json.loads(path.read_bytes())
            if envelope["payload"]["future_runtime_id"] == selected:
                intents.append(envelope)
        require(len(intents) == 1, "launch_intent_not_observed")
        wrapped = intents[0]
        row = wrapped["payload"]
        require(
            wrapped["schema"]
            == f"vardr.worker-lifecycle-intent/{4 if ordinal == 1 else 3}"
            and row["disposition"] == "enabled"
            and all(row["effects"].values())
            and row["resources"]["expected_ordinal"] == ordinal
            and row["observations"]["running"] == asdict(identity)
            and row["observations"]["created"]["container_id"] == identity.container_id
            and row["resources"]["readiness_volume"] == ready
            and [item["container_id"] for item in row["predecessors"]]
            == ([] if predecessor is None else [predecessor["container_id"]]),
            "launch_durable_chain_not_observed",
        )
        self.persistent_idle(admission, 0)
        before = self.verify_empty_worker_state(
            self.empty_worker_state(admission), admission
        )
        self.receipt["stage"] = f"launch_stop_{ordinal}"
        stopped = self.worker_action("stop", selected)
        exit_proof = observer.observe_exit(identity)
        require(
            stopped["state"] == "stopped_observed"
            and stopped["identity"] == asdict(identity)
            and stopped["exit_code"] == exit_proof.exit_code
            and stopped["finished_at"] == exit_proof.finished_at
            and stopped["new_work_disable_state"] == "acknowledged",
            "launch_exact_exit_not_observed",
        )
        physical = {
            "identity": asdict(identity),
            "runtime_id": selected,
            "runtime_sha256": admission["runtime_sha256"],
            "admission_sha256": admission["admission_sha256"],
            "finished_at": exit_proof.finished_at,
            "exit_code": exit_proof.exit_code,
            "operator_stop_state": stopped["state"],
        }
        retired = self.report_exit(physical)
        reconciled = self.worker_action("reconcile", selected, timeout=120)
        after = self.verify_empty_worker_state(
            self.empty_worker_state(admission), admission
        )
        require(
            retired["last_sequence"] == "0"
            and retired["runtime_sequence"] is None
            and retired["retired"] is True
            and retired["attempt_receipt"] is None
            and reconciled["state"] == "terminal_observed"
            and reconciled["receipt"]["retirement"] == retired
            and before == after,
            "launch_empty_retirement_not_observed",
        )
        return (
            {
                "ordinal": ordinal,
                "runtime_id": selected,
                "container_id": identity.container_id,
                "started_at": identity.started_at,
                "finished_at": exit_proof.finished_at,
                "intent_sha256": digest(canonical(row)),
                "retirement_sha256": retired["receipt_sha256"],
                "predecessor_cids": [
                    item["container_id"] for item in row["predecessors"]
                ],
                "bootstrap_audit_sha256": row.get("bootstrap_audit_sha256"),
                "runner_state_sha256": row["resources"]["runner_state"][
                    "metadata_sha256"
                ],
            },
            observer,
            exit_proof,
        )

    def persistent_empty_stop(self):
        from worker_runtime import LocalDocker, WorkerLayout

        self.receipt["stage"] = "launch_prepare"
        require(self.traffic() == [], "launch_unexpected_target_traffic")
        self.empty_engagements()
        self.helper("init", "--non-interactive", "--no-install-tools")
        binding = self.enroll_runner()
        self.empty_audit_volumes = []
        observer = LocalDocker(
            self.m["docker_context"],
            WorkerLayout(
                str(self.install / "trust"),
                str(self.install / "worker-admissions"),
                self.project + "_runner-state",
                self.ready_volume,
            ),
            protocol="persistent-v3",
        )
        initial = observer.capture_project_containers(self.project)
        require(initial["all_worker_ids"] == [], "launch_preexisting_worker")
        config, signing = self.launch_config(observer, initial)
        first, old_observer, old_exit = self.launch_and_retire(
            config, signing, binding, 1, None
        )
        second, _, _ = self.launch_and_retire(config, signing, binding, 2, first)
        old_observer.confirm_exit(old_exit)
        final = observer.capture_project_containers(self.project)
        require(
            final["all_worker_ids"]
            == sorted([first["container_id"], second["container_id"]])
            and final["core"] == initial["core"]
            and first["runtime_id"] != second["runtime_id"]
            and first["runner_state_sha256"] == second["runner_state_sha256"]
            and self.traffic() == [],
            "launch_preservation_or_traffic_not_observed",
        )
        self.empty_engagements()
        self.receipt["launch_pair"] = [first, second]
        self.receipt["status"] = "selected_launch_slice_passed"
        self.receipt["stage"] = "selected_launch_complete"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", required=True, type=Path)
    parser.add_argument("--compose-executable", required=True, type=Path)
    parser.add_argument("--compose-sha256", required=True)
    parser.add_argument("--docker-config", required=True, type=Path)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print("Launch acceptance requires explicit --execute.")
        return 2
    try:
        fixture = LaunchFixture(
            manifest(args.cohort),
            compose=args.compose_executable,
            compose_sha256=args.compose_sha256,
            docker_config=args.docker_config,
        )
        fixture.run()
        return 0 if fixture.receipt["status"] == "selected_launch_slice_passed" else 1
    except Exception:
        print(
            "Launch fixture held. Retain the owned installation and resources.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
