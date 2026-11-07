"""Opt-in first and subsequent worker launch in a retained Docker installation."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import shutil
import sys
import time

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
    def __init__(
        self, selection, *, compose, compose_sha256, docker_config,
        completed=False, stop_work=False,
    ):
        super().__init__(
            selection,
            scenario="stop-work" if stop_work else EMPTY_SCENARIO,
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
        self.completed = completed
        self.stop_work = stop_work
        self.protocol = "persistent-v3"
        self.max_attempts = None
        require(not (completed and stop_work), "launch_fixture_mode_conflict")
        scenario = "persistent-launch-empty"
        scope = "first_and_next_empty_launch"
        if completed:
            scenario, scope = "persistent-launch-completed", "completed_then_next_launch"
        elif stop_work:
            scenario, scope = "persistent-launch-stop-work", "stop_work_then_next_launch"
        self.receipt.update(
            schema="vardr.nm2-worker-launch-acceptance/1",
            scenario=scenario, acceptance_scope=scope, nm2_exit_status="incomplete",
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

    def await_completed_job(self, admission, case):
        engagement, job, _, _ = case
        deadline = time.monotonic() + 45
        while True:
            observed = self.inventory(engagement, job)
            if observed["job_status"] == "done":
                break
            require(
                observed["job_status"] in {"pending", "running"}
                and time.monotonic() < deadline,
                "launch_completed_job_not_done",
            )
            time.sleep(0.2)
        self.persistent_idle(admission, 1)
        self.verify_persistent_local(
            self.persistent_metadata(admission, 1), admission, 1
        )

    def reconcile_original(self, admission, retired):
        binding = {
            key: admission[key]
            for key in ("runner_id", "runtime_id", "runtime_sha256", "admission_sha256")
        }
        selectors = []
        for key, value in binding.items():
            selectors.extend(("--" + key.replace("_", "-"), value))
        self.receipt["stage"] = "launch_reconcile_original"
        reconciled = json.loads(
            self.helper(
                "worker-reconcile",
                "--journal",
                "/home/runner/.vardrmap/runner-journal.sqlite3",
                "--identity",
                "/home/runner/.vardrmap/runner-identity.json",
                *selectors,
            )
        )
        require(
            reconciled["schema"] == "vardr.worker-reconciliation/1"
            and reconciled["status"] in {"reconciled", "already_retired"}
            and reconciled["complete"] is True
            and reconciled["binding"] == binding
            and type(reconciled["remaining_local_holds"]) is int
            and reconciled["remaining_local_holds"] == 0
            and reconciled["retirement_receipt_sha256"] == retired["receipt_sha256"],
            "launch_completed_reconciliation_not_observed",
        )
        self.receipt["stage"] = "launch_audit_retired"
        audit = self.worker_state(admission)
        require(
            audit["schema"] == "vardr.worker-state-audit/1"
            and audit["status"] == "retired"
            and audit["complete"] is True
            and audit["binding"] == binding
            and type(audit["global_holds"]) is int
            and audit["global_holds"] == 0
            and audit["retirement_receipt_sha256"] == retired["receipt_sha256"]
            and audit["counts"]["attempts"] == 1,
            "launch_completed_audit_not_observed",
        )
        return audit

    def completed_reconciliation(self, physical, admission, retired, case):
        engagement, job, stored, before = case
        requests = self.traffic()
        require(len(requests) == 5, "launch_completed_traffic_changed")
        _, measured = self.verify_fixed(
            engagement, job, stored, physical, before, requests,
            self.inventory(engagement, job), persistent=True,
        )
        audit = self.reconcile_original(admission, retired)
        self.receipt["completed_job"] = {
            "job_id": job,
            "retirement_sha256": retired["receipt_sha256"],
            "audit_sha256": digest(canonical(audit)),
            "target_requests": len(requests),
            "fixed_evidence_sha256": measured["evidence_sha256"],
        }

    def cancelled_reconciliation(self, physical, admission, retired, case, action, after):
        import worker_host_persistent as persistent

        engagement, job, stored, _ = case
        requests = after["requests"]
        require(requests == action["requests"] and len(requests) == 3,
                "launch_stop_work_traffic_changed")
        stop_elapsed = after["observed_monotonic_ns"] - requests[-1]["received_monotonic_ns"]
        require(0 < stop_elapsed < 15_000_000_000, "launch_stop_work_exit_not_observed")
        inventory = self.inventory(engagement, job)
        require(
            inventory["job_status"] == "failed"
            and len(inventory["contracts"]) == len(inventory["runtimes"]) == 1
            and (len(inventory["results"]), len(inventory["stops"])) in {(1, 0), (0, 1)}
            and inventory["targets_spent"] == 1 and inventory["duration_allocated"] == 30
            and inventory["execution"]["capacity_reserved"] is False
            and inventory["execution"]["target_charge"] == 1
            and inventory["execution"]["duration_seconds"] == 30,
            "launch_stop_work_capacity_not_released",
        )
        runtime = inventory["runtimes"][0]
        require(
            runtime["id"] == physical["runtime_id"]
            and runtime["runtime_sha256"] == physical["runtime_sha256"]
            and runtime["identity"] == physical["identity"]
            and runtime["mode"] == "persistent" and runtime["retired"] is True
            and runtime["new_work_disabled"] is True
            and runtime["last_sequence"] == "1" and len(runtime["attempts"]) == 1,
            "launch_stop_work_runtime_not_retired",
        )
        record = {
            "runtime_id": admission["runtime_id"],
            "registration": {k: v for k, v in admission.items() if k not in
                             {"schema", "runtime_id", "runtime_sha256", "admission_sha256"}},
        }
        persistent.retirement(record, retired)
        binding = retired["binding"]
        terminal = retired["attempt_receipt"]
        attempt = runtime["attempts"][0]
        require(
            attempt["binding"] == binding and attempt["job_id"] == job
            and attempt["runtime_sequence"] == "1"
            and attempt["runtime_id"] == runtime["id"]
            and attempt["confirmed_at"] is not None
            and attempt["release_receipt"] is None and attempt["released_at"] is None
            and attempt["native_done_sha256"] is None
            and terminal["capacity_reserved"] is False
            and inventory["execution"]["state"] == terminal["outcome"],
            "launch_stop_work_attempt_reused",
        )
        local = self.local_metadata(action["run_id"], engagement, job)
        require(
            local["consumption_sent"] == local["consumption_acknowledged"] == 1
            and local["local_stop_requested"] is False,
            "launch_stop_work_original_run_not_preserved",
        )
        if inventory["results"]:
            require(
                local.get("failure_reason") == "remote_stop_requested",
                "launch_stop_work_terminal_not_proven",
            )
            self.verify_failed_partial(engagement, job, stored, binding, terminal, inventory, local)
        else:
            require(
                terminal.get("cause") == "remote_stop_requested"
                and inventory["stops"][0] == {
                    "contract_id": binding["contract_id"],
                    "receipt_sha256": terminal["receipt_sha256"],
                    "outcome": "cancelled",
                    "cause": "remote_stop_requested",
                },
                "launch_stop_work_terminal_not_proven",
            )
        audit = self.reconcile_original(admission, retired)
        require(self.timed_traffic()["requests"] == requests, "launch_stop_work_traffic_changed")
        self.receipt["cancelled_job"] = {
            "job_id": job, "retirement_sha256": retired["receipt_sha256"],
            "audit_sha256": digest(canonical(audit)), "target_requests": len(requests),
            "terminal_sha256": digest(canonical(terminal)),
            "exit_observed_within_ns": stop_elapsed,
        }

    def launch_and_retire(
        self, config, signing, binding, ordinal, predecessor, *, case=None
    ):
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
        if predecessor is not None and (self.completed or self.stop_work):
            proof = self.receipt["cancelled_job" if self.stop_work else "completed_job"]
            require(
                row["predecessors"][0]["original_local_audit_sha256"]
                == proof["audit_sha256"],
                "launch_completed_audit_changed",
            )
        cancelling = self.stop_work and case is not None
        if case is None:
            self.persistent_idle(admission, 0)
            before = self.verify_empty_worker_state(
                self.empty_worker_state(admission), admission
            )
        elif cancelling:
            self.receipt["stage"] = "launch_stop_work_observe"
            action = self.cancellation_action(*case[:3])
        else:
            self.await_completed_job(admission, case)
        self.receipt["stage"] = f"launch_stop_{ordinal}"
        stopped = None if cancelling else self.worker_action("stop", selected)
        exit_proof = observer.observe_exit(identity)
        if cancelling:
            after = self.timed_traffic()
            require(exit_proof.exit_code != 0, "launch_stop_work_exit_not_observed")
        else:
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
            "operator_stop_state": "not_requested" if cancelling else stopped["state"],
        }
        retired = self.report_exit(physical)
        reconciled = self.worker_action("reconcile", selected, timeout=120)
        require(
            retired["last_sequence"] == ("0" if case is None else "1")
            and retired["runtime_sequence"] == ("1" if cancelling else None)
            and retired["retired"] is True
            and (retired["attempt_receipt"] is not None) == cancelling
            and reconciled["state"] == "terminal_observed"
            and reconciled["receipt"]["retirement"] == retired,
            "launch_retirement_not_observed",
        )
        if case is None:
            require(
                before
                == self.verify_empty_worker_state(
                    self.empty_worker_state(admission), admission
                ),
                "launch_empty_retirement_not_observed",
            )
        elif cancelling:
            self.cancelled_reconciliation(physical, admission, retired, case, action, after)
        else:
            self.completed_reconciliation(physical, admission, retired, case)
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

    def cancelled_http(self):
        self.launch_pair()

    def persistent_empty_stop(self):
        self.launch_pair()

    def launch_pair(self):
        from worker_runtime import LocalDocker, WorkerLayout

        self.receipt["stage"] = "launch_prepare"
        require(self.traffic() == [], "launch_unexpected_target_traffic")
        if not self.stop_work:
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
        case = None
        if self.completed or self.stop_work:
            name = "launch-stop-work" if self.stop_work else "launch-completed"
            engagement, authorization, job, stored = self.new_job(name, marker=True)
            require(
                self.approve(name, engagement, authorization, job, stored)
                == binding,
                "launch_completed_enrollment_changed",
            )
            before = self.inventory(engagement, job)
            require(
                before["job_status"] == "pending"
                and before["execution"] is None
                and before["contracts"] == []
                and before["targets_spent"] == before["duration_allocated"] == 0
                and self.traffic() == [],
                "launch_completed_job_not_pending",
            )
            case = engagement, job, stored, before
        first, old_observer, old_exit = self.launch_and_retire(
            config, signing, binding, 1, None, case=case
        )
        baseline = self.traffic()
        second, _, _ = self.launch_and_retire(config, signing, binding, 2, first)
        old_observer.confirm_exit(old_exit)
        final = observer.capture_project_containers(self.project)
        require(
            final["all_worker_ids"]
            == sorted([first["container_id"], second["container_id"]])
            and final["core"] == initial["core"]
            and first["runtime_id"] != second["runtime_id"]
            and first["runner_state_sha256"] == second["runner_state_sha256"]
            and self.traffic() == baseline,
            "launch_preservation_or_traffic_not_observed",
        )
        if not (self.completed or self.stop_work):
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
    workload = parser.add_mutually_exclusive_group()
    workload.add_argument("--completed-job", action="store_true")
    workload.add_argument("--stop-work", action="store_true")
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
            completed=args.completed_job,
            stop_work=args.stop_work,
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
