"""Opt-in first and subsequent worker launch in a retained Docker installation."""

import argparse
from calendar import timegm
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

def stop_exit_elapsed_ns(request, after, finished_at):
    from worker_runtime import _timestamp

    second, fraction = _timestamp(finished_at)
    finished_ns = timegm(second.utctimetuple()) * 1_000_000_000 + fraction
    wall_elapsed = after["observed_utc_ns"] - request["received_utc_ns"]
    monotonic_elapsed = after["observed_monotonic_ns"] - request["received_monotonic_ns"]
    elapsed = finished_ns - request["received_utc_ns"]
    # Target and Engine share the Linux VM clock. Validate its elapsed time
    # against the target's monotonic clock and measure the exit event itself.
    require(
        abs(wall_elapsed - monotonic_elapsed) < 50_000_000
        and 0 < elapsed <= wall_elapsed
        and elapsed < 15_000_000_000,
        "launch_stop_work_exit_not_observed",
    )
    return elapsed


class LaunchFixture(Fixture):
    def __init__(
        self, selection, *, compose, compose_sha256, docker_config,
        completed=False, stop_work=False, queued_peer=False, local_stop=False, missing_grant=False,
        revoke_grant=False,
    ):
        super().__init__(
            selection,
            scenario=(
                "missing-local-grant" if missing_grant
                else "active-target-grant-revoked" if revoke_grant
                else "local-emergency-stop" if local_stop
                else "stop-work" if stop_work else EMPTY_SCENARIO
            ),
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
        self.cancelling = stop_work or local_stop or revoke_grant
        self.local_stop = local_stop
        self.missing_local_grant = missing_grant
        self.revoke_grant = revoke_grant
        self.queued_peer = queued_peer
        self.protocol = "persistent-v3"
        self.max_attempts = None
        require(sum((completed, stop_work, local_stop, missing_grant, revoke_grant)) <= 1 and (not queued_peer or stop_work),
                "launch_fixture_mode_conflict")
        scenario = "persistent-launch-empty"
        scope = "first_and_next_empty_launch"
        if completed:
            scenario, scope = "persistent-launch-completed", "completed_then_next_launch"
        elif stop_work:
            scenario, scope = "persistent-launch-stop-work", "stop_work_then_next_launch"
            if queued_peer:
                scenario, scope = "persistent-launch-stop-work-queued", "stop_work_excludes_queued_job"
        elif local_stop:
            scenario, scope = "persistent-launch-local-stop", "local_stop_then_next_launch"
        elif missing_grant:
            scenario, scope = "persistent-launch-missing-grant", "missing_grant_then_next_launch"
        elif revoke_grant:
            scenario, scope = "persistent-launch-grant-revocation", "grant_revocation_then_next_launch"
        self.receipt.update(
            schema="vardr.nm2-worker-launch-acceptance/1",
            scenario=scenario, acceptance_scope=scope, nm2_exit_status="incomplete",
        )

    def target_environment(self):
        environment = super().target_environment()
        if self.cancelling:
            environment["NM2_FIXTURE_UTC_TIMING"] = "1"
        return environment

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

    def managed_output_count(self):
        source = """import re
from vardrrunner import config
root=config.runs_dir()
directories=[]
if root.exists():
    for path in root.iterdir():
        if re.fullmatch(r'managed-[0-9a-f]{32}', path.name):
            assert path.is_dir() and not path.is_symlink() and not any(path.iterdir())
            directories.append(path)
print(len(directories))
"""
        return int(self.helper("-I", "-c", source, python=True))

    def await_missing_grant_denial(self, admission, case):
        engagement, _, _, _ = case
        self.receipt["stage"] = "launch_missing_grant_observe"
        self.persistent_idle(admission, 0)
        deadline = time.monotonic() + 30
        while self.managed_output_count() == 0:
            require(time.monotonic() < deadline, "launch_missing_grant_not_observed")
            time.sleep(0.2)
        stopped = self.api.request(
            f"/engagements/{engagement}/stop-work",
            {"reason": "Freeze the unissued missing-grant test cohort"},
        )
        require(stopped.get("stop_work_at") is not None, "cancellation_stop_work_not_recorded")
        self.persistent_idle(admission, 0)
        audit = self.empty_worker_state(admission)
        directories = self.managed_output_count()
        require(0 < directories <= 40, "launch_missing_grant_not_observed")
        return audit, directories

    def verify_missing_grant_launch(self, admission, retired, case, prior):
        engagement, job, _, before = case
        after = self.verify_unclaimed_peer((engagement, job), targets=0, duration=0)
        require(
            before["approvals"] == [after]
            and self.traffic() == []
            and self.grant_snapshot(engagement) == {
                "grants": [], "policy_reason": "grant_missing_or_replaced",
            },
            "launch_missing_grant_issued_or_changed",
        )
        audit = self.empty_worker_state(admission)
        before_audit, directories = prior
        require(
            audit == before_audit and self.managed_output_count() == directories,
            "launch_missing_grant_history_changed",
        )
        self.receipt["unissued_job"] = {
            "job_id": job, "retirement_sha256": retired["receipt_sha256"],
            "audit_sha256": digest(canonical(audit)),
            "unissued_discoveries": directories,
        }

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

        self.receipt["stage"] = "launch_stop_work_inventory"
        engagement, job, stored, _ = case
        requests = after["requests"]
        require(requests == action["requests"] and len(requests) == 3,
                "launch_stop_work_traffic_changed")
        stop_elapsed = stop_exit_elapsed_ns(requests[-1], after, physical["finished_at"])
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
        pending = action.get("cancel_requested")
        attempt = runtime["attempts"][0]
        require(
            attempt["binding"] == binding and attempt["job_id"] == job
            and (self.local_stop or self.revoke_grant or (
                pending["contract_id"] == binding["contract_id"]
                and pending["attempt_id"] == binding["attempt_id"]
            ))
            and attempt["runtime_sequence"] == "1"
            and attempt["runtime_id"] == runtime["id"]
            and attempt["confirmed_at"] is not None
            and attempt["release_receipt"] is None and attempt["released_at"] is None
            and attempt["native_done_sha256"] is None
            and terminal["capacity_reserved"] is False
            and inventory["execution"]["state"] == terminal["outcome"],
            "launch_stop_work_attempt_reused",
        )
        self.receipt["stage"] = "launch_stop_work_local_attempt"
        local = self.local_metadata(action["run_id"], engagement, job)
        require(
            local["consumption_sent"] == local["consumption_acknowledged"] == 1
            and local["local_stop_requested"] is self.local_stop,
            "launch_stop_work_original_run_not_preserved",
        )
        audit = self.reconcile_original(admission, retired)
        expected_causes = (
            {"local_emergency_stop"} if self.local_stop
            else {"control_lease_expired"} if self.revoke_grant
            else {"remote_stop_requested", "control_lease_expired"}
        )
        if inventory["results"]:
            self.receipt["stage"] = "launch_stop_work_partial_evidence"
            cause = local.get("failure_reason")
            retained = self.local_metadata(action["run_id"], engagement, job)
            require(
                all(retained[key] == local[key] for key in (
                    "run_id", "job_id", "engagement_id", "partial_files", "partial_result",
                    "consumption_sent", "consumption_acknowledged", "local_stop_requested",
                )),
                "launch_stop_work_original_run_not_preserved",
            )
            completion_event = "managed_completion_receipt"
            if retained["claim_state"] == "failed_completion_observed":
                require(retained["failure_reason"] == "observed_failed_completion",
                        "launch_stop_work_terminal_not_proven")
                completion_event = "managed_failed_completion_receipt"
                cause = "observed_exit"
            else:
                require(cause in expected_causes,
                        "launch_stop_work_terminal_not_proven")
            self.verify_failed_partial(
                engagement, job, stored, binding, terminal, inventory, retained,
                completion_event=completion_event,
            )
        else:
            cause = terminal.get("cause")
            require(
                cause in expected_causes | {"observed_exit"}
                and inventory["stops"][0] == {
                    "contract_id": binding["contract_id"],
                    "receipt_sha256": terminal["receipt_sha256"],
                    "outcome": terminal["outcome"],
                    "cause": cause,
                },
                "launch_stop_work_terminal_not_proven",
            )
        require(self.timed_traffic()["requests"] == requests, "launch_stop_work_traffic_changed")
        proof = {
            "job_id": job, "retirement_sha256": retired["receipt_sha256"],
            "audit_sha256": digest(canonical(audit)), "target_requests": len(requests),
            "terminal_sha256": digest(canonical(terminal)),
            "terminal_cause": cause,
            "physical_exit_elapsed_ns": stop_elapsed,
        }
        if self.local_stop:
            proof["local_stop_sha256"] = digest(canonical({
                "run_id": local["run_id"], "binding": binding, "local_stop_requested": True,
            }))
        elif self.revoke_grant:
            self.helper("whoami")
            revocation = {
                **action["grant_revocation"], "original_runner_auth": "verified",
            }
            proof["grant_revocation_sha256"] = digest(canonical(revocation))
        else:
            proof["cancel_requested_sha256"] = digest(canonical(pending))
        self.receipt["cancelled_job"] = proof

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
        if predecessor is not None and (self.completed or self.cancelling or self.missing_local_grant):
            key = "unissued_job" if self.missing_local_grant else "cancelled_job" if self.cancelling else "completed_job"
            proof = self.receipt[key]
            require(
                row["predecessors"][0]["original_local_audit_sha256"]
                == proof["audit_sha256"],
                "launch_completed_audit_changed",
            )
        cancelling = self.cancelling and case is not None
        if case is None:
            self.persistent_idle(admission, 0)
            before = self.verify_empty_worker_state(
                self.empty_worker_state(admission), admission
            )
        elif self.missing_local_grant:
            unissued = self.await_missing_grant_denial(admission, case)
        elif cancelling:
            self.receipt["stage"] = "launch_stop_work_observe"
            action = self.cancellation_action(*case[:3])
            if self.revoke_grant:
                self.receipt["stage"] = "launch_grant_revocation_catalog"
                action["grant_revocation"] = self.verify_grant_revocation(
                    case[0], self.grant_before, self.grant_snapshot(case[0]),
                )
            elif not self.local_stop:
                self.observe_stop_work(case, action)
        else:
            self.await_completed_job(admission, case)
        self.receipt["stage"] = "launch_stop_work_exit" if cancelling else f"launch_stop_{ordinal}"
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
        if cancelling:
            self.receipt["stage"] = "launch_stop_work_retirement"
        retired = self.report_exit(physical)
        reconciled = self.worker_action("reconcile", selected, timeout=120)
        require(
            retired["last_sequence"] == ("0" if case is None or self.missing_local_grant else "1")
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
        elif self.missing_local_grant:
            self.verify_missing_grant_launch(admission, retired, case, unissued)
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

    def observe_stop_work(self, case, action):
        pending = self.inventory(*case[:2])
        require(
            pending["job_status"] == "running"
            and pending["execution"] == {
                "state": "cancel_requested", "capacity_reserved": True,
                "target_charge": 1, "duration_seconds": 30,
            }
            and len(pending["contracts"]) == 1 and pending["contracts"][0]["consumed"] is True,
            "launch_stop_work_active_cancellation_not_observed",
        )
        contract = pending["contracts"][0]
        action["cancel_requested"] = {
            **pending["execution"],
            "contract_id": contract["id"],
            "attempt_id": contract["attempt_id"],
        }

    def cancelled_http(self):
        self.launch_pair()

    def missing_grant(self):
        self.launch_pair()

    def persistent_empty_stop(self):
        self.launch_pair()

    def launch_pair(self):
        from worker_runtime import LocalDocker, WorkerLayout

        self.receipt["stage"] = "launch_prepare"
        require(self.traffic() == [], "launch_unexpected_target_traffic")
        if not (self.cancelling or self.missing_local_grant):
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
        peer = None
        if self.completed or self.cancelling or self.missing_local_grant:
            name = "launch-" + (self.scenario if not self.completed else "completed")
            engagement, authorization, job, stored = self.new_job(name, marker=True)
            if self.queued_peer:
                peer_name = "launch-stop-work-peer"
                peer_job, peer_case = self.job_in_engagement(
                    peer_name, engagement, marker=True
                )
            require(
                self.approve(name, engagement, authorization, job, stored,
                             local_grants=not self.missing_local_grant)
                == binding,
                "launch_completed_enrollment_changed",
            )
            if self.queued_peer:
                require(
                    self.approve(peer_name, engagement, authorization, peer_job,
                                 peer_case, local_grants=False) == binding,
                    "launch_stop_work_enrollment_changed",
                )
                if peer_job < job:
                    job, stored, peer_job = peer_job, peer_case, job
                peer = (engagement, peer_job)
                peer_before = self.verify_unclaimed_peer(peer, targets=0, duration=0)
            before = self.inventory(engagement, job)
            if self.missing_local_grant:
                require(
                    self.managed_output_count() == 0 and self.grant_snapshot(engagement) == {
                        "grants": [], "policy_reason": "grant_missing_or_replaced",
                    },
                    "launch_missing_grant_precondition_failed",
                )
                self.helper("whoami")
            if self.revoke_grant:
                self.grant_before = self.grant_snapshot(engagement)
                require(self.grant_before["policy_reason"] == "granted",
                        "grant_not_initially_active")
                self.helper("whoami")
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
        if self.missing_local_grant:
            require(
                self.managed_output_count() == self.receipt["unissued_job"]["unissued_discoveries"]
                and [self.verify_unclaimed_peer(case[:2], targets=0, duration=0)]
                == case[3]["approvals"],
                "launch_missing_grant_issued_or_changed",
            )
        if peer is not None:
            peer_after = self.verify_unclaimed_peer(peer, targets=1, duration=30)
            require(peer_after == peer_before, "launch_stop_work_queued_job_changed")
            self.receipt["unclaimed_job"] = {
                "job_id": peer[1],
                "approval_inventory_sha256": digest(canonical(peer_after)),
            }
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
        if not (self.completed or self.cancelling or self.missing_local_grant):
            self.empty_engagements()
        self.receipt["launch_pair"] = [first, second]
        self.receipt["status"] = "selected_launch_slice_passed"
        self.receipt["stage"] = "selected_launch_complete"

    def verify_unclaimed_peer(self, peer, *, targets, duration):
        inventory = self.inventory(*peer)
        approvals = inventory["approvals"]
        require(
            inventory["job_status"] == "pending"
            and inventory["execution"] is None
            and inventory["contracts"] == inventory["runtimes"] == []
            and inventory["results"] == inventory["stops"] == []
            and inventory["targets_spent"] == targets
            and inventory["duration_allocated"] == duration
            and len(approvals) == 1
            and approvals[0]["issued"] == 0 and approvals[0]["revoked"] is False,
            "launch_stop_work_queued_job_changed",
        )
        return approvals[0]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", required=True, type=Path)
    parser.add_argument("--compose-executable", required=True, type=Path)
    parser.add_argument("--compose-sha256", required=True)
    parser.add_argument("--docker-config", required=True, type=Path)
    workload = parser.add_mutually_exclusive_group()
    workload.add_argument("--completed-job", action="store_true")
    workload.add_argument("--stop-work", action="store_true")
    workload.add_argument("--stop-work-queued", action="store_true")
    workload.add_argument("--local-stop", action="store_true")
    workload.add_argument("--missing-grant", action="store_true")
    workload.add_argument("--revoke-grant", action="store_true")
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
            stop_work=args.stop_work or args.stop_work_queued,
            queued_peer=args.stop_work_queued,
            local_stop=args.local_stop,
            missing_grant=args.missing_grant,
            revoke_grant=args.revoke_grant,
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
