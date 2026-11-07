"""Opt-in first and subsequent worker launch in a retained Docker installation."""

import argparse
from calendar import timegm
from dataclasses import asdict
from datetime import datetime, timedelta
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid

from nm2_worker_acceptance import (
    EMPTY_SCENARIO,
    ORIGIN,
    AcceptanceRefused,
    Fixture,
    canonical,
    command,
    digest,
    manifest,
    publish,
    require,
    worker_cli_command,
)

SECOND_NS = 1_000_000_000
STOPPED_PREDECESSOR_SCENARIO = "persistent-launch-stopped-predecessor"
DURATION_SCENARIO = "persistent-launch-duration-exhaustion"
DURATION_PASS = "selected_duration_exhaustion_slice_passed"
DURATION_MAP_COMMIT = "40bf4e37076d6a85648f817dd8b6bc69104bd863"
TARGET_SCENARIO = "persistent-launch-target-exhaustion"
TARGET_PASS = "selected_target_exhaustion_slice_passed"
TARGET_MAP_COMMIT = "41635f9a75598c84192b4b53be95e025bf0b9b9d"
BUDGET_LIMITS = {
    "duration": {"concurrency": 1, "targets": 5, "duration": 30},
    "target": {"concurrency": 1, "targets": 1, "duration": 120},
}
_BUDGET_WARNINGS = {
    budget: re.compile(
        rb"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3}"
        rb" WARNING managed_http managed_claim_" + budget.encode("ascii") + rb"_exhausted"
    )
    for budget in BUDGET_LIMITS
}


def budget_witness_count(raw, budget):
    warning = _BUDGET_WARNINGS[budget]
    return sum(warning.fullmatch(line) is not None for line in raw.splitlines())


def duration_witness_count(raw):
    return budget_witness_count(raw, "duration")


def expect_unresolved_launch(arguments, runtime_id, *, cwd, env, stdin):
    """Require the exact refusal from one ordinary launch invocation."""
    try:
        result = subprocess.run(
            arguments, cwd=cwd, env=env, input=stdin.encode(), capture_output=True,
            timeout=240, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise AcceptanceRefused("launch_unresolved_predecessor_refusal_missing") from None
    expected = {
        "schema": "vardr.worker-cli/1", "state": "held", "runtime_id": runtime_id,
        "failure_phase": "launch_catalog", "failure_code": "validation_refused",
    }
    require(
        result.returncode == 1 and type(result.stdout) is bytes
        and len(result.stdout) <= 4096
        and result.stdout.splitlines() == [json.dumps(expected, sort_keys=True).encode()],
        "launch_unresolved_predecessor_refusal_missing",
    )


def grant_time_ns(value):
    stamp = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    require(stamp.utcoffset() == timedelta(0), "launch_active_grant_expiry_timing")
    return timegm(stamp.utctimetuple()) * SECOND_NS + stamp.microsecond * 1000


def active_expiry_elapsed_ns(request, observed, expiry_ns, physical_elapsed, cause):
    request_ns = request["received_utc_ns"]
    active_elapsed = observed["observed_utc_ns"] - request_ns
    monotonic_elapsed = observed["observed_monotonic_ns"] - request["received_monotonic_ns"]
    grant_elapsed = expiry_ns - request_ns
    # Runner floors the grant-bound tool timeout to whole seconds before launch.
    # Only that terminal cause can explain a cutoff within one second early.
    earliest_offset = -SECOND_NS if cause == "tool_timeout" else 0
    require(
        0 <= active_elapsed <= grant_elapsed - SECOND_NS
        and abs(active_elapsed - monotonic_elapsed) < 50_000_000
        and grant_elapsed <= 14 * SECOND_NS
        and earliest_offset <= physical_elapsed - grant_elapsed <= 2_500_000_000,
        "launch_active_grant_expiry_timing",
    )
    return grant_elapsed


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
        revoke_grant=False, expire_grant=False, expire_active_grant=False,
        duration_exhaustion=False, target_exhaustion=False, stopped_predecessor=False,
    ):
        super().__init__(
            selection,
            scenario=(
                "missing-local-grant" if missing_grant or expire_grant
                else "active-target-grant-revoked" if revoke_grant
                else "local-emergency-stop" if local_stop
                else "stop-work" if stop_work or expire_active_grant or stopped_predecessor
                else EMPTY_SCENARIO
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
        self.budget_exhaustion = "duration" if duration_exhaustion else "target" if target_exhaustion else None
        self.completed = completed or self.budget_exhaustion is not None
        self.stopped_predecessor = stopped_predecessor
        self.cancelling = stop_work or local_stop or revoke_grant or expire_active_grant
        self.local_stop = local_stop
        self.local_grant_denial = missing_grant or expire_grant
        self.expire_grant = expire_grant
        self.revoke_grant = revoke_grant
        self.expire_active_grant = expire_active_grant
        self.queued_peer = queued_peer
        self.protocol = "persistent-v3"
        self.max_attempts = None
        require(
            sum((completed, stop_work, local_stop, missing_grant, revoke_grant,
                 expire_grant, expire_active_grant, duration_exhaustion, target_exhaustion,
                 stopped_predecessor)) <= 1
            and (not queued_peer or stop_work),
            "launch_fixture_mode_conflict",
        )
        scenario = "persistent-launch-empty"
        scope = "first_and_next_empty_launch"
        if duration_exhaustion:
            require(
                selection["sources"]["map"]["commit"] == DURATION_MAP_COMMIT,
                "launch_duration_witness_source_required",
            )
            scenario, scope = DURATION_SCENARIO, "allocated_duration_exhaustion"
        elif target_exhaustion:
            require(
                TARGET_MAP_COMMIT is not None
                and selection["sources"]["map"]["commit"] == TARGET_MAP_COMMIT,
                "launch_target_witness_source_required",
            )
            scenario, scope = TARGET_SCENARIO, "represented_origin_exhaustion"
        elif stopped_predecessor:
            scenario, scope = STOPPED_PREDECESSOR_SCENARIO, "stopped_predecessor_then_next_launch"
        elif completed:
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
        elif expire_grant:
            scenario, scope = "persistent-launch-expired-grant", "expired_grant_then_next_launch"
        elif expire_active_grant:
            scenario = "persistent-launch-active-grant-expiry"
            scope = "active_grant_expiry_then_next_launch"
        self.receipt.update(
            schema="vardr.nm2-worker-launch-acceptance/1",
            scenario=scenario, acceptance_scope=scope, nm2_exit_status="incomplete",
        )

    def target_environment(self):
        environment = super().target_environment()
        if self.cancelling or self.stopped_predecessor:
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
        local = self.persistent_metadata(admission, 1)
        self.verify_persistent_local(local, admission, 1)
        return local

    def budget_witnesses(self):
        raw = self.docker(
            "container", "logs", "--tail", "100", self.budget_api_id, timeout=8
        )
        return budget_witness_count(raw, self.budget_exhaustion)

    def observe_budget_exhaustion(self, observer, identity, admission, case, binding, local):
        budget = self.budget_exhaustion
        engagement, first_job, _, _ = case
        self.receipt["stage"] = f"launch_{budget}_prepare_second"
        first_inventory = self.inventory(engagement, first_job, include_capacity=True)
        traffic = self.traffic()
        require(
            len(traffic) == 5 and self.budget_witnesses() == 0
            and canonical([first_inventory["targets_spent"], first_inventory["duration_allocated"]])
            == b"[1,30]"
            and canonical([first_inventory["capacity_reserved_count"], first_inventory["concurrency_limit"]])
            == b"[0,1]"
            and first_inventory["execution"]["capacity_reserved"] is False
            and len(first_inventory["runtimes"]) == 1
            and first_inventory["runtimes"][0]["id"] == admission["runtime_id"]
            and first_inventory["runtimes"][0]["last_sequence"] == "1"
            and first_inventory["runtimes"][0]["active_sequence"] is None
            and len(first_inventory["runtimes"][0]["attempts"]) == 1,
            f"launch_{budget}_first_release_required",
        )
        name = f"launch-{budget}-exhausted"
        job, stored = self.job_in_engagement(name, engagement, marker=True)
        authority = {}
        require(
            self.approve(
                name, engagement, self.budget_authorization, job, stored,
                local_grants=False, review_authority=authority,
            ) == binding
            and canonical(authority["limits"])
            == canonical(BUDGET_LIMITS[budget]),
            f"launch_{budget}_second_approval_required",
        )
        self.receipt["stage"] = f"launch_{budget}_observe_refusal"
        # Observe the natural exit before issuing any stop/disable command.
        exited = observer.observe_exit(identity)
        require(
            type(exited.exit_code) is int and exited.exit_code != 0
            and self.budget_witnesses() == 1 and self.traffic() == traffic,
            f"launch_{budget}_exact_refusal_required",
        )
        peer = (engagement, job)
        approval = self.verify_unclaimed_peer(peer, targets=1, duration=30)
        refused = self.inventory(engagement, first_job, include_capacity=True)
        require(
            all(canonical(refused[key]) == canonical(first_inventory[key])
                for key in first_inventory if key != "runtimes"),
            f"launch_{budget}_refusal_mutated_inventory",
        )
        rows = json.loads(self.helper("audit", "list", "--engagement", engagement,
                                      "--limit", "3", "--json"))
        require(
            type(rows) is list and len(rows) == 2
            and {row["job_id"] for row in rows} == {first_job, job},
            f"launch_{budget}_original_hold_required",
        )
        run = next(row for row in rows if row["job_id"] == job)
        metadata = self.local_metadata(run["run_id"], engagement, job)
        require(
            run["phase"] == "claiming" and run["status"] == "claim_unknown"
            and run["pid"] is None and run["artifact_sha256"] is None
            and metadata["claim_state"] == "claim_unknown"
            and canonical([metadata["consumption_sent"], metadata["consumption_acknowledged"]])
            == b"[0,0]"
            and metadata["partial_files"] == [] and metadata["partial_result"] is None,
            f"launch_{budget}_original_hold_required",
        )
        return exited, peer, approval, run["run_id"], local["attempt"], first_inventory

    def reconcile_original(self, admission, retired, *, unissued_run_id=None, host_exit_run_id=None):
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
        if unissued_run_id is not None:
            require(
                reconciled["selected_run_id"] == unissued_run_id
                and reconciled["selected_sequence"] == "2"
                and reconciled["reconciliation_state"] == "terminal_runtime_unbound_retired"
                and retired["last_sequence"] == "1" and retired["binding"] is None,
                f"launch_{self.budget_exhaustion}_unbound_reconciliation_required",
            )
        if host_exit_run_id is not None:
            require(
                reconciled["selected_run_id"] == host_exit_run_id
                and reconciled["selected_sequence"] == "1"
                and reconciled["reconciliation_state"] == "terminal_host_exit_observed",
                "launch_host_exit_original_reconciliation_missing",
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

    def grant_pair_snapshot(self, engagement):
        before = self.grant_snapshot(engagement)
        grants = {row["name"]: row for row in before["grants"]}
        require(
            before["policy_reason"] == "granted" and len(before["grants"]) == 2
            and set(grants) == {"FIXTURE_OWNER_TOKEN", "FIXTURE_PEER_TOKEN"}
            and all(row["issuer"] == self.issuer_origin and row["engagement_id"] == engagement
                    and row["origin"] == ORIGIN and row["source"] == "env"
                    and row["status"] == "active" for row in grants.values()),
            "launch_expired_grant_not_proven",
        )
        return before, grants["FIXTURE_OWNER_TOKEN"]

    def verify_expired_catalog(self, engagement, before, after):
        peer = self.grant_snapshot(engagement, peer_only=True)
        require(
            after == {**before, "policy_reason": "grant_expired_or_revoked"} and peer == before,
            "launch_expired_grant_not_proven",
        )
        return digest(canonical({"before": before, "after": after, "peer": peer}))

    def prepare_expired_grant(self, engagement):
        self.receipt["stage"] = "launch_expired_grant_prepare"
        self.approve_local_grant(engagement, "peer", 600)
        self.approve_local_grant(engagement, "owner", 10)
        before, _ = self.grant_pair_snapshot(engagement)
        self.receipt["stage"] = "launch_expired_grant_observe"
        deadline = time.monotonic() + 20
        after = self.grant_snapshot(engagement)
        while after == before and time.monotonic() < deadline:
            time.sleep(0.2)
            after = self.grant_snapshot(engagement)
        self.grant_expiry_sha256 = self.verify_expired_catalog(engagement, before, after)
        return after

    def await_active_grant_expiry(self, admission, case):
        engagement, job, stored, _ = case
        self.receipt["stage"] = "launch_active_grant_expiry_window"
        self.persistent_idle(admission, 0)
        self.approve_local_grant(engagement, "peer", 600)
        self.approve_local_grant(engagement, "owner", 60)
        self.grant_before, owner = self.grant_pair_snapshot(engagement)
        expiry_ns = grant_time_ns(owner["expires_at"])
        review = self.expiry_review
        signed_ends = [
            review["expires_at"], review["testing_end"],
            *(row["expires_at"] for row in review["credential_grants"]),
        ]
        require(
            expiry_ns - grant_time_ns(owner["issued_at"]) == 60 * SECOND_NS
            and len(signed_ends) == 4
            and min(map(grant_time_ns, signed_ends)) > expiry_ns + 5 * SECOND_NS,
            "launch_active_grant_expiry_window",
        )
        deadline = time.monotonic() + 65
        while True:
            observed = self.timed_traffic()
            require(not observed["requests"] and time.monotonic() < deadline,
                    "launch_active_grant_expiry_window")
            remaining = expiry_ns - observed["observed_utc_ns"]
            if remaining <= 14 * SECOND_NS:
                break
            time.sleep(min(5, max(0.05, remaining / SECOND_NS - 14)))
        require(12 * SECOND_NS <= remaining, "launch_active_grant_expiry_window")
        self.api.request(f"/jobs/{job}/managed/approval/register", self.pending_approval)
        self.receipt["stage"] = "launch_stop_work_observe"
        run_id, observed = self.observe_active_run(engagement, job, stored)
        return {
            "run_id": run_id, "requests": observed["requests"],
            "observed": observed, "expiry_ns": expiry_ns,
        }

    def await_local_grant_denial(self, admission, case):
        engagement, _, _, _ = case
        self.receipt["stage"] = "launch_missing_grant_observe"
        self.persistent_idle(admission, 0)
        deadline = time.monotonic() + 30
        while self.managed_output_count() == 0:
            require(time.monotonic() < deadline, "launch_missing_grant_not_observed")
            time.sleep(0.2)
        stopped = self.api.request(
            f"/engagements/{engagement}/stop-work",
            {"reason": "Freeze the unissued local grant denial fixture"},
        )
        require(stopped.get("stop_work_at") is not None, "cancellation_stop_work_not_recorded")
        self.persistent_idle(admission, 0)
        audit = self.empty_worker_state(admission)
        directories = self.managed_output_count()
        require(0 < directories <= 40, "launch_missing_grant_not_observed")
        return audit, directories

    def verify_grant_denial_launch(self, admission, retired, case, prior):
        engagement, job, _, before = case
        after = self.verify_unclaimed_peer((engagement, job), targets=0, duration=0)
        require(
            before["approvals"] == [after]
            and self.traffic() == []
            and self.grant_snapshot(engagement) == self.denied_grant_snapshot,
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
        if self.expire_grant:
            self.receipt["unissued_job"]["grant_expiry_sha256"] = self.grant_expiry_sha256

    def completed_reconciliation(self, physical, admission, retired, case, *, unissued_run_id=None):
        engagement, job, stored, before = case
        requests = self.traffic()
        require(len(requests) == 5, "launch_completed_traffic_changed")
        _, measured = self.verify_fixed(
            engagement, job, stored, physical, before, requests,
            self.inventory(engagement, job), persistent=True,
        )
        audit = self.reconcile_original(admission, retired, unissued_run_id=unissued_run_id)
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
            and (self.local_stop or self.revoke_grant or self.expire_active_grant or (
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
        # Runner treats local grant revalidation failure as a local stop.
        # The original journal above distinguishes it from an operator stop.
        expected_causes = (
            {"local_emergency_stop"} if self.local_stop or self.revoke_grant
            else {"remote_stop_requested", "control_lease_expired"}
        )
        if self.expire_active_grant:
            expected_causes = {
                "authorization_deadline", "control_lease_expired", "local_emergency_stop", "tool_timeout",
            }
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
                inventory["stops"][0] == {
                    "contract_id": binding["contract_id"],
                    "receipt_sha256": terminal["receipt_sha256"],
                    "outcome": terminal["outcome"],
                    "cause": cause,
                },
                "launch_stop_work_terminal_not_proven",
            )
        allowed_causes = expected_causes if self.revoke_grant else expected_causes | {"observed_exit"}
        require(cause in allowed_causes, "launch_stop_work_terminal_not_proven")
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
        elif self.expire_active_grant:
            self.receipt["stage"] = "launch_active_grant_expiry_timing"
            proof["grant_expiry_elapsed_ns"] = active_expiry_elapsed_ns(
                requests[-1], action["observed"], action["expiry_ns"], stop_elapsed, cause
            )
            self.receipt["stage"] = "launch_active_grant_expiry_catalog"
            self.helper("whoami")
            proof["grant_expiry_sha256"] = self.verify_expired_catalog(
                engagement, self.grant_before, self.grant_snapshot(engagement)
            )
        else:
            proof["cancel_requested_sha256"] = digest(canonical(pending))
        self.receipt["cancelled_job"] = proof

    def verify_unresolved_predecessor(
        self, observer, exit_proof, admission, case, run_id, observed, arguments
    ):
        from worker_cli import records_for
        from worker_launch import _public_inventory
        from worker_lifecycle_intent import IntentStore

        self.receipt["stage"] = "launch_predecessor_unreported"
        observer.confirm_exit(exit_proof)
        requests = observed["requests"]
        after = self.timed_traffic()
        require(
            exit_proof.exit_code == 125 and requests == after["requests"] and len(requests) == 3,
            "launch_active_predecessor_exit_missing",
        )
        elapsed = stop_exit_elapsed_ns(requests[-1], after, exit_proof.finished_at)
        engagement, job = case[:2]
        inventory = self.inventory(engagement, job, include_capacity=True)
        require(
            inventory["job_status"] == "running"
            and canonical(inventory["execution"]) == canonical({
                "state": "active", "capacity_reserved": True,
                "target_charge": 1, "duration_seconds": 30,
            })
            and type(inventory["capacity_reserved_count"]) is int
            and inventory["capacity_reserved_count"] == 1
            and inventory["targets_spent"] == 1 and inventory["duration_allocated"] == 30
            and len(inventory["contracts"]) == len(inventory["runtimes"]) == 1
            and inventory["stops"] == inventory["results"] == [],
            "launch_predecessor_capacity_not_held",
        )
        runtime, contract = inventory["runtimes"][0], inventory["contracts"][0]
        require(
            runtime["id"] == admission["runtime_id"]
            and runtime["runtime_sha256"] == admission["runtime_sha256"]
            and runtime["admission_sha256"] == admission["admission_sha256"]
            and runtime["identity"] == asdict(exit_proof.identity)
            and runtime["active_sequence"] == runtime["last_sequence"] == "1"
            and runtime["new_work_disabled"] is True
            and runtime["retired"] is False and runtime["report_sha256"] is None
            and len(runtime["attempts"]) == 1,
            "launch_predecessor_unreported_runtime_changed",
        )
        attempt = runtime["attempts"][0]
        require(
            attempt["runtime_id"] == runtime["id"] and attempt["runtime_sequence"] == "1"
            and attempt["job_id"] == job and attempt["confirmed_at"] is not None
            and contract["consumed"] is True
            and canonical(attempt["binding"]) == canonical({
                "origin": admission["origin"], "runner_id": admission["runner_id"],
                "job_id": job, "contract_id": contract["id"],
                **{key: contract[key] for key in ("attempt_id", "fence", "contract_sha256")},
            })
            and all(attempt[key] is None for key in (
                "released_at", "terminal_receipt", "terminal_receipt_sha256",
                "native_done_sha256", "release_receipt",
            )),
            "launch_predecessor_original_attempt_missing",
        )
        local = self.local_metadata(run_id, engagement, job)
        require(
            local["phase"] == "executing" and local["claim_state"] == "consume_acknowledged"
            and local["consumption_sent"] == local["consumption_acknowledged"] == 1
            and local["local_stop_requested"] is False and local["failure_reason"] is None,
            "launch_predecessor_original_run_not_held",
        )

        records = records_for(self.install, str(self.private), existing=True)
        store = IntentStore(records)

        def catalog():
            with records.operation() as operation:
                value = store.inventory(operation=operation)
                _public_inventory(self.public_root, value)
            return value

        old = catalog()
        selected = admission["runtime_id"]
        require(
            set(old["records"]) == {selected} and len(old["intents"]) == 1
            and old["reports"] == []
            and old["records"][selected]["admission"] == admission
            and old["records"][selected]["stop_state"] == "none"
            and old["records"][selected]["receipt"] is None
            and self.successor_id != selected,
            "launch_predecessor_already_reported",
        )
        before = self.snapshot()
        ready_name = f"{self.project}_worker-ready-{self.successor_id}"
        require(ready_name not in before["volumes"], "launch_successor_volume_exists")

        self.receipt["stage"] = "launch_refuse_unresolved_predecessor"
        expect_unresolved_launch(
            arguments, self.successor_id, cwd=self.install, env=self.environment,
            stdin=self.password + "\n",
        )
        observer.confirm_exit(exit_proof)
        require(
            canonical(catalog()) == canonical(old)
            and canonical(self.snapshot()) == canonical(before)
            and canonical(self.inventory(engagement, job, include_capacity=True))
            == canonical(inventory)
            and canonical(self.local_metadata(run_id, engagement, job)) == canonical(local)
            and self.traffic() == requests,
            "launch_unresolved_refusal_changed_state",
        )
        self.receipt["stopped_predecessor"] = {
            "refused_runtime_id": self.successor_id,
            "failure_phase": "launch_catalog", "failure_code": "validation_refused",
            "new_resources": 0, "target_requests": len(requests),
            "physical_exit_elapsed_ns": elapsed,
        }
        return inventory

    def verify_host_exit_reconciliation(self, admission, retired, case, run_id, before):
        from worker_host import _terminal

        self.receipt["stage"] = "launch_host_exit_verification"
        runtime = before["runtimes"][0]
        binding = runtime["attempts"][0]["binding"]
        terminal = _terminal(binding, retired["attempt_receipt"])
        require(
            retired["admission_sha256"] == admission["admission_sha256"]
            and canonical(retired["binding"]) == canonical(binding)
            and terminal["schema"] == "vardr.managed-stop-receipt/1"
            and terminal["cause"] == "observed_exit" and terminal["outcome"] == "failed",
            "launch_host_exit_terminal_not_proven",
        )
        expected = {
            **before, "job_status": "failed", "capacity_reserved_count": 0,
            "execution": {**before["execution"], "state": "failed", "capacity_reserved": False},
            "runtimes": [{**runtime, "retired": True, "report_sha256": retired["report_sha256"]}],
            "stops": [{key: terminal[key] for key in ("contract_id", "receipt_sha256", "outcome", "cause")}],
        }
        after = self.inventory(*case[:2], include_capacity=True)
        require(canonical(after) == canonical(expected), "launch_host_exit_budget_or_history_changed")
        audit = self.reconcile_original(admission, retired, host_exit_run_id=run_id)
        self.retired_predecessor_inventory = after
        self.receipt["stopped_predecessor"].update(
            audit_sha256=digest(canonical(audit)), retirement_sha256=retired["receipt_sha256"],
            host_retirement_sha256=digest(canonical(retired)),
            terminal_sha256=digest(canonical(terminal)), terminal_cause="observed_exit",
            capacity_before=before["capacity_reserved_count"],
            capacity_after=after["capacity_reserved_count"],
            targets_spent=after["targets_spent"], duration_allocated=after["duration_allocated"],
            remaining_local_holds=audit["global_holds"],
        )

    def launch_arguments(self, config, signing, binding, runtime_id):
        runner, enrollment = binding
        arguments = [
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
        ]
        if runtime_id is not None:
            arguments.extend(("--runtime-id", runtime_id))
        return arguments

    def launch_and_retire(
        self, config, signing, binding, ordinal, predecessor, *, case=None
    ):
        from worker_runtime import LocalDocker, RuntimeIdentity, WorkerLayout

        runner, _ = binding
        self.receipt["stage"] = f"launch_{ordinal}"
        selected_id = self.successor_id if self.stopped_predecessor and ordinal == 2 else None
        enabled = json.loads(
            worker_cli_command(
                self.launch_arguments(config, signing, binding, selected_id),
                cwd=self.install,
                env=self.environment,
                stdin=self.password + "\n",
                timeout=240,
            )
        )
        require(enabled["state"] == "enabled", "launch_enable_not_observed")
        selected = enabled["runtime_id"]
        require(selected_id is None or selected == selected_id, "launch_successor_identity_changed")
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
        if predecessor is not None and self.stopped_predecessor:
            require(
                row["predecessors"][0]["original_local_audit_sha256"]
                == self.receipt["stopped_predecessor"]["audit_sha256"]
                and row["predecessors"][0]["host_retirement_sha256"]
                == self.receipt["stopped_predecessor"]["host_retirement_sha256"]
                and row["resources"]["runner_state"]["metadata_sha256"]
                == predecessor["runner_state_sha256"],
                "launch_host_exit_predecessor_binding_changed",
            )
        if predecessor is not None and (self.completed or self.cancelling or self.local_grant_denial):
            key = "unissued_job" if self.local_grant_denial else "cancelled_job" if self.cancelling else "completed_job"
            proof = self.receipt[key]
            require(
                row["predecessors"][0]["original_local_audit_sha256"]
                == proof["audit_sha256"],
                "launch_completed_audit_changed",
            )
        cancelling = self.cancelling and case is not None
        stopping_predecessor = self.stopped_predecessor and case is not None
        exhausted = None
        if case is None:
            self.persistent_idle(admission, 0)
            before = self.verify_empty_worker_state(
                self.empty_worker_state(admission), admission
            )
        elif self.local_grant_denial:
            unissued = self.await_local_grant_denial(admission, case)
        elif stopping_predecessor:
            self.receipt["stage"] = "launch_predecessor_active"
            require(
                observer.capture_running(
                    container_id=identity.container_id, image_id=identity.image_id,
                    project=identity.project,
                ) == identity,
                "launch_active_predecessor_identity_changed",
            )
            run_id, observed = self.observe_active_run(*case[:3])
        elif cancelling and self.expire_active_grant:
            action = self.await_active_grant_expiry(admission, case)
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
            local = self.await_completed_job(admission, case)
            if self.budget_exhaustion:
                exhausted = self.observe_budget_exhaustion(
                    observer, identity, admission, case, binding, local
                )
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
        if exhausted is not None:
            natural = exhausted[0]
            require(
                exit_proof.identity == natural.identity
                and exit_proof.exit_code == natural.exit_code
                and exit_proof.finished_at == natural.finished_at,
                f"launch_{self.budget_exhaustion}_exit_changed",
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
        if stopping_predecessor:
            before_report = self.verify_unresolved_predecessor(
                observer, exit_proof, admission, case, run_id, observed,
                self.launch_arguments(config, signing, binding, self.successor_id),
            )
            self.receipt["stage"] = "launch_report_predecessor"
        retired = self.report_exit(physical)
        reconciled = self.worker_action("reconcile", selected, timeout=120)
        require(
            retired["last_sequence"] == ("0" if case is None or self.local_grant_denial else "1")
            and retired["runtime_sequence"] == ("1" if cancelling or stopping_predecessor else None)
            and retired["retired"] is True
            and (retired["attempt_receipt"] is not None) == (cancelling or stopping_predecessor)
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
        elif self.local_grant_denial:
            self.verify_grant_denial_launch(admission, retired, case, unissued)
        elif stopping_predecessor:
            self.verify_host_exit_reconciliation(admission, retired, case, run_id, before_report)
        elif cancelling:
            self.cancelled_reconciliation(physical, admission, retired, case, action, after)
        elif exhausted is not None:
            natural, peer, approval, run_id, original_attempt, inventory = exhausted
            self.completed_reconciliation(physical, admission, retired, case, unissued_run_id=run_id)
            budget = self.budget_exhaustion
            self.receipt["stage"] = f"launch_{budget}_verify_retired"
            current = self.inventory(*case[:2], include_capacity=True)
            runtime = current["runtimes"][0]
            require(
                canonical(self.verify_unclaimed_peer(peer, targets=1, duration=30)) == canonical(approval)
                and self.api.request(f"/engagements/{peer[0]}/evidence?job_id={peer[1]}")["evidence"] == []
                and all(canonical(current[key]) == canonical(inventory[key])
                        for key in inventory if key != "runtimes")
                and len(current["runtimes"]) == 1
                and runtime["id"] == admission["runtime_id"] and runtime["retired"] is True
                and runtime["last_sequence"] == "1" and runtime["active_sequence"] is None
                and canonical(runtime["attempts"])
                == canonical(inventory["runtimes"][0]["attempts"])
                and canonical(self.persistent_metadata(admission, 1)["attempt"])
                == canonical(original_attempt)
                and self.budget_witnesses() == 1,
                f"launch_{budget}_original_history_changed",
            )
            self.receipt[f"{budget}_exhaustion"] = {
                "marker": f"managed_claim_{budget}_exhausted", "marker_count": 1,
                "targets_spent": current["targets_spent"],
                "duration_allocated": current["duration_allocated"],
                "duration_limit": BUDGET_LIMITS[budget]["duration"],
                **({"target_limit": BUDGET_LIMITS[budget]["targets"]} if budget == "target" else {}),
                "capacity_before": inventory["capacity_reserved_count"],
                "capacity_after": current["capacity_reserved_count"],
                "second_job_id": peer[1],
                "second_job_issued": 0, "second_job_target_requests": 0,
                "selected_sequence": "2", "last_issued_sequence": "1",
                "remaining_local_holds": 0, "natural_exit_code": natural.exit_code,
                "retirement_sha256": retired["receipt_sha256"],
            }
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

    def configure_budget_exhaustion(self, initial, engagement, authorization):
        budget = self.budget_exhaustion
        api = next(row for row in initial["core"] if row["service"] == "api")
        require(
            api["image_id"] == self.images["api"]
            and re.fullmatch(r"[0-9a-f]{64}", api["container_id"]) is not None,
            f"launch_{budget}_api_identity_required",
        )
        self.budget_api_id = api["container_id"]
        self.budget_authorization = authorization
        if budget == "duration":
            request = {"limit_seconds": 30}
            expected = {
                **request, "allocated_seconds": 0, "unit": "allocated_wall_permission_seconds/1",
            }
        else:
            request = {"limit": 1}
            expected = {**request, "spent": 0, "unit": "represented_origin_attempts/1"}
        policy = self.api.request(f"/engagements/{engagement}/{budget}-policy", request, method="PUT")
        require(canonical(policy) == canonical(expected), f"launch_{budget}_policy_required")

    def launch_pair(self):
        from worker_runtime import LocalDocker, WorkerLayout, _timestamp

        self.receipt["stage"] = "launch_prepare"
        require(self.traffic() == [], "launch_unexpected_target_traffic")
        if not (self.cancelling or self.local_grant_denial or self.stopped_predecessor):
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
        if self.stopped_predecessor:
            self.successor_id = str(uuid.uuid4())
        if self.completed or self.cancelling or self.local_grant_denial or self.stopped_predecessor:
            name = "launch-" + (
                "stopped-predecessor" if self.stopped_predecessor else
                "active-grant-expiry" if self.expire_active_grant else
                "expired-grant" if self.expire_grant else "completed" if self.completed else self.scenario
            )
            engagement, authorization, job, stored = self.new_job(name, marker=True)
            if self.budget_exhaustion:
                self.configure_budget_exhaustion(initial, engagement, authorization)
            first_authority = {} if self.budget_exhaustion == "target" else None
            if self.queued_peer:
                peer_name = "launch-stop-work-peer"
                peer_job, peer_case = self.job_in_engagement(
                    peer_name, engagement, marker=True
                )
            self.pending_approval = {} if self.expire_active_grant else None
            self.expiry_review = {} if self.expire_active_grant else None
            require(
                self.approve(
                    name, engagement, authorization, job, stored,
                    local_grants=not (self.local_grant_denial or self.expire_active_grant),
                    deferred_registration=self.pending_approval, review_context=self.expiry_review,
                    **({"review_authority": first_authority} if first_authority is not None else {}),
                ) == binding,
                "launch_completed_enrollment_changed",
            )
            if first_authority is not None:
                require(
                    canonical(first_authority["limits"]) == canonical(BUDGET_LIMITS["target"]),
                    "launch_target_first_approval_required",
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
            if self.expire_active_grant:
                require(before["approvals"] == [], "launch_active_grant_expiry_window")
            if self.local_grant_denial:
                self.denied_grant_snapshot = (
                    self.prepare_expired_grant(engagement) if self.expire_grant
                    else {"grants": [], "policy_reason": "grant_missing_or_replaced"}
                )
                require(
                    self.managed_output_count() == 0
                    and self.grant_snapshot(engagement) == self.denied_grant_snapshot,
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
        if self.budget_exhaustion:
            old_observer.confirm_exit(old_exit)
            final = observer.capture_project_containers(self.project)
            require(
                final["all_worker_ids"] == [first["container_id"]]
                and final["core"] == initial["core"] and len(self.traffic()) == 5,
                "launch_preservation_or_traffic_not_observed",
            )
            self.receipt.update(
                launch=first,
                status=DURATION_PASS if self.budget_exhaustion == "duration" else TARGET_PASS,
                stage=f"selected_{self.budget_exhaustion}_exhaustion_complete",
            )
            return
        baseline = self.traffic()
        second, _, _ = self.launch_and_retire(config, signing, binding, 2, first)
        old_observer.confirm_exit(old_exit)
        if self.local_grant_denial:
            require(
                self.managed_output_count() == self.receipt["unissued_job"]["unissued_discoveries"]
                and [self.verify_unclaimed_peer(case[:2], targets=0, duration=0)]
                == case[3]["approvals"],
                "launch_missing_grant_issued_or_changed",
            )
        if self.expire_grant:
            require(
                self.grant_snapshot(case[0]) == self.denied_grant_snapshot
                and self.grant_snapshot(case[0], peer_only=True)
                == {**self.denied_grant_snapshot, "policy_reason": "granted"},
                "launch_expired_grant_not_proven",
            )
            self.helper("whoami")
        if self.expire_active_grant:
            require(
                self.verify_expired_catalog(case[0], self.grant_before, self.grant_snapshot(case[0]))
                == self.receipt["cancelled_job"]["grant_expiry_sha256"],
                "launch_expired_grant_not_proven",
            )
            self.helper("whoami")
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
        if self.stopped_predecessor:
            require(
                canonical(self.inventory(*case[:2], include_capacity=True))
                == canonical(self.retired_predecessor_inventory)
                and second["runtime_id"] == self.successor_id
                and _timestamp(first["finished_at"]) < _timestamp(second["started_at"]),
                "launch_host_exit_predecessor_history_changed",
            )
        if not (self.completed or self.cancelling or self.local_grant_denial or self.stopped_predecessor):
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
    workload.add_argument("--expire-grant", action="store_true")
    workload.add_argument("--expire-active-grant", action="store_true")
    workload.add_argument("--duration-exhaustion", action="store_true")
    workload.add_argument("--target-exhaustion", action="store_true")
    workload.add_argument("--stopped-predecessor", action="store_true")
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
            expire_grant=args.expire_grant,
            expire_active_grant=args.expire_active_grant,
            duration_exhaustion=args.duration_exhaustion,
            target_exhaustion=args.target_exhaustion,
            stopped_predecessor=args.stopped_predecessor,
        )
        fixture.run()
        expected = (
            DURATION_PASS if args.duration_exhaustion else
            TARGET_PASS if args.target_exhaustion else "selected_launch_slice_passed"
        )
        return 0 if fixture.receipt["status"] == expected else 1
    except Exception:
        print(
            "Launch fixture held. Retain the owned installation and resources.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
