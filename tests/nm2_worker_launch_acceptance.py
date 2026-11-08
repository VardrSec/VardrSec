"""Opt-in first and subsequent worker launch in a retained Docker installation."""

import argparse
from calendar import timegm
from concurrent.futures import ThreadPoolExecutor
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
    EXECUTION,
    ORIGIN,
    AcceptanceRefused,
    Fixture,
    OwnerAPI,
    canonical,
    command,
    digest,
    manifest,
    publish,
    require,
    worker_cli_command,
)

SECOND_NS = 1_000_000_000
CLAIM_REPLY_LOSS_SCENARIO = "persistent-launch-claim-reply-loss"
CLAIM_REPLY_LOSS_PASS = "selected_claim_reply_loss_slice_passed"
CLAIM_REPLY_LOSS_SOURCES = {
    "map": "05dc78cf9a385255de459c8a5b833842d6528a63",
    "runner": "f359686b9f21410e08c82f7a8ad092697412f9c5",  # Required reviewed inspection follow-up; fail closed until pinned.
    "gate": "d80d4730b8486b75be72431b5af88e0ddb45020b",
}


POST_CLAIM_REPLY_LOSS_SOURCES = {
    "map": "05dc78cf9a385255de459c8a5b833842d6528a63",
    "runner": "f3dc7e92ea0cc04f5aca4bb74cc739fd79f5be19",
    "gate": "57cfedfaf59b11cf626288c343f34a34c7b1df13",
}
TERMINAL_REPLY_LOSS = {
    "result": {"scenario": "persistent-launch-result-reply-loss", "hosted": "vardr.nm2-hosted/23",
               "scope": "committed_result_reply_loss", "phase": "uploading",
               "intent_state": "result_in_flight", "finish_sent": 0, "outcome": None,
               "reconciliation": "terminal_failed_completion_observed"},
    "finish": {"scenario": "persistent-launch-finish-reply-loss", "hosted": "vardr.nm2-hosted/24",
               "scope": "committed_completion_reply_loss", "phase": "finalizing",
               "intent_state": "finish_in_flight", "finish_sent": 1, "outcome": "completed",
               "reconciliation": "terminal_receipt_observed"},
}


def terminal_reply_loss_state(operation, inventory, metadata, case_sha256, *, retired=False):
    """Read only original result facts; observation never supplies a missing ACK."""
    policy = TERMINAL_REPLY_LOSS[operation]
    require(type(retired) is bool and len(inventory["results"]) == 1
            and inventory["stops"] == [], "launch_terminal_loss_result_not_proven")
    result, runtime = inventory["results"][0], inventory["runtimes"][0]
    attempt = runtime["attempts"][0]
    binding = attempt["binding"]
    intent, local = metadata["result_intent"], metadata["persistent_attempt"]
    require(set(intent) == {"binding", "artifact_sha256", "artifact_size", "case_sha256",
                            "receipt_sha256", "outcome", "state", "finish_sent"}
            and canonical(intent["binding"]) == canonical(binding)
            and intent["case_sha256"] == case_sha256 and intent["outcome"] == "completed"
            and type(intent["finish_sent"]) is int and intent["finish_sent"] == policy["finish_sent"]
            and type(intent["artifact_size"]) is int and 0 < intent["artifact_size"] <= 512000
            and type(intent["artifact_sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", intent["artifact_sha256"]) is not None
            and result["artifact_sha256"] == intent["artifact_sha256"]
            and result["contract_id"] == binding["contract_id"]
            and result["receipt_sha256"] == intent["receipt_sha256"] == digest(canonical({
                "schema": "vardr.managed-result/1", **binding,
                "artifact_sha256": intent["artifact_sha256"], "case_sha256": case_sha256}))
            and type(result["evidence_created"]) is int and result["evidence_created"] == 5
            and type(result["scan_items_created"]) is int and result["scan_items_created"] == 0,
            "launch_terminal_loss_result_not_proven")
    require(set(local) == {"state", "binding", "completion", "native_done_sha256",
                           "release_intent", "release_ack", "retired_from_state"}
            and canonical(local["binding"]) == canonical({**binding,
                "runtime_id": runtime["id"], "runtime_sha256": runtime["runtime_sha256"],
                "admission_sha256": runtime["admission_sha256"], "runtime_sequence": "1"})
            and all(local[key] is None for key in (
                "completion", "native_done_sha256", "release_intent", "release_ack"))
            and local["state"] == ("physical_retirement_observed" if retired else "bound")
            and local["retired_from_state"] == ("bound" if retired else None)
            and metadata["consumption_sent"] == metadata["consumption_acknowledged"] == 1
            and all(type(metadata[key]) is int for key in ("consumption_sent", "consumption_acknowledged"))
            and metadata["local_stop_requested"] is False and metadata["partial_result"] is None
            and metadata["partial_files"] == [{"name": "vardrgate_result.json",
                "size": intent["artifact_size"], "sha256": intent["artifact_sha256"]}],
            "launch_terminal_loss_local_not_proven")
    outcome = "failed" if retired and operation == "result" else policy["outcome"]
    require(result["outcome"] == outcome
            and inventory["job_status"] == ("running" if outcome is None else "done" if outcome == "completed" else "failed")
            and canonical(inventory["execution"]) == canonical({"state": "active" if outcome is None else outcome,
                "capacity_reserved": outcome is None, "target_charge": 1, "duration_seconds": 30})
            and type(inventory["capacity_reserved_count"]) is int
            and inventory["capacity_reserved_count"] == (1 if outcome is None else 0)
            and metadata["phase"] == (policy["phase"] if not retired else "done" if operation == "finish" else "failed")
            and metadata["upload_state"] == ("in_progress" if operation == "result" else "succeeded")
            and intent["state"] == (policy["intent_state"] if not retired else "server_retired" if operation == "result" else "terminal")
            and metadata["claim_state"] == ("failed_completion_observed" if retired and operation == "result" else "consume_acknowledged"),
            "launch_terminal_loss_state_not_proven")
    return {"schema": "vardr.managed-completion/1", **binding,
            "receipt_sha256": result["receipt_sha256"],
            "outcome": "failed" if operation == "result" else "completed", "capacity_reserved": False}


def claim_reply_loss_config(original, job, *, operation="claim"):
    require(type(operation) is str and operation in {"claim", "consume", "runtime-bind", "result", "finish"},
            "launch_claim_loss_config_required")
    require(type(original) is bytes and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", job) is not None,
            "launch_claim_loss_config_required")
    old = """    handle_path /backend/* {
        reverse_proxy api:8000 {
            header_up X-Forwarded-For {remote_host}
            header_up X-Forwarded-Proto https
        }
    }
"""
    text = original.decode("utf-8").replace("\r\n", "\n")
    require(text.count(old) == 1, "launch_claim_loss_config_required")
    selected = """    @c03 {
        method POST
        path /jobs/JOB/managed/claim
    }
    handle_path /backend/* {
        route {
            reverse_proxy @c03 api:8000 {
                header_up X-Forwarded-For {remote_host}
                header_up X-Forwarded-Proto https
                @committed status 200
                handle_response @committed {
                    abort
                }
            }
            reverse_proxy api:8000 {
                header_up X-Forwarded-For {remote_host}
                header_up X-Forwarded-Proto https
            }
        }
    }
""".replace("JOB", job).replace("/managed/claim", "/managed/" + operation)
    return text.replace(old, selected, 1).encode("utf-8")



STOPPED_PREDECESSOR_SCENARIO = "persistent-launch-stopped-predecessor"
PID1_LOSS_SCENARIO = "persistent-launch-pid1-loss"
PID1_LOSS_SCOPE = "unexpected_pid1_loss_then_next_launch"
PID1_LOSS_SOURCES = {
    "map": "05dc78cf9a385255de459c8a5b833842d6528a63",
    "runner": "f3dc7e92ea0cc04f5aca4bb74cc739fd79f5be19",
    "gate": "57cfedfaf59b11cf626288c343f34a34c7b1df13",
}
REPEAT_SCENARIO = "persistent-launch-repeat-managed-claim"
REPEAT_SCOPE = "installed_repeated_managed_claim_then_exact_stop"
PRECLAIM_SCENARIO = "persistent-launch-preclaim-recovery"
PRECLAIM_SCOPE = "trusted_synthetic_closed_preclaim_parent0"
MAP_DISCONNECT_SCENARIO = "persistent-launch-map-disconnect"
MAP_DISCONNECT_PASS = "selected_map_disconnect_slice_passed"
MAP_DISCONNECT_SCOPE = "ordinary_map_api_outage"
MAP_DISCONNECT_LEASE_NS = 10 * SECOND_NS
MAP_DISCONNECT_CUT_WINDOW_NS = 15 * SECOND_NS - MAP_DISCONNECT_LEASE_NS
MAP_DISCONNECT_SOURCES = {
    "map": "05dc78cf9a385255de459c8a5b833842d6528a63",
    "runner": "5ecc869d80f53ae7fdbca25b971838976a6c41e9",
    "gate": "d80d4730b8486b75be72431b5af88e0ddb45020b",
}
DURATION_SCENARIO = "persistent-launch-duration-exhaustion"
DURATION_PASS = "selected_duration_exhaustion_slice_passed"
DURATION_MAP_COMMIT = "40bf4e37076d6a85648f817dd8b6bc69104bd863"
TARGET_SCENARIO = "persistent-launch-target-exhaustion"
TARGET_PASS = "selected_target_exhaustion_slice_passed"
TARGET_MAP_COMMIT = "41635f9a75598c84192b4b53be95e025bf0b9b9d"
CONCURRENCY_SCENARIO = "persistent-launch-concurrency-exhaustion"
CONCURRENCY_PASS = "selected_concurrency_exhaustion_slice_passed"
CONCURRENCY_MAP_COMMIT = "05dc78cf9a385255de459c8a5b833842d6528a63"
BUDGET_LIMITS = {
    "duration": {"concurrency": 1, "targets": 5, "duration": 30},
    "target": {"concurrency": 1, "targets": 1, "duration": 120},
    "concurrency": {"concurrency": 1, "targets": 5, "duration": 120},
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


_EXPECTED_LAUNCH_REFUSAL = ("launch_catalog", "validation_refused")
_LAUNCH_REPLY_CHECKPOINTS = {"runtime_mismatch", "refusal_mismatch", "reply_format"}
_LAUNCH_PROCESS_CHECKPOINTS = {
    "timeout", "spawn", "unexpected_success", "unexpected_exit",
    "empty_stdout", "output_limit", "invalid_stdout",
}


class UnresolvedLaunchRefused(AcceptanceRefused):
    def __init__(self, checkpoint, phase=None, code=None):
        super().__init__("launch_unresolved_predecessor_refusal_missing")
        self.public = {"checkpoint": checkpoint, "failure_phase": phase, "failure_code": code}


def launch_refusal_failure_detail(value):
    """Return only fixed diagnostic categories from the selected refusal boundary."""
    from worker_cli import FAILURE_CODES, FAILURE_PHASES

    if type(value) is not dict or set(value) != {"checkpoint", "failure_phase", "failure_code"}:
        return None
    checkpoint, phase, code = (value[key] for key in ("checkpoint", "failure_phase", "failure_code"))
    if type(checkpoint) is not str:
        return None
    if checkpoint in _LAUNCH_REPLY_CHECKPOINTS:
        if (type(phase) is not str or phase not in FAILURE_PHASES
                or type(code) is not str or code not in FAILURE_CODES):
            return None
        if checkpoint == "reply_format" and (phase, code) != _EXPECTED_LAUNCH_REFUSAL:
            return None
        if checkpoint == "refusal_mismatch" and (phase, code) == _EXPECTED_LAUNCH_REFUSAL:
            return None
    elif checkpoint not in _LAUNCH_PROCESS_CHECKPOINTS or phase is not None or code is not None:
        return None
    return {"checkpoint": checkpoint, "failure_phase": phase, "failure_code": code}


def _launch_reply_failure(raw, expected):
    from worker_host import HostRefused, _json, _uuid

    try:
        reply = _json(raw)
        if (set(reply) != set(expected) or reply["schema"] != expected["schema"]
                or reply["state"] != expected["state"]):
            return UnresolvedLaunchRefused("invalid_stdout")
        selected = reply["runtime_id"]
        if selected is not None:
            _uuid(selected)
    except HostRefused:
        return UnresolvedLaunchRefused("invalid_stdout")
    phase, code = reply["failure_phase"], reply["failure_code"]
    if selected != expected["runtime_id"]:
        checkpoint = "runtime_mismatch"
    elif (phase, code) != _EXPECTED_LAUNCH_REFUSAL:
        checkpoint = "refusal_mismatch"
    else:
        return None
    refusal = UnresolvedLaunchRefused(checkpoint, phase, code)
    if launch_refusal_failure_detail(refusal.public) is None:
        return UnresolvedLaunchRefused("invalid_stdout")
    return refusal


def expect_unresolved_launch(arguments, runtime_id, *, cwd, env, stdin):
    """Require the exact refusal from one ordinary launch invocation."""
    try:
        result = subprocess.run(
            arguments, cwd=cwd, env=env, input=stdin.encode(), capture_output=True,
            timeout=240, check=False,
        )
    except subprocess.TimeoutExpired:
        raise UnresolvedLaunchRefused("timeout") from None
    except (OSError, subprocess.SubprocessError):
        raise UnresolvedLaunchRefused("spawn") from None
    if result.returncode != 1:
        raise UnresolvedLaunchRefused("unexpected_success" if result.returncode == 0 else "unexpected_exit")
    raw = result.stdout
    if type(raw) is not bytes:
        raise UnresolvedLaunchRefused("invalid_stdout")
    if not raw:
        raise UnresolvedLaunchRefused("empty_stdout")
    if len(raw) > 4096:
        raise UnresolvedLaunchRefused("output_limit")
    phase, code = _EXPECTED_LAUNCH_REFUSAL
    expected = {
        "schema": "vardr.worker-cli/1", "state": "held", "runtime_id": runtime_id,
        "failure_phase": phase, "failure_code": code,
    }
    refusal = _launch_reply_failure(raw, expected)
    if refusal is not None:
        raise refusal


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


def engine_timestamp_ns(value):
    from worker_runtime import _timestamp

    second, fraction = _timestamp(value)
    return timegm(second.utctimetuple()) * SECOND_NS + fraction


def require_fresh_map_disconnect_sample(observed, sample_started_ns, now_ns):
    observed_ns = observed["observed_monotonic_ns"]
    received_ns = observed["requests"][-1]["received_monotonic_ns"]
    require(
        all(type(value) is int for value in (observed_ns, received_ns, sample_started_ns, now_ns))
        and 0 <= received_ns <= observed_ns
        and 0 <= sample_started_ns <= now_ns
        # The complete host-side sample duration conservatively covers time since
        # the target sampled its clock, without comparing different clock epochs.
        and observed_ns - received_ns + now_ns - sample_started_ns < MAP_DISCONNECT_CUT_WINDOW_NS,
        "launch_map_disconnect_sample_stale",
    )


def map_disconnect_timing(request, after, api_finished_at, worker_finished_at):
    elapsed = stop_exit_elapsed_ns(request, after, worker_finished_at)
    cut_to_exit = engine_timestamp_ns(worker_finished_at) - engine_timestamp_ns(api_finished_at)
    require(
        0 < cut_to_exit < elapsed and cut_to_exit <= MAP_DISCONNECT_LEASE_NS,
        "launch_map_disconnect_timing_refused",
    )
    return elapsed, cut_to_exit


def repeated_claim_state(inventory):
    """Only stable owned attempt/accounting fields, never refresh/presence times."""
    require(len(inventory["approvals"]) == 1, "launch_repeat_original_not_active")
    approval = inventory["approvals"][0]
    require(type(approval["issued"]) is int and approval["issued"] == 1
            and approval["revoked"] is False, "launch_repeat_original_not_active")
    require(len(inventory["contracts"]) == 1
            and canonical([inventory["contracts"][0][key] for key in ("ordinal", "fence")])
            == b"[1,1]", "launch_repeat_original_not_active")
    return {
        **{key: inventory[key] for key in (
            "job_status", "execution", "targets_spent", "duration_allocated",
            "capacity_reserved_count", "concurrency_limit", "contracts", "results", "stops",
        )},
        "approval": {key: approval[key] for key in ("id", "issued", "revoked")},
        "runtime": {key: inventory["runtimes"][0][key] for key in (
            "id", "runtime_sha256", "admission_sha256", "identity", "last_sequence",
            "head_sequence", "active_sequence", "retired", "new_work_disabled", "report_sha256", "attempts",
        )},
    }


class LaunchFixture(Fixture):
    pid1_loss = False

    def __init__(
        self, selection, *, compose, compose_sha256, docker_config,
        completed=False, stop_work=False, queued_peer=False, local_stop=False, missing_grant=False,
        revoke_grant=False, expire_grant=False, expire_active_grant=False,
        duration_exhaustion=False, target_exhaustion=False, stopped_predecessor=False,
        concurrency_exhaustion=False, map_disconnect=False, preclaim_recovery=False, claim_reply_loss=False,
        repeat_managed_claim=False, reply_loss_operation=None, pid1_loss=False,
    ):
        super().__init__(
            selection,
            scenario=(
                "missing-local-grant" if missing_grant or expire_grant
                else "active-target-grant-revoked" if revoke_grant
                else "local-emergency-stop" if local_stop
                else "stop-work" if stop_work or expire_active_grant or stopped_predecessor or map_disconnect or repeat_managed_claim or pid1_loss
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
        self.pid1_loss = pid1_loss
        self.stopped_predecessor = stopped_predecessor or repeat_managed_claim or pid1_loss
        self.repeat_managed_claim = repeat_managed_claim
        self.map_disconnect = map_disconnect
        self.preclaim_recovery = preclaim_recovery
        self.concurrency_exhaustion = concurrency_exhaustion
        require(reply_loss_operation is None or (type(reply_loss_operation) is str
                and reply_loss_operation in {"consume", "runtime-bind", *TERMINAL_REPLY_LOSS}), "launch_fixture_mode_conflict")
        self.claim_reply_loss = claim_reply_loss or reply_loss_operation is not None
        self.reply_loss_operation = reply_loss_operation or "claim"
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
                 stopped_predecessor, concurrency_exhaustion, map_disconnect, preclaim_recovery,
                 claim_reply_loss, repeat_managed_claim, reply_loss_operation is not None, pid1_loss)) <= 1
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
        elif concurrency_exhaustion:
            require(
                selection["sources"]["map"]["commit"] == CONCURRENCY_MAP_COMMIT,
                "launch_concurrency_witness_source_required",
            )
            scenario, scope = CONCURRENCY_SCENARIO, "shared_engagement_concurrency_exhaustion"
        elif repeat_managed_claim:
            require(all(selection["sources"][name]["commit"] == commit
                        for name, commit in MAP_DISCONNECT_SOURCES.items()),
                    "launch_repeat_sources_required")
            scenario, scope = REPEAT_SCENARIO, REPEAT_SCOPE
        elif pid1_loss:
            require(
                all(selection["sources"][name]["commit"] == commit
                    for name, commit in PID1_LOSS_SOURCES.items()),
                "launch_pid1_loss_source_required",
            )
            scenario, scope = PID1_LOSS_SCENARIO, PID1_LOSS_SCOPE
        elif stopped_predecessor:
            scenario, scope = STOPPED_PREDECESSOR_SCENARIO, "stopped_predecessor_then_next_launch"
        elif preclaim_recovery:
            scenario, scope = PRECLAIM_SCENARIO, PRECLAIM_SCOPE
        elif map_disconnect:
            require(
                all(selection["sources"][name]["commit"] == commit
                    for name, commit in MAP_DISCONNECT_SOURCES.items()),
                "launch_map_disconnect_source_required",
            )
            scenario, scope = MAP_DISCONNECT_SCENARIO, MAP_DISCONNECT_SCOPE
        elif self.claim_reply_loss:
            sources = POST_CLAIM_REPLY_LOSS_SOURCES if reply_loss_operation else CLAIM_REPLY_LOSS_SOURCES
            require(all(selection["sources"][name]["commit"] == commit
                        for name, commit in sources.items()), "launch_claim_loss_source_required")
            scenario, scope = ((TERMINAL_REPLY_LOSS[self.reply_loss_operation]["scenario"],
                                TERMINAL_REPLY_LOSS[self.reply_loss_operation]["scope"])
                               if self.reply_loss_operation in TERMINAL_REPLY_LOSS else
                               ("persistent-launch-" + self.reply_loss_operation + "-reply-loss",
                                "committed_" + self.reply_loss_operation.replace("-", "_") + "_reply_loss"))
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
        if self.cancelling or self.stopped_predecessor or self.map_disconnect:
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
        self.docker_sha256 = digest(self.docker_executable.read_bytes())
        publish(
            config,
            canonical(
                {
                    "docker": str(self.docker_executable),
                    "docker_sha256": self.docker_sha256,
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

    def budget_witnesses(self, *, budget=None):
        raw = self.docker(
            "container", "logs", "--tail", "100", self.budget_api_id, timeout=8
        )
        return budget_witness_count(raw, budget if budget is not None else self.budget_exhaustion)

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
        run_id = self.unissued_claim_run(
            engagement, job, {first_job, job}, f"launch_{budget}_original_hold_required",
        )
        return exited, peer, approval, run_id, local["attempt"], first_inventory

    def unissued_claim_run(self, engagement, job, job_ids, reason):
        rows = json.loads(self.helper("audit", "list", "--engagement", engagement,
                                      "--limit", "3", "--json"))
        require(
            type(rows) is list and len(rows) == len(job_ids)
            and {row["job_id"] for row in rows} == job_ids,
            reason,
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
            reason,
        )
        return run["run_id"]

    def reconcile_original(
        self, admission, retired, *, unissued_run_id=None, host_exit_run_id=None,
        unissued_parent_zero=False, selected_only_issued=False, terminal_reply_loss=None,
    ):
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
                and reconciled["selected_sequence"] == ("1" if unissued_parent_zero else "2")
                and reconciled["reconciliation_state"] == "terminal_runtime_unbound_retired"
                and retired["last_sequence"] == ("0" if unissued_parent_zero else "1")
                and retired["binding"] is None,
                "launch_concurrency_unbound_reconciliation_required" if unissued_parent_zero
                else f"launch_{self.budget_exhaustion}_unbound_reconciliation_required",
            )
        if host_exit_run_id is not None:
            require(
                reconciled["selected_run_id"] == host_exit_run_id
                and reconciled["selected_sequence"] == "1"
                and reconciled["reconciliation_state"] == (TERMINAL_REPLY_LOSS[terminal_reply_loss]["reconciliation"]
                    if terminal_reply_loss is not None else "terminal_host_exit_observed"),
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
            and audit["counts"]["attempts"] == (0 if unissued_parent_zero or selected_only_issued else 1),
            "launch_completed_audit_not_observed",
        )
        if unissued_parent_zero:
            require(
                unissued_run_id is not None
                and canonical(audit["parent"]) == canonical({
                    "state": "retired", "last_sequence": "0", "head_sequence": None,
                    "active_sequence": None,
                })
                and canonical(audit["counts"]) == canonical({
                    "attempts": 0, "selections": 1, "associated_runs": 1, "associated_claims": 1,
                }),
                "launch_concurrency_unbound_reconciliation_required",
            )
        if terminal_reply_loss is not None:
            self.receipt["claim_reply_loss"]["reconciliation"] = reconciled
        if selected_only_issued:
            require(
                host_exit_run_id is not None and retired["last_sequence"] == "1"
                and retired["binding"] is not None
                and canonical(audit["parent"]) == canonical({
                    "state": "retired", "last_sequence": "0", "head_sequence": None,
                    "active_sequence": None,
                })
                and canonical(audit["counts"]) == canonical({
                    "attempts": 0, "selections": 1, "associated_runs": 1, "associated_claims": 1,
                }),
                "launch_claim_loss_original_reconciliation_missing",
            )
        if getattr(self, "claim_reply_loss", False) and host_exit_run_id is not None:
            self.receipt["claim_reply_loss"]["reconciliation"] = reconciled
        return audit

    def concurrency_post(self, path, body):
        from vardrrunner.api import VardrMapClient

        require(digest(self.api.ca.read_bytes()) == self.api.ca_sha256, "fixture_ca_changed")
        client = VardrMapClient(self.url + "/backend", self.key["token"], retries=0)
        client.session.trust_env = False
        client.session.verify = str(self.api.ca)
        try:
            return client.managed_post(path, body)
        finally:
            client.session.close()

    def reserve_legacy_capacity(self, engagement, contender, runner):
        self.receipt["stage"] = "launch_concurrency_reserve"
        holder, stored = self.job_in_engagement(
            "launch-concurrency-holder", engagement, contract_required=False,
        )
        require(holder != contender and self.traffic() == [], "launch_concurrency_holder_required")
        holder_runner = str(uuid.uuid4())
        require(holder_runner != runner, "launch_concurrency_holder_required")
        body = {
            "runner_id": holder_runner, "origin": self.issuer_origin,
            "concurrency_budget": True, "duration_seconds": 30,
            "target_binding": {
                "profile": "gate-fixed-http/1",
                "case_sha256": digest(canonical(stored["spec"])), "origins": [ORIGIN],
            },
        }
        reply = self.concurrency_post(f"/jobs/{holder}/claim", body)
        owned = reply["execution_control"]
        token = owned["token"]
        require(
            reply["id"] == holder and reply["status"] == "running"
            and type(token) is str and 32 <= len(token) <= 100
            and canonical({key: value for key, value in owned.items() if key != "token"})
            == canonical({
                "job_id": holder, "runner_id": holder_runner, "origin": self.issuer_origin,
                "capacity_reserved": True, "lease_seconds": 10,
                "target_budget": {"binding": body["target_binding"], "charged": 1, "spent": 1, "limit": 5},
                "duration_budget": {
                    "allocated_seconds": 30, "total_allocated_seconds": 30, "limit_seconds": 120,
                },
            }),
            "launch_concurrency_holder_required",
        )
        inventory = self.inventory(engagement, holder, include_capacity=True)
        require(
            canonical([inventory[key] for key in (
                "targets_spent", "duration_allocated", "capacity_reserved_count", "concurrency_limit",
            )]) == b"[1,30,1,1]"
            and inventory["job_status"] == "running"
            and canonical(inventory["execution"]) == canonical({
                "state": "active", "capacity_reserved": True, "target_charge": 1, "duration_seconds": 30,
            })
            and all(inventory[key] == [] for key in ("approvals", "contracts", "runtimes", "results", "stops"))
            and self.traffic() == [],
            "launch_concurrency_holder_required",
        )
        self.concurrency_holder = holder, inventory
        return {**body, "token": token, "outcome": "failed"}

    def verify_concurrency_held(self, case):
        engagement, job, _, before = case
        holder, original = self.concurrency_holder
        held = self.inventory(engagement, holder, include_capacity=True)
        approval = self.verify_unclaimed_peer((engagement, job), targets=1, duration=30)
        require(
            canonical(held) == canonical(original)
            and canonical([approval]) == canonical(before["approvals"])
            and self.traffic() == [],
            "launch_concurrency_hold_changed",
        )
        return held["capacity_reserved_count"]

    def finish_legacy_capacity(self, case, body):
        self.receipt["stage"] = "launch_concurrency_finish"
        engagement, job, _, before = case
        holder, original = self.concurrency_holder
        capacity_before = self.verify_concurrency_held(case)
        reply = self.concurrency_post(f"/jobs/{holder}/execution-finish", body)
        final = self.inventory(engagement, holder, include_capacity=True)
        expected = {
            **original, "job_status": "failed", "capacity_reserved_count": 0,
            "execution": {**original["execution"], "state": "failed", "capacity_reserved": False},
        }
        approval = self.verify_unclaimed_peer((engagement, job), targets=1, duration=30)
        require(
            reply == {"state": "failed"}
            and canonical(final) == canonical(expected)
            and canonical([approval]) == canonical(before["approvals"])
            and self.traffic() == []
            and all(self.api.request(f"/engagements/{engagement}/evidence?job_id={selected}")["evidence"]
                    == [] for selected in (holder, job))
            and self.budget_witnesses(budget="concurrency") == 1,
            "launch_concurrency_release_required",
        )
        return capacity_before, final

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
        partial_retention = None
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
            partial_retention = {
                **self.verify_failed_partial(
                    engagement, job, stored, binding, terminal, inventory, retained,
                    completion_event=completion_event,
                ),
                "binding": binding,
                "case_sha256": digest(canonical(stored["spec"])),
            }
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
        # C01 observes retained evidence in this existing graceful-revocation case.
        # Forced exit without an emitted artifact stays valid stop evidence, but
        # cannot satisfy this retained-artifact acceptance witness.
        require(not self.revoke_grant or partial_retention is not None,
                "cancelled_partial_witness_unobserved")
        if partial_retention is not None:
            proof["partial_retention"] = partial_retention
        self.receipt["cancelled_job"] = proof

    def observe_repeated_managed_claim(self, admission, case, identity, run_id, observed):
        # This one metadata-only contender cannot consume or launch. Genuine
        # simultaneous server competition is covered by the independent PG race.
        self.receipt["stage"] = "launch_repeat_managed_claim"
        before = self.unreported_attempt(admission, case, identity, disabled=False)
        snapshot = repeated_claim_state(before)
        requests = observed["requests"]
        require(len(requests) == 3 and self.traffic() == requests,
                "launch_repeat_original_not_active")
        body = {
            "origin": admission["origin"], "runner_id": admission["runner_id"],
            "concurrency_budget": True, "duration_seconds": 30,
            "target_binding": {
                "profile": "gate-fixed-http/1",
                "case_sha256": digest(canonical(case[2]["spec"])), "origins": [ORIGIN],
            },
            **{key: admission[key] for key in (
                "runtime_id", "runtime_sha256", "admission_sha256",
            )},
            "runtime_sequence": "1",
        }
        # Existing strict bearer helper has no owner cookies, retries or redirect.
        client = OwnerAPI(self.url, self.api.ca)
        refusal = client.request(
            f"/jobs/{case[1]}/managed/claim", body, method="POST", csrf=False,
            expected=409, bearer=self.key["token"],
        )
        require(refusal == {"detail": "managed_request_refused"},
                "launch_repeat_refusal_required")
        after = self.unreported_attempt(admission, case, identity, disabled=False)
        require(canonical(repeated_claim_state(after)) == canonical(snapshot)
                and self.traffic() == requests,
                "launch_repeat_changed_original")
        self.receipt["repeated_managed_claim"] = {
            "runtime_id": admission["runtime_id"], "repeat_count": 1, "http_status": 409,
            "issued_attempts": len(after["contracts"]), "target_requests": len(requests),
            "targets_spent": after["targets_spent"], "duration_allocated": after["duration_allocated"],
            "capacity_before": before["capacity_reserved_count"],
            "capacity_after": after["capacity_reserved_count"],
            "state_before_sha256": digest(canonical(snapshot)),
            "state_after_sha256": digest(canonical(repeated_claim_state(after))),
            "binding_sha256": digest(canonical(after["runtimes"][0]["attempts"][0]["binding"])),
            "original_run_sha256": digest(run_id.encode("ascii")),
            "request_sha256": digest(canonical(body)), "refusal_sha256": digest(canonical(refusal)),
            "state_before": snapshot, "state_after": repeated_claim_state(after),
            "request": body, "request_path": f"/jobs/{case[1]}/managed/claim",
            "original_run_id": run_id, "case": case[2]["spec"],
        }

    def unreported_attempt(self, admission, case, identity, *, disabled):
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
            and runtime["identity"] == asdict(identity)
            and runtime["active_sequence"] == runtime["last_sequence"] == "1"
            and runtime["new_work_disabled"] is disabled
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
        return inventory

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
            exit_proof.exit_code == (137 if self.pid1_loss else 125)
            and requests == after["requests"] and len(requests) == 3,
            "launch_active_predecessor_exit_missing",
        )
        elapsed = stop_exit_elapsed_ns(requests[-1], after, exit_proof.finished_at)
        engagement, job = case[:2]
        inventory = self.unreported_attempt(
            admission, case, exit_proof.identity, disabled=not self.pid1_loss,
        )
        local = self.local_metadata(run_id, engagement, job)
        require(
            local["phase"] == "executing" and local["claim_state"] == "consume_acknowledged"
            and local["consumption_sent"] == local["consumption_acknowledged"] == 1
            and local["local_stop_requested"] is False and local["failure_reason"] is None,
            "launch_predecessor_original_run_not_held",
        )
        if self.pid1_loss:
            files = local["partial_files"]
            require(
                local["partial_result"] is None and len(files) <= 1
                and all(row["name"] == "vardrgate_result.json" for row in files),
                "launch_pid1_loss_artifact_promoted",
            )
            self.pid1_original_files = files
            self.pid1_original_run = (run_id, engagement, job)
            self.receipt["pid1_loss"].update(
                exit_code=exit_proof.exit_code, new_work_disabled_before_report=False,
                original_artifact_files=files,
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
        try:
            expect_unresolved_launch(
                arguments, self.successor_id, cwd=self.install, env=self.environment,
                stdin=self.password + "\n",
            )
        except UnresolvedLaunchRefused as error:
            self.receipt["launch_refusal_failure"] = error.public
            raise
        observer.confirm_exit(exit_proof)
        require(canonical(catalog()) == canonical(old),
                "launch_unresolved_refusal_catalog_changed")
        require(canonical(self.snapshot()) == canonical(before),
                "launch_unresolved_refusal_engine_changed")
        require(canonical(self.inventory(engagement, job, include_capacity=True))
                == canonical(inventory), "launch_unresolved_refusal_server_changed")
        require(canonical(self.local_metadata(run_id, engagement, job)) == canonical(local),
                "launch_unresolved_refusal_journal_changed")
        require(self.traffic() == requests, "launch_unresolved_refusal_traffic_changed")
        self.receipt["stopped_predecessor"] = {
            "refused_runtime_id": self.successor_id,
            "failure_phase": "launch_catalog", "failure_code": "validation_refused",
            "new_resources": 0, "target_requests": len(requests),
            "physical_exit_elapsed_ns": elapsed,
        }
        return inventory

    def verify_host_exit_reconciliation(
        self, admission, retired, case, run_id, before, *, proof_key="stopped_predecessor"
    ):
        from worker_host import _terminal

        if getattr(self, "reply_loss_operation", "claim") in TERMINAL_REPLY_LOSS:
            return self.verify_terminal_reply_loss(admission, retired, case, run_id, before)
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
            "runtimes": [{
                **runtime, "retired": True, "report_sha256": retired["report_sha256"],
                **({"new_work_disabled": True}
                   if proof_key in {"map_disconnect", "claim_reply_loss"} or self.pid1_loss else {}),
            }],
            "stops": [{key: terminal[key] for key in ("contract_id", "receipt_sha256", "outcome", "cause")}],
        }
        after = self.inventory(*case[:2], include_capacity=True)
        require(canonical(after) == canonical(expected), "launch_host_exit_budget_or_history_changed")
        audit = self.reconcile_original(
            admission, retired, host_exit_run_id=run_id,
            **({"selected_only_issued": True}
               if getattr(self, "claim_reply_loss", False) and getattr(self, "reply_loss_operation", "claim") == "claim" and proof_key == "claim_reply_loss" else {}),
        )
        if self.pid1_loss:
            local = self.local_metadata(run_id, *case[:2])
            require(
                local["partial_files"] == self.pid1_original_files
                and local["partial_result"] is None and after["results"] == [],
                "launch_pid1_loss_artifact_or_publication_changed",
            )
            self.receipt["pid1_loss"]["new_work_disabled_after_report"] = True
        self.retired_predecessor_inventory = after
        self.receipt[proof_key].update(
            audit_sha256=digest(canonical(audit)), retirement_sha256=retired["receipt_sha256"],
            host_retirement_sha256=digest(canonical(retired)),
            terminal_sha256=digest(canonical(terminal)), terminal_cause="observed_exit",
            capacity_before=before["capacity_reserved_count"],
            capacity_after=after["capacity_reserved_count"],
            targets_spent=after["targets_spent"], duration_allocated=after["duration_allocated"],
            remaining_local_holds=audit["global_holds"],
        )
        if getattr(self, "repeat_managed_claim", False):
            self.receipt["repeated_managed_claim"]["terminal_receipt"] = terminal
        return audit

    def kill_active_pid1(self, observer, identity):
        """One host-daemon fault against the freshly verified exact incarnation."""
        require(
            self.pid1_loss and self.receipt["scenario"] == PID1_LOSS_SCENARIO
            and "pid1_loss" not in self.receipt
            and digest(self.docker_executable.read_bytes()) == self.docker_sha256
            and observer.capture_running(
                container_id=identity.container_id, image_id=identity.image_id,
                project=identity.project,
            ) == identity,
            "launch_pid1_loss_identity_or_repeat_refused",
        )
        # Mark before dispatch: an ambiguous CLI failure must not be retried.
        self.receipt["pid1_loss"] = {
            "signal": "KILL", "kill_calls": 1, "container_id": identity.container_id,
        }
        command(
            [str(self.docker_executable), "--config", str(self.docker_config),
             "--context", self.m["docker_context"], "kill", "--signal", "KILL",
             identity.container_id],
            env=self.environment, timeout=10,
        )

    def arm_claim_reply_loss(self, observer, initial, job):
        from worker_runtime import host_bind_path

        self.receipt["stage"] = "launch_claim_loss_proxy_arm"
        require(initial["all_worker_ids"] == [], "launch_claim_loss_proxy_identity")
        proxy = next(row for row in initial["core"] if row["service"] == "proxy")
        cid = proxy["container_id"]
        expected_daemon = observer.daemon()
        target = self.install / "Caddyfile"
        original = (self.source / "Caddyfile").read_bytes()
        require(target.is_file() and not target.is_symlink()
                and target.read_bytes() == original, "launch_claim_loss_config_required")
        before = self.claim_loss_proxy(proxy)
        require(before["state"]["Status"] == "running"
                and before["state"]["Health"]["Status"] == "healthy",
                "launch_claim_loss_proxy_identity")
        mounts = before["mounts"]
        expected_mounts = {
            "/etc/caddy/Caddyfile": ("bind", None, False),
            "/data": ("volume", self.project + "_proxy-data", True),
            "/config": ("volume", self.project + "_proxy-config", True),
        }
        require({row["Destination"] for row in mounts} == set(expected_mounts)
                and len(mounts) == 3, "launch_claim_loss_proxy_identity")
        for row in mounts:
            kind, name, writable = expected_mounts[row["Destination"]]
            require(row["Type"] == kind and row["RW"] is writable
                    and (name is None or row["Name"] == name),
                    "launch_claim_loss_proxy_identity")
            if kind == "bind":
                require(host_bind_path(row["Source"]) == host_bind_path(str(target)),
                        "launch_claim_loss_proxy_identity")
        ca = self.install / "trust/root.crt"
        ca_sha256 = digest(ca.read_bytes())
        require(digest(self.docker("exec", cid, "cat",
                    "/data/caddy/pki/authorities/local/root.crt")) == ca_sha256,
                "launch_claim_loss_proxy_identity")
        version = self.docker("exec", cid, "caddy", "version").decode().strip()
        require(re.fullmatch(r"v2\.11\.7(?: h1:[A-Za-z0-9+/=]+)?", version) is not None,
                "launch_claim_loss_adapter_refused")
        config = claim_reply_loss_config(original, job, operation=getattr(self, "reply_loss_operation", "claim"))
        file_identity = target.stat().st_dev, target.stat().st_ino
        # Same inode: Docker's existing read-only bind must see the selected file.
        target.write_bytes(config)
        require((target.stat().st_dev, target.stat().st_ino) == file_identity,
                "launch_claim_loss_config_required")
        adapted = self.docker("exec", cid, "caddy", "adapt", "--config",
                              "/etc/caddy/Caddyfile", "--adapter", "caddyfile")
        require(0 < len(adapted) <= 131072 and type(json.loads(adapted)) is dict,
                "launch_claim_loss_adapter_refused")
        require(observer.daemon() == expected_daemon, "launch_claim_loss_proxy_identity")
        self.docker("--config", str(self.docker_config), "container", "stop", "--time", "10", cid,
                    timeout=20)
        stopped = self.claim_loss_proxy(proxy)
        require(stopped["state"]["Status"] == "exited"
                and stopped["state"]["Running"] is False,
                "launch_claim_loss_proxy_identity")
        self.docker("--config", str(self.docker_config), "container", "start", cid, timeout=20)
        until = time.monotonic() + 60
        after = None
        while time.monotonic() < until:
            after = self.claim_loss_proxy(proxy)
            if after["state"].get("Health", {}).get("Status") == "healthy":
                break
            time.sleep(0.25)
        require(after is not None and after["state"]["Status"] == "running"
                and after["state"]["Running"] is True
                and after["state"].get("Health", {}).get("Status") == "healthy"
                and {k: v for k, v in before.items() if k != "state"}
                == {k: v for k, v in after.items() if k != "state"}
                and before["state"]["StartedAt"] != after["state"]["StartedAt"]
                and digest(ca.read_bytes()) == ca_sha256
                and digest(self.docker("exec", cid, "cat",
                    "/data/caddy/pki/authorities/local/root.crt")) == ca_sha256
                and observer.daemon() == expected_daemon,
                "launch_claim_loss_proxy_identity")
        self.api.request("/ready")
        status = self.docker(
            "exec", cid, "curl", "--fail", "--silent", "--show-error", "--cacert",
            "/data/caddy/pki/authorities/local/root.crt", "--output", "/dev/null",
            "--write-out", "%{http_code}", "https://localhost:" + str(self.m["https_port"]) + "/",
        )
        require(status == b"200", "launch_claim_loss_proxy_identity")
        armed = observer.capture_project_containers(self.project)
        require(armed["all_worker_ids"] == []
                and all(row == next(item for item in armed["core"] if item["service"] == row["service"])
                        for row in initial["core"] if row["service"] != "proxy"),
                "launch_claim_loss_proxy_identity")
        self.claim_loss_proxy_binding = {
            "before": before, "armed": after, "base_config_sha256": digest(original),
            "config_sha256": digest(config), "adapter_sha256": digest(adapted),
            "ca_sha256": ca_sha256, "caddy_version": version,
            "ready_http_status": 200, "web_http_status": 200,
        }
        return armed

    def claim_loss_proxy(self, proxy):
        cid = proxy["container_id"]
        value = json.loads(self.docker(
            "--config", str(self.docker_config), "container", "inspect", "--format",
            '{"id":{{json .Id}},"image":{{json .Image}},"labels":{{json .Config.Labels}},'
            '"state":{{json .State}},"restarts":{{json .RestartCount}},"mounts":{{json .Mounts}},'
            '"profile":{"entrypoint":{{json .Config.Entrypoint}},"cmd":{{json .Config.Cmd}},'
            '"user":{{json .Config.User}},"readonly":{{json .HostConfig.ReadonlyRootfs}},'
            '"privileged":{{json .HostConfig.Privileged}},"caps":{{json .HostConfig.CapAdd}},'
            '"drop":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},'
            '"network":{{json .HostConfig.NetworkMode}},"ports":{{json .HostConfig.PortBindings}}}}',
            cid, timeout=8,
        ))
        require(value["id"] == cid and value["image"] == proxy["image_id"] == self.images["proxy"]
                and value["labels"].get("com.docker.compose.project") == self.project
                and value["labels"].get("com.docker.compose.service") == "proxy"
                and value["labels"].get("com.docker.compose.oneoff") == "False"
                and type(value["restarts"]) is int and value["restarts"] == 0
                and all(value["state"][k] is False for k in ("Paused", "Restarting", "Dead", "OOMKilled")),
                "launch_claim_loss_proxy_identity")
        value["mounts"] = sorted(value["mounts"], key=lambda row: row["Destination"])
        return value

    def observe_terminal_reply_loss(self, observer, identity, admission, case):
        self.receipt["stage"] = "launch_terminal_loss_register"
        self.persistent_idle(admission, 0)
        require(self.traffic() == [], "launch_terminal_loss_state_changed")
        registered = self.api.request(f"/jobs/{case[1]}/managed/approval/register", self.pending_approval)
        require(type(registered) is dict and set(registered) == {"approval_record_id"},
                "launch_terminal_loss_result_not_proven")
        self.receipt["stage"] = "launch_terminal_loss_observe"
        physical = observer.observe_exit(identity)
        require(type(physical.exit_code) is int and physical.exit_code == 125,
                "launch_terminal_loss_result_not_proven")
        observer.confirm_exit(physical)
        before = self.inventory(*case[:2], include_capacity=True)
        rows = json.loads(self.helper("audit", "list", "--engagement", case[0], "--limit", "3", "--json"))
        require(type(rows) is list and len(rows) == 1 and rows[0]["job_id"] == case[1],
                "launch_terminal_loss_local_not_proven")
        run = rows[0]
        require(re.fullmatch(r"[0-9a-f]{32}", run["run_id"]) is not None and run["pid"] is None,
                "launch_terminal_loss_local_not_proven")
        metadata = self.local_metadata(run["run_id"], *case[:2], include_result=True)
        terminal_reply_loss_state(self.reply_loss_operation, before, metadata, digest(canonical(case[2]["spec"])))
        requests = self.traffic()
        require(len(requests) == 5, "launch_terminal_loss_result_not_proven")
        evidence = self.api.request(f"/engagements/{case[0]}/evidence?job_id={case[1]}")["evidence"]
        require(len(evidence) == 5 and all(digest(row["body"].encode()) == row["content_hash"] for row in evidence),
                "launch_terminal_loss_result_not_proven")
        job = next(row for row in self.api.request(f"/engagements/{case[0]}/jobs")["jobs"] if row["id"] == case[1])
        assessment = job["assessment"]
        require(assessment["status"] == "conclusive" and assessment["baseline_valid"] is True
                and assessment["case_snapshot_verified"] is True and assessment["preflight"]["status"] == "passed"
                and assessment["case_hash"] == digest(canonical(case[2]["spec"]))
                and type(assessment["candidate_findings"]) is int and assessment["candidate_findings"] == 0
                and self.api.request(f"/engagements/{case[0]}/scans?job_id={case[1]}")["scans"] == [],
                "launch_terminal_loss_result_not_proven")
        audit = self.worker_state(admission, expected_held="issued_unknown")
        self.receipt["claim_reply_loss"] = {
            "operation": self.reply_loss_operation, "job_id": case[1], "run_id": run["run_id"],
            "approval_record_id": registered["approval_record_id"], "initial": case[3], "committed": before,
            "local_unknown": {"run": run, "metadata": metadata, "audit": audit},
            "proxy": self.claim_loss_proxy_binding, "target_requests": 5, "requests": requests,
            "case": case[2]["spec"], "assessment": {key: assessment[key] for key in (
                "status", "baseline_valid", "case_snapshot_verified", "preflight", "case_hash", "candidate_findings")},
            "evidence_count": 5, "evidence_sha256": digest(canonical(evidence)),
        }
        require(canonical(self.inventory(*case[:2], include_capacity=True)) == canonical(before)
                and self.traffic() == requests
                and digest((self.install / "Caddyfile").read_bytes()) == self.claim_loss_proxy_binding["config_sha256"],
                "launch_terminal_loss_state_changed")
        return run["run_id"], physical, before

    def verify_terminal_reply_loss(self, admission, retired, case, run_id, before):
        from worker_host import _terminal

        self.receipt["stage"] = "launch_terminal_loss_reconcile"
        operation = self.reply_loss_operation
        proof = self.receipt["claim_reply_loss"]
        original = before["runtimes"][0]["attempts"][0]["binding"]
        terminal = _terminal(original, retired["attempt_receipt"])
        expected = terminal_reply_loss_state(operation, before, proof["local_unknown"]["metadata"],
                                            digest(canonical(proof["case"])))
        require(canonical(terminal) == canonical(expected), "launch_terminal_loss_result_not_proven")
        audit = self.reconcile_original(admission, retired, host_exit_run_id=run_id, terminal_reply_loss=operation)
        after = self.inventory(*case[:2], include_capacity=True)
        local = self.local_metadata(run_id, *case[:2], include_result=True)
        terminal_reply_loss_state(operation, after, local, digest(canonical(proof["case"])), retired=True)
        require(self.traffic() == proof["requests"], "launch_terminal_loss_state_changed")
        self.retired_predecessor_inventory = after
        proof.update(after=after, local_after=local, audit=audit,
            audit_sha256=digest(canonical(audit)), retirement_sha256=retired["receipt_sha256"],
            host_retirement_sha256=digest(canonical(retired)), terminal_sha256=digest(canonical(terminal)),
            terminal_cause="retained_result_failure" if operation == "result" else "existing_completed",
            capacity_before=before["capacity_reserved_count"], capacity_after=after["capacity_reserved_count"],
            targets_spent=after["targets_spent"], duration_allocated=after["duration_allocated"], remaining_local_holds=0)
        return audit

    def observe_claim_reply_loss(self, observer, identity, admission, case):
        if getattr(self, "reply_loss_operation", "claim") in TERMINAL_REPLY_LOSS:
            return self.observe_terminal_reply_loss(observer, identity, admission, case)
        operation = getattr(self, "reply_loss_operation", "claim")
        issued = operation != "claim"
        self.receipt["stage"] = "launch_claim_loss_register"
        self.persistent_idle(admission, 0)
        require(self.traffic() == [], "launch_claim_loss_state_changed")
        registered = self.api.request(f"/jobs/{case[1]}/managed/approval/register", self.pending_approval)
        require(type(registered) is dict and set(registered) == {"approval_record_id"},
                "launch_claim_loss_commit_not_observed")
        self.receipt["stage"] = "launch_claim_loss_observe"
        physical = observer.observe_exit(identity)
        require(type(physical.exit_code) is int and physical.exit_code == 125,
                "launch_claim_loss_commit_not_observed")
        observer.confirm_exit(physical)
        self.receipt["stage"] = "launch_claim_loss_original_hold"
        before = self.inventory(*case[:2], include_capacity=True)
        require(before["job_status"] == "running"
                and canonical(before["execution"]) == canonical({
                    "state": "active", "capacity_reserved": True, "target_charge": 1, "duration_seconds": 30})
                and type(before["capacity_reserved_count"]) is int and before["capacity_reserved_count"] == 1
                and before["targets_spent"] == 1 and before["duration_allocated"] == 30
                and len(before["contracts"]) == len(before["runtimes"]) == 1
                and before["results"] == before["stops"] == [] and self.traffic() == [],
                "launch_claim_loss_commit_not_observed")
        runtime, contract = before["runtimes"][0], before["contracts"][0]
        require(runtime["id"] == admission["runtime_id"]
                and runtime["runtime_sha256"] == admission["runtime_sha256"]
                and runtime["admission_sha256"] == admission["admission_sha256"]
                and runtime["identity"] == asdict(identity)
                and runtime["active_sequence"] == runtime["head_sequence"] == runtime["last_sequence"] == "1"
                and runtime["retired"] is False and runtime["new_work_disabled"] is False
                and runtime["report_sha256"] is None and len(runtime["attempts"]) == 1
                and contract["consumed"] is issued and contract["ordinal"] == 1
                and len(before["approvals"]) == 1
                and before["approvals"][0]["id"] == registered["approval_record_id"]
                and before["approvals"][0]["issued"] == 1
                and before["approvals"][0]["revoked"] is False,
                "launch_claim_loss_commit_not_observed")
        attempt = runtime["attempts"][0]
        require(attempt["job_id"] == case[1] and attempt["runtime_sequence"] == "1"
                and attempt["runtime_id"] == runtime["id"] and attempt["bound_at"] is not None
                and canonical(attempt["binding"]) == canonical({
                    "origin": admission["origin"], "runner_id": admission["runner_id"], "job_id": case[1],
                    "contract_id": contract["id"],
                    **{k: contract[k] for k in ("attempt_id", "fence", "contract_sha256")},
                })
                and (attempt["confirmed_at"] is not None) == (operation == "runtime-bind")
                and all(attempt[k] is None for k in ("released_at", "terminal_receipt",
                    "terminal_receipt_sha256", "native_done_sha256", "release_receipt")),
                "launch_claim_loss_commit_not_observed")
        run_id = None if issued else self.unissued_claim_run(*case[:2], {case[1]}, "launch_claim_loss_original_hold_missing")
        audit = self.worker_state(admission, expected_held="issued_unknown" if issued else "claim_unknown")
        require(audit["schema"] == "vardr.worker-state-audit/1" and audit["status"] == "held"
                and audit["complete"] is True and audit["reason"] == "local_holds"
                and audit["binding"] == {k: admission[k] for k in (
                    "runner_id", "runtime_id", "runtime_sha256", "admission_sha256")}
                and canonical(audit["parent"]) == canonical({
                    "state": "active" if issued else "idle", "last_sequence": str(int(issued)),
                    "head_sequence": "1" if issued else None, "active_sequence": "1" if issued else None})
                and canonical(audit["counts"]) == canonical({
                    "attempts": int(issued), "selections": 1, "associated_runs": 1, "associated_claims": 1})
                and type(audit["global_holds"]) is int and audit["global_holds"] > 0
                and audit["retirement_receipt_sha256"] is None,
                "launch_claim_loss_original_hold_missing")
        rows = json.loads(self.helper("audit", "list", "--engagement", case[0], "--limit", "3", "--json"))
        require(type(rows) is list and len(rows) == 1 and rows[0]["job_id"] == case[1], "launch_claim_loss_original_hold_missing")
        run_id = rows[0]["run_id"] if issued else run_id
        local = next(row for row in rows if row["run_id"] == run_id)
        metadata = self.local_metadata(run_id, *case[:2])
        if issued:
            require(local["phase"] == metadata["phase"] == "executing"
                    and local["status"] == metadata["status"] == metadata["claim_state"] == "held_after_claim"
                    and local["pid"] is local["artifact_sha256"] is None
                    and canonical([metadata["consumption_sent"], metadata["consumption_acknowledged"]]) == b"[1,0]"
                    and metadata["partial_files"] == [] and metadata["partial_result"] is None,
                    "launch_claim_loss_original_hold_missing")
        require(self.traffic() == []
                and canonical(self.inventory(*case[:2], include_capacity=True)) == canonical(before)
                and digest((self.install / "Caddyfile").read_bytes()) == self.claim_loss_proxy_binding["config_sha256"],
                "launch_claim_loss_state_changed")
        self.receipt["claim_reply_loss"] = {
            "job_id": case[1], "run_id": run_id, "approval_record_id": registered["approval_record_id"],
            "initial": case[3], "committed": before,
            "local_unknown": {"run": local, "metadata": metadata, "audit": audit},
            "proxy": self.claim_loss_proxy_binding, "target_requests": 0,
        }
        return run_id, physical, before


    def disconnect_core_state(self, core):
        cid = core["container_id"]
        require(re.fullmatch(r"[0-9a-f]{64}", cid), "launch_map_disconnect_api_identity")
        row = json.loads(self.docker(
            "--config", str(self.docker_config), "container", "inspect", "--format",
            '{"id":{{json .Id}},"image":{{json .Image}},"labels":{{json .Config.Labels}},'
            '"state":{{json .State}},"restarts":{{json .RestartCount}}}',
            cid, timeout=8,
        ))
        labels, state = row["labels"], row["state"]
        require(
            row["id"] == cid and row["image"] == core["image_id"]
            and labels.get("com.docker.compose.project") == self.project
            and labels.get("com.docker.compose.service") == core["service"]
            and labels.get("com.docker.compose.oneoff") == "False"
            and type(row["restarts"]) is int and row["restarts"] == 0
            and all(state[key] is False for key in ("Paused", "Restarting", "Dead", "OOMKilled")),
            "launch_map_disconnect_api_identity",
        )
        return state

    def observe_map_disconnect(self, observer, identity, admission, case):
        self.receipt["stage"] = "launch_map_disconnect_active"
        self.persistent_idle(admission, 0)
        require(
            observer.capture_running(
                container_id=identity.container_id, image_id=identity.image_id,
                project=identity.project,
            ) == identity,
            "launch_map_disconnect_api_identity",
        )
        require(self.traffic() == [], "launch_map_disconnect_prework_traffic")
        api = next(row for row in self.disconnect_core if row["service"] == "api")
        proxy = next(row for row in self.disconnect_core if row["service"] == "proxy")
        prior = self.disconnect_core_state(api)
        require(
            prior["Status"] == "running" and prior["Running"] is True
            and prior["Health"]["Status"] == "healthy"
            and prior["StartedAt"] == api["started_at"]
            and observer.daemon() == identity.daemon_id,
            "launch_map_disconnect_api_identity",
        )
        self.receipt["stage"] = "launch_map_disconnect_register"
        engagement, job, stored = case[:3]
        self.api.request(f"/jobs/{job}/managed/approval/register", self.pending_approval)

        self.receipt["stage"] = "launch_map_disconnect_active"
        # A matching dispatched prefix makes the exact pre-cut Map inventory
        # meaningful without polling intermediate claim states.
        prefix, _ = self.observe_target_prefix(stored, minimum=1)
        def audit_original_run():
            started_ns = time.monotonic_ns()
            run_id = self.observe_executing_run_id(engagement, job)
            return run_id, started_ns, time.monotonic_ns()

        # One unchanged audit runs beside the positive Map check and final sample.
        # Join it on every path; its helper retains the existing 60-second timeout.
        with ThreadPoolExecutor(max_workers=1) as audit_pool:
            audit_future = audit_pool.submit(audit_original_run)
            original = self.unreported_attempt(admission, case, identity, disabled=False)
            observed, sample_started_ns = self.observe_target_prefix(stored)
            requests = observed["requests"]
            require(
                len(requests) == 3 and requests[:len(prefix["requests"])] == prefix["requests"],
                "launch_map_disconnect_target_changed",
            )
            self.receipt["stage"] = "launch_map_disconnect_stop_api"
            cid = api["container_id"]
            require_fresh_map_disconnect_sample(observed, sample_started_ns, time.monotonic_ns())
            api_stop_call_ns = time.monotonic_ns()
            self.docker("--config", str(self.docker_config), "container", "stop", "--time", "10", cid,
                        timeout=20)
            stopped = self.disconnect_core_state(api)
            require(
                stopped["Status"] == "exited" and stopped["Running"] is False
                and stopped["StartedAt"] == prior["StartedAt"]
                and type(stopped["ExitCode"]) is int and stopped["ExitCode"] in {0, 143},
                "launch_map_disconnect_api_exit_missing",
            )
            self.receipt["stage"] = "launch_map_disconnect_observe_worker"
            exit_proof = observer.observe_exit(identity)
            exit_observed_ns = time.monotonic_ns()
            after = self.timed_traffic()
            still_stopped = self.disconnect_core_state(api)
            require(exit_proof.exit_code == 125, "launch_map_disconnect_worker_exit_code")
            require(
                len(after["requests"]) == len(requests),
                "launch_map_disconnect_target_count_changed",
            )
            require(after["requests"] == requests, "launch_map_disconnect_target_rows_changed")
            require(
                all(still_stopped[key] == stopped[key] for key in (
                    "Status", "Running", "StartedAt", "FinishedAt", "ExitCode",
                )),
                "launch_map_disconnect_api_exit_changed",
            )
            elapsed, cut_to_exit = map_disconnect_timing(
                requests[-1], after, stopped["FinishedAt"], exit_proof.finished_at
            )
            # Require the original strict audit after physical exit and cutoff
            # checks, before API restart or host reporting.
            self.receipt["stage"] = "launch_map_disconnect_journal_after_exit"
            run_id, audit_started_ns, audit_finished_ns = audit_future.result()
            require(
                0 <= audit_started_ns <= audit_finished_ns
                and audit_started_ns <= api_stop_call_ns <= exit_observed_ns,
                "launch_map_disconnect_timing_refused",
            )
            # Raw scheduling interval only; not the exact SQLite snapshot instant.
            self.receipt["map_disconnect_audit"] = {
                "started_monotonic_ns": audit_started_ns,
                "finished_monotonic_ns": audit_finished_ns,
                "api_stop_call_monotonic_ns": api_stop_call_ns,
                "exit_observed_monotonic_ns": exit_observed_ns,
            }
            observer.confirm_exit(exit_proof)

        self.receipt["stage"] = "launch_map_disconnect_start_api"
        require(observer.daemon() == identity.daemon_id, "launch_map_disconnect_api_identity")
        self.docker("--config", str(self.docker_config), "container", "start", cid, timeout=20)
        until = time.monotonic() + 75
        while True:
            recovered = self.disconnect_core_state(api)
            routed = self.disconnect_core_state(proxy)
            require(
                recovered["Status"] == "running" and recovered["Running"] is True
                and engine_timestamp_ns(exit_proof.finished_at)
                < engine_timestamp_ns(recovered["StartedAt"])
                and routed["Status"] == "running" and routed["Running"] is True
                and routed["StartedAt"] == proxy["started_at"],
                "launch_map_disconnect_api_restart_missing",
            )
            if recovered["Health"]["Status"] == routed["Health"]["Status"] == "healthy":
                break
            require(time.monotonic() < until, "launch_map_disconnect_api_restart_missing")
            time.sleep(0.2)

        self.receipt["stage"] = "launch_map_disconnect_verify_held"
        observer.confirm_exit(exit_proof)
        final = observer.capture_project_containers(self.project)
        expected_core = [
            {**row, "started_at": recovered["StartedAt"]} if row["service"] == "api" else row
            for row in self.disconnect_core
        ]
        require(
            final["daemon_id"] == identity.daemon_id
            and canonical(final["core"]) == canonical(expected_core)
            and final["all_worker_ids"] == [identity.container_id]
            and canonical(self.unreported_attempt(admission, case, identity, disabled=False))
            == canonical(original)
            and self.traffic() == requests,
            "launch_map_disconnect_recovery_state_changed",
        )
        self.receipt["map_disconnect"] = {
            "api_container_id": cid, "api_started_at": prior["StartedAt"],
            "api_finished_at": stopped["FinishedAt"], "api_restarted_at": recovered["StartedAt"],
            "physical_exit_elapsed_ns": elapsed, "api_cut_to_worker_exit_ns": cut_to_exit,
            "target_requests": len(requests),
        }
        return run_id, exit_proof, original

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
        selected_id = self.successor_id if (self.stopped_predecessor or self.preclaim_recovery) and ordinal == 2 else None
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
        if predecessor is not None and self.preclaim_recovery:
            require(
                row["predecessors"][0]["original_local_audit_sha256"] == self.receipt["preclaim_recovery"]["audit_sha256"]
                and row["predecessors"][0]["host_retirement_sha256"] == self.receipt["preclaim_recovery"]["host_retirement_sha256"],
                "launch_preclaim_predecessor_binding_changed",
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
        disconnecting = self.map_disconnect and case is not None
        lost_claim = getattr(self, "claim_reply_loss", False) and case is not None
        exhausted = None
        concurrency_refused = None
        if case is None:
            self.persistent_idle(admission, 0)
            before = self.verify_empty_worker_state(
                self.empty_worker_state(admission), admission
            )
        elif lost_claim:
            run_id, exit_proof, before_report = self.observe_claim_reply_loss(
                observer, identity, admission, case
            )
        elif self.concurrency_exhaustion:
            self.receipt["stage"] = "launch_concurrency_observe_refusal"
            natural = observer.observe_exit(identity)
            require(
                type(natural.exit_code) is int and natural.exit_code != 0
                and self.budget_witnesses(budget="concurrency") == 1,
                "launch_concurrency_exact_refusal_required",
            )
            refused_capacity = self.verify_concurrency_held(case)
            run_id = self.unissued_claim_run(
                *case[:2], {case[1]}, "launch_concurrency_original_hold_required",
            )
            concurrency_refused = natural, run_id, refused_capacity
        elif self.local_grant_denial:
            unissued = self.await_local_grant_denial(admission, case)
        elif disconnecting:
            run_id, exit_proof, before_report = self.observe_map_disconnect(
                observer, identity, admission, case
            )
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
            if self.pid1_loss:
                self.unreported_attempt(admission, case, identity, disabled=False)
            if self.repeat_managed_claim:
                self.observe_repeated_managed_claim(admission, case, identity, run_id, observed)
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
        if not (disconnecting or lost_claim):
            self.receipt["stage"] = "launch_stop_work_exit" if cancelling else f"launch_stop_{ordinal}"
            losing_pid1 = stopping_predecessor and self.pid1_loss
            if losing_pid1:
                self.kill_active_pid1(observer, identity)
            stopped = None if cancelling or losing_pid1 else self.worker_action("stop", selected)
            exit_proof = observer.observe_exit(identity)
            if cancelling:
                after = self.timed_traffic()
                require(exit_proof.exit_code != 0, "launch_stop_work_exit_not_observed")
            elif losing_pid1:
                require(exit_proof.exit_code == 137, "launch_pid1_loss_exit_not_observed")
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
        if concurrency_refused is not None:
            natural = concurrency_refused[0]
            require(
                exit_proof.identity == natural.identity
                and exit_proof.exit_code == natural.exit_code
                and exit_proof.finished_at == natural.finished_at,
                "launch_concurrency_exit_changed",
            )
        physical = {
            "identity": asdict(identity),
            "runtime_id": selected,
            "runtime_sha256": admission["runtime_sha256"],
            "admission_sha256": admission["admission_sha256"],
            "finished_at": exit_proof.finished_at,
            "exit_code": exit_proof.exit_code,
            "operator_stop_state": "not_requested" if cancelling or disconnecting or lost_claim or (
                stopping_predecessor and self.pid1_loss
            ) else stopped["state"],
        }
        if cancelling:
            self.receipt["stage"] = "launch_stop_work_retirement"
        if stopping_predecessor:
            before_report = self.verify_unresolved_predecessor(
                observer, exit_proof, admission, case, run_id, observed,
                self.launch_arguments(config, signing, binding, self.successor_id),
            )
            self.receipt["stage"] = "launch_report_predecessor"
        if disconnecting:
            self.receipt["stage"] = "launch_map_disconnect_report_exit"
        if self.preclaim_recovery and ordinal == 1:
            self.prepare_preclaim_recovery(observer, exit_proof, admission, config, signing, binding)
        if lost_claim:
            self.receipt["stage"] = "launch_claim_loss_report_exit"
        if lost_claim:
            self.receipt["claim_reply_loss"]["physical"] = physical
        retired = self.report_exit(physical)
        reconciled = self.worker_action("reconcile", selected, timeout=120)
        require(
            retired["last_sequence"] == (
                "0" if case is None or self.local_grant_denial or concurrency_refused is not None else "1"
            )
            and retired["runtime_sequence"] == ("1" if cancelling or stopping_predecessor or disconnecting or lost_claim else None)
            and retired["retired"] is True
            and (retired["attempt_receipt"] is not None) == (cancelling or stopping_predecessor or disconnecting or lost_claim)
            and reconciled["state"] == "terminal_observed"
            and reconciled["receipt"]["retirement"] == retired,
            "launch_retirement_not_observed",
        )
        if case is None and self.preclaim_recovery and ordinal == 1:
            self.reconcile_preclaim_recovery(admission, retired)
        elif case is None:
            require(
                before
                == self.verify_empty_worker_state(
                    self.empty_worker_state(admission), admission
                ),
                "launch_empty_retirement_not_observed",
            )
        elif concurrency_refused is not None:
            natural, run_id, refused_capacity = concurrency_refused
            audit = self.reconcile_original(
                admission, retired, unissued_run_id=run_id, unissued_parent_zero=True,
            )
            self.concurrency_retirement = {
                "natural_exit_code": natural.exit_code,
                "retirement_sha256": retired["receipt_sha256"],
                "audit_sha256": digest(canonical(audit)),
                "last_issued_sequence": audit["parent"]["last_sequence"],
                "issued_attempts": audit["counts"]["attempts"],
                "remaining_local_holds": audit["global_holds"],
                "capacity_after_refusal": refused_capacity,
            }
        elif self.local_grant_denial:
            self.verify_grant_denial_launch(admission, retired, case, unissued)
        elif lost_claim:
            audit = self.verify_host_exit_reconciliation(
                admission, retired, case, run_id, before_report, proof_key="claim_reply_loss",
            )
            self.receipt["claim_reply_loss"].update(
                after=self.retired_predecessor_inventory, retirement=retired, audit=audit,
            )
        elif disconnecting:
            self.verify_host_exit_reconciliation(
                admission, retired, case, run_id, before_report, proof_key="map_disconnect",
            )
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
        if not (self.cancelling or self.local_grant_denial or self.stopped_predecessor or self.map_disconnect):
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
        if self.map_disconnect:
            self.disconnect_core = initial["core"]
        case = None
        peer = None
        if self.stopped_predecessor or self.preclaim_recovery:
            self.successor_id = str(uuid.uuid4())
        if self.preclaim_recovery:
            engagement, authorization, job, stored = self.new_job("launch-closed-preclaim", marker=True)
            self.prepare_preclaim_grant_catalogue(engagement)
            require(self.approve("launch-closed-preclaim", engagement, authorization, job, stored, local_grants=False) == binding,
                    "launch_preclaim_enrollment_changed")
            self.preclaim_case = engagement, job, stored
            self.preclaim_inventory = self.preclaim_unissued()

        if (
            self.completed or self.cancelling or self.local_grant_denial
            or self.stopped_predecessor or self.concurrency_exhaustion or self.map_disconnect
            or getattr(self, "claim_reply_loss", False)
        ):
            name = "launch-" + (
                "claim-reply-loss" if getattr(self, "claim_reply_loss", False) else
                "map-disconnect" if self.map_disconnect else
                "stopped-predecessor" if self.stopped_predecessor else
                "concurrency-contender" if self.concurrency_exhaustion else
                "active-grant-expiry" if self.expire_active_grant else
                "expired-grant" if self.expire_grant else "completed" if self.completed else self.scenario
            )
            engagement, authorization, job, stored = self.new_job(name, marker=True)
            if getattr(self, "claim_reply_loss", False):
                initial = self.arm_claim_reply_loss(observer, initial, job)
            if self.budget_exhaustion:
                self.configure_budget_exhaustion(initial, engagement, authorization)
            if self.concurrency_exhaustion:
                api = next(row for row in initial["core"] if row["service"] == "api")
                require(
                    api["image_id"] == self.images["api"]
                    and re.fullmatch(r"[0-9a-f]{64}", api["container_id"]) is not None,
                    "launch_concurrency_api_identity_required",
                )
                self.budget_api_id = api["container_id"]
            first_authority = {} if self.budget_exhaustion == "target" or self.concurrency_exhaustion else None
            if self.queued_peer:
                peer_name = "launch-stop-work-peer"
                peer_job, peer_case = self.job_in_engagement(
                    peer_name, engagement, marker=True
                )
            self.pending_approval = {} if self.expire_active_grant or self.map_disconnect or getattr(self, "claim_reply_loss", False) else None
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
                    canonical(first_authority["limits"]) == canonical(BUDGET_LIMITS[
                        "concurrency" if self.concurrency_exhaustion else "target"
                    ]),
                    "launch_concurrency_approval_required" if self.concurrency_exhaustion
                    else "launch_target_first_approval_required",
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
            before = self.inventory(
                engagement, job,
                **({"include_capacity": True} if getattr(self, "claim_reply_loss", False) else {}),
            )
            if self.expire_active_grant:
                require(before["approvals"] == [], "launch_active_grant_expiry_window")
            if self.map_disconnect:
                require(before["approvals"] == [], "launch_map_disconnect_approval_not_deferred")
            if getattr(self, "claim_reply_loss", False):
                require(before["approvals"] == [], "launch_claim_loss_eligible_before_arm")
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
        if self.concurrency_exhaustion:
            require(self.budget_witnesses(budget="concurrency") == 0, "launch_concurrency_baseline_required")
            finish_body = self.reserve_legacy_capacity(*case[:2], binding[0])
            capacity_before = self.verify_concurrency_held(case)
        first, old_observer, old_exit = self.launch_and_retire(
            config, signing, binding, 1, None, case=case
        )
        if getattr(self, "claim_reply_loss", False):
            old_observer.confirm_exit(old_exit)
            final = observer.capture_project_containers(self.project)
            require(final["all_worker_ids"] == [first["container_id"]]
                    and final["core"] == initial["core"]
                    and self.traffic() == self.receipt["claim_reply_loss"].get("requests", [])
                    and canonical(self.inventory(*case[:2], include_capacity=True))
                    == canonical(self.retired_predecessor_inventory),
                    "launch_claim_loss_state_changed")
            operation = getattr(self, "reply_loss_operation", "claim")
            slug = operation.replace("-", "_")
            self.receipt.update(launch=first, status=("selected_terminal_reply_loss_slice_passed"
                                if operation in TERMINAL_REPLY_LOSS else "selected_" + slug + "_reply_loss_slice_passed"),
                                stage=("selected_terminal_reply_loss_complete" if operation in TERMINAL_REPLY_LOSS
                                else "selected_" + slug + "_reply_loss_complete"))
            return
        if self.concurrency_exhaustion:
            old_observer.confirm_exit(old_exit)
            final = observer.capture_project_containers(self.project)
            require(
                final["all_worker_ids"] == [first["container_id"]]
                and final["core"] == initial["core"] and self.traffic() == [],
                "launch_preservation_or_traffic_not_observed",
            )
            held_capacity, released = self.finish_legacy_capacity(case, finish_body)
            self.receipt.update(
                launch=first,
                concurrency_exhaustion={
                    **self.concurrency_retirement,
                    "marker": "managed_claim_concurrency_exhausted", "marker_count": 1,
                    "legacy_job_id": self.concurrency_holder[0], "managed_job_id": case[1],
                    "legacy_finish_state": released["execution"]["state"],
                    "target_requests": len(self.traffic()),
                    "targets_spent": released["targets_spent"],
                    "duration_allocated": released["duration_allocated"],
                    "concurrency_limit": released["concurrency_limit"],
                    "capacity_before": capacity_before,
                    "capacity_before_finish": held_capacity,
                    "capacity_after_finish": released["capacity_reserved_count"],
                    "selected_sequence": "1",
                },
                status=CONCURRENCY_PASS, stage="selected_concurrency_exhaustion_complete",
            )
            return
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
        if self.map_disconnect:
            old_observer.confirm_exit(old_exit)
            require(
                len(self.traffic()) == 3
                and canonical(self.inventory(*case[:2], include_capacity=True))
                == canonical(self.retired_predecessor_inventory),
                "launch_map_disconnect_recovery_state_changed",
            )
            self.receipt.update(
                launch=first, status=MAP_DISCONNECT_PASS, stage="selected_map_disconnect_complete",
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
            if self.pid1_loss:
                retained = self.local_metadata(*self.pid1_original_run)
                require(
                    retained["partial_files"] == self.pid1_original_files
                    and retained["partial_result"] is None,
                    "launch_pid1_loss_successor_changed_artifact",
                )
        if self.preclaim_recovery:
            require(second["runtime_id"] == self.successor_id
                    and canonical(self.preclaim_unissued()) == canonical(self.preclaim_inventory)
                    and self.read_preclaim_snapshot()["tombstone_sha256"] == self.preclaim_tombstone,
                    "launch_preclaim_source_changed")
        if not (self.completed or self.cancelling or self.local_grant_denial or self.stopped_predecessor or self.preclaim_recovery):
            self.empty_engagements()
        self.receipt["launch_pair"] = [first, second]
        self.receipt["status"] = "selected_launch_slice_passed"
        self.receipt["stage"] = "selected_launch_complete"

    def prepare_preclaim_grant_catalogue(self, engagement):
        # Establish valid grant custody through the real CLI, without granting
        # either selected-case reference or creating another queueable job.
        inert = self.api.request("/engagements", {"name": "NM2 inert preclaim catalogue"})["id"]
        require(inert != engagement, "launch_preclaim_inert_engagement_changed")
        self.helper(
            "credentials", "approve", "--engagement", inert,
            "--origin", "https://nm2-preclaim-catalog.invalid",
            "--env", "NM2_PRECLAIM_INERT_TOKEN", "--issuer", self.issuer_origin,
            "--expires-in", "600",
        )
        require(
            self.grant_snapshot(engagement)
            == {"grants": [], "policy_reason": "grant_missing_or_replaced"},
            "launch_preclaim_selected_grants_not_missing",
        )

    def preclaim_unissued(self):
        engagement, job = self.preclaim_case[:2]
        self.verify_unclaimed_peer((engagement, job), targets=0, duration=0)
        value = self.inventory(engagement, job, include_capacity=True)
        require(type(value["capacity_reserved_count"]) is int and value["capacity_reserved_count"] == 0
                and self.traffic() == [], "launch_preclaim_server_changed")
        return value

    def read_preclaim_snapshot(self):
        source = (self.install / "tests/nm2_worker_preclaim_fixture.py").read_text(encoding="utf-8")
        return json.loads(self.helper("-I", "-c", source, "snapshot", python=True,
                                      stdin=canonical({"run_id": self.preclaim_run_id})))

    def prepare_preclaim_recovery(self, observer, proof, admission, config, signing, binding):
        from worker_cli import records_for
        from worker_launch import _public_inventory
        from worker_lifecycle_intent import IntentStore
        from worker_runtime import ObservedExit

        self.receipt["stage"] = "launch_preclaim_setup"
        require(isinstance(proof, ObservedExit) and asdict(proof.identity) == admission["identity"],
                "launch_preclaim_exit_not_bound")
        observer.confirm_exit(proof)
        require(canonical(self.preclaim_unissued()) == canonical(self.preclaim_inventory), "launch_preclaim_server_changed")
        source = (self.install / "tests/nm2_worker_preclaim_fixture.py").read_text(encoding="utf-8")
        engagement, job, stored = self.preclaim_case
        setup = json.loads(self.helper("-I", "-c", source, python=True, stdin=canonical({
            "admission": admission, "engagement_id": engagement, "job_id": job,
            "case": stored["spec"], "execution": EXECUTION,
        })))
        require(set(setup) == {"schema", "kind", "selected", "closed"}
                and setup["schema"] == "vardr.nm2-preclaim-setup/1" and setup["kind"] == "trusted_synthetic",
                "launch_preclaim_setup_invalid")
        closed = setup["closed"]
        require(closed["phase"] == "failed" and closed["status"] == "not_claimed"
                and closed["claim_state"] == closed["selection_state"] == "preclaim_retired"
                and closed["failure_reason"] == "local_preclaim_denied_before_rpc"
                and re.fullmatch(r"[0-9a-f]{32}", closed["run_id"]) is not None
                and re.fullmatch(r"[0-9a-f]{64}", closed["tombstone_sha256"]) is not None,
                "launch_preclaim_setup_invalid")
        self.preclaim_run_id, self.preclaim_tombstone = closed["run_id"], closed["tombstone_sha256"]
        audit = self.worker_state(admission, expected_held="closed_preclaim")
        require(audit["status"] == "held" and audit["reason"] == "runtime_unretired"
                and audit["complete"] is True and audit["global_holds"] == 0
                and audit["parent"] == {"state": "idle", "last_sequence": "0", "head_sequence": None, "active_sequence": None}
                and audit["counts"] == {"attempts": 0, "selections": 1, "associated_runs": 1, "associated_claims": 1},
                "launch_preclaim_parent_not_held")
        records = records_for(self.install, str(self.private), existing=True)
        store = IntentStore(records)
        def catalog():
            with records.operation() as operation:
                value = store.inventory(operation=operation)
                _public_inventory(self.public_root, value)
            return value
        original, resources = catalog(), self.snapshot()
        self.receipt["stage"] = "launch_preclaim_refuse_successor"
        expect_unresolved_launch(self.launch_arguments(config, signing, binding, self.successor_id),
                                 self.successor_id, cwd=self.install, env=self.environment, stdin=self.password + "\n")
        observer.confirm_exit(proof)
        require(canonical(catalog()) == canonical(original) and canonical(self.snapshot()) == canonical(resources)
                and self.read_preclaim_snapshot()["tombstone_sha256"] == self.preclaim_tombstone
                and canonical(self.preclaim_unissued()) == canonical(self.preclaim_inventory),
                "launch_preclaim_refusal_changed_state")
        self.receipt["preclaim_recovery"] = {
            "setup_kind": "trusted_synthetic", "marker": "local_preclaim_denied_before_rpc",
            "failure_phase": "launch_catalog", "failure_code": "validation_refused",
            "refused_runtime_id": self.successor_id, "new_resources": 0, "target_requests": 0,
            "targets_spent": 0, "duration_allocated": 0, "capacity_before": 0, "capacity_after": 0,
            "issued_attempts": 0, "retained_tombstones": 1, "last_sequence": "0",
            "tombstone_before_sha256": self.preclaim_tombstone,
        }

    def reconcile_preclaim_recovery(self, admission, retired):
        self.receipt["stage"] = "launch_preclaim_reconcile"
        require(retired["last_sequence"] == "0" and retired["runtime_sequence"] is None
                and retired["binding"] is None and retired["attempt_receipt"] is None, "launch_preclaim_retirement_invalid")
        binding = {key: admission[key] for key in ("runner_id", "runtime_id", "runtime_sha256", "admission_sha256")}
        selectors = [value for key, item in binding.items() for value in ("--" + key.replace("_", "-"), item)]
        reply = json.loads(self.helper("worker-reconcile", "--journal", "/home/runner/.vardrmap/runner-journal.sqlite3",
                                      "--identity", "/home/runner/.vardrmap/runner-identity.json", *selectors))
        require(reply["schema"] == "vardr.worker-reconciliation/1" and reply["status"] == "reconciled"
                and reply["complete"] is True and reply["binding"] == binding
                and reply["selected_run_id"] == self.preclaim_run_id and reply["selected_sequence"] == "1"
                and reply["reconciliation_state"] == "terminal_preclaim_parent_retired"
                and reply["remaining_local_holds"] == 0 and reply["retirement_receipt_sha256"] == retired["receipt_sha256"],
                "launch_preclaim_original_reconciliation_missing")
        audit = self.worker_state(admission)
        require(audit["status"] == "retired" and audit["complete"] is True and audit["binding"] == binding
                and audit["global_holds"] == 0 and audit["retirement_receipt_sha256"] == retired["receipt_sha256"]
                and audit["parent"] == {"state": "retired", "last_sequence": "0", "head_sequence": None, "active_sequence": None}
                and audit["counts"] == {"attempts": 0, "selections": 1, "associated_runs": 1, "associated_claims": 1}
                and self.read_preclaim_snapshot()["tombstone_sha256"] == self.preclaim_tombstone
                and canonical(self.preclaim_unissued()) == canonical(self.preclaim_inventory), "launch_preclaim_source_changed")
        self.receipt["preclaim_recovery"].update(
            tombstone_after_sha256=self.preclaim_tombstone, audit_sha256=digest(canonical(audit)),
            retirement_sha256=retired["receipt_sha256"], host_retirement_sha256=digest(canonical(retired)),
            remaining_local_holds=0, reconciliation_state=reply["reconciliation_state"],
        )

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
    workload.add_argument("--concurrency-exhaustion", action="store_true")
    workload.add_argument("--stopped-predecessor", action="store_true")
    workload.add_argument("--pid1-loss", action="store_true",
                          help="Explicit owner-approved C08 paired PID1-loss acceptance route")
    workload.add_argument("--map-disconnect", action="store_true")
    workload.add_argument("--claim-reply-loss", action="store_true")
    workload.add_argument("--result-reply-loss", action="store_true")
    workload.add_argument("--finish-reply-loss", action="store_true")
    workload.add_argument("--consume-reply-loss", action="store_true")
    workload.add_argument("--runtime-bind-reply-loss", action="store_true")
    workload.add_argument("--preclaim-recovery", action="store_true")
    workload.add_argument("--repeat-managed-claim", action="store_true")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print("Launch acceptance requires explicit --execute.")
        return 2
    try:
        operation = ("consume" if args.consume_reply_loss else "runtime-bind" if args.runtime_bind_reply_loss
                     else "result" if args.result_reply_loss else "finish" if args.finish_reply_loss else None)
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
            concurrency_exhaustion=args.concurrency_exhaustion,
            stopped_predecessor=args.stopped_predecessor,
            **({"pid1_loss": True} if args.pid1_loss else {}),
            map_disconnect=args.map_disconnect,
            **({"claim_reply_loss": True} if args.claim_reply_loss else {}),
            **({"reply_loss_operation": operation} if operation is not None else {}),
            preclaim_recovery=args.preclaim_recovery,
            repeat_managed_claim=args.repeat_managed_claim,
        )
        fixture.run()
        expected = (
            "selected_terminal_reply_loss_slice_passed" if args.result_reply_loss or args.finish_reply_loss else
            "selected_" + operation.replace("-", "_") + "_reply_loss_slice_passed" if operation is not None else
            CLAIM_REPLY_LOSS_PASS if args.claim_reply_loss else
            DURATION_PASS if args.duration_exhaustion else
            TARGET_PASS if args.target_exhaustion else
            CONCURRENCY_PASS if args.concurrency_exhaustion else
            MAP_DISCONNECT_PASS if args.map_disconnect else "selected_launch_slice_passed"
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
