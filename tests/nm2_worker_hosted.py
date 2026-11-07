"""Opt-in fresh GitHub-hosted Ubuntu execution of the existing NM-2 harness.

No execution occurs without --execute. Inputs select exact public source commits,
not product pins. Raw output and fixture custody never enter the public receipt.
"""

import argparse
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import socket
import stat
import subprocess
import sys
import time
from urllib.parse import parse_qs, urlsplit
import uuid

SOURCE = Path(__file__).resolve().parents[1]
# Direct script execution (including -I) puts only tests/ on the import path.
# Root helpers must come from this exact source tree, never the caller's cwd.
sys.path.insert(0, str(SOURCE))
BRANCH = "refs/heads/codex/nm1-nm2-closeout"
LAUNCH_SCENARIO = "persistent-launch-empty"
LAUNCH_COMPLETED_SCENARIO = "persistent-launch-completed"
LAUNCH_SCENARIOS = {LAUNCH_SCENARIO, LAUNCH_COMPLETED_SCENARIO}
LAUNCH_SCHEMA = "vardr.nm2-worker-launch-acceptance/1"
COMPOSE_ASSET = "https://github.com/docker/compose/releases/download/v5.6.1/docker-compose-linux-x86_64"
COMPOSE_SHA256 = "47737f4236e6d3ccea7291995203f8f018058783b4c3a9469119811a0b5db8c0"
COMPOSE_BYTES = 32676477
PERSISTENT_SCENARIOS = {"persistent-availability", "persistent-count-limit", "persistent-idle-limit", "persistent-empty-stop", *LAUNCH_SCENARIOS}
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
    "healthy_sequence",
    "missing_local_grant",
}
REMAINING_REQUIRED_CASES = (
    "strict_other_denials",
    "missing_local_grant",
    "local_emergency_stop",
    "engagement_stop_work",
    "target_grant_expiry_revocation",
    "budget_exhaustion",
    "map_disconnect",
    "worker_crash_stop",
    "lost_claim_consume_bind_reply",
    "restart_duplicate_claim",
    "lost_terminal_reply",
)
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
    "launch_compose_pin",
    "harness",
    "complete",
}
_CLI_FAILURE_PHASES = {
    "arguments",
    "installation",
    "dispatch",
    "launch_inputs", "launch_preflight", "launch_intent", "launch_resources",
    "launch_create", "launch_start",
    "launch_core_inventory", "launch_state_inventory", "launch_network_inventory",
    "launch_readiness_inventory", "launch_compose_inventory", "launch_catalog",
    "launch_audit_image", "launch_audit_run", "launch_audit_recheck",
    "enable_inputs",
    "enable_observer_setup",
    "enable_api_setup",
    "enable_custody",
    "enable_owner_auth",
    "enable_capture",
    "enable_capture_daemon",
    "enable_capture_inspect",
    "enable_capture_identity",
    "enable_capture_mounts",
    "enable_capture_tmpfs",
    "enable_capture_profile",
    "enable_capture_volume_metadata",
    "enable_capture_running_state",
    "enable_capture_readiness_copy",
    "enable_capture_readiness_archive",
    "enable_capture_readiness_schema",
    "enable_capture_incarnation_recheck",
    "enable_registration",
    "enable_publication_checks",
    "enable_recapture",
    "enable_mount_custody",
    "enable_publish_trust",
    "enable_publish_admission",
}
_CLI_FAILURE_CODES = {
    "validation_refused",
    "runtime_refused",
    "host_refused",
    "secret_custody_refused",
    "local_io_failed",
    "operation_failed",
    "interrupted",
}
_BINDING = {
    "origin",
    "job_id",
    "runner_id",
    "contract_id",
    "attempt_id",
    "fence",
    "contract_sha256",
}
_ATTEMPT = {
    "runtime_sequence",
    "engagement_id",
    "job_id",
    "case_sha256",
    "evidence_count",
    "evidence_sha256",
    "artifact_sha256",
    "result_receipt_sha256",
    "terminal_receipt_sha256",
    "release_receipt_sha256",
    "native_done_sha256",
    "bound_at",
    "confirmed_at",
    "released_at",
    "binding",
    "terminal_receipt",
    "release_receipt",
    "requests",
    "assessment",
    "target_charge",
    "duration_seconds",
    "capacity_reserved",
}


class HostedRefused(ValueError):
    pass


def require(value):
    if not value:
        raise HostedRefused("nm2_hosted_prerequisite_refused")


def _hash(value):
    require(type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value))
    return value


def _digest(value):
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _fields(value, names):
    require(type(value) is dict and set(value) == names)
    return value


def _same(first, second):
    require(_digest(first) == _digest(second))


def _identifier(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value))
    return value


def _uuid(value):
    require(type(value) is str)
    try:
        require(str(uuid.UUID(value)) == value)
    except ValueError:
        raise HostedRefused("nm2_hosted_prerequisite_refused") from None
    return value


def _time(value):
    require(
        type(value) is str
        and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z", value)
    )
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise HostedRefused("nm2_hosted_prerequisite_refused") from None


def _physical_time(value):
    require(type(value) is str)
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z", value)
    require(match is not None)
    try:
        # Python 3.10 accepts only three/six fractional digits. Validate the
        # calendar at whole-second precision, then retain all Docker nanoseconds
        # in the fixed-width ordering key below.
        datetime.fromisoformat(match[1] + "+00:00")
    except ValueError:
        raise HostedRefused("nm2_hosted_prerequisite_refused") from None
    return match[1] + "." + (match[2] or "").ljust(9, "0") + "Z"


def _requests(rows):
    require(type(rows) is list and len(rows) == 5)
    identities, paths, markers = [], [], set()
    for row in rows:
        require(type(row) is dict and row.get("method") == "GET")
        require(row.get("identity") in {"owner", "peer", "anonymous"})
        path = row.get("path")
        require(type(path) is str and len(path) <= 2048)
        parsed = urlsplit(path)
        require(not parsed.scheme and not parsed.netloc and not parsed.fragment)
        marker = parse_qs(parsed.query).get("nm2_case")
        require(type(marker) is list and len(marker) == 1)
        markers.add(_identifier(marker[0]))
        identities.append(row["identity"])
        paths.append(parsed.path)
    require(sorted(identities) == ["anonymous", "owner", "owner", "peer", "peer"])
    require(
        paths.count("/session") == 2
        and paths.count("/fixed/records/42") == 3
        and len(markers) == 1
    )
    return next(iter(markers))


def _sequence(raw, selection):
    happy, sequence = raw["cases"]["happy_fixed"], raw["cases"]["healthy_sequence"]
    _fields(
        sequence,
        {
            "status",
            "physical",
            "runtime_id",
            "runtime_sha256",
            "max_attempts",
            "last_sequence",
            "active_sequence",
            "attempts",
            "target_request_count",
            "evidence_count",
            "targets_spent",
            "duration_allocated",
        },
    )
    for key, expected in (
        ("max_attempts", 2),
        ("last_sequence", 2),
        ("target_request_count", 10),
        ("evidence_count", 10),
        ("targets_spent", 2),
        ("duration_allocated", 60),
    ):
        require(type(sequence[key]) is int and sequence[key] == expected)
    require(sequence["status"] == "passed" and sequence["active_sequence"] is None)
    physical = _fields(
        sequence["physical"],
        {
            "identity",
            "runtime_id",
            "runtime_sha256",
            "exit_code",
            "finished_at",
            "operator_enable_state",
        },
    )
    _same(physical, happy.get("physical"))
    identity = _fields(
        physical["identity"],
        {
            "daemon_id",
            "container_id",
            "image_id",
            "project",
            "started_at",
            "owner_nonce",
        },
    )
    for key in ("container_id", "owner_nonce"):
        _hash(identity[key])
    _identifier(identity["daemon_id"])
    require(
        identity["image_id"] == selection["images"]["worker"]
        and identity["project"] == selection["project"]
    )
    require(
        type(physical["exit_code"]) is int
        and physical["exit_code"] == 0
        and physical["operator_enable_state"] == "enabled"
    )
    require(
        _physical_time(physical["finished_at"]) > _physical_time(identity["started_at"])
    )
    require(_uuid(sequence["runtime_id"]) == physical["runtime_id"])
    require(
        _hash(sequence["runtime_sha256"])
        == physical["runtime_sha256"]
        == _digest(identity)
    )
    attempts = sequence["attempts"]
    require(type(attempts) is list and len(attempts) == 2)
    runtimes = happy["inventory"].get("runtimes")
    require(type(runtimes) is list and len(runtimes) == 1)
    retained = runtimes[0]
    require(
        type(retained) is dict
        and retained.get("id") == sequence["runtime_id"]
        and retained.get("runtime_sha256") == sequence["runtime_sha256"]
        and type(retained.get("max_attempts")) is int
        and retained["max_attempts"] == 2
        and type(retained.get("last_sequence")) is int
        and retained["last_sequence"] == 2
        and retained.get("active_sequence") is None
        and retained.get("retired") is False
        and retained.get("report_sha256") is None
    )
    _same(retained.get("identity"), identity)
    history = retained.get("attempts")
    require(type(history) is list and len(history) == 2)
    projected, markers, previous_release = [], [], None
    for number, attempt in enumerate(attempts, 1):
        _fields(attempt, _ATTEMPT)
        stored = history[number - 1]
        require(
            type(stored) is dict and stored.get("runtime_id") == sequence["runtime_id"]
        )
        for key in (
            "runtime_sequence",
            "job_id",
            "binding",
            "bound_at",
            "confirmed_at",
            "released_at",
            "terminal_receipt",
            "terminal_receipt_sha256",
            "native_done_sha256",
            "release_receipt",
        ):
            _same(stored.get(key), attempt[key])
        require(
            type(attempt["runtime_sequence"]) is int
            and attempt["runtime_sequence"] == number
        )
        for key in ("engagement_id", "job_id"):
            _identifier(attempt[key])
        for key in (
            "case_sha256",
            "evidence_sha256",
            "artifact_sha256",
            "result_receipt_sha256",
            "terminal_receipt_sha256",
            "release_receipt_sha256",
            "native_done_sha256",
        ):
            _hash(attempt[key])
        for key, expected in (
            ("evidence_count", 5),
            ("target_charge", 1),
            ("duration_seconds", 30),
        ):
            require(type(attempt[key]) is int and attempt[key] == expected)
        require(attempt["capacity_reserved"] is False)
        binding = _fields(attempt["binding"], _BINDING)
        require(
            binding["job_id"] == attempt["job_id"]
            and binding["origin"]
            == f"https://vardrsec.localhost:{selection['https_port']}/backend"
        )
        for key in ("runner_id", "contract_id", "attempt_id"):
            _uuid(binding[key])
        _hash(binding["contract_sha256"])
        require(type(binding["fence"]) is int and 1 <= binding["fence"] <= 2**53 - 1)
        terminal = _fields(
            attempt["terminal_receipt"],
            _BINDING | {"schema", "outcome", "receipt_sha256", "capacity_reserved"},
        )
        _same({key: terminal[key] for key in _BINDING}, binding)
        require(
            terminal["schema"] == "vardr.managed-completion/1"
            and terminal["outcome"] == "completed"
            and terminal["capacity_reserved"] is False
        )
        require(
            terminal["receipt_sha256"]
            == attempt["result_receipt_sha256"]
            == _digest(
                {
                    "schema": "vardr.managed-result/1",
                    **binding,
                    "artifact_sha256": attempt["artifact_sha256"],
                    "case_sha256": attempt["case_sha256"],
                }
            )
        )
        require(attempt["terminal_receipt_sha256"] == _digest(terminal))
        release = _fields(
            attempt["release_receipt"],
            {
                "schema",
                "runtime_id",
                "runtime_sha256",
                "runtime_sequence",
                "binding",
                "terminal_receipt_sha256",
                "native_done_sha256",
                "released",
                "receipt_sha256",
            },
        )
        require(
            release["schema"] == "vardr.worker-idle-release/1"
            and release["released"] is True
            and type(release["runtime_sequence"]) is int
            and release["runtime_sequence"] == number
        )
        require(
            all(
                release[key] == sequence[key]
                for key in ("runtime_id", "runtime_sha256")
            )
        )
        _same(release["binding"], binding)
        require(
            all(
                release[key] == attempt[key]
                for key in ("terminal_receipt_sha256", "native_done_sha256")
            )
        )
        require(
            release["receipt_sha256"]
            == attempt["release_receipt_sha256"]
            == _digest(
                {
                    key: value
                    for key, value in release.items()
                    if key != "receipt_sha256"
                }
            )
        )
        bound, confirmed, released = (
            _time(attempt[key]) for key in ("bound_at", "confirmed_at", "released_at")
        )
        require(
            bound <= confirmed <= released
            and (previous_release is None or previous_release <= bound)
        )
        previous_release = released
        markers.append(_requests(attempt["requests"]))
        assessment = _fields(
            attempt["assessment"],
            {
                "status",
                "baseline_valid",
                "case_snapshot_verified",
                "preflight",
                "case_hash",
                "candidate_findings",
            },
        )
        require(
            assessment["status"] == "conclusive"
            and assessment["baseline_valid"] is True
            and assessment["case_snapshot_verified"] is True
            and assessment["preflight"] == {"status": "passed"}
            and assessment["case_hash"] == attempt["case_sha256"]
            and type(assessment["candidate_findings"]) is int
            and assessment["candidate_findings"] == 0
        )
        projected.append(
            {
                "runtime_sequence": number,
                "target_request_count": 5,
                "evidence_count": 5,
                **{
                    key: attempt[key]
                    for key in (
                        "case_sha256",
                        "evidence_sha256",
                        "artifact_sha256",
                        "result_receipt_sha256",
                        "terminal_receipt_sha256",
                        "release_receipt_sha256",
                        "native_done_sha256",
                    )
                },
            }
        )
    require(len(set(markers)) == 2)
    for attempt in attempts:
        require(
            all(
                type(row.get("received_monotonic_ns")) is int
                and row["received_monotonic_ns"] > 0
                for row in attempt["requests"]
            )
        )
    require(
        max(row["received_monotonic_ns"] for row in attempts[0]["requests"])
        <= min(row["received_monotonic_ns"] for row in attempts[1]["requests"])
    )
    for key in (
        "job_id",
        "case_sha256",
        "artifact_sha256",
        "terminal_receipt_sha256",
        "release_receipt_sha256",
    ):
        require(attempts[0][key] != attempts[1][key])
    require(attempts[0]["binding"]["runner_id"] == attempts[1]["binding"]["runner_id"])
    require(
        attempts[0]["binding"]["contract_id"] != attempts[1]["binding"]["contract_id"]
        and attempts[0]["binding"]["attempt_id"] != attempts[1]["binding"]["attempt_id"]
    )
    _same(happy["requests"], attempts[0]["requests"])
    require(
        all(
            happy[key] == attempts[0][key]
            for key in ("case_sha256", "evidence_sha256", "evidence_count")
        )
    )
    result = happy["inventory"]["results"][0]
    require(
        result["contract_id"] == attempts[0]["binding"]["contract_id"]
        and result["artifact_sha256"] == attempts[0]["artifact_sha256"]
        and result["receipt_sha256"] == attempts[0]["result_receipt_sha256"]
    )
    return {
        "target_request_count": 10,
        "evidence_count": 10,
        "targets_spent": 2,
        "duration_allocated": 60,
        "max_attempts": 2,
        "last_sequence": 2,
        "active_sequence": None,
        "runtime_sha256": sequence["runtime_sha256"],
        "attempts": projected,
    }, identity["container_id"]


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


def execution_options(env):
    scenario = env.get("NM2_SCENARIO", "healthy")
    revision = env.get("NM2_DATABASE_REVISION", "0040runtimesequence")
    require(type(scenario) is str and scenario in {"healthy", *PERSISTENT_SCENARIOS})
    require(
        type(revision) is str
        and revision in {"0040runtimesequence", "0041persistentruntime"}
    )
    require(scenario not in PERSISTENT_SCENARIOS or revision == "0041persistentruntime")
    return scenario, revision


def decode_receipt(data):
    """Bounded evidence JSON: reject duplicate keys and non-finite constants."""
    require(type(data) is bytes and 0 < len(data) <= 4 * 1024 * 1024)

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result

    def invalid_constant(_):
        raise HostedRefused("nm2_hosted_receipt_refused")

    def finite_float(text):
        value = float(text)
        require(math.isfinite(value))
        return value

    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique,
            parse_constant=invalid_constant,
            parse_float=finite_float,
        )
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise HostedRefused("nm2_hosted_receipt_refused") from None


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


def failure_projection(raw, selection):
    """Allow only fixed failure categories; no raw nested receipt data escapes."""
    require(
        type(raw) is dict
        and raw.get("schema")
        in {
            "vardr.nm2-worker-acceptance/1",
            "vardr.nm2-worker-acceptance/2",
            "vardr.nm2-worker-persistent-acceptance/1",
            "vardr.nm2-worker-count-acceptance/1",
            "vardr.nm2-worker-idle-acceptance/1",
            "vardr.nm2-worker-empty-acceptance/1",
            LAUNCH_SCHEMA,
        }
        and raw.get("status") == "held"
        and raw.get("sources") == selection["sources"]
        and raw.get("images") == selection["images"]
        and raw.get("project") == selection["project"]
        and raw.get("platform") == "linux"
    )
    if raw["schema"] == "vardr.nm2-worker-persistent-acceptance/1":
        require(
            raw.get("scenario") == "persistent-availability"
            and raw.get("expected_database_revision") == "0041persistentruntime"
        )
    elif raw["schema"] == "vardr.nm2-worker-count-acceptance/1":
        require(
            raw.get("scenario") == "persistent-count-limit"
            and raw.get("expected_database_revision") == "0041persistentruntime"
        )
    if raw["schema"] == "vardr.nm2-worker-idle-acceptance/1":
        require(raw.get("scenario") == "persistent-idle-limit"
                and raw.get("expected_database_revision") == "0041persistentruntime")
    if raw["schema"] == "vardr.nm2-worker-empty-acceptance/1":
        require(raw.get("scenario") == "persistent-empty-stop"
                and raw.get("expected_database_revision") == "0041persistentruntime")
    if raw["schema"] == LAUNCH_SCHEMA:
        require(raw.get("scenario") in LAUNCH_SCENARIOS
                and raw.get("expected_database_revision") == "0041persistentruntime")
    stages = {
        "launch_prepare", "launch_1", "launch_2", "launch_stop_1", "launch_stop_2",
        "launch_reconcile_completed", "launch_audit_retired",
        "selected_launch_complete",
        "empty_stop_setup", "empty_stop_ready", "empty_operator_stop",
        "empty_stop_reconciliation", "selected_empty_stop_complete",
        "image_sources",
        "core_setup",
        "default_disabled",
        "managed_setup",
        "strict_scope_setup",
        "strict_scope_denial",
        "happy_setup",
        "operator_worker_enable",
        "happy_verification",
        "healthy_sequence_verification",
        "initial_complete",
        "persistent_idle",
        "persistent_job_approval",
        "persistent_job_release",
        "persistent_operator_stop",
        "persistent_exit_observation",
        "persistent_exit_binding",
        "idle_control_setup", "idle_control_release", "idle_control_observation",
        "idle_control_unchanged", "idle_control_reconciliation",
        "selected_idle_control_complete",
        "count_control_setup",
        "count_control_release",
        "count_control_local_release",
        "count_control_eligibility",
        "count_control_reconciliation",
        "count_control_verification",
        "selected_count_control_complete",
        "persistent_receipt_reconciliation",
        "persistent_availability_verification",
        "selected_availability_complete",
    }
    reasons = {
        "launch_preexisting_worker", "launch_unexpected_target_traffic",
        "launch_enable_not_observed", "launch_admission_not_bound",
        "launch_intent_not_observed", "launch_durable_chain_not_observed",
        "launch_exact_exit_not_observed", "launch_empty_retirement_not_observed",
        "launch_preservation_or_traffic_not_observed",
        "launch_retirement_not_observed", "launch_completed_job_not_done",
        "launch_completed_reconciliation_not_observed", "launch_completed_enrollment_changed",
        "launch_completed_job_not_pending", "launch_completed_audit_changed",
        "launch_completed_audit_not_observed",
        "empty_audit_volume_not_bound", "empty_audit_volume_changed",
        "empty_local_state_not_proven", "empty_map_inventory_not_empty",
        "empty_target_traffic_not_empty", "empty_operator_stop_not_proven",
        "empty_physical_stop_not_bound", "empty_retirement_not_unbound",
        "empty_host_receipt_changed",
        "fixture_http_status",
        "idle_baseline_not_empty", "idle_job_not_completed",
        "idle_complete_traffic_changed", "idle_initial_readiness_missing",
        "idle_native_exit_not_observed", "idle_observation_budget_changed",
        "idle_executed_or_changed_work", "idle_native_exit_not_proven",
        "idle_host_receipt_changed", "idle_original_reconciliation_held",
        "idle_status_refused",
        "count_baseline_not_empty",
        "count_complete_traffic_changed",
        "count_enrollment_changed",
        "count_first_authority_not_fresh",
        "count_first_job_not_proven",
        "count_history_changed",
        "count_host_receipt_changed",
        "count_incarnation_or_policy_changed",
        "count_job_not_completed",
        "count_original_receipt_changed",
        "count_registered_context_changed",
        "count_original_reconciliation_held",
        "count_retirement_changed",
        "count_second_job_not_eligible",
        "count_second_job_was_issued",
        "count_self_exit_not_proven",
        "count_self_exit_scope_refused",
        "fixture_stage_failed",
        "fixture_command_failed",
        "happy_worker_exit_not_clean",
        "happy_terminal_receipt_missing",
        "happy_retained_allowance_mismatch",
        "happy_fixed_traffic_mismatch",
        "image_source_inventory_mismatch",
        "normal_database_readiness_required",
        "actual_owner_readiness_not_observed",
        "operator_enable_not_bound",
        "fixture_marker_invalid",
        "operator_sequence_mode_not_bound",
        "happy_case_traffic_binding_mismatch",
        "fixed_runtime_attempt_missing",
        "fixed_runtime_attempt_unreleased",
        "fixed_runtime_attempt_binding_mismatch",
        "fixed_runtime_attempt_hash_invalid",
        "fixed_full_completion_not_proven",
        "fixed_runtime_release_not_proven",
        "fixed_result_receipt_hash_mismatch",
        "healthy_sequence_enrollment_changed",
        "healthy_sequence_total_traffic_mismatch",
        "healthy_sequence_count_mismatch",
        "healthy_sequence_snapshot_mismatch",
        "healthy_sequence_incarnation_mismatch",
        "healthy_sequence_runtime_not_idle",
        "healthy_sequence_history_mismatch",
        "healthy_sequence_measurement_mismatch",
        "healthy_sequence_timestamp_invalid",
        "healthy_sequence_attempt_order_invalid",
        "healthy_sequence_release_after_next_binding",
        "healthy_sequence_marker_reused",
        "healthy_sequence_request_clock_invalid",
        "healthy_sequence_request_order_invalid",
        "healthy_sequence_allowance_mismatch",
        "healthy_sequence_reused_job_id",
        "healthy_sequence_reused_engagement_id",
        "healthy_sequence_reused_case_sha256",
        "healthy_sequence_reused_artifact_sha256",
        "healthy_sequence_reused_result_receipt_sha256",
        "healthy_sequence_reused_terminal_receipt_sha256",
        "healthy_sequence_reused_release_receipt_sha256",
        "healthy_sequence_reused_native_done_sha256",
        "operator_persistent_mode_not_bound",
        "persistent_allowance_mismatch",
        "persistent_approval_missing",
        "persistent_approval_not_fresh",
        "persistent_availability_disabled",
        "persistent_availability_measurement_missing",
        "persistent_enrollment_changed",
        "persistent_history_incomplete",
        "persistent_host_receipt_changed",
        "persistent_idle_executed_work",
        "persistent_idle_not_empty",
        "persistent_idle_not_observed",
        "persistent_incarnation_or_policy_changed",
        "persistent_job_or_local_ack_mismatch",
        "persistent_local_grant_not_fresh",
        "persistent_local_job_changed",
        "persistent_observed_request_order_invalid",
        "persistent_operator_stop_not_proven",
        "persistent_original_ack_not_closed",
        "persistent_original_journal_not_closed",
        "persistent_original_reconciliation_held",
        "persistent_release_after_next_binding",
        "persistent_request_marker_invalid",
        "persistent_request_marker_reused",
        "persistent_retirement_receipt_changed",
        "persistent_retirement_rewrote_job",
        "persistent_status_identity_changed",
        "persistent_status_refused",
        "persistent_stop_exit_changed",
        "persistent_total_traffic_mismatch",
        "persistent_unapproved_job_executed",
        *{
            "persistent_reused_" + name
            for name in (
                "job_id",
                "engagement_id",
                "case_sha256",
                "artifact_sha256",
                "result_receipt_sha256",
                "terminal_receipt_sha256",
                "release_receipt_sha256",
                "native_done_sha256",
            )
        },
    }
    value = {
        "stage": raw.get("stage") if raw.get("stage") in stages else "unclassified",
        "reason": raw.get("reason")
        if raw.get("reason") in reasons
        else "unclassified_refusal",
    }
    command_failure = raw.get("command_failure")
    if (
        value["reason"] == "fixture_command_failed"
        and type(command_failure) is dict
        and set(command_failure)
        in (
            {"failure_phase", "failure_code"},
            {"failure_phase", "failure_code", "registration_failure"},
        )
        and type(command_failure["failure_phase"]) is str
        and command_failure["failure_phase"] in _CLI_FAILURE_PHASES
        and type(command_failure["failure_code"]) is str
        and command_failure["failure_code"] in _CLI_FAILURE_CODES
    ):
        diagnostic = dict(command_failure)
        if "registration_failure" in diagnostic:
            from worker_host import registration_detail

            detail = registration_detail(diagnostic["registration_failure"])
            if (
                diagnostic["failure_phase"] != "enable_registration"
                or diagnostic["failure_code"] != "host_refused"
                or detail is None
            ):
                diagnostic = None
            else:
                diagnostic["registration_failure"] = detail
        if diagnostic is not None:
            value["command_failure"] = diagnostic
    status_failure = raw.get("status_failure")
    if (
        value["reason"] in {"persistent_status_refused", "idle_status_refused"}
        and type(status_failure) is dict
        and set(status_failure) == {"checkpoint"}
        and type(status_failure["checkpoint"]) is str
        and status_failure["checkpoint"]
        in {
            "admission",
            "subprocess",
            "output",
            "identity",
            "lookup",
            "cursor",
            "presence",
            "freshness",
            "advisory",
            "readiness",
            "unclassified",
        }
    ):
        value["status_failure"] = dict(status_failure)
    failure = raw.get("http_failure")
    if (
        type(failure) is dict
        and failure.get("method") in {"GET", "POST", "PUT", "DELETE", "PATCH"}
        and all(
            type(failure.get(k)) is int and 100 <= failure[k] <= 599
            for k in ("actual_status", "expected_status")
        )
    ):
        routes = {
            "/jobs/{id}/managed/approval/review",
            "/jobs/{id}/managed/approval/register",
            "/jobs/managed/pending",
            "/engagements",
            "/auth/local/login",
        }
        value["http_failure"] = {
            **{k: failure[k] for k in ("method", "actual_status", "expected_status")},
            "route": failure.get("route")
            if failure.get("route") in routes
            else "other_route",
        }
    return value


def launch_projection(raw, selection):
    scenario = raw.get("scenario")
    require(type(scenario) is str and scenario in LAUNCH_SCENARIOS)
    completed = scenario == LAUNCH_COMPLETED_SCENARIO
    scope = "completed_then_next_launch" if completed else "first_and_next_empty_launch"
    require(
        raw.get("expected_database_revision") == "0041persistentruntime"
        and raw.get("acceptance_scope") == scope
        and raw.get("status") == "selected_launch_slice_passed"
        and raw.get("stage") == "selected_launch_complete"
        and raw.get("retained") is True and raw.get("platform") == "linux"
        and raw.get("nm2_exit_status") == "incomplete"
        and raw.get("sources") == selection["sources"]
        and raw.get("images") == selection["images"]
        and raw.get("project") == selection["project"]
    )
    pair = raw["launch_pair"]
    require(type(pair) is list and len(pair) == 2)
    fields = {"ordinal", "runtime_id", "container_id", "started_at", "finished_at",
              "intent_sha256", "retirement_sha256", "predecessor_cids",
              "bootstrap_audit_sha256", "runner_state_sha256"}
    for ordinal, row in enumerate(pair, 1):
        require(type(row) is dict and set(row) == fields and type(row["ordinal"]) is int
                and row["ordinal"] == ordinal
                and _physical_time(row["started_at"]) < _physical_time(row["finished_at"]))
        _uuid(row["runtime_id"])
        for key in ("container_id", "intent_sha256", "retirement_sha256", "runner_state_sha256"):
            _hash(row[key])
    first, second = pair
    _hash(first["bootstrap_audit_sha256"])
    require(
        first["predecessor_cids"] == []
        and second["predecessor_cids"] == [first["container_id"]]
        and second["bootstrap_audit_sha256"] is None
        and first["runtime_id"] != second["runtime_id"]
        and first["container_id"] != second["container_id"]
        and first["runner_state_sha256"] == second["runner_state_sha256"]
        and _physical_time(first["finished_at"]) < _physical_time(second["started_at"])
    )
    result = {"launch_pair": pair, "nm2_exit_status": "incomplete", "resources_retained": True}
    if completed:
        proof = raw.get("completed_job")
        require(
            type(proof) is dict
            and set(proof) == {"job_id", "retirement_sha256", "audit_sha256",
                               "target_requests", "fixed_evidence_sha256"}
            and type(proof["target_requests"]) is int and proof["target_requests"] == 5
            and proof["retirement_sha256"] == first["retirement_sha256"]
        )
        _uuid(proof["job_id"])
        _hash(proof["audit_sha256"])
        _hash(proof["fixed_evidence_sha256"])
        result["completed_job"] = proof
    else:
        require("completed_job" not in raw)
    return result


def public_projection(raw, selection):
    """Project only fixed statuses and measured hashes, never raw nested data."""
    if type(raw) is dict and raw.get("schema") == LAUNCH_SCHEMA:
        return launch_projection(raw, selection)
    if type(raw) is dict and raw.get("schema") == "vardr.nm2-worker-empty-acceptance/1":
        from nm2_worker_empty_projection import project
        try:
            return project(raw, selection)
        except (ValueError, TypeError, KeyError, IndexError):
            raise HostedRefused("nm2_hosted_empty_receipt_refused") from None
    if type(raw) is dict and raw.get("schema") == "vardr.nm2-worker-idle-acceptance/1":
        from nm2_worker_idle_projection import project
        try:
            return project(raw, selection)
        except (ValueError, TypeError, KeyError, IndexError):
            raise HostedRefused("nm2_hosted_idle_receipt_refused") from None
    if type(raw) is dict and raw.get("schema") == "vardr.nm2-worker-count-acceptance/1":
        from nm2_worker_count_projection import project

        try:
            return project(raw, selection)
        except (ValueError, TypeError, KeyError, IndexError):
            raise HostedRefused("nm2_hosted_count_receipt_refused") from None
    if (
        type(raw) is dict
        and raw.get("schema") == "vardr.nm2-worker-persistent-acceptance/1"
    ):
        from nm2_worker_persistent_projection import project

        try:
            return project(raw, selection)
        except (ValueError, TypeError, KeyError, IndexError):
            raise HostedRefused("nm2_hosted_persistent_receipt_refused") from None
    require(
        type(raw) is dict
        and raw.get("schema") == "vardr.nm2-worker-acceptance/2"
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
    require(observed["missing_local_grant"] == "not_run")
    disabled = cases["default_disabled"]
    require(
        type(disabled.get("services")) is list
        and sorted(disabled["services"]) == ["api", "db", "proxy", "web"]
    )
    for key, expected in (
        ("managed_pending_status", 404),
        ("csrf_write_status", 403),
        ("unauthenticated_read_status", 401),
    ):
        require(type(disabled.get(key)) is int and disabled[key] == expected)
    denied = cases["strict_out_of_scope"]
    require(
        type(denied.get("approval_http_status")) is int
        and denied["approval_http_status"] == 409
        and type(denied.get("traffic_delta")) is int
        and denied["traffic_delta"] == 0
    )
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
    sequence, worker_container = _sequence(raw, selection)
    require(len(containers) == 6 and worker_container in containers)
    measurements = {
        **sequence,
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
        self.scenario, self.database_revision = execution_options(env)
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
            "schema": "vardr.nm2-hosted/2",
            "status": "held",
            "stage": "host",
            "sources": self.pins,
            "source_trees": {},
            "images": {},
            "scope": "Two healthy jobs in one explicit runtime; remaining NM2 cases are not acceptance",
            "remaining_required_cases": dict.fromkeys(
                REMAINING_REQUIRED_CASES, "not_run"
            ),
        }
        if self.scenario == "persistent-availability":
            self.receipt.update(
                schema="vardr.nm2-hosted/3",
                scenario=self.scenario,
                expected_database_revision=self.database_revision,
                scope="Persistent idle availability and 35 separately authorized jobs in one explicitly stopped incarnation; NM2 remains incomplete",
            )
        elif self.scenario == "persistent-empty-stop":
            self.receipt.update(schema="vardr.nm2-hosted/6", scenario=self.scenario,
                expected_database_revision=self.database_revision,
                scope="Explicit zero-issued-job stop with offline empty audit; NM2 remains incomplete")
        elif self.scenario in LAUNCH_SCENARIOS:
            self.receipt.update(
                schema="vardr.nm2-hosted/7", scenario=self.scenario,
                expected_database_revision=self.database_revision,
                scope=(
                    "Complete and reconcile one approved job before subsequent launch"
                    if self.scenario == LAUNCH_COMPLETED_SCENARIO
                    else "First and next worker launch, physical stop and zero-job reconciliation"
                ),
            )
        elif self.scenario == "persistent-idle-limit":
            self.receipt.update(schema="vardr.nm2-hosted/5", scenario=self.scenario,
                expected_database_revision=self.database_revision,
                scope="Optional native60s idle control after one reviewed job; NM2 remains incomplete")
        elif self.scenario == "persistent-count-limit":
            self.receipt.update(
                schema="vardr.nm2-hosted/4",
                scenario=self.scenario,
                expected_database_revision=self.database_revision,
                scope="Optional persistent count-one control in one self-exited incarnation; NM2 remains incomplete",
            )

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

    def launch_harness(self, path):
        self.receipt["stage"] = "launch_compose_pin"
        compose = self.root / "docker-compose-5.6.1"
        self.command(
            ["curl", "--fail", "--location", "--proto", "=https", "--max-time", "90",
             "--max-filesize", str(COMPOSE_BYTES), "--output", str(compose), COMPOSE_ASSET],
            timeout=95,
        )
        require(compose.stat().st_size == COMPOSE_BYTES
                and hashlib.sha256(compose.read_bytes()).hexdigest() == COMPOSE_SHA256)
        compose.chmod(0o700)
        config = self.root / "home" / ".docker"
        config.mkdir(mode=0o700, exist_ok=True)
        require(config.is_dir() and not config.is_symlink())
        return [
            str(SOURCE / "tests/nm2_worker_launch_acceptance.py"),
            "--cohort", str(path), "--compose-executable", str(compose),
            "--compose-sha256", COMPOSE_SHA256, "--docker-config", str(config),
            *(["--completed-job"] if self.scenario == LAUNCH_COMPLETED_SCENARIO else []),
            "--execute",
        ]

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
                file=self.sources["runner"]
                / (
                    "Dockerfile.worker.persistent"
                    if self.scenario in PERSISTENT_SCENARIOS
                    else "Dockerfile.worker"
                ),
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
            harness = (
                self.launch_harness(path)
                if self.scenario in LAUNCH_SCENARIOS
                else [
                    str(SOURCE / "tests/nm2_worker_acceptance.py"),
                    "--cohort", str(path), "--scenario", self.scenario,
                    "--database-revision", self.database_revision, "--execute",
                ]
            )
            self.receipt["stage"] = "harness"
            try:
                self.command(
                    [str(python), *harness],
                    timeout=1200 if self.scenario == "persistent-availability" else 900,
                )
            except Exception:
                try:
                    with (self.root / "installation/nm2-worker-receipt.json").open(
                        "rb"
                    ) as handle:
                        failed = handle.read(4 * 1024 * 1024 + 1)
                    require(len(failed) <= 4 * 1024 * 1024)
                    self.receipt["harness_failure"] = failure_projection(
                        decode_receipt(failed), selection
                    )
                except Exception:
                    self.receipt["harness_failure"] = {
                        "stage": "unobserved",
                        "reason": "receipt_unavailable_or_invalid",
                    }
                raise
            with (self.root / "installation/nm2-worker-receipt.json").open(
                "rb"
            ) as handle:
                raw = handle.read(4 * 1024 * 1024 + 1)
            require(len(raw) <= 4 * 1024 * 1024)
            observed = decode_receipt(raw)
            if self.scenario in LAUNCH_SCENARIOS:
                require(observed.get("scenario") == self.scenario)
            require(
                observed.get("expected_database_revision", "0040runtimesequence")
                == self.database_revision
            )
            require(
                observed.get("schema")
                == {
                    "healthy": "vardr.nm2-worker-acceptance/2",
                    "persistent-availability": "vardr.nm2-worker-persistent-acceptance/1",
                    "persistent-count-limit": "vardr.nm2-worker-count-acceptance/1",
                    "persistent-idle-limit": "vardr.nm2-worker-idle-acceptance/1",
                    "persistent-empty-stop": "vardr.nm2-worker-empty-acceptance/1",
                    LAUNCH_SCENARIO: LAUNCH_SCHEMA,
                    LAUNCH_COMPLETED_SCENARIO: LAUNCH_SCHEMA,
                }[self.scenario]
            )
            self.receipt.update(public_projection(observed, selection))
            self.receipt.update(
                schema={
                    "healthy": "vardr.nm2-hosted/2",
                    "persistent-availability": "vardr.nm2-hosted/3",
                    "persistent-count-limit": "vardr.nm2-hosted/4",
                    "persistent-idle-limit": "vardr.nm2-hosted/5",
                    "persistent-empty-stop": "vardr.nm2-hosted/6",
                    LAUNCH_SCENARIO: "vardr.nm2-hosted/7",
                    LAUNCH_COMPLETED_SCENARIO: "vardr.nm2-hosted/7",
                }[self.scenario],
                stage="complete",
                status=observed["status"],
            )
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
        print("NM2 hosted selected slice passed; remaining acceptance stays open")
        return 0
    except Exception:
        print("NM2 hosted held; no acceptance claimed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
