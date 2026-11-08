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
BOOTSTRAP_SCENARIO = "bootstrap-configurations"
BOOTSTRAP_RUNNER = "5ecc869d80f53ae7fdbca25b971838976a6c41e9"
BOOTSTRAP_GATE = "d80d4730b8486b75be72431b5af88e0ddb45020b"
LAUNCH_SCENARIO = "persistent-launch-empty"
LAUNCH_PRECLAIM_SCENARIO = "persistent-launch-preclaim-recovery"
PRECLAIM_HOSTED = "vardr.nm2-hosted/17"
LAUNCH_REPEAT_SCENARIO = "persistent-launch-repeat-managed-claim"
REPEAT_LEGACY_HOSTED = "vardr.nm2-hosted/19"
REPEAT_HOSTED = "vardr.nm2-hosted/25"
LAUNCH_STOPPED_PREDECESSOR_SCENARIO = "persistent-launch-stopped-predecessor"
STOPPED_PREDECESSOR_HOSTED = "vardr.nm2-hosted/11"
LAUNCH_PID1_LOSS_SCENARIO = "persistent-launch-pid1-loss"
PID1_LOSS_HOSTED = "vardr.nm2-hosted/20"
LAUNCH_MAP_DISCONNECT_SCENARIO = "persistent-launch-map-disconnect"
MAP_DISCONNECT_HOSTED = "vardr.nm2-hosted/14"
LAUNCH_CLAIM_REPLY_LOSS_SCENARIO = "persistent-launch-claim-reply-loss"
CLAIM_REPLY_LOSS_HOSTED = "vardr.nm2-hosted/18"
LAUNCH_CONSUME_REPLY_LOSS_SCENARIO = "persistent-launch-consume-reply-loss"
LAUNCH_BIND_REPLY_LOSS_SCENARIO = "persistent-launch-runtime-bind-reply-loss"
LAUNCH_RESULT_REPLY_LOSS_SCENARIO = "persistent-launch-result-reply-loss"
LAUNCH_FINISH_REPLY_LOSS_SCENARIO = "persistent-launch-finish-reply-loss"
REPLY_LOSS_OPERATIONS = {LAUNCH_CLAIM_REPLY_LOSS_SCENARIO: "claim",
    LAUNCH_CONSUME_REPLY_LOSS_SCENARIO: "consume", LAUNCH_BIND_REPLY_LOSS_SCENARIO: "runtime-bind",
    LAUNCH_RESULT_REPLY_LOSS_SCENARIO: "result", LAUNCH_FINISH_REPLY_LOSS_SCENARIO: "finish"}
REPLY_LOSS_HOSTED = {LAUNCH_CLAIM_REPLY_LOSS_SCENARIO: CLAIM_REPLY_LOSS_HOSTED,
    LAUNCH_CONSUME_REPLY_LOSS_SCENARIO: "vardr.nm2-hosted/21", LAUNCH_BIND_REPLY_LOSS_SCENARIO: "vardr.nm2-hosted/22",
    LAUNCH_RESULT_REPLY_LOSS_SCENARIO: "vardr.nm2-hosted/23", LAUNCH_FINISH_REPLY_LOSS_SCENARIO: "vardr.nm2-hosted/24"}
LAUNCH_COMPLETED_SCENARIO = "persistent-launch-completed"
LAUNCH_STOP_WORK_SCENARIO = "persistent-launch-stop-work"
LAUNCH_STOP_WORK_QUEUED_SCENARIO = "persistent-launch-stop-work-queued"
LAUNCH_LOCAL_STOP_SCENARIO = "persistent-launch-local-stop"
LAUNCH_MISSING_GRANT_SCENARIO = "persistent-launch-missing-grant"
LAUNCH_GRANT_REVOKE_SCENARIO = "persistent-launch-grant-revocation"
LAUNCH_EXPIRED_GRANT_SCENARIO = "persistent-launch-expired-grant"
LAUNCH_ACTIVE_GRANT_EXPIRY_SCENARIO = "persistent-launch-active-grant-expiry"
LAUNCH_DURATION_SCENARIO = "persistent-launch-duration-exhaustion"
LAUNCH_TARGET_SCENARIO = "persistent-launch-target-exhaustion"
LAUNCH_CONCURRENCY_SCENARIO = "persistent-launch-concurrency-exhaustion"
DURATION_MAP_COMMIT = "40bf4e37076d6a85648f817dd8b6bc69104bd863"
TARGET_MAP_COMMIT = "41635f9a75598c84192b4b53be95e025bf0b9b9d"
CONCURRENCY_MAP_COMMIT = "05dc78cf9a385255de459c8a5b833842d6528a63"
LAUNCH_BUDGETS = {
    LAUNCH_DURATION_SCENARIO: "duration",
    LAUNCH_TARGET_SCENARIO: "target",
    LAUNCH_CONCURRENCY_SCENARIO: "concurrency",
}
LAUNCH_BUDGET_SCHEMAS = {
    LAUNCH_DURATION_SCENARIO: "vardr.nm2-hosted/8",
    LAUNCH_TARGET_SCENARIO: "vardr.nm2-hosted/10",
    LAUNCH_CONCURRENCY_SCENARIO: "vardr.nm2-hosted/12",
}
LAUNCH_GRANT_DENIAL_SCENARIOS = {LAUNCH_MISSING_GRANT_SCENARIO, LAUNCH_EXPIRED_GRANT_SCENARIO}
LAUNCH_CANCELLATION_SCENARIOS = {
    LAUNCH_STOP_WORK_SCENARIO, LAUNCH_STOP_WORK_QUEUED_SCENARIO, LAUNCH_LOCAL_STOP_SCENARIO,
    LAUNCH_GRANT_REVOKE_SCENARIO, LAUNCH_ACTIVE_GRANT_EXPIRY_SCENARIO,
}
LAUNCH_SCOPES = {
    LAUNCH_SCENARIO: "first_and_next_empty_launch",
    LAUNCH_PRECLAIM_SCENARIO: "trusted_synthetic_closed_preclaim_parent0",
    LAUNCH_REPEAT_SCENARIO: "installed_repeated_managed_claim_exact_stop_and_successor",
    LAUNCH_STOPPED_PREDECESSOR_SCENARIO: "stopped_predecessor_then_next_launch",
    LAUNCH_PID1_LOSS_SCENARIO: "unexpected_pid1_loss_then_next_launch",
    LAUNCH_MAP_DISCONNECT_SCENARIO: "ordinary_map_api_outage",
    LAUNCH_CLAIM_REPLY_LOSS_SCENARIO: "committed_claim_reply_loss",
    LAUNCH_RESULT_REPLY_LOSS_SCENARIO: "committed_result_reply_loss",
    LAUNCH_FINISH_REPLY_LOSS_SCENARIO: "committed_completion_reply_loss",
    LAUNCH_CONSUME_REPLY_LOSS_SCENARIO: "committed_consume_reply_loss",
    LAUNCH_BIND_REPLY_LOSS_SCENARIO: "committed_runtime_bind_reply_loss",
    LAUNCH_COMPLETED_SCENARIO: "completed_then_next_launch",
    LAUNCH_STOP_WORK_SCENARIO: "stop_work_then_next_launch",
    LAUNCH_STOP_WORK_QUEUED_SCENARIO: "stop_work_excludes_queued_job",
    LAUNCH_LOCAL_STOP_SCENARIO: "local_stop_then_next_launch",
    LAUNCH_MISSING_GRANT_SCENARIO: "missing_grant_then_next_launch",
    LAUNCH_GRANT_REVOKE_SCENARIO: "grant_revocation_then_next_launch",
    LAUNCH_EXPIRED_GRANT_SCENARIO: "expired_grant_then_next_launch",
    LAUNCH_ACTIVE_GRANT_EXPIRY_SCENARIO: "active_grant_expiry_then_next_launch",
    LAUNCH_DURATION_SCENARIO: "allocated_duration_exhaustion",
    LAUNCH_TARGET_SCENARIO: "represented_origin_exhaustion",
    LAUNCH_CONCURRENCY_SCENARIO: "shared_engagement_concurrency_exhaustion",
}
LAUNCH_SCENARIOS = set(LAUNCH_SCOPES)
LAUNCH_SCHEMA = "vardr.nm2-worker-launch-acceptance/1"
STRICT_DRIFT_SCENARIO = "strict-authority-drift"
STRICT_DRIFT_SCHEMA = "vardr.nm2-worker-strict-drift-acceptance/1"
STRICT_DRIFT_HOSTED = "vardr.nm2-hosted/9"
STRICT_REVIEW_SCENARIO = "strict-review-authority"
STRICT_REVIEW_SCHEMA = "vardr.nm2-worker-strict-review-acceptance/1"
STRICT_REVIEW_HOSTED = "vardr.nm2-hosted/13"
STRICT_REVIEW_MAP = "05dc78cf9a385255de459c8a5b833842d6528a63"
STALE_CLAIM_SCENARIO = "strict-stale-registered-claim"
STALE_CLAIM_SCHEMA = "vardr.nm2-worker-strict-stale-claim-acceptance/1"
STALE_CLAIM_HOSTED = "vardr.nm2-hosted/15"
STALE_CLAIM_MAP = "ebb1bc8dd6cc0c3215ad468a2dd1c848d812842a"
COMPOSE_ASSET = "https://github.com/docker/compose/releases/download/v5.6.1/docker-compose-linux-x86_64"
COMPOSE_SHA256 = "47737f4236e6d3ccea7291995203f8f018058783b4c3a9469119811a0b5db8c0"
COMPOSE_BYTES = 32676477
PERSISTENT_SCENARIOS = {
    "persistent-availability", "persistent-count-limit", "persistent-idle-limit",
    "persistent-empty-stop", STRICT_DRIFT_SCENARIO, STRICT_REVIEW_SCENARIO,
    STALE_CLAIM_SCENARIO, *LAUNCH_SCENARIOS,
}
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
    "persisted_preclaim_recovery",
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
    "bootstrap_qualification",
    "bootstrap_harness",
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


def _require_budget_source(budget, commit):
    expected = {
        "duration": DURATION_MAP_COMMIT,
        "target": TARGET_MAP_COMMIT,
        "concurrency": CONCURRENCY_MAP_COMMIT,
    }[budget]
    require(expected is not None and commit == expected)


def execution_options(env):
    scenario = env.get("NM2_SCENARIO", "healthy")
    revision = env.get("NM2_DATABASE_REVISION", "0040runtimesequence")
    require(type(scenario) is str and scenario in {"healthy", BOOTSTRAP_SCENARIO, *PERSISTENT_SCENARIOS})
    require(
        type(revision) is str
        and revision in {"0040runtimesequence", "0041persistentruntime"}
    )
    require(scenario not in PERSISTENT_SCENARIOS or revision == "0041persistentruntime")
    if scenario in LAUNCH_BUDGETS:
        _require_budget_source(LAUNCH_BUDGETS[scenario], env.get("NM2_MAP_SHA"))
    if scenario in {LAUNCH_PRECLAIM_SCENARIO, LAUNCH_REPEAT_SCENARIO}:
        require(env.get("NM2_RUNNER_SHA") == "5ecc869d80f53ae7fdbca25b971838976a6c41e9"
                and env.get("NM2_MAP_SHA") == "05dc78cf9a385255de459c8a5b833842d6528a63"
                and env.get("NM2_GATE_SHA") == "d80d4730b8486b75be72431b5af88e0ddb45020b")
    if scenario == STRICT_REVIEW_SCENARIO:
        require(env.get("NM2_MAP_SHA") == STRICT_REVIEW_MAP)
    if scenario == STALE_CLAIM_SCENARIO:
        require(STALE_CLAIM_MAP is not None and env.get("NM2_MAP_SHA") == STALE_CLAIM_MAP)
    if scenario == LAUNCH_MAP_DISCONNECT_SCENARIO:
        from nm2_worker_launch_acceptance import MAP_DISCONNECT_SOURCES

        require(all(env.get("NM2_" + name.upper() + "_SHA") == commit
                    for name, commit in MAP_DISCONNECT_SOURCES.items()))
    if scenario == BOOTSTRAP_SCENARIO:
        require(env.get("NM2_RUNNER_SHA") == BOOTSTRAP_RUNNER
                and env.get("NM2_GATE_SHA") == BOOTSTRAP_GATE)
    if scenario in REPLY_LOSS_OPERATIONS:
        from nm2_worker_launch_acceptance import CLAIM_REPLY_LOSS_SOURCES, POST_CLAIM_REPLY_LOSS_SOURCES
        sources = CLAIM_REPLY_LOSS_SOURCES if REPLY_LOSS_OPERATIONS[scenario] == "claim" else POST_CLAIM_REPLY_LOSS_SOURCES
        require(all(env.get("NM2_" + n.upper() + "_SHA") == v for n, v in sources.items()))
    if scenario == LAUNCH_PID1_LOSS_SCENARIO:
        from nm2_worker_launch_acceptance import PID1_LOSS_SOURCES
        require(all(env.get("NM2_" + name.upper() + "_SHA") == commit
                    for name, commit in PID1_LOSS_SOURCES.items()))
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
            STRICT_DRIFT_SCHEMA, STRICT_REVIEW_SCHEMA, STALE_CLAIM_SCHEMA,
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
    if raw["schema"] in {STRICT_DRIFT_SCHEMA, STRICT_REVIEW_SCHEMA}:
        scenario = STRICT_DRIFT_SCENARIO if raw["schema"] == STRICT_DRIFT_SCHEMA else STRICT_REVIEW_SCENARIO
        require(raw.get("scenario") == scenario
                and raw.get("expected_database_revision") == "0041persistentruntime")
    if raw["schema"] == STALE_CLAIM_SCHEMA:
        require(raw.get("scenario") == STALE_CLAIM_SCENARIO
                and raw.get("expected_database_revision") == "0041persistentruntime")
    if raw["schema"] == LAUNCH_SCHEMA:
        require(raw.get("scenario") in LAUNCH_SCENARIOS
                and raw.get("expected_database_revision") == "0041persistentruntime")
    stages = {
        "launch_claim_loss_proxy_arm", "launch_claim_loss_register",
        "launch_claim_loss_observe", "launch_claim_loss_original_hold",
        "launch_claim_loss_report_exit", "selected_claim_reply_loss_complete",
        "selected_consume_reply_loss_complete", "selected_runtime_bind_reply_loss_complete",
        "launch_prepare", "launch_1", "launch_2", "launch_stop_1", "launch_stop_2",
        "launch_preclaim_setup", "launch_preclaim_refuse_successor", "launch_preclaim_reconcile",
        "launch_predecessor_active", "launch_predecessor_unreported",
        "launch_repeat_managed_claim", "launch_repeat_original_held", "launch_terminal_loss_register", "launch_terminal_loss_observe", "launch_terminal_loss_reconcile",
        "selected_terminal_reply_loss_complete",
        "launch_refuse_unresolved_predecessor", "launch_report_predecessor",
        "launch_host_exit_verification",
        "launch_map_disconnect_active", "launch_map_disconnect_register",
        "launch_map_disconnect_stop_api",
        "launch_map_disconnect_observe_worker", "launch_map_disconnect_journal_after_exit",
        "launch_map_disconnect_start_api",
        "launch_map_disconnect_verify_held", "launch_map_disconnect_report_exit",
        "selected_map_disconnect_complete",
        "launch_reconcile_original", "launch_audit_retired",
        "launch_stop_work_observe", "cancellation_request",
        "launch_stop_work_exit", "launch_stop_work_retirement",
        "launch_stop_work_inventory", "launch_stop_work_local_attempt",
        "launch_stop_work_partial_evidence",
        "launch_missing_grant_observe", "launch_expired_grant_prepare", "launch_expired_grant_observe",
        "launch_grant_revocation_catalog",
        "launch_active_grant_expiry_window", "launch_active_grant_expiry_timing",
        "launch_active_grant_expiry_catalog",
        "launch_duration_prepare_second",
        "launch_duration_observe_refusal",
        "launch_duration_verify_retired",
        "selected_launch_complete",
        "selected_duration_exhaustion_complete",
        "launch_target_prepare_second", "launch_target_observe_refusal",
        "launch_target_verify_retired", "selected_target_exhaustion_complete",
        "launch_concurrency_reserve", "launch_concurrency_observe_refusal",
        "launch_concurrency_finish", "selected_concurrency_exhaustion_complete",
        "empty_stop_setup", "empty_stop_ready", "empty_operator_stop",
        "empty_stop_reconciliation", "selected_empty_stop_complete",
        "image_sources",
        "core_setup",
        "default_disabled",
        "managed_setup",
        "strict_scope_setup",
        "strict_scope_denial",
        "strict_review_missing", "strict_review_expired", "selected_strict_review_complete",
        "strict_stale_claim_register", "strict_stale_claim_mutation", "strict_stale_claim_refusal",
        "selected_strict_stale_claim_complete",
        "strict_authority_drift_setup", "strict_authority_drift_mutation",
        "strict_authority_drift_refusal", "strict_authority_drift_positive_control",
        "selected_strict_drift_complete",
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
        "launch_claim_loss_source_required", "launch_claim_loss_config_required",
        "launch_claim_loss_proxy_identity", "launch_claim_loss_adapter_refused",
        "launch_claim_loss_eligible_before_arm", "launch_claim_loss_commit_not_observed",
        "launch_claim_loss_original_hold_missing", "launch_claim_loss_state_changed",
        "launch_claim_loss_original_reconciliation_missing",
        "launch_terminal_loss_result_not_proven", "launch_terminal_loss_local_not_proven",
        "launch_terminal_loss_state_not_proven", "launch_terminal_loss_state_changed",
        "launch_repeat_sources_required", "launch_repeat_original_not_active",
        "launch_repeat_refusal_required", "launch_repeat_changed_original", "launch_repeat_original_not_held",
        "launch_preexisting_worker", "launch_unexpected_target_traffic",
        "launch_preclaim_predecessor_binding_changed", "launch_preclaim_enrollment_changed",
        "launch_preclaim_source_changed", "launch_preclaim_server_changed", "launch_preclaim_exit_not_bound",
        "launch_preclaim_setup_invalid", "launch_preclaim_parent_not_held", "launch_preclaim_refusal_changed_state",
        "launch_preclaim_retirement_invalid", "launch_preclaim_original_reconciliation_missing",
        "launch_active_predecessor_identity_changed", "launch_active_predecessor_exit_missing",
        "launch_predecessor_capacity_not_held", "launch_predecessor_unreported_runtime_changed",
        "launch_predecessor_original_attempt_missing", "launch_predecessor_original_run_not_held",
        "launch_predecessor_already_reported", "launch_successor_volume_exists",
        "launch_unresolved_predecessor_refusal_missing", "launch_unresolved_refusal_changed_state",
        "launch_unresolved_refusal_catalog_changed", "launch_unresolved_refusal_engine_changed", "launch_unresolved_refusal_server_changed", "launch_unresolved_refusal_journal_changed", "launch_unresolved_refusal_traffic_changed",
        "launch_host_exit_original_reconciliation_missing", "launch_host_exit_terminal_not_proven",
        "launch_host_exit_budget_or_history_changed", "launch_host_exit_predecessor_history_changed",
        "launch_host_exit_predecessor_binding_changed", "launch_successor_identity_changed",
        "launch_map_disconnect_source_required", "launch_map_disconnect_api_identity",
        "launch_map_disconnect_target_changed", "launch_map_disconnect_api_exit_missing",
        "launch_map_disconnect_exit_or_traffic", "launch_map_disconnect_timing_refused",
        "launch_map_disconnect_worker_exit_code", "launch_map_disconnect_target_count_changed",
        "launch_map_disconnect_target_rows_changed", "launch_map_disconnect_api_exit_changed",
        "launch_map_disconnect_api_restart_missing", "launch_map_disconnect_recovery_state_changed",
        "launch_map_disconnect_sample_stale", "launch_map_disconnect_prework_traffic",
        "launch_map_disconnect_approval_not_deferred",
        "launch_enable_not_observed", "launch_admission_not_bound",
        "launch_intent_not_observed", "launch_durable_chain_not_observed",
        "launch_exact_exit_not_observed", "launch_empty_retirement_not_observed",
        "launch_preservation_or_traffic_not_observed",
        "launch_retirement_not_observed", "launch_completed_job_not_done",
        "launch_completed_reconciliation_not_observed", "launch_completed_enrollment_changed",
        "launch_completed_job_not_pending", "launch_completed_audit_changed",
        "launch_completed_audit_not_observed",
        "launch_duration_witness_source_required",
        "launch_duration_first_release_required",
        "launch_duration_second_approval_required",
        "launch_duration_exact_refusal_required",
        "launch_duration_refusal_mutated_inventory",
        "launch_duration_original_hold_required",
        "launch_duration_unbound_reconciliation_required",
        "launch_duration_exit_changed",
        "launch_duration_original_history_changed",
        "launch_duration_api_identity_required",
        "launch_duration_policy_required",
        "launch_target_witness_source_required", "launch_target_first_release_required",
        "launch_target_first_approval_required", "launch_target_second_approval_required",
        "launch_target_exact_refusal_required", "launch_target_refusal_mutated_inventory",
        "launch_target_original_hold_required", "launch_target_unbound_reconciliation_required",
        "launch_target_exit_changed", "launch_target_original_history_changed",
        "launch_target_api_identity_required", "launch_target_policy_required",
        "launch_concurrency_witness_source_required", "launch_concurrency_holder_required",
        "launch_concurrency_hold_changed", "launch_concurrency_release_required",
        "launch_concurrency_exact_refusal_required", "launch_concurrency_original_hold_required",
        "launch_concurrency_unbound_reconciliation_required", "launch_concurrency_exit_changed",
        "launch_concurrency_api_identity_required", "launch_concurrency_approval_required",
        "launch_concurrency_baseline_required",
        "launch_stop_work_exit_not_observed", "launch_stop_work_traffic_changed",
        "launch_stop_work_capacity_not_released", "launch_stop_work_runtime_not_retired",
        "launch_stop_work_attempt_reused", "launch_stop_work_original_run_not_preserved",
        "launch_stop_work_terminal_not_proven", "cancellation_stop_work_not_recorded",
        "launch_stop_work_active_cancellation_not_observed",
        "launch_stop_work_queued_job_changed", "launch_stop_work_enrollment_changed",
        "launch_missing_grant_not_observed", "launch_missing_grant_issued_or_changed",
        "launch_missing_grant_history_changed", "launch_missing_grant_precondition_failed",
        "launch_expired_grant_not_proven",
        "launch_active_grant_expiry_timing", "launch_active_grant_expiry_window",
        "grant_not_initially_active", "target_grant_revocation_not_proven",
        "target_grant_identity_changed",
        "cancellation_dispatch_advanced_before_action", "cancellation_request_binding_mismatch",
        "cancellation_original_run_not_active", "cancellation_resource_not_observed",
        "cancelled_partial_identity_binding_invalid", "cancelled_partial_result_not_proven",
        "cancelled_partial_files_missing", "cancelled_partial_receipt_mismatch",
        "cancelled_partial_witness_unobserved",
        "cancelled_partial_assessment_mismatch", "cancelled_partial_evidence_mismatch",
        "cancellation_host_report_not_bound",
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
        "strict_authority_drift_traffic", "strict_authority_drift_dirty_inventory",
        "strict_authority_drift_proof_shape", "strict_authority_drift_original_context",
        "strict_authority_drift_mutation_unconfirmed", "strict_authority_drift_refusal_shape",
        "strict_authority_drift_fresh_context", "strict_authority_drift_mutated_or_dispatched",
        "strict_authority_drift_original_signature", "strict_authority_drift_positive_control",
        "strict_review_map_source_required", "strict_review_authority_mode", "strict_review_traffic_changed",
        "strict_review_authority_precondition", "strict_review_refusal_shape",
        "strict_review_window_binding", "strict_review_positive_binding", "strict_review_proof_shape",
        "strict_stale_claim_map_source_required", "strict_stale_claim_no_worker_required",
        "strict_stale_claim_api_identity_required", "strict_stale_claim_bearer_required",
        "strict_stale_claim_original_binding", "strict_stale_claim_retained_approval_required",
        "strict_stale_claim_mutation_required", "strict_stale_claim_refusal_required",
        "strict_stale_claim_window_required", "strict_stale_claim_proof_shape",
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
    if (
        raw["schema"] == LAUNCH_SCHEMA
        and raw.get("scenario") in {LAUNCH_STOPPED_PREDECESSOR_SCENARIO, LAUNCH_REPEAT_SCENARIO}
        and value["stage"] == "launch_refuse_unresolved_predecessor"
        and value["reason"] == "launch_unresolved_predecessor_refusal_missing"
    ):
        from nm2_worker_launch_acceptance import launch_refusal_failure_detail

        diagnostic = launch_refusal_failure_detail(raw.get("launch_refusal_failure"))
        if diagnostic is not None:
            value["launch_refusal_failure"] = diagnostic
    if (raw["schema"] == LAUNCH_SCHEMA
            and raw.get("scenario") in {LAUNCH_STOPPED_PREDECESSOR_SCENARIO, LAUNCH_REPEAT_SCENARIO, LAUNCH_PID1_LOSS_SCENARIO}
            and value["stage"] == "launch_refuse_unresolved_predecessor"
            and value["reason"] == "launch_unresolved_refusal_engine_changed"):
        from nm2_worker_launch_acceptance import engine_difference_detail
        diagnostic = engine_difference_detail(raw.get("engine_difference"))
        if diagnostic is not None:
            value["engine_difference"] = diagnostic
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


def _launch_row(row, ordinal):
    fields = {
        "ordinal", "runtime_id", "container_id", "started_at", "finished_at",
        "intent_sha256", "retirement_sha256", "predecessor_cids",
        "bootstrap_audit_sha256", "runner_state_sha256",
    }
    require(
        type(row) is dict
        and set(row) == fields
        and type(row["ordinal"]) is int
        and row["ordinal"] == ordinal
        and _physical_time(row["started_at"]) < _physical_time(row["finished_at"])
    )
    _uuid(row["runtime_id"])
    for key in ("container_id", "intent_sha256", "retirement_sha256", "runner_state_sha256"):
        _hash(row[key])


def _completed_launch(proof, launch):
    require(
        type(proof) is dict
        and set(proof) == {"job_id", "retirement_sha256", "audit_sha256",
                           "target_requests", "fixed_evidence_sha256"}
        and type(proof["target_requests"]) is int
        and proof["target_requests"] == 5
        and proof["retirement_sha256"] == launch["retirement_sha256"]
    )
    _uuid(proof["job_id"])
    _hash(proof["audit_sha256"])
    _hash(proof["fixed_evidence_sha256"])
    return dict(proof)


def _budget_projection(raw, selection, budget):
    sources = selection["sources"]
    require(type(sources) is dict and type(sources.get("map")) is dict)
    _require_budget_source(budget, sources["map"].get("commit"))
    other = "target_exhaustion" if budget == "duration" else "duration_exhaustion"
    require(not any(key in raw for key in (
        "launch_pair", "cancelled_job", "unclaimed_job", "unissued_job", other, "concurrency_exhaustion",
    )))
    launch = raw.get("launch")
    _launch_row(launch, 1)
    require(launch["predecessor_cids"] == [])
    _hash(launch["bootstrap_audit_sha256"])
    completed = _completed_launch(raw.get("completed_job"), launch)

    counts = {
        "marker_count": 1,
        "targets_spent": 1,
        "duration_allocated": 30,
        "duration_limit": 30 if budget == "duration" else 120,
        **({"target_limit": 1} if budget == "target" else {}),
        "capacity_before": 0,
        "capacity_after": 0,
        "second_job_issued": 0,
        "second_job_target_requests": 0,
        "remaining_local_holds": 0,
    }
    proof_key = f"{budget}_exhaustion"
    proof = raw.get(proof_key)
    require(
        type(proof) is dict
        and set(proof) == set(counts) | {
            "marker", "second_job_id", "selected_sequence", "last_issued_sequence",
            "natural_exit_code", "retirement_sha256",
        }
        and all(type(proof[key]) is int and proof[key] == value for key, value in counts.items())
        and proof["marker"] == f"managed_claim_{budget}_exhausted"
        and proof["selected_sequence"] == "2"
        and proof["last_issued_sequence"] == "1"
        and type(proof["natural_exit_code"]) is int
        and 1 <= proof["natural_exit_code"] <= 255
        and proof["retirement_sha256"] == launch["retirement_sha256"]
        and proof["second_job_id"] != completed["job_id"]
    )
    _uuid(proof["second_job_id"])
    return {
        "launch": dict(launch),
        "completed_job": completed,
        proof_key: dict(proof),
        "nm2_exit_status": "incomplete",
        "resources_retained": True,
    }


def _concurrency_projection(raw, selection):
    sources = selection["sources"]
    require(type(sources) is dict and type(sources.get("map")) is dict)
    _require_budget_source("concurrency", sources["map"].get("commit"))
    require(not any(key in raw for key in (
        "launch_pair", "completed_job", "cancelled_job", "unclaimed_job", "unissued_job",
        "duration_exhaustion", "target_exhaustion", "stopped_predecessor",
    )))
    launch = raw.get("launch")
    _launch_row(launch, 1)
    require(launch["predecessor_cids"] == [])
    _hash(launch["bootstrap_audit_sha256"])
    counts = {
        "marker_count": 1, "targets_spent": 1, "duration_allocated": 30, "concurrency_limit": 1,
        "capacity_before": 1, "capacity_after_refusal": 1, "capacity_before_finish": 1,
        "capacity_after_finish": 0, "target_requests": 0, "issued_attempts": 0,
        "remaining_local_holds": 0,
    }
    proof = raw.get("concurrency_exhaustion")
    require(
        type(proof) is dict and set(proof) == set(counts) | {
            "marker", "legacy_job_id", "managed_job_id", "legacy_finish_state",
            "selected_sequence", "last_issued_sequence", "natural_exit_code",
            "retirement_sha256", "audit_sha256",
        }
        and all(type(proof[key]) is int and proof[key] == value for key, value in counts.items())
        and proof["marker"] == "managed_claim_concurrency_exhausted"
        and proof["legacy_job_id"] != proof["managed_job_id"]
        and proof["legacy_finish_state"] == "failed"
        and proof["selected_sequence"] == "1"
        and proof["last_issued_sequence"] == "0"
        and type(proof["natural_exit_code"]) is int and 1 <= proof["natural_exit_code"] <= 255
        and proof["retirement_sha256"] == launch["retirement_sha256"]
    )
    _uuid(proof["legacy_job_id"])
    _uuid(proof["managed_job_id"])
    _hash(proof["audit_sha256"])
    stopped = raw.get("fixture_stop")
    require(
        type(stopped) is dict and set(stopped) == {"status", "container_ids", "stop_requested_ids"}
        and stopped["status"] == "stopped_retained"
        and type(stopped["container_ids"]) is list and len(stopped["container_ids"]) == 6
        and all(type(cid) is str for cid in stopped["container_ids"])
        and len(set(stopped["container_ids"])) == 6
        and launch["container_id"] in stopped["container_ids"]
        and stopped["stop_requested_ids"] == sorted(
            set(stopped["container_ids"]) - {launch["container_id"]}
        )
    )
    for cid in stopped["container_ids"]:
        _hash(cid)
    return {
        "launch": dict(launch), "concurrency_exhaustion": dict(proof),
        "owned_stopped_container_count": 6, "nm2_exit_status": "incomplete", "resources_retained": True,
    }


def _launch_retention(raw, selection, launches, inventories, *, desktop, first_exit=125):
    from nm2_worker_acceptance import AcceptanceRefused, canonical, digest, unchanged_inventory

    admit_bridge = selection["allow_empty_builtin_bridge_id_change"]
    require(
        selection["docker_context"] == ("desktop-linux" if desktop else "default")
        and type(admit_bridge) is bool and (desktop or not admit_bridge)
        and len(inventories) == 2
    )
    kinds = {"containers", "images", "networks", "volumes"}
    for snapshot, key in zip(inventories, ("before_sha256", "after_sha256")):
        require(type(snapshot) is dict and set(snapshot) == kinds
                and all(type(snapshot[kind]) is dict for kind in kinds))
        document = canonical(snapshot)
        require(len(document) <= 4 * 1024 * 1024 and digest(document) == raw[key])
    before, after = inventories
    project = selection["project"]
    try:
        admitted = unchanged_inventory(before, after, project, admit_bridge=admit_bridge)
    except AcceptanceRefused:
        raise HostedRefused("nm2_hosted_launch_retention_refused") from None
    require(
        len(admitted) <= 1
        and canonical(admitted) == canonical(raw["admitted_inventory_diffs"])
        and canonical(before["images"]) == canonical(after["images"])
    )
    replacements = {entry["before"]: entry["after"] for entry in admitted}
    for kind in kinds:
        for key, prior in before[kind].items():
            selected_id = replacements.get(key, key) if kind == "networks" else key
            current = after[kind][selected_id]
            if selected_id != key:
                require(
                    key not in after["networks"] and selected_id not in before["networks"]
                    and prior["driver"] == "bridge" and prior["scope"] == "local"
                    and prior["containers"] == current["containers"] == {}
                )
                current = {**current, "id": key}
            require(canonical(prior) == canonical(current))
    state_volume = project + "_runner-state"
    expected_volumes = {state_volume, *(
        f"{project}_worker-ready-{row['runtime_id']}" for row in launches
    )}
    require(
        not expected_volumes & before["volumes"].keys()
        and expected_volumes <= after["volumes"].keys()
        and all(after["volumes"][name]["id"] == name for name in expected_volumes)
    )
    owned = set(after["containers"]) - set(before["containers"])
    workers = {row["container_id"]: row for row in launches}
    stopped = raw["fixture_stop"]
    require(
        type(stopped) is dict and set(stopped) == {"status", "container_ids", "stop_requested_ids"}
        and stopped["status"] == "stopped_retained"
        and len(owned) == 5 + len(launches) and workers.keys() <= owned
        and stopped["container_ids"] == sorted(owned)
        and stopped["stop_requested_ids"] == sorted(owned - workers.keys())
    )
    images = selection["images"]
    services = {name: images[name] for name in ("api", "db", "proxy", "web")}
    services["gate-fixture"] = images["worker"]
    for cid in sorted(owned):
        row = after["containers"][cid]
        _hash(cid)
        require(
            row["id"] == cid and row["labels"]["com.docker.compose.project"] == project
            and all(row["state"][name] is False for name in ("running", "paused", "restarting", "dead"))
        )
        service = row["labels"]["com.docker.compose.service"]
        if cid in workers:
            launch = workers[cid]
            require(
                service == "managed-worker" and row["image"] == images["worker"]
                and row["labels"]["com.docker.compose.container-number"] == str(launch["ordinal"])
                and type(row["restarts"]) is int and row["restarts"] == 0
                and row["state"]["started_at"] == launch["started_at"]
                and row["state"]["finished_at"] == launch["finished_at"]
                and (launch["ordinal"] != 1 or row["state"]["exit_code"] == first_exit)
            )
            mounts = [item for item in row["mounts"] if item["Destination"] == "/home/runner/.vardrmap"]
            require(
                len(mounts) == 1 and mounts[0]["Type"] == "volume"
                and mounts[0]["Name"] == state_volume and mounts[0]["RW"] is True
            )
        else:
            require(service in services and row["image"] == services.pop(service))
    require(not services)
    return len(owned), len(admitted)


def _stopped_predecessor_projection(raw, selection, first, second, inventories, *, desktop):

    counts = {
        "new_resources": 0, "target_requests": 3, "capacity_before": 1,
        "capacity_after": 0, "targets_spent": 1, "duration_allocated": 30,
        "remaining_local_holds": 0,
    }
    hashes = ("retirement_sha256", "host_retirement_sha256", "audit_sha256", "terminal_sha256")
    proof = raw.get("stopped_predecessor")
    require(
        type(proof) is dict and set(proof) == set(counts) | set(hashes) | {
            "refused_runtime_id", "failure_phase", "failure_code",
            "physical_exit_elapsed_ns", "terminal_cause",
        }
        and all(type(proof[key]) is int and proof[key] == value for key, value in counts.items())
        and proof["refused_runtime_id"] == second["runtime_id"]
        and proof["retirement_sha256"] == first["retirement_sha256"]
        and proof["failure_phase"] == "launch_catalog"
        and proof["failure_code"] == "validation_refused"
        and proof["terminal_cause"] == "observed_exit"
        and type(proof["physical_exit_elapsed_ns"]) is int
        and 0 < proof["physical_exit_elapsed_ns"] < 15_000_000_000
    )
    for key in hashes:
        _hash(proof[key])

    pid1_loss = raw["scenario"] == LAUNCH_PID1_LOSS_SCENARIO
    fault = None
    if pid1_loss:
        from nm2_worker_launch_acceptance import PID1_LOSS_SOURCES

        require(all(selection["sources"][name]["commit"] == commit
                    for name, commit in PID1_LOSS_SOURCES.items()))
        fault = raw.get("pid1_loss")
        require(
            type(fault) is dict and set(fault) == {
                "signal", "kill_calls", "container_id", "exit_code",
                "new_work_disabled_before_report", "new_work_disabled_after_report",
                "original_artifact_files",
            }
            and fault["signal"] == "KILL"
            and type(fault["kill_calls"]) is int and fault["kill_calls"] == 1
            and fault["container_id"] == first["container_id"]
            and type(fault["exit_code"]) is int and fault["exit_code"] == 137
            and fault["new_work_disabled_before_report"] is False
            and fault["new_work_disabled_after_report"] is True
            and type(fault["original_artifact_files"]) is list
            and len(fault["original_artifact_files"]) <= 1
        )
        for artifact in fault["original_artifact_files"]:
            require(
                type(artifact) is dict and set(artifact) == {"name", "size", "sha256"}
                and artifact["name"] == "vardrgate_result.json"
                and type(artifact["size"]) is int and 0 < artifact["size"] <= 1024 * 1024
            )
            _hash(artifact["sha256"])
    else:
        require("pid1_loss" not in raw)
    owned_count, admitted_count = _launch_retention(
        raw, selection, (first, second), inventories, desktop=desktop,
        first_exit=137 if pid1_loss else 125,
    )
    result = {
        "pid1_loss" if pid1_loss else "stopped_predecessor": {
            **{key: proof[key] for key in (*counts, *hashes, "failure_phase", "failure_code",
                                          "terminal_cause", "physical_exit_elapsed_ns")},
            "same_runner_state_volume": True,
            "owned_stopped_container_count": owned_count,
        },
        "nm2_exit_status": "incomplete", "resources_retained": True,
    }
    if pid1_loss:
        result["pid1_loss"].update(
            **{key: fault[key] for key in (
                "signal", "kill_calls", "exit_code", "new_work_disabled_before_report",
                "new_work_disabled_after_report", "original_artifact_files",
            )},
            original_artifact_status="producer_verified_unchanged" if fault["original_artifact_files"] else "not_observed",
            scope="PID1 loss only; separate Runner-loss case remains open",
        )
    if desktop:
        result.update(platform="win32", container_platform="linux",
                      empty_builtin_bridge_id_change_count=admitted_count)
    return result


def _repeat_retirement_projection(raw, selection, first, second, inventories, *, desktop):
    from nm2_worker_acceptance import canonical, digest
    from nm2_worker_launch_acceptance import MAP_DISCONNECT_SOURCES, repeated_claim_state
    from worker_host import _terminal
    from worker_host_persistent import retirement, original_local_audit

    require(all(selection["sources"][name]["commit"] == commit for name,commit in MAP_DISCONNECT_SOURCES.items())
            and "stopped_predecessor" not in raw)
    repeated = _repeat_projection(raw, selection, first)
    proof = raw["repeat_retirement"]
    require(type(proof) is dict and set(proof) == {"before", "after", "local_before", "retirement", "audit",
        "reconciliation", "host_reconciled", "physical", "audit_sha256", "retirement_sha256",
        "host_retirement_sha256", "terminal_sha256", "terminal_cause", "capacity_before", "capacity_after",
        "targets_spent", "duration_allocated", "remaining_local_holds"})
    before, after = proof["before"], proof["after"]
    expected = raw["repeated_managed_claim"]["state_after"]
    _same(repeated_claim_state(before), {**expected, "runtime": {**expected["runtime"], "new_work_disabled": True}})
    runtime = before["runtimes"][0]
    original = runtime["admission"]
    record = {"runtime_id": runtime["id"], "registration": {key:value for key,value in original.items()
        if key not in {"schema","runtime_id","runtime_sha256","admission_sha256"}},
        "admission": original, "registration_state": "acknowledged", "stop_state": "observed", "receipt": proof["retirement"],
        "revocation_state": "none", "disable_state": "none"}
    retained = retirement(record, proof["retirement"])
    binding = runtime["attempts"][0]["binding"]
    terminal = _terminal(binding, retained["attempt_receipt"])
    require(retained["runtime_sequence"] == retained["last_sequence"] == "1"
            and canonical(retained["binding"]) == canonical(binding)
            and retained["receipt_sha256"] == first["retirement_sha256"] == proof["retirement_sha256"]
            and terminal["schema"] == "vardr.managed-stop-receipt/1"
            and terminal["outcome"] == "failed" and terminal["cause"] == proof["terminal_cause"] == "observed_exit")
    _same(after, {**before, "job_status": "failed", "capacity_reserved_count": 0,
        "execution": {**before["execution"], "state": "failed", "capacity_reserved": False},
        "runtimes": [{**runtime, "retired": True, "report_sha256": retained["report_sha256"]}],
        "stops": [{key:terminal[key] for key in ("contract_id","receipt_sha256","outcome","cause")}]})
    local = proof["local_before"]
    require(local["run_id"] == raw["repeated_managed_claim"]["original_run_id"]
            and local["job_id"] == binding["job_id"] and local["engagement_id"] == before["engagement_id"]
            and local["phase"] == "executing"
            and local["claim_state"] == "consume_acknowledged"
            and canonical([local["consumption_sent"],local["consumption_acknowledged"]]) == b"[1,1]"
            and local["local_stop_requested"] is False and local["failure_reason"] is None)
    physical = proof["physical"]
    _same(physical, {"identity":runtime["identity"],"runtime_id":runtime["id"],
        "runtime_sha256":runtime["runtime_sha256"],"admission_sha256":runtime["admission_sha256"],
        "finished_at":first["finished_at"],"exit_code":125,"operator_stop_state":"stopped_observed"})
    host = proof["host_reconciled"]
    require(host["schema"] == "vardr.worker-cli/1" and host["state"] == "terminal_observed"
            and host["runtime_id"] == runtime["id"] and host["receipt"]["retirement"] == retained)
    audited = original_local_audit(record, host["receipt"], output=canonical(proof["audit"]), returncode=0)
    require(audited["original_local_audit_sha256"] == proof["audit_sha256"])
    _same(proof["audit"]["counts"], {"attempts":1,"selections":1,"associated_runs":1,"associated_claims":1})
    reconciled = proof["reconciliation"]
    require(set(reconciled) == {"schema","status","reason","complete","binding","selected_run_id",
        "selected_sequence","reconciliation_state","remaining_local_holds","retirement_receipt_sha256"}
        and reconciled["schema"] == "vardr.worker-reconciliation/1" and reconciled["status"] == "reconciled"
        and reconciled["reason"] is None and reconciled["complete"] is True
        and reconciled["binding"] == proof["audit"]["binding"]
        and reconciled["selected_run_id"] == local["run_id"] and reconciled["selected_sequence"] == "1"
        and reconciled["reconciliation_state"] == "terminal_host_exit_observed"
        and type(reconciled["remaining_local_holds"]) is int and reconciled["remaining_local_holds"] == 0
        and reconciled["retirement_receipt_sha256"] == retained["receipt_sha256"])
    counts = {"capacity_before":1,"capacity_after":0,"targets_spent":1,"duration_allocated":30,"remaining_local_holds":0}
    require(all(type(proof[key]) is int and proof[key] == value for key,value in counts.items()))
    for key,value in (("host_retirement_sha256",retained),("terminal_sha256",terminal)):
        require(proof[key] == digest(canonical(value)))
    owned,admitted = _launch_retention(raw,selection,(first,second),inventories,desktop=desktop)
    return {"repeated_managed_claim":repeated,"repeat_retirement":{**counts,
        **{key:proof[key] for key in ("retirement_sha256","host_retirement_sha256","terminal_sha256","audit_sha256")}},
        "same_runner_state_volume":True,"owned_stopped_container_count":owned,
        "scope":"Installed repeat and exact stop/recovery; independent PG competition and accepted refusal/latency evidence reused",
        "platform":"win32" if desktop else "linux","container_platform":"linux",
        "empty_builtin_bridge_id_change_count":admitted,"nm2_exit_status":"incomplete","resources_retained":True}


def _repeat_projection(raw, selection, first):
    from types import SimpleNamespace
    from nm2_worker_acceptance import canonical, digest, ORIGIN
    from nm2_worker_launch_acceptance import LaunchFixture, repeated_claim_state
    from worker_host import _terminal
    from worker_runtime import RuntimeIdentity

    counts = {
        "repeat_count": 1, "http_status": 409, "issued_attempts": 1, "target_requests": 3,
        "targets_spent": 1, "duration_allocated": 30, "capacity_before": 1, "capacity_after": 1,
    }
    hashes = ("state_before_sha256", "state_after_sha256", "binding_sha256",
              "original_run_sha256", "request_sha256", "refusal_sha256")
    proof = raw.get("repeated_managed_claim")
    retained = {"state_before", "state_after", "request", "request_path", "original_run_id", "case", "terminal_receipt"}
    require(type(proof) is dict and set(proof) == set(counts) | set(hashes) | {"runtime_id"} | retained
            and proof["runtime_id"] == first["runtime_id"]
            and all(type(proof[key]) is int and proof[key] == value for key, value in counts.items())
            and proof["state_before_sha256"] == proof["state_after_sha256"]
            and proof["refusal_sha256"] == digest(canonical({"detail": "managed_request_refused"})))
    for key in hashes:
        _hash(proof[key])
    # Reuse the actual active-owned-attempt oracle on retained normalized rows.
    # This stub has no transport, constructors, journal writes or tool callback.
    before, after = proof["state_before"], proof["state_after"]
    _same(before, after)
    runtime = before["runtime"]
    attempt = runtime["attempts"][0]
    binding = _fields(attempt["binding"], _BINDING)
    identity = RuntimeIdentity(**runtime["identity"])
    require(identity.container_id == first["container_id"] and identity.started_at == first["started_at"]
            and identity.project == selection["project"] and identity.image_id == selection["images"]["worker"]
            and runtime["id"] == first["runtime_id"]
            and runtime["runtime_sha256"] == digest(canonical(runtime["identity"])))
    admission = {"runtime_id": runtime["id"], "identity": runtime["identity"],
                 **{key: runtime[key] for key in ("runtime_sha256", "admission_sha256")},
                 "origin": f"https://vardrsec.localhost:{selection['https_port']}/backend",
                 "runner_id": binding["runner_id"]}
    inventory = {**{key: value for key, value in before.items() if key not in {"runtime", "approval"}},
                 "approvals": [before["approval"]], "runtimes": [runtime]}
    probe = SimpleNamespace(inventory=lambda *args, **kwargs: inventory)
    validated = LaunchFixture.unreported_attempt(probe, admission, (None, binding["job_id"]), identity, disabled=False)
    _same(before, repeated_claim_state(validated))
    _same({key: before[key] for key in ("targets_spent", "duration_allocated", "capacity_reserved_count")},
          {"targets_spent": proof["targets_spent"], "duration_allocated": proof["duration_allocated"],
           "capacity_reserved_count": proof["capacity_before"]})
    for key in ("runner_id", "contract_id", "attempt_id"):
        _uuid(binding[key])
    _hash(runtime["admission_sha256"])
    request = proof["request"]
    _hash(request["target_binding"]["case_sha256"])
    _same(request, {"origin": admission["origin"], "runner_id": admission["runner_id"],
                   "concurrency_budget": True, "duration_seconds": 30,
                   "target_binding": {"profile": "gate-fixed-http/1", "origins": [ORIGIN],
                                      "case_sha256": digest(canonical(proof["case"]))},
                   **{key: admission[key] for key in ("runtime_id", "runtime_sha256", "admission_sha256")},
                   "runtime_sequence": "1"})
    require(proof["request_path"] == f"/jobs/{binding['job_id']}/managed/claim"
            and type(proof["original_run_id"]) is str and re.fullmatch(r"[a-f0-9]{32}", proof["original_run_id"]))
    for key, value in (("state_before_sha256", before), ("state_after_sha256", after),
                       ("binding_sha256", binding), ("request_sha256", request)):
        require(proof[key] == digest(canonical(value)))
    require(proof["original_run_sha256"] == digest(proof["original_run_id"].encode("ascii")))
    terminal = _terminal(binding, proof["terminal_receipt"])
    require(terminal["schema"] == "vardr.managed-stop-receipt/1" and terminal["cause"] == "observed_exit"
            and digest(canonical(terminal)) == raw["repeat_retirement"]["terminal_sha256"])
    return {key: proof[key] for key in (*counts, *hashes)}


def _preclaim_projection(raw, selection, first, second, inventories, *, desktop):
    from nm2_worker_launch_acceptance import MAP_DISCONNECT_SOURCES

    require(all(selection["sources"][name]["commit"] == commit for name, commit in MAP_DISCONNECT_SOURCES.items()))
    counts = {"new_resources": 0, "target_requests": 0, "targets_spent": 0, "duration_allocated": 0,
              "capacity_before": 0, "capacity_after": 0, "issued_attempts": 0,
              "retained_tombstones": 1, "remaining_local_holds": 0}
    hashes = ("tombstone_before_sha256", "tombstone_after_sha256", "audit_sha256", "retirement_sha256", "host_retirement_sha256")
    proof = raw.get("preclaim_recovery")
    require(type(proof) is dict and set(proof) == set(counts) | set(hashes) | {
        "setup_kind", "marker", "failure_phase", "failure_code", "refused_runtime_id", "last_sequence", "reconciliation_state",
    } and all(type(proof[key]) is int and proof[key] == value for key, value in counts.items())
        and proof["setup_kind"] == "trusted_synthetic" and proof["marker"] == "local_preclaim_denied_before_rpc"
        and proof["failure_phase"] == "launch_catalog" and proof["failure_code"] == "validation_refused"
        and proof["refused_runtime_id"] == second["runtime_id"] and proof["last_sequence"] == "0"
        and proof["reconciliation_state"] == "terminal_preclaim_parent_retired"
        and proof["tombstone_before_sha256"] == proof["tombstone_after_sha256"]
        and proof["retirement_sha256"] == first["retirement_sha256"])
    for key in hashes:
        _hash(proof[key])
    owned, admitted = _launch_retention(raw, selection, (first, second), inventories, desktop=desktop)
    return {"preclaim_recovery": {**{key: proof[key] for key in (*counts, *hashes, "setup_kind", "marker", "failure_phase", "failure_code", "last_sequence", "reconciliation_state")},
            "same_runner_state_volume": True, "owned_stopped_container_count": owned},
            "platform": "win32" if desktop else "linux", "container_platform": "linux",
            "empty_builtin_bridge_id_change_count": admitted, "nm2_exit_status": "incomplete", "resources_retained": True}


def _claim_reply_loss_projection(raw, selection, inventories, *, desktop, operation="claim"):
    """Join the committed claim to original local unknown and physical retirement."""
    from nm2_worker_launch_acceptance import (CLAIM_REPLY_LOSS_SOURCES, POST_CLAIM_REPLY_LOSS_SOURCES,
        TERMINAL_REPLY_LOSS, terminal_reply_loss_state, claim_reply_loss_config)
    from worker_host import _terminal

    terminal_loss = operation in TERMINAL_REPLY_LOSS
    policy = TERMINAL_REPLY_LOSS[operation] if terminal_loss else None
    require(operation == REPLY_LOSS_OPERATIONS[raw["scenario"]])
    require(type(operation) is str and operation in {"claim", "consume", "runtime-bind", "result", "finish"})
    issued = operation != "claim"
    sources = CLAIM_REPLY_LOSS_SOURCES if not issued else POST_CLAIM_REPLY_LOSS_SOURCES
    require(all(type(commit) is str and selection["sources"][name]["commit"] == commit
                for name, commit in sources.items()))
    require(not any(key in raw for key in (
        "launch_pair", "completed_job", "cancelled_job", "unclaimed_job", "unissued_job",
        "duration_exhaustion", "target_exhaustion", "concurrency_exhaustion",
        "stopped_predecessor", "map_disconnect", "preclaim_recovery",
    )))
    launch = raw["launch"]
    _launch_row(launch, 1)
    require(launch["predecessor_cids"] == [])
    _hash(launch["bootstrap_audit_sha256"])
    proof = raw["claim_reply_loss"]
    require(type(proof) is dict and set(proof) == {
        "job_id", "run_id", "approval_record_id", "initial", "committed", "after",
        "local_unknown", "proxy", "target_requests", "retirement", "audit", "reconciliation", "physical",
        "audit_sha256", "retirement_sha256", "host_retirement_sha256", "terminal_sha256",
        "terminal_cause", "capacity_before", "capacity_after", "targets_spent",
        "duration_allocated", "remaining_local_holds",
    } | ({"operation", "requests", "case", "assessment", "evidence_count", "evidence_sha256", "local_after"} if terminal_loss else set()))
    _uuid(proof["job_id"])
    require(type(proof["run_id"]) is str and re.fullmatch(r"[0-9a-f]{32}", proof["run_id"]) is not None
            and type(proof["approval_record_id"]) is str
            and re.fullmatch(r"[A-Za-z0-9_.:-]{1,257}", proof["approval_record_id"]) is not None)
    counts = {"target_requests": 5 if terminal_loss else 0, "capacity_before": 0 if operation == "finish" else 1, "capacity_after": 0,
              "targets_spent": 1, "duration_allocated": 30, "remaining_local_holds": 0}
    require(all(type(proof[key]) is int and proof[key] == value for key, value in counts.items()))
    initial, committed, after = (proof[key] for key in ("initial", "committed", "after"))
    require(initial["schema"] == committed["schema"] == "vardr.nm2-fixture-inventory/3"
            and initial["schema_revision"] == committed["schema_revision"] == "0041persistentruntime"
            and initial["job_id"] == committed["job_id"] == proof["job_id"]
            and initial["engagement_id"] == committed["engagement_id"]
            and initial["runtime_attempt_bound"] == committed["runtime_attempt_bound"] == 35
            and initial["job_status"] == "pending" and initial["execution"] is None
            and all(initial[key] == [] for key in ("approvals", "contracts", "runtimes", "results", "stops"))
            and all(type(initial[key]) is int and initial[key] == 0
                    for key in ("targets_spent", "duration_allocated", "capacity_reserved_count"))
            and committed["job_status"] == ("done" if operation == "finish" else "running")
            and all(type(committed[key]) is int and committed[key] == value for key, value in (
                ("targets_spent", 1), ("duration_allocated", 30), ("capacity_reserved_count", 0 if operation == "finish" else 1)))
            and committed["stops"] == [] and (len(committed["results"]) == 1 if terminal_loss else committed["results"] == [])
            and len(committed["contracts"]) == len(committed["runtimes"]) == len(committed["approvals"]) == 1)
    _uuid(committed["engagement_id"])
    _same(committed["execution"], {
        "state": "completed" if operation == "finish" else "active",
        "capacity_reserved": operation != "finish", "target_charge": 1, "duration_seconds": 30,
    })
    changed = {"job_status", "targets_spent", "duration_allocated", "capacity_reserved_count",
               "execution", "contracts", "runtimes", "approvals"} | ({"results"} if terminal_loss else set())
    _same({key: value for key, value in initial.items() if key not in changed},
          {key: value for key, value in committed.items() if key not in changed})
    contract, runtime, approval = (committed[key][0] for key in ("contracts", "runtimes", "approvals"))
    require(contract["consumed"] is issued and type(contract["ordinal"]) is int and contract["ordinal"] == 1
            and approval["id"] == proof["approval_record_id"] and type(approval["issued"]) is int
            and approval["issued"] == 1 and approval["revoked"] is False
            and runtime["id"] == launch["runtime_id"] and runtime["mode"] == "persistent"
            and runtime["max_attempts"] is None and runtime["retired"] is False
            and runtime["new_work_disabled"] is False and runtime["reporting_revoked"] is False
            and runtime["report_sha256"] is None
            and runtime["active_sequence"] == runtime["head_sequence"] == runtime["last_sequence"] == "1"
            and len(runtime["attempts"]) == 1)
    identity = runtime["identity"]
    require(set(identity) == {"daemon_id", "container_id", "image_id", "project", "started_at", "owner_nonce"}
            and identity["container_id"] == launch["container_id"]
            and identity["image_id"] == selection["images"]["worker"]
            and identity["project"] == selection["project"] and identity["started_at"] == launch["started_at"]
            and runtime["runtime_sha256"] == _digest(identity))
    physical = proof["physical"]
    require(set(physical) == {"identity", "runtime_id", "runtime_sha256", "admission_sha256",
                              "finished_at", "exit_code", "operator_stop_state"}
            and physical["identity"] == identity and physical["runtime_id"] == runtime["id"]
            and physical["runtime_sha256"] == runtime["runtime_sha256"]
            and physical["admission_sha256"] == runtime["admission_sha256"]
            and physical["finished_at"] == launch["finished_at"]
            and type(physical["exit_code"]) is int and physical["exit_code"] == 125
            and physical["operator_stop_state"] == "not_requested")
    _hash(identity["owner_nonce"])
    require(type(identity["daemon_id"]) is str and 1 <= len(identity["daemon_id"]) <= 128)
    binding = {key: runtime[key] for key in ("runner_id", "runtime_sha256", "admission_sha256")}
    binding["runtime_id"] = runtime["id"]
    _uuid(binding["runner_id"])
    admission = runtime["admission"]
    _hash(admission["capability_sha256"])
    expected_admission = {
        "schema": "vardr.worker-admission/3", **binding, "enrollment_id": runtime["enrollment_id"],
        "origin": f"https://vardrsec.localhost:{selection['https_port']}/backend",
        "capability_sha256": admission["capability_sha256"], "identity": identity, "mode": "persistent",
        "limits": {"max_attempts": None, "idle_timeout_seconds": None},
        "reporting_authority": {"purpose": "worker-stop-only", "expires_at": None},
    }
    _same(admission, expected_admission)
    require(binding["admission_sha256"] == _digest({key: value for key, value in admission.items() if key != "admission_sha256"}))
    _same(runtime["legacy_binding"], dict.fromkeys(("job_id", "contract_id", "attempt_id", "fence",
                                                   "contract_sha256", "bound_at", "confirmed_at")))
    for key in ("runtime_sha256", "admission_sha256"):
        _hash(binding[key])
    attempt = runtime["attempts"][0]
    original = {
        "origin": f"https://vardrsec.localhost:{selection['https_port']}/backend",
        "runner_id": binding["runner_id"], "job_id": proof["job_id"], "contract_id": contract["id"],
        **{key: contract[key] for key in ("attempt_id", "fence", "contract_sha256")},
    }
    for key in ("contract_id", "attempt_id"):
        _uuid(original[key])
    _hash(original["contract_sha256"])
    require(type(original["fence"]) is int and 1 <= original["fence"] <= 2**53 - 1
            and attempt["runtime_id"] == runtime["id"] and attempt["runtime_sequence"] == "1"
            and attempt["runtime_mode"] == "persistent" and attempt["previous_sequence"] is None
            and attempt["job_id"] == proof["job_id"]
            and _physical_time(launch["started_at"]) <= _physical_time(attempt["bound_at"])
            <= _physical_time(launch["finished_at"])
            and (attempt["confirmed_at"] is not None) == (terminal_loss or operation == "runtime-bind")
            and all(attempt[key] is None for key in ("released_at", "terminal_receipt",
                "terminal_receipt_sha256", "native_done_sha256", "release_receipt")))
    if operation == "runtime-bind":
        require(_physical_time(attempt["bound_at"]) <= _physical_time(attempt["confirmed_at"]) <= _physical_time(launch["finished_at"]))
    _same(attempt["binding"], original)
    unknown = proof["local_unknown"]
    require(type(unknown) is dict and set(unknown) == {"run", "metadata", "audit"})
    for row in (unknown["run"], unknown["metadata"]):
        require(row["run_id"] == proof["run_id"] and row["job_id"] == proof["job_id"]
                and row["engagement_id"] == committed["engagement_id"]
                and row["phase"] == (policy["phase"] if terminal_loss else "executing" if issued else "claiming")
                and row["status"] == ("local_artifact_held" if terminal_loss else "held_after_claim" if issued else "claim_unknown"))
    require(unknown["run"]["pid"] is None
            and (unknown["run"]["artifact_sha256"] == committed["results"][0]["artifact_sha256"] if terminal_loss else unknown["run"]["artifact_sha256"] is None)
            and unknown["metadata"]["claim_state"] == ("consume_acknowledged" if terminal_loss else "held_after_claim" if issued else "claim_unknown")
            and (terminal_loss or unknown["metadata"]["partial_files"] == []) and unknown["metadata"]["partial_result"] is None
            and all(type(unknown["metadata"][key]) is int and unknown["metadata"][key] == value
                    for key,value in (("consumption_sent",int(issued)),("consumption_acknowledged",int(terminal_loss)))))
    retired, audit, reconciliation = (proof[key] for key in ("retirement", "audit", "reconciliation"))
    for row, state, holds in ((unknown["audit"], "active" if issued else "idle", True), (audit, "retired", False)):
        require(set(row) == {"schema", "status", "reason", "complete", "binding", "parent", "counts",
                             "retirement_receipt_sha256", "global_holds"}
                and row["schema"] == "vardr.worker-state-audit/1" and row["complete"] is True
                and row["reason"] == ("local_holds" if holds else None)
                and row["status"] == ("held" if holds else "retired")
                and type(row["global_holds"]) is int
                and (row["global_holds"] > 0 if holds else row["global_holds"] == 0)
                and row["retirement_receipt_sha256"] == (None if holds else launch["retirement_sha256"]))
        _same(row["binding"], binding)
        _same(row["parent"], {"state": state, "last_sequence": str(int(issued)), "head_sequence": "1" if issued else None, "active_sequence": "1" if holds and issued else None})
        _same(row["counts"], {"attempts": int(issued), "selections": 1, "associated_runs": 1, "associated_claims": 1})
    require(set(reconciliation) == {"schema", "status", "reason", "complete", "binding", "selected_run_id",
                                    "selected_sequence", "reconciliation_state", "remaining_local_holds",
                                    "retirement_receipt_sha256"}
            and reconciliation["reason"] is None
            and unknown["audit"]["reason"] == "local_holds"
            and reconciliation["schema"] == "vardr.worker-reconciliation/1"
            and reconciliation["status"] in {"reconciled", "already_retired"}
            and reconciliation["complete"] is True
            and reconciliation["selected_run_id"] == proof["run_id"]
            and reconciliation["selected_sequence"] == "1"
            and reconciliation["reconciliation_state"] == (policy["reconciliation"] if terminal_loss else "terminal_host_exit_observed")
            and type(reconciliation["remaining_local_holds"]) is int
            and reconciliation["remaining_local_holds"] == 0
            and reconciliation["retirement_receipt_sha256"] == launch["retirement_sha256"])
    _same(reconciliation["binding"], binding)
    require(set(retired) == {"schema", "runtime_id", "runtime_sha256", "admission_sha256", "origin", "runner_id",
                             "enrollment_id", "runtime_sequence", "last_sequence", "binding", "attempt_receipt",
                             "report_sha256", "retired", "receipt_sha256"}
            and retired["schema"] == "vardr.worker-retirement/3" and retired["retired"] is True
            and all(retired[key] == value for key, value in binding.items())
            and retired["last_sequence"] == retired["runtime_sequence"] == "1"
            and retired["origin"] == original["origin"] and retired["runner_id"] == original["runner_id"]
            and retired["enrollment_id"] == runtime["enrollment_id"]
            and retired["receipt_sha256"] == launch["retirement_sha256"]
            == _digest({key: value for key, value in retired.items() if key != "receipt_sha256"}))
    _same(retired["binding"], original)
    terminal = _terminal(original, retired["attempt_receipt"])
    if terminal_loss:
        require(proof["operation"] == operation and type(proof["case"]) is dict
                and type(proof["evidence_count"]) is int and proof["evidence_count"] == 5)
        _hash(proof["evidence_sha256"])
        case_sha = _digest(proof["case"])
        assessment = proof["assessment"]
        require(assessment["status"] == "conclusive" and assessment["baseline_valid"] is True
                and assessment["case_snapshot_verified"] is True and assessment["preflight"]["status"] == "passed"
                and assessment["case_hash"] == case_sha and type(assessment["candidate_findings"]) is int
                and assessment["candidate_findings"] == 0)
        marker = _requests(proof["requests"])
        require(parse_qs(urlsplit(proof["case"]["request"]["url"]).query).get("nm2_case") == [marker])
        clocks = [row["received_monotonic_ns"] for row in proof["requests"]]
        require(all(type(value) is int and value > 0 for value in clocks) and clocks == sorted(clocks))
        expected_terminal = terminal_reply_loss_state(operation, committed, unknown["metadata"], case_sha)
        _same(terminal, expected_terminal)
        terminal_reply_loss_state(operation, after, proof["local_after"], case_sha, retired=True)
        require(proof["local_after"]["run_id"] == proof["run_id"]
                and proof["local_after"]["job_id"] == proof["job_id"]
                and proof["local_after"]["engagement_id"] == committed["engagement_id"]
                and proof["terminal_cause"] == ("retained_result_failure" if operation == "result" else "existing_completed"))
    else:
        require(terminal["schema"] == "vardr.managed-stop-receipt/1"
                and terminal["outcome"] == "failed" and terminal["cause"] == proof["terminal_cause"] == "observed_exit")
    _hash(retired["report_sha256"])
    _same(after, {
        **committed, "job_status": "done" if operation == "finish" else "failed", "capacity_reserved_count": 0,
        "execution": {**committed["execution"], "state": "completed" if operation == "finish" else "failed", "capacity_reserved": False},
        "runtimes": [{**runtime, "retired": True, "new_work_disabled": True, "report_sha256": retired["report_sha256"]}],
        **({"results": [{**committed["results"][0], "outcome": terminal["outcome"]}], "stops": []}
           if terminal_loss else {"stops": [{key: terminal[key] for key in ("contract_id", "receipt_sha256", "outcome", "cause")}]}),
    })
    for key, value in (("audit_sha256", audit), ("host_retirement_sha256", retired), ("terminal_sha256", terminal)):
        require(proof[key] == _digest(value))
    require(proof["retirement_sha256"] == launch["retirement_sha256"])
    proxy = proof["proxy"]
    require(set(proxy) == {"before", "armed", "base_config_sha256", "config_sha256", "adapter_sha256",
                          "ca_sha256", "caddy_version", "ready_http_status", "web_http_status"})
    before_proxy, armed = proxy["before"], proxy["armed"]
    require(set(before_proxy) == set(armed) == {"id", "image", "labels", "state", "restarts", "mounts", "profile"})
    _same({key: value for key, value in before_proxy.items() if key != "state"},
          {key: value for key, value in armed.items() if key != "state"})
    require(before_proxy["image"] == selection["images"]["proxy"]
            and before_proxy["labels"]["com.docker.compose.project"] == selection["project"]
            and before_proxy["labels"]["com.docker.compose.service"] == "proxy"
            and before_proxy["labels"]["com.docker.compose.oneoff"] == "False"
            and type(before_proxy["restarts"]) is int and before_proxy["restarts"] == 0
            and re.fullmatch(r"v2\.11\.7(?: h1:[A-Za-z0-9+/=]+)?", proxy["caddy_version"]) is not None)
    for row in (before_proxy, armed):
        require(row["state"]["Status"] == "running" and row["state"]["Running"] is True
                and row["state"]["Health"]["Status"] == "healthy"
                and all(row["state"][key] is False for key in ("Paused", "Restarting", "Dead", "OOMKilled")))
    require(_physical_time(before_proxy["state"]["StartedAt"]) < _physical_time(armed["state"]["StartedAt"])
            < _physical_time(launch["started_at"]))
    original_config = (SOURCE / "Caddyfile").read_bytes()
    require(proxy["base_config_sha256"] == hashlib.sha256(original_config).hexdigest()
            and proxy["config_sha256"] == hashlib.sha256(claim_reply_loss_config(original_config, proof["job_id"], operation=operation)).hexdigest()
            and all(type(proxy[key]) is int and proxy[key] == 200 for key in ("ready_http_status", "web_http_status")))
    for key in ("adapter_sha256", "ca_sha256"):
        _hash(proxy[key])
    owned, admitted = _launch_retention(raw, selection, (launch,), inventories, desktop=desktop)
    final_proxy = inventories[1]["containers"][armed["id"]]
    require(final_proxy["image"] == armed["image"] and final_proxy["labels"] == armed["labels"]
            and final_proxy["state"]["started_at"] == armed["state"]["StartedAt"])
    _same(sorted(final_proxy["mounts"], key=lambda row: row["Destination"]), armed["mounts"])
    return {
        operation.replace("-", "_") + "_reply_loss": {**counts, "map_issued_sequence": "1", "local_last_sequence": str(int(issued)),
            "consumed": issued, "runtime_bind_confirmed": terminal_loss or operation == "runtime-bind", "operator_stop_requested": False,
            "owned_stopped_container_count": owned,
            **{key: proof[key] for key in ("audit_sha256", "retirement_sha256", "host_retirement_sha256", "terminal_sha256")},
            **{key: proxy[key] for key in ("config_sha256", "ca_sha256", "adapter_sha256")},
            **({"evidence_count": 5, "evidence_sha256": proof["evidence_sha256"],
                "artifact_sha256": committed["results"][0]["artifact_sha256"],
                "case_sha256": _digest(proof["case"]),
                "result_receipt_sha256": committed["results"][0]["receipt_sha256"],
                "server_outcome": terminal["outcome"], "reconciliation_state": policy["reconciliation"]}
               if terminal_loss else {})},
        "platform": "win32" if desktop else "linux", "container_platform": "linux",
        "empty_builtin_bridge_id_change_count": admitted,
        "nm2_exit_status": "incomplete", "resources_retained": True,
    }


def _map_disconnect_projection(raw, selection, inventories, *, desktop):
    from nm2_worker_launch_acceptance import (
        MAP_DISCONNECT_LEASE_NS, MAP_DISCONNECT_SOURCES, engine_timestamp_ns,
    )

    sources = selection["sources"]
    require(
        all(sources[name]["commit"] == commit for name, commit in MAP_DISCONNECT_SOURCES.items())
        and not any(key in raw for key in (
            "launch_pair", "stopped_predecessor", "completed_job", "cancelled_job",
            "unclaimed_job", "unissued_job", "duration_exhaustion", "target_exhaustion",
            "concurrency_exhaustion",
        ))
    )
    if "map_disconnect_audit" in raw:
        audit = raw["map_disconnect_audit"]
        keys = {
            "started_monotonic_ns", "finished_monotonic_ns",
            "api_stop_call_monotonic_ns", "exit_observed_monotonic_ns",
        }
        require(
            type(audit) is dict and set(audit) == keys
            and all(type(audit[key]) is int and audit[key] >= 0 for key in keys)
            and audit["started_monotonic_ns"] <= audit["finished_monotonic_ns"]
            and audit["started_monotonic_ns"] <= audit["api_stop_call_monotonic_ns"]
            <= audit["exit_observed_monotonic_ns"]
        )
    launch = raw["launch"]
    _launch_row(launch, 1)
    require(launch["predecessor_cids"] == [])
    _hash(launch["bootstrap_audit_sha256"])
    counts = {
        "target_requests": 3, "capacity_before": 1, "capacity_after": 0,
        "targets_spent": 1, "duration_allocated": 30, "remaining_local_holds": 0,
    }
    hashes = ("audit_sha256", "retirement_sha256", "host_retirement_sha256", "terminal_sha256")
    timing = ("api_cut_to_worker_exit_ns", "physical_exit_elapsed_ns")
    proof = raw["map_disconnect"]
    require(
        type(proof) is dict and set(proof) == set(counts) | set(hashes) | set(timing) | {
            "api_container_id", "api_started_at", "api_finished_at", "api_restarted_at", "terminal_cause",
        }
        and all(type(proof[key]) is int and proof[key] == count for key, count in counts.items())
        and all(type(proof[key]) is int for key in timing)
        and proof["terminal_cause"] == "observed_exit"
        and proof["retirement_sha256"] == launch["retirement_sha256"]
    )
    for key in hashes:
        _hash(proof[key])
    _hash(proof["api_container_id"])
    api_started = engine_timestamp_ns(proof["api_started_at"])
    api_stopped = engine_timestamp_ns(proof["api_finished_at"])
    api_restarted = engine_timestamp_ns(proof["api_restarted_at"])
    worker_started = engine_timestamp_ns(launch["started_at"])
    worker_finished = engine_timestamp_ns(launch["finished_at"])
    cut_to_exit = proof["api_cut_to_worker_exit_ns"]
    require(
        api_started < worker_started < api_stopped < worker_finished < api_restarted
        and cut_to_exit == worker_finished - api_stopped
        and cut_to_exit <= MAP_DISCONNECT_LEASE_NS
        and cut_to_exit < proof["physical_exit_elapsed_ns"] < 15_000_000_000
    )
    owned, admitted = _launch_retention(raw, selection, (launch,), inventories, desktop=desktop)
    api_id = proof["api_container_id"]
    before, after = inventories
    api = after["containers"][api_id]
    require(
        api_id not in before["containers"]
        and api["labels"]["com.docker.compose.service"] == "api"
        and api["state"]["started_at"] == proof["api_restarted_at"]
        and engine_timestamp_ns(api["state"]["finished_at"]) > api_restarted
        and type(api["restarts"]) is int and api["restarts"] == 0
    )
    return {
        "map_disconnect": {
            **{key: proof[key] for key in (*counts, *hashes, *timing, "terminal_cause")},
            "configured_lease_ceiling_ns": MAP_DISCONNECT_LEASE_NS,
            "lease_evidence": "configured_ceiling_only",
            "owned_stopped_container_count": owned,
        },
        "platform": "win32" if desktop else "linux",
        "container_platform": "linux", "empty_builtin_bridge_id_change_count": admitted,
        "nm2_exit_status": "incomplete", "resources_retained": True,
    }


def _cancelled_partial_retention(value, proof, selection):
    fields = {
        "artifact_sha256", "result_receipt_sha256", "terminal_receipt_sha256",
        "evidence_count", "evidence_sha256", "assessment_status", "binding", "case_sha256",
    }
    witness = _fields(value, fields)
    binding = _fields(witness["binding"], _BINDING)
    require(
        binding["job_id"] == proof["job_id"]
        and binding["origin"] == f"https://vardrsec.localhost:{selection['https_port']}/backend"
        and type(binding["fence"]) is int and 1 <= binding["fence"] <= 2**53 - 1
        and type(witness["evidence_count"]) is int and witness["evidence_count"] == 5
        and witness["assessment_status"] == "inconclusive"
    )
    for key in ("runner_id", "contract_id", "attempt_id"):
        _uuid(binding[key])
    _hash(binding["contract_sha256"])
    for key in ("artifact_sha256", "result_receipt_sha256", "terminal_receipt_sha256",
                "evidence_sha256", "case_sha256"):
        _hash(witness[key])
    result_sha = _digest({
        "schema": "vardr.managed-result/1", **binding,
        "artifact_sha256": witness["artifact_sha256"], "case_sha256": witness["case_sha256"],
    })
    require(
        witness["result_receipt_sha256"] == result_sha
        and witness["terminal_receipt_sha256"] == proof["terminal_sha256"] == _digest({
            "schema": "vardr.managed-completion/1", **binding,
            "receipt_sha256": result_sha, "outcome": "failed", "capacity_reserved": False,
        })
    )
    return {key: witness[key] for key in fields - {"binding"}}


def launch_projection(raw, selection, *, inventories=(), desktop=False):
    scenario = raw.get("scenario")
    require(
        type(scenario) is str and scenario in LAUNCH_SCENARIOS
        and type(desktop) is bool
        and (not desktop or scenario in {
            LAUNCH_STOPPED_PREDECESSOR_SCENARIO, LAUNCH_CONCURRENCY_SCENARIO,
            LAUNCH_MAP_DISCONNECT_SCENARIO, LAUNCH_GRANT_REVOKE_SCENARIO, LAUNCH_PRECLAIM_SCENARIO, *REPLY_LOSS_OPERATIONS,
            LAUNCH_PID1_LOSS_SCENARIO,
            LAUNCH_REPEAT_SCENARIO,
        })
    )
    budget = LAUNCH_BUDGETS.get(scenario)
    status = f"selected_{budget}_exhaustion_slice_passed" if budget else "selected_launch_slice_passed"
    stage = f"selected_{budget}_exhaustion_complete" if budget else "selected_launch_complete"
    if scenario in REPLY_LOSS_OPERATIONS:
        status, stage = (("selected_claim_reply_loss_slice_passed", "selected_claim_reply_loss_complete")
                         if scenario == LAUNCH_CLAIM_REPLY_LOSS_SCENARIO else
                         ("selected_terminal_reply_loss_slice_passed", "selected_terminal_reply_loss_complete")
                         if REPLY_LOSS_OPERATIONS[scenario] in {"result","finish"} else
                         ("selected_" + REPLY_LOSS_OPERATIONS[scenario].replace("-","_") + "_reply_loss_slice_passed",
                          "selected_" + REPLY_LOSS_OPERATIONS[scenario].replace("-","_") + "_reply_loss_complete"))
    if scenario == LAUNCH_MAP_DISCONNECT_SCENARIO:
        status, stage = "selected_map_disconnect_slice_passed", "selected_map_disconnect_complete"
    require(
        raw.get("expected_database_revision") == "0041persistentruntime"
        and raw.get("acceptance_scope") == LAUNCH_SCOPES[scenario]
        and raw.get("status") == status
        and raw.get("stage") == stage
        and raw.get("retained") is True
        and raw.get("platform") == ("win32" if desktop else "linux")
        and raw.get("nm2_exit_status") == "incomplete"
        and raw.get("sources") == selection["sources"]
        and raw.get("images") == selection["images"]
        and raw.get("project") == selection["project"]
    )
    if scenario in REPLY_LOSS_OPERATIONS:
        return _claim_reply_loss_projection(raw, selection, inventories, desktop=desktop, operation=REPLY_LOSS_OPERATIONS[scenario])
    if scenario == LAUNCH_MAP_DISCONNECT_SCENARIO:
        return _map_disconnect_projection(raw, selection, inventories, desktop=desktop)
    if scenario == LAUNCH_CONCURRENCY_SCENARIO:
        return _concurrency_projection(raw, selection)
    if budget:
        return _budget_projection(raw, selection, budget)
    require(not any(key in raw for key in (
        "launch", "duration_exhaustion", "target_exhaustion", "concurrency_exhaustion",
    )))
    pair = raw["launch_pair"]
    require(type(pair) is list and len(pair) == 2)
    for ordinal, row in enumerate(pair, 1):
        _launch_row(row, ordinal)
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
    if scenario == LAUNCH_COMPLETED_SCENARIO:
        result["completed_job"] = _completed_launch(raw.get("completed_job"), first)
    else:
        require("completed_job" not in raw)
    if scenario in LAUNCH_CANCELLATION_SCENARIOS:
        proof = raw.get("cancelled_job")
        active_expiry = scenario == LAUNCH_ACTIVE_GRANT_EXPIRY_SCENARIO
        authority_key, expected_causes = {
            LAUNCH_LOCAL_STOP_SCENARIO: ("local_stop_sha256", {"local_emergency_stop"}),
            LAUNCH_GRANT_REVOKE_SCENARIO: ("grant_revocation_sha256", {"local_emergency_stop"}),
            LAUNCH_ACTIVE_GRANT_EXPIRY_SCENARIO: (
                "grant_expiry_sha256",
                {"authorization_deadline", "control_lease_expired", "local_emergency_stop", "tool_timeout"},
            ),
        }.get(scenario, ("cancel_requested_sha256", {"remote_stop_requested", "control_lease_expired"}))
        allowed_causes = (
            expected_causes if scenario == LAUNCH_GRANT_REVOKE_SCENARIO
            else expected_causes | {"observed_exit"}
        )
        fields = {"job_id", "retirement_sha256", "audit_sha256", "target_requests",
                  "terminal_sha256", "terminal_cause", authority_key, "physical_exit_elapsed_ns"}
        if active_expiry:
            fields.add("grant_expiry_elapsed_ns")
        require(
            type(proof) is dict
            and set(proof) in (fields, fields | {"partial_retention"})
            and type(proof["target_requests"]) is int and proof["target_requests"] == 3
            and type(proof["physical_exit_elapsed_ns"]) is int
            and 0 < proof["physical_exit_elapsed_ns"] < 15_000_000_000
            and type(proof["terminal_cause"]) is str
            and proof["terminal_cause"] in allowed_causes
            and proof["retirement_sha256"] == first["retirement_sha256"]
        )
        _uuid(proof["job_id"])
        _hash(proof["audit_sha256"])
        _hash(proof["terminal_sha256"])
        _hash(proof[authority_key])
        if active_expiry:
            expiry = proof["grant_expiry_elapsed_ns"]
            earliest_offset = -1_000_000_000 if proof["terminal_cause"] == "tool_timeout" else 0
            require(
                type(expiry) is int and 1_000_000_000 <= expiry <= 14_000_000_000
                and earliest_offset <= proof["physical_exit_elapsed_ns"] - expiry <= 2_500_000_000
            )
        result["cancelled_job"] = {key: value for key, value in proof.items() if key != "partial_retention"}
        if "partial_retention" in proof:
            result["cancelled_job"]["partial_retention"] = _cancelled_partial_retention(
                proof["partial_retention"], proof, selection
            )
    else:
        require("cancelled_job" not in raw)
    if scenario == LAUNCH_STOP_WORK_QUEUED_SCENARIO:
        unclaimed = raw.get("unclaimed_job")
        require(
            type(unclaimed) is dict and set(unclaimed) == {"job_id", "approval_inventory_sha256"}
            and unclaimed["job_id"] != result["cancelled_job"]["job_id"]
        )
        _uuid(unclaimed["job_id"])
        _hash(unclaimed["approval_inventory_sha256"])
        result["unclaimed_job"] = unclaimed
    else:
        require("unclaimed_job" not in raw)
    if scenario in LAUNCH_GRANT_DENIAL_SCENARIOS:
        unissued = raw.get("unissued_job")
        fields = {"job_id", "retirement_sha256", "audit_sha256", "unissued_discoveries"}
        if scenario == LAUNCH_EXPIRED_GRANT_SCENARIO:
            fields.add("grant_expiry_sha256")
        require(
            type(unissued) is dict
            and set(unissued) == fields
            and type(unissued["unissued_discoveries"]) is int
            and 0 < unissued["unissued_discoveries"] <= 40
            and unissued["retirement_sha256"] == first["retirement_sha256"]
        )
        _uuid(unissued["job_id"])
        _hash(unissued["audit_sha256"])
        if scenario == LAUNCH_EXPIRED_GRANT_SCENARIO:
            _hash(unissued["grant_expiry_sha256"])
        result["unissued_job"] = unissued
    else:
        require("unissued_job" not in raw)
    if scenario == LAUNCH_PRECLAIM_SCENARIO:
        return _preclaim_projection(raw, selection, first, second, inventories, desktop=desktop)
    if scenario == LAUNCH_REPEAT_SCENARIO:
        return _repeat_retirement_projection(raw, selection, first, second, inventories, desktop=desktop)
    if scenario in {LAUNCH_STOPPED_PREDECESSOR_SCENARIO, LAUNCH_PID1_LOSS_SCENARIO}:
        result = _stopped_predecessor_projection(
            raw, selection, first, second, inventories, desktop=desktop
        )
        require("repeated_managed_claim" not in raw)
        return result
    return result


def grant_revocation_desktop_projection(raw, selection, *, inventories):
    """Read the existing Desktop revocation case, including optional C01 witness."""
    require(
        type(raw) is dict and raw.get("schema") == LAUNCH_SCHEMA
        and raw.get("scenario") == LAUNCH_GRANT_REVOKE_SCENARIO
    )
    try:
        result = launch_projection(raw, selection, desktop=True)
        owned, admitted = _launch_retention(
            raw, selection, tuple(raw["launch_pair"]), inventories, desktop=True
        )
        return {**result, "platform": "win32", "container_platform": "linux",
                "owned_stopped_container_count": owned,
                "empty_builtin_bridge_id_change_count": admitted}
    except (KeyError, TypeError, IndexError, ValueError):
        raise HostedRefused("nm2_desktop_grant_revocation_receipt_refused") from None


def concurrency_desktop_projection(raw, selection):
    """Read only the Windows Desktop shared-capacity fixture evidence."""
    require(
        type(raw) is dict and raw.get("schema") == LAUNCH_SCHEMA
        and raw.get("scenario") == LAUNCH_CONCURRENCY_SCENARIO
    )
    try:
        return launch_projection(raw, selection, desktop=True)
    except (KeyError, TypeError, IndexError, ValueError):
        raise HostedRefused("nm2_desktop_concurrency_receipt_refused") from None


def claim_reply_loss_desktop_projection(raw, selection, *, inventories):
    """Read only the Windows Desktop committed claim/reply-loss evidence."""
    require(type(raw) is dict and raw.get("schema") == LAUNCH_SCHEMA
            and raw.get("scenario") in REPLY_LOSS_OPERATIONS)
    try:
        return launch_projection(raw, selection, inventories=inventories, desktop=True)
    except (KeyError, TypeError, IndexError, ValueError):
        raise HostedRefused("nm2_desktop_claim_reply_loss_receipt_refused") from None


def map_disconnect_desktop_projection(raw, selection, *, inventories):
    """Read only the Windows Desktop ordinary Map outage evidence."""
    require(
        type(raw) is dict and raw.get("schema") == LAUNCH_SCHEMA
        and raw.get("scenario") == LAUNCH_MAP_DISCONNECT_SCENARIO
    )
    try:
        return launch_projection(raw, selection, inventories=inventories, desktop=True)
    except (KeyError, TypeError, IndexError, ValueError):
        raise HostedRefused("nm2_desktop_map_disconnect_receipt_refused") from None


def pid1_loss_desktop_projection(raw, selection, *, inventories):
    """Read only the Windows Desktop PID1-loss fixture evidence."""
    require(
        type(raw) is dict and raw.get("schema") == LAUNCH_SCHEMA
        and raw.get("scenario") == LAUNCH_PID1_LOSS_SCENARIO
    )
    try:
        return launch_projection(raw, selection, inventories=inventories, desktop=True)
    except (KeyError, TypeError, IndexError, ValueError):
        raise HostedRefused("nm2_desktop_pid1_loss_receipt_refused") from None


def stopped_predecessor_desktop_projection(raw, selection, *, inventories):
    """Read only the Windows Desktop stopped-predecessor fixture evidence."""
    require(
        type(raw) is dict and raw.get("schema") == LAUNCH_SCHEMA
        and raw.get("scenario") == LAUNCH_STOPPED_PREDECESSOR_SCENARIO
    )
    try:
        return launch_projection(raw, selection, inventories=inventories, desktop=True)
    except (KeyError, TypeError, IndexError, ValueError):
        raise HostedRefused("nm2_desktop_stopped_predecessor_receipt_refused") from None


def public_projection(raw, selection, *, inventories=()):
    """Project only fixed statuses and measured hashes, never raw nested data."""
    if type(raw) is dict and raw.get("schema") == STALE_CLAIM_SCHEMA:
        from nm2_worker_strict_projection import project

        try:
            return project(raw, selection, *inventories)
        except (ValueError, TypeError, KeyError, IndexError):
            raise HostedRefused("nm2_hosted_strict_stale_claim_receipt_refused") from None
    if type(raw) is dict and raw.get("schema") in (STRICT_DRIFT_SCHEMA, STRICT_REVIEW_SCHEMA):
        from nm2_worker_strict_projection import project

        try:
            return project(raw, selection, *inventories)
        except (ValueError, TypeError, KeyError, IndexError):
            reason = (
                "nm2_hosted_strict_drift_receipt_refused" if raw["schema"] == STRICT_DRIFT_SCHEMA
                else "nm2_hosted_strict_review_receipt_refused"
            )
            raise HostedRefused(reason) from None
    if type(raw) is dict and raw.get("schema") == LAUNCH_SCHEMA:
        if raw.get("scenario") in REPLY_LOSS_OPERATIONS:
            try:
                return launch_projection(raw, selection, inventories=inventories)
            except (KeyError, TypeError, IndexError, ValueError):
                raise HostedRefused("nm2_hosted_claim_reply_loss_receipt_refused") from None
        if raw.get("scenario") == LAUNCH_MAP_DISCONNECT_SCENARIO:
            try:
                return launch_projection(raw, selection, inventories=inventories)
            except (KeyError, TypeError, IndexError, ValueError):
                raise HostedRefused("nm2_hosted_map_disconnect_receipt_refused") from None
        if raw.get("scenario") == LAUNCH_PRECLAIM_SCENARIO:
            return launch_projection(raw, selection, inventories=inventories)
        if raw.get("scenario") in {
            LAUNCH_STOPPED_PREDECESSOR_SCENARIO, LAUNCH_REPEAT_SCENARIO, LAUNCH_PID1_LOSS_SCENARIO,
        }:
            try:
                return launch_projection(raw, selection, inventories=inventories)
            except (KeyError, TypeError, IndexError, ValueError):
                raise HostedRefused("nm2_hosted_stopped_predecessor_receipt_refused") from None
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
        elif self.scenario == STALE_CLAIM_SCENARIO:
            self.receipt.update(schema=STALE_CLAIM_HOSTED, scenario=self.scenario,
                expected_database_revision=self.database_revision,
                scope="Stale registered Strict approval refused by installed Map claim; NM2 remains incomplete")
        elif self.scenario == STRICT_REVIEW_SCENARIO:
            self.receipt.update(schema=STRICT_REVIEW_HOSTED, scenario=self.scenario,
                expected_database_revision=self.database_revision,
                scope="Missing-authority and closed-window Strict review denials; NM2 remains incomplete")
        elif self.scenario == STRICT_DRIFT_SCENARIO:
            self.receipt.update(schema=STRICT_DRIFT_HOSTED, scenario=self.scenario,
                expected_database_revision=self.database_revision,
                scope="Strict authority drift only; other Strict denials and NM2 remain incomplete")
        elif self.scenario in REPLY_LOSS_OPERATIONS:
            self.receipt.update(schema=REPLY_LOSS_HOSTED[self.scenario], scenario=self.scenario,
                                expected_database_revision=self.database_revision,
                                scope=LAUNCH_SCOPES[self.scenario])
        elif self.scenario == LAUNCH_MAP_DISCONNECT_SCENARIO:
            self.receipt.update(
                schema=MAP_DISCONNECT_HOSTED, scenario=self.scenario,
                expected_database_revision=self.database_revision,
                scope=LAUNCH_SCOPES[self.scenario],
            )
        elif self.scenario == LAUNCH_REPEAT_SCENARIO:
            self.receipt.update(schema=REPEAT_HOSTED, scenario=self.scenario,
                expected_database_revision=self.database_revision, scope=LAUNCH_SCOPES[self.scenario])
        elif self.scenario == LAUNCH_PRECLAIM_SCENARIO:
            self.receipt.update(schema=PRECLAIM_HOSTED, scenario=self.scenario,
                expected_database_revision=self.database_revision, scope=LAUNCH_SCOPES[self.scenario])
        elif self.scenario == LAUNCH_STOPPED_PREDECESSOR_SCENARIO:
            self.receipt.update(
                schema=STOPPED_PREDECESSOR_HOSTED, scenario=self.scenario,
                expected_database_revision=self.database_revision,
                scope=LAUNCH_SCOPES[self.scenario],
            )
        elif self.scenario == LAUNCH_PID1_LOSS_SCENARIO:
            self.receipt.update(
                schema=PID1_LOSS_HOSTED, scenario=self.scenario,
                expected_database_revision=self.database_revision,
                scope=LAUNCH_SCOPES[self.scenario],
            )
        elif self.scenario in LAUNCH_SCENARIOS:
            self.receipt.update(
                schema=LAUNCH_BUDGET_SCHEMAS.get(self.scenario, "vardr.nm2-hosted/7"),
                scenario=self.scenario,
                expected_database_revision=self.database_revision,
                scope=LAUNCH_SCOPES[self.scenario],
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

    def command(self, args, *, capture=False, timeout=60, stdin=None):
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
                    **({"input": stdin} if stdin is not None else {}),
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

    def prepare_sources(self, names=None):
        self.receipt["stage"] = "sources"
        require(
            self.command(["git", "rev-parse", "HEAD"], capture=True)
            == self.pins["distribution"]
        )
        selected = tuple(REPOSITORIES) if names is None else names
        require(type(selected) is tuple and selected in (tuple(REPOSITORIES), ("runner", "gate")))
        for name in selected:
            repository = REPOSITORIES[name]
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

    def build_worker_images(self, *, persistent):
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
                if persistent
                else "Dockerfile.worker"
            ),
            extra=("--build-arg", "RUNNER_BASE_IMAGE=" + tag),
        )[0]
        return toolkit, tag

    def run_bootstrap(self):
        """Build and qualify only Runner/Gate; invoke the unchanged two-case fixture."""
        import nm2_worker_acceptance as shared
        import nm2_worker_bootstrap as bootstrap

        self.receipt = {
            "schema": "vardr.nm2-hosted-bootstrap/1", "status": "held",
            "stage": "sources", "scenario": BOOTSTRAP_SCENARIO,
            "scope": "two_target_free_bootstrap_configuration_refusals",
            "sources": {n: self.pins[n] for n in ("distribution", "runner", "gate")},
            "source_trees": {}, "images": {}, "nm2_exit_status": "incomplete",
        }
        self.prepare_sources(names=("runner", "gate"))

        def frozen_inputs():
            result = {}
            for name in ("runner", "gate"):
                source = self.sources[name]
                require(self.command(
                    ["git", "-C", str(source), "rev-parse", "HEAD"], capture=True
                ) == self.pins[name])
                require(not self.command(
                    ["git", "-C", str(source), "status", "--porcelain", "--untracked-files=no"],
                    capture=True,
                ))
                names = self.command(
                    ["git", "-C", str(source), "ls-files", "-z"], capture=True
                ).split("\0")
                result[name] = {
                    relative: hashlib.sha256((source / relative).read_bytes()).hexdigest()
                    for relative in names if relative
                }
            return result

        frozen = frozen_inputs()
        self.build_worker_images(persistent=True)
        image = self.receipt["images"]["worker"]
        self.receipt["stage"] = "bootstrap_qualification"
        measured = shared.image_source(
            "runner", self.sources["runner"], image, self.project,
            lambda *args, **kwargs: self.docker(*args, capture=True, **kwargs),
        )
        self.docker(
            "run", "--rm", "--network", "none", "--user", "10001:10001",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--read-only", "--pids-limit", "64", "--memory", "512m", "--cpus", "1",
            "--label", "com.docker.compose.project=" + self.project,
            "--entrypoint", "/usr/local/bin/python", image,
            "-I", "-m", "pip", "check", capture=True,
        )
        require(frozen_inputs() == frozen)
        source_hashes = frozen["runner"]
        owner = measured["executables"]["/usr/local/bin/vardr-worker-owner"]
        require(re.fullmatch(r"[0-9a-f]{64}", owner)
                and measured["image_id"] == image)
        qualification = {
            "status": "passed_frozen_build_dependency_probe", "image": image,
            "source_commit": self.pins["runner"],
            "source_tree": self.receipt["source_trees"]["runner"],
            "source_manifest_sha256": shared.digest(shared.canonical(source_hashes)),
            "source_hashes": source_hashes,
            "python_inventory_sha256": measured["python_inventory_sha256"],
            "owner_binary_sha256": owner,
        }
        build_receipt = self.root / "bootstrap-build.json"
        shared.publish(build_receipt, shared.canonical(qualification))
        output = self.root / "bootstrap"
        selection = bootstrap.validate(argparse.Namespace(
            build_receipt=build_receipt, image=image, owner_sha256=owner,
            docker_context="default", project=self.project, output=output,
            allow_empty_builtin_bridge_id_change=False,
        ))
        self.receipt["stage"] = "bootstrap_harness"
        raw = bootstrap.Bootstrap(selection).run()
        require(raw["schema"] == "vardr.nm2-worker-bootstrap/1"
                and raw["status"] == "passed_configuration_refusals"
                and raw["image"] == image
                and raw["owner_binary_sha256"] == owner
                and raw["source_commit"] == self.pins["runner"]
                and raw["source_tree"] == qualification["source_tree"]
                and set(raw["cases"]) == set(bootstrap.CASES))
        for case in raw["cases"].values():
            require(case["status"] == "passed" and type(case["exit_code"]) is int
                    and case["exit_code"] == 125 and case["readiness_absent"] is True
                    and case["descendant_absence"] == "not_independently_observed")
        self.receipt.update(
            status="passed_configuration_refusals", stage="complete",
            source_manifest_sha256=qualification["source_manifest_sha256"],
            python_inventory_sha256=measured["python_inventory_sha256"],
            owner_binary_sha256=owner,
            owner_source_sha256=source_hashes["container/worker_owner.c"],
            cases={name: {
                "status": "passed", "exit_code": 125, "readiness_absent": True,
                "descendant_absence": "not_independently_observed",
            } for name in bootstrap.CASES},
            resources_retained=True, owned_stopped_container_count=2,
        )

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
            *{
                LAUNCH_SCENARIO: [],
                LAUNCH_STOPPED_PREDECESSOR_SCENARIO: ["--stopped-predecessor"],
                LAUNCH_PID1_LOSS_SCENARIO: ["--pid1-loss"],
                LAUNCH_PRECLAIM_SCENARIO: ["--preclaim-recovery"],
                LAUNCH_REPEAT_SCENARIO: ["--repeat-managed-claim"],
                LAUNCH_MAP_DISCONNECT_SCENARIO: ["--map-disconnect"],
                LAUNCH_CLAIM_REPLY_LOSS_SCENARIO: ["--claim-reply-loss"],
                LAUNCH_RESULT_REPLY_LOSS_SCENARIO: ["--result-reply-loss"],
                LAUNCH_FINISH_REPLY_LOSS_SCENARIO: ["--finish-reply-loss"],
                LAUNCH_CONSUME_REPLY_LOSS_SCENARIO: ["--consume-reply-loss"],
                LAUNCH_BIND_REPLY_LOSS_SCENARIO: ["--runtime-bind-reply-loss"],
                LAUNCH_COMPLETED_SCENARIO: ["--completed-job"],
                LAUNCH_STOP_WORK_SCENARIO: ["--stop-work"],
                LAUNCH_STOP_WORK_QUEUED_SCENARIO: ["--stop-work-queued"],
                LAUNCH_LOCAL_STOP_SCENARIO: ["--local-stop"],
                LAUNCH_MISSING_GRANT_SCENARIO: ["--missing-grant"],
                LAUNCH_GRANT_REVOKE_SCENARIO: ["--revoke-grant"],
                LAUNCH_EXPIRED_GRANT_SCENARIO: ["--expire-grant"],
                LAUNCH_ACTIVE_GRANT_EXPIRY_SCENARIO: ["--expire-active-grant"],
                LAUNCH_DURATION_SCENARIO: ["--duration-exhaustion"],
                LAUNCH_TARGET_SCENARIO: ["--target-exhaustion"],
                LAUNCH_CONCURRENCY_SCENARIO: ["--concurrency-exhaustion"],
            }[self.scenario],
            "--execute",
        ]

    def run(self):
        try:
            self.daemon_guard()
            if self.scenario == BOOTSTRAP_SCENARIO:
                self.run_bootstrap()
                return
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
            toolkit, tag = self.build_worker_images(
                persistent=self.scenario in PERSISTENT_SCENARIOS
            )
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
                    LAUNCH_STOPPED_PREDECESSOR_SCENARIO: LAUNCH_SCHEMA,
                    LAUNCH_PID1_LOSS_SCENARIO: LAUNCH_SCHEMA,
                    LAUNCH_PRECLAIM_SCENARIO: LAUNCH_SCHEMA,
                    LAUNCH_REPEAT_SCENARIO: LAUNCH_SCHEMA,
                    LAUNCH_MAP_DISCONNECT_SCENARIO: LAUNCH_SCHEMA,
                    **{scenario: LAUNCH_SCHEMA for scenario in REPLY_LOSS_OPERATIONS},
                    LAUNCH_COMPLETED_SCENARIO: LAUNCH_SCHEMA,
                    LAUNCH_STOP_WORK_SCENARIO: LAUNCH_SCHEMA,
                    LAUNCH_STOP_WORK_QUEUED_SCENARIO: LAUNCH_SCHEMA,
                    LAUNCH_LOCAL_STOP_SCENARIO: LAUNCH_SCHEMA,
                    LAUNCH_MISSING_GRANT_SCENARIO: LAUNCH_SCHEMA,
                    LAUNCH_GRANT_REVOKE_SCENARIO: LAUNCH_SCHEMA,
                    LAUNCH_EXPIRED_GRANT_SCENARIO: LAUNCH_SCHEMA,
                    LAUNCH_ACTIVE_GRANT_EXPIRY_SCENARIO: LAUNCH_SCHEMA,
                    LAUNCH_DURATION_SCENARIO: LAUNCH_SCHEMA,
                    LAUNCH_TARGET_SCENARIO: LAUNCH_SCHEMA,
                    LAUNCH_CONCURRENCY_SCENARIO: LAUNCH_SCHEMA,
                    STRICT_DRIFT_SCENARIO: STRICT_DRIFT_SCHEMA,
                    STRICT_REVIEW_SCENARIO: STRICT_REVIEW_SCHEMA,
                    STALE_CLAIM_SCENARIO: STALE_CLAIM_SCHEMA,
                }[self.scenario]
            )
            if self.scenario in {
                STRICT_DRIFT_SCENARIO, STRICT_REVIEW_SCENARIO, STALE_CLAIM_SCENARIO,
                LAUNCH_STOPPED_PREDECESSOR_SCENARIO, LAUNCH_PRECLAIM_SCENARIO, LAUNCH_REPEAT_SCENARIO,
                LAUNCH_PID1_LOSS_SCENARIO, LAUNCH_MAP_DISCONNECT_SCENARIO, *REPLY_LOSS_OPERATIONS,
            }:
                inventories = []
                for name in ("before", "after"):
                    with (self.root / f"installation/nm2-inventory-{name}.json").open("rb") as handle:
                        inventories.append(decode_receipt(handle.read(4 * 1024 * 1024 + 1)))
                self.receipt.update(public_projection(observed, selection, inventories=inventories))
                if self.scenario == STRICT_DRIFT_SCENARIO:
                    self.receipt["remaining_required_cases"]["strict_other_denials"] = (
                        "authority_drift_verified_other_strict_denials_open"
                    )
                elif self.scenario == STRICT_REVIEW_SCENARIO:
                    self.receipt["remaining_required_cases"]["strict_other_denials"] = (
                        "missing_and_expired_reviews_verified_stale_registered_claim_open"
                    )
                elif self.scenario == STALE_CLAIM_SCENARIO:
                    self.receipt["remaining_required_cases"]["strict_other_denials"] = (
                        "stale_registered_claim_refusal_verified_selected_cohort"
                    )
                elif self.scenario in REPLY_LOSS_OPERATIONS:
                    operation = REPLY_LOSS_OPERATIONS[self.scenario]
                    self.receipt["remaining_required_cases"][
                        "lost_terminal_reply" if operation in {"result","finish"} else "lost_claim_consume_bind_reply"
                    ] = ("committed_claim_reply_loss_verified_consume_bind_open" if operation == "claim"
                         else operation + "_reply_loss_verified_other_boundary_independent" if operation in {"result","finish"}
                         else "committed_" + operation.replace("-","_") + "_reply_loss_verified_other_stages_open")
                elif self.scenario == LAUNCH_MAP_DISCONNECT_SCENARIO:
                    self.receipt["remaining_required_cases"]["map_disconnect"] = (
                        "ordinary_api_outage_verified_selected_cohort"
                    )
                elif self.scenario == LAUNCH_REPEAT_SCENARIO:
                    self.receipt["remaining_required_cases"]["restart_duplicate_claim"] = (
                        "installed_repeat_and_stopped_predecessor_verified_server_race_component_proof_separate"
                    )
                elif self.scenario == LAUNCH_PRECLAIM_SCENARIO:
                    self.receipt["remaining_required_cases"]["persisted_preclaim_recovery"] = "trusted_synthetic_closed_parent0_verified"
                else:
                    self.receipt["remaining_required_cases"]["worker_crash_stop"] = (
                        "ordinary_operator_stop_verified_crash_open"
                    )
                    self.receipt["remaining_required_cases"]["restart_duplicate_claim"] = (
                        "stopped_predecessor_verified_duplicate_claim_open"
                    )
            else:
                self.receipt.update(public_projection(observed, selection))
            verified_case = {
                LAUNCH_STOP_WORK_QUEUED_SCENARIO: "engagement_stop_work",
                LAUNCH_LOCAL_STOP_SCENARIO: "local_emergency_stop",
                LAUNCH_MISSING_GRANT_SCENARIO: "missing_local_grant",
            }.get(self.scenario)
            if verified_case is not None:
                self.receipt["remaining_required_cases"][verified_case] = "verified_selected_cohort"
            if self.scenario == LAUNCH_GRANT_REVOKE_SCENARIO:
                self.receipt["remaining_required_cases"]["target_grant_expiry_revocation"] = (
                    "revocation_verified_expiry_open"
                )
            if self.scenario == LAUNCH_EXPIRED_GRANT_SCENARIO:
                self.receipt["remaining_required_cases"]["target_grant_expiry_revocation"] = (
                    "expiry_before_claim_verified"
                )
            if self.scenario == LAUNCH_ACTIVE_GRANT_EXPIRY_SCENARIO:
                self.receipt["remaining_required_cases"]["target_grant_expiry_revocation"] = (
                    "active_expiry_verified_selected_cohort"
                )
            if self.scenario == LAUNCH_DURATION_SCENARIO:
                self.receipt["remaining_required_cases"]["budget_exhaustion"] = (
                    "allocated_duration_exhaustion_verified_selected_cohort"
                )
            if self.scenario == LAUNCH_TARGET_SCENARIO:
                self.receipt["remaining_required_cases"]["budget_exhaustion"] = (
                    "represented_origin_exhaustion_verified_selected_cohort"
                )
            if self.scenario == LAUNCH_CONCURRENCY_SCENARIO:
                self.receipt["remaining_required_cases"]["budget_exhaustion"] = (
                    "shared_concurrency_exhaustion_verified_selected_cohort"
                )
            self.receipt.update(
                schema={
                    "healthy": "vardr.nm2-hosted/2",
                    "persistent-availability": "vardr.nm2-hosted/3",
                    "persistent-count-limit": "vardr.nm2-hosted/4",
                    "persistent-idle-limit": "vardr.nm2-hosted/5",
                    "persistent-empty-stop": "vardr.nm2-hosted/6",
                    LAUNCH_SCENARIO: "vardr.nm2-hosted/7",
                    LAUNCH_STOPPED_PREDECESSOR_SCENARIO: STOPPED_PREDECESSOR_HOSTED,
                    LAUNCH_PID1_LOSS_SCENARIO: PID1_LOSS_HOSTED,
                    LAUNCH_PRECLAIM_SCENARIO: PRECLAIM_HOSTED,
                    LAUNCH_REPEAT_SCENARIO: REPEAT_HOSTED,
                    LAUNCH_MAP_DISCONNECT_SCENARIO: MAP_DISCONNECT_HOSTED,
                    **REPLY_LOSS_HOSTED,
                    LAUNCH_COMPLETED_SCENARIO: "vardr.nm2-hosted/7",
                    LAUNCH_STOP_WORK_SCENARIO: "vardr.nm2-hosted/7",
                    LAUNCH_STOP_WORK_QUEUED_SCENARIO: "vardr.nm2-hosted/7",
                    LAUNCH_LOCAL_STOP_SCENARIO: "vardr.nm2-hosted/7",
                    LAUNCH_MISSING_GRANT_SCENARIO: "vardr.nm2-hosted/7",
                    LAUNCH_GRANT_REVOKE_SCENARIO: "vardr.nm2-hosted/7",
                    LAUNCH_EXPIRED_GRANT_SCENARIO: "vardr.nm2-hosted/7",
                    LAUNCH_ACTIVE_GRANT_EXPIRY_SCENARIO: "vardr.nm2-hosted/7",
                    **LAUNCH_BUDGET_SCHEMAS,
                    STRICT_DRIFT_SCENARIO: STRICT_DRIFT_HOSTED,
                    STRICT_REVIEW_SCENARIO: STRICT_REVIEW_HOSTED,
                    STALE_CLAIM_SCENARIO: STALE_CLAIM_HOSTED,
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
