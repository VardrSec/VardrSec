"""Explicit coupled NM-2 fixture. Default: source validation, no Docker calls.

Run only against a new, separately named installation and reviewed immutable
image/source cohort. This is not a release, an old-candidate recovery tool, or a
second execution engine. Unknown mutations remain held; fixtures are retained.
"""

import argparse
import csv
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import http.cookiejar
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlsplit
import uuid

ROOT = Path(__file__).resolve().parents[1]
SOURCE_NAMES = {"distribution", "map", "runner", "gate"}
IMAGE_NAMES = {"db", "api", "web", "proxy", "worker"}
TARGET_HOST = "gate-fixture.test"
ORIGIN = f"http://{TARGET_HOST}:8080"
EXECUTION = {
    "timeout_seconds": 20,
    "max_response_bytes": 65536,
    "allow_private_targets": True,
}
INITIAL_CASES = (
    "default_disabled",
    "strict_out_of_scope",
    "happy_fixed",
    "healthy_sequence",
    "missing_local_grant",
)
STRICT_DRIFT_SCENARIO = "strict-authority-drift"
STRICT_DRIFT_CASE = "strict_authority_drift"
STRICT_DRIFT_SCHEMA = "vardr.nm2-worker-strict-drift-acceptance/1"
STRICT_DRIFT_SCOPE = "strict_authority_drift_only"
STRICT_DRIFT_PASS = "selected_strict_drift_slice_passed"
STRICT_DRIFT_COMPLETE = "selected_strict_drift_complete"
STRICT_DRIFT_SERVICES = ["api", "db", "gate-fixture", "proxy", "web"]
STRICT_REVIEW_SCENARIO = "strict-review-authority"
STRICT_REVIEW_CASE = "strict_review_authority"
STRICT_REVIEW_SCHEMA = "vardr.nm2-worker-strict-review-acceptance/1"
STRICT_REVIEW_SCOPE = "strict_review_denials_only"
STRICT_REVIEW_PASS = "selected_strict_review_slice_passed"
STRICT_REVIEW_COMPLETE = "selected_strict_review_complete"
STRICT_REVIEW_MAP = "05dc78cf9a385255de459c8a5b833842d6528a63"
STALE_CLAIM_SCENARIO = "strict-stale-registered-claim"
STALE_CLAIM_CASE = "strict_stale_registered_claim"
STALE_CLAIM_SCHEMA = "vardr.nm2-worker-strict-stale-claim-acceptance/1"
STALE_CLAIM_SCOPE = "strict_stale_registered_claim_only"
STALE_CLAIM_PASS = "selected_strict_stale_claim_slice_passed"
STALE_CLAIM_COMPLETE = "selected_strict_stale_claim_complete"
STALE_CLAIM_MAP = "ebb1bc8dd6cc0c3215ad468a2dd1c848d812842a"
STALE_CLAIM_MARKER = re.compile(
    rb"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3}"
    rb" WARNING managed_http managed_claim_authority_revision_changed"
)
CLOSED_WINDOW_WARNING = {
    "reason": "outside_testing_window", "message": "The testing window has closed.",
}
SCENARIOS = (
    STRICT_DRIFT_SCENARIO,
    STRICT_REVIEW_SCENARIO,
    STALE_CLAIM_SCENARIO,
    "healthy",
    "persistent-availability",
    "persistent-count-limit",
    "persistent-idle-limit",
    "persistent-empty-stop",
    "local-emergency-stop",
    "stop-work",
    "missing-local-grant",
    "active-target-grant-revoked",
)
COUNT_SCENARIO = "persistent-count-limit"
IDLE_SCENARIO = "persistent-idle-limit"
EMPTY_SCENARIO = "persistent-empty-stop"
PERSISTENT_SCENARIOS = {
    "persistent-availability", COUNT_SCENARIO, IDLE_SCENARIO, EMPTY_SCENARIO,
    STRICT_DRIFT_SCENARIO, STRICT_REVIEW_SCENARIO, STALE_CLAIM_SCENARIO,
}


def count_approval_context(inventory, original_context):
    """Correlate the original public context with its registered row; not attestation."""
    require(
        type(inventory) is dict
        and inventory.get("schema") == "vardr.nm2-fixture-inventory/4"
        and type(inventory.get("approvals")) is list
        and len(inventory["approvals"]) == 1
        and type(inventory["approvals"][0]) is dict
        and type(inventory["approvals"][0].get("id")) is str
        and type(original_context) is dict
        and type(inventory.get("approval_context_sha256")) is dict,
        "count_registered_context_changed",
    )
    registered = inventory["approval_context_sha256"]
    identifier = inventory["approvals"][0]["id"]
    require(
        set(registered) == {identifier}
        and type(registered[identifier]) is str
        and re.fullmatch(r"[a-f0-9]{64}", registered[identifier]) is not None
        and registered[identifier] == digest(canonical(original_context)),
        "count_registered_context_changed",
    )


def persistent_limits(scenario):
    require(scenario in PERSISTENT_SCENARIOS, "fixture_scenario_refused")
    return {
        "max_attempts": "1" if scenario == COUNT_SCENARIO else None,
        "idle_timeout_seconds": 60 if scenario == IDLE_SCENARIO else None,
    }


def persistent_enable_args(scenario):
    limits = persistent_limits(scenario)
    return ["--protocol", "persistent-v3"] + (
        ["--max-attempts", limits["max_attempts"]] if limits["max_attempts"] else []
    ) + (["--idle-timeout-seconds", "60"] if scenario == IDLE_SCENARIO else [])


_CONFIGURATION_ENV = {
    "HTTPS_PORT",
    "PROXY_IP",
    "APPLICATION_SUBNET",
    "APPLICATION_IP_RANGE",
    "POSTGRES_PASSWORD",
    "POSTGRES_APP_PASSWORD",
    "BACKEND_JWT_SECRET",
    "AUTH_SECRET",
    "MAP_SOURCE",
    "RUNNER_SOURCE",
    "GATE_SOURCE",
    "PGPASSWORD",
}


class AcceptanceRefused(ValueError):
    pass


STATUS_CHECKPOINTS = frozenset(
    {
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
)


class WorkerStatusRefused(AcceptanceRefused):
    def __init__(self, checkpoint):
        super().__init__("persistent_status_refused")
        self.public = {
            "checkpoint": checkpoint
            if type(checkpoint) is str and checkpoint in STATUS_CHECKPOINTS
            else "unclassified"
        }


class IdleStatusRefused(WorkerStatusRefused):
    def __init__(self, checkpoint):
        super().__init__(checkpoint)
        self.args = ("idle_status_refused",)


class WorkerCLIRefused(AcceptanceRefused):
    def __init__(self, phase, code, registration_failure=None):
        super().__init__("fixture_command_failed")
        self.public = {"failure_phase": phase, "failure_code": code}
        if registration_failure is not None:
            self.public["registration_failure"] = registration_failure


class HTTPStatusRefused(AcceptanceRefused):
    def __init__(self, method, path, expected, actual):
        super().__init__("fixture_http_status")
        route = re.sub(
            r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}",
            "{id}",
            path.partition("?")[0],
        )
        self.public = {
            "method": method
            if method in {"GET", "POST", "PUT", "DELETE", "PATCH"}
            else "refused",
            "route": route
            if re.fullmatch(r"/[A-Za-z0-9_/{}/.:-]{0,255}", route)
            else "refused",
            "expected_status": expected,
            "actual_status": actual,
        }


def require(condition, reason):
    if not condition:
        raise AcceptanceRefused(reason)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def strict_drift_empty(inventory, engagement, job):
    expected = {
        "schema": "vardr.nm2-fixture-inventory/4", "schema_revision": "0041persistentruntime",
        "database_user": "vardrmap_app", "engagement_id": engagement, "job_id": job,
        "runtime_attempt_bound": 35, "job_status": "pending", "execution": None,
        "targets_spent": 0, "duration_allocated": 0, "capacity_reserved_count": 0,
        "concurrency_limit": 1, "approvals": [], "contracts": [], "results": [],
        "stops": [], "runtimes": [], "approval_context_sha256": {},
    }
    require(canonical(inventory) == canonical(expected), "strict_authority_drift_dirty_inventory")


def strict_drift_contexts(original, fresh, old_approved_at):
    require(all(type(item) is dict and set(item) == {"context", "authority_snapshot"}
                for item in (original, fresh)), "strict_authority_drift_proof_shape")
    context, authority = original["context"], original["authority_snapshot"]
    revision = authority["authority_revision"]
    engagement = context["engagement_id"]
    authorization = authority["authority"]["authorization"]
    require(
        type(revision) is int and revision >= 0
        and authority["schema"] == "vardr.map-managed-authority/1"
        and authority["authority"]["engagement_id"] == engagement
        and authorization["status"] == "active" and context["mode"] == "strict"
        and canonical(context["authority_revision"]) == canonical(revision)
        and context["authority_sha256"] == digest(canonical(authority)),
        "strict_authority_drift_original_context",
    )
    expected_authority = {**authority, "authority_revision": revision + 2}
    expected_context = {
        **context, "not_before": fresh["context"]["not_before"],
        "authority_revision": revision + 2,
        "authority_sha256": digest(canonical(expected_authority)),
    }
    original_time, signed_time, fresh_time, expiry = (
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        for value in (context["not_before"], old_approved_at,
                      fresh["context"]["not_before"], context["expires_at"])
    )
    require(
        canonical(fresh["authority_snapshot"]) == canonical(expected_authority)
        and canonical(fresh["context"]) == canonical(expected_context)
        and original_time <= signed_time <= fresh_time < expiry,
        "strict_authority_drift_fresh_context",
    )


def strict_drift_measurements(proof):
    """Recheck the retained observations and emit only fixed measurements."""
    require(type(proof) is dict and set(proof) == {
        "original", "fresh", "mutations", "refusal", "registration_sha256",
        "old_approved_at", "before", "after", "traffic_before", "traffic_after",
        "services", "positive",
    }, "strict_authority_drift_proof_shape")
    original, fresh = proof["original"], proof["fresh"]
    strict_drift_contexts(original, fresh, proof["old_approved_at"])
    context = original["context"]
    engagement, job = context["engagement_id"], context["job_id"]
    authorization = original["authority_snapshot"]["authority"]["authorization"]
    require(
        proof["mutations"] == [
            {"id": authorization["id"], "program_id": engagement, "status": status}
            for status in ("revoked", "active")
        ] and proof["refusal"] == {"detail": "managed_approval_refused"}
        and re.fullmatch(r"[0-9a-f]{64}", proof["registration_sha256"]),
        "strict_authority_drift_refusal_shape",
    )
    strict_drift_empty(proof["before"], engagement, job)
    strict_drift_empty(proof["after"], engagement, job)
    require(proof["traffic_before"] == proof["traffic_after"] == []
            and proof["services"] == STRICT_DRIFT_SERVICES,
            "strict_authority_drift_mutated_or_dispatched")

    positive = proof["positive"]
    require(type(positive) is dict and set(positive) == {
        "approval_record_id", "registration_sha256", "inventory", "traffic",
    }, "strict_authority_drift_positive_control")
    approval_id, fresh_context = positive["approval_record_id"], fresh["context"]
    require(re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}:fixture-strict-authority-drift-fresh", approval_id)
            and re.fullmatch(r"[0-9a-f]{64}", positive["registration_sha256"])
            and positive["registration_sha256"] != proof["registration_sha256"]
            and positive["traffic"] == [], "strict_authority_drift_positive_control")
    approval = {
        "id": approval_id, "issued": 0, "revoked": False,
        "approved_at": fresh_context["not_before"],
        **{key: fresh_context[key] for key in (
            "expires_at", "max_executions", "max_duration_seconds", "credential_grants",
        )},
    }
    fresh_sha = digest(canonical(fresh_context))
    require(
        canonical(positive["inventory"]) == canonical({
            **proof["after"], "approvals": [approval],
            "approval_context_sha256": {approval_id: fresh_sha},
        }),
        "strict_authority_drift_positive_control",
    )
    return {
        "stale_registration_status": 409, "fresh_review_status": 200,
        "fresh_registration_status": 200, "authority_revision_delta": 2,
        "target_request_count": 0, "targets_spent": 0, "duration_allocated": 0,
        "capacity_reserved_count": 0,
        "stale_registration_sha256": proof["registration_sha256"],
        "fresh_registration_sha256": positive["registration_sha256"],
        "original_context_sha256": digest(canonical(context)),
        "fresh_context_sha256": fresh_sha,
        "unchanged_inventory_sha256": digest(canonical(proof["after"])),
    }


def _strict_review_window_time(value):
    # Authorization readback uses datetime.isoformat(). The Map policy treats
    # a naive database timestamp as UTC. Signed review fields below require Z.
    require(type(value) is str and re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:Z|[+]00:00)?", value,
    ), "strict_review_window_binding")
    moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return moment.replace(tzinfo=timezone.utc)


def strict_review_measurements(proof):
    require(type(proof) is dict and set(proof) == {
        "missing", "expired", "traffic_before", "traffic_after", "services",
    }, "strict_review_proof_shape")
    require(proof["traffic_before"] == proof["traffic_after"] == []
            and proof["services"] == STRICT_DRIFT_SERVICES, "strict_review_traffic_changed")
    results = {}
    identities = set()
    for kind in ("missing", "expired"):
        row = proof[kind]
        keys = {
            "before", "after_refusal", "after_review", "listed_before", "active_before",
            "authorization_after", "active_after", "review_input", "accepted_input_sha256",
            "runner_id", "refusal", "review",
        }
        require(type(row) is dict and set(row) == keys | ({"queued_warnings"} if kind == "expired" else set()),
                "strict_review_proof_shape")
        require(row["refusal"] == {"detail": "managed_approval_refused"}
                and row["active_before"] is None, "strict_review_refusal_shape")
        review = row["review"]
        require(type(review) is dict and set(review) == {"context", "authority_snapshot", "case"},
                "strict_review_proof_shape")
        context, authority = review["context"], review["authority_snapshot"]
        engagement, job = context["engagement_id"], context["job_id"]
        identities.add((engagement, job))
        for key in ("before", "after_refusal", "after_review"):
            strict_drift_empty(row[key], engagement, job)
        current, submitted = row["authorization_after"], row["review_input"]
        require(type(submitted) is dict and set(submitted) == {
            "enrollment_id", "authorization_id", "plan", "expires_at",
            "max_executions", "max_duration_seconds", "max_artifact_bytes", "credential_grants",
        }, "strict_review_positive_binding")
        accepted = {**submitted, "authorization_id": current["id"]}
        plan = submitted["plan"]
        require(
            canonical(current) == canonical(row["active_after"])
            and current["program_id"] == engagement and current["status"] == "active"
            and row["accepted_input_sha256"] == digest(canonical(accepted))
            and authority["schema"] == "vardr.map-managed-authority/1"
            and authority["authority"]["engagement_id"] == engagement
            and authority["enrollment"]["id"] == submitted["enrollment_id"]
            and authority["enrollment"]["runner_id"] == context["runner_id"] == row["runner_id"]
            and type(context["authority_revision"]) is int
            and canonical(context["authority_revision"]) == canonical(authority["authority_revision"])
            and context["mode"] == "strict" and context["control"] == "managed_online"
            and context["authority_sha256"] == digest(canonical(authority))
            and context["plan_sha256"] == digest(canonical(plan))
            and plan["profile"] == "gate-fixed-http/1"
            and plan["case_hash"] == digest(canonical(review["case"]))
            and all(canonical(context[key]) == canonical(submitted[key]) for key in (
                "expires_at", "max_executions", "max_duration_seconds", "max_artifact_bytes",
                "credential_grants",
            )), "strict_review_positive_binding",
        )
        snapshot = authority["authority"]["authorization"]
        start, end = (_strict_review_window_time(current[key]) for key in ("window_start", "window_end"))
        now, expiry = (
            datetime.strptime(context[key], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            for key in ("not_before", "expires_at")
        )
        require(
            snapshot["id"] == current["id"] and snapshot["status"] == "active"
            and _strict_review_window_time(snapshot["window_start"]) == start
            and _strict_review_window_time(snapshot["window_end"]) == end
            and start <= now < expiry <= end, "strict_review_window_binding",
        )
        if kind == "missing":
            require(row["listed_before"] == [] and submitted["authorization_id"] == "nm2-absent-authorization"
                    and current["id"] != submitted["authorization_id"], "strict_review_authority_precondition")
        else:
            require(type(row["listed_before"]) is list and len(row["listed_before"]) == 1
                    and row["queued_warnings"] == [CLOSED_WINDOW_WARNING],
                    "strict_review_authority_precondition")
            prior = row["listed_before"][0]
            require(canonical({**prior, "window_end": current["window_end"]}) == canonical(current)
                    and submitted["authorization_id"] == current["id"]
                    and start < _strict_review_window_time(prior["window_end"]) < now,
                    "strict_review_window_binding")
        results[{"missing": "missing_authority", "expired": "expired_testing_window"}[kind]] = {
            "refused_review_status": 409, "repaired_review_status": 200,
            "unchanged_inventory_sha256": digest(canonical(row["after_refusal"])),
            "positive_context_sha256": digest(canonical(context)),
        }
    require(len({engagement for engagement, _ in identities}) == 2
            and len({job for _, job in identities}) == 2, "strict_review_proof_shape")
    return {**results, "target_request_count": 0, "targets_spent": 0,
            "duration_allocated": 0, "capacity_reserved_count": 0}


def stale_claim_measurements(proof):
    require(type(proof) is dict and set(proof) == {
        "original", "fresh", "plan", "request", "mutation", "refusal", "observed_at",
        "marker_counts", "api_container_id", "before", "after", "traffic_before", "traffic_after",
        "services",
    }, "strict_stale_claim_proof_shape")
    old, fresh = proof["original"], proof["fresh"]
    require(all(type(row) is dict and set(row) == {"context", "authority_snapshot"}
                for row in (old, fresh)), "strict_stale_claim_proof_shape")
    context, authority = old["context"], old["authority_snapshot"]
    revision = context["authority_revision"]
    engagement, job = context["engagement_id"], context["job_id"]
    plan = proof["plan"]
    require(
        type(revision) is int and revision >= 0
        and authority["schema"] == "vardr.map-managed-authority/1"
        and authority["authority"]["engagement_id"] == engagement
        and authority["authority"]["authorization"]["status"] == "active"
        and canonical(authority["authority_revision"]) == canonical(revision)
        and canonical(authority["limits"]) == b'{"concurrency":1,"duration":120,"targets":5}'
        and context["mode"] == "strict" and context["control"] == "managed_online"
        and context["authority_sha256"] == digest(canonical(authority))
        and context["runner_id"] == authority["enrollment"]["runner_id"]
        and context["plan_sha256"] == digest(canonical(plan))
        and plan["profile"] == "gate-fixed-http/1"
        and re.fullmatch(r"[a-f0-9]{64}", plan["case_hash"]) is not None,
        "strict_stale_claim_original_binding",
    )
    expected_authority = {
        **authority, "authority_revision": revision + 1,
        "limits": {**authority["limits"], "targets": 4},
    }
    expected_context = {
        **context, "not_before": fresh["context"]["not_before"],
        "authority_revision": revision + 1,
        "authority_sha256": digest(canonical(expected_authority)),
    }
    require(
        canonical(fresh["authority_snapshot"]) == canonical(expected_authority)
        and canonical(fresh["context"]) == canonical(expected_context)
        and canonical(proof["mutation"]) == canonical({
            "limit": 4, "spent": 0, "unit": "represented_origin_attempts/1",
        }),
        "strict_stale_claim_mutation_required",
    )
    before, after = proof["before"], proof["after"]
    count_approval_context(before, context)
    strict_drift_empty({**before, "approvals": [], "approval_context_sha256": {}}, engagement, job)
    approval = before["approvals"][0]
    require(
        canonical(after) == canonical(before)
        and approval["id"].endswith(":fixture-" + STALE_CLAIM_SCENARIO)
        and canonical([approval["issued"], approval["revoked"]]) == b"[0,false]"
        and all(canonical(approval[key]) == canonical(context[key]) for key in (
            "expires_at", "max_executions", "max_duration_seconds", "credential_grants",
        )),
        "strict_stale_claim_retained_approval_required",
    )
    earlier, signed, refreshed, observed, expiry = (
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        for value in (
            context["not_before"], approval["approved_at"], fresh["context"]["not_before"],
            proof["observed_at"], context["expires_at"],
        )
    )
    require(earlier <= signed <= refreshed <= observed < expiry, "strict_stale_claim_window_required")
    expected_request = {
        "origin": authority["origin"], "runner_id": context["runner_id"],
        "concurrency_budget": True, "duration_seconds": 30,
        "target_binding": {
            "profile": "gate-fixed-http/1", "case_sha256": plan["case_hash"], "origins": [ORIGIN],
        },
    }
    require(
        canonical(proof["request"]) == canonical(expected_request)
        and canonical(proof["refusal"]) == canonical({
            "status": 409, "cache_control": "no-store", "body": {"detail": "managed_request_refused"},
        })
        and canonical(proof["marker_counts"]) == b"[0,1]"
        and re.fullmatch(r"[a-f0-9]{64}", proof["api_container_id"]) is not None
        and proof["services"] == STRICT_DRIFT_SERVICES
        and proof["traffic_before"] == proof["traffic_after"] == [],
        "strict_stale_claim_refusal_required",
    )
    return {
        "stored_authority_revision": revision, "current_authority_revision": revision + 1,
        "refusal_status": 409, "cache_control": "no-store", "marker_count": 1,
        "registered_context_sha256": digest(canonical(context)), "approval_issued": 0,
        "targets_spent": 0, "duration_allocated": 0, "capacity_reserved_count": 0,
        "target_requests": 0, "worker_containers": 0,
    }


def target_environment(scenario):
    require(scenario in SCENARIOS, "fixture_scenario_refused")
    if scenario == "persistent-availability":
        return {"NM2_FIXTURE_REQUEST_CEILING": "175"}
    if scenario in {
        COUNT_SCENARIO, IDLE_SCENARIO, EMPTY_SCENARIO,
        STRICT_DRIFT_SCENARIO, STRICT_REVIEW_SCENARIO, STALE_CLAIM_SCENARIO,
    }:
        return {}
    if scenario != "healthy":
        return {"NM2_FIXTURE_DELAY_SECONDS": "15"}
    return {}


def command(arguments, *, cwd=None, env=None, stdin=None, timeout=30):
    """Never echo a command's stdout/stderr or secret environment on failure."""
    if isinstance(stdin, str):
        stdin = stdin.encode()
    try:
        result = subprocess.run(
            arguments,
            cwd=cwd,
            env=env,
            input=stdin,
            capture_output=True,
            timeout=timeout,
            check=True,
        )
        require(len(result.stdout) <= 4 * 1024 * 1024, "fixture_output_bound")
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        raise AcceptanceRefused("fixture_command_failed") from None


def worker_cli_command(arguments, *, cwd=None, env=None, stdin=None, timeout=30):
    """Only known worker commands: project fixed held diagnostics, never raw output."""
    if isinstance(stdin, str):
        stdin = stdin.encode()
    try:
        result = subprocess.run(
            arguments,
            cwd=cwd,
            env=env,
            input=stdin,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise AcceptanceRefused("fixture_command_failed") from None
    if result.returncode == 0:
        require(
            type(result.stdout) is bytes and len(result.stdout) <= 4 * 1024 * 1024,
            "fixture_output_bound",
        )
        return result.stdout

    def unique(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError()
            value[key] = item
        return value

    def invalid_constant(value):
        raise ValueError()

    try:
        from worker_cli import FAILURE_CODES, FAILURE_PHASES

        raw = result.stdout
        if type(raw) is not bytes or len(raw) > 4096:
            raise ValueError()
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique,
            parse_constant=invalid_constant,
        )
        expected = {
            "schema",
            "state",
            "runtime_id",
            "failure_phase",
            "failure_code",
        }
        if type(value) is not dict or set(value) not in (
            expected,
            expected | {"registration_failure"},
        ):
            raise ValueError()
        if (
            value["schema"] != "vardr.worker-cli/1"
            or type(value["state"]) is not str
            or value["state"] not in {"held", "held_interrupted"}
        ):
            raise ValueError()
        phase, code = value["failure_phase"], value["failure_code"]
        if (
            type(phase) is not str
            or phase not in FAILURE_PHASES
            or type(code) is not str
            or code not in FAILURE_CODES
        ):
            raise ValueError()
        if (value["state"] == "held_interrupted") != (code == "interrupted") or (
            code == "interrupted" and result.returncode != 130
        ):
            raise ValueError()
        selected = value["runtime_id"]
        if selected is not None and (
            type(selected) is not str or str(uuid.UUID(selected)) != selected
        ):
            raise ValueError()
        detail = None
        if "registration_failure" in value:
            from worker_host import registration_detail

            detail = registration_detail(value["registration_failure"])
            if (
                phase != "enable_registration"
                or code != "host_refused"
                or detail is None
            ):
                raise ValueError()
    except (ValueError, UnicodeError, TypeError, KeyError):
        raise AcceptanceRefused("fixture_command_failed") from None
    # Runtime IDs are checked but deliberately not exported: admission may be
    # ambiguous after a lost reply. No hashes of raw output or secret values.
    raise WorkerCLIRefused(phase, code, detail)


def worker_status_command(arguments, *, cwd, env, timeout, expected_admission):
    """Read-only status may report a narrowly validated advisory hold with rc1."""
    import worker_host
    import worker_host_persistent
    import worker_runtime

    reason = "persistent_status_refused"
    checkpoint = "admission"
    try:
        require(
            expected_admission["schema"] == "vardr.worker-admission/3"
            and expected_admission["mode"] == "persistent"
            and expected_admission["limits"]
            in tuple(persistent_limits(scenario) for scenario in {"persistent-availability", COUNT_SCENARIO})
            and expected_admission["runtime_sha256"]
            == digest(canonical(expected_admission["identity"]))
            and expected_admission["admission_sha256"]
            == digest(
                canonical(
                    {
                        k: v
                        for k, v in expected_admission.items()
                        if k != "admission_sha256"
                    }
                )
            ),
            reason,
        )
        worker_runtime.RuntimeIdentity(**expected_admission["identity"])
        checkpoint = "subprocess"
        result = subprocess.run(
            arguments,
            cwd=cwd,
            env=env,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        checkpoint = "output"
        require(
            type(result.returncode) is int
            and result.returncode in {0, 1}
            and type(result.stdout) is bytes
            and 0 < len(result.stdout) <= 4096
            and result.stderr == b"",
            reason,
        )
        value = worker_host._json(result.stdout)
        checkpoint = "identity"
        require(
            set(value)
            == {
                "schema",
                "runtime_id",
                "protocol",
                "mode",
                "limits",
                "identity",
                "state",
                "reason",
                "cursor",
                "availability",
                "new_work_disabled",
                "reporting_revoked",
                "registration_state",
                "disable_state",
                "stop_state",
                "revocation_state",
                "container_state",
            }
            and value["schema"] == "vardr.worker-status/1"
            and value["protocol"] == "persistent-v3"
            and value["mode"] == "persistent"
            and value["runtime_id"] == expected_admission["runtime_id"]
            and canonical(value["identity"])
            == canonical(expected_admission["identity"])
            and canonical(value["limits"]) == canonical(expected_admission["limits"])
            and value["container_state"] == "running"
            and value["registration_state"] == "acknowledged"
            and value["disable_state"]
            == value["stop_state"]
            == value["revocation_state"]
            == "none",
            reason,
        )
        checkpoint = "lookup"
        if all(
            value[key] is None
            for key in (
                "cursor",
                "availability",
                "new_work_disabled",
                "reporting_revoked",
            )
        ):
            # Product status could not read Map availability. This is only an
            # advisory hold; persistent_idle still requires fresh idle-ready.
            require(
                result.returncode == 1
                and value["state"] == "held"
                and value["reason"] == "availability_unconfirmed",
                reason,
            )
            return result.stdout
        require(
            value["new_work_disabled"] is False and value["reporting_revoked"] is False,
            reason,
        )
        checkpoint = "cursor"
        _, phase = worker_host_persistent.cursor_key(value["cursor"])
        presence = value["availability"]
        checkpoint = "presence"
        require(
            type(presence) is dict
            and set(presence) == {"state", "observed_at", "fresh_until", "cursor"}
            and canonical(presence["cursor"]) == canonical(value["cursor"]),
            reason,
        )
        expected_state = "active" if phase == 0 else "idle-ready"
        fresh = False
        checkpoint = "freshness"
        if presence["observed_at"] is None:
            require(presence["fresh_until"] is None, reason)
        else:
            observed = worker_host_persistent._stamp(presence["observed_at"])
            ending = worker_host_persistent._stamp(presence["fresh_until"])
            instant = datetime.now(timezone.utc)
            require(
                observed <= instant
                and timedelta(0) < ending - observed <= timedelta(seconds=15),
                reason,
            )
            fresh = instant < ending
        if result.returncode == 1:
            checkpoint = "advisory"
            require(
                value["state"] == "held"
                and type(value["reason"]) is str
                and value["reason"]
                in {"availability_stale", "availability_unconfirmed"}
                and (
                    presence["state"] == "held" and presence["observed_at"] is not None
                    if value["reason"] == "availability_unconfirmed"
                    else not fresh
                    and presence["state"] in {"held", expected_state}
                    and (
                        presence["state"] == "held"
                        or presence["observed_at"] is not None
                    )
                ),
                reason,
            )
        else:
            checkpoint = "readiness"
            require(
                value["state"] == presence["state"] == expected_state
                and value["reason"] is None
                and fresh,
                reason,
            )
        return result.stdout
    except (
        OSError,
        subprocess.SubprocessError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
    ):
        raise WorkerStatusRefused(checkpoint) from None


IDLE_STATUS_FIELDS = {
    "schema", "runtime_id", "protocol", "mode", "limits", "identity", "state",
    "reason", "cursor", "availability", "new_work_disabled", "reporting_revoked",
    "registration_state", "disable_state", "stop_state", "revocation_state",
    "container_state",
}


def idle_status_value(value, code, admission):
    """Closed fixture-only decoder for the explicit60s optional-idle control."""
    import worker_host_persistent as persistent

    reason = "idle_status_refused"
    checkpoint = "admission"
    try:
        record = {"runtime_id": admission["runtime_id"],
                  "registration": {k: admission[k] for k in persistent.REGISTRATION}}
        persistent.admission(record, admission)
        require(admission["limits"] == persistent_limits(IDLE_SCENARIO), reason)
        checkpoint = "output"
        require(type(code) is int and code in {0, 1} and type(value) is dict, reason)
        terminal = value.get("state") == "stopped"
        container_missing = "container_state" not in value
        fields = IDLE_STATUS_FIELDS - {"container_state"} if container_missing else IDLE_STATUS_FIELDS
        require(set(value) == fields | ({"exit_code", "finished_at"} if terminal else set())
                and (not container_missing or value.get("state") == "held"
                     and value.get("reason") == "physical_unconfirmed"), reason)
        checkpoint = "identity"
        require(value["schema"] == "vardr.worker-status/1"
                and value["protocol"] == "persistent-v3" and value["mode"] == "persistent"
                and value["runtime_id"] == admission["runtime_id"]
                and canonical(value["identity"]) == canonical(admission["identity"])
                and canonical(value["limits"]) == canonical(admission["limits"])
                and value["registration_state"] == "acknowledged"
                and value["disable_state"] == value["stop_state"]
                == value["revocation_state"] == "none", reason)
        if terminal:
            checkpoint = "readiness"
            require(code == 0 and value.get("container_state") == "exited"
                    and value["reason"] is None and type(value["exit_code"]) is int
                    and value["exit_code"] == 124
                    and all(value[k] is None for k in (
                        "cursor", "availability", "new_work_disabled", "reporting_revoked")), reason)
            # Docker physical timestamps permit nanoseconds; no normalization loss.
            from nm2_worker_persistent_projection import stamp
            stamp(value["finished_at"], physical=True)
            return value
        physical_unknown = value["state"] == "held" and value["reason"] == "physical_unconfirmed"
        checkpoint = "advisory"
        if physical_unknown:
            require(code == 1 and (container_missing or value["container_state"] == "exited"), reason)
        if all(value[k] is None for k in (
            "cursor", "availability", "new_work_disabled", "reporting_revoked"
        )):
            # Neither advisory family supplies initial readiness or physical proof.
            require(physical_unknown or code == 1 and value["state"] == "held"
                    and value["reason"] == "availability_unconfirmed"
                    and value.get("container_state") == "running", reason)
            return value
        # A complete Map DTO survives only the producer's final-inspection failure,
        # before container_state is assigned. Other cross-products are not valid.
        require((container_missing if physical_unknown else value.get("container_state") == "running")
                and value["new_work_disabled"] is False
                and value["reporting_revoked"] is False, reason)
        checkpoint = "cursor"
        persistent.cursor_key(value["cursor"])
        require(value["cursor"] == {"last_sequence": "1", "phase": "idle"}, reason)
        presence = value["availability"]
        checkpoint = "presence"
        require(type(presence) is dict and set(presence) == {
                    "state", "observed_at", "fresh_until", "cursor"}
                and presence["cursor"] == value["cursor"]
                and type(presence["state"]) is str
                and presence["state"] in {"held", "idle-ready"}, reason)
        fresh = False
        checkpoint = "freshness"
        if presence["observed_at"] is None:
            require(presence["fresh_until"] is None and presence["state"] == "held", reason)
        else:
            observed, ending = persistent._stamp(presence["observed_at"]), persistent._stamp(presence["fresh_until"])
            instant = datetime.now(timezone.utc)
            require(observed <= instant and timedelta(0) < ending-observed <= timedelta(seconds=15), reason)
            fresh = instant < ending
        if physical_unknown:
            return value  # Remains held; only a later independent exit can finish.
        if code == 0:
            checkpoint = "readiness"
            require(value["state"] == presence["state"] == "idle-ready"
                    and value["reason"] is None and fresh, reason)
        else:
            checkpoint = "advisory"
            require(value["state"] == "held" and (
                value["reason"] == "availability_stale" and not fresh
                and presence["state"] in {"held", "idle-ready"}
                or value["reason"] == "availability_unconfirmed"
                and presence["state"] == "held" and presence["observed_at"] is not None), reason)
        return value
    except IdleStatusRefused:
        raise
    except (ValueError, KeyError, TypeError, AttributeError):
        raise IdleStatusRefused(checkpoint) from None


def worker_idle_status_command(arguments, *, cwd, env, timeout, expected_admission):
    """No retries, stop, or claim; one existing read-only product status command."""
    import worker_host
    checkpoint = "subprocess"
    try:
        result = subprocess.run(arguments, cwd=cwd, env=env, capture_output=True,
                                timeout=timeout, check=False)
        checkpoint = "output"
        require(type(result.stdout) is bytes and 0 < len(result.stdout) <= 4096
                and result.stderr == b"", "idle_status_refused")
        value = worker_host._json(result.stdout)
        checkpoint = "lookup"
        idle_status_value(value, result.returncode, expected_admission)
        return result.stdout
    except IdleStatusRefused:
        raise
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, AttributeError):
        raise IdleStatusRefused(checkpoint) from None


def fixture_subnets(value):
    if "fixture_subnets" not in value:
        return {}
    selected = value["fixture_subnets"]
    reason = "fixture_subnet_selection_refused"
    require(type(selected) is dict and set(selected) == {"database", "runner"}, reason)
    blocks = [
        ipaddress.ip_network(cidr)
        for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    ]
    networks = []
    for raw in (value["application_subnet"], selected["database"], selected["runner"]):
        require(type(raw) is str, reason)
        try:
            network = ipaddress.ip_network(raw, strict=True)
        except ValueError:
            raise AcceptanceRefused(reason) from None
        require(
            network.version == 4
            and network.prefixlen == 24
            and str(network) == raw
            and any(network.subnet_of(block) for block in blocks),
            reason,
        )
        networks.append(network)
    require(
        all(
            not left.overlaps(right)
            for index, left in enumerate(networks)
            for right in networks[index + 1 :]
        ),
        reason,
    )
    return dict(selected)


def manifest(path):
    value = json.loads(Path(path).read_bytes())
    require(
        set(value) - {"fixture_subnets"}
        == {
            "schema",
            "sources",
            "images",
            "docker_context",
            "project",
            "installation",
            "private_root",
            "https_port",
            "application_subnet",
            "allow_empty_builtin_bridge_id_change",
        },
        "manifest_fields",
    )
    require(value["schema"] == "vardr.nm2-worker-cohort/1", "manifest_schema")
    require(
        set(value["sources"]) == SOURCE_NAMES and set(value["images"]) == IMAGE_NAMES,
        "manifest_cohort",
    )
    require(
        all(
            isinstance(v, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", v)
            for v in value["images"].values()
        ),
        "immutable_image_required",
    )
    require(
        re.fullmatch(r"vardrsec-nm2-[a-z0-9]{8,24}", value["project"] or ""),
        "separate_project_required",
    )
    require(
        re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value["docker_context"] or ""),
        "explicit_local_context_required",
    )
    require(
        type(value["https_port"]) is int and 1024 <= value["https_port"] <= 65535,
        "loopback_port_required",
    )
    require(
        type(value["allow_empty_builtin_bridge_id_change"]) is bool,
        "bridge_admission_required",
    )
    fixture_subnets(value)
    network = ipaddress.ip_network(value["application_subnet"])
    require(
        network.version == 4 and network.is_private and network.prefixlen == 24,
        "private_fixture_subnet_required",
    )
    roots = [Path(value[name]) for name in ("installation", "private_root")]
    require(
        all(p.is_absolute() and not p.exists() and not p.is_symlink() for p in roots),
        "new_fixture_directories_required",
    )
    require(
        roots[0] != roots[1]
        and not any(a in b.parents for a, b in (roots, roots[::-1])),
        "separate_host_custody_required",
    )
    for name, selection in value["sources"].items():
        require(
            set(selection) == {"path", "commit"}
            and re.fullmatch(r"[0-9a-f]{40}", selection["commit"] or ""),
            "source_selection_required",
        )
        source = Path(selection["path"])
        require(
            source.is_absolute() and source.is_dir() and not source.is_symlink(),
            "source_directory_required",
        )
        require(
            command(["git", "-C", str(source), "rev-parse", "HEAD"]).decode().strip()
            == selection["commit"],
            "source_commit_mismatch",
        )
        require(
            not command(
                [
                    "git",
                    "-C",
                    str(source),
                    "status",
                    "--porcelain",
                    "--untracked-files=no",
                ]
            ),
            "tracked_source_changes_unreviewed",
        )
        require(
            source not in roots
            and not any(source in p.parents or p in source.parents for p in roots),
            "fixture_outside_sources_required",
        )
    distribution = Path(value["sources"]["distribution"]["path"])
    required_distribution = (
        "compose.yaml",
        "compose.worker.json",
        "vardrsec.py",
        "database_roles.py",
        "worker_host.py",
        "worker_host_sequence.py",
        "worker_host_persistent.py",
        "worker_runtime.py",
        "worker_secrets.py",
        "worker_volumes.py",
        "worker_cli.py",
        "tests/gate/target.py",
        "tests/nm2_worker_acceptance.py",
        "tests/nm2_worker_inventory.py",
        "tests/nm2_worker_target.py",
    )
    command(
        [
            "git",
            "-C",
            str(distribution),
            "ls-files",
            "--error-unmatch",
            "--",
            *required_distribution,
        ]
    )
    for relative in required_distribution:
        require((distribution / relative).is_file(), "required_public_source_missing")
    value["proxy_ip"] = str(network.network_address + 2)
    value["application_ip_range"] = str(network.network_address + 128) + "/25"
    return value


def private_directory(path):
    path.mkdir(mode=0o700)
    if os.name == "nt":
        raw = (
            command(["whoami", "/user", "/fo", "csv", "/nh"])
            .decode("utf-8-sig")
            .strip()
        )
        sid = next(csv.reader([raw]))[-1]
        require(re.fullmatch(r"S-1-[0-9-]+", sid), "current_user_sid_required")
        command(
            [
                "icacls",
                str(path),
                "/inheritance:r",
                "/grant:r",
                f"*{sid}:(OI)(CI)F",
                "*S-1-5-18:(OI)(CI)F",
            ]
        )
    else:
        path.chmod(0o700)


def publish(path, data, *, mode=0o600):
    """Exclusive files; admission is atomically published after host ACK only."""
    require(not path.exists(), "fixture_file_already_exists")
    temporary = path.with_name(path.name + ".prepared")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.rename(path)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class OwnerAPI:
    """Actual CA-validated local session and CSRF; no synthetic owner headers."""

    def __init__(self, url, ca):
        self.url, self.ca = url, ca
        self.ca_sha256 = digest(ca.read_bytes())
        self.jar = http.cookiejar.CookieJar()
        context = ssl.create_default_context(cafile=str(ca))
        context.keylog_filename = None
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=context),
        )
        self.csrf = None

    def request(self, path, body=None, *, method=None, csrf=True, expected=200, bearer=None):
        require(digest(self.ca.read_bytes()) == self.ca_sha256, "fixture_ca_changed")
        headers = {"Origin": self.url}
        if bearer is not None:
            require(
                type(bearer) is str and re.fullmatch(r"vmap_[A-Za-z0-9_-]{1,128}", bearer) is not None
                and self.csrf is None and len(self.jar) == 0 and csrf is False
                and method == "POST" and expected == 409
                and re.fullmatch(r"/jobs/[A-Za-z0-9_-]{1,128}/managed/claim", path) is not None,
                "strict_stale_claim_bearer_required",
            )
            headers["Authorization"] = "Bearer " + bearer
        if body is not None:
            headers["Content-Type"] = "application/json"
        if csrf and self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        request = urllib.request.Request(
            self.url + "/backend" + path,
            data=None if body is None else canonical(body),
            headers=headers,
            method=method,
        )
        try:
            response = self.opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            if response.status != expected:
                raise HTTPStatusRefused(
                    request.get_method(), path, expected, response.status
                )
            if bearer is not None:
                require(response.headers.get("Cache-Control") == "no-store",
                        "strict_stale_claim_refusal_required")
            raw = response.read(1024 * 1024 + 1)
            require(len(raw) <= 1024 * 1024, "fixture_http_bound")
            return json.loads(raw) if raw else None

    def login(self, username, password):
        self.request("/auth/local/login", {"username": username, "password": password})
        session = self.request("/auth/local/session")
        require(session["authMethod"] == "local", "actual_local_owner_required")
        self.csrf = session["csrfToken"]
        return session["user"]["githubId"]


def unchanged_inventory(before, after, project, *, admit_bridge=False):
    """Compare pre-existing public resource metadata, including stopped fixtures."""
    admitted = []
    for kind in ("containers", "volumes", "images"):
        for key, value in before[kind].items():
            require(after[kind].get(key) == value, "preexisting_" + kind + "_changed")
    for key, value in before["networks"].items():
        candidate = after["networks"].get(key)
        if (
            candidate != value
            and admit_bridge
            and value["name"] == "bridge"
            and not value["containers"]
        ):
            matches = [
                n
                for n in after["networks"].values()
                if n["name"] == "bridge" and not n["containers"]
            ]
            if len(matches) == 1 and {k: v for k, v in value.items() if k != "id"} == {
                k: v for k, v in matches[0].items() if k != "id"
            }:
                candidate = value
                admitted.append(
                    {
                        "kind": "empty_builtin_bridge_id",
                        "before": key,
                        "after": matches[0]["id"],
                    }
                )
        require(candidate == value, "preexisting_network_changed")
    for kind in ("containers", "volumes", "networks"):
        admitted_ids = (
            {item["after"] for item in admitted} if kind == "networks" else set()
        )
        require(
            all(
                key in before[kind]
                or key in admitted_ids
                or value.get("labels", {}).get("com.docker.compose.project") == project
                for key, value in after[kind].items()
            ),
            "unowned_new_resource",
        )
    return admitted


class Fixture:
    def __init__(
        self, selection, *, scenario="healthy", database_revision="0040runtimesequence"
    ):
        require(scenario in SCENARIOS, "fixture_scenario_refused")
        require(
            database_revision in {"0040runtimesequence", "0041persistentruntime"},
            "fixture_database_revision_refused",
        )
        require(
            scenario not in PERSISTENT_SCENARIOS
            or database_revision == "0041persistentruntime",
            "persistent_database_revision_required",
        )
        require(scenario != STRICT_REVIEW_SCENARIO
                or selection["sources"]["map"]["commit"] == STRICT_REVIEW_MAP,
                "strict_review_map_source_required")
        require(scenario != STALE_CLAIM_SCENARIO
                or (STALE_CLAIM_MAP is not None and selection["sources"]["map"]["commit"] == STALE_CLAIM_MAP),
                "strict_stale_claim_map_source_required")
        self.scenario = scenario
        self.protocol = (
            "persistent-v3" if scenario in PERSISTENT_SCENARIOS else "finite-v2"
        )
        self.database_revision = database_revision
        self.max_attempts = (
            None
            if self.protocol == "persistent-v3"
            else (2 if scenario == "healthy" else 1)
        )
        self.m = selection
        self.source = Path(selection["sources"]["distribution"]["path"])
        self.install = Path(selection["installation"])
        self.private = Path(selection["private_root"])
        self.project = selection["project"]
        # One physical incarnation per new fixture project; the preflight below
        # also refuses existing unlabeled resources at every exact volume name.
        self.ready_volume = self.project + "_worker-ready"
        self.images = selection["images"]
        self.url = "https://localhost:" + str(selection["https_port"])
        self.issuer_origin = (
            "https://vardrsec.localhost:" + str(selection["https_port"]) + "/backend"
        )
        self.environment = {
            k: v
            for k, v in os.environ.items()
            if not k.upper().startswith(("COMPOSE_", "DOCKER_", "VARDR"))
            and k.upper() not in _CONFIGURATION_ENV
        }
        self.environment.update(
            DOCKER_CONTEXT=selection["docker_context"],
            COMPOSE_PROJECT_NAME=self.project,
            VARDRSEC_WORKER_READY_VOLUME=self.ready_volume,
            NO_COLOR="1",
            TERM="dumb",
        )
        self.receipt = {
            "schema": "vardr.nm2-worker-acceptance/2",
            "platform": sys.platform,
            "project": self.project,
            "readiness_volume": self.ready_volume,
            "sources": selection["sources"],
            "images": self.images,
            "cases": {name: {"status": "not_run"} for name in INITIAL_CASES},
            "status": "prepared",
            "retained": True,
            "expected_database_revision": database_revision,
        }
        if scenario == "persistent-availability":
            self.receipt.update(
                schema="vardr.nm2-worker-persistent-acceptance/1",
                scenario=scenario,
                acceptance_scope="persistent_availability_only",
                nm2_exit_status="incomplete",
            )
            self.receipt["cases"]["persistent_availability"] = {"status": "not_run"}
        elif scenario == EMPTY_SCENARIO:
            self.receipt.update(
                schema="vardr.nm2-worker-empty-acceptance/1", scenario=scenario,
                acceptance_scope="persistent_empty_stop_only", nm2_exit_status="incomplete",
            )
            self.receipt["cases"]["persistent_empty_stop"] = {"status": "not_run"}
        elif scenario == IDLE_SCENARIO:
            self.receipt.update(
                schema="vardr.nm2-worker-idle-acceptance/1", scenario=scenario,
                acceptance_scope="persistent_idle_control_only", nm2_exit_status="incomplete",
            )
            self.receipt["cases"]["persistent_idle_limit"] = {"status": "not_run"}
        elif scenario == COUNT_SCENARIO:
            self.receipt.update(
                schema="vardr.nm2-worker-count-acceptance/1",
                scenario=scenario,
                acceptance_scope="persistent_count_control_only",
                nm2_exit_status="incomplete",
            )
            self.receipt["cases"]["persistent_count_limit"] = {"status": "not_run"}
        elif scenario == STRICT_DRIFT_SCENARIO:
            self.receipt.update(
                schema=STRICT_DRIFT_SCHEMA, scenario=scenario,
                acceptance_scope=STRICT_DRIFT_SCOPE, nm2_exit_status="incomplete",
            )
            self.receipt["cases"][STRICT_DRIFT_CASE] = {"status": "not_run"}
        elif scenario == STRICT_REVIEW_SCENARIO:
            self.receipt.update(
                schema=STRICT_REVIEW_SCHEMA, scenario=scenario,
                acceptance_scope=STRICT_REVIEW_SCOPE, nm2_exit_status="incomplete",
            )
            self.receipt["cases"][STRICT_REVIEW_CASE] = {"status": "not_run"}
        elif scenario == STALE_CLAIM_SCENARIO:
            self.receipt.update(
                schema=STALE_CLAIM_SCHEMA, scenario=scenario,
                acceptance_scope=STALE_CLAIM_SCOPE, nm2_exit_status="incomplete",
            )
            self.receipt["cases"][STALE_CLAIM_CASE] = {"status": "not_run"}
        elif scenario != "healthy":
            self.receipt.update(
                schema="vardr.nm2-worker-failure-acceptance/1",
                scenario=scenario,
                acceptance_scope=(
                    "credential_grant_failure_only"
                    if scenario
                    in {"missing-local-grant", "active-target-grant-revoked"}
                    else "ordinary_http_cancellation_only"
                ),
                nm2_exit_status="incomplete",
            )
            key = (
                "missing_local_grant" if scenario == "missing-local-grant" else scenario
            )
            self.receipt["cases"][key] = {"status": "not_run"}
        self.secrets = []

    def docker(self, *args, env=None, **kwargs):
        return command(
            ["docker", "--context", self.m["docker_context"], *args],
            env=self.environment if env is None else env,
            **kwargs,
        )

    def compose(self, *args, worker=False, **kwargs):
        flags = [
            "-f",
            str(self.install / "compose.yaml"),
            "-f",
            str(self.install / "fixture.compose.json"),
        ]
        if worker:
            flags += ["-f", str(self.install / "compose.worker.json")]
        return self.docker(
            "compose",
            "--project-directory",
            str(self.install),
            "-p",
            self.project,
            *flags,
            *args,
            cwd=self.install,
            **kwargs,
        )

    def snapshot(self):
        specs = {
            "containers": (
                "container",
                ["ps", "-aq", "--no-trunc"],
                '{"id":{{json .Id}},"image":{{json .Image}},"labels":{{json .Config.Labels}},"state":{"running":{{json .State.Running}},"paused":{{json .State.Paused}},"restarting":{{json .State.Restarting}},"dead":{{json .State.Dead}},"exit_code":{{json .State.ExitCode}},"started_at":{{json .State.StartedAt}},"finished_at":{{json .State.FinishedAt}}},"restarts":{{json .RestartCount}},"networks":{{json .NetworkSettings.Networks}},"mounts":{{json .Mounts}}}',
            ),
            "networks": (
                "network",
                ["network", "ls", "-q", "--no-trunc"],
                '{"id":{{json .Id}},"name":{{json .Name}},"driver":{{json .Driver}},"scope":{{json .Scope}},"internal":{{json .Internal}},"attachable":{{json .Attachable}},"ipv6":{{json .EnableIPv6}},"ingress":{{json .Ingress}},"options":{{json .Options}},"ipam":{{json .IPAM}},"labels":{{json .Labels}},"containers":{{json .Containers}}}',
            ),
            "volumes": (
                "volume",
                ["volume", "ls", "-q"],
                '{"id":{{json .Name}},"driver":{{json .Driver}},"labels":{{json .Labels}},"options":{{json .Options}}}',
            ),
            "images": (
                "image",
                ["image", "ls", "-q", "--no-trunc"],
                '{"id":{{json .Id}},"tags":{{json .RepoTags}},"digests":{{json .RepoDigests}}}',
            ),
        }
        result = {}
        for kind, (noun, listing, template) in specs.items():
            rows = {}
            identifiers = sorted(set(self.docker(*listing).decode().split()))
            # Keep the full original projection while bounding command length.
            # Retained fixtures must not make every later guard need hundreds
            # of separate Docker client processes.
            for start in range(0, len(identifiers), 32):
                selected = identifiers[start : start + 32]
                raw = self.docker(noun, "inspect", "--format", template, *selected)
                observed = set()
                for line in raw.splitlines():
                    row = json.loads(line)
                    require(
                        type(row) is dict
                        and type(row.get("id")) is str
                        and row["id"] in selected
                        and row["id"] not in observed,
                        "inventory_batch_mismatch",
                    )
                    observed.add(row["id"])
                    row["labels"] = row.get("labels") or {}
                    rows[row["id"]] = row
                require(observed == set(selected), "inventory_batch_mismatch")
            result[kind] = rows
        return result

    def stop_owned(self, before):
        """Stop only newly created exact fixture IDs; retain every resource."""
        current = self.snapshot()
        owned = {
            key: row
            for key, row in current["containers"].items()
            if key not in before["containers"]
            and row["labels"].get("com.docker.compose.project") == self.project
        }
        running = []
        for container_id, row in sorted(owned.items()):
            require(re.fullmatch(r"[0-9a-f]{64}", container_id), "fixture_stop_id")
            observed = json.loads(
                self.docker(
                    "container",
                    "inspect",
                    "--format",
                    '{"id":{{json .Id}},"image":{{json .Image}},"project":{{json (index .Config.Labels "com.docker.compose.project")}}}',
                    container_id,
                )
            )
            require(
                observed
                == {"id": container_id, "image": row["image"], "project": self.project},
                "fixture_stop_identity_changed",
            )
            if row["state"]["running"]:
                running.append(container_id)
        if running:
            self.docker("container", "stop", "-t", "10", *running, timeout=90)
        stopped = self.snapshot()
        require(
            all(
                key in stopped["containers"]
                and stopped["containers"][key]["labels"].get(
                    "com.docker.compose.project"
                )
                == self.project
                and stopped["containers"][key]["state"]["running"] is False
                for key in owned
            ),
            "fixture_stop_not_observed",
        )
        self.receipt["fixture_stop"] = {
            "status": "stopped_retained",
            "container_ids": sorted(owned),
            "stop_requested_ids": running,
        }

    def image_sources(self):
        """Read files in ordinary network-none helpers, without invoking tools."""
        inventory = {}
        program = """import hashlib,json,pathlib,sys
selection=json.load(sys.stdin)
base=pathlib.Path('/app')
if selection['component']=='runner':
 import vardrrunner
 base=pathlib.Path(vardrrunner.__file__).parent
hashes={path.relative_to(base).as_posix():hashlib.sha256(path.read_bytes().replace(b'\\r\\n',b'\\n')).hexdigest() for path in base.rglob('*.py') if not {'tests','postgres_tests'} & set(path.relative_to(base).parts)}
executables={name:hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest() for name in selection['executables']}
print(json.dumps({'files':hashes,'executables':executables}))
"""
        for component, prefix, image in (
            ("map", "backend", self.images["api"]),
            ("runner", "vardrrunner", self.images["worker"]),
        ):
            source = Path(self.m["sources"][component]["path"])
            files = {}
            tracked = command(
                ["git", "-C", str(source), "ls-files", "-z", "--", prefix]
            )
            for raw in tracked.split(b"\0"):
                if not raw:
                    continue
                relative = Path(os.fsdecode(raw))
                if relative.suffix != ".py" or {"tests", "postgres_tests"} & set(
                    relative.parts
                ):
                    continue
                require(
                    relative.parts[0] == prefix and ".." not in relative.parts,
                    "image_source_path_refused",
                )
                files[relative.relative_to(prefix).as_posix()] = digest(
                    (source / relative).read_bytes().replace(b"\r\n", b"\n")
                )
            require(files, "image_source_inventory_empty")
            executables = (
                ["/usr/local/bin/vardr-worker-owner", "/usr/local/bin/vardrgate"]
                if component == "runner"
                else []
            )
            measured = json.loads(
                self.docker(
                    "run",
                    "--rm",
                    "-i",
                    "--network",
                    "none",
                    "--user",
                    "10001:10001",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges:true",
                    "--read-only",
                    "--label",
                    "com.docker.compose.project=" + self.project,
                    "--entrypoint",
                    "/usr/local/bin/python",
                    image,
                    "-I",
                    "-c",
                    program,
                    stdin=canonical(
                        {
                            "component": component,
                            "files": sorted(files),
                            "executables": executables,
                        }
                    ),
                )
            )
            require(measured["files"] == files, "image_source_inventory_mismatch")
            inventory[component] = {
                "image_id": image,
                "python_file_count": len(files),
                "python_inventory_sha256": digest(canonical(files)),
                "executables": measured["executables"],
                "line_endings": "CRLF-normalized-to-LF",
            }
        return inventory

    def stage(self):
        private_directory(self.install)
        private_directory(self.private)
        for raw in command(["git", "-C", str(self.source), "ls-files", "-z"]).split(
            b"\0"
        ):
            if not raw:
                continue
            relative = Path(os.fsdecode(raw))
            require(
                not relative.is_absolute() and ".." not in relative.parts,
                "tracked_source_path_refused",
            )
            if relative.parts[0] in {"artifacts", ".sources", ".git"}:
                continue
            source = self.source / relative
            require(
                source.is_file() and not source.is_symlink(),
                "tracked_source_link_refused",
            )
            target = self.install / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        sys.path.insert(0, str(self.install))
        self.lifecycle = load_module(
            "nm2_fixture_lifecycle", self.install / "vardrsec.py"
        )
        self.lifecycle.ROOT = self.install
        values = self.lifecycle.configuration_values()
        values.update(
            HTTPS_PORT=str(self.m["https_port"]),
            APPLICATION_SUBNET=self.m["application_subnet"],
            APPLICATION_IP_RANGE=self.m["application_ip_range"],
            PROXY_IP=self.m["proxy_ip"],
        )
        self.secrets += [
            values[k]
            for k in (
                "POSTGRES_PASSWORD",
                "POSTGRES_APP_PASSWORD",
                "BACKEND_JWT_SECRET",
                "AUTH_SECRET",
            )
        ]
        self.lifecycle.configure(values)
        # Shell values take precedence over .env in Compose. Pin this fixture's
        # fresh configuration before any role setup or container creation.
        self.environment.update(values)
        self.overlay = {
            "services": {
                name: {"image": self.images[name], "pull_policy": "never"}
                for name in ("db", "api", "web", "proxy")
            }
        }
        self.overlay["services"]["api"]["environment"] = {
            "VARDRMAP_MANAGED_WORKER": "0"
        }
        self.overlay["services"]["runner"] = {
            "image": self.images["worker"],
            "pull_policy": "never",
            "user": "10001:10001",
            "environment": {
                "HOME": "/home/runner",
                "VARDRRUNNER_ALLOW_PRIVATE_TARGETS": "1",
                "VARDRRUNNER_TOOLS_DIR": "/opt/vardrtools",
            },
        }
        self.write_overlay()
        roles = load_module("nm2_fixture_roles", self.install / "database_roles.py")

        def role_compose(root, *args, project=None, **kwargs):
            require(
                root == self.install and project == self.project,
                "database_role_fixture_scope",
            )
            environment = dict(self.environment)
            supplied = kwargs.pop("env", None)
            if supplied and "PGPASSWORD" in supplied:
                environment["PGPASSWORD"] = supplied["PGPASSWORD"]
            source = kwargs.pop("input", None)
            kwargs.pop("capture_output", None)
            text_output = kwargs.pop("text", False)
            output = self.compose(
                *args, env=environment, stdin=source, timeout=180, **kwargs
            )
            return subprocess.CompletedProcess(
                args,
                0,
                stdout=output.decode() if text_output else output,
                stderr="" if text_output else b"",
            )

        roles.recovery.compose = role_compose
        roles.apply(self.install, project=self.project)
        self.compose(
            "up",
            "-d",
            "--no-build",
            "--pull",
            "never",
            "--wait",
            "--wait-timeout",
            "180",
            "db",
            "api",
            "web",
            "proxy",
            timeout=240,
        )
        self.compose(
            "cp",
            "proxy:/data/caddy/pki/authorities/local/root.crt",
            str(self.install / "trust" / "root.crt"),
        )
        (self.install / "trust" / "root.crt").chmod(0o644)
        bootstrap = self.compose(
            "exec",
            "-T",
            "api",
            "python",
            "-m",
            "local_accounts",
            "init",
            "--username",
            "operator",
            "--generate-password",
        ).decode()
        self.password = bootstrap.split(
            "Generated password (store securely; shown once): ", 1
        )[1].strip()
        self.secrets.append(self.password)
        self.api = OwnerAPI(self.url, self.install / "trust" / "root.crt")
        self.owner = self.api.login("operator", self.password)
        self.receipt["public_ca_der_sha256"] = digest(
            ssl.PEM_cert_to_DER_cert(
                (self.install / "trust" / "root.crt").read_text(encoding="utf-8")
            )
        )

    def write_overlay(self):
        for name, subnet in fixture_subnets(self.m).items():
            self.overlay.setdefault("networks", {}).setdefault(name, {}).setdefault(
                "ipam", {}
            )["config"] = [{"subnet": subnet}]
        (self.install / "fixture.compose.json").write_bytes(canonical(self.overlay))

    def helper(self, *args, python=False, stdin=None):
        return self.compose(
            "run",
            "--rm",
            "--no-deps",
            "--user",
            "10001:10001",
            "--entrypoint",
            "/usr/local/bin/python" if python else "vardrrunner",
            "runner",
            *args,
            stdin=stdin,
            timeout=60,
        )

    def inventory(self, engagement, job, *, include_capacity=False):
        source = (self.install / "tests" / "nm2_worker_inventory.py").read_text(
            encoding="utf-8"
        )
        return json.loads(
            self.compose(
                "exec",
                "-T",
                "api",
                "python",
                "-c",
                source,
                stdin=canonical(
                    {"engagement_id": engagement, "job_id": job}
                    | (
                        {"runtime_attempt_bound": 35}
                        if self.protocol == "persistent-v3"
                        else {}
                    )
                    | (
                        {"count_approval_contexts": True}
                        if getattr(self, "scenario", None)
                        in {COUNT_SCENARIO, IDLE_SCENARIO, STRICT_DRIFT_SCENARIO,
                            STRICT_REVIEW_SCENARIO, STALE_CLAIM_SCENARIO}
                        else {}
                    )
                    | ({"include_capacity": True} if include_capacity else {})
                ),
            )
        )

    def traffic(self):
        code = "import urllib.request;print(urllib.request.urlopen('http://localhost:8080/observations',timeout=3).read().decode())"
        return json.loads(
            self.compose("exec", "-T", "gate-fixture", "python", "-c", code)
        )["requests"]

    def enable(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        sys.path.insert(0, self.m["sources"]["runner"]["path"])
        from vardrrunner.authorization.codec import b64

        self.operator_key, contract_key = (
            secrets.token_bytes(32),
            secrets.token_bytes(32),
        )

        def public(key):
            return b64(
                Ed25519PrivateKey.from_private_bytes(key)
                .public_key()
                .public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
            )

        self.issuer_id = "nm2-fixture-" + self.project.removeprefix("vardrsec-nm2-")
        # Readable by Map UID10001 inside its single-file read-only mount; the
        # containing host directory has owner-only access and is never mounted.
        publish(self.private / "contract.key", contract_key, mode=0o444)
        publish(
            self.private / "operators.json",
            canonical(
                [
                    {
                        "issuer_id": self.issuer_id,
                        "key_id": "operator",
                        "approver_id": self.owner,
                        "public_key": public(self.operator_key),
                        "revoked": False,
                    }
                ]
            ),
            mode=0o444,
        )
        self.trust = [
            {
                "issuer_id": self.issuer_id,
                "key_id": key_id,
                "public_key": public(key),
                "purposes": [purpose],
                "origins": ["map"],
                "revoked": False,
            }
            for key_id, key, purpose in (
                ("operator", self.operator_key, "approval"),
                ("contract", contract_key, "contract"),
            )
        ]
        self.secrets += [b64(self.operator_key), b64(contract_key)]
        config = self.overlay["services"]["api"]
        config["environment"].update(
            VARDRMAP_MANAGED_WORKER="1",
            VARDRMAP_MANAGED_ORIGIN=self.issuer_origin,
            VARDRMAP_MANAGED_ISSUER_ID=self.issuer_id,
            VARDRMAP_MANAGED_CONTRACT_KEY_ID="contract",
            VARDRMAP_MANAGED_CONTRACT_KEY_FILE="/run/nm2-map/contract.key",
            VARDRMAP_MANAGED_OPERATOR_TRUST_FILE="/run/nm2-map/operators.json",
        )
        config["volumes"] = [
            {
                "type": "bind",
                "source": str(self.private / name),
                "target": "/run/nm2-map/" + name,
                "read_only": True,
            }
            for name in ("contract.key", "operators.json")
        ]
        self.write_overlay()
        self.compose(
            "up",
            "-d",
            "--no-build",
            "--pull",
            "never",
            "--wait",
            "--wait-timeout",
            "120",
            "api",
            timeout=150,
        )
        self.key = self.api.request(
            "/auth/apikeys", {"label": "owned NM2 fixture", "scope": "runner"}
        )
        self.environment["VARDRMAP_API_KEY"] = self.key["token"]
        self.secrets.append(self.key["token"])
        self.tokens = {
            f"FIXTURE_{name.upper()}_TOKEN": secrets.token_urlsafe(32)
            for name in ("owner", "peer", "reader")
        }
        self.secrets += list(self.tokens.values())
        publish(
            self.private / "worker.env",
            (
                "\n".join(k + "=" + v for k, v in self.tokens.items())
                + "\nVARDRRUNNER_ALLOW_PRIVATE_TARGETS=1\n"
            ).encode(),
        )
        target = {
            "image": self.images["worker"],
            "pull_policy": "never",
            "user": "10001:10001",
            "entrypoint": [
                "/usr/local/bin/python",
                "-I",
                "/fixture/nm2_worker_target.py",
            ],
            "env_file": [str(self.private / "worker.env")],
            "volumes": [
                {
                    "type": "bind",
                    "source": str(self.install / "tests"),
                    "target": "/fixture",
                    "read_only": True,
                }
            ],
            "networks": {"runner": {"aliases": [TARGET_HOST]}},
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "read_only": True,
            "restart": "no",
            "labels": {"io.vardrsec.nm2-fixture": self.project},
        }
        environment = self.target_environment()
        if environment:
            target["environment"] = environment
        self.overlay["services"]["gate-fixture"] = target
        self.write_overlay()
        self.compose("up", "-d", "--no-build", "--pull", "never", "gate-fixture")
        until = time.monotonic() + 20
        while True:
            try:
                health = self.compose(
                    "exec",
                    "-T",
                    "gate-fixture",
                    "python",
                    "-c",
                    "import urllib.request;print(urllib.request.urlopen('http://localhost:8080/health',timeout=3).read().decode())",
                    timeout=min(5, max(0.001, until - time.monotonic())),
                )
                require(
                    json.loads(health) == {"ready": True}, "fixture_health_not_ready"
                )
                break
            except AcceptanceRefused:
                require(time.monotonic() < until, "fixture_health_not_ready")
                time.sleep(0.2)
        self.receipt["doctor_sha256"] = digest(
            self.helper("doctor", "--platform", "--offline", "--json")
        )

    def target_environment(self):
        return target_environment(self.scenario)

    def fixture_authorization(self, engagement, window_start, window_end):
        return self.api.request(
            f"/engagements/{engagement}/authorizations",
            {
                "permits": "Owned synthetic fixture only",
                "authorized_by": "Fixture local owner",
                "reference": self.project,
                "window_start": window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "window_end": window_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            expected=201,
        )

    def new_job(self, name, *, in_scope=True, marker=False,
                authority="current", queue_warnings=None):
        require(authority in {"current", "missing", "expired"}, "strict_review_authority_mode")
        now = datetime.now(timezone.utc)

        def stamp(moment):
            return moment.strftime("%Y-%m-%dT%H:%M:%SZ")

        engagement = self.api.request(
            "/engagements",
            {
                "name": "NM2 " + name,
                "starts_at": stamp(now - timedelta(minutes=1)),
                "ends_at": stamp(now + timedelta(minutes=15)),
            },
        )["id"]
        base = "/engagements/" + engagement
        authorization = None
        if authority != "missing":
            window = (
                (now - timedelta(days=2), now - timedelta(days=1))
                if authority == "expired"
                else (now - timedelta(minutes=1), now + timedelta(minutes=15))
            )
            authorization = self.fixture_authorization(engagement, *window)["id"]
        self.api.request(
            base + "/scope/in",
            {
                "kind": "url",
                "value": ORIGIN + "/" if in_scope else ORIGIN + "/unapproved/",
            },
            expected=200,
        )
        for endpoint, body in (
            ("concurrency-policy", {"limit": 1}),
            ("target-policy", {"limit": 5}),
            ("duration-policy", {"limit_seconds": 120}),
        ):
            self.api.request(base + "/" + endpoint, body, method="PUT")
        job, stored = self.job_in_engagement(name, engagement, marker=marker,
                                             queue_warnings=queue_warnings)
        return engagement, authorization, job, stored

    def job_in_engagement(self, name, engagement, *, marker=False, contract_required=True, queue_warnings=None):
        from gate_acceptance import ORIGIN as REVIEWED_ORIGIN, reviewed_cases

        base = "/engagements/" + engagement
        case = next(case for case in reviewed_cases() if case["name"] == "fixed")
        case["spec"]["id"] = "nm2-" + name
        requests = [case["spec"]["request"]]
        requests.extend(
            identity["preflight"]
            for identity in case["spec"]["identities"]
            if identity.get("preflight") is not None
        )
        for request in requests:
            require(
                request["url"].startswith(REVIEWED_ORIGIN + "/"),
                "fixture_case_origin_mismatch",
            )
            request["url"] = ORIGIN + request["url"][len(REVIEWED_ORIGIN) :]
            if marker:
                require(
                    re.fullmatch(r"[a-z0-9-]{1,64}", name) is not None,
                    "fixture_marker_invalid",
                )
                request["url"] += (
                    ("&" if "?" in request["url"] else "?") + "nm2_case=" + name
                )
        stored = self.api.request(base + "/test-cases", case, expected=201)
        job = self.api.request(
            base + "/jobs",
            {
                "tool_type": "vardrgate_api_test",
                "target_source": "scope",
                "config": {
                    "test_case_id": stored["id"],
                    "timeout": EXECUTION["timeout_seconds"],
                },
                "authorization_contract_required": contract_required,
            },
        )
        if queue_warnings is not None:
            queue_warnings.extend(job["warnings"])
        return job["id"], stored

    def enroll_runner(self):
        identity = self.helper("identity", "show").decode()
        runner_id = re.search(r"Runner ID:\s*([0-9a-f-]{36})", identity).group(1)
        enrollment = json.loads(
            self.compose(
                "exec",
                "-T",
                "api",
                "python",
                "-m",
                "managed_enrollment",
                "bind",
                "--owner",
                self.owner,
                "--api-key-id",
                self.key["id"],
                "--runner-id",
                runner_id,
                "--origin",
                self.issuer_origin,
                "--key-stdin",
                stdin=(self.key["token"] + "\n").encode(),
            )
        )
        self.runner_binding = runner_id, enrollment["enrollment_id"]
        return self.runner_binding

    def approve_local_grant(self, engagement, identity, lifetime):
        self.helper(
            "credentials", "approve", "--engagement", engagement, "--origin", ORIGIN,
            "--env", f"FIXTURE_{identity.upper()}_TOKEN", "--issuer", self.issuer_origin,
            "--expires-in", str(lifetime),
        )

    def approval_review_input(self, engagement, authorization, case, *, local_grants=True):
        from vardrrunner.authorization.plan import compile_gate_plan

        runner_id, enrollment_id = self.enroll_runner()
        if local_grants:
            for who in ("owner", "peer"):
                self.approve_local_grant(engagement, who, 600)
        tool_sha256 = (
            self.helper(
                "-I",
                "-c",
                "import hashlib,pathlib;print(hashlib.sha256(pathlib.Path('/usr/local/bin/vardrgate').read_bytes()).hexdigest())",
                python=True,
            )
            .decode()
            .strip()
        )
        plan = compile_gate_plan(case["spec"], EXECUTION, tool_sha256=tool_sha256)
        expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        selection = {
            "enrollment_id": enrollment_id,
            "authorization_id": authorization,
            "plan": plan,
        }
        review_input = {
            **selection,
            "expires_at": expiry,
            "max_executions": 1,
            "max_duration_seconds": 30,
            "max_artifact_bytes": 1024 * 1024,
            "credential_grants": [
                {**reference, "revision": 1, "expires_at": expiry}
                for reference in plan["credential_references"]
            ],
        }
        return (runner_id, enrollment_id), review_input

    def approve(
        self,
        name,
        engagement,
        authorization,
        job,
        case,
        *,
        local_grants=True,
        expected=200,
        review_snapshot=None,
        review_context=None,
        review_authority=None,
        deferred_registration=None,
    ):
        from vardrrunner.authorization.contracts import approve

        binding, review_input = self.approval_review_input(
            engagement, authorization, case, local_grants=local_grants,
        )
        selection = {key: review_input[key] for key in ("enrollment_id", "authorization_id", "plan")}
        review = self.api.request(
            f"/jobs/{job}/managed/approval/review", review_input, expected=expected
        )
        if expected != 200:
            return None
        approval = approve(
            review["context"],
            {"id": self.issuer_id, "key_id": "operator"},
            "map",
            self.owner,
            "fixture-" + name,
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            self.operator_key,
        )
        registration = {**selection, "approval": approval}
        if deferred_registration is None:
            self.api.request(f"/jobs/{job}/managed/approval/register", registration)
        else:
            deferred_registration.update(registration)
        if review_snapshot is not None:
            review_snapshot.update(review_input)
        if review_context is not None:
            review_context.update(review["context"])
        if review_authority is not None:
            review_authority.update(review["authority_snapshot"])
        return binding

    def strict_drift_replacement(self, registration, original, fresh):
        from vardrrunner.authorization.codec import TrustAnchor, unb64
        from vardrrunner.authorization.contracts import approve, approved
        from vardrrunner.authorization.documents import read_document

        operators = read_document(self.private / "operators.json")
        require(type(operators) is list and len(operators) == 1,
                "strict_authority_drift_original_signature")
        operator = operators[0]
        require(operator["issuer_id"] == self.issuer_id and operator["key_id"] == "operator"
                and operator["approver_id"] == self.owner and operator["revoked"] is False,
                "strict_authority_drift_original_signature")
        anchor = TrustAnchor(
            self.issuer_id, "operator", unb64(operator["public_key"]),
            frozenset({"approval"}), frozenset({"map"}),
        )
        old = approved(registration["approval"], (anchor,))
        require(old["approver_id"] == self.owner
                and old["approval_id"] == "fixture-" + STRICT_DRIFT_SCENARIO
                and canonical(old["context"]) == canonical(original["context"]),
                "strict_authority_drift_original_signature")
        strict_drift_contexts(original, fresh, old["approved_at"])
        context = fresh["context"]
        approval_id = "fixture-" + STRICT_DRIFT_SCENARIO + "-fresh"
        envelope = approve(
            context, {"id": self.issuer_id, "key_id": "operator"}, "map", self.owner,
            approval_id, context["not_before"], self.operator_key,
        )
        return old["approved_at"], {**registration, "approval": envelope}, f"{self.issuer_id}:{approval_id}"

    def strict_authority_drift(self):
        self.receipt["stage"] = "strict_authority_drift_setup"
        traffic_before = self.traffic()
        require(traffic_before == [], "strict_authority_drift_traffic")
        name = STRICT_DRIFT_SCENARIO
        engagement, authorization, job, case = self.new_job(name)
        review_input, context, authority, registration = {}, {}, {}, {}
        self.approve(
            name, engagement, authorization, job, case,
            review_snapshot=review_input, review_context=context,
            review_authority=authority, deferred_registration=registration,
        )
        before = self.inventory(engagement, job, include_capacity=True)
        strict_drift_empty(before, engagement, job)

        self.receipt["stage"] = "strict_authority_drift_mutation"
        path = f"/engagements/{engagement}/authorizations/{authorization}"
        mutations = []
        for status in ("revoked", "active"):
            observed = self.api.request(path, {"status": status}, method="PATCH")
            mutations.append({key: observed[key] for key in ("id", "program_id", "status")})
            require(
                mutations[-1] == {"id": authorization, "program_id": engagement, "status": status},
                "strict_authority_drift_mutation_unconfirmed",
            )

        self.receipt["stage"] = "strict_authority_drift_refusal"
        path = f"/jobs/{job}/managed/approval"
        original = {"context": context, "authority_snapshot": authority}
        reviewed = self.api.request(path + "/review", review_input)
        fresh = {key: reviewed[key] for key in ("context", "authority_snapshot")}
        old_approved_at, replacement, approval_id = self.strict_drift_replacement(
            registration, original, fresh,
        )
        refused = self.api.request(path + "/register", registration, expected=409)
        require(refused == {"detail": "managed_approval_refused"},
                "strict_authority_drift_refusal_shape")
        after = self.inventory(engagement, job, include_capacity=True)
        strict_drift_empty(after, engagement, job)
        traffic_after = self.traffic()
        require(traffic_after == [], "strict_authority_drift_traffic")

        self.receipt["stage"] = "strict_authority_drift_positive_control"
        require(
            sorted(self.compose("ps", "--all", "--services").decode().split()) == STRICT_DRIFT_SERVICES,
            "strict_authority_drift_mutated_or_dispatched",
        )
        reply = self.api.request(path + "/register", replacement)
        require(reply == {"approval_record_id": approval_id},
                "strict_authority_drift_positive_control")
        proof = {
            "original": original, "fresh": fresh, "mutations": mutations,
            "refusal": refused, "old_approved_at": old_approved_at,
            "registration_sha256": digest(canonical(registration)),
            "before": before, "after": after, "traffic_before": traffic_before,
            "traffic_after": traffic_after,
            "services": sorted(self.compose("ps", "--all", "--services").decode().split()),
            "positive": {
                "approval_record_id": approval_id,
                "registration_sha256": digest(canonical(replacement)),
                "inventory": self.inventory(engagement, job, include_capacity=True),
                "traffic": self.traffic(),
            },
        }
        strict_drift_measurements(proof)
        self.receipt["cases"][STRICT_DRIFT_CASE] = {"status": "passed", "proof": proof}
        self.receipt["status"], self.receipt["stage"] = STRICT_DRIFT_PASS, STRICT_DRIFT_COMPLETE

    def stale_claim_marker(self):
        selected = self.compose("ps", "--quiet", "api").decode().split()
        require(len(selected) == 1 and re.fullmatch(r"[a-f0-9]{64}", selected[0]) is not None,
                "strict_stale_claim_api_identity_required")
        cid = selected[0]
        template = (
            '{"id":{{json .Id}},"image":{{json .Image}},'
            '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
            '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
            '"started_at":{{json .State.StartedAt}},"running":{{json .State.Running}},'
            '"restarts":{{json .RestartCount}}}'
        )
        api = json.loads(self.docker("container", "inspect", "--format", template, cid))
        require(
            api["id"] == cid and api["project"] == self.project and api["service"] == "api"
            and api["image"] == self.images["api"] and api["running"] is True
            and type(api["restarts"]) is int and api["restarts"] == 0,
            "strict_stale_claim_api_identity_required",
        )
        raw = self.docker("container", "logs", "--tail", "100", cid, timeout=8)
        return api, sum(STALE_CLAIM_MARKER.fullmatch(line) is not None for line in raw.splitlines())

    def strict_stale_registered_claim(self):
        self.receipt["stage"] = "strict_stale_claim_register"
        traffic_before = self.traffic()
        services = sorted(self.compose("ps", "--all", "--services").decode().split())
        require(traffic_before == [] and services == STRICT_DRIFT_SERVICES,
                "strict_stale_claim_no_worker_required")
        name = STALE_CLAIM_SCENARIO
        engagement, authorization, job, case = self.new_job(name)
        review_input, context, authority = {}, {}, {}
        runner, enrollment = self.approve(
            name, engagement, authorization, job, case, local_grants=False,
            review_snapshot=review_input, review_context=context, review_authority=authority,
        )
        plan = review_input["plan"]
        require(
            authority["enrollment"]["id"] == enrollment and authority["enrollment"]["runner_id"] == runner
            and authority["origin"] == self.issuer_origin
            and plan["case_hash"] == digest(canonical(case["spec"])),
            "strict_stale_claim_original_binding",
        )
        before = self.inventory(engagement, job, include_capacity=True)
        count_approval_context(before, context)
        strict_drift_empty({**before, "approvals": [], "approval_context_sha256": {}}, engagement, job)
        require(
            before["approvals"][0]["id"] == self.issuer_id + ":fixture-" + name
            and canonical([before["approvals"][0]["issued"], before["approvals"][0]["revoked"]])
            == b"[0,false]",
            "strict_stale_claim_retained_approval_required",
        )

        self.receipt["stage"] = "strict_stale_claim_mutation"
        mutation = self.api.request(f"/engagements/{engagement}/target-policy", {"limit": 4}, method="PUT")
        require(canonical(mutation) == canonical({
            "limit": 4, "spent": 0, "unit": "represented_origin_attempts/1",
        }), "strict_stale_claim_mutation_required")
        reviewed = self.api.request(f"/jobs/{job}/managed/approval/review", review_input)
        fresh = {key: reviewed[key] for key in ("context", "authority_snapshot")}
        api, prior = self.stale_claim_marker()
        require(prior == 0, "strict_stale_claim_refusal_required")

        self.receipt["stage"] = "strict_stale_claim_refusal"
        body = {
            "origin": self.issuer_origin, "runner_id": runner, "concurrency_budget": True,
            "duration_seconds": 30, "target_binding": {
                "profile": "gate-fixed-http/1", "case_sha256": plan["case_hash"], "origins": [ORIGIN],
            },
        }
        transport = OwnerAPI(self.url, self.api.ca)
        require(transport.ca_sha256 == self.api.ca_sha256, "fixture_ca_changed")
        refusal = transport.request(
            f"/jobs/{job}/managed/claim", body, method="POST", csrf=False,
            expected=409, bearer=self.key["token"],
        )
        observed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        same_api, count = self.stale_claim_marker()
        require(canonical(same_api) == canonical(api), "strict_stale_claim_api_identity_required")
        require(
            self.api.request(f"/engagements/{engagement}/evidence?job_id={job}")["evidence"] == []
            and sorted(self.compose("ps", "--all", "--services").decode().split()) == services,
            "strict_stale_claim_no_worker_required",
        )
        proof = {
            "original": {"context": context, "authority_snapshot": authority}, "fresh": fresh,
            "plan": plan, "request": body, "mutation": mutation, "observed_at": observed_at,
            "refusal": {"status": 409, "cache_control": "no-store", "body": refusal},
            "marker_counts": [prior, count], "api_container_id": api["id"],
            "before": before, "after": self.inventory(engagement, job, include_capacity=True),
            "traffic_before": traffic_before, "traffic_after": self.traffic(), "services": services,
        }
        stale_claim_measurements(proof)
        self.receipt["cases"][STALE_CLAIM_CASE] = {"status": "passed", "proof": proof}
        self.receipt["status"], self.receipt["stage"] = STALE_CLAIM_PASS, STALE_CLAIM_COMPLETE

    def strict_review_authority(self):
        traffic_before = self.traffic()
        require(traffic_before == [], "strict_review_traffic_changed")
        proof = {"traffic_before": traffic_before}
        for kind in ("missing", "expired"):
            self.receipt["stage"] = f"strict_review_{kind}"
            warnings = []
            engagement, authorization, job, case = self.new_job(
                f"strict-review-{kind}", authority=kind, queue_warnings=warnings,
            )
            base = f"/engagements/{engagement}"
            path = f"/jobs/{job}/managed/approval/review"
            listed = self.api.request(base + "/authorizations")
            active = self.api.request(base + "/authorization/active")
            require(active is None and (listed == [] if kind == "missing" else
                    type(listed) is list and len(listed) == 1
                    and listed[0]["id"] == authorization and warnings == [CLOSED_WINDOW_WARNING]),
                    "strict_review_authority_precondition")
            binding, review_input = self.approval_review_input(
                engagement, authorization or "nm2-absent-authorization", case,
            )
            before = self.inventory(engagement, job, include_capacity=True)
            strict_drift_empty(before, engagement, job)
            refusal = self.api.request(path, review_input, expected=409)
            require(refusal == {"detail": "managed_approval_refused"}, "strict_review_refusal_shape")
            after_refusal = self.inventory(engagement, job, include_capacity=True)
            strict_drift_empty(after_refusal, engagement, job)

            now = datetime.now(timezone.utc)
            if kind == "missing":
                current = self.fixture_authorization(
                    engagement, now - timedelta(minutes=1), now + timedelta(minutes=15),
                )
            else:
                current = self.api.request(
                    f"{base}/authorizations/{authorization}",
                    {"window_end": (now + timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ")},
                    method="PATCH",
                )
            accepted_input = {**review_input, "authorization_id": current["id"]}
            review = self.api.request(path, accepted_input)
            proof[kind] = {
                "before": before, "after_refusal": after_refusal,
                "after_review": self.inventory(engagement, job, include_capacity=True),
                "listed_before": listed, "active_before": active, "authorization_after": current,
                "active_after": self.api.request(base + "/authorization/active"),
                "review_input": review_input, "accepted_input_sha256": digest(canonical(accepted_input)),
                "runner_id": binding[0], "refusal": refusal,
                "review": {key: review[key] for key in ("authority_snapshot", "case", "context")},
            }
            if kind == "expired":
                proof[kind]["queued_warnings"] = warnings
        proof["traffic_after"] = self.traffic()
        proof["services"] = sorted(self.compose("ps", "--all", "--services").decode().split())
        strict_review_measurements(proof)
        self.receipt["cases"][STRICT_REVIEW_CASE] = {"status": "passed", "proof": proof}
        self.receipt["status"], self.receipt["stage"] = STRICT_REVIEW_PASS, STRICT_REVIEW_COMPLETE

    def verify_fixed(
        self,
        engagement,
        job,
        case,
        physical,
        before_worker,
        requests,
        inventory,
        *,
        persistent=False,
        self_exit=False,
    ):
        require(
            inventory["schema"]
            == (
                "vardr.nm2-fixture-inventory/4"
                if persistent and getattr(self, "scenario", None) in {COUNT_SCENARIO, IDLE_SCENARIO}
                else "vardr.nm2-fixture-inventory/3"
                if persistent
                else "vardr.nm2-fixture-inventory/2"
            )
            and inventory["schema_revision"] == self.database_revision
            and inventory["database_user"] == "vardrmap_app",
            "normal_database_readiness_required",
        )
        require(
            not self_exit or (persistent and self.scenario in {COUNT_SCENARIO, IDLE_SCENARIO}),
            "count_self_exit_scope_refused",
        )
        require(
            (
                type(physical["exit_code"]) is int
                and 0 <= physical["exit_code"] <= 255
                and (
                    physical["exit_code"] == (124 if self.scenario == IDLE_SCENARIO else 0)
                    and physical["operator_stop_state"] == "not_requested"
                    if self_exit
                    else physical["operator_stop_state"] == "stopped_observed"
                )
            )
            if persistent
            else physical["exit_code"] == 0,
            "happy_worker_exit_not_clean",
        )
        require(
            inventory["job_status"] == "done"
            and len(inventory["contracts"]) == len(inventory["results"]) == 1
            and not inventory["stops"],
            "happy_terminal_receipt_missing",
        )
        require(
            inventory["execution"]["state"] == "completed"
            and inventory["execution"]["capacity_reserved"] is False
            and inventory["execution"]["target_charge"] == 1
            and inventory["execution"]["duration_seconds"] == 30
            and inventory["targets_spent"] == 1
            and inventory["duration_allocated"] == 30
            and inventory["contracts"][0]["consumed"] is True
            and inventory["contracts"][0]["ordinal"] == 1
            and inventory["contracts"][0]["fence"] == 1
            and inventory["results"][0]["outcome"] == "completed",
            "happy_retained_allowance_mismatch",
        )
        require(
            len(requests) == 5
            and {row["identity"] for row in requests} == {"owner", "peer", "anonymous"},
            "happy_fixed_traffic_mismatch",
        )
        marker = parse_qs(urlsplit(case["spec"]["request"]["url"]).query).get(
            "nm2_case"
        )
        require(
            marker is not None
            and all(
                parse_qs(urlsplit(row["path"]).query).get("nm2_case") == marker
                for row in requests
            ),
            "happy_case_traffic_binding_mismatch",
        )
        base = "/engagements/" + engagement
        completed_job = next(
            row for row in self.api.request(base + "/jobs")["jobs"] if row["id"] == job
        )
        assessment = completed_job["assessment"]
        require(
            assessment["status"] == "conclusive"
            and assessment["baseline_valid"] is True
            and assessment["case_snapshot_verified"] is True
            and assessment["preflight"]["status"] == "passed"
            and assessment["case_hash"] == digest(canonical(case["spec"]))
            and assessment["candidate_findings"] == 0,
            "fixed_assessment_not_proven",
        )
        require(
            self.api.request(base + "/scans?job_id=" + job)["scans"] == []
            and len(inventory["runtimes"]) == 1
            and inventory["results"][0]["evidence_created"] == 5
            and inventory["results"][0]["scan_items_created"] == 0,
            "fixed_result_runtime_binding_not_proven",
        )
        runtime = inventory["runtimes"][0]
        selected = [row for row in runtime["attempts"] if row["job_id"] == job]
        require(len(selected) == 1, "fixed_runtime_attempt_missing")
        attempt = selected[0]
        require(
            attempt["runtime_id"] == runtime["id"]
            and attempt["confirmed_at"] is not None
            and attempt["released_at"] is not None,
            "fixed_runtime_attempt_unreleased",
        )
        result, contract = inventory["results"][0], inventory["contracts"][0]
        binding = attempt["binding"]
        require(
            binding
            == {
                "origin": self.issuer_origin,
                "runner_id": runtime["runner_id"],
                "job_id": job,
                "contract_id": contract["id"],
                "attempt_id": contract["attempt_id"],
                "fence": contract["fence"],
                "contract_sha256": contract["contract_sha256"],
            }
            and result["contract_id"] == binding["contract_id"],
            "fixed_runtime_attempt_binding_mismatch",
        )
        require(
            all(
                re.fullmatch(r"[a-f0-9]{64}", value or "") is not None
                for value in (
                    binding["contract_sha256"],
                    result["artifact_sha256"],
                    result["receipt_sha256"],
                    attempt["native_done_sha256"],
                )
            ),
            "fixed_runtime_attempt_hash_invalid",
        )
        require(
            result["receipt_sha256"]
            == digest(
                canonical(
                    {
                        "schema": "vardr.managed-result/1",
                        **binding,
                        "artifact_sha256": result["artifact_sha256"],
                        "case_sha256": assessment["case_hash"],
                    }
                )
            ),
            "fixed_result_receipt_hash_mismatch",
        )
        terminal = {
            "schema": "vardr.managed-completion/1",
            **binding,
            "receipt_sha256": result["receipt_sha256"],
            "outcome": "completed",
            "capacity_reserved": False,
        }
        require(
            canonical(attempt["terminal_receipt"]) == canonical(terminal)
            and attempt["terminal_receipt_sha256"] == digest(canonical(terminal)),
            "fixed_full_completion_not_proven",
        )
        release = {
            "schema": "vardr.worker-idle-release/2"
            if persistent
            else "vardr.worker-idle-release/1",
            "runtime_id": runtime["id"],
            "runtime_sha256": runtime["runtime_sha256"],
            "runtime_sequence": attempt["runtime_sequence"],
            "binding": binding,
            "terminal_receipt_sha256": digest(canonical(terminal)),
            "native_done_sha256": attempt["native_done_sha256"],
            "released": True,
        }
        if persistent:
            release["admission_sha256"] = runtime["admission_sha256"]
        release["receipt_sha256"] = digest(canonical(release))
        require(
            canonical(attempt["release_receipt"]) == canonical(release),
            "fixed_runtime_release_not_proven",
        )
        evidence = self.api.request(base + "/evidence?job_id=" + job)["evidence"]
        require(
            len(evidence) == 5
            and all(
                digest(row["body"].encode()) == row["content_hash"] for row in evidence
            ),
            "evidence_hash_mismatch",
        )
        retained = canonical(evidence)
        require(
            not any(
                secret.encode() in retained
                for secret in (
                    *self.secrets,
                    "disposable-private-response-canary",
                    "disposable-response-cookie-canary",
                )
            ),
            "evidence_redaction_failed",
        )
        public_assessment = {
            key: assessment[key]
            for key in (
                "status",
                "baseline_valid",
                "case_snapshot_verified",
                "case_hash",
                "candidate_findings",
            )
        } | {"preflight": {"status": assessment["preflight"]["status"]}}
        measured = {
            "runtime_sequence": attempt["runtime_sequence"],
            "engagement_id": engagement,
            "job_id": job,
            "case_sha256": assessment["case_hash"],
            "evidence_count": len(evidence),
            "evidence_sha256": digest(retained),
            "artifact_sha256": result["artifact_sha256"],
            "result_receipt_sha256": result["receipt_sha256"],
            "terminal_receipt_sha256": digest(canonical(terminal)),
            "release_receipt_sha256": release["receipt_sha256"],
            "native_done_sha256": attempt["native_done_sha256"],
            **{
                key: attempt[key] for key in ("bound_at", "confirmed_at", "released_at")
            },
            "binding": binding,
            "terminal_receipt": terminal,
            "release_receipt": release,
            "requests": requests,
            "assessment": public_assessment,
            "target_charge": inventory["execution"]["target_charge"],
            "duration_seconds": inventory["execution"]["duration_seconds"],
            "capacity_reserved": inventory["execution"]["capacity_reserved"],
        }
        return {
            "status": "passed",
            "physical": physical,
            "before_worker": before_worker,
            "inventory": inventory,
            "requests": requests,
            "case_sha256": assessment["case_hash"],
            "evidence_count": len(evidence),
            "evidence_sha256": digest(retained),
        }, measured

    def verify_healthy_sequence(
        self, physical, measured, inventories, runner_id, enrollment_id
    ):
        require(
            len(measured) == len(inventories) == 2, "healthy_sequence_count_mismatch"
        )
        runtimes = [inventory["runtimes"][0] for inventory in inventories]
        runtime = runtimes[0]
        require(
            canonical(runtime) == canonical(runtimes[1]),
            "healthy_sequence_snapshot_mismatch",
        )
        require(
            runtime["id"] == physical["runtime_id"]
            and runtime["runtime_sha256"]
            == physical["runtime_sha256"]
            == digest(canonical(physical["identity"]))
            and runtime["identity"] == physical["identity"]
            and runtime["runner_id"] == runner_id
            and runtime["enrollment_id"] == enrollment_id,
            "healthy_sequence_incarnation_mismatch",
        )
        require(
            type(runtime["max_attempts"]) is int
            and runtime["max_attempts"] == 2
            and type(runtime["last_sequence"]) is int
            and runtime["last_sequence"] == 2
            and runtime["active_sequence"] is None
            and runtime["retired"] is False
            and runtime["report_sha256"] is None
            and set(runtime["legacy_binding"])
            == {
                "job_id",
                "contract_id",
                "attempt_id",
                "fence",
                "contract_sha256",
                "bound_at",
                "confirmed_at",
            }
            and all(value is None for value in runtime["legacy_binding"].values()),
            "healthy_sequence_runtime_not_idle",
        )
        require(
            len(runtime["attempts"]) == 2
            and [row["runtime_sequence"] for row in runtime["attempts"]] == [1, 2]
            and [row["job_id"] for row in runtime["attempts"]]
            == [row["job_id"] for row in measured]
            and all(
                type(row["runtime_sequence"]) is int for row in runtime["attempts"]
            ),
            "healthy_sequence_history_mismatch",
        )
        for key in (
            "job_id",
            "engagement_id",
            "case_sha256",
            "artifact_sha256",
            "result_receipt_sha256",
            "terminal_receipt_sha256",
            "release_receipt_sha256",
            "native_done_sha256",
        ):
            require(
                len({row[key] for row in measured}) == 2,
                "healthy_sequence_reused_" + key,
            )
        dates = []
        for row in measured:
            require(
                type(row["runtime_sequence"]) is int
                and row["runtime_sequence"] in {1, 2}
                and row["evidence_count"] == len(row["requests"]) == 5
                and row["target_charge"] == 1
                and row["duration_seconds"] == 30
                and row["capacity_reserved"] is False,
                "healthy_sequence_measurement_mismatch",
            )
            current = []
            for key in ("bound_at", "confirmed_at", "released_at"):
                value = row[key]
                require(
                    type(value) is str
                    and re.fullmatch(
                        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", value
                    )
                    is not None,
                    "healthy_sequence_timestamp_invalid",
                )
                try:
                    current.append(datetime.fromisoformat(value.replace("Z", "+00:00")))
                except ValueError:
                    raise AcceptanceRefused(
                        "healthy_sequence_timestamp_invalid"
                    ) from None
            require(
                current[0] <= current[1] <= current[2],
                "healthy_sequence_attempt_order_invalid",
            )
            dates.append(current)
        require(
            dates[0][2] <= dates[1][0], "healthy_sequence_release_after_next_binding"
        )
        require(
            len(
                {
                    tuple(
                        parse_qs(urlsplit(row["requests"][0]["path"]).query).get(
                            "nm2_case", []
                        )
                    )
                    for row in measured
                }
            )
            == 2,
            "healthy_sequence_marker_reused",
        )
        require(
            all(
                type(request["received_monotonic_ns"]) is int
                and request["received_monotonic_ns"] > 0
                for row in measured
                for request in row["requests"]
            ),
            "healthy_sequence_request_clock_invalid",
        )
        require(
            max(row["received_monotonic_ns"] for row in measured[0]["requests"])
            <= min(row["received_monotonic_ns"] for row in measured[1]["requests"]),
            "healthy_sequence_request_order_invalid",
        )
        require(
            sum(inventory["targets_spent"] for inventory in inventories) == 2
            and sum(inventory["duration_allocated"] for inventory in inventories) == 60,
            "healthy_sequence_allowance_mismatch",
        )
        return {
            "status": "passed",
            "physical": physical,
            "runtime_id": runtime["id"],
            "runtime_sha256": runtime["runtime_sha256"],
            "max_attempts": 2,
            "last_sequence": 2,
            "active_sequence": None,
            "attempts": measured,
            "target_request_count": 10,
            "evidence_count": 10,
            "targets_spent": 2,
            "duration_allocated": 60,
        }

    def timed_traffic(self):
        # Both timestamps come from this owned target's Linux monotonic clock.
        # This inserts no process into the worker's private PID lineage.
        source = (
            "import json,time,urllib.request;"
            "data=json.load(urllib.request.urlopen('http://localhost:8080/observations',timeout=3));"
            "print(json.dumps({'requests':data['requests'],'observed_monotonic_ns':time.monotonic_ns(),"
            "'observed_utc_ns':time.time_ns()}))"
        )
        return json.loads(
            self.compose(
                "exec", "-T", "gate-fixture", "python", "-c", source, timeout=5
            )
        )

    def local_metadata(self, run_id, engagement, job):
        # Read only exact original association and retained known output metadata.
        # No PID lookup/signal, capability reconstruction or raw file export.
        source = """
import hashlib,json,os,re,stat,sys
from pathlib import Path
from vardrrunner import config
from vardrrunner.journal import Journal
selection=json.load(sys.stdin)
journal=Journal(config.journal_file())
record=journal.get(selection['run_id'])
assert record is not None and record.job_id==selection['job_id'] and record.engagement_id==selection['engagement_id']
with journal._connection() as con:
    claim=con.execute('SELECT state,consumption_sent,consumption_acknowledged FROM managed_claim_intents WHERE run_id=?',(record.run_id,)).fetchone()
assert claim is not None
files=[]
partial=None
if record.run_dir is not None:
    directory=Path(record.run_dir)
    assert directory.parent==config.runs_dir() and directory.is_dir() and all(not item.is_symlink() for item in (directory,*directory.parents))
    for name in ('vardrgate_result.json','vardrgate_stopped_result.json'):
        path=directory/name
        if path.exists() or path.is_symlink():
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as stream:
                before=os.fstat(stream.fileno())
                assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=1024*1024
                raw=stream.read(1024*1024+1)
                after=os.fstat(stream.fileno())
                assert len(raw)==before.st_size and (before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns)
            files.append({'name':name,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
            if name=='vardrgate_stopped_result.json':
                data=json.loads(raw)
                assert data['error']=='execution_cancelled' and re.fullmatch('[0-9a-f]{64}',data['case_hash'])
                assert all(type(data.get(key)) is list for key in ('executions','preflight','findings'))
                identities=[row.get('identity_id') for row in data['executions']]
                preflights=[row.get('identity_id') for row in data['preflight'] if row.get('status')=='passed']
                assert all(type(value) is str and value in {'owner','peer','anonymous'} for value in identities+preflights)
                partial={'error':'execution_cancelled','case_sha256':data['case_hash'],'execution_count':len(data['executions']),'preflight_count':len(data['preflight']),'finding_count':len(data['findings']),'cancelled_execution_count':sum(row.get('error')=='execution_cancelled' for row in data['executions']),'passed_preflight_count':len(preflights),'execution_identity_ids':identities,'cancelled_identity_ids':[row['identity_id'] for row in data['executions'] if row.get('error')=='execution_cancelled'],'passed_preflight_identity_ids':preflights,'response_identity_ids':[row['identity_id'] for row in data['executions'] if row.get('status_code',0)]}
reason=getattr(record,'failure_reason',None)
assert reason in {None,'local_emergency_stop','remote_stop_requested','control_lease_expired','authorization_deadline','tool_timeout','descendants_after_tool_exit','control_cap_unavailable','observed_failed_completion'}
event=getattr(record,'last_event',None)
print(json.dumps({'run_id':record.run_id,'job_id':record.job_id,'engagement_id':record.engagement_id,'phase':record.phase.value,'status':record.status,'failure_reason':reason,'last_event':event if event in {'managed_completion_receipt','managed_failed_completion_receipt'} else 'other','local_stop_requested':journal.stop_requested(record.run_id),'claim_state':claim['state'],'consumption_sent':claim['consumption_sent'],'consumption_acknowledged':claim['consumption_acknowledged'],'partial_files':files,'partial_result':partial}))
"""
        return json.loads(
            self.helper(
                "-I",
                "-c",
                source,
                python=True,
                stdin=canonical(
                    {"run_id": run_id, "engagement_id": engagement, "job_id": job}
                ),
            )
        )

    def grant_snapshot(self, engagement, *, peer_only=False):
        # Existing grant validator, public references only; never resolve a value.
        source = """
import json,sys
from vardrrunner import credential_grants
selection=json.load(sys.stdin)
policy=credential_grants.Policy(selection['issuer'])
grants=[row for row in policy.store.entries() if row['issuer']==selection['issuer'] and row['engagement_id']==selection['engagement_id'] and row['origin']==selection['origin'] and row['source']=='env' and row['name'] in {'FIXTURE_OWNER_TOKEN','FIXTURE_PEER_TOKEN'}]
references=[('peer','env','FIXTURE_PEER_TOKEN')]
if not selection['peer_only']:
    references.insert(0,('owner','env','FIXTURE_OWNER_TOKEN'))
try:
    policy.check(selection['engagement_id'],[selection['origin']],references)
    reason='granted'
except credential_grants.GrantError as error:
    reason=str(error)
assert reason in {'granted','grant_missing_or_replaced','grant_expired_or_revoked'}
print(json.dumps({'grants':grants,'policy_reason':reason}))
"""
        return json.loads(
            self.helper(
                "-I",
                "-c",
                source,
                python=True,
                stdin=canonical(
                    {
                        "issuer": self.issuer_origin,
                        "engagement_id": engagement,
                        "origin": ORIGIN,
                        "peer_only": peer_only,
                    }
                ),
            )
        )

    def verify_grant_revocation(self, engagement, before, after):
        require(
            set(before) == set(after) == {"grants", "policy_reason"}
            and before["policy_reason"] == "granted"
            and after["policy_reason"] == "grant_expired_or_revoked"
            and len(before["grants"]) == len(after["grants"]) == 2,
            "target_grant_revocation_not_proven",
        )
        previous = {row["name"]: row for row in before["grants"]}
        current = {row["name"]: row for row in after["grants"]}
        require(
            set(previous)
            == set(current)
            == {"FIXTURE_OWNER_TOKEN", "FIXTURE_PEER_TOKEN"},
            "target_grant_identity_changed",
        )
        require(
            previous["FIXTURE_OWNER_TOKEN"]["id"]
            != previous["FIXTURE_PEER_TOKEN"]["id"],
            "target_grant_identity_changed",
        )
        for name, row in previous.items():
            require(
                set(row)
                == {
                    "issuer",
                    "engagement_id",
                    "origin",
                    "source",
                    "name",
                    "id",
                    "issued_at",
                    "expires_at",
                    "status",
                }
                and row["issuer"] == self.issuer_origin
                and row["engagement_id"] == engagement
                and row["origin"] == ORIGIN
                and row["source"] == "env"
                and row["status"] == "active"
                and re.fullmatch(r"[0-9a-f-]{36}", row["id"]) is not None
                and current[name]
                == {
                    **row,
                    "status": "revoked" if name == "FIXTURE_OWNER_TOKEN" else "active",
                },
                "target_grant_identity_changed",
            )
        return {
            "grant_id": previous["FIXTURE_OWNER_TOKEN"]["id"],
            "peer_grant_id": previous["FIXTURE_PEER_TOKEN"]["id"],
            "before_status": "active",
            "after_status": "revoked",
            "policy_reason": after["policy_reason"],
            "catalog_before_sha256": digest(canonical(before)),
            "catalog_after_sha256": digest(canonical(after)),
        }

    def report_exit(self, physical):
        reported = json.loads(
            worker_cli_command(
                [
                    sys.executable,
                    str(self.install / "vardrsec.py"),
                    "worker",
                    "report-exit",
                    "--runtime-id",
                    physical["runtime_id"],
                    "--private-root",
                    str(self.private),
                ],
                cwd=self.install,
                env=self.environment,
                timeout=120,
            )
        )
        require(
            reported["schema"] == "vardr.worker-cli/1"
            and reported["state"] == "terminal_observed"
            and reported["runtime_id"] == physical["runtime_id"],
            "cancellation_host_report_not_bound",
        )
        return reported["receipt"]["receipt"]

    def unclaimed_metadata(self, engagement, job, physical):
        source = """
import json,sys
from vardrrunner import config
from vardrrunner.journal import Journal
from vardrrunner.authorization.reconciliation import local_holds
selection=json.load(sys.stdin)
journal=Journal(config.journal_file())
queries={
 'claims':('managed_claim_intents','SELECT count(*) FROM managed_claim_intents WHERE backend=? AND job=?',(selection['origin'],selection['job_id'])),
 'contracts':('authorization_contracts','SELECT count(*) FROM authorization_contracts WHERE job=?',(selection['job_id'],)),
 'fences':('authorization_fences','SELECT count(*) FROM authorization_fences WHERE job=?',(selection['job_id'],)),
 'attempts':('managed_worker_attempts','SELECT count(*) FROM managed_worker_attempts WHERE runtime_id=?',(selection['runtime_id'],)),
}
with journal._connection() as con:
    counts={name:(con.execute(query,args).fetchone()[0] if con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone() else 0) for name,(table,query,args) in queries.items()}
    row=con.execute('SELECT runtime_id,runtime_sha256,max_attempts,last_sequence,active_sequence,state,retirement FROM managed_worker_incarnations WHERE runtime_id=?',(selection['runtime_id'],)).fetchone()
assert row is not None
print(json.dumps({'runs':len([row for row in journal.list(engagement_id=selection['engagement_id']) if row.job_id==selection['job_id']]),**counts,'incarnation':dict(row),'remaining_local_holds':local_holds(journal)}))
"""
        return json.loads(
            self.helper(
                "-I",
                "-c",
                source,
                python=True,
                stdin=canonical(
                    {
                        "origin": self.issuer_origin,
                        "engagement_id": engagement,
                        "job_id": job,
                        "runtime_id": physical["runtime_id"],
                    }
                ),
            )
        )

    def verify_missing_grant(
        self,
        job,
        runner_id,
        enrollment_id,
        physical,
        inventory,
        retirement,
        local,
        grants,
        traffic,
    ):
        require(
            not traffic
            and grants == {"grants": [], "policy_reason": "grant_missing_or_replaced"}
            and inventory["schema"] == "vardr.nm2-fixture-inventory/2"
            and inventory["schema_revision"] == self.database_revision
            and inventory["database_user"] == "vardrmap_app"
            and inventory["job_id"] == job
            and inventory["job_status"] == "pending"
            and inventory["execution"] is None
            and inventory["targets_spent"] == inventory["duration_allocated"] == 0
            and not any(
                inventory[key] for key in ("contracts", "results", "stops", "runtimes")
            )
            and len(inventory["approvals"]) == 1
            and inventory["approvals"][0]["issued"] == 0
            and inventory["approvals"][0]["revoked"] is False,
            "missing_grant_not_zero_rpc",
        )
        require(
            set(physical)
            == {
                "identity",
                "runtime_id",
                "runtime_sha256",
                "exit_code",
                "finished_at",
                "operator_enable_state",
            }
            and type(physical["exit_code"]) is int
            and physical["exit_code"] != 0
            and physical["operator_enable_state"] == "enabled"
            and physical["runtime_sha256"] == digest(canonical(physical["identity"])),
            "missing_grant_physical_exit_not_proven",
        )
        expected = {
            "schema": "vardr.worker-retirement/2",
            "runtime_id": physical["runtime_id"],
            "runtime_sha256": physical["runtime_sha256"],
            "origin": self.issuer_origin,
            "runner_id": runner_id,
            "enrollment_id": enrollment_id,
            "runtime_sequence": None,
            "last_sequence": 0,
            "binding": None,
            "attempt_receipt": None,
            "report_sha256": retirement["report_sha256"],
            "retired": True,
        }
        require(
            re.fullmatch(r"[0-9a-f]{64}", retirement["report_sha256"]) is not None
            and canonical(retirement)
            == canonical({**expected, "receipt_sha256": digest(canonical(expected))}),
            "missing_grant_runtime_not_unissued",
        )
        require(
            set(local)
            == {
                "runs",
                "claims",
                "contracts",
                "fences",
                "attempts",
                "incarnation",
                "remaining_local_holds",
            }
            and all(
                type(local[key]) is int and local[key] == 0
                for key in (
                    "runs",
                    "claims",
                    "contracts",
                    "fences",
                    "attempts",
                    "remaining_local_holds",
                )
            )
            and canonical(local["incarnation"])
            == canonical(
                {
                    "runtime_id": physical["runtime_id"],
                    "runtime_sha256": physical["runtime_sha256"],
                    "max_attempts": 1,
                    "last_sequence": 0,
                    "active_sequence": None,
                    "state": "idle",
                    "retirement": None,
                }
            ),
            "missing_grant_local_claim_or_hold_exists",
        )
        return {
            "status": "passed",
            "physical": physical,
            "job_id": job,
            "target_request_count": 0,
            "targets_spent": 0,
            "duration_allocated": 0,
            "policy_reason": grants["policy_reason"],
            "journal_run_count": 0,
            "claim_intent_count": 0,
            "runtime_last_sequence": 0,
            "retirement_receipt_sha256": retirement["receipt_sha256"],
            "local_reconciliation": "not_required_no_run",
            "remaining_local_holds": 0,
            "original_runner_auth": "verified",
        }

    def missing_grant(self):
        self.receipt["stage"] = "missing_grant_setup"
        engagement, authorization, job, case = self.new_job(self.scenario, marker=True)
        runner_id, enrollment_id = self.approve(
            self.scenario, engagement, authorization, job, case, local_grants=False
        )
        grants = self.grant_snapshot(engagement)
        require(
            grants == {"grants": [], "policy_reason": "grant_missing_or_replaced"},
            "missing_grant_precondition_failed",
        )
        self.helper("whoami")  # Original enrolled API credential, no replacement key.
        require(not self.traffic(), "missing_grant_target_traffic")
        self.receipt["stage"] = "missing_grant_worker"
        physical = self.worker(runner_id, enrollment_id)
        self.receipt["stage"] = "missing_grant_host_reconciliation"
        retirement = self.report_exit(physical)
        self.helper("whoami")
        inventory = self.inventory(engagement, job)
        local = self.unclaimed_metadata(engagement, job, physical)
        after = self.grant_snapshot(engagement)
        require(after == grants, "missing_grant_catalog_changed")
        traffic = self.traffic()
        self.receipt["observed_failure"] = {
            "physical": physical,
            "inventory": inventory,
            "retirement": retirement,
            "local": local,
            "grants": after,
        }
        self.receipt["stage"] = "missing_grant_verification"
        self.receipt["cases"]["missing_local_grant"] = self.verify_missing_grant(
            job,
            runner_id,
            enrollment_id,
            physical,
            inventory,
            retirement,
            local,
            after,
            traffic,
        )
        self.receipt["status"], self.receipt["stage"] = (
            "selected_failure_slice_passed",
            "selected_failure_complete",
        )

    def observe_active_run(self, engagement, job, case):
        until = time.monotonic() + 25
        marker = parse_qs(urlsplit(case["spec"]["request"]["url"]).query)["nm2_case"]
        while True:
            observed = self.timed_traffic()
            requests = observed["requests"]
            require(len(requests) <= 3, "cancellation_dispatch_advanced_before_action")
            if len(requests) == 3:
                require(
                    [row["identity"] for row in requests] == ["owner", "peer", "owner"]
                    and [urlsplit(row["path"]).path for row in requests]
                    == ["/session", "/session", "/fixed/records/42"]
                    and all(
                        parse_qs(urlsplit(row["path"]).query).get("nm2_case") == marker
                        for row in requests
                    ),
                    "cancellation_request_binding_mismatch",
                )
                break
            require(time.monotonic() < until, "cancellation_resource_not_observed")
            time.sleep(0.1)
        records = json.loads(
            self.helper("audit", "list", "--json", "--engagement", engagement)
        )
        selected = [row for row in records if row["job_id"] == job]
        require(
            len(selected) == 1
            and selected[0]["phase"] == "executing"
            and selected[0]["backend_url"] == self.issuer_origin
            and selected[0]["command_profile"].get("controlled") is True,
            "cancellation_original_run_not_active",
        )
        run_id = selected[0]["run_id"]
        require(
            re.fullmatch(r"[0-9a-f]{32}", run_id) is not None,
            "cancellation_run_id_invalid",
        )
        return run_id, observed

    def cancellation_action(self, engagement, job, case):
        run_id, observed = self.observe_active_run(engagement, job, case)
        self.receipt["stage"] = "cancellation_request"
        if self.scenario == "local-emergency-stop":
            self.helper("jobs", "stop", run_id)
        elif self.scenario == "active-target-grant-revoked":
            self.helper(
                "credentials",
                "revoke",
                "--engagement",
                engagement,
                "--origin",
                ORIGIN,
                "--env",
                "FIXTURE_OWNER_TOKEN",
                "--issuer",
                self.issuer_origin,
            )
        else:
            require(self.scenario == "stop-work", "fixture_scenario_refused")
            stopped = self.api.request(
                f"/engagements/{engagement}/stop-work",
                {"reason": "NM2 controlled HTTP fixture"},
            )
            require(
                stopped.get("stop_work_at") is not None,
                "cancellation_stop_work_not_recorded",
            )
        return {"run_id": run_id, "requests": observed["requests"]}

    def verify_failed_partial(
        self, engagement, job, case, binding, terminal, inventory, local, *,
        completion_event="managed_completion_receipt",
    ):
        result = inventory["results"][0]
        summary = local.get("partial_result")
        case_sha = digest(canonical(case["spec"]))
        identities = [row["id"] for row in case["spec"]["identities"]]
        preflights = [
            row["id"]
            for row in case["spec"]["identities"]
            if row.get("preflight") is not None
        ]
        require(
            len(identities) == len(set(identities)) and len(preflights) == 2,
            "cancelled_partial_identity_binding_invalid",
        )
        # Logical cancelled records include identities refused before networking.
        # The independent target count proves actual dispatch, not this count.
        evidence_count = len(identities) + len(preflights)
        require(
            summary
            == {
                "error": "execution_cancelled",
                "case_sha256": case_sha,
                "execution_count": len(identities),
                "preflight_count": len(preflights),
                "finding_count": 0,
                "cancelled_execution_count": len(identities),
                "passed_preflight_count": len(preflights),
                "execution_identity_ids": identities,
                "cancelled_identity_ids": identities,
                "passed_preflight_identity_ids": preflights,
                "response_identity_ids": [],
            }
            and local["phase"] == local["status"] == "failed"
            and local["last_event"] == completion_event,
            "cancelled_partial_result_not_proven",
        )
        files = {row["name"]: row for row in local["partial_files"]}
        require(
            set(files) == {"vardrgate_result.json", "vardrgate_stopped_result.json"},
            "cancelled_partial_files_missing",
        )
        artifact_sha = files["vardrgate_stopped_result.json"]["sha256"]
        receipt_sha = digest(
            canonical(
                {
                    "schema": "vardr.managed-result/1",
                    **binding,
                    "artifact_sha256": artifact_sha,
                    "case_sha256": case_sha,
                }
            )
        )
        require(
            result
            == {
                "contract_id": binding["contract_id"],
                "artifact_sha256": artifact_sha,
                "receipt_sha256": receipt_sha,
                "outcome": "failed",
                "evidence_created": evidence_count,
                "scan_items_created": 0,
            }
            and canonical(terminal)
            == canonical(
                {
                    "schema": "vardr.managed-completion/1",
                    **binding,
                    "receipt_sha256": receipt_sha,
                    "outcome": "failed",
                    "capacity_reserved": False,
                }
            ),
            "cancelled_partial_receipt_mismatch",
        )
        base = "/engagements/" + engagement
        assessment = next(
            row for row in self.api.request(base + "/jobs")["jobs"] if row["id"] == job
        )["assessment"]
        evidence = self.api.request(base + "/evidence?job_id=" + job)["evidence"]
        require(
            assessment["status"] == "inconclusive"
            and assessment["baseline_valid"] is False
            and assessment["case_snapshot_verified"] is True
            and assessment["case_hash"] == case_sha
            and assessment["preflight"]["status"] == "passed"
            and assessment["candidate_findings"] == 0
            and len(evidence) == evidence_count
            and self.api.request(base + "/scans?job_id=" + job)["scans"] == [],
            "cancelled_partial_assessment_mismatch",
        )
        details = []
        for row in evidence:
            require(
                type(row["body"]) is str
                and row["content_hash"] == digest(row["body"].encode())
                and not any(
                    secret.encode() in canonical(row) for secret in self.secrets
                ),
                "cancelled_partial_evidence_mismatch",
            )
            details.append(json.loads(row["body"]))
        observed_preflights = [
            row.get("identity_id")
            for row in details
            if row.get("phase") == "identity_preflight"
            and row.get("status") == "passed"
        ]
        cancelled = [
            row for row in details if row.get("error") == "execution_cancelled"
        ]
        require(
            sorted(observed_preflights) == sorted(preflights)
            and sorted(row.get("identity_id") for row in cancelled)
            == sorted(identities)
            and all(not row.get("status_code") for row in cancelled),
            "cancelled_partial_evidence_mismatch",
        )
        return {
            "artifact_sha256": artifact_sha,
            "result_receipt_sha256": receipt_sha,
            "terminal_receipt_sha256": digest(canonical(terminal)),
            "evidence_count": evidence_count,
            "evidence_sha256": digest(canonical(evidence)),
            "assessment_status": "inconclusive",
        }

    def verify_cancellation(
        self,
        engagement,
        job,
        case,
        physical,
        inventory,
        action,
        after,
        retirement,
        local,
        reconciled,
    ):
        require(
            set(physical)
            == {
                "identity",
                "runtime_id",
                "runtime_sha256",
                "exit_code",
                "finished_at",
                "operator_enable_state",
            }
            and set(physical["identity"])
            == {
                "daemon_id",
                "container_id",
                "image_id",
                "project",
                "started_at",
                "owner_nonce",
            }
            and type(physical["exit_code"]) is int
            and physical["exit_code"] != 0
            and physical["operator_enable_state"] == "enabled",
            "cancellation_physical_exit_not_proven",
        )
        require(
            inventory["schema"] == "vardr.nm2-fixture-inventory/2"
            and inventory["schema_revision"] == self.database_revision
            and inventory["database_user"] == "vardrmap_app",
            "normal_database_readiness_required",
        )
        requests = after["requests"]
        require(
            requests == action["requests"]
            and len(requests) == 3
            and all(
                set(row) == {"identity", "method", "path", "received_monotonic_ns"}
                and row["method"] == "GET"
                for row in requests
            )
            and [row["identity"] for row in requests] == ["owner", "peer", "owner"]
            and [urlsplit(row["path"]).path for row in requests]
            == ["/session", "/session", "/fixed/records/42"],
            "cancellation_dispatch_after_stop",
        )
        clocks = [row["received_monotonic_ns"] for row in requests]
        require(
            all(
                type(value) is int and value > 0
                for value in [*clocks, after["observed_monotonic_ns"]]
            )
            and clocks == sorted(clocks)
            and 0 < after["observed_monotonic_ns"] - clocks[-1] < 15_000_000_000,
            "cancellation_not_before_http_timeout",
        )
        require(
            inventory["job_status"] == "failed"
            and len(inventory["contracts"]) == len(inventory["runtimes"]) == 1
            and (
                (len(inventory["stops"]) == 1 and not inventory["results"])
                or (len(inventory["results"]) == 1 and not inventory["stops"])
            )
            and inventory["targets_spent"] == 1
            and inventory["duration_allocated"] == 30,
            "cancellation_terminal_inventory_mismatch",
        )
        contract, stop, runtime = (
            inventory["contracts"][0],
            inventory["stops"][0] if inventory["stops"] else None,
            inventory["runtimes"][0],
        )
        require(
            contract["consumed"] is True
            and type(contract["ordinal"]) is type(contract["fence"]) is int
            and contract["ordinal"] == contract["fence"] == 1
            and runtime["id"] == physical["runtime_id"]
            and runtime["runtime_sha256"]
            == physical["runtime_sha256"]
            == digest(canonical(physical["identity"]))
            and runtime["identity"] == physical["identity"]
            and all(
                type(runtime[key]) is int and runtime[key] == 1
                for key in ("max_attempts", "last_sequence", "active_sequence")
            )
            and runtime["retired"] is True
            and len(runtime["attempts"]) == 1,
            "cancellation_runtime_binding_mismatch",
        )
        binding = {
            "origin": self.issuer_origin,
            "job_id": job,
            "runner_id": runtime["runner_id"],
            "contract_id": contract["id"],
            "attempt_id": contract["attempt_id"],
            "fence": contract["fence"],
            "contract_sha256": contract["contract_sha256"],
        }
        attempt = runtime["attempts"][0]
        require(
            attempt["runtime_id"] == runtime["id"]
            and type(attempt["runtime_sequence"]) is int
            and attempt["runtime_sequence"] == 1
            and attempt["job_id"] == job
            and all(value is None for value in runtime["legacy_binding"].values())
            and canonical(attempt["binding"]) == canonical(binding)
            and attempt["bound_at"] is not None
            and attempt["confirmed_at"] is not None
            and attempt["released_at"] is None
            and attempt["release_receipt"] is None
            and attempt["native_done_sha256"] is None
            and attempt["terminal_receipt"] is None
            and attempt["terminal_receipt_sha256"] is None,
            "cancellation_attempt_reused_or_unconfirmed",
        )
        terminal = retirement["attempt_receipt"]
        cause = stop["cause"] if stop is not None else local.get("failure_reason")
        require(
            cause
            in {
                "local_emergency_stop",
                "remote_stop_requested",
                "control_lease_expired",
                "observed_exit",
            },
            "cancellation_unrelated_stop_cause",
        )
        outcome = (
            "failed"
            if stop is None
            else (
                "cancelled"
                if cause in {"local_emergency_stop", "remote_stop_requested"}
                else "failed"
            )
        )
        partial = None
        stop_sha = None
        if stop is None:
            partial = self.verify_failed_partial(
                engagement, job, case, binding, terminal, inventory, local
            )
        else:
            stop_sha = digest(
                canonical(
                    {
                        "schema": "vardr.managed-stop/1",
                        **binding,
                        "outcome": outcome,
                        "cause": cause,
                        "termination_confirmed": True,
                    }
                )
            )
        require(
            (
                stop is None
                or (
                    canonical(terminal)
                    == canonical(
                        {
                            "schema": "vardr.managed-stop-receipt/1",
                            **binding,
                            "outcome": outcome,
                            "cause": cause,
                            "receipt_sha256": stop_sha,
                            "capacity_reserved": False,
                        }
                    )
                    and stop
                    == {
                        "contract_id": binding["contract_id"],
                        "receipt_sha256": stop_sha,
                        "outcome": outcome,
                        "cause": cause,
                    }
                )
            )
            and inventory["execution"]
            == {
                "state": outcome,
                "capacity_reserved": False,
                "target_charge": 1,
                "duration_seconds": 30,
            },
            "cancellation_stop_receipt_mismatch",
        )
        expected = {
            "schema": "vardr.worker-retirement/2",
            "runtime_id": physical["runtime_id"],
            "runtime_sha256": physical["runtime_sha256"],
            "origin": self.issuer_origin,
            "runner_id": runtime["runner_id"],
            "enrollment_id": runtime["enrollment_id"],
            "runtime_sequence": 1,
            "last_sequence": 1,
            "binding": binding,
            "attempt_receipt": terminal,
            "report_sha256": runtime["report_sha256"],
            "retired": True,
        }
        require(
            isinstance(runtime["report_sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", runtime["report_sha256"]) is not None
            and canonical(retirement)
            == canonical({**expected, "receipt_sha256": digest(canonical(expected))}),
            "cancellation_retirement_mismatch",
        )
        require(
            local["run_id"] == action["run_id"]
            and local["job_id"] == job
            and local["engagement_id"] == engagement
            and type(local["consumption_sent"])
            is type(local["consumption_acknowledged"])
            is int
            and local["consumption_sent"] == local["consumption_acknowledged"] == 1
            and local["local_stop_requested"]
            is (self.scenario == "local-emergency-stop")
            and reconciled["state"].startswith("terminal_")
            and type(reconciled["remaining_local_holds"]) is int
            and reconciled["remaining_local_holds"] == 0,
            "cancellation_local_reconciliation_mismatch",
        )
        files = local["partial_files"]
        require(
            len(files) <= 2
            and all(
                set(row) == {"name", "size", "sha256"}
                and row["name"]
                in {"vardrgate_result.json", "vardrgate_stopped_result.json"}
                and type(row["size"]) is int
                and 0 < row["size"] <= 1024 * 1024
                and re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                for row in files
            ),
            "cancellation_partial_projection_invalid",
        )
        proof = {
            "status": "passed",
            "physical": physical,
            "job_id": job,
            "case_sha256": digest(canonical(case["spec"])),
            "requests": [
                {
                    "identity": row["identity"],
                    "method": row["method"],
                    "route": urlsplit(row["path"]).path,
                    "received_monotonic_ns": row["received_monotonic_ns"],
                }
                for row in requests
            ],
            "target_request_count": 3,
            "delay_seconds": 15,
            "resource_to_exit_observation_seconds": (
                after["observed_monotonic_ns"] - clocks[-1]
            )
            / 1e9,
            "stop_cause": cause,
            "native_stop_receipt": stop is not None and cause != "observed_exit",
            "stop_receipt_sha256": stop_sha,
            "retirement_receipt_sha256": retirement["receipt_sha256"],
            "targets_spent": 1,
            "duration_allocated": 30,
            "capacity_reserved": False,
            "partial_files": files,
            "partial_result_state": "retained" if files else "not_emitted",
            "retained_observations_sha256": digest(canonical(requests)),
            "local_stop_requested": local["local_stop_requested"],
            "remaining_local_holds": 0,
            "forced_uncooperative_child_test": "not_run",
        }
        if self.scenario == "active-target-grant-revoked":
            proof["grant_revocation"] = self.verify_grant_revocation(
                engagement, action["grant_before"], action["grant_after"]
            )
            proof["grant_revocation"]["original_runner_auth"] = "verified"
        if partial is not None:
            proof["failed_completion"] = partial
        return proof

    def cancelled_http(self):
        self.receipt["stage"] = "cancellation_setup"
        engagement, authorization, job, case = self.new_job(self.scenario, marker=True)
        runner_id, enrollment_id = self.approve(
            self.scenario, engagement, authorization, job, case
        )
        grant_before = None
        if self.scenario == "active-target-grant-revoked":
            grant_before = self.grant_snapshot(engagement)
            require(
                grant_before["policy_reason"] == "granted",
                "target_grant_not_initially_active",
            )
        before = self.inventory(engagement, job)
        require(
            not self.traffic()
            and before["job_status"] == "pending"
            and before["execution"] is None
            and not before["contracts"]
            and before["targets_spent"] == before["duration_allocated"] == 0,
            "approved_queue_executed_before_worker_enablement",
        )
        action = {}

        def on_running(admission):
            self.receipt["stage"] = "cancellation_observe"
            action.update(self.cancellation_action(engagement, job, case))

        physical = self.worker(runner_id, enrollment_id, on_running=on_running)
        after = self.timed_traffic()
        self.receipt["stage"] = "cancellation_host_reconciliation"
        retirement = self.report_exit(physical)
        if grant_before is not None:
            action.update(
                grant_before=grant_before, grant_after=self.grant_snapshot(engagement)
            )
        local = self.local_metadata(action["run_id"], engagement, job)
        reconciled = json.loads(
            self.helper("audit", "reconcile-managed", action["run_id"])
        )
        retained = self.local_metadata(action["run_id"], engagement, job)
        require(
            all(
                retained[key] == local[key]
                for key in (
                    "run_id",
                    "job_id",
                    "engagement_id",
                    "consumption_sent",
                    "consumption_acknowledged",
                    "local_stop_requested",
                    "partial_files",
                    "partial_result",
                )
            ),
            "cancellation_original_metadata_changed",
        )
        inventory = self.inventory(engagement, job)
        self.receipt["observed_failure"] = {
            "physical": physical,
            "inventory": inventory,
            "retirement": retirement,
            "local": local,
            "reconciled": reconciled,
            "target_request_count": len(after["requests"]),
        }
        if grant_before is not None:
            self.receipt["observed_failure"]["grant_transition"] = {
                "before": grant_before,
                "after": action["grant_after"],
            }
        require(self.traffic() == after["requests"], "cancellation_dispatch_after_stop")
        self.receipt["stage"] = "cancellation_verification"
        self.receipt["cases"][self.scenario] = self.verify_cancellation(
            engagement,
            job,
            case,
            physical,
            inventory,
            action,
            after,
            retirement,
            local,
            reconciled,
        )
        self.receipt["status"], self.receipt["stage"] = (
            "selected_failure_slice_passed",
            "selected_failure_complete",
        )

    def worker_action(self, action, runtime_id, *, timeout=45, expected_admission=None):
        command = (worker_idle_status_command if getattr(self, "scenario", None) == IDLE_SCENARIO
                   else worker_status_command) if action == "status" else worker_cli_command
        return json.loads(
            command(
                [
                    sys.executable,
                    str(self.install / "vardrsec.py"),
                    "worker",
                    action,
                    "--runtime-id",
                    runtime_id,
                    "--private-root",
                    str(self.private),
                ],
                cwd=self.install,
                env=self.environment,
                timeout=timeout,
                **(
                    {"expected_admission": expected_admission}
                    if action == "status"
                    else {}
                ),
            )
        )

    def persistent_idle(self, admission, number):
        until = time.monotonic() + 45
        while True:
            value = self.worker_action(
                "status",
                admission["runtime_id"],
                timeout=max(0.001, until - time.monotonic()),
                expected_admission=admission,
            )
            require(
                value["schema"] == "vardr.worker-status/1"
                and value["protocol"] == "persistent-v3"
                and value["mode"] == "persistent"
                and value["limits"]
                == {"max_attempts": None, "idle_timeout_seconds": None}
                and value["identity"] == admission["identity"]
                and value["runtime_id"] == admission["runtime_id"],
                "persistent_status_identity_changed",
            )
            if value["state"] == "idle-ready" and value["cursor"] == {
                "last_sequence": str(number),
                "phase": "idle",
            }:
                require(
                    value["new_work_disabled"] is False
                    and value["reporting_revoked"] is False,
                    "persistent_availability_disabled",
                )
                return value
            require(
                value["state"] != "stopped" and time.monotonic() < until,
                "persistent_idle_not_observed",
            )
            time.sleep(0.2)

    def persistent_metadata(self, admission, number):
        # Separate ordinary Runner container, only after idle/DONE/release. Never
        # exec a process into the managed worker's private PID namespace.
        source = """
import json,sys,time
from vardrrunner import config
from vardrrunner.journal import Journal
from vardrrunner.authorization import worker_persistent as persistent
from vardrrunner.authorization.reconciliation import local_holds
selection=json.load(sys.stdin)
journal=Journal(config.journal_file())
until=time.monotonic()+5
while True:
    with journal._connection() as con:
        current=persistent.parent(con,selection['runtime_id'])
        assert current['admission_sha256']==selection['admission_sha256']
        attempt=con.execute('SELECT * FROM managed_persistent_attempts WHERE runtime_id=? AND runtime_sequence=?',(selection['runtime_id'],selection['number'])).fetchone() if selection['number'] else None
        ready=current['last_sequence']==selection['number'] and current['active_sequence'] is None and (attempt is None or attempt['state'] in {'released','physical_retirement_observed'})
    if ready:break
    assert time.monotonic()<until
    time.sleep(.1)
with journal._connection() as con:
    current=persistent.parent(con,selection['runtime_id'])
    counts={}
    for name,query in {'runs':'SELECT count(*) FROM runs','claims':'SELECT count(*) FROM managed_claim_intents','contracts':'SELECT count(*) FROM authorization_contracts','results':'SELECT count(*) FROM managed_result_intents'}.items():
        table={'runs':'runs','claims':'managed_claim_intents','contracts':'authorization_contracts','results':'managed_result_intents'}[name]
        counts[name]=con.execute(query).fetchone()[0] if con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone() else 0
    projected=None
    if attempt is not None:
        persistent._validate_attempt(con,attempt)
        claim=con.execute('SELECT state,consumption_sent,consumption_acknowledged FROM managed_claim_intents WHERE run_id=?',(attempt['run_id'],)).fetchone()
        run=journal.get(attempt['run_id'])
        assert claim is not None and run is not None
        projected={'run_id':run.run_id,'job_id':run.job_id,'phase':run.phase.value,'pid':run.pid,'artifact_sha256':run.artifact_sha256,'state':attempt['state'],'retired_from_state':attempt['retired_from_state'],'claim_state':claim['state'],'consumption_sent':claim['consumption_sent'],'consumption_acknowledged':claim['consumption_acknowledged'],'native_done_sha256':attempt['native_done_sha256'],'completion':json.loads(attempt['completion']),'release':json.loads(attempt['release_ack'])}
    result={'runtime_id':current['runtime_id'],'runtime_sha256':current['runtime_sha256'],'admission_sha256':current['admission_sha256'],'last_sequence':str(current['last_sequence']),'active_sequence':None if current['active_sequence'] is None else str(current['active_sequence']),'state':current['state'],'retirement':None if current['retirement'] is None else json.loads(current['retirement']),'counts':counts,'attempt':projected}
result['remaining_local_holds']=local_holds(journal)
print(json.dumps(result))
"""
        return json.loads(
            self.helper(
                "-I",
                "-c",
                source,
                python=True,
                stdin=canonical(
                    {
                        "runtime_id": admission["runtime_id"],
                        "admission_sha256": admission["admission_sha256"],
                        "number": number,
                    }
                ),
            )
        )

    @staticmethod
    def verify_persistent_local(value, admission, number, *, retired=False):
        require(
            value["runtime_id"] == admission["runtime_id"]
            and value["runtime_sha256"] == admission["runtime_sha256"]
            and value["admission_sha256"] == admission["admission_sha256"]
            and value["last_sequence"] == str(number)
            and value["active_sequence"] is None
            and value["state"] == ("retired" if retired else "idle")
            and type(value["remaining_local_holds"]) is int
            and value["remaining_local_holds"] == 0
            and value["counts"]
            == dict.fromkeys(("runs", "claims", "contracts", "results"), number)
            and all(type(count) is int for count in value["counts"].values()),
            "persistent_original_journal_not_closed",
        )
        if number == 0:
            require(value["attempt"] is None, "persistent_idle_not_empty")
        else:
            attempt = value["attempt"]
            require(
                attempt["phase"] == "done"
                and attempt["pid"] is None
                and attempt["state"]
                == ("physical_retirement_observed" if retired else "released")
                and (not retired or attempt["retired_from_state"] == "released")
                and attempt["claim_state"] == "persistent_released"
                and type(attempt["consumption_sent"])
                is type(attempt["consumption_acknowledged"])
                is int
                and attempt["consumption_sent"]
                == attempt["consumption_acknowledged"]
                == 1,
                "persistent_original_ack_not_closed",
            )

    @staticmethod
    def verify_empty_worker_state(value, admission):
        expected = {
            "schema": "vardr.worker-state-audit/1", "status": "empty_unissued",
            "reason": None, "complete": True,
            "binding": {key: admission[key] for key in (
                "runner_id", "runtime_id", "runtime_sha256", "admission_sha256")},
            "parent": {"state": "idle", "last_sequence": "0",
                       "head_sequence": None, "active_sequence": None},
            "counts": {"attempts": 0, "selections": 0,
                       "associated_runs": 0, "associated_claims": 0},
            "global_holds": 0, "retirement_receipt_sha256": None,
        }
        require(canonical(value) == canonical(expected), "empty_local_state_not_proven")
        return value

    def empty_audit_volume(self, admission):
        import worker_volumes

        endpoint = json.loads(self.docker("context", "inspect", self.m["docker_context"],
                                         "--format", "{{json .Endpoints.docker.Host}}"))
        daemon = json.loads(self.docker("info", "--format", "{{json .ID}}"))
        root = worker_volumes.daemon_root(self.docker(
            "info", "--format", worker_volumes.DAEMON_FORMAT).decode("utf-8"))
        name = self.project + "_runner-state"
        template = ('{"name":{{json .Name}},"driver":{{json .Driver}},'
                    '"scope":{{json .Scope}},"options":{{json .Options}},'
                    '"source":{{json .Mountpoint}},"created_at":{{json .CreatedAt}},'
                    '"project":{{json (index .Labels "com.docker.compose.project")}},'
                    '"volume":{{json (index .Labels "com.docker.compose.volume")}}}')
        value = worker_volumes.parse_document(self.docker(
            "volume", "inspect", "--format", template, name).decode("utf-8"))
        reason = "empty_audit_volume_not_bound"
        require(type(endpoint) is str and endpoint.startswith(("unix:///", "npipe:////"))
                and daemon == admission["identity"]["daemon_id"], reason)
        require(set(value) == {"name", "driver", "scope", "options", "source",
                               "created_at", "project", "volume"}
                and value["name"] == name and value["driver"] == value["scope"] == "local"
                and value["options"] in (None, {}) and value["project"] == self.project
                and value["volume"] == "runner-state"
                and worker_volumes._path(value["source"])
                == worker_volumes._path(root) / "volumes" / name / "_data"
                and type(value["created_at"]) is str and 1 <= len(value["created_at"]) <= 64,
                reason)
        require(datetime.fromisoformat(value["created_at"].replace("Z", "+00:00")).tzinfo is not None,
                reason)
        return {"daemon_id": daemon, "endpoint": endpoint, "root": root, **value}

    def worker_state(self, admission):
        # Component-owned offline inspection. The root filesystem is read-only;
        # this one exact state volume permits ordinary SQLite WAL sidecars.
        args = ["run", "--rm", "--pull", "never", "--user", "10001:10001",
                "--read-only", "--network", "none", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true", "--label",
                "com.docker.compose.project=" + self.project,
                "--pids-limit", "64", "--memory", "512m", "--cpus", "1", "--mount",
                "type=volume,source=" + self.project + "_runner-state,target=/home/runner/.vardrmap",
                "--env", "HOME=/home/runner", "--env", "PYTHONDONTWRITEBYTECODE=1",
                "--entrypoint", "vardrrunner", self.images["worker"], "worker-state",
                "--journal", "/home/runner/.vardrmap/runner-journal.sqlite3",
                "--identity", "/home/runner/.vardrmap/runner-identity.json"]
        for key in ("runner_id", "runtime_id", "runtime_sha256", "admission_sha256"):
            args.extend(["--" + key.replace("_", "-"), admission[key]])
        before = self.empty_audit_volume(admission)  # Absence refuses before run.
        value = json.loads(self.docker(*args, timeout=45))
        after = self.empty_audit_volume(admission)
        require(canonical(before) == canonical(after), "empty_audit_volume_changed")
        self.empty_audit_volumes.append({"before": before, "after": after})
        return value

    def empty_worker_state(self, admission):
        return self.verify_empty_worker_state(self.worker_state(admission), admission)

    def empty_engagements(self):
        value = self.api.request("/engagements")
        require(canonical(value) == canonical({"engagements": [], "programs": []}),
                "empty_map_inventory_not_empty")
        return value

    def persistent_empty_stop(self):
        self.receipt["stage"] = "empty_stop_setup"
        engagements_before, traffic_before = self.empty_engagements(), self.traffic()
        require(traffic_before == [], "empty_target_traffic_not_empty")
        binding = self.enroll_runner()
        self.empty_audit_volumes = []
        proof = {"engagements_before": engagements_before, "traffic_before": traffic_before}

        def on_running(admission):
            proof["admission"] = admission
            self.receipt["stage"] = "empty_stop_ready"
            proof["status"] = self.persistent_idle(admission, 0)
            proof["status_observed_at"] = datetime.now(timezone.utc).isoformat(
                timespec="microseconds").replace("+00:00", "Z")
            proof["audit_before"] = self.verify_empty_worker_state(self.empty_worker_state(admission), admission)
            self.receipt["stage"] = "empty_operator_stop"
            self.operator_stop = self.worker_action("stop", admission["runtime_id"])
            require(self.operator_stop["schema"] == "vardr.worker-cli/1"
                    and self.operator_stop["state"] == "stopped_observed"
                    and self.operator_stop["runtime_id"] == admission["runtime_id"]
                    and self.operator_stop["new_work_disable_state"] == "acknowledged",
                    "empty_operator_stop_not_proven")
            proof["operator_stop"] = self.operator_stop

        physical = self.worker(*binding, on_running=on_running)
        admission = proof["admission"]
        require(physical["identity"] == admission["identity"]
                and all(physical[key] == self.operator_stop[key] for key in (
                    "runtime_id", "exit_code", "finished_at", "identity"))
                and physical["operator_stop_state"] == "stopped_observed",
                "empty_physical_stop_not_bound")
        self.receipt["stage"] = "empty_stop_reconciliation"
        proof["retirement"] = self.report_exit(physical)
        retirement = proof["retirement"]
        require(retirement["last_sequence"] == "0" and retirement["runtime_sequence"] is None
                and retirement["binding"] is None and retirement["attempt_receipt"] is None
                and retirement["retired"] is True, "empty_retirement_not_unbound")
        proof["host_reconciled"] = self.worker_action("reconcile", physical["runtime_id"], timeout=120)
        require(proof["host_reconciled"]["state"] == "terminal_observed"
                and canonical(proof["host_reconciled"]["receipt"]["retirement"]) == canonical(retirement),
                "empty_host_receipt_changed")
        proof["audit_after"] = self.verify_empty_worker_state(self.empty_worker_state(admission), admission)
        proof["audit_volumes"] = self.empty_audit_volumes
        require(len(proof["audit_volumes"]) == 2
                and all(canonical(row["before"]) == canonical(proof["audit_volumes"][0]["before"])
                        and canonical(row["after"]) == canonical(row["before"])
                        for row in proof["audit_volumes"]), "empty_audit_volume_changed")
        proof["engagements_after"], proof["traffic_after"] = self.empty_engagements(), self.traffic()
        require(proof["traffic_after"] == [], "empty_target_traffic_not_empty")
        self.receipt["cases"]["persistent_empty_stop"] = {
            "status": "passed", "limits": persistent_limits(EMPTY_SCENARIO),
            "physical": physical, "proof": proof,
        }
        self.receipt["status"], self.receipt["stage"] = (
            "selected_empty_stop_slice_passed", "selected_empty_stop_complete")

    def persistent_idle_limit(self, zero):
        require(type(zero) is list and not zero, "idle_baseline_not_empty")
        self.receipt["stage"] = "idle_control_setup"
        engagement, authorization, job, case = self.new_job("idle-control", marker=True)
        original, context, authority = {}, {}, {}
        binding = self.approve(
            "idle-control", engagement, authorization, job, case,
            review_snapshot=original, review_context=context, review_authority=authority,
        )
        before = self.inventory(engagement, job)
        count_approval_context(before, context)
        require(self.traffic() == zero, "idle_baseline_not_empty")
        observed = {}

        def on_running(admission):
            observed["admission"] = json.loads(canonical(admission))
            self.receipt["stage"] = "idle_control_release"
            until = time.monotonic() + 45
            while True:
                current = next(row for row in self.api.request(
                    f"/engagements/{engagement}/jobs")["jobs"] if row["id"] == job)
                if current["status"] == "done":
                    break
                require(current["status"] in {"pending", "running"}
                        and time.monotonic() < until, "idle_job_not_completed")
                time.sleep(0.2)
            local = self.persistent_metadata(admission, 1)
            self.verify_persistent_local(local, admission, 1)
            local["grants"] = self.grant_snapshot(engagement)
            observed["local"] = local
            observed["inventory_before_idle"] = self.inventory(engagement, job)
            observed["traffic_before_idle"] = self.traffic()
            require(len(observed["traffic_before_idle"]) == 5,
                    "idle_complete_traffic_changed")
            self.receipt["stage"] = "idle_control_observation"
            entered = time.monotonic()
            until = entered + 75  # Host observation only; native limit remains60.
            first = self.worker_action("status", admission["runtime_id"],
                timeout=max(0.001, until - time.monotonic()), expected_admission=admission)
            require(first["state"] == "idle-ready", "idle_initial_readiness_missing")
            observed["status_before_idle"] = first
            while True:
                remaining = until - time.monotonic()
                require(remaining > 0, "idle_native_exit_not_observed")
                time.sleep(min(1, remaining))
                remaining = until - time.monotonic()
                require(remaining > 0, "idle_native_exit_not_observed")
                value = self.worker_action("status", admission["runtime_id"],
                    timeout=remaining, expected_admission=admission)
                if value["state"] == "stopped":
                    observed["status_after_idle"] = value
                    break
            observed["observation_seconds"] = time.monotonic() - entered
            require(0 < observed["observation_seconds"] <= 75,
                    "idle_observation_budget_changed")
            self.receipt["stage"] = "idle_control_unchanged"
            observed["after_idle"] = self.persistent_metadata(admission, 1)
            observed["inventory_after_idle"] = self.inventory(engagement, job)
            observed["traffic_after_idle"] = self.traffic()
            self.verify_persistent_local(observed["after_idle"], admission, 1)
            require(canonical(observed["after_idle"]) == canonical(
                {k: v for k, v in local.items() if k != "grants"})
                and canonical(observed["inventory_after_idle"])
                == canonical(observed["inventory_before_idle"])
                and canonical(observed["traffic_after_idle"])
                == canonical(observed["traffic_before_idle"]),
                "idle_executed_or_changed_work")

        physical = self.worker(*binding, on_running=on_running)
        stopped = observed["status_after_idle"]
        require(type(physical["exit_code"]) is int and physical["exit_code"] == 124
                and physical["operator_stop_state"] == "not_requested"
                and physical["identity"] == observed["admission"]["identity"]
                and all(physical[k] == stopped[k] for k in ("exit_code", "finished_at")),
                "idle_native_exit_not_proven")
        self.receipt["stage"] = "idle_control_reconciliation"
        retirement = self.report_exit(physical)
        host = self.worker_action("reconcile", physical["runtime_id"], timeout=120)
        require(host["state"] == "terminal_observed"
                and canonical(host["receipt"]["retirement"]) == canonical(retirement),
                "idle_host_receipt_changed")
        reconciled = json.loads(self.helper("audit", "reconcile-managed",
            observed["local"]["attempt"]["run_id"]))
        require(type(reconciled["state"]) is str
                and reconciled["state"].startswith("terminal_")
                and type(reconciled["remaining_local_holds"]) is int
                and reconciled["remaining_local_holds"] == 0,
                "idle_original_reconciliation_held")
        retained = self.persistent_metadata(observed["admission"], 1)
        self.verify_persistent_local(retained, observed["admission"], 1, retired=True)
        inventory, traffic = self.inventory(engagement, job), self.traffic()
        require(canonical(traffic) == canonical(observed["traffic_after_idle"]),
                "idle_complete_traffic_changed")
        fixed, measured = self.verify_fixed(engagement, job, case, physical, before,
            traffic, inventory, persistent=True, self_exit=True)
        proof = dict(observed, fixed=fixed, measured=measured, inventory=inventory,
            retirement=retirement, retained=retained, reconciled=reconciled,
            selection={"engagement_id": engagement, "job_id": job,
                "case_spec": case["spec"], "review_input": original,
                "review_context": context, "review_authority": authority})
        self.receipt["cases"]["persistent_idle_limit"] = {
            "status": "passed", "limits": persistent_limits(IDLE_SCENARIO),
            "physical": physical, "proof": proof,
        }
        self.receipt["status"], self.receipt["stage"] = (
            "selected_idle_control_slice_passed", "selected_idle_control_complete")


    def persistent_count_limit(self, zero):
        require(type(zero) is list and not zero, "count_baseline_not_empty")
        self.receipt["stage"] = "count_control_setup"
        selections = []
        for name in ("count-a", "count-b"):
            engagement, authorization, job, case = self.new_job(name, marker=True)
            review_input, review_context, review_authority = {}, {}, {}
            binding = self.approve(
                name,
                engagement,
                authorization,
                job,
                case,
                review_snapshot=review_input,
                review_context=review_context,
                review_authority=review_authority,
            )
            selections.append(
                (
                    engagement,
                    job,
                    case,
                    binding,
                    review_input,
                    review_context,
                    review_authority,
                )
            )
        selections.sort(key=lambda row: row[1])  # Existing discovery order.
        first, second = selections
        require(first[3] == second[3], "count_enrollment_changed")
        before = self.inventory(*first[:2])
        pending_before = json.loads(canonical(self.inventory(*second[:2])))
        baseline = self.traffic()
        require(type(baseline) is list and not baseline, "count_baseline_not_empty")
        originals = json.loads(
            canonical(
                [
                    {
                        "engagement_id": row[0],
                        "job_id": row[1],
                        "case_spec": row[2]["spec"],
                        "review_input": row[4],
                        "review_context": row[5],
                        "review_authority": row[6],
                    }
                    for row in selections
                ]
            )
        )
        count_approval_context(before, originals[0]["review_context"])
        count_approval_context(pending_before, originals[1]["review_context"])
        observed = {}

        def on_running(admission):
            observed["admission"] = json.loads(canonical(admission))
            self.receipt["stage"] = "count_control_release"
            until = time.monotonic() + 45
            while True:
                rows = self.api.request(f"/engagements/{first[0]}/jobs")["jobs"]
                job = next(row for row in rows if row["id"] == first[1])
                if job["status"] == "done":
                    break
                require(
                    job["status"] in {"pending", "running"}
                    and time.monotonic() < until,
                    "count_job_not_completed",
                )
                time.sleep(0.2)

        physical = self.worker(*first[3], on_running=on_running)
        require(
            type(physical["exit_code"]) is int
            and physical["exit_code"] == 0
            and physical["operator_stop_state"] == "not_requested",
            "count_self_exit_not_proven",
        )
        # Map completion precedes native DONE and the durable release ACK.
        self.receipt["stage"] = "count_control_local_release"
        observed["local"] = self.persistent_metadata(observed["admission"], 1)
        self.verify_persistent_local(observed["local"], observed["admission"], 1)
        observed["local"]["grants"] = self.grant_snapshot(first[0])
        # Same original unsigned review, no new approval/register/grant operation.
        self.receipt["stage"] = "count_control_eligibility"
        eligibility = self.api.request(
            f"/jobs/{second[1]}/managed/approval/review", second[4]
        )
        eligibility["original_context"] = second[5]
        eligibility["observed_at"] = (
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        )
        grants = self.grant_snapshot(second[0])
        self.receipt["stage"] = "count_control_reconciliation"
        retirement = self.report_exit(physical)
        host = self.worker_action("reconcile", physical["runtime_id"], timeout=120)
        require(
            host["state"] == "terminal_observed"
            and canonical(host["receipt"]["retirement"]) == canonical(retirement),
            "count_host_receipt_changed",
        )
        local = observed["local"]
        reconciled = json.loads(
            self.helper("audit", "reconcile-managed", local["attempt"]["run_id"])
        )
        require(
            type(reconciled["state"]) is str
            and reconciled["state"].startswith("terminal_")
            and type(reconciled["remaining_local_holds"]) is int
            and reconciled["remaining_local_holds"] == 0,
            "count_original_reconciliation_held",
        )
        retained = self.persistent_metadata(observed["admission"], 1)
        inventories = [self.inventory(*row[:2]) for row in selections]
        traffic = self.traffic()
        require(
            type(traffic) is list and len(traffic) == 5,
            "count_complete_traffic_changed",
        )
        fixed, measured = self.verify_fixed(
            *first[:3],
            physical,
            before,
            traffic,
            inventories[0],
            persistent=True,
            self_exit=True,
        )
        require(
            canonical(traffic) == canonical(measured["requests"]),
            "count_complete_traffic_changed",
        )
        self.receipt["stage"] = "count_control_verification"
        summary = self.verify_count_limit(
            physical,
            observed["admission"],
            measured,
            inventories,
            local,
            retirement,
            retained,
            eligibility,
            grants,
            [row["review_context"] for row in originals],
        )
        summary["proof"] = dict(
            admission=observed["admission"],
            selections=originals,
            pending_before=pending_before,
            traffic={"before": baseline, "after": traffic},
            fixed=fixed,
            measured=measured,
            inventories=inventories,
            local=local,
            retirement=retirement,
            retained=retained,
            eligibility=eligibility,
            grants=grants,
        )
        self.receipt["cases"]["persistent_count_limit"] = summary
        self.receipt["status"], self.receipt["stage"] = (
            "selected_count_control_slice_passed",
            "selected_count_control_complete",
        )

    def verify_count_limit(
        self,
        physical,
        admission,
        measured,
        inventories,
        local,
        retirement,
        retained,
        eligibility,
        grants,
        original_contexts,
    ):
        from worker_host_persistent import (
            _purpose,
            admission as checked_admission,
            retirement as checked_retirement,
        )

        from worker_runtime import _timestamp as physical_time

        record = {
            "runtime_id": admission["runtime_id"],
            "registration": {
                k: v
                for k, v in admission.items()
                if k
                not in {"schema", "runtime_id", "runtime_sha256", "admission_sha256"}
            },
        }
        try:
            checked_admission(record, admission)
            checked_retirement(record, retirement)
        except ValueError:
            raise AcceptanceRefused("count_incarnation_or_policy_changed") from None

        def moment(value):
            return datetime.fromisoformat(value.replace("Z", "+00:00"))

        def grants_live(snapshot, engagement, start, end):
            entries = snapshot["grants"]
            fields = {
                "issuer",
                "engagement_id",
                "origin",
                "source",
                "name",
                "id",
                "issued_at",
                "expires_at",
                "status",
            }
            names = {"FIXTURE_OWNER_TOKEN", "FIXTURE_PEER_TOKEN"}
            try:
                return (
                    snapshot["policy_reason"] == "granted"
                    and type(entries) is list
                    and len(entries) == 2
                    and all(type(g) is dict and set(g) == fields for g in entries)
                    and len({g["id"] for g in entries}) == 2
                    and {g["name"] for g in entries} == names
                    and all(
                        type(g["id"]) is str
                        and str(uuid.UUID(g["id"])) == g["id"]
                        and g["issuer"] == admission["origin"]
                        and g["engagement_id"] == engagement
                        and g["origin"] == ORIGIN
                        and g["source"] == "env"
                        and g["status"] == "active"
                        and moment(g["issued_at"]) <= start
                        and moment(g["expires_at"]) > end
                        for g in entries
                    )
                )
            except (KeyError, ValueError, TypeError, AttributeError):
                return False

        def references_live(references, end):
            fields = {"identity_id", "source", "name", "revision", "expires_at"}
            return (
                type(references) is list
                and len(references) == 2
                and all(type(g) is dict and set(g) == fields for g in references)
                and {g["identity_id"] for g in references} == {"owner", "peer"}
                and all(
                    g["source"] == "value_env"
                    and g["name"] == "FIXTURE_" + g["identity_id"].upper() + "_TOKEN"
                    and type(g["revision"]) is int
                    and g["revision"] == 1
                    and moment(g["expires_at"]) > end
                    for g in references
                )
            )

        def approval_live(approval, issued, start, end):
            expected = dict(
                issued=issued, revoked=False, max_executions=1, max_duration_seconds=30
            )
            return (
                canonical({k: approval[k] for k in expected}) == canonical(expected)
                and moment(approval["approved_at"]) <= start
                and moment(approval["expires_at"]) > end
                and references_live(approval["credential_grants"], end)
            )

        require(
            len(inventories) == 2 and len(inventories[0]["runtimes"]) == 1,
            "count_history_changed",
        )
        require(
            type(original_contexts) is list and len(original_contexts) == 2,
            "count_registered_context_changed",
        )
        for inventory, context in zip(inventories, original_contexts, strict=True):
            count_approval_context(inventory, context)
        issued, pending = inventories
        runtime = issued["runtimes"][0]
        require(
            type(physical["exit_code"]) is int
            and physical["exit_code"] == 0
            and physical["operator_stop_state"] == "not_requested"
            and canonical(physical["identity"]) == canonical(admission["identity"])
            and admission["mode"] == runtime["mode"] == "persistent"
            and admission["limits"] == persistent_limits(COUNT_SCENARIO)
            and canonical(runtime["admission"]) == canonical(admission)
            and all(
                physical[k] == admission[k] == runtime["id" if k == "runtime_id" else k]
                for k in ("runtime_id", "runtime_sha256", "admission_sha256")
            )
            and type(runtime["max_attempts"]) is int
            and runtime["max_attempts"] == 1
            and runtime["last_sequence"] == runtime["head_sequence"] == "1"
            and runtime["active_sequence"] is None
            and runtime["retired"] is True
            and runtime["new_work_disabled"] is True
            and runtime["reporting_revoked"] is False
            and all(v is None for v in runtime["legacy_binding"].values()),
            "count_incarnation_or_policy_changed",
        )
        require(len(runtime["attempts"]) == 1, "count_history_changed")
        attempt = runtime["attempts"][0]
        bound, released = moment(attempt["bound_at"]), moment(attempt["released_at"])
        require(
            bound <= moment(attempt["confirmed_at"]) <= released
            and len(issued["approvals"]) == 1
            and approval_live(issued["approvals"][0], 1, bound, released)
            and grants_live(
                local["grants"], measured["engagement_id"], bound, released
            ),
            "count_first_authority_not_fresh",
        )
        self.verify_persistent_local(local, admission, 1)
        self.verify_persistent_local(retained, admission, 1, retired=True)
        require(
            attempt["runtime_sequence"] == "1"
            and attempt["previous_sequence"] is None
            and attempt["runtime_mode"] == "persistent"
            and attempt["job_id"] == measured["job_id"]
            and canonical(attempt["binding"]) == canonical(measured["binding"])
            and canonical(attempt["terminal_receipt"])
            == canonical(local["attempt"]["completion"])
            == canonical(measured["terminal_receipt"])
            and canonical(attempt["release_receipt"])
            == canonical(local["attempt"]["release"])
            == canonical(measured["release_receipt"])
            and local["attempt"]["job_id"] == measured["job_id"]
            and local["attempt"]["artifact_sha256"] == measured["artifact_sha256"]
            and local["attempt"]["native_done_sha256"]
            == attempt["native_done_sha256"]
            == measured["native_done_sha256"]
            and measured["terminal_receipt_sha256"]
            == attempt["terminal_receipt_sha256"]
            == digest(canonical(attempt["terminal_receipt"]))
            and canonical(retained["attempt"])
            == canonical(
                {
                    **local["attempt"],
                    "state": "physical_retirement_observed",
                    "retired_from_state": "released",
                }
            ),
            "count_original_receipt_changed",
        )
        require(
            type(measured["evidence_count"]) is int
            and measured["evidence_count"] == len(measured["requests"]) == 5
            and all(
                type(row["received_monotonic_ns"]) is int
                and row["received_monotonic_ns"] > 0
                for row in measured["requests"]
            )
            and type(issued["targets_spent"])
            is type(issued["duration_allocated"])
            is int
            and issued["targets_spent"] == 1
            and issued["duration_allocated"] == 30,
            "count_first_job_not_proven",
        )
        require(
            pending["job_id"] > measured["job_id"]
            and pending["engagement_id"] != measured["engagement_id"]
            and pending["job_status"] == "pending"
            and pending["execution"] is None
            and all(
                not pending[k] for k in ("contracts", "results", "stops", "runtimes")
            )
            and type(pending["targets_spent"])
            is type(pending["duration_allocated"])
            is int
            and pending["targets_spent"] == pending["duration_allocated"] == 0
            and len(pending["approvals"]) == 1,
            "count_second_job_was_issued",
        )
        approval, context = pending["approvals"][0], eligibility["context"]
        instant = moment(eligibility["observed_at"])
        original = eligibility["original_context"]
        snapshot = eligibility["authority_snapshot"]
        require(
            type(context) is type(original) is dict
            and canonical({k: v for k, v in context.items() if k != "not_before"})
            == canonical({k: v for k, v in original.items() if k != "not_before"})
            and moment(original["not_before"])
            <= moment(context["not_before"])
            <= instant
            and snapshot["origin"] == admission["origin"]
            and snapshot["enrollment"]["id"] == admission["enrollment_id"]
            and snapshot["enrollment"]["runner_id"] == admission["runner_id"]
            and context["authority_sha256"] == digest(canonical(snapshot))
            and type(context["authority_revision"]) is int
            and context["authority_revision"] >= 0
            and type(context["plan_sha256"]) is str
            and re.fullmatch(r"[a-f0-9]{64}", context["plan_sha256"])
            and context["mode"] == "strict"
            and context["control"] == "managed_online"
            and context["exceptions"] == []
            and type(context["scope"]) is list
            and context["scope"]
            and all(
                row["origin"] == ORIGIN
                and row["method"] == "GET"
                and row["excluded"] is False
                for row in context["scope"]
            )
            and canonical(context["credential_grants"])
            == canonical(approval["credential_grants"]),
            "count_second_job_not_eligible",
        )
        require(
            physical_time(attempt["released_at"])
            <= physical_time(physical["finished_at"])
            <= physical_time(eligibility["observed_at"])
            and context["job_id"] == pending["job_id"]
            and context["engagement_id"] == pending["engagement_id"]
            and context["runner_id"] == admission["runner_id"]
            and context["expires_at"] == approval["expires_at"]
            and type(context["max_executions"])
            is type(context["max_duration_seconds"])
            is int
            and context["max_executions"] == 1
            and context["max_duration_seconds"] == 30
            and canonical(eligibility["authority_snapshot"]["limits"])
            == canonical({"concurrency": 1, "targets": 5, "duration": 120})
            and approval_live(approval, 0, instant, instant)
            and grants_live(grants, pending["engagement_id"], instant, instant),
            "count_second_job_not_eligible",
        )
        report_sha = _purpose(
            {"runtime_id": physical["runtime_id"]},
            {
                **{
                    k: physical[k]
                    for k in (
                        "runtime_sha256",
                        "admission_sha256",
                        "finished_at",
                        "exit_code",
                    )
                },
                "observation_sha256": digest(
                    canonical(
                        {
                            k: physical[k]
                            for k in ("identity", "finished_at", "exit_code")
                        }
                    )
                ),
                "last_sequence": "1",
            },
        )
        require(
            runtime["report_sha256"] == report_sha
            and retirement["report_sha256"] == report_sha
            and retirement["last_sequence"] == "1"
            and retirement["runtime_sequence"] is None
            and canonical(retained["retirement"]) == canonical(retirement),
            "count_retirement_changed",
        )
        return dict(
            status="passed",
            limits=admission["limits"],
            physical=physical,
            issued_job_id=measured["job_id"],
            unissued_job_id=pending["job_id"],
            issued_attempts=1,
            unissued_target_charge=0,
            unissued_duration_charge=0,
            target_request_count=5,
            evidence_count=5,
            remaining_local_holds=0,
        )

    def persistent_availability(self, denied_engagement, denied_job, zero):
        runner_id, enrollment_id = self.runner_binding
        selections, before_jobs, local, idle = [], [], [], {}

        def on_running(admission):
            self.receipt["stage"] = "persistent_idle"
            self.persistent_idle(admission, 0)
            initial = self.persistent_metadata(admission, 0)
            self.verify_persistent_local(initial, admission, 0)
            entered = time.monotonic()
            while time.monotonic() - entered < 70:
                time.sleep(max(0.0, min(1, 70 - (time.monotonic() - entered))))
            elapsed = time.monotonic() - entered
            status = self.persistent_idle(admission, 0)
            after = self.persistent_metadata(admission, 0)
            self.verify_persistent_local(after, admission, 0)
            denied = self.inventory(denied_engagement, denied_job)
            require(
                elapsed >= 70
                and self.traffic() == zero
                and denied["execution"] is None
                and not denied["contracts"]
                and denied["targets_spent"] == denied["duration_allocated"] == 0,
                "persistent_idle_executed_work",
            )
            idle.update(
                seconds=elapsed,
                before=initial,
                after=after,
                status=status,
                target_request_count=0,
            )
            for number in range(1, 36):
                self.receipt["stage"] = "persistent_job_approval"
                name = "persistent-" + str(number).zfill(2)
                engagement, authorization, job, case = self.new_job(name, marker=True)
                before = self.inventory(engagement, job)
                require(
                    before["job_status"] == "pending"
                    and before["execution"] is None
                    and not before["approvals"]
                    and not before["contracts"]
                    and not before["results"]
                    and before["targets_spent"] == before["duration_allocated"] == 0,
                    "persistent_unapproved_job_executed",
                )
                before_jobs.append(before)
                require(
                    self.approve(name, engagement, authorization, job, case)
                    == (runner_id, enrollment_id),
                    "persistent_enrollment_changed",
                )
                selections.append((engagement, job, case))
                self.receipt["stage"] = "persistent_job_release"
                self.persistent_idle(admission, number)
                metadata = self.persistent_metadata(admission, number)
                self.verify_persistent_local(metadata, admission, number)
                require(
                    metadata["attempt"]["job_id"] == job, "persistent_local_job_changed"
                )
                metadata["grants"] = self.grant_snapshot(engagement)
                local.append(metadata)
            self.receipt["stage"] = "persistent_operator_stop"
            self.operator_stop = self.worker_action("stop", admission["runtime_id"])
            require(
                self.operator_stop["schema"] == "vardr.worker-cli/1"
                and self.operator_stop["state"] == "stopped_observed"
                and self.operator_stop["runtime_id"] == admission["runtime_id"]
                and self.operator_stop["new_work_disable_state"] == "acknowledged",
                "persistent_operator_stop_not_proven",
            )
            idle["admission"] = admission

        physical = self.worker(runner_id, enrollment_id, on_running=on_running)
        self.receipt["stage"] = "persistent_receipt_reconciliation"
        retirement = self.report_exit(physical)
        host = self.worker_action("reconcile", physical["runtime_id"], timeout=120)
        require(
            host["state"] == "terminal_observed"
            and canonical(host["receipt"]["retirement"]) == canonical(retirement),
            "persistent_host_receipt_changed",
        )
        reconciled = json.loads(
            self.helper("audit", "reconcile-managed", local[-1]["attempt"]["run_id"])
        )
        require(
            type(reconciled["state"]) is str
            and reconciled["state"].startswith("terminal_")
            and reconciled["remaining_local_holds"] == 0,
            "persistent_original_reconciliation_held",
        )
        retained = self.persistent_metadata(idle["admission"], 35)
        self.verify_persistent_local(retained, idle["admission"], 35, retired=True)
        require(
            canonical(retained["retirement"]) == canonical(retirement)
            and all(
                retained["attempt"][key] == local[-1]["attempt"][key]
                for key in (
                    "run_id",
                    "job_id",
                    "phase",
                    "pid",
                    "artifact_sha256",
                    "claim_state",
                    "consumption_sent",
                    "consumption_acknowledged",
                    "native_done_sha256",
                    "completion",
                    "release",
                )
            ),
            "persistent_retirement_rewrote_job",
        )
        inventories = [
            self.inventory(engagement, job) for engagement, job, _ in selections
        ]
        observed = self.traffic()[len(zero) :]
        require(len(observed) == 175, "persistent_total_traffic_mismatch")
        measured = []
        for index, ((engagement, job, case), inventory) in enumerate(
            zip(selections, inventories)
        ):
            marker = parse_qs(urlsplit(case["spec"]["request"]["url"]).query)[
                "nm2_case"
            ]
            requests = [
                row
                for row in observed
                if parse_qs(urlsplit(row["path"]).query).get("nm2_case") == marker
            ]
            _, proof = self.verify_fixed(
                engagement,
                job,
                case,
                physical,
                before_jobs[index],
                requests,
                inventory,
                persistent=True,
            )
            proof["local"] = local[index]
            measured.append(proof)
        self.receipt["stage"] = "persistent_availability_verification"
        self.receipt["cases"]["persistent_availability"] = (
            self.verify_persistent_sequence(
                physical, idle, measured, inventories, retirement, retained
            )
        )
        self.receipt["status"], self.receipt["stage"] = (
            "selected_availability_slice_passed",
            "selected_availability_complete",
        )

    def verify_persistent_sequence(
        self, physical, idle, measured, inventories, retirement, retained
    ):
        require(
            type(idle["seconds"]) in {int, float}
            and idle["seconds"] >= 70
            and idle["target_request_count"] == 0
            and len(measured) == len(inventories) == 35,
            "persistent_availability_measurement_missing",
        )
        admission = idle["admission"]
        self.verify_persistent_local(idle["before"], admission, 0)
        self.verify_persistent_local(idle["after"], admission, 0)
        self.verify_persistent_local(retained, admission, 35, retired=True)
        runtime = inventories[0]["runtimes"][0]
        require(
            all(
                len(value["runtimes"]) == 1
                and canonical(value["runtimes"][0]) == canonical(runtime)
                for value in inventories
            )
            and runtime["id"] == physical["runtime_id"] == admission["runtime_id"]
            and runtime["identity"] == physical["identity"] == admission["identity"]
            and runtime["runtime_sha256"]
            == physical["runtime_sha256"]
            == admission["runtime_sha256"]
            == digest(canonical(physical["identity"]))
            and runtime["admission_sha256"]
            == physical["admission_sha256"]
            == admission["admission_sha256"]
            and canonical(runtime["admission"]) == canonical(admission)
            and admission["schema"] == "vardr.worker-admission/3"
            and admission["mode"] == runtime["mode"] == "persistent"
            and admission["admission_sha256"]
            == digest(
                canonical(
                    {
                        key: value
                        for key, value in admission.items()
                        if key != "admission_sha256"
                    }
                )
            )
            and admission["reporting_authority"]
            == {"purpose": "worker-stop-only", "expires_at": None}
            and admission["limits"]
            == {"max_attempts": None, "idle_timeout_seconds": None}
            and runtime["max_attempts"] is None
            and runtime["last_sequence"] == runtime["head_sequence"] == "35"
            and runtime["active_sequence"] is None
            and runtime["retired"] is True
            and runtime["new_work_disabled"] is True
            and runtime["reporting_revoked"] is False
            and all(value is None for value in runtime["legacy_binding"].values()),
            "persistent_incarnation_or_policy_changed",
        )
        require(
            len(runtime["attempts"]) == 35
            and [row["runtime_sequence"] for row in runtime["attempts"]]
            == [str(n) for n in range(1, 36)]
            and [row["previous_sequence"] for row in runtime["attempts"]]
            == [None] + [str(n) for n in range(1, 35)]
            and all(row["runtime_mode"] == "persistent" for row in runtime["attempts"])
            and [row["job_id"] for row in runtime["attempts"]]
            == [row["job_id"] for row in measured],
            "persistent_history_incomplete",
        )
        for key in (
            "job_id",
            "engagement_id",
            "case_sha256",
            "artifact_sha256",
            "result_receipt_sha256",
            "terminal_receipt_sha256",
            "release_receipt_sha256",
            "native_done_sha256",
        ):
            require(
                len({row[key] for row in measured}) == 35, "persistent_reused_" + key
            )
        markers = []
        previous_clock = None
        for row in measured:
            clocks = [request["received_monotonic_ns"] for request in row["requests"]]
            marker = parse_qs(urlsplit(row["requests"][0]["path"]).query).get(
                "nm2_case"
            )
            require(
                len(clocks) == 5
                and all(type(clock) is int and clock > 0 for clock in clocks)
                and (previous_clock is None or previous_clock <= min(clocks)),
                "persistent_observed_request_order_invalid",
            )
            require(
                type(marker) is list
                and len(marker) == 1
                and all(
                    parse_qs(urlsplit(request["path"]).query).get("nm2_case") == marker
                    for request in row["requests"]
                ),
                "persistent_request_marker_invalid",
            )
            markers.append(marker[0])
            previous_clock = max(clocks)
        require(len(set(markers)) == 35, "persistent_request_marker_reused")
        prior = None
        grant_ids = set()
        for number, (row, inventory) in enumerate(zip(measured, inventories), 1):
            self.verify_persistent_local(row["local"], admission, number)
            require(
                row["runtime_sequence"] == str(number)
                and row["evidence_count"] == len(row["requests"]) == 5
                and row["target_charge"] == 1
                and row["duration_seconds"] == 30
                and row["capacity_reserved"] is False
                and row["local"]["attempt"]["artifact_sha256"] == row["artifact_sha256"]
                and canonical(row["local"]["attempt"]["completion"])
                == canonical(row["terminal_receipt"])
                and canonical(row["local"]["attempt"]["release"])
                == canonical(row["release_receipt"])
                and row["local"]["attempt"]["native_done_sha256"]
                == row["native_done_sha256"],
                "persistent_job_or_local_ack_mismatch",
            )
            times = [
                datetime.fromisoformat(row[key].replace("Z", "+00:00"))
                for key in ("bound_at", "confirmed_at", "released_at")
            ]
            require(
                times[0] <= times[1] <= times[2]
                and (prior is None or prior <= times[0]),
                "persistent_release_after_next_binding",
            )
            prior = times[2]
            require(len(inventory["approvals"]) == 1, "persistent_approval_missing")
            approval = inventory["approvals"][0]
            require(
                approval["issued"] == 1
                and approval["revoked"] is False
                and approval["max_executions"] == 1
                and approval["max_duration_seconds"] == 30
                and len(approval["credential_grants"]) == 2
                and datetime.fromisoformat(
                    approval["approved_at"].replace("Z", "+00:00")
                )
                <= times[0]
                and datetime.fromisoformat(
                    approval["expires_at"].replace("Z", "+00:00")
                )
                > times[2]
                and all(
                    datetime.fromisoformat(g["expires_at"].replace("Z", "+00:00"))
                    > times[2]
                    for g in approval["credential_grants"]
                ),
                "persistent_approval_not_fresh",
            )
            grants = row["local"]["grants"]
            require(
                grants["policy_reason"] == "granted" and len(grants["grants"]) == 2,
                "persistent_local_grant_not_fresh",
            )
            for grant in grants["grants"]:
                require(
                    grant["id"] not in grant_ids
                    and grant["status"] == "active"
                    and grant["engagement_id"] == row["engagement_id"]
                    and datetime.fromisoformat(
                        grant["issued_at"].replace("Z", "+00:00")
                    )
                    <= times[0]
                    and datetime.fromisoformat(
                        grant["expires_at"].replace("Z", "+00:00")
                    )
                    > times[2],
                    "persistent_local_grant_not_fresh",
                )
                grant_ids.add(grant["id"])
        expected = {
            "schema": "vardr.worker-retirement/3",
            "runtime_id": physical["runtime_id"],
            "runtime_sha256": physical["runtime_sha256"],
            "admission_sha256": physical["admission_sha256"],
            **{key: admission[key] for key in ("origin", "runner_id", "enrollment_id")},
            "runtime_sequence": None,
            "last_sequence": "35",
            "binding": None,
            "attempt_receipt": None,
            "report_sha256": runtime["report_sha256"],
            "retired": True,
        }
        expected["receipt_sha256"] = digest(canonical(expected))
        require(
            canonical(retirement) == canonical(expected)
            and retained["retirement"] == retirement
            and re.fullmatch(r"[a-f0-9]{64}", runtime["report_sha256"] or "")
            is not None
            and all(
                retained["attempt"][key] == measured[-1]["local"]["attempt"][key]
                for key in (
                    "run_id",
                    "job_id",
                    "phase",
                    "pid",
                    "artifact_sha256",
                    "claim_state",
                    "consumption_sent",
                    "consumption_acknowledged",
                    "native_done_sha256",
                    "completion",
                    "release",
                )
            ),
            "persistent_retirement_receipt_changed",
        )
        require(
            sum(v["targets_spent"] for v in inventories) == 35
            and sum(v["duration_allocated"] for v in inventories) == 1050,
            "persistent_allowance_mismatch",
        )
        return {
            "status": "passed",
            "physical": physical,
            "idle_seconds": idle["seconds"],
            "idle_target_request_count": 0,
            "limits": admission["limits"],
            "admission_sha256": admission["admission_sha256"],
            "last_sequence": "35",
            "attempts": measured,
            "target_request_count": 175,
            "evidence_count": 175,
            "targets_spent": 35,
            "duration_allocated": 1050,
            "remaining_local_holds": 0,
            "retirement_receipt_sha256": retirement["receipt_sha256"],
            "runtime_acceptance_scope": "persistent_availability_only",
            "proof": {
                "idle": idle,
                "runtime": runtime,
                "inventories": [
                    {
                        key: value
                        for key, value in inventory.items()
                        if key != "runtimes"
                    }
                    for inventory in inventories
                ],
                "retirement": retirement,
                "retained": retained,
            },
        }

    def worker(self, runner_id, enrollment_id, *, on_running=None):
        import worker_runtime

        public = self.install / "worker-public"
        public.mkdir(mode=0o755)
        publish(public / "trust.json", canonical(self.trust), mode=0o444)
        self.environment.update(
            VARDRSEC_WORKER_IMAGE=self.images["worker"],
            VARDRSEC_WORKER_CREDENTIAL_FILE=str(self.private / "worker.env"),
            VARDRSEC_WORKER_PUBLIC_DIR=str(public),
            VARDRRUNNER_WORKER_CREDENTIAL_ENV="FIXTURE_OWNER_TOKEN,FIXTURE_PEER_TOKEN",
            VARDRRUNNER_WORKER_WAIT_SECONDS="10",
            VARDRRUNNER_WORKER_ADMISSION_WAIT_SECONDS="60",
        )
        self.compose(
            "--profile",
            "managed-worker",
            "up",
            "-d",
            "--no-build",
            "--pull",
            "never",
            "--no-deps",
            "managed-worker",
            worker=True,
        )
        container_id = (
            self.compose(
                "--profile",
                "managed-worker",
                "ps",
                "-aq",
                "managed-worker",
                worker=True,
            )
            .decode()
            .strip()
        )
        observer = worker_runtime.LocalDocker(
            self.m["docker_context"],
            worker_runtime.WorkerLayout(
                str(self.install / "trust"),
                str(public),
                self.project + "_runner-state",
                self.ready_volume,
            ),
            max_attempts=self.max_attempts,
            protocol=self.protocol,
        )
        entered = time.monotonic()
        while True:
            try:
                identity = observer.capture_running(
                    container_id=container_id,
                    image_id=self.images["worker"],
                    project=self.project,
                )
                break
            except worker_runtime.RuntimeRefused:
                require(
                    time.monotonic() - entered < 15,
                    "actual_owner_readiness_not_observed",
                )
                time.sleep(0.2)
        self.receipt["stage"] = "operator_worker_enable"
        enabled = json.loads(
            worker_cli_command(
                [
                    sys.executable,
                    str(self.install / "vardrsec.py"),
                    "worker",
                    "enable",
                    "--api-url",
                    self.url + "/backend",
                    "--ca",
                    str(self.install / "trust" / "root.crt"),
                    "--private-root",
                    str(self.private),
                    "--context",
                    self.m["docker_context"],
                    "--container-id",
                    container_id,
                    "--image-id",
                    self.images["worker"],
                    "--project",
                    self.project,
                    "--trust-source",
                    str(self.install / "trust"),
                    "--admission-source",
                    str(public),
                    "--state-volume",
                    self.project + "_runner-state",
                    "--readiness-volume",
                    self.ready_volume,
                    "--enrollment-id",
                    enrollment_id,
                    "--runner-id",
                    runner_id,
                    "--origin",
                    self.issuer_origin,
                    "--public-trust",
                    str(public / "trust.json"),
                    *(
                        persistent_enable_args(self.scenario)
                        if self.protocol == "persistent-v3"
                        else [
                            "--expires-in",
                            "900",
                            "--max-attempts",
                            str(self.max_attempts),
                            "--protocol",
                            "finite-v2",
                        ]
                    ),
                    "--username",
                    "operator",
                    "--password-stdin",
                ],
                cwd=self.install,
                env=self.environment,
                stdin=self.password + "\n",
                timeout=90,
            )
        )
        admission = json.loads((public / "admission.json").read_bytes())
        require(
            enabled["schema"] == "vardr.worker-cli/1"
            and enabled["state"] == "enabled"
            and enabled["identity"] == asdict(identity)
            and enabled["runtime_id"] == admission["runtime_id"]
            and enabled["runtime_sha256"] == admission["runtime_sha256"],
            "operator_enable_not_bound",
        )
        if self.protocol == "persistent-v3":
            require(
                admission["schema"] == "vardr.worker-admission/3"
                and admission["mode"] == "persistent"
                and admission["limits"] == persistent_limits(self.scenario)
                and admission["reporting_authority"]
                == {"purpose": "worker-stop-only", "expires_at": None}
                and admission["admission_sha256"]
                == digest(
                    canonical(
                        {k: v for k, v in admission.items() if k != "admission_sha256"}
                    )
                ),
                "operator_persistent_mode_not_bound",
            )
        else:
            require(
                admission["schema"] == "vardr.worker-admission/2"
                and type(admission["max_attempts"]) is int
                and admission["max_attempts"] == self.max_attempts,
                "operator_sequence_mode_not_bound",
            )
        if on_running is not None:
            on_running(admission)
        # Direct host observation of exact incarnation exit, never an exec or
        # a caller-generated JSON object passed off as physical proof.
        if self.protocol == "persistent-v3":
            self.receipt["stage"] = "persistent_exit_observation"
        proof = observer.observe_exit(identity)
        value = {
            "identity": asdict(identity),
            "runtime_id": admission["runtime_id"],
            "runtime_sha256": admission["runtime_sha256"],
            "exit_code": proof.exit_code,
            "finished_at": proof.finished_at,
            "operator_enable_state": enabled["state"],
        }
        if self.protocol == "persistent-v3" and self.scenario in {COUNT_SCENARIO, IDLE_SCENARIO}:
            value.update(
                admission_sha256=admission["admission_sha256"],
                operator_stop_state="not_requested",
            )
        elif self.protocol == "persistent-v3":
            self.receipt["stage"] = "persistent_exit_binding"
            require(
                self.operator_stop["identity"] == asdict(identity)
                and self.operator_stop["exit_code"] == proof.exit_code
                and self.operator_stop["finished_at"] == proof.finished_at,
                "persistent_stop_exit_changed",
            )
            value.update(
                admission_sha256=admission["admission_sha256"],
                operator_stop_state=self.operator_stop["state"],
            )
        return value

    def run(self):
        sys.path.insert(0, str(self.source))
        import worker_runtime

        # Validate the explicitly selected local endpoint before any container
        # creation. A caller's context name is not proof of local observation.
        observer = worker_runtime.LocalDocker(
            self.m["docker_context"],
            worker_runtime.WorkerLayout(
                str(self.install / "trust"),
                str(self.install / "worker-public"),
                self.project + "_runner-state",
                self.ready_volume,
            ),
            max_attempts=self.max_attempts,
            protocol=self.protocol,
        )
        self.receipt["daemon_id"] = observer.daemon()
        require(
            json.loads(self.docker("info", "--format", "{{json .OSType}}")) == "linux",
            "linux_container_engine_required",
        )
        self.receipt["docker_architecture"] = json.loads(
            self.docker("info", "--format", "{{json .Architecture}}")
        )
        before = self.snapshot()
        expected_volumes = {
            self.project + "_" + name
            for name in ("database", "proxy-data", "proxy-config", "runner-state")
        } | {self.ready_volume}
        require(
            not expected_volumes.intersection(before["volumes"]),
            "fixture_volume_name_exists",
        )
        expected_networks = {
            self.project + "_" + name for name in ("database", "application", "runner")
        }
        require(
            not expected_networks.intersection(
                {row["name"] for row in before["networks"].values()}
            ),
            "fixture_network_name_exists",
        )
        require(
            not any(
                row.get("labels", {}).get("com.docker.compose.project") == self.project
                for kind in ("containers", "networks", "volumes")
                for row in before[kind].values()
            ),
            "fixture_project_exists",
        )
        for image in self.images.values():
            require(image in before["images"], "reviewed_local_image_missing")
        self.receipt["before_sha256"] = digest(canonical(before))
        try:
            self.receipt["stage"] = "image_sources"
            self.receipt["image_sources"] = self.image_sources()
            self.receipt["stage"] = "core_setup"
            self.stage()
            publish(self.install / "nm2-inventory-before.json", canonical(before))
            self.receipt["stage"] = "default_disabled"
            OwnerAPI(self.url, self.install / "trust" / "root.crt").request(
                "/engagements", expected=401
            )
            self.api.request("/jobs/managed/pending", {}, expected=404)
            services = self.compose("ps", "--all", "--services").decode().split()
            require(
                set(services) == {"db", "api", "web", "proxy"}, "default_started_worker"
            )
            original_engagements = self.api.request("/engagements")
            self.api.request(
                "/engagements", {"name": "CSRF must refuse"}, csrf=False, expected=403
            )
            require(
                self.api.request("/engagements") == original_engagements,
                "csrf_denial_mutated_state",
            )
            self.receipt["cases"]["default_disabled"] = {
                "status": "passed",
                "services": sorted(services),
                "managed_pending_status": 404,
                "csrf_write_status": 403,
                "unauthenticated_read_status": 401,
            }
            self.receipt["stage"] = "managed_setup"
            self.enable()
            if self.scenario == EMPTY_SCENARIO:
                self.persistent_empty_stop()
                return
            if self.scenario == STRICT_DRIFT_SCENARIO:
                self.strict_authority_drift()
                return
            if self.scenario == STRICT_REVIEW_SCENARIO:
                self.strict_review_authority()
                return
            if self.scenario == STALE_CLAIM_SCENARIO:
                self.strict_stale_registered_claim()
                return
            self.receipt["stage"] = "strict_scope_setup"
            engagement, authorization, job, case = self.new_job(
                "strict-denial", in_scope=False
            )
            zero = self.traffic()
            self.receipt["stage"] = "strict_scope_denial"
            self.approve(
                "strict-denial", engagement, authorization, job, case, expected=409
            )
            inventory = self.inventory(engagement, job)
            require(
                self.traffic() == zero
                and inventory["contracts"] == []
                and inventory["execution"] is None
                and inventory["targets_spent"] == inventory["duration_allocated"] == 0,
                "strict_denial_mutated_or_dispatched",
            )
            self.receipt["cases"]["strict_out_of_scope"] = {
                "status": "passed",
                "approval_http_status": 409,
                "inventory": inventory,
                "traffic_delta": 0,
            }
            if self.scenario == "persistent-availability":
                self.persistent_availability(engagement, job, zero)
                return
            if self.scenario == IDLE_SCENARIO:
                self.persistent_idle_limit(zero)
                return
            if self.scenario == COUNT_SCENARIO:
                self.persistent_count_limit(zero)
                return
            if self.scenario == "missing-local-grant":
                self.missing_grant()
                return
            if self.scenario != "healthy":
                self.cancelled_http()
                return
            # Both approved jobs queue before one explicitly admitted incarnation.
            self.receipt["stage"] = "happy_setup"
            selections = []
            for name in ("happy-fixed", "healthy-sequence"):
                engagement, authorization, job, case = self.new_job(name, marker=True)
                binding = self.approve(name, engagement, authorization, job, case)
                selections.append((engagement, job, case, binding))
            # The existing managed discovery route orders by immutable job ID,
            # not creation time. Keep the expected first/second jobs aligned.
            selections.sort(key=lambda row: row[1])
            require(
                selections[0][3] == selections[1][3],
                "healthy_sequence_enrollment_changed",
            )
            traffic = self.traffic()
            before_jobs = [
                self.inventory(engagement, job) for engagement, job, _, _ in selections
            ]
            require(
                traffic == zero
                and all(
                    before["job_status"] == "pending"
                    and before["execution"] is None
                    and not before["contracts"]
                    and before["targets_spent"] == before["duration_allocated"] == 0
                    and len(before["approvals"]) == 1
                    and before["approvals"][0]["issued"] == 0
                    for before in before_jobs
                ),
                "approved_queue_executed_before_worker_enablement",
            )
            physical = self.worker(*selections[0][3])
            self.receipt["stage"] = "happy_verification"
            inventories = [
                self.inventory(engagement, job) for engagement, job, _, _ in selections
            ]
            observed = self.traffic()[len(traffic) :]
            self.receipt["observed_attempt"] = {
                "physical": physical,
                "inventories": inventories,
                "target_request_count": len(observed),
            }
            require(len(observed) == 10, "healthy_sequence_total_traffic_mismatch")
            measured = []
            for index, ((engagement, job, case, _), inventory) in enumerate(
                zip(selections, inventories)
            ):
                marker = parse_qs(urlsplit(case["spec"]["request"]["url"]).query)[
                    "nm2_case"
                ]
                requests = [
                    row
                    for row in observed
                    if parse_qs(urlsplit(row["path"]).query).get("nm2_case") == marker
                ]
                proof, attempt = self.verify_fixed(
                    engagement,
                    job,
                    case,
                    physical,
                    before_jobs[index],
                    requests,
                    inventory,
                )
                measured.append(attempt)
                if index == 0:
                    self.receipt["cases"]["happy_fixed"] = proof
            self.receipt["stage"] = "healthy_sequence_verification"
            self.receipt["cases"]["healthy_sequence"] = self.verify_healthy_sequence(
                physical, measured, inventories, *selections[0][3]
            )
            self.receipt["status"] = "initial_stages_passed"
            self.receipt["stage"] = "initial_complete"
        except Exception as error:
            self.receipt["status"] = "held"
            self.receipt["reason"] = (
                str(error)
                if isinstance(error, AcceptanceRefused)
                else "fixture_stage_failed"
            )
            if isinstance(error, HTTPStatusRefused):
                self.receipt["http_failure"] = {
                    **error.public,
                    "stage": self.receipt.get("stage", "unknown"),
                }
            if isinstance(error, WorkerCLIRefused):
                self.receipt["command_failure"] = dict(error.public)
            if isinstance(error, WorkerStatusRefused):
                self.receipt["status_failure"] = dict(error.public)
            raise
        finally:
            # Preserve stopped/failed fixtures and custody; never down/prune or
            # retry a claim, consume, binding, result or lost runtime admission.
            after = None
            try:
                self.stop_owned(before)
            except Exception:
                self.receipt["status"] = "held"
                self.receipt["fixture_stop"] = {"status": "unknown_preserve_resources"}
            try:
                after = self.snapshot()
                self.receipt["after_sha256"] = digest(canonical(after))
                self.receipt["admitted_inventory_diffs"] = unchanged_inventory(
                    before,
                    after,
                    self.project,
                    admit_bridge=self.m["allow_empty_builtin_bridge_id_change"],
                )
            except AcceptanceRefused as error:
                self.receipt["status"], self.receipt["inventory_reason"] = (
                    "held",
                    str(error),
                )
            except Exception:
                self.receipt["status"] = "held"
                self.receipt["inventory_reason"] = "inventory_observation_unavailable"
            if self.install.is_dir():
                if not (self.install / "nm2-inventory-before.json").exists():
                    publish(
                        self.install / "nm2-inventory-before.json", canonical(before)
                    )
                if after is not None:
                    publish(self.install / "nm2-inventory-after.json", canonical(after))
                raw = canonical(self.receipt)
                require(
                    not any(secret.encode() in raw for secret in self.secrets),
                    "receipt_redaction_failed",
                )
                publish(self.install / "nm2-worker-receipt.json", raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", required=True, type=Path)
    parser.add_argument("--scenario", choices=SCENARIOS, default="healthy")
    parser.add_argument(
        "--database-revision",
        choices=("0040runtimesequence", "0041persistentruntime"),
        default="0040runtimesequence",
        help="Require this exact reviewed Map schema; no automatic upgrade or acceptance",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Run the reviewed explicit fixture; creates and retains owned Docker resources",
    )
    args = parser.parse_args(argv)
    require(
        args.scenario not in PERSISTENT_SCENARIOS
        or args.database_revision == "0041persistentruntime",
        "persistent_database_revision_required",
    )
    selection = manifest(args.cohort)
    require(args.scenario != STRICT_REVIEW_SCENARIO
            or selection["sources"]["map"]["commit"] == STRICT_REVIEW_MAP,
            "strict_review_map_source_required")
    require(args.scenario != STALE_CLAIM_SCENARIO
            or (STALE_CLAIM_MAP is not None and selection["sources"]["map"]["commit"] == STALE_CLAIM_MAP),
            "strict_stale_claim_map_source_required")
    if not args.execute:
        receipt = {
            "schema": "vardr.nm2-worker-source-validation/1",
            "status": "sources_validated_runtime_not_run",
            "project": selection["project"],
            "sources": selection["sources"],
            "images": selection["images"],
            "initial_cases": INITIAL_CASES,
            "docker_calls": 0,
            "expected_database_revision": args.database_revision,
        }
        if args.scenario != "healthy":
            receipt["scenario"] = args.scenario
        if args.scenario == "persistent-availability":
            receipt["initial_cases"] = (
                "default_disabled",
                "strict_out_of_scope",
                "persistent_availability",
            )
        if args.scenario == EMPTY_SCENARIO:
            receipt["initial_cases"] = ("default_disabled", "persistent_empty_stop")
            receipt.update(scenario=args.scenario, limits=persistent_limits(EMPTY_SCENARIO),
                           acceptance_scope="persistent_empty_stop_only")
        if args.scenario == IDLE_SCENARIO:
            receipt["initial_cases"] = ("default_disabled", "strict_out_of_scope", "persistent_idle_limit")
            receipt.update(scenario=args.scenario, limits=persistent_limits(IDLE_SCENARIO),
                           acceptance_scope="persistent_idle_control_only")
        if args.scenario == STRICT_REVIEW_SCENARIO:
            receipt.update(
                initial_cases=("default_disabled", STRICT_REVIEW_CASE),
                acceptance_scope=STRICT_REVIEW_SCOPE,
            )
        if args.scenario == STALE_CLAIM_SCENARIO:
            receipt.update(
                initial_cases=("default_disabled", STALE_CLAIM_CASE),
                acceptance_scope=STALE_CLAIM_SCOPE,
            )
        if args.scenario == STRICT_DRIFT_SCENARIO:
            receipt.update(
                initial_cases=("default_disabled", STRICT_DRIFT_CASE),
                acceptance_scope=STRICT_DRIFT_SCOPE,
            )
        if args.scenario == COUNT_SCENARIO:
            receipt["initial_cases"] = (
                "default_disabled",
                "strict_out_of_scope",
                "persistent_count_limit",
            )
        print(
            json.dumps(
                receipt,
                indent=2,
            )
        )
        return 0
    fixture = Fixture(
        selection, scenario=args.scenario, database_revision=args.database_revision
    )
    try:
        fixture.run()
    except Exception:
        print(
            "NM2 fixture held; preserve its installation, host custody and Docker resources.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(fixture.receipt, indent=2))
    return (
        0
        if fixture.receipt["status"]
        in {
            "initial_stages_passed",
            "selected_failure_slice_passed",
            "selected_availability_slice_passed",
            "selected_count_control_slice_passed",
            "selected_idle_control_slice_passed",
            "selected_empty_stop_slice_passed",
            STRICT_DRIFT_PASS, STRICT_REVIEW_PASS, STALE_CLAIM_PASS,
        }
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
