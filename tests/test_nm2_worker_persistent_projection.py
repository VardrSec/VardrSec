"""Pure untrusted-receipt projection tests; no Docker, HTTP or Runner install."""

import copy
import json
import unittest
from unittest.mock import patch
import uuid

import nm2_worker_persistent_projection as projection
import test_nm2_persistent_availability as producer_tests
import worker_host as host


def hashed(value):
    return producer_tests.hashed(value)


def identifier(number):
    return str(uuid.UUID(int=number))


def vector():
    """Extend the producer's oracle vector to the exact retained wire shapes."""
    value = producer_tests.vector()
    selection = {
        "sources": {
            name: {"path": "/private/source/" + name, "commit": str(i) * 40}
            for i, name in enumerate(sorted(projection.fixture.SOURCE_NAMES), 1)
        },
        "images": {
            name: "sha256:" + str(i) * 64
            for i, name in enumerate(sorted(projection.fixture.IMAGE_NAMES), 1)
        },
        "project": "vardrsec-nm2-abcdefgh",
        "https_port": 28443,
    }
    admission = value.idle["admission"]
    admission["origin"] = "https://vardrsec.localhost:28443/backend"
    admission["identity"].update(
        project=selection["project"], image_id=selection["images"]["worker"]
    )
    admission["runtime_sha256"] = host.digest(admission["identity"])
    admission["admission_sha256"] = host.digest(
        {k: v for k, v in admission.items() if k != "admission_sha256"}
    )
    value.fixture.issuer_origin = admission["origin"]
    value.physical.update(
        runtime_sha256=admission["runtime_sha256"],
        admission_sha256=admission["admission_sha256"],
        operator_enable_state="enabled",
        finished_at="2026-11-06T02:02:00.123456789Z",
    )
    value.runtime.pop("origin")
    value.runtime.update(
        runtime_sha256=admission["runtime_sha256"],
        admission_sha256=admission["admission_sha256"],
    )
    for row in (value.idle["before"], value.idle["after"]):
        row.update(
            runtime_sha256=admission["runtime_sha256"],
            admission_sha256=admission["admission_sha256"],
        )
    value.idle["status"] = {
        "schema": "vardr.worker-status/1",
        "runtime_id": admission["runtime_id"],
        "protocol": "persistent-v3",
        "mode": "persistent",
        "limits": admission["limits"],
        "identity": admission["identity"],
        "state": "idle-ready",
        "reason": None,
        "cursor": {"last_sequence": "0", "phase": "idle"},
        "availability": {
            "state": "idle-ready",
            "observed_at": "2026-11-06T01:59:00Z",
            "fresh_until": "2026-11-06T01:59:15Z",
            "cursor": {"last_sequence": "0", "phase": "idle"},
        },
        "new_work_disabled": False,
        "reporting_revoked": False,
        "registration_state": "acknowledged",
        "disable_state": "none",
        "stop_state": "none",
        "revocation_state": "none",
        "container_state": "running",
    }
    for n, (measured, history, inventory) in enumerate(
        zip(value.measured, value.runtime["attempts"], value.inventories), 1
    ):
        binding = history["binding"]
        binding.update(
            origin=admission["origin"],
            contract_id=identifier(1000 + n),
            attempt_id=identifier(2000 + n),
        )
        result = host.digest(
            {
                "schema": "vardr.managed-result/1",
                **binding,
                "artifact_sha256": measured["artifact_sha256"],
                "case_sha256": measured["case_sha256"],
            }
        )
        terminal = {
            "schema": "vardr.managed-completion/1",
            **binding,
            "receipt_sha256": result,
            "outcome": "completed",
            "capacity_reserved": False,
        }
        terminal_sha = host.digest(terminal)
        release = {
            "schema": "vardr.worker-idle-release/2",
            "runtime_id": admission["runtime_id"],
            "runtime_sha256": admission["runtime_sha256"],
            "admission_sha256": admission["admission_sha256"],
            "runtime_sequence": str(n),
            "binding": binding,
            "terminal_receipt_sha256": terminal_sha,
            "native_done_sha256": measured["native_done_sha256"],
            "released": True,
        }
        release["receipt_sha256"] = host.digest(release)
        history.update(
            terminal_receipt=terminal,
            terminal_receipt_sha256=terminal_sha,
            release_receipt=release,
        )
        measured.update(
            binding=binding,
            evidence_sha256=hashed("evidence" + str(n)),
            terminal_receipt=terminal,
            terminal_receipt_sha256=terminal_sha,
            result_receipt_sha256=result,
            release_receipt=release,
            release_receipt_sha256=release["receipt_sha256"],
            assessment={
                "status": "conclusive",
                "baseline_valid": True,
                "case_snapshot_verified": True,
                "preflight": {"status": "passed"},
                "case_hash": measured["case_sha256"],
                "candidate_findings": 0,
            },
        )
        for i, row in enumerate(measured["requests"]):
            row.update(
                method="GET",
                path=("/session" if i < 2 else "/fixed/records/42")
                + f"?nm2_case=persistent-{n:02d}",
            )
        metadata = measured["local"]
        metadata.update(
            runtime_sha256=admission["runtime_sha256"],
            admission_sha256=admission["admission_sha256"],
        )
        metadata["attempt"].update(
            run_id=f"{n:032x}", completion=terminal, release=release
        )
        for i, who in enumerate(("owner", "peer")):
            catalog_grant = metadata["grants"]["grants"][i]
            catalog_grant.update(
                issuer=admission["origin"],
                origin=projection.TARGET,
                source="env",
                name="FIXTURE_" + who.upper() + "_TOKEN",
                id=identifier(3000 + n * 2 + i),
            )
            for key in ("issued_at", "expires_at"):
                catalog_grant[key] = catalog_grant[key].replace("Z", "+00:00")
        approval = inventory["approvals"][0]
        approval["id"] = identifier(4000 + n)
        for i, who in enumerate(("owner", "peer")):
            approval["credential_grants"][i].update(
                identity_id=who,
                source="value_env",
                name="FIXTURE_" + who.upper() + "_TOKEN",
                revision=1,
            )
        inventory.update(
            schema="vardr.nm2-fixture-inventory/3",
            schema_revision="0041persistentruntime",
            database_user="vardrmap_app",
            engagement_id=measured["engagement_id"],
            job_id=measured["job_id"],
            runtime_attempt_bound=35,
            job_status="done",
            execution={
                "state": "completed",
                "capacity_reserved": False,
                "target_charge": 1,
                "duration_seconds": 30,
            },
            contracts=[
                {
                    "id": binding["contract_id"],
                    "attempt_id": binding["attempt_id"],
                    "ordinal": 1,
                    "fence": 1,
                    "consumed": True,
                    "contract_sha256": binding["contract_sha256"],
                }
            ],
            results=[
                {
                    "contract_id": binding["contract_id"],
                    "artifact_sha256": measured["artifact_sha256"],
                    "receipt_sha256": result,
                    "outcome": "completed",
                    "evidence_created": 5,
                    "scan_items_created": 0,
                }
            ],
            stops=[],
        )
    value.retirement.update(
        origin=admission["origin"],
        runtime_sha256=admission["runtime_sha256"],
        admission_sha256=admission["admission_sha256"],
    )
    value.retirement["receipt_sha256"] = host.digest(
        {k: v for k, v in value.retirement.items() if k != "receipt_sha256"}
    )
    value.retained = copy.deepcopy(value.measured[-1]["local"])
    value.retained.pop("grants")
    value.retained.update(state="retired", retirement=value.retirement)
    value.retained["attempt"].update(
        state="physical_retirement_observed", retired_from_state="released"
    )
    case = value.fixture.verify_persistent_sequence(
        value.physical,
        value.idle,
        value.measured,
        value.inventories,
        value.retirement,
        value.retained,
    )
    cases = {name: {"status": "not_run"} for name in projection.CASES}
    cases.update(
        default_disabled={
            "status": "passed",
            "services": ["api", "db", "proxy", "web"],
            "managed_pending_status": 404,
            "csrf_write_status": 403,
            "unauthenticated_read_status": 401,
        },
        strict_out_of_scope={
            "status": "passed",
            "approval_http_status": 409,
            "traffic_delta": 0,
            "inventory": {
                "schema": "vardr.nm2-fixture-inventory/3",
                "schema_revision": "0041persistentruntime",
                "database_user": "vardrmap_app",
                "engagement_id": "eng-strict",
                "job_id": "job-strict",
                "runtime_attempt_bound": 35,
                "job_status": "pending",
                "approvals": [],
                "contracts": [],
                "results": [],
                "stops": [],
                "runtimes": [],
                "execution": None,
                "targets_spent": 0,
                "duration_allocated": 0,
            },
        },
        persistent_availability=case,
    )
    raw = {
        "schema": "vardr.nm2-worker-persistent-acceptance/1",
        "status": "selected_availability_slice_passed",
        "stage": "selected_availability_complete",
        "scenario": "persistent-availability",
        "acceptance_scope": "persistent_availability_only",
        "nm2_exit_status": "incomplete",
        "platform": "linux",
        "retained": True,
        "sources": selection["sources"],
        "images": selection["images"],
        "project": selection["project"],
        "readiness_volume": selection["project"] + "_worker-ready",
        "expected_database_revision": "0041persistentruntime",
        "before_sha256": hashed("before"),
        "after_sha256": hashed("after"),
        "public_ca_der_sha256": hashed("ca"),
        "admitted_inventory_diffs": [],
        "cases": cases,
        "fixture_stop": {
            "status": "stopped_retained",
            "container_ids": ["a" * 64] + [hashed(str(n)) for n in range(5)],
            "stop_requested_ids": ["a" * 64],
        },
        "image_sources": {
            name: {
                "image_id": selection["images"][image],
                "python_file_count": 200,
                "python_inventory_sha256": hashed(name + "python"),
                "executables": {},
                "line_endings": "CRLF-normalized-to-LF",
            }
            for name, image in (("map", "api"), ("runner", "worker"))
        },
    }
    raw["image_sources"]["runner"]["executables"] = {
        "/usr/local/bin/vardr-worker-owner": hashed("owner"),
        "/usr/local/bin/vardrgate": hashed("gate"),
    }
    return raw, selection


def desktop_vector(*, bridge_change=False):
    raw, selection = vector()
    raw["platform"] = "win32"
    selection.update(
        docker_context="desktop-linux",
        allow_empty_builtin_bridge_id_change=bridge_change,
    )
    for name, row in selection["sources"].items():
        row["path"] = "C:\\private\\source\\" + name
    physical = raw["cases"]["persistent_availability"]["physical"]

    def container(container_id, service, *, old=False):
        state = {
            "running": False,
            "paused": False,
            "restarting": False,
            "dead": False,
            "exit_code": physical["exit_code"] if service == "managed-worker" else 0,
            "started_at": physical["identity"]["started_at"],
            "finished_at": physical["finished_at"],
        }
        return {
            "id": container_id,
            "image": selection["images"][
                service if service in {"db", "api", "web", "proxy"} else "worker"
            ],
            "labels": {
                "com.docker.compose.project": "old-project"
                if old
                else selection["project"],
                "com.docker.compose.service": service,
            },
            "state": state,
            "restarts": 0,
            "networks": {},
            "mounts": [],
        }

    bridge_id = hashed("old-bridge")
    before = {
        "containers": {
            hashed("old-stopped"): container(hashed("old-stopped"), "db", old=True)
        },
        "networks": {
            bridge_id: {
                "id": bridge_id,
                "name": "bridge",
                "driver": "bridge",
                "scope": "local",
                "internal": False,
                "attachable": False,
                "ipv6": False,
                "ingress": False,
                "options": {"com.docker.network.bridge.default_bridge": "true"},
                "ipam": {"Driver": "default", "Options": None, "Config": []},
                "labels": {},
                "containers": {},
            }
        },
        "volumes": {
            "PRIVATE-old-volume": {
                "id": "PRIVATE-old-volume",
                "driver": "local",
                "labels": {},
                "options": None,
            }
        },
        "images": {
            image: {
                "id": image,
                "tags": ["PRIVATE-image-tag"],
                "digests": [],
                "labels": {},
            }
            for image in selection["images"].values()
        },
    }
    after = copy.deepcopy(before)
    for container_id, service in zip(
        raw["fixture_stop"]["container_ids"],
        ("managed-worker", "db", "api", "web", "proxy", "gate-fixture"),
        strict=True,
    ):
        after["containers"][container_id] = container(container_id, service)
    if bridge_change:
        bridge = after["networks"].pop(bridge_id)
        bridge["id"] = hashed("new-bridge")
        after["networks"][bridge["id"]] = bridge
    raw["before_sha256"] = host.digest(before)
    raw["after_sha256"] = host.digest(after)
    raw["admitted_inventory_diffs"] = projection.fixture.unchanged_inventory(
        before, after, selection["project"], admit_bridge=bridge_change
    )
    return raw, selection, before, after


class PersistentProjectionTests(unittest.TestCase):
    def assert_refused(self, raw, selection):
        with self.assertRaisesRegex(
            projection.ProjectionRefused, "^nm2_persistent_projection_refused$"
        ):
            projection.project(raw, selection)

    def test_realistic_full_proof_is_pure_and_outputs_only_whitelist(self):
        raw, selection = vector()
        with (
            patch("subprocess.run", side_effect=AssertionError("no process")),
            patch("socket.create_connection", side_effect=AssertionError("no network")),
        ):
            result = projection.project(raw, selection)
        self.assertEqual(
            set(result),
            {
                "schema",
                "status",
                "nm2_exit_status",
                "remaining_matrix_status",
                "cases",
                "measurements",
                "executables",
                "source_inventories",
            },
        )
        self.assertEqual(result["remaining_matrix_status"], "not_closed")
        self.assertEqual(result["nm2_exit_status"], "incomplete")
        self.assertEqual(result["measurements"]["target_request_count"], 175)
        self.assertEqual(result["measurements"]["last_sequence"], "35")
        self.assertEqual(len(result["measurements"]["attempts"]), 35)
        self.assertEqual(
            set(result["measurements"]["attempts"][0]),
            {"runtime_sequence"} | projection.HASHES,
        )
        serialized = json.dumps(result)
        for value in (
            selection["project"],
            "/private/source/",
            "http",
            "FIXTURE_",
            "owner_nonce",
            raw["cases"]["persistent_availability"]["physical"]["identity"][
                "container_id"
            ],
        ):
            self.assertNotIn(value, serialized)

    def test_source_platform_cleanup_and_gate_negatives(self):
        mutations = [
            (("platform",), "win32"),
            (("retained",), False),
            (("status",), "initial_stages_passed"),
            (("nm2_exit_status",), "complete"),
            (("expected_database_revision",), "0040runtimeattempt"),
            (("readiness_volume",), "other-volume"),
            (("project",), "other"),
            (("images", "worker"), "sha256:" + "f" * 64),
            (("fixture_stop", "container_ids"), ["a" * 64] * 6),
            (("fixture_stop", "container_ids"), [hashed(str(n)) for n in range(6)]),
            (("fixture_stop", "status"), "running"),
            (("cases", "default_disabled", "csrf_write_status"), 200),
            (
                ("cases", "default_disabled", "services"),
                {name: "PRIVATE_CANARY" for name in ("api", "db", "proxy", "web")},
            ),
            (("cases", "default_disabled", "services"), ("api", "db", "proxy", "web")),
            (("cases", "strict_out_of_scope", "approval_http_status"), 403),
            (("cases", "strict_out_of_scope", "inventory", "targets_spent"), True),
            (("cases", "missing_local_grant", "status"), "passed"),
        ]
        for path, replacement in mutations:
            with self.subTest(path=path):
                raw, selection = copy.deepcopy(vector())
                cursor = raw
                for key in path[:-1]:
                    cursor = cursor[key]
                cursor[path[-1]] = replacement
                self.assert_refused(raw, selection)

    def test_bad_counters_policy_hashes_and_partial_proof_refuse(self):
        paths = [
            (("idle_seconds",), True),
            (("idle_seconds",), float("nan")),
            (("idle_seconds",), float("inf")),
            (("idle_seconds",), 69.99),
            (("target_request_count",), 175.0),
            (("evidence_count",), 174),
            (("remaining_local_holds",), False),
            (("limits", "max_attempts"), "35"),
            (("last_sequence",), 35),
            (("proof", "runtime", "last_sequence"), "035"),
            (("proof", "runtime", "legacy_binding", "fence"), 1),
            (("proof", "idle", "status", "state"), "held"),
            (("proof", "idle", "status", "new_work_disabled"), True),
            (
                ("proof", "idle", "status", "availability", "fresh_until"),
                "2026-11-06T01:59:16Z",
            ),
            (("proof", "retained", "attempt", "consumption_acknowledged"), False),
            (("proof", "retained", "attempt", "completion", "fence"), True),
            (("proof", "retained", "attempt", "release", "binding", "fence"), 1.0),
        ]
        for path, replacement in paths:
            with self.subTest(path=path, replacement=replacement):
                raw, selection = vector()
                cursor = raw["cases"]["persistent_availability"]
                for key in path[:-1]:
                    cursor = cursor[key]
                cursor[path[-1]] = replacement
                self.assert_refused(raw, selection)
        for key in ("idle", "runtime", "inventories", "retirement", "retained"):
            raw, selection = vector()
            del raw["cases"]["persistent_availability"]["proof"][key]
            self.assert_refused(raw, selection)

    def test_local_catalogue_utc_format_does_not_widen_map_timestamps(self):
        raw, selection = vector()
        original = copy.deepcopy(raw)
        projection.project(raw, selection)
        self.assertEqual(raw, original)
        for value in (
            "2026-11-06T02:10:00.000000Z",
            "2026-11-06T02:10:00+00:00",
            "2026-11-06T02:10:00.00000+00:00",
            "2026-11-06T02:10:00.0000000+00:00",
            "2026-11-06T02:10:00.000000+01:00",
            "2026-11-06T02:10:00.000000-00:00",
            "2026-02-30T02:10:00.000000+00:00",
        ):
            with self.subTest(value=value):
                for key in ("issued_at", "expires_at"):
                    raw, selection = vector()
                    raw["cases"]["persistent_availability"]["attempts"][0]["local"][
                        "grants"
                    ]["grants"][0][key] = value
                    self.assert_refused(raw, selection)
        raw, selection = vector()
        raw["cases"]["persistent_availability"]["proof"]["inventories"][0]["approvals"][
            0
        ]["expires_at"] = "2026-11-06T02:10:00.000000+00:00"
        self.assert_refused(raw, selection)

    def test_real_receipt_joins_reject_rehashed_outer_tampering(self):
        for field, replacement in (
            ("fence", True),
            ("fence", 1.0),
            ("outcome", "failed"),
            ("receipt_sha256", "f" * 64),
            ("contract_id", identifier(99999)),
        ):
            with self.subTest(field=field, replacement=replacement):
                raw, selection = vector()
                case = raw["cases"]["persistent_availability"]
                row = case["attempts"][0]
                terminal = row["terminal_receipt"]
                terminal[field] = replacement
                row["terminal_receipt_sha256"] = host.digest(terminal)
                history = case["proof"]["runtime"]["attempts"][0]
                history["terminal_receipt_sha256"] = row["terminal_receipt_sha256"]
                release = row["release_receipt"]
                release["terminal_receipt_sha256"] = row["terminal_receipt_sha256"]
                release["receipt_sha256"] = host.digest(
                    {k: v for k, v in release.items() if k != "receipt_sha256"}
                )
                row["release_receipt_sha256"] = release["receipt_sha256"]
                self.assert_refused(raw, selection)

    def test_history_inventory_grants_and_local_ack_joins_are_required(self):
        for kind in (
            "missing_history",
            "wrong_previous",
            "inventory_artifact",
            "inventory_contract",
            "consumed_bool",
            "local_ack",
            "local_completion",
            "local_release",
            "grant_expired",
            "grant_source",
            "grant_duplicate",
            "approval_expired",
            "approval_extra",
            "approval_wrong_ref",
            "duplicate_run",
        ):
            with self.subTest(kind=kind):
                raw, selection = vector()
                case = raw["cases"]["persistent_availability"]
                row, proof = case["attempts"][0], case["proof"]
                inventory = proof["inventories"][0]
                if kind == "missing_history":
                    proof["runtime"]["attempts"].pop()
                elif kind == "wrong_previous":
                    proof["runtime"]["attempts"][1]["previous_sequence"] = None
                elif kind == "inventory_artifact":
                    inventory["results"][0]["artifact_sha256"] = "f" * 64
                elif kind == "inventory_contract":
                    inventory["contracts"][0]["contract_sha256"] = "f" * 64
                elif kind == "consumed_bool":
                    inventory["contracts"][0]["consumed"] = 1
                elif kind == "local_ack":
                    row["local"]["attempt"]["consumption_sent"] = True
                elif kind == "local_completion":
                    row["local"]["attempt"]["completion"] = None
                elif kind == "local_release":
                    row["local"]["attempt"]["release"] = None
                elif kind == "grant_expired":
                    row["local"]["grants"]["grants"][0]["expires_at"] = row[
                        "bound_at"
                    ].replace("Z", "+00:00")
                elif kind == "grant_source":
                    row["local"]["grants"]["grants"][0]["source"] = "file"
                elif kind == "grant_duplicate":
                    row["local"]["grants"]["grants"][1]["id"] = row["local"]["grants"][
                        "grants"
                    ][0]["id"]
                elif kind == "approval_expired":
                    inventory["approvals"][0]["expires_at"] = row["bound_at"]
                elif kind == "approval_extra":
                    inventory["approvals"][0]["credential_grants"][0]["secret"] = (
                        "PRIVATE_CANARY"
                    )
                elif kind == "approval_wrong_ref":
                    inventory["approvals"][0]["credential_grants"][0]["revision"] = True
                elif kind == "duplicate_run":
                    case["attempts"][1]["local"]["attempt"]["run_id"] = row["local"][
                        "attempt"
                    ]["run_id"]
                self.assert_refused(raw, selection)

    def test_actual_dispatch_identities_clocks_and_release_order_are_required(self):
        for kind in (
            "identity",
            "method",
            "origin",
            "query",
            "clock_bool",
            "clock_zero",
            "cross_job",
            "release_order",
        ):
            with self.subTest(kind=kind):
                raw, selection = vector()
                case = raw["cases"]["persistent_availability"]
                request = case["attempts"][0]["requests"][0]
                if kind == "identity":
                    request["identity"] = "anonymous"
                elif kind == "method":
                    request["method"] = "POST"
                elif kind == "origin":
                    request["path"] = (
                        "http://outside.invalid/session?nm2_case=persistent-01"
                    )
                elif kind == "query":
                    request["path"] += "&authorization=PRIVATE_CANARY"
                elif kind == "clock_bool":
                    request["received_monotonic_ns"] = True
                elif kind == "clock_zero":
                    request["received_monotonic_ns"] = 0
                elif kind == "cross_job":
                    case["attempts"][1]["requests"][0]["received_monotonic_ns"] = 1
                elif kind == "release_order":
                    case["attempts"][1]["bound_at"] = case["attempts"][0]["bound_at"]
                self.assert_refused(raw, selection)

    def test_retirement_cannot_be_rehashed_to_claim_more_or_other_history(self):
        for field, value in (
            ("last_sequence", "34"),
            ("admission_sha256", "f" * 64),
            ("retired", 1),
            ("binding", {}),
            ("extra", "PRIVATE_CANARY"),
        ):
            with self.subTest(field=field):
                raw, selection = vector()
                case = raw["cases"]["persistent_availability"]
                retirement = case["proof"]["retirement"]
                retirement[field] = value
                retirement["receipt_sha256"] = host.digest(
                    {k: v for k, v in retirement.items() if k != "receipt_sha256"}
                )
                case["retirement_receipt_sha256"] = retirement["receipt_sha256"]
                self.assert_refused(raw, selection)

    def test_rehashed_optional_controls_and_physical_clock_mismatch_refuse(self):
        for policy in (
            {"max_attempts": "35", "idle_timeout_seconds": None},
            {"max_attempts": None, "idle_timeout_seconds": 60},
        ):
            with self.subTest(policy=policy):
                raw, selection = vector()
                case = raw["cases"]["persistent_availability"]
                admission = case["proof"]["idle"]["admission"]
                admission["limits"] = policy
                admission["admission_sha256"] = host.digest(
                    {k: v for k, v in admission.items() if k != "admission_sha256"}
                )
                case["limits"] = policy
                case["admission_sha256"] = admission["admission_sha256"]
                self.assert_refused(raw, selection)
        for stamp in ("2026-11-06T02:00:01Z", "2026-02-30T02:02:00.123456789Z"):
            raw, selection = vector()
            raw["cases"]["persistent_availability"]["physical"]["finished_at"] = stamp
            self.assert_refused(raw, selection)
        for year in (2001, 2099):
            raw, selection = vector()
            presence = raw["cases"]["persistent_availability"]["proof"]["idle"][
                "status"
            ]["availability"]
            presence.update(
                observed_at=f"{year}-11-06T01:59:00Z",
                fresh_until=f"{year}-11-06T01:59:15Z",
            )
            self.assert_refused(raw, selection)

    def test_recomputed_receipts_cannot_reuse_authority_or_change_first_fence(self):
        for duplicate in ("contract_id", "attempt_id", "fence"):
            raw, selection = vector()
            case = raw["cases"]["persistent_availability"]
            row = case["attempts"][1]
            binding = row["binding"]
            binding[duplicate] = (
                2 if duplicate == "fence" else case["attempts"][0]["binding"][duplicate]
            )
            result = host.digest(
                {
                    "schema": "vardr.managed-result/1",
                    **binding,
                    "artifact_sha256": row["artifact_sha256"],
                    "case_sha256": row["case_sha256"],
                }
            )
            row["terminal_receipt"].update(**binding, receipt_sha256=result)
            row["result_receipt_sha256"] = result
            row["terminal_receipt_sha256"] = host.digest(row["terminal_receipt"])
            history = case["proof"]["runtime"]["attempts"][1]
            history["terminal_receipt_sha256"] = row["terminal_receipt_sha256"]
            release = row["release_receipt"]
            release["terminal_receipt_sha256"] = row["terminal_receipt_sha256"]
            release["receipt_sha256"] = host.digest(
                {k: v for k, v in release.items() if k != "receipt_sha256"}
            )
            row["release_receipt_sha256"] = release["receipt_sha256"]
            inventory = case["proof"]["inventories"][1]
            inventory["contracts"][0].update(
                id=binding["contract_id"],
                attempt_id=binding["attempt_id"],
                fence=binding["fence"],
            )
            inventory["results"][0].update(
                contract_id=binding["contract_id"], receipt_sha256=result
            )
            self.assert_refused(raw, selection)

    def test_private_unknown_top_data_is_never_exported_and_nested_extras_refuse(self):
        raw, selection = vector()
        raw.update(
            stdout="PRIVATE_STDOUT_CANARY",
            credentials={"token": "PRIVATE_CREDENTIAL_CANARY"},
            headers={"Authorization": "PRIVATE_HEADER_CANARY"},
            body="PRIVATE_BODY_CANARY",
            extra_arrays=[["PRIVATE_ARRAY_CANARY"]],
        )
        result = json.dumps(projection.project(raw, selection))
        self.assertNotIn("PRIVATE_", result)
        for path in (
            ("proof", "runtime"),
            ("proof", "idle", "status"),
            ("proof", "retained"),
            ("attempts", 0),
            ("attempts", 0, "requests", 0),
            ("attempts", 0, "assessment"),
        ):
            raw, selection = vector()
            cursor = raw["cases"]["persistent_availability"]
            for key in path:
                cursor = cursor[key]
            cursor["PRIVATE_EXTRA_CANARY"] = "PRIVATE_CREDENTIAL_CANARY"
            self.assert_refused(raw, selection)

    def test_desktop_entry_preserves_raw_platform_and_uses_the_same_strict_proof(self):
        for bridge_change in (False, True):
            with self.subTest(bridge_change=bridge_change):
                args = desktop_vector(bridge_change=bridge_change)
                original = copy.deepcopy(args)
                with (
                    patch("subprocess.run", side_effect=AssertionError("no process")),
                    patch(
                        "socket.create_connection",
                        side_effect=AssertionError("no network"),
                    ),
                ):
                    result = projection.project_desktop(*args)
                self.assertEqual(args, original)
                self.assertEqual(result["platform"], "win32")
                self.assertEqual(result["container_platform"], "linux")
                self.assertEqual(
                    result["schema"], "vardr.nm2-worker-persistent-desktop-public/1"
                )
                self.assertEqual(
                    result["inventory_guard"]["new_stopped_owned_container_count"], 6
                )
                self.assertEqual(
                    result["inventory_guard"]["before_counts"]["containers"], 1
                )
                self.assertEqual(
                    result["inventory_guard"]["after_counts"]["containers"], 7
                )
                self.assertEqual(
                    result["inventory_guard"]["semantic_bridge_classification"],
                    {
                        "empty_builtin_bridge_id_change_count": int(bridge_change),
                        "cause": "unknown",
                    },
                )
                linux, selection = vector()
                expected = projection.project(linux, selection)
                self.assertEqual(
                    {key: result[key] for key in expected if key != "schema"},
                    {key: value for key, value in expected.items() if key != "schema"},
                )
                self.assert_refused(
                    *args[:2]
                )  # Original win32 receipt stays unacceptable to Linux.
                text = json.dumps(result)
                for canary in (
                    "PRIVATE-",
                    "C:\\",
                    "old-project",
                    "container_id",
                    "before_sha256",
                    "after_sha256",
                ):
                    self.assertNotIn(canary, text)

    def test_desktop_platform_paths_context_and_snapshot_hashes_are_required(self):
        for kind in (
            "platform",
            "posix",
            "relative",
            "traversal",
            "context",
            "bridge_bool",
            "before_hash",
            "after_hash",
        ):
            with self.subTest(kind=kind):
                raw, selection, before, after = desktop_vector()
                if kind == "platform":
                    raw["platform"] = "linux"
                elif kind == "posix":
                    selection["sources"]["runner"]["path"] = "/private/source/runner"
                elif kind == "relative":
                    selection["sources"]["runner"]["path"] = "C:relative"
                elif kind == "traversal":
                    selection["sources"]["runner"]["path"] = "C:\\private\\..\\runner"
                elif kind == "context":
                    selection["docker_context"] = "default"
                elif kind == "bridge_bool":
                    selection["allow_empty_builtin_bridge_id_change"] = 1
                elif kind == "before_hash":
                    raw["before_sha256"] = "0" * 64
                elif kind == "after_hash":
                    raw["after_sha256"] = "0" * 64
                with self.assertRaisesRegex(
                    projection.ProjectionRefused, "^nm2_persistent_projection_refused$"
                ):
                    projection.project_desktop(raw, selection, before, after)

    def test_desktop_resource_guard_rejects_mutation_unowned_or_running_cleanup(self):
        for kind in (
            "old_mutation",
            "old_float",
            "unowned",
            "extra_owned",
            "running",
            "paused",
            "restarting",
            "dead",
            "image",
            "service",
            "worker_exit",
            "worker_start",
            "worker_finish",
            "old_cleanup",
        ):
            with self.subTest(kind=kind):
                raw, selection, before, after = desktop_vector()
                worker_id = raw["cases"]["persistent_availability"]["physical"][
                    "identity"
                ]["container_id"]
                worker = after["containers"][worker_id]
                old_id = next(iter(before["containers"]))
                if kind == "old_mutation":
                    after["containers"][old_id]["state"]["running"] = True
                elif kind == "old_float":
                    after["containers"][old_id]["state"]["exit_code"] = 0.0
                elif kind in {"unowned", "extra_owned"}:
                    new = copy.deepcopy(worker)
                    new["id"] = hashed("extra")
                    if kind == "unowned":
                        new["labels"] = {}
                    after["containers"][new["id"]] = new
                elif kind in {"running", "paused", "restarting", "dead"}:
                    worker["state"][kind] = True
                elif kind == "image":
                    worker["image"] = selection["images"]["db"]
                elif kind == "service":
                    worker["labels"]["com.docker.compose.service"] = "gate-fixture"
                elif kind == "worker_exit":
                    worker["state"]["exit_code"] = 0
                elif kind == "worker_start":
                    worker["state"]["started_at"] = "2026-11-06T01:58:00Z"
                elif kind == "worker_finish":
                    worker["state"]["finished_at"] = "2026-11-06T02:03:00Z"
                elif kind == "old_cleanup":
                    raw["fixture_stop"]["container_ids"][1] = old_id
                raw["after_sha256"] = host.digest(after)
                with self.assertRaises(projection.ProjectionRefused):
                    projection.project_desktop(raw, selection, before, after)

    def test_desktop_empty_bridge_admission_is_explicit_exact_and_semantic(self):
        for kind in (
            "not_explicit",
            "missing_diff",
            "attached",
            "nondefault",
            "bool_change",
        ):
            with self.subTest(kind=kind):
                raw, selection, before, after = desktop_vector(bridge_change=True)
                old = next(iter(before["networks"].values()))
                new = next(iter(after["networks"].values()))
                if kind == "not_explicit":
                    selection["allow_empty_builtin_bridge_id_change"] = False
                elif kind == "missing_diff":
                    raw["admitted_inventory_diffs"] = []
                elif kind == "attached":
                    new["containers"] = {hashed("attached"): {}}
                elif kind == "nondefault":
                    old["options"]["com.docker.network.bridge.default_bridge"] = "false"
                    new["options"]["com.docker.network.bridge.default_bridge"] = "false"
                elif kind == "bool_change":
                    new["internal"] = 0
                raw["before_sha256"], raw["after_sha256"] = (
                    host.digest(before),
                    host.digest(after),
                )
                with self.assertRaises(projection.ProjectionRefused):
                    projection.project_desktop(raw, selection, before, after)


if __name__ == "__main__":
    unittest.main()
