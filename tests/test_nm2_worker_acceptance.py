"""Source/protocol guards only; no Docker calls, real keys or target traffic."""

from contextlib import redirect_stdout
import copy
from datetime import datetime
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

import nm2_worker_acceptance as acceptance
import worker_runtime


class AcceptanceGuards(unittest.TestCase):
    def sequence_fixture(self):
        fixture = object.__new__(acceptance.Fixture)
        fixture.issuer_origin, fixture.secrets = (
            "https://map.example/backend",
            ["private-token-canary"],
        )
        identity = {
            "daemon_id": "owned-daemon",
            "container_id": "a" * 64,
            "image_id": "sha256:" + "b" * 64,
            "project": "vardrsec-nm2-sequence",
            "started_at": "2026-11-06T02:00:00.000000Z",
            "owner_nonce": "c" * 64,
        }
        runtime_id = "00000000-0000-4000-8000-000000000090"
        runner_id = "00000000-0000-4000-8000-000000000080"
        physical = {
            "identity": identity,
            "runtime_id": runtime_id,
            "runtime_sha256": acceptance.digest(acceptance.canonical(identity)),
            "exit_code": 0,
            "finished_at": "2026-11-06T02:01:00.000000Z",
            "operator_enable_state": "enabled",
        }
        runtime = {
            "id": runtime_id,
            "runtime_sha256": physical["runtime_sha256"],
            "identity": copy.deepcopy(identity),
            "runner_id": runner_id,
            "enrollment_id": "enrolled",
            "max_attempts": 2,
            "last_sequence": 2,
            "active_sequence": None,
            "retired": False,
            "report_sha256": None,
            "legacy_binding": dict.fromkeys(
                (
                    "job_id",
                    "contract_id",
                    "attempt_id",
                    "fence",
                    "contract_sha256",
                    "bound_at",
                    "confirmed_at",
                )
            ),
            "attempts": [],
        }
        selections, inventories, traffic, responses = [], [], [], {}
        for number in (1, 2):
            engagement, job, marker = (
                f"engagement-{number}",
                f"job-{number}",
                f"case-{number}",
            )
            case = {
                "spec": {
                    "id": marker,
                    "request": {
                        "method": "GET",
                        "url": acceptance.ORIGIN
                        + "/fixed/records/42?nm2_case="
                        + marker,
                    },
                }
            }
            case_sha = acceptance.digest(acceptance.canonical(case["spec"]))
            binding = {
                "origin": fixture.issuer_origin,
                "runner_id": runner_id,
                "job_id": job,
                "contract_id": f"contract-{number}",
                "attempt_id": f"attempt-{number}",
                "fence": 1,
                "contract_sha256": acceptance.digest(f"contract {number}".encode()),
            }
            artifact = acceptance.digest(f"artifact {number}".encode())
            result_sha = acceptance.digest(
                acceptance.canonical(
                    {
                        "schema": "vardr.managed-result/1",
                        **binding,
                        "artifact_sha256": artifact,
                        "case_sha256": case_sha,
                    }
                )
            )
            terminal = {
                "schema": "vardr.managed-completion/1",
                **binding,
                "receipt_sha256": result_sha,
                "outcome": "completed",
                "capacity_reserved": False,
            }
            terminal_sha = acceptance.digest(acceptance.canonical(terminal))
            native_sha = acceptance.digest(f"native done {number}".encode())
            release = {
                "schema": "vardr.worker-idle-release/1",
                "runtime_id": runtime_id,
                "runtime_sha256": physical["runtime_sha256"],
                "runtime_sequence": number,
                "binding": binding,
                "terminal_receipt_sha256": terminal_sha,
                "native_done_sha256": native_sha,
                "released": True,
            }
            release["receipt_sha256"] = acceptance.digest(acceptance.canonical(release))
            prefix = f"2026-11-06T02:00:0{number}."
            runtime["attempts"].append(
                {
                    "runtime_id": runtime_id,
                    "runtime_sequence": number,
                    "job_id": job,
                    "binding": binding,
                    "bound_at": prefix + "100000Z",
                    "confirmed_at": prefix + "200000Z",
                    "released_at": prefix + "300000Z",
                    "terminal_receipt": terminal,
                    "terminal_receipt_sha256": terminal_sha,
                    "native_done_sha256": native_sha,
                    "release_receipt": release,
                }
            )
            inventory = {
                "schema": "vardr.nm2-fixture-inventory/2",
                "schema_revision": "0040runtimesequence",
                "database_user": "vardrmap_app",
                "job_status": "done",
                "targets_spent": 1,
                "duration_allocated": 30,
                "execution": {
                    "state": "completed",
                    "capacity_reserved": False,
                    "target_charge": 1,
                    "duration_seconds": 30,
                },
                "contracts": [
                    {
                        "id": binding["contract_id"],
                        "attempt_id": binding["attempt_id"],
                        "ordinal": 1,
                        "fence": 1,
                        "consumed": True,
                        "contract_sha256": binding["contract_sha256"],
                    }
                ],
                "results": [
                    {
                        "contract_id": binding["contract_id"],
                        "artifact_sha256": artifact,
                        "receipt_sha256": result_sha,
                        "outcome": "completed",
                        "evidence_created": 5,
                        "scan_items_created": 0,
                    }
                ],
                "stops": [],
            }
            inventories.append(inventory)
            requests = [
                {
                    "identity": who,
                    "method": "GET",
                    "path": ("/session" if index < 2 else "/fixed/records/42")
                    + "?nm2_case="
                    + marker,
                    "received_monotonic_ns": number * 100 + index,
                }
                for index, who in enumerate(
                    ("owner", "peer", "owner", "peer", "anonymous")
                )
            ]
            traffic.append(requests)
            assessment = {
                "status": "conclusive",
                "baseline_valid": True,
                "case_snapshot_verified": True,
                "preflight": {"status": "passed"},
                "case_hash": case_sha,
                "candidate_findings": 0,
            }
            base = "/engagements/" + engagement
            responses[base + "/jobs"] = {
                "jobs": [{"id": job, "assessment": assessment}]
            }
            responses[base + "/scans?job_id=" + job] = {"scans": []}
            evidence = [
                {"body": f"public evidence {number}-{index}"} for index in range(5)
            ]
            for row in evidence:
                row["content_hash"] = acceptance.digest(row["body"].encode())
            responses[base + "/evidence?job_id=" + job] = {"evidence": evidence}
            selections.append((engagement, job, case))
        for inventory in inventories:
            inventory["runtimes"] = [copy.deepcopy(runtime)]
        fixture.api = Mock()
        fixture.api.request.side_effect = lambda route: responses[route]
        return SimpleNamespace(
            fixture=fixture,
            physical=physical,
            runner_id=runner_id,
            selections=selections,
            inventories=inventories,
            traffic=traffic,
        )

    def measure_sequence(self, data):
        proofs, measured = [], []
        for selection, inventory, requests in zip(
            data.selections, data.inventories, data.traffic
        ):
            proof, attempt = data.fixture.verify_fixed(
                *selection,
                data.physical,
                {"job_status": "pending"},
                requests,
                inventory,
            )
            proofs.append(proof)
            measured.append(attempt)
        return proofs, data.fixture.verify_healthy_sequence(
            data.physical, measured, data.inventories, data.runner_id, "enrolled"
        )

    def test_two_distinct_healthy_jobs_require_one_exact_idle_runtime_and_full_receipts(
        self,
    ):
        proofs, measured = self.measure_sequence(self.sequence_fixture())
        self.assertEqual([len(proof["requests"]) for proof in proofs], [5, 5])
        self.assertEqual(measured["target_request_count"], 10)
        self.assertEqual(measured["evidence_count"], 10)
        self.assertEqual(
            (measured["targets_spent"], measured["duration_allocated"]), (2, 60)
        )
        self.assertEqual(
            [row["runtime_sequence"] for row in measured["attempts"]], [1, 2]
        )
        self.assertIsNone(measured["active_sequence"])
        for row in measured["attempts"]:
            self.assertNotEqual(
                row["terminal_receipt_sha256"], row["result_receipt_sha256"]
            )

    def cancellation_fixture(self, scenario="local-emergency-stop"):
        data = self.sequence_fixture()
        fixture = data.fixture
        fixture.scenario = scenario
        engagement, job, case = data.selections[0]
        inventory = data.inventories[0]
        inventory.update(job_status="failed", results=[])
        runtime = inventory["runtimes"][0]
        runtime.update(
            max_attempts=1,
            last_sequence=1,
            active_sequence=1,
            retired=True,
            report_sha256="e" * 64,
        )
        runtime["attempts"] = runtime["attempts"][:1]
        attempt = runtime["attempts"][0]
        attempt.update(
            released_at=None,
            release_receipt=None,
            native_done_sha256=None,
            terminal_receipt=None,
            terminal_receipt_sha256=None,
        )
        binding = attempt["binding"]
        cause = (
            "local_emergency_stop"
            if scenario == "local-emergency-stop"
            else "remote_stop_requested"
        )
        stop_sha = acceptance.digest(
            acceptance.canonical(
                {
                    "schema": "vardr.managed-stop/1",
                    **binding,
                    "outcome": "cancelled",
                    "cause": cause,
                    "termination_confirmed": True,
                }
            )
        )
        terminal = {
            "schema": "vardr.managed-stop-receipt/1",
            **binding,
            "outcome": "cancelled",
            "cause": cause,
            "receipt_sha256": stop_sha,
            "capacity_reserved": False,
        }
        inventory["stops"] = [
            {
                "contract_id": binding["contract_id"],
                "outcome": "cancelled",
                "cause": cause,
                "receipt_sha256": stop_sha,
            }
        ]
        inventory["execution"]["state"] = "cancelled"
        retirement = {
            "schema": "vardr.worker-retirement/2",
            "runtime_id": runtime["id"],
            "runtime_sha256": runtime["runtime_sha256"],
            "origin": fixture.issuer_origin,
            "runner_id": runtime["runner_id"],
            "enrollment_id": runtime["enrollment_id"],
            "runtime_sequence": 1,
            "last_sequence": 1,
            "binding": binding,
            "attempt_receipt": terminal,
            "report_sha256": runtime["report_sha256"],
            "retired": True,
        }
        retirement["receipt_sha256"] = acceptance.digest(
            acceptance.canonical(retirement)
        )
        requests = data.traffic[0][:3]
        local = {
            "run_id": "original-run",
            "job_id": job,
            "engagement_id": engagement,
            "consumption_sent": 1,
            "consumption_acknowledged": 1,
            "local_stop_requested": scenario == "local-emergency-stop",
            "partial_files": [],
            "private_extra": "private-local-canary",
        }
        data.physical["exit_code"] = 125
        return fixture, [
            engagement,
            job,
            case,
            data.physical,
            inventory,
            {"run_id": "original-run", "requests": requests},
            {
                "requests": copy.deepcopy(requests),
                "observed_monotonic_ns": requests[-1]["received_monotonic_ns"]
                + 4_000_000_000,
            },
            retirement,
            local,
            {"state": "terminal_cancelled", "remaining_local_holds": 0},
        ]

    def test_cancellation_proof_is_bounded_retains_accounting_and_does_not_invent_partial_result(
        self,
    ):
        for scenario in ("local-emergency-stop", "stop-work"):
            with self.subTest(scenario=scenario):
                fixture, values = self.cancellation_fixture(scenario)
                proof = fixture.verify_cancellation(*values)
                self.assertEqual(proof["status"], "passed")
                self.assertEqual(proof["target_request_count"], 3)
                self.assertEqual(proof["resource_to_exit_observation_seconds"], 4)
                self.assertEqual(proof["partial_result_state"], "not_emitted")
                self.assertEqual(proof["partial_files"], [])
                self.assertEqual(proof["forced_uncooperative_child_test"], "not_run")
                self.assertNotIn("private-", json.dumps(proof))
                self.assertTrue(all("path" not in row for row in proof["requests"]))

    def failed_partial_fixture(self):
        fixture, values = self.cancellation_fixture()
        engagement, job, case, _, inventory, _, _, retirement, local, reconciled = (
            values
        )
        binding = retirement["binding"]
        case_sha = acceptance.digest(acceptance.canonical(case["spec"]))
        artifact_sha = "f" * 64
        local.update(
            phase="failed",
            status="failed",
            last_event="managed_completion_receipt",
            failure_reason="local_emergency_stop",
            partial_result={
                "error": "execution_cancelled",
                "case_sha256": case_sha,
                "execution_count": 1,
                "preflight_count": 2,
                "finding_count": 0,
                "cancelled_execution_count": 1,
                "passed_preflight_count": 2,
            },
            partial_files=[
                {"name": "vardrgate_result.json", "size": 123, "sha256": "a" * 64},
                {
                    "name": "vardrgate_stopped_result.json",
                    "size": 234,
                    "sha256": artifact_sha,
                },
            ],
        )
        result_sha = acceptance.digest(
            acceptance.canonical(
                {
                    "schema": "vardr.managed-result/1",
                    **binding,
                    "artifact_sha256": artifact_sha,
                    "case_sha256": case_sha,
                }
            )
        )
        inventory.update(
            stops=[],
            results=[
                {
                    "contract_id": binding["contract_id"],
                    "artifact_sha256": artifact_sha,
                    "receipt_sha256": result_sha,
                    "outcome": "failed",
                    "evidence_created": 3,
                    "scan_items_created": 0,
                }
            ],
        )
        inventory["execution"]["state"] = "failed"
        retirement["attempt_receipt"] = {
            "schema": "vardr.managed-completion/1",
            **binding,
            "receipt_sha256": result_sha,
            "outcome": "failed",
            "capacity_reserved": False,
        }
        retirement["receipt_sha256"] = acceptance.digest(
            acceptance.canonical(
                {
                    key: item
                    for key, item in retirement.items()
                    if key != "receipt_sha256"
                }
            )
        )
        reconciled["state"] = "terminal_failed"
        evidence = []
        for detail in (
            {"phase": "identity_preflight", "status": "passed"},
            {"phase": "identity_preflight", "status": "passed"},
            {"error": "execution_cancelled"},
        ):
            body = json.dumps(detail)
            evidence.append(
                {"body": body, "content_hash": acceptance.digest(body.encode())}
            )
        responses = {
            f"/engagements/{engagement}/jobs": {
                "jobs": [
                    {
                        "id": job,
                        "assessment": {
                            "status": "inconclusive",
                            "baseline_valid": False,
                            "case_snapshot_verified": True,
                            "case_hash": case_sha,
                            "preflight": {"status": "passed"},
                            "candidate_findings": 0,
                        },
                    }
                ]
            },
            f"/engagements/{engagement}/evidence?job_id={job}": {"evidence": evidence},
            f"/engagements/{engagement}/scans?job_id={job}": {"scans": []},
        }
        fixture.api.request.side_effect = lambda route: responses[route]
        return fixture, values, responses

    def test_failed_partial_is_case_bound_inconclusive_evidence_without_stop_or_release(
        self,
    ):
        fixture, values, _ = self.failed_partial_fixture()
        proof = fixture.verify_cancellation(*values)
        self.assertEqual(proof["failed_completion"]["evidence_count"], 3)
        self.assertEqual(
            proof["failed_completion"]["assessment_status"], "inconclusive"
        )
        self.assertIsNone(proof["stop_receipt_sha256"])
        self.assertFalse(proof["native_stop_receipt"])
        self.assertEqual(proof["partial_result_state"], "retained")
        for mutation in (
            "success",
            "wrong_artifact",
            "wrong_case",
            "not_cancelled",
            "missing_original",
            "conclusive",
            "evidence_hash",
            "evidence_canary",
        ):
            with self.subTest(mutation=mutation):
                fixture, values, responses = self.failed_partial_fixture()
                inventory, retirement, local = values[4], values[7], values[8]
                base = "/engagements/" + values[0]
                if mutation == "success":
                    retirement["attempt_receipt"]["outcome"] = "completed"
                elif mutation == "wrong_artifact":
                    inventory["results"][0]["artifact_sha256"] = "b" * 64
                elif mutation == "wrong_case":
                    local["partial_result"]["case_sha256"] = "b" * 64
                elif mutation == "not_cancelled":
                    local["partial_result"]["cancelled_execution_count"] = 0
                elif mutation == "missing_original":
                    local["partial_files"] = local["partial_files"][1:]
                elif mutation == "conclusive":
                    responses[base + "/jobs"]["jobs"][0]["assessment"]["status"] = (
                        "conclusive"
                    )
                elif mutation == "evidence_hash":
                    responses[base + "/evidence?job_id=" + values[1]]["evidence"][0][
                        "content_hash"
                    ] = "b" * 64
                else:
                    row = responses[base + "/evidence?job_id=" + values[1]]["evidence"][
                        0
                    ]
                    row["body"] = json.dumps({"secret": fixture.secrets[0]})
                    row["content_hash"] = acceptance.digest(row["body"].encode())
                with self.assertRaises(acceptance.AcceptanceRefused):
                    fixture.verify_cancellation(*values)

    def test_cancellation_refuses_timeout_unrelated_failure_reuse_missing_proof_and_raw_fields(
        self,
    ):
        for mutation in (
            "timeout",
            "extra_dispatch",
            "result",
            "unconsumed",
            "reused",
            "wrong_runtime",
            "bad_retirement",
            "holds",
            "missing_marker",
            "raw_header",
            "partial_canary",
            "boolean_fence",
            "physical_success",
            "physical_extra",
            "unrelated_cause",
        ):
            with self.subTest(mutation=mutation):
                fixture, values = self.cancellation_fixture()
                inventory, action, after, retirement, local, reconciled = values[4:]
                if mutation == "timeout":
                    after["observed_monotonic_ns"] += 16_000_000_000
                elif mutation == "extra_dispatch":
                    after["requests"].append(copy.deepcopy(after["requests"][-1]))
                elif mutation == "result":
                    inventory["results"] = [{"outcome": "completed"}]
                elif mutation == "unconsumed":
                    inventory["contracts"][0]["consumed"] = False
                elif mutation == "reused":
                    inventory["runtimes"][0]["last_sequence"] = 2
                elif mutation == "wrong_runtime":
                    inventory["runtimes"][0]["identity"]["container_id"] = "f" * 64
                elif mutation == "bad_retirement":
                    retirement["runtime_sequence"] = None
                elif mutation == "holds":
                    reconciled["remaining_local_holds"] = 1
                elif mutation == "missing_marker":
                    local["local_stop_requested"] = False
                elif mutation == "raw_header":
                    for rows in (action["requests"], after["requests"]):
                        rows[0]["headers"] = {"Authorization": "private-header-canary"}
                elif mutation == "partial_canary":
                    local["partial_files"] = [
                        {"name": "private-path-canary", "size": 1, "sha256": "a" * 64}
                    ]
                elif mutation == "boolean_fence":
                    inventory["contracts"][0]["fence"] = True
                elif mutation == "physical_success":
                    values[3]["exit_code"] = 0
                elif mutation == "physical_extra":
                    values[3]["raw_log"] = "private-physical-canary"
                elif mutation == "unrelated_cause":
                    inventory["stops"][0]["cause"] = "tool_timeout"
                with self.assertRaises(acceptance.AcceptanceRefused):
                    fixture.verify_cancellation(*values)

    def test_each_scenario_source_validation_is_explicit_and_never_contacts_docker(
        self,
    ):
        for scenario in (
            "local-emergency-stop",
            "stop-work",
            "missing-local-grant",
            "active-target-grant-revoked",
        ):
            with (
                self.subTest(scenario=scenario),
                tempfile.TemporaryDirectory() as temporary,
            ):
                selection = self.selection(Path(temporary))
                path = Path(temporary) / "cohort.json"
                path.write_text(json.dumps(selection))
                output = io.StringIO()
                with (
                    patch.object(acceptance, "command", side_effect=self.git_only),
                    patch.object(
                        acceptance.Fixture,
                        "run",
                        side_effect=AssertionError("no execution"),
                    ),
                    redirect_stdout(output),
                ):
                    self.assertEqual(
                        acceptance.main(
                            ["--cohort", str(path), "--scenario", scenario]
                        ),
                        0,
                    )
                receipt = json.loads(output.getvalue())
                self.assertEqual(receipt["scenario"], scenario)
                self.assertEqual(receipt["docker_calls"], 0)
                fixture = acceptance.Fixture(selection, scenario=scenario)
                self.assertEqual(fixture.max_attempts, 1)
                self.assertEqual(fixture.receipt["nm2_exit_status"], "incomplete")
                self.assertNotEqual(
                    fixture.receipt["schema"], "vardr.nm2-worker-acceptance/2"
                )
                self.assertEqual(
                    fixture.receipt["cases"][
                        "missing_local_grant"
                        if scenario == "missing-local-grant"
                        else scenario
                    ],
                    {"status": "not_run"},
                )

    def test_cancellation_actions_use_only_original_run_marker_or_owner_stop_work(self):
        for scenario in (
            "local-emergency-stop",
            "stop-work",
            "active-target-grant-revoked",
        ):
            with self.subTest(scenario=scenario):
                fixture, values = self.cancellation_fixture(scenario)
                engagement, job, case = values[:3]
                run_id = "0123456789abcdef" * 2
                active = {
                    "run_id": run_id,
                    "job_id": job,
                    "phase": "executing",
                    "backend_url": fixture.issuer_origin,
                    "command_profile": {"controlled": True},
                }
                fixture.timed_traffic = Mock(return_value=values[6])
                fixture.helper = Mock(return_value=acceptance.canonical([active]))
                fixture.api = Mock()
                fixture.api.request.return_value = {
                    "stop_work_at": "2026-11-06T02:00:00Z"
                }
                fixture.receipt = {}
                action = fixture.cancellation_action(engagement, job, case)
                self.assertEqual(action["run_id"], run_id)
                first = fixture.helper.call_args_list[0]
                self.assertEqual(
                    first.args, ("audit", "list", "--json", "--engagement", engagement)
                )
                if scenario == "local-emergency-stop":
                    self.assertEqual(
                        fixture.helper.call_args_list[1].args, ("jobs", "stop", run_id)
                    )
                    fixture.api.request.assert_not_called()
                elif scenario == "stop-work":
                    self.assertEqual(fixture.helper.call_count, 1)
                    fixture.api.request.assert_called_once_with(
                        f"/engagements/{engagement}/stop-work",
                        {"reason": "NM2 controlled HTTP fixture"},
                    )
                else:
                    self.assertEqual(
                        fixture.helper.call_args_list[1].args,
                        (
                            "credentials",
                            "revoke",
                            "--engagement",
                            engagement,
                            "--origin",
                            acceptance.ORIGIN,
                            "--env",
                            "FIXTURE_OWNER_TOKEN",
                            "--issuer",
                            fixture.issuer_origin,
                        ),
                    )
                    fixture.api.request.assert_not_called()
                self.assertNotIn("pid", str(fixture.helper.call_args_list).lower())
                fixture.timed_traffic.return_value["requests"].append(
                    copy.deepcopy(values[6]["requests"][-1])
                )
                fixture.helper.reset_mock()
                fixture.api.reset_mock()
                with self.assertRaisesRegex(
                    acceptance.AcceptanceRefused, "advanced_before_action"
                ):
                    fixture.cancellation_action(engagement, job, case)
                fixture.helper.assert_not_called()
                fixture.api.request.assert_not_called()

    def grant_catalogs(self, fixture, engagement):
        before = {
            "policy_reason": "granted",
            "grants": [
                {
                    "issuer": fixture.issuer_origin,
                    "engagement_id": engagement,
                    "origin": acceptance.ORIGIN,
                    "source": "env",
                    "name": "FIXTURE_" + who + "_TOKEN",
                    "id": str(number) * 8 + "-0000-4000-8000-" + str(number) * 12,
                    "issued_at": "2026-11-06T02:00:00.000000+00:00",
                    "expires_at": "2026-11-06T02:10:00.000000+00:00",
                    "status": "active",
                }
                for number, who in enumerate(("OWNER", "PEER"), 1)
            ],
        }
        after = copy.deepcopy(before)
        after["policy_reason"] = "grant_expired_or_revoked"
        after["grants"][0]["status"] = "revoked"
        return before, after

    def test_active_grant_revocation_requires_same_public_grant_and_original_peer(self):
        fixture, values = self.cancellation_fixture("active-target-grant-revoked")
        before, after = self.grant_catalogs(fixture, values[0])
        values[5].update(grant_before=before, grant_after=after)
        proof = fixture.verify_cancellation(*values)
        self.assertEqual(
            proof["grant_revocation"]["grant_id"], before["grants"][0]["id"]
        )
        self.assertEqual(
            proof["grant_revocation"]["policy_reason"], "grant_expired_or_revoked"
        )
        self.assertFalse(proof["local_stop_requested"])
        for mutation in ("replacement", "peer", "scope", "policy", "raw_secret"):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(after)
                if mutation == "replacement":
                    changed["grants"][0]["id"] = "f" * 36
                elif mutation == "peer":
                    changed["grants"][1]["status"] = "revoked"
                elif mutation == "scope":
                    changed["grants"][0]["origin"] = "http://other.test"
                elif mutation == "policy":
                    changed["policy_reason"] = "granted"
                else:
                    changed["grants"][0]["raw_secret"] = "private-catalog-canary"
                with self.assertRaises(acceptance.AcceptanceRefused):
                    fixture.verify_grant_revocation(values[0], before, changed)

    def missing_grant_fixture(self):
        data = self.sequence_fixture()
        fixture, physical = data.fixture, data.physical
        physical["exit_code"] = 125
        inventory = data.inventories[0]
        inventory.update(
            job_id="job-1",
            job_status="pending",
            execution=None,
            targets_spent=0,
            duration_allocated=0,
            approvals=[{"id": "approved", "issued": 0, "revoked": False}],
            contracts=[],
            results=[],
            stops=[],
            runtimes=[],
        )
        expected = {
            "schema": "vardr.worker-retirement/2",
            "runtime_id": physical["runtime_id"],
            "runtime_sha256": physical["runtime_sha256"],
            "origin": fixture.issuer_origin,
            "runner_id": data.runner_id,
            "enrollment_id": "enrolled",
            "runtime_sequence": None,
            "last_sequence": 0,
            "binding": None,
            "attempt_receipt": None,
            "report_sha256": "d" * 64,
            "retired": True,
        }
        retirement = {
            **expected,
            "receipt_sha256": acceptance.digest(acceptance.canonical(expected)),
        }
        local = dict.fromkeys(
            (
                "runs",
                "claims",
                "contracts",
                "fences",
                "attempts",
                "remaining_local_holds",
            ),
            0,
        )
        local["incarnation"] = {
            "runtime_id": physical["runtime_id"],
            "runtime_sha256": physical["runtime_sha256"],
            "max_attempts": 1,
            "last_sequence": 0,
            "active_sequence": None,
            "state": "idle",
            "retirement": None,
        }
        return fixture, [
            "job-1",
            data.runner_id,
            "enrolled",
            physical,
            inventory,
            retirement,
            local,
            {"grants": [], "policy_reason": "grant_missing_or_replaced"},
            [],
        ]

    def test_missing_grant_proves_zero_claim_without_creating_a_journal_record(self):
        fixture, values = self.missing_grant_fixture()
        proof = fixture.verify_missing_grant(*values)
        self.assertEqual(proof["journal_run_count"], 0)
        self.assertEqual(proof["local_reconciliation"], "not_required_no_run")
        self.assertEqual(proof["runtime_last_sequence"], 0)
        for mutation in (
            "traffic",
            "issued",
            "contract",
            "history",
            "local_record",
            "grant_present",
            "hold",
        ):
            with self.subTest(mutation=mutation):
                fixture, changed = self.missing_grant_fixture()
                if mutation == "traffic":
                    changed[-1].append({"identity": "owner"})
                elif mutation == "issued":
                    changed[4]["approvals"][0]["issued"] = 1
                elif mutation == "contract":
                    changed[4]["contracts"] = [{"id": "issued"}]
                elif mutation == "history":
                    changed[5]["last_sequence"] = 1
                elif mutation == "local_record":
                    changed[6]["runs"] = 1
                elif mutation == "grant_present":
                    changed[7]["policy_reason"] = "granted"
                else:
                    changed[6]["remaining_local_holds"] = 1
                with self.assertRaises(acceptance.AcceptanceRefused):
                    fixture.verify_missing_grant(*changed)

    def test_missing_grant_flow_observes_without_fabricating_run_or_reconciliation(
        self,
    ):
        fixture, values = self.missing_grant_fixture()
        (
            job,
            runner,
            enrollment,
            physical,
            inventory,
            retirement,
            local,
            grants,
            traffic,
        ) = values
        fixture.scenario = "missing-local-grant"
        fixture.receipt = {"cases": {"missing_local_grant": {"status": "not_run"}}}
        fixture.new_job = Mock(return_value=("eng", "authorization", job, {"spec": {}}))
        fixture.approve = Mock(return_value=(runner, enrollment))
        fixture.grant_snapshot = Mock(return_value=grants)
        fixture.helper = Mock(return_value=b"authenticated public identity")
        fixture.traffic = Mock(return_value=traffic)
        fixture.worker = Mock(return_value=physical)
        fixture.report_exit = Mock(return_value=retirement)
        fixture.inventory = Mock(return_value=inventory)
        fixture.unclaimed_metadata = Mock(return_value=local)
        fixture.missing_grant()
        self.assertEqual(
            fixture.receipt["cases"]["missing_local_grant"]["status"], "passed"
        )
        self.assertEqual(
            [call.args for call in fixture.helper.call_args_list],
            [("whoami",), ("whoami",)],
        )
        self.assertFalse(fixture.approve.call_args.kwargs["local_grants"])
        fixture.worker.assert_called_once_with(runner, enrollment)
        fixture.unclaimed_metadata.assert_called_once_with("eng", job, physical)
        self.assertEqual(fixture.receipt["observed_failure"]["local"]["runs"], 0)

    def test_cancellation_run_id_requires_actual_journal_hex_format_before_stop(self):
        for run_id in ("00000000-0000-4000-8000-000000000099", "a" * 31, "A" * 32):
            with self.subTest(run_id=run_id):
                fixture, values = self.cancellation_fixture()
                engagement, job, case = values[:3]
                fixture.timed_traffic = Mock(return_value=values[6])
                fixture.helper = Mock(
                    return_value=acceptance.canonical(
                        [
                            {
                                "run_id": run_id,
                                "job_id": job,
                                "phase": "executing",
                                "backend_url": fixture.issuer_origin,
                                "command_profile": {"controlled": True},
                            }
                        ]
                    )
                )
                fixture.receipt = {}
                with self.assertRaisesRegex(
                    acceptance.AcceptanceRefused, "cancellation_run_id_invalid"
                ):
                    fixture.cancellation_action(engagement, job, case)
                fixture.helper.assert_called_once_with(
                    "audit", "list", "--json", "--engagement", engagement
                )

    def test_retained_partial_helper_exports_only_hash_and_original_ack_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            runs = Path(temporary) / "runs"
            directory = runs / "managed-original"
            directory.mkdir(parents=True)
            raw = b'{"private_body":"private-file-canary"}'
            (directory / "vardrgate_result.json").write_bytes(raw)
            record = SimpleNamespace(
                run_id="run",
                job_id="job",
                engagement_id="eng",
                run_dir=str(directory),
                phase=SimpleNamespace(value="executing"),
                status="cancelled",
            )
            claim = {
                "state": "stop_closed",
                "consumption_sent": 1,
                "consumption_acknowledged": 1,
            }
            connection = MagicMock()
            connection.__enter__.return_value.execute.return_value.fetchone.return_value = claim
            journal = Mock()
            journal.get.return_value = record
            journal._connection.return_value = connection
            journal.stop_requested.return_value = True
            package = SimpleNamespace(
                config=SimpleNamespace(
                    journal_file=lambda: "fixture-journal", runs_dir=lambda: runs
                )
            )
            journal_module = SimpleNamespace(Journal=lambda path: journal)
            fixture = object.__new__(acceptance.Fixture)

            def helper(*args, **kwargs):
                self.assertEqual(args[:2], ("-I", "-c"))
                self.assertTrue(kwargs["python"])
                output = io.StringIO()
                with (
                    patch.dict(
                        sys.modules,
                        {"vardrrunner": package, "vardrrunner.journal": journal_module},
                    ),
                    patch("sys.stdin", io.StringIO(kwargs["stdin"].decode())),
                    patch.object(
                        os, "O_NOFOLLOW", getattr(os, "O_NOFOLLOW", 0), create=True
                    ),
                    patch.object(
                        os, "O_NONBLOCK", getattr(os, "O_NONBLOCK", 0), create=True
                    ),
                    redirect_stdout(output),
                ):
                    exec(compile(args[2], "fixed_metadata_helper", "exec"), {})
                return output.getvalue().encode()

            fixture.helper = helper
            metadata = fixture.local_metadata("run", "eng", "job")
            self.assertEqual(
                metadata["partial_files"],
                [
                    {
                        "name": "vardrgate_result.json",
                        "size": len(raw),
                        "sha256": acceptance.digest(raw),
                    }
                ],
            )
            self.assertEqual(metadata["consumption_acknowledged"], 1)
            self.assertNotIn("private-", json.dumps(metadata))
            self.assertNotIn(str(directory), json.dumps(metadata))
            stopped = {
                "error": "execution_cancelled",
                "case_hash": "a" * 64,
                "executions": [
                    {
                        "error": "execution_cancelled",
                        "private_body": "private-stopped-canary",
                    }
                ],
                "preflight": [{"status": "passed"}, {"status": "passed"}],
                "findings": [],
            }
            (directory / "vardrgate_stopped_result.json").write_bytes(
                acceptance.canonical(stopped)
            )
            metadata = fixture.local_metadata("run", "eng", "job")
            self.assertEqual(len(metadata["partial_files"]), 2)
            self.assertEqual(metadata["partial_result"]["cancelled_execution_count"], 1)
            self.assertEqual(metadata["partial_result"]["passed_preflight_count"], 2)
            self.assertNotIn("private-", json.dumps(metadata))
            record.job_id = "different-job"
            with self.assertRaises(AssertionError):
                fixture.local_metadata("run", "eng", "job")

    def test_sequence_proof_refuses_changed_identity_reuse_wrong_markers_and_missing_release(
        self,
    ):
        for change in (
            "identity",
            "active",
            "history",
            "release_order",
            "marker",
            "artifact",
            "full_completion",
            "release_hash",
            "legacy_binding",
        ):
            with self.subTest(change=change):
                data = self.sequence_fixture()
                if change == "identity":
                    data.physical["identity"]["container_id"] = "d" * 64
                elif change == "marker":
                    data.traffic[1][0]["path"] = "/session?nm2_case=case-1"
                elif change == "artifact":
                    data.inventories[1]["results"][0]["artifact_sha256"] = (
                        data.inventories[0]["results"][0]["artifact_sha256"]
                    )
                else:
                    for inventory in data.inventories:
                        runtime = inventory["runtimes"][0]
                        if change == "active":
                            runtime["active_sequence"] = 2
                        elif change == "history":
                            runtime["attempts"][1]["runtime_sequence"] = 1
                        elif change == "release_order":
                            runtime["attempts"][0]["released_at"] = (
                                "2026-11-06T02:00:03.000000Z"
                            )
                        elif change == "full_completion":
                            runtime["attempts"][0]["terminal_receipt_sha256"] = runtime[
                                "attempts"
                            ][0]["terminal_receipt"]["receipt_sha256"]
                        elif change == "release_hash":
                            runtime["attempts"][1]["release_receipt"][
                                "receipt_sha256"
                            ] = "f" * 64
                        elif change == "legacy_binding":
                            runtime["legacy_binding"]["job_id"] = "job-1"
                with self.assertRaises(acceptance.AcceptanceRefused):
                    self.measure_sequence(data)

    def test_one_worker_uses_actual_v2_observer_and_explicit_bounded_cli_enable(self):
        with tempfile.TemporaryDirectory() as temporary:
            selection = self.selection(Path(temporary))
            fixture = acceptance.Fixture(selection)
            fixture.install.mkdir()
            fixture.private.mkdir()
            fixture.trust, fixture.password = [], "synthetic test password"
            fixture.issuer_origin = "https://map.example/backend"
            identity = worker_runtime.RuntimeIdentity(
                "daemon",
                "a" * 64,
                fixture.images["worker"],
                fixture.project,
                "2026-11-06T02:00:00.000000Z",
                "c" * 64,
            )
            observer = Mock()
            observer.capture_running.return_value = identity
            order = []

            def observe_exit(selected):
                order.append("actual_exit_observation")
                return SimpleNamespace(
                    exit_code=0, finished_at="2026-11-06T02:01:00.000000Z"
                )

            observer.observe_exit.side_effect = observe_exit
            fixture.compose = Mock(
                side_effect=lambda *args, **kwargs: (
                    identity.container_id.encode() if "ps" in args else b""
                )
            )
            admission = {
                "schema": "vardr.worker-admission/2",
                "max_attempts": 2,
                "runtime_id": "runtime",
                "runtime_sha256": acceptance.digest(
                    acceptance.canonical(acceptance.asdict(identity))
                ),
            }

            def command(arguments, **kwargs):
                self.assertEqual(arguments[arguments.index("--max-attempts") + 1], "2")
                (fixture.install / "worker-public" / "admission.json").write_bytes(
                    acceptance.canonical(admission)
                )
                return acceptance.canonical(
                    {
                        "schema": "vardr.worker-cli/1",
                        "state": "enabled",
                        "identity": acceptance.asdict(identity),
                        **{
                            key: admission[key]
                            for key in ("runtime_id", "runtime_sha256")
                        },
                    }
                )

            with (
                patch.object(
                    worker_runtime, "LocalDocker", return_value=observer
                ) as constructor,
                patch.object(acceptance, "command", side_effect=command) as cli,
            ):
                result = fixture.worker(
                    "runner",
                    "enrolled",
                    on_running=lambda selected: (
                        order.append("admitted_action")
                        if selected == admission
                        else self.fail("admission changed")
                    ),
                )
            self.assertEqual(constructor.call_args.kwargs, {"max_attempts": 2})
            cli.assert_called_once()
            observer.observe_exit.assert_called_once_with(identity)
            self.assertEqual(order, ["admitted_action", "actual_exit_observation"])
            self.assertEqual(result["identity"], acceptance.asdict(identity))
            self.assertEqual(
                sum("up" in call.args for call in fixture.compose.call_args_list), 1
            )

    def test_readonly_inventory_finds_v2_history_when_legacy_binding_is_null(self):
        data = self.sequence_fixture()
        chosen = data.inventories[0]
        public = chosen["runtimes"][0]
        names = (
            "Engagement",
            "JobExecution",
            "ManagedApproval",
            "ManagedContract",
            "ManagedResult",
            "ManagedRuntime",
            "ManagedRuntimeAttempt",
            "ManagedStop",
            "ScanJob",
        )
        models = {name: type(name, (), {"runtime_sequence": 0}) for name in names}
        runtime = SimpleNamespace(
            **{key: value for key, value in public.items() if key != "legacy_binding"},
            **public["legacy_binding"],
            origin=data.fixture.issuer_origin,
            capability_sha256="private-stop-canary",
        )
        attempts = []
        for row in public["attempts"]:
            values = {
                key: value
                for key, value in row.items()
                if key not in {"binding", "bound_at", "confirmed_at", "released_at"}
            }
            values.update(
                {
                    key: row["binding"][key]
                    for key in ("contract_id", "attempt_id", "fence", "contract_sha256")
                }
            )
            values.update(
                {
                    key: datetime.fromisoformat(row[key].replace("Z", "+00:00"))
                    for key in ("bound_at", "confirmed_at", "released_at")
                }
            )
            attempts.append(SimpleNamespace(**values))
        records = {
            models["ManagedRuntimeAttempt"]: attempts,
            models["ManagedRuntime"]: [runtime],
            models["ManagedContract"]: [
                SimpleNamespace(
                    **chosen["contracts"][0],
                    job_id="job-1",
                    envelope={"private": "private-envelope-canary"},
                )
            ],
            models["ManagedResult"]: [
                SimpleNamespace(**chosen["results"][0], job_id="job-1")
            ],
        }
        filters, statements = [], []

        class Query:
            def __init__(self, model, rows):
                self.model, self.rows, self.bound = model, list(rows), None

            def filter_by(self, **values):
                filters.append((self.model.__name__, values))
                self.rows = [
                    row
                    for row in self.rows
                    if all(getattr(row, key) == value for key, value in values.items())
                ]
                return self

            def order_by(self, *unused):
                self.rows.sort(key=lambda row: row.runtime_sequence)
                return self

            def limit(self, bound):
                self.bound = bound
                return self

            def all(self):
                return self.rows if self.bound is None else self.rows[: self.bound]

        class Database:
            def __init__(self):
                self.rolled_back = False

            def __enter__(self):
                return self

            def __exit__(self, *unused):
                return False

            def execute(self, statement):
                statements.append(statement)
                return SimpleNamespace(
                    scalar_one=lambda: (
                        "0040runtimesequence"
                        if "version_num" in statement
                        else "vardrmap_app"
                    )
                )

            def get(self, model, identifier):
                if model is models["Engagement"]:
                    return SimpleNamespace(
                        id=identifier, targets_spent=1, duration_allocated=30
                    )
                if model is models["ScanJob"]:
                    return SimpleNamespace(
                        id=identifier, program_id="engagement-1", status="done"
                    )
                if model is models["JobExecution"]:
                    return SimpleNamespace(**chosen["execution"])
                if model is models["ManagedRuntime"] and identifier == runtime.id:
                    return runtime
                return None

            def query(self, model):
                return Query(model, records.get(model, []))

            def rollback(self):
                self.rolled_back = True

        database = Database()
        source = Path(acceptance.__file__).with_name("nm2_worker_inventory.py")
        spec = importlib.util.spec_from_file_location("nm2_inventory_unit", source)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(
            sys.modules,
            {
                "models": SimpleNamespace(**models),
                "db": SimpleNamespace(SessionLocal=lambda: database),
                "sqlalchemy": SimpleNamespace(text=lambda value: value),
            },
        ):
            spec.loader.exec_module(module)
            observed = module.observe(
                {"engagement_id": "engagement-1", "job_id": "job-1"}
            )
        self.assertEqual(statements[0], "SET TRANSACTION READ ONLY")
        self.assertTrue(database.rolled_back)
        self.assertIn(("ManagedRuntimeAttempt", {"job_id": "job-1"}), filters)
        self.assertNotIn(("ManagedRuntime", {"job_id": "job-1"}), filters)
        self.assertEqual(len(observed["runtimes"]), 1)
        self.assertEqual(
            [row["runtime_sequence"] for row in observed["runtimes"][0]["attempts"]],
            [1, 2],
        )
        self.assertTrue(
            all(
                value is None
                for value in observed["runtimes"][0]["legacy_binding"].values()
            )
        )
        self.assertNotIn("private-", json.dumps(observed))

    def test_snapshot_batches_exact_public_ids_and_refuses_incomplete_or_mixed_output(
        self,
    ):
        identifiers = {
            "container": [f"{number:064x}" for number in range(70)],
            "network": ["network-one", "network-two"],
            "volume": ["volume-one", "volume-two"],
            "image": ["sha256:" + "a" * 64, "sha256:" + "b" * 64],
        }
        for fault in (None, "missing", "duplicate", "foreign"):
            with self.subTest(fault=fault):
                fixture = object.__new__(acceptance.Fixture)
                batches = []

                def docker(*args):
                    if args[0] == "ps":
                        return "\n".join(identifiers["container"]).encode()
                    if args[1] == "ls":
                        return "\n".join(identifiers[args[0]]).encode()
                    self.assertEqual(args[1:3], ("inspect", "--format"))
                    self.assertNotIn(".Config.Env", args[3])
                    selected = args[4:]
                    self.assertTrue(0 < len(selected) <= 32)
                    batches.append((args[0], selected))
                    rows = [{"id": value, "labels": None} for value in selected]
                    if args[0] == "container":
                        if fault == "missing":
                            rows.pop()
                        elif fault == "duplicate":
                            rows.append(rows[0])
                        elif fault == "foreign":
                            rows[0] = {"id": "f" * 64}
                    return "\n".join(json.dumps(row) for row in rows).encode()

                fixture.docker = docker
                if fault is not None:
                    with self.assertRaisesRegex(
                        acceptance.AcceptanceRefused, "inventory_batch_mismatch"
                    ):
                        fixture.snapshot()
                    continue
                result = fixture.snapshot()
                self.assertEqual(
                    [len(batch) for kind, batch in batches if kind == "container"],
                    [32, 32, 6],
                )
                for noun, kind in (
                    ("container", "containers"),
                    ("network", "networks"),
                    ("volume", "volumes"),
                    ("image", "images"),
                ):
                    self.assertEqual(set(result[kind]), set(identifiers[noun]))
                    self.assertTrue(
                        all(row["labels"] == {} for row in result[kind].values())
                    )

    def test_case_and_scope_use_same_unambiguous_owned_fixture_origin(self):
        from gate_acceptance import ORIGIN as REVIEWED_ORIGIN, reviewed_cases

        for in_scope, marked in ((True, False), (False, False), (True, True)):
            with self.subTest(in_scope=in_scope, marked=marked):
                fixture = object.__new__(acceptance.Fixture)
                fixture.project = "vardrsec-nm2-publicfixture"

                def request(path, body=None, **kwargs):
                    if path == "/engagements":
                        return {"id": "engagement"}
                    if path.endswith("/authorizations"):
                        return {"id": "authorization"}
                    if path.endswith("/test-cases"):
                        return {**copy.deepcopy(body), "id": "case"}
                    if path.endswith("/jobs"):
                        return {"id": "job"}
                    return {}

                fixture.api = Mock()
                fixture.api.request.side_effect = request
                with patch.object(
                    acceptance,
                    "command",
                    side_effect=AssertionError("queue preparation must not run Docker"),
                ):
                    _, _, _, case = fixture.new_job(
                        "origin", in_scope=in_scope, marker=marked
                    )
                suffix = "&nm2_case=origin" if marked else ""
                self.assertEqual(acceptance.TARGET_HOST, "gate-fixture.test")
                self.assertEqual(acceptance.ORIGIN, "http://gate-fixture.test:8080")
                self.assertEqual(
                    case["spec"]["request"]["url"],
                    acceptance.ORIGIN
                    + "/fixed/records/42?view=full&include=owner"
                    + suffix,
                )
                self.assertEqual(
                    [
                        identity["preflight"]["url"]
                        for identity in case["spec"]["identities"]
                        if identity.get("preflight") is not None
                    ],
                    [
                        acceptance.ORIGIN
                        + "/session"
                        + ("?nm2_case=origin" if marked else "")
                    ]
                    * 2,
                )
                scope = next(
                    call.args[1]
                    for call in fixture.api.request.call_args_list
                    if call.args[0].endswith("/scope/in")
                )
                self.assertEqual(
                    scope,
                    {
                        "kind": "url",
                        "value": acceptance.ORIGIN
                        + ("/" if in_scope else "/unapproved/"),
                    },
                )
        # The shared installed-Gate fixture keeps its original default origin.
        self.assertEqual(
            reviewed_cases()[1]["spec"]["request"]["url"],
            REVIEWED_ORIGIN + "/fixed/records/42?view=full&include=owner",
        )

    def test_http_refusal_records_only_status_and_normalized_route(self):
        api = object.__new__(acceptance.OwnerAPI)
        api.url, api.csrf = "https://localhost:28443", None
        api.ca = Mock()
        api.ca.read_bytes.return_value = b"public-fixture-CA"
        api.ca_sha256 = acceptance.digest(b"public-fixture-CA")
        response = MagicMock()
        response.status = 409
        response.read.return_value = b'{"token":"private-response-canary"}'
        api.opener = Mock()
        api.opener.open.return_value = response
        path = "/jobs/00000000-0000-0000-0000-000000000011/managed/approval/review?token=private-query-canary"
        with self.assertRaises(acceptance.HTTPStatusRefused) as refused:
            api.request(path, {"password": "private-body-canary"}, expected=403)
        self.assertEqual(str(refused.exception), "fixture_http_status")
        self.assertEqual(
            refused.exception.public,
            {
                "method": "POST",
                "route": "/jobs/{id}/managed/approval/review",
                "expected_status": 403,
                "actual_status": 409,
            },
        )
        self.assertNotIn("private-", json.dumps(refused.exception.public))
        response.read.assert_not_called()

    def test_constructor_isolates_compose_inputs_and_preserves_os_path(self):
        controls = (
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
        )
        inherited_path = os.environ.get("PATH")
        with tempfile.TemporaryDirectory() as temporary:
            selection = self.selection(Path(temporary))
            inherited = {
                name: "public-synthetic-inherited-control" for name in controls
            }
            inherited.update(
                COMPOSE_PROJECT_NAME="unrelated-project",
                DOCKER_CONTEXT="unrelated-context",
                DOCKER_HOST="tcp://unrelated.invalid:2375",
                VARDRMAP_API_KEY="public-synthetic-key",
            )
            with (
                patch.dict(os.environ, inherited),
                patch.object(
                    acceptance,
                    "command",
                    side_effect=AssertionError("constructor must not invoke Docker"),
                ) as command,
            ):
                fixture = acceptance.Fixture(selection)
            self.assertTrue(
                all(name not in fixture.environment for name in controls),
                "inherited Compose controls must not enter the fixture",
            )
            self.assertTrue(
                fixture.environment.get("PATH") == inherited_path,
                "OS command lookup must remain unchanged",
            )
            self.assertEqual(
                fixture.environment["COMPOSE_PROJECT_NAME"], selection["project"]
            )
            self.assertEqual(
                fixture.environment["DOCKER_CONTEXT"], selection["docker_context"]
            )
            self.assertTrue("DOCKER_HOST" not in fixture.environment)
            self.assertTrue("VARDRMAP_API_KEY" not in fixture.environment)
            command.assert_not_called()

    def stop_fixture(self):
        fixture = object.__new__(acceptance.Fixture)
        fixture.project = "vardrsec-nm2-12345678"
        fixture.receipt = {}
        before = {"containers": {"a" * 64: {}}}
        current = {
            "containers": {
                key: {
                    "id": key,
                    "image": "sha256:" + "d" * 64,
                    "labels": {"com.docker.compose.project": project},
                    "state": {"running": True},
                }
                for key, project in (
                    ("a" * 64, fixture.project),
                    ("b" * 64, fixture.project),
                    ("c" * 64, "unrelated"),
                )
            }
        }
        stopped = copy.deepcopy(current)
        stopped["containers"]["b" * 64]["state"]["running"] = False
        fixture.snapshot = Mock(side_effect=[current, stopped])
        return fixture, before

    def test_cleanup_stops_only_new_exact_project_ids_and_retains_old_containers(self):
        fixture, before = self.stop_fixture()

        def docker(*arguments, **kwargs):
            if arguments[:2] == ("container", "inspect"):
                self.assertEqual(arguments[-1], "b" * 64)
                return acceptance.canonical(
                    {
                        "id": "b" * 64,
                        "image": "sha256:" + "d" * 64,
                        "project": fixture.project,
                    }
                )
            self.assertEqual(arguments, ("container", "stop", "-t", "10", "b" * 64))
            return b"bounded owned stop"

        fixture.docker = Mock(side_effect=docker)
        fixture.stop_owned(before)
        self.assertEqual(fixture.receipt["fixture_stop"]["container_ids"], ["b" * 64])
        self.assertEqual(fixture.snapshot.call_count, 2)
        self.assertEqual(fixture.docker.call_count, 2)

    def test_cleanup_refuses_changed_identity_before_stop(self):
        fixture, before = self.stop_fixture()
        fixture.docker = Mock(
            return_value=acceptance.canonical(
                {"id": "b" * 64, "image": "changed-image", "project": fixture.project}
            )
        )
        with self.assertRaisesRegex(
            acceptance.AcceptanceRefused, "fixture_stop_identity_changed"
        ):
            fixture.stop_owned(before)
        self.assertEqual(fixture.docker.call_count, 1)

    def selection(self, directory):
        sources = {}
        for name in acceptance.SOURCE_NAMES:
            source = directory / "sources" / name
            source.mkdir(parents=True)
            sources[name] = {"path": str(source), "commit": "a" * 40}
        distribution = Path(sources["distribution"]["path"])
        for name in (
            "compose.yaml",
            "compose.worker.json",
            "vardrsec.py",
            "database_roles.py",
            "worker_host.py",
            "worker_host_sequence.py",
            "worker_runtime.py",
            "worker_secrets.py",
            "worker_volumes.py",
            "worker_cli.py",
            "tests/gate/target.py",
            "tests/nm2_worker_acceptance.py",
            "tests/nm2_worker_inventory.py",
            "tests/nm2_worker_target.py",
        ):
            target = distribution / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("public fixture source")
        return {
            "schema": "vardr.nm2-worker-cohort/1",
            "sources": sources,
            "images": {name: "sha256:" + "b" * 64 for name in acceptance.IMAGE_NAMES},
            "docker_context": "desktop-linux",
            "project": "vardrsec-nm2-12345678",
            "installation": str(directory / "installation"),
            "private_root": str(directory / "private"),
            "https_port": 28443,
            "application_subnet": "172.29.217.0/24",
            "allow_empty_builtin_bridge_id_change": False,
        }

    @staticmethod
    def git_only(arguments, **kwargs):
        if arguments[0] != "git":
            raise AssertionError("Source validation must not use Docker")
        return b"a" * 40 + b"\n" if "rev-parse" in arguments else b""

    def test_default_validates_sources_without_creating_or_contacting_docker(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            selection = self.selection(directory)
            path = directory / "cohort.json"
            path.write_text(json.dumps(selection))
            output = io.StringIO()
            with (
                patch.object(acceptance, "command", side_effect=self.git_only),
                patch.object(
                    acceptance.Fixture,
                    "run",
                    side_effect=AssertionError("execution is explicit"),
                ),
                redirect_stdout(output),
            ):
                self.assertEqual(acceptance.main(["--cohort", str(path)]), 0)
            receipt = json.loads(output.getvalue())
            self.assertEqual(receipt["status"], "sources_validated_runtime_not_run")
            self.assertEqual(receipt["docker_calls"], 0)
            self.assertFalse(Path(selection["installation"]).exists())
            self.assertFalse(Path(selection["private_root"]).exists())

    def test_mutable_or_existing_selections_fail_before_docker(self):
        for mutation in (
            "mutable_image",
            "existing_installation",
            "shared_private_root",
            "old_project",
            "source_mismatch",
            "dirty_source",
            "public_helper_untracked",
            "missing_sequence_host",
        ):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                directory = Path(temporary)
                selection = self.selection(directory)
                if mutation == "mutable_image":
                    selection["images"]["worker"] = "worker:latest"
                elif mutation == "existing_installation":
                    Path(selection["installation"]).mkdir()
                elif mutation == "shared_private_root":
                    selection["private_root"] = selection["installation"]
                elif mutation == "old_project":
                    selection["project"] = "vardrsec-compose-review"
                elif mutation == "missing_sequence_host":
                    (
                        Path(selection["sources"]["distribution"]["path"])
                        / "worker_host_sequence.py"
                    ).unlink()
                path = directory / "cohort.json"
                path.write_text(json.dumps(selection))

                def selected_git(arguments, **kwargs):
                    result = self.git_only(arguments)
                    if mutation == "source_mismatch" and "rev-parse" in arguments:
                        return b"c" * 40
                    if mutation == "dirty_source" and "status" in arguments:
                        return b" M managed_worker.py\n"
                    if (
                        mutation == "public_helper_untracked"
                        and "--error-unmatch" in arguments
                    ):
                        raise acceptance.AcceptanceRefused("fixture_command_failed")
                    return result

                with (
                    patch.object(acceptance, "command", side_effect=selected_git),
                    self.assertRaises(acceptance.AcceptanceRefused),
                ):
                    acceptance.manifest(path)

    def test_exact_old_state_and_tags_are_preserved(self):
        before = {
            "containers": {
                "old-stopped": {"id": "old-stopped", "state": "stopped", "labels": {}}
            },
            "networks": {
                "old-network": {
                    "id": "old-network",
                    "name": "owned-old",
                    "labels": {},
                    "containers": {},
                }
            },
            "volumes": {"old-volume": {"labels": {}}},
            "images": {"old-image": {"tags": ["development"]}},
        }
        after = copy.deepcopy(before)
        after["containers"]["fixture"] = {
            "id": "fixture",
            "labels": {"com.docker.compose.project": "vardrsec-nm2-12345678"},
        }
        self.assertEqual(
            acceptance.unchanged_inventory(before, after, "vardrsec-nm2-12345678"), []
        )
        for kind, key, change in (
            ("containers", "old-stopped", {"state": "running"}),
            ("volumes", "old-volume", {"changed": True}),
            ("images", "old-image", {"tags": []}),
        ):
            bad = copy.deepcopy(after)
            bad[kind][key].update(change)
            with (
                self.subTest(kind=kind),
                self.assertRaises(acceptance.AcceptanceRefused),
            ):
                acceptance.unchanged_inventory(before, bad, "vardrsec-nm2-12345678")
        after["containers"]["unowned"] = {"id": "unowned", "labels": {}}
        with self.assertRaisesRegex(
            acceptance.AcceptanceRefused, "unowned_new_resource"
        ):
            acceptance.unchanged_inventory(before, after, "vardrsec-nm2-12345678")

    def test_remote_or_unknown_context_refuses_before_creating_resources(self):
        with tempfile.TemporaryDirectory() as temporary:
            selection = self.selection(Path(temporary))
            fixture = acceptance.Fixture(selection)
            with (
                patch("sys.path", list(sys.path)),
                patch.object(worker_runtime, "LocalDocker", autospec=True) as observer,
                patch.object(fixture, "docker") as docker,
                patch.object(fixture, "snapshot") as snapshot,
                patch.object(fixture, "stage") as stage,
            ):
                observer.return_value.daemon.side_effect = (
                    worker_runtime.RuntimeRefused("worker_runtime_refused")
                )
                with self.assertRaises(worker_runtime.RuntimeRefused):
                    fixture.run()
            observer.assert_called_once()
            self.assertEqual(observer.call_args.kwargs, {"max_attempts": 2})
            docker.assert_not_called()
            snapshot.assert_not_called()
            stage.assert_not_called()

    def test_mismatched_image_source_refuses_before_platform_setup(self):
        with tempfile.TemporaryDirectory() as temporary:
            selection = self.selection(Path(temporary))
            source = Path(selection["sources"]["map"]["path"]) / "backend" / "main.py"
            source.parent.mkdir()
            source.write_bytes(b"# approved source\r\n")
            fixture = acceptance.Fixture(selection)
            with (
                patch.object(acceptance, "command", return_value=b"backend/main.py\0"),
                patch.object(
                    fixture,
                    "docker",
                    return_value=json.dumps(
                        {
                            "files": {"main.py": "different-image-source"},
                            "executables": {},
                        }
                    ).encode(),
                ) as docker,
                self.assertRaisesRegex(
                    acceptance.AcceptanceRefused, "image_source_inventory_mismatch"
                ),
            ):
                fixture.image_sources()
            arguments = docker.call_args.args
            self.assertEqual(arguments[arguments.index("--network") + 1], "none")
            self.assertEqual(arguments[arguments.index("--user") + 1], "10001:10001")
            self.assertEqual(arguments[arguments.index("--cap-drop") + 1], "ALL")
            self.assertIn("--read-only", arguments)

    def test_empty_builtin_bridge_id_admission_is_explicit_and_semantic(self):
        before = {kind: {} for kind in ("containers", "networks", "volumes", "images")}
        before["networks"]["old"] = {
            "id": "old",
            "name": "bridge",
            "driver": "bridge",
            "containers": {},
            "labels": {},
        }
        after = copy.deepcopy(before)
        after["networks"] = {"new": {**before["networks"]["old"], "id": "new"}}
        with self.assertRaises(acceptance.AcceptanceRefused):
            acceptance.unchanged_inventory(before, after, "vardrsec-nm2-12345678")
        self.assertEqual(
            acceptance.unchanged_inventory(
                before, after, "vardrsec-nm2-12345678", admit_bridge=True
            ),
            [{"kind": "empty_builtin_bridge_id", "before": "old", "after": "new"}],
        )
        after["networks"]["new"]["containers"] = {"unexpected": {}}
        with self.assertRaises(acceptance.AcceptanceRefused):
            acceptance.unchanged_inventory(
                before, after, "vardrsec-nm2-12345678", admit_bridge=True
            )

    def test_http_delay_stays_bounded_without_process_fixtures(self):
        source = Path(acceptance.__file__).with_name("nm2_worker_target.py")
        spec = importlib.util.spec_from_file_location("controlled_nm2_target", source)
        module = importlib.util.module_from_spec(spec)
        environment = {
            f"FIXTURE_{name}_TOKEN": name for name in ("OWNER", "PEER", "READER")
        }
        with (
            patch.dict("os.environ", environment),
            patch.dict(sys.modules),
            patch("sys.path", [str(source.parent / "gate"), *sys.path]),
        ):
            spec.loader.exec_module(module)
        for value in ("0", "15"):
            self.assertEqual(module.response_delay(value), int(value))
        for value in ("-1", "16", "900", "1", "nan"):
            with self.assertRaises(ValueError):
                module.response_delay(value)
        instance = object.__new__(module.ControlledTarget)
        instance.command, instance.path, instance.delay = "GET", "/fixed/records/42", 15
        with (
            patch.object(module.time, "sleep") as sleep,
            patch.object(module.Target, "reply", side_effect=BrokenPipeError),
        ):
            self.assertIsNone(instance.reply(200, {}))
        sleep.assert_called_once_with(15)


if __name__ == "__main__":
    unittest.main()
