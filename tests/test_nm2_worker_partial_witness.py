"""Inert retention and independent hash checks for one existing cancellation case."""

import unittest
from unittest.mock import Mock, patch

import nm2_worker_hosted as hosted
import nm2_worker_launch_acceptance as launch
from nm2_worker_acceptance import AcceptanceRefused, canonical, digest
import test_nm2_worker_stopped_predecessor_hosted as retained


def witness(selection, job):
    binding = {
        "origin": f"https://vardrsec.localhost:{selection['https_port']}/backend",
        "job_id": job,
        "runner_id": "1b66cc3b-9f67-4fd7-a9d8-38dc3f7307d0",
        "contract_id": "cb0690c6-f87d-46a8-9021-7a65e2f5ff38",
        "attempt_id": "ab203fbc-5418-4a09-8e3b-37b169fb21e1",
        "fence": 1,
        "contract_sha256": "d" * 64,
    }
    result_sha = digest(
        canonical(
            {
                "schema": "vardr.managed-result/1",
                **binding,
                "artifact_sha256": "b" * 64,
                "case_sha256": "a" * 64,
            }
        )
    )
    terminal = {
        "schema": "vardr.managed-completion/1",
        **binding,
        "receipt_sha256": result_sha,
        "outcome": "failed",
        "capacity_reserved": False,
    }
    return {
        "binding": binding,
        "case_sha256": "a" * 64,
        "artifact_sha256": "b" * 64,
        "result_receipt_sha256": result_sha,
        "terminal_receipt_sha256": digest(canonical(terminal)),
        "evidence_count": 5,
        "evidence_sha256": "c" * 64,
        "assessment_status": "inconclusive",
    }, terminal


def vector(desktop=False):
    raw, selection, inventories = (
        retained.desktop_evidence() if desktop else retained.evidence()
    )
    raw.pop("stopped_predecessor")
    selection["https_port"] = 28443
    first = raw["launch_pair"][0]
    job = "ddd8e594-dfcb-4ca2-83f8-abfda598e1a7"
    partial, _ = witness(selection, job)
    raw.update(
        scenario=hosted.LAUNCH_GRANT_REVOKE_SCENARIO,
        acceptance_scope="grant_revocation_then_next_launch",
        cancelled_job={
            "job_id": job,
            "retirement_sha256": first["retirement_sha256"],
            "audit_sha256": "e" * 64,
            "target_requests": 3,
            "terminal_sha256": partial["terminal_receipt_sha256"],
            "terminal_cause": "local_emergency_stop",
            "grant_revocation_sha256": "f" * 64,
            "physical_exit_elapsed_ns": 2_000_000_000,
            "partial_retention": partial,
        },
    )
    return raw, selection, inventories


class PartialWitnessTests(unittest.TestCase):
    def test_closed_witness_recomputes_receipts_and_exports_no_binding(self):
        for desktop in (False, True):
            raw, selection, inventories = vector(desktop)
            project = (
                hosted.grant_revocation_desktop_projection
                if desktop
                else hosted.public_projection
            )
            result = project(raw, selection, inventories=inventories)
            partial = result["cancelled_job"]["partial_retention"]
            self.assertEqual(
                partial,
                {
                    k: v
                    for k, v in raw["cancelled_job"]["partial_retention"].items()
                    if k != "binding"
                },
            )
            self.assertNotIn("binding", partial)
            for key in ("origin", "runner_id", "contract_id", "attempt_id"):
                self.assertNotIn(
                    raw["cancelled_job"]["partial_retention"]["binding"][key].encode(),
                    canonical(result),
                )

    def test_legacy_absence_preserves_stop_credit_without_c01_witness(self):
        for desktop in (False, True):
            raw, selection, inventories = vector(desktop)
            raw["cancelled_job"].pop("partial_retention")
            project = (
                hosted.grant_revocation_desktop_projection
                if desktop
                else hosted.public_projection
            )
            result = project(raw, selection, inventories=inventories)
            self.assertNotIn("partial_retention", result["cancelled_job"])

    def test_malformed_or_unbound_partial_witness_never_projects(self):
        for desktop in (False, True):
            for mutation in (
                "artifact",
                "result",
                "terminal",
                "case",
                "count_bool",
                "count",
                "status",
                "foreign_origin",
                "foreign_job",
                "bool_fence",
                "float_fence",
                "missing",
                "canary",
                "completed",
                "null",
            ):
                raw, selection, inventories = vector(desktop)
                value = raw["cancelled_job"]["partial_retention"]
                if mutation in {"artifact", "result", "terminal", "case"}:
                    value[
                        {
                            "artifact": "artifact_sha256",
                            "result": "result_receipt_sha256",
                            "terminal": "terminal_receipt_sha256",
                            "case": "case_sha256",
                        }[mutation]
                    ] = "0" * 64
                elif mutation == "count_bool":
                    value["evidence_count"] = True
                elif mutation == "count":
                    value["evidence_count"] = 6
                elif mutation == "status":
                    value["assessment_status"] = "conclusive"
                elif mutation == "foreign_origin":
                    value["binding"]["origin"] = "https://foreign.invalid/backend"
                elif mutation == "foreign_job":
                    value["binding"]["job_id"] = retained.RUN_ONE
                elif mutation in {"bool_fence", "float_fence"}:
                    value["binding"]["fence"] = (
                        True if mutation == "bool_fence" else 1.0
                    )
                elif mutation == "missing":
                    value.pop("artifact_sha256")
                elif mutation == "canary":
                    value["secret"] = retained.PRIVATE_CANARY
                elif mutation == "null":
                    raw["cancelled_job"]["partial_retention"] = None
                else:
                    completed = {
                        "schema": "vardr.managed-completion/1",
                        **value["binding"],
                        "receipt_sha256": value["result_receipt_sha256"],
                        "outcome": "completed",
                        "capacity_reserved": False,
                    }
                    value["terminal_receipt_sha256"] = raw["cancelled_job"][
                        "terminal_sha256"
                    ] = digest(canonical(completed))
                project = (
                    hosted.grant_revocation_desktop_projection
                    if desktop
                    else hosted.public_projection
                )
                with (
                    self.subTest(desktop=desktop, mutation=mutation),
                    self.assertRaises(hosted.HostedRefused),
                ):
                    project(raw, selection, inventories=inventories)

    def fixture(self):
        raw, selection, _ = vector()
        partial = raw["cancelled_job"]["partial_retention"]
        binding = partial["binding"]
        _, terminal = witness(selection, binding["job_id"])
        spec = {"synthetic": "reviewed-case"}
        partial["case_sha256"] = digest(canonical(spec))
        result_sha = digest(
            canonical(
                {
                    "schema": "vardr.managed-result/1",
                    **binding,
                    "artifact_sha256": partial["artifact_sha256"],
                    "case_sha256": partial["case_sha256"],
                }
            )
        )
        partial["result_receipt_sha256"] = terminal["receipt_sha256"] = result_sha
        partial["terminal_receipt_sha256"] = digest(canonical(terminal))
        fixture = launch.LaunchFixture.__new__(launch.LaunchFixture)
        fixture.receipt = {}
        fixture.local_stop, fixture.revoke_grant, fixture.expire_active_grant = (
            False,
            True,
            False,
        )
        identity = {"synthetic": "physical"}
        runtime_id = raw["launch_pair"][0]["runtime_id"]
        physical = {
            "runtime_id": runtime_id,
            "runtime_sha256": "1" * 64,
            "identity": identity,
            "finished_at": "2026-11-07T01:00:03Z",
        }
        admission = {
            "runtime_id": runtime_id,
            "runtime_sha256": "1" * 64,
            "admission_sha256": "2" * 64,
        }
        retired = {
            "binding": binding,
            "attempt_receipt": terminal,
            "receipt_sha256": "3" * 64,
        }
        attempt = {
            "binding": binding,
            "job_id": binding["job_id"],
            "runtime_sequence": "1",
            "runtime_id": runtime_id,
            "confirmed_at": "2026-11-07T01:00:01Z",
            "release_receipt": None,
            "released_at": None,
            "native_done_sha256": None,
        }
        inventory = {
            "job_status": "failed",
            "contracts": [{}],
            "stops": [],
            "results": [{}],
            "runtimes": [
                {
                    "id": runtime_id,
                    "runtime_sha256": "1" * 64,
                    "identity": identity,
                    "mode": "persistent",
                    "retired": True,
                    "new_work_disabled": True,
                    "last_sequence": "1",
                    "attempts": [attempt],
                }
            ],
            "targets_spent": 1,
            "duration_allocated": 30,
            "execution": {
                "state": "failed",
                "capacity_reserved": False,
                "target_charge": 1,
                "duration_seconds": 30,
            },
        }
        metadata = {
            "run_id": "4" * 32,
            "job_id": binding["job_id"],
            "engagement_id": "engagement",
            "consumption_sent": 1,
            "consumption_acknowledged": 1,
            "local_stop_requested": False,
            "failure_reason": "local_emergency_stop",
            "claim_state": "consume_acknowledged",
            "partial_files": [],
            "partial_result": {},
        }
        fixture.local_metadata = Mock(return_value=metadata)
        fixture.inventory = Mock(return_value=inventory)
        fixture.reconcile_original = Mock(return_value={"status": "retired"})
        fixture.verify_failed_partial = Mock(
            return_value={
                k: v for k, v in partial.items() if k not in {"binding", "case_sha256"}
            }
        )
        fixture.helper = Mock()
        start = launch.engine_timestamp_ns("2026-11-07T01:00:00Z")
        requests = [{"received_utc_ns": start, "received_monotonic_ns": 1}] * 3
        after = {
            "requests": requests,
            "observed_utc_ns": start + 5_000_000_000,
            "observed_monotonic_ns": 5_000_000_001,
        }
        fixture.timed_traffic = Mock(return_value=after)
        case = ("engagement", binding["job_id"], {"spec": spec}, {})
        action = {
            "run_id": metadata["run_id"],
            "requests": requests,
            "grant_revocation": {},
        }
        return (
            fixture,
            (physical, admission, retired, case, action, after),
            inventory,
            partial,
        )

    def test_producer_retains_validated_return_instead_of_discarding_it(self):
        fixture, args, _, partial = self.fixture()
        with patch("worker_host_persistent.retirement"):
            fixture.cancelled_reconciliation(*args)
        fixture.verify_failed_partial.assert_called_once()
        self.assertEqual(fixture.receipt["cancelled_job"]["partial_retention"], partial)

    def test_selected_case_without_emission_holds_c01_not_product_stop(self):
        fixture, args, inventory, _ = self.fixture()
        terminal = args[2]["attempt_receipt"]
        terminal["cause"] = "local_emergency_stop"
        inventory["results"] = []
        inventory["stops"] = [
            {
                "contract_id": terminal["contract_id"],
                "receipt_sha256": terminal["receipt_sha256"],
                "outcome": "failed",
                "cause": "local_emergency_stop",
            }
        ]
        with (
            patch("worker_host_persistent.retirement"),
            self.assertRaisesRegex(
                AcceptanceRefused, "^cancelled_partial_witness_unobserved$"
            ),
        ):
            fixture.cancelled_reconciliation(*args)
        fixture.verify_failed_partial.assert_not_called()
        self.assertNotIn("cancelled_job", fixture.receipt)
