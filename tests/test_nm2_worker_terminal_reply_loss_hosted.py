"""Two committed terminal reply boundaries; inert models, no installed execution."""

from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from urllib.parse import parse_qs, urlsplit
from unittest.mock import Mock, patch

import gate_acceptance
import nm2_worker_hosted as hosted
import nm2_worker_launch_acceptance as local
from nm2_worker_acceptance import AcceptanceRefused, canonical, digest
import test_nm2_worker_claim_reply_loss_hosted as claim


def evidence(operation, *, desktop=False):
    raw, selected, inventories = claim.evidence(desktop=desktop)
    policy = local.TERMINAL_REPLY_LOSS[operation]
    raw.update(scenario=policy["scenario"], acceptance_scope=policy["scope"],
               status="selected_terminal_reply_loss_slice_passed", stage="selected_terminal_reply_loss_complete")
    for name, commit in local.POST_CLAIM_REPLY_LOSS_SOURCES.items():
        selected["sources"][name]["commit"] = raw["sources"][name]["commit"] = commit
    proof = raw["claim_reply_loss"]
    committed = proof["committed"]
    runtime = committed["runtimes"][0]
    attempt = runtime["attempts"][0]
    binding = attempt["binding"]
    committed["contracts"][0]["consumed"] = True
    attempt["confirmed_at"] = "2026-11-07T01:00:02.000000Z"
    case = deepcopy(next(row["spec"] for row in gate_acceptance.reviewed_cases() if row["name"] == "fixed"))
    case["id"] = "nm2-launch-claim-reply-loss"
    for request in [case["request"], *[row["preflight"] for row in case["identities"] if row.get("preflight")]]:
        request["url"] = local.ORIGIN + request["url"][len(gate_acceptance.ORIGIN):]
        request["url"] += ("&" if "?" in request["url"] else "?") + "nm2_case=launch-claim-reply-loss"
    case_sha = digest(canonical(case))
    result = dict(contract_id=binding["contract_id"], artifact_sha256="d" * 64,
                  receipt_sha256=digest(canonical({"schema": "vardr.managed-result/1", **binding,
                      "artifact_sha256": "d" * 64, "case_sha256": case_sha})),
                  outcome=policy["outcome"], evidence_created=5, scan_items_created=0)
    committed["results"] = [result]
    if operation == "finish":
        committed.update(job_status="done", capacity_reserved_count=0,
                         execution={**committed["execution"], "state": "completed", "capacity_reserved": False})
    unknown = proof["local_unknown"]
    for row in (unknown["run"], unknown["metadata"]):
        row.update(phase=policy["phase"], status="local_artifact_held")
    unknown["run"]["artifact_sha256"] = result["artifact_sha256"]
    intent = dict(binding=binding, artifact_sha256=result["artifact_sha256"], artifact_size=111,
                  case_sha256=case_sha, receipt_sha256=result["receipt_sha256"], outcome="completed",
                  state=policy["intent_state"], finish_sent=policy["finish_sent"])
    metadata = unknown["metadata"]
    metadata.update(claim_state="consume_acknowledged", consumption_sent=1, consumption_acknowledged=1,
                    local_stop_requested=False, failure_reason=None, last_event="other",
                    upload_state="in_progress" if operation == "result" else "succeeded",
                    partial_files=[{"name": "vardrgate_result.json", "size": 111, "sha256": result["artifact_sha256"]}],
                    result_intent=intent, persistent_attempt=dict(state="bound", binding={**binding,
                        "runtime_id": runtime["id"], "runtime_sha256": runtime["runtime_sha256"],
                        "admission_sha256": runtime["admission_sha256"], "runtime_sequence": "1"},
                        completion=None, native_done_sha256=None, release_intent=None, release_ack=None,
                        retired_from_state=None))
    for audit in (unknown["audit"], proof["audit"]):
        audit["counts"]["attempts"] = 1
        audit["parent"].update(last_sequence="1", head_sequence="1")
    unknown["audit"]["parent"].update(state="active", active_sequence="1")
    terminal = {"schema": "vardr.managed-completion/1", **binding,
                "receipt_sha256": result["receipt_sha256"],
                "outcome": "failed" if operation == "result" else "completed", "capacity_reserved": False}
    retirement = proof["retirement"]
    retirement["attempt_receipt"] = terminal
    retirement["receipt_sha256"] = digest(canonical({key: value for key, value in retirement.items() if key != "receipt_sha256"}))
    raw["launch"]["retirement_sha256"] = proof["retirement_sha256"] = retirement["receipt_sha256"]
    proof["audit"]["retirement_receipt_sha256"] = proof["reconciliation"]["retirement_receipt_sha256"] = retirement["receipt_sha256"]
    proof["reconciliation"]["reconciliation_state"] = policy["reconciliation"]
    proof["terminal_sha256"] = digest(canonical(terminal))
    proof["host_retirement_sha256"] = digest(canonical(retirement))
    proof["audit_sha256"] = digest(canonical(proof["audit"]))
    proof["after"] = {**deepcopy(committed), "job_status": "done" if operation == "finish" else "failed",
                      "capacity_reserved_count": 0,
                      "execution": {**committed["execution"], "state": terminal["outcome"], "capacity_reserved": False}}
    proof["after"]["results"][0]["outcome"] = terminal["outcome"]
    proof["after"]["runtimes"][0].update(retired=True, new_work_disabled=True, report_sha256=retirement["report_sha256"])
    proof["local_after"] = deepcopy(metadata)
    proof["local_after"].update(phase="done" if operation == "finish" else "failed",
                                status="done" if operation == "finish" else "failed",
                                claim_state="consume_acknowledged" if operation == "finish" else "failed_completion_observed",
                                last_event="managed_completion_receipt" if operation == "finish" else "managed_failed_completion_receipt",
                                failure_reason=None if operation == "finish" else "observed_failed_completion")
    proof["local_after"]["result_intent"]["state"] = "terminal" if operation == "finish" else "server_retired"
    proof["local_after"]["persistent_attempt"].update(state="physical_retirement_observed", retired_from_state="bound")
    proof.update(operation=operation, case=case, target_requests=5,
                 requests=[dict(identity=who, method="GET",
                                path=urlsplit(request["url"]).path + "?" + urlsplit(request["url"]).query,
                                received_monotonic_ns=(index + 1) * 1000000000)
                           for index, (who, request) in enumerate([
                               ("owner", case["identities"][0]["preflight"]),
                               ("peer", case["identities"][1]["preflight"]),
                               ("owner", case["request"]), ("peer", case["request"]),
                               ("anonymous", case["request"])])],
                 assessment=dict(status="conclusive", baseline_valid=True, case_snapshot_verified=True,
                                 preflight={"status": "passed"}, case_hash=case_sha, candidate_findings=0),
                 evidence_count=5, evidence_sha256="e" * 64,
                 terminal_cause="retained_result_failure" if operation == "result" else "existing_completed",
                 capacity_before=1 if operation == "result" else 0)
    proof["proxy"]["config_sha256"] = digest(local.claim_reply_loss_config(
        (hosted.SOURCE / "Caddyfile").read_bytes(), claim.JOB, operation=operation))
    return raw, selected, inventories


class TerminalReplyLossTests(TestCase):
    def test_observation_uses_one_registration_and_real_unknown_metadata_without_replay(self):
        for operation in ("result", "finish"):
            raw, _, _ = evidence(operation)
            proof = raw["claim_reply_loss"]
            original_unknown = deepcopy(proof["local_unknown"])
            fixture = local.LaunchFixture.__new__(local.LaunchFixture)
            fixture.receipt, fixture.reply_loss_operation = {}, operation
            fixture.pending_approval = {"synthetic": "approval"}
            fixture.persistent_idle = Mock()
            fixture.inventory = Mock(return_value=proof["committed"])
            fixture.helper = Mock(return_value=json.dumps([proof["local_unknown"]["run"]]).encode())
            fixture.local_metadata = Mock(return_value=proof["local_unknown"]["metadata"])
            fixture.worker_state = Mock(return_value=proof["local_unknown"]["audit"])
            fixture.traffic = Mock(side_effect=[[], proof["requests"], proof["requests"]])
            fixture.claim_loss_proxy_binding = proof["proxy"]
            fixture.api = SimpleNamespace(request=Mock())
            retained = [{"body": "synthetic-" + str(index), "content_hash": digest(("synthetic-" + str(index)).encode())}
                        for index in range(5)]

            def request(path, *args):
                if path.endswith("/managed/approval/register"):
                    return {"approval_record_id": proof["approval_record_id"]}
                if "/evidence?" in path:
                    return {"evidence": retained}
                if path.endswith("/jobs"):
                    return {"jobs": [{"id": proof["job_id"], "assessment": proof["assessment"]}]}
                if "/scans?" in path:
                    return {"scans": []}
                self.fail("unexpected fixture API request")

            fixture.api.request.side_effect = request
            physical = SimpleNamespace(exit_code=125)
            observer, identity = Mock(), object()
            observer.observe_exit.return_value = physical
            with TemporaryDirectory() as temporary:
                fixture.install = Path(temporary)
                (fixture.install / "Caddyfile").write_bytes(local.claim_reply_loss_config(
                    (hosted.SOURCE / "Caddyfile").read_bytes(), proof["job_id"], operation=operation))
                case = claim.ENGAGEMENT, claim.JOB, {"spec": proof["case"]}, proof["initial"]
                run_id, observed, before = fixture.observe_terminal_reply_loss(observer, identity,
                    proof["committed"]["runtimes"][0]["admission"], case)
            self.assertEqual(run_id, proof["run_id"])
            self.assertIs(observed, physical)
            self.assertEqual(before, proof["committed"])
            self.assertEqual(proof["local_unknown"], original_unknown)
            observer.observe_exit.assert_called_once_with(identity)
            fixture.worker_state.assert_called_once_with(
                proof["committed"]["runtimes"][0]["admission"], expected_held="issued_unknown")
            fixture.local_metadata.assert_called_once_with(run_id, claim.ENGAGEMENT, claim.JOB, include_result=True)
            self.assertEqual(sum(call.args[0].endswith("/managed/approval/register")
                                 for call in fixture.api.request.call_args_list), 1)

    def test_recovery_only_observes_original_receipt_and_retains_unknown_native_fields(self):
        for operation in ("result", "finish"):
            raw, _, _ = evidence(operation)
            proof = raw["claim_reply_loss"]
            unknown_before = deepcopy(proof["local_unknown"])
            fixture = local.LaunchFixture.__new__(local.LaunchFixture)
            fixture.receipt, fixture.reply_loss_operation = raw, operation
            fixture.inventory = Mock(return_value=proof["after"])
            fixture.local_metadata = Mock(return_value=proof["local_after"])
            fixture.traffic = Mock(return_value=proof["requests"])
            fixture.reconcile_original = Mock(return_value=proof["audit"])
            fixture.worker_action, fixture.helper = Mock(), Mock()
            admission = proof["committed"]["runtimes"][0]["admission"]
            case = claim.ENGAGEMENT, claim.JOB, {"spec": proof["case"]}, proof["initial"]
            audit = fixture.verify_terminal_reply_loss(admission, proof["retirement"], case,
                                                       proof["run_id"], proof["committed"])
            self.assertEqual(audit, proof["audit"])
            self.assertEqual(proof["local_unknown"], unknown_before)
            fixture.reconcile_original.assert_called_once_with(admission, proof["retirement"],
                host_exit_run_id=proof["run_id"], terminal_reply_loss=operation)
            fixture.helper.assert_not_called()
            fixture.worker_action.assert_not_called()
            self.assertIsNone(proof["local_after"]["persistent_attempt"]["native_done_sha256"])
            self.assertIsNone(proof["local_after"]["persistent_attempt"]["release_ack"])

    def test_selected_boundary_preserves_claim_config_and_only_aborts_success(self):
        original = (hosted.SOURCE / "Caddyfile").read_bytes()
        self.assertEqual(local.claim_reply_loss_config(original, claim.JOB),
                         local.claim_reply_loss_config(original, claim.JOB, operation="claim"))
        for operation in ("result", "finish"):
            text = local.claim_reply_loss_config(original, claim.JOB, operation=operation).decode()
            self.assertIn("path /jobs/" + claim.JOB + "/managed/" + operation, text)
            self.assertEqual(text.count("@committed status 200"), 1)
            self.assertEqual(text.count("abort"), 1)
            self.assertIn("tls internal", text)
        for invalid in (None, True, [], "stopped", "result*", "finish\nabort"):
            with self.subTest(invalid=invalid), self.assertRaises(AcceptanceRefused):
                local.claim_reply_loss_config(original, claim.JOB, operation=invalid)

    def test_both_boundaries_project_on_both_platforms_with_private_redaction(self):
        for operation in ("result", "finish"):
            for desktop in (False, True):
                raw, selected, inventories = evidence(operation, desktop=desktop)
                query = parse_qs(urlsplit(raw["claim_reply_loss"]["case"]["request"]["url"]).query)
                self.assertEqual(query, {"view": ["full"], "include": ["owner"],
                                         "nm2_case": ["launch-claim-reply-loss"]})
                self.assertTrue(all(parse_qs(urlsplit(row["path"]).query) == query
                                    for row in raw["claim_reply_loss"]["requests"][2:]))
                result = (hosted.claim_reply_loss_desktop_projection(raw, selected, inventories=inventories)
                          if desktop else hosted.public_projection(raw, selected, inventories=inventories))
                row = result[operation + "_reply_loss"]
                self.assertEqual((row["target_requests"], row["evidence_count"]), (5, 5))
                self.assertEqual(row["server_outcome"], "failed" if operation == "result" else "completed")
                self.assertEqual(row["reconciliation_state"], local.TERMINAL_REPLY_LOSS[operation]["reconciliation"])
                self.assertEqual(row["owned_stopped_container_count"], 6)
                for private in (claim.JOB, claim.RUN, claim.PROXY_CID, "nm2-launch-claim-reply-loss", "/private/"):
                    self.assertNotIn(private, json.dumps(result))

    def test_receipt_and_local_ack_uncertainty_cannot_be_rewritten(self):
        for operation in ("result", "finish"):
            for part, key, value in (("result_intent", "finish_sent", 1 if operation == "result" else 0),
                                     ("result_intent", "outcome", "failed"),
                                     ("persistent_attempt", "native_done_sha256", "f" * 64),
                                     ("persistent_attempt", "release_ack", {}),
                                     ("result_intent", "artifact_size", True)):
                raw, selected, inventories = evidence(operation)
                raw["claim_reply_loss"]["local_unknown"]["metadata"][part][key] = value
                with self.subTest(operation=operation, key=key), self.assertRaises(hosted.HostedRefused):
                    hosted.public_projection(raw, selected, inventories=inventories)

    def test_no_result_stop_coexistence_or_other_completion_is_accepted(self):
        for operation in ("result", "finish"):
            for mutation in ("missing", "stop", "outcome", "case", "count", "clock"):
                raw, selected, inventories = evidence(operation)
                proof = raw["claim_reply_loss"]
                if mutation == "missing":
                    proof["committed"]["results"] = []
                elif mutation == "stop":
                    proof["after"]["stops"] = [{}]
                elif mutation == "outcome":
                    proof["after"]["results"][0]["outcome"] = "cancelled"
                elif mutation == "case":
                    proof["case"]["id"] = "other-case"
                elif mutation == "count":
                    proof["evidence_count"] = True
                else:
                    proof["requests"][0]["received_monotonic_ns"] = True
                with self.subTest(operation=operation, mutation=mutation), self.assertRaises(hosted.HostedRefused):
                    hosted.public_projection(raw, selected, inventories=inventories)

    def test_after_recovery_preserves_original_intent_and_unissued_native_ack(self):
        for operation in ("result", "finish"):
            for key, value in (("artifact_sha256", "0" * 64), ("finish_sent", True), ("outcome", "failed")):
                raw, selected, inventories = evidence(operation)
                raw["claim_reply_loss"]["local_after"]["result_intent"][key] = value
                with self.subTest(operation=operation, key=key), self.assertRaises(hosted.HostedRefused):
                    hosted.public_projection(raw, selected, inventories=inventories)

    def test_explicit_routing_requires_new_exact_sources_and_stays_inert_by_default(self):
        for operation in ("result", "finish"):
            scenario = local.TERMINAL_REPLY_LOSS[operation]["scenario"]
            env = {"NM2_SCENARIO": scenario, "NM2_DATABASE_REVISION": "0041persistentruntime",
                   **{"NM2_" + name.upper() + "_SHA": value for name, value in local.POST_CLAIM_REPLY_LOSS_SOURCES.items()}}
            self.assertEqual(hosted.execution_options(env), (scenario, "0041persistentruntime"))
            with self.assertRaises(hosted.HostedRefused):
                hosted.execution_options({**env, "NM2_RUNNER_SHA": local.CLAIM_REPLY_LOSS_SOURCES["runner"]})
            with patch.object(local, "LaunchFixture") as fixture:
                self.assertEqual(local.main(["--cohort", "unused", "--compose-executable", "unused",
                                             "--compose-sha256", "0" * 64, "--docker-config", "unused",
                                             "--" + operation + "-reply-loss"]), 2)
                fixture.assert_not_called()
