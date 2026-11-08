"""Actual idle fixture/reader with synthetic wire and entirely mocked external I/O."""

import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

import nm2_worker_acceptance as fixture
import nm2_worker_count_projection as count_reader
import nm2_worker_hosted as hosted
import nm2_worker_idle_projection as reader
import nm2_worker_persistent_projection as availability
import test_nm2_worker_count_projection as count_vectors
import worker_host as host
import worker_host_persistent as persistent

CANARY = "private-idle-profile-credential-body-canary"


def vector(*, run=True):
    count, selection = count_vectors.vector()
    old = count["cases"]["persistent_count_limit"]
    proof = old["proof"]
    admission = copy.deepcopy(proof["admission"])
    admission["limits"] = {"max_attempts": None, "idle_timeout_seconds": 60}
    admission["admission_sha256"] = host.digest({
        k:v for k,v in admission.items() if k != "admission_sha256"})
    physical = copy.deepcopy(old["physical"])
    physical.update(exit_code=124, admission_sha256=admission["admission_sha256"])
    original = copy.deepcopy(proof["selections"][0])
    spec = count_vectors._case("idle-control")
    plan = count_vectors._wire_plan(spec, count["image_sources"]["runner"]["executables"]["/usr/local/bin/vardrgate"])
    original["case_spec"] = spec
    original["review_input"]["plan"] = plan
    original["review_context"]["plan_sha256"] = host.digest(plan)
    measured = copy.deepcopy(proof["measured"])
    measured.update(case_sha256=host.digest(spec))
    measured["assessment"]["case_hash"] = measured["case_sha256"]
    for row in measured["requests"]:
        row["path"] = row["path"].replace("nm2_case=count-a", "nm2_case=idle-control")
    terminal = copy.deepcopy(measured["terminal_receipt"])
    terminal["receipt_sha256"] = host.digest({"schema":"vardr.managed-result/1",
        **measured["binding"], "artifact_sha256":measured["artifact_sha256"],
        "case_sha256":measured["case_sha256"]})
    release = copy.deepcopy(measured["release_receipt"])
    release.update(admission_sha256=admission["admission_sha256"],
                   terminal_receipt_sha256=host.digest(terminal))
    release["receipt_sha256"] = host.digest({k:v for k,v in release.items() if k != "receipt_sha256"})
    measured.update(terminal_receipt=terminal, terminal_receipt_sha256=host.digest(terminal),
        result_receipt_sha256=terminal["receipt_sha256"], release_receipt=release,
        release_receipt_sha256=release["receipt_sha256"])
    local = copy.deepcopy(proof["local"])
    grants = local.pop("grants")
    # Unlike35, this scenario registers both grants before physical worker start.
    for grant in grants["grants"]:
        grant["issued_at"] = "2026-11-06T02:00:00.000000+00:00"
    local["admission_sha256"] = admission["admission_sha256"]
    local["attempt"].update(completion=terminal, release=release)
    inventory = copy.deepcopy(proof["inventories"][0])
    inventory["approval_context_sha256"] = {
        inventory["approvals"][0]["id"]: host.digest(original["review_context"])}
    inventory["results"][0]["receipt_sha256"] = terminal["receipt_sha256"]
    runtime = inventory["runtimes"][0]
    runtime.update(admission=admission, admission_sha256=admission["admission_sha256"], max_attempts=None)
    runtime["attempts"][0].update(terminal_receipt=terminal,
        terminal_receipt_sha256=host.digest(terminal), release_receipt=release)
    report_body = {k:physical[k] for k in ("runtime_sha256", "admission_sha256", "finished_at", "exit_code")}
    report_body.update(last_sequence="1", observation_sha256=host.digest({
        k:physical[k] for k in ("identity", "finished_at", "exit_code")}))
    report = persistent._purpose({"runtime_id":admission["runtime_id"]}, report_body)
    runtime["report_sha256"] = report
    retirement = copy.deepcopy(proof["retirement"])
    retirement.update(admission_sha256=admission["admission_sha256"], report_sha256=report)
    retirement["receipt_sha256"] = host.digest({k:v for k,v in retirement.items() if k != "receipt_sha256"})
    retained = copy.deepcopy(local)
    retained.update(state="retired", retirement=retirement)
    retained["attempt"].update(state="physical_retirement_observed", retired_from_state="released")
    before_worker = copy.deepcopy(proof["fixed"]["before_worker"])
    before_worker["approval_context_sha256"] = copy.deepcopy(inventory["approval_context_sha256"])
    before_idle = copy.deepcopy(inventory)
    before_idle["runtimes"][0].update(retired=False, new_work_disabled=False, report_sha256=None)
    status = {"schema":"vardr.worker-status/1", "runtime_id":admission["runtime_id"],
        "protocol":"persistent-v3", "mode":"persistent", "limits":admission["limits"],
        "identity":admission["identity"], "state":"idle-ready", "reason":None,
        "cursor":{"last_sequence":"1", "phase":"idle"},
        "availability":{"state":"idle-ready", "observed_at":"2026-11-06T02:00:05Z",
            "fresh_until":"2026-11-06T02:00:20Z", "cursor":{"last_sequence":"1", "phase":"idle"}},
        "new_work_disabled":False, "reporting_revoked":False, "registration_state":"acknowledged",
        "disable_state":"none", "stop_state":"none", "revocation_state":"none", "container_state":"running"}
    stopped = {**copy.deepcopy(status), "state":"stopped", "container_state":"exited",
        "cursor":None, "availability":None, "new_work_disabled":None, "reporting_revoked":None,
        "exit_code":124, "finished_at":physical["finished_at"]}
    owner = object.__new__(fixture.Fixture)
    owner.scenario, owner.protocol, owner.database_revision = fixture.IDLE_SCENARIO, "persistent-v3", "0041persistentruntime"
    owner.issuer_origin, owner.project, owner.secrets = admission["origin"], selection["project"], []
    raw = copy.deepcopy(count)
    raw.update(schema="vardr.nm2-worker-idle-acceptance/1", scenario=fixture.IDLE_SCENARIO,
        acceptance_scope="persistent_idle_control_only", status="prepared", stage="idle_control_setup")
    raw["fixture_stop"]["stop_requested_ids"] = [
        value for value in raw["fixture_stop"]["container_ids"]
        if value != physical["identity"]["container_id"]]
    raw["cases"].pop("persistent_count_limit")
    raw["cases"]["persistent_idle_limit"] = {"status":"not_run"}
    owner.receipt = raw
    owner.new_job = Mock(return_value=(original["engagement_id"], original["review_input"]["authorization_id"],
        original["job_id"], {"spec":spec}))
    def approved(*args, **kwargs):
        kwargs["review_snapshot"].update(copy.deepcopy(original["review_input"]))
        kwargs["review_context"].update(copy.deepcopy(original["review_context"]))
        kwargs["review_authority"].update(copy.deepcopy(original["review_authority"]))
        return admission["runner_id"], admission["enrollment_id"]
    owner.approve = Mock(side_effect=approved)
    def api(path, *args, **kwargs):
        if path.endswith("/jobs"):
            return {"jobs":[{"id":original["job_id"], "status":"done", "assessment":measured["assessment"]}]}
        if "/scans?" in path:
            return {"scans":[]}
        if "/evidence?" in path:
            return {"evidence":[{"body":"synthetic-redacted-evidence-"+str(i),
                "content_hash":fixture.digest(("synthetic-redacted-evidence-"+str(i)).encode())} for i in range(5)]}
        raise AssertionError("unexpected_synthetic_route")
    owner.api = Mock()
    owner.api.request.side_effect = api
    owner.inventory = Mock(side_effect=[before_worker, before_idle, copy.deepcopy(before_idle), inventory])
    rows = measured["requests"]
    owner.traffic = Mock(side_effect=[[], rows, copy.deepcopy(rows), copy.deepcopy(rows)])
    owner.worker = Mock(side_effect=lambda *_args, on_running: (on_running(admission), physical)[1])
    owner.persistent_metadata = Mock(side_effect=[local, copy.deepcopy(local), retained])
    owner.grant_snapshot = Mock(return_value=grants)
    owner.worker_action = Mock(side_effect=[status, stopped,
        {"state":"terminal_observed", "receipt":{"retirement":retirement}}])
    owner.report_exit = Mock(return_value=retirement)
    owner.helper = Mock(return_value=b'{"state":"terminal_completed","remaining_local_holds":0}')
    if run:
        run_owner(owner)
    return raw, selection, owner, admission, status, stopped


def run_owner(owner, zero=None):
    with patch.object(fixture.time, "monotonic", side_effect=range(100, 130)), patch.object(fixture.time, "sleep"):
        owner.persistent_idle_limit([] if zero is None else zero)


class IdleLimit(unittest.TestCase):
    def test_actual_fixture_and_fixed_verifier_feed_independent_idle_reader(self):
        raw, selection, owner, *_ = vector()
        public = reader.project(raw, selection)
        self.assertEqual(public["schema"], "vardr.nm2-worker-idle-public/1")
        self.assertEqual(public["measurements"]["native_exit_code"], 124)
        self.assertEqual(public["measurements"]["target_request_count"], 5)
        self.assertEqual(hosted.public_projection(raw, selection), public)
        self.assertEqual([call.args[0] for call in owner.worker_action.call_args_list], ["status", "status", "reconcile"])
        owner.helper.assert_called_once_with("audit", "reconcile-managed", raw["cases"][reader.CASE]["proof"]["local"]["attempt"]["run_id"])
        for old_reader in (count_reader, availability):
            with self.assertRaises(availability.ProjectionRefused):
                old_reader.project(raw, selection)
        self.assertNotIn("observation_seconds", public["measurements"])

    def test_explicit_idle_limits_and_existing_default_controls_are_separate(self):
        self.assertEqual(fixture.persistent_limits(fixture.IDLE_SCENARIO), reader.LIMITS)
        self.assertEqual(fixture.persistent_enable_args(fixture.IDLE_SCENARIO), ["--protocol", "persistent-v3", "--idle-timeout-seconds", "60"])
        self.assertEqual(fixture.persistent_limits("persistent-availability"), {"max_attempts":None, "idle_timeout_seconds":None})
        self.assertEqual(fixture.persistent_enable_args(fixture.COUNT_SCENARIO), ["--protocol", "persistent-v3", "--max-attempts", "1"])
        self.assertEqual(fixture.target_environment(fixture.IDLE_SCENARIO), {})

    def test_closed_status_accepts_product_stopped_shape_only_for_idle(self):
        _, _, _, admission, running, stopped = vector(run=False)
        now = datetime(2026, 11, 6, 2, 0, 6, tzinfo=timezone.utc)
        with patch.object(fixture, "datetime", wraps=datetime) as clock:
            clock.now.return_value = now
            self.assertEqual(fixture.idle_status_value(running, 0, admission), running)
        self.assertEqual(fixture.idle_status_value(stopped, 0, admission), stopped)
        result = subprocess.CompletedProcess([], 0, host.canonical(stopped), b"")
        with patch.object(fixture.subprocess, "run", return_value=result) as call:
            self.assertEqual(json.loads(fixture.worker_idle_status_command([], cwd=Path.cwd(), env={}, timeout=3,
                expected_admission=admission)), stopped)
            self.assertEqual(call.call_count, 1)
            with self.assertRaises(fixture.AcceptanceRefused):
                fixture.worker_status_command([], cwd=Path.cwd(), env={}, timeout=3, expected_admission=admission)

    def test_closed_status_refuses_changed_scope_types_metadata_and_secret_errors(self):
        _, _, _, admission, _, stopped = vector(run=False)
        for key, value in (("exit_code", 0), ("exit_code", 125), ("exit_code", True), ("exit_code", 124.0),
            ("limits", {"max_attempts":"1", "idle_timeout_seconds":"60"}),
            ("identity", {**stopped["identity"], "owner_nonce":"f"*64}),
            ("reason", CANARY), ("state", "held"), ("stop_state", "observed"),
            ("disable_state", "acknowledged"), ("cursor", {"last_sequence":"1", "phase":"idle"}),
            ("finished_at", CANARY), ("extra", CANARY)):
            with self.subTest(key=key, kind=type(value).__name__), self.assertRaises(ValueError):
                fixture.idle_status_value({**stopped, key:value}, 0, admission)
        for invalid in ("60", True, 60.0):
            changed = copy.deepcopy(admission)
            changed["limits"]["idle_timeout_seconds"] = invalid
            changed["admission_sha256"] = host.digest({k:v for k,v in changed.items() if k != "admission_sha256"})
            with self.subTest(idle_type=type(invalid).__name__), self.assertRaises(ValueError):
                fixture.idle_status_value({**stopped, "limits":changed["limits"]}, 0, changed)
        for code in (1, True, 0.0):
            with self.subTest(code=code), self.assertRaises(ValueError):
                fixture.idle_status_value(stopped, code, admission)
        with patch.object(fixture.subprocess, "run", side_effect=OSError(CANARY)):
            with self.assertRaisesRegex(fixture.AcceptanceRefused, "^idle_status_refused$") as error:
                fixture.worker_idle_status_command([], cwd=Path.cwd(), env={}, timeout=3, expected_admission=admission)
        self.assertNotIn(CANARY, str(error.exception))

    def test_one_job_only_no_claim_counter_or_traffic_changes_hidden_during_idle(self):
        for change in ("prefix", "suffix", "local-count", "map-counter", "hold", "native-done"):
            raw, _, owner, *_ = vector(run=False)
            if change in {"prefix", "suffix"}:
                extra = {"identity":"anonymous", "method":"GET", "path":"/extra", "received_monotonic_ns":9}
                traffic = copy.deepcopy(vector()[0]["cases"][reader.CASE]["proof"]["traffic_before_idle"])
                final = [extra]+traffic if change == "prefix" else traffic+[extra]
                owner.traffic.side_effect = [[], traffic, final]
            elif change == "map-counter":
                values = list(owner.inventory.side_effect)
                values[2]["targets_spent"] = 2
                owner.inventory.side_effect = values
            else:
                values = list(owner.persistent_metadata.side_effect)
                if change == "local-count": values[1]["counts"]["claims"] = 2
                elif change == "hold": values[1]["remaining_local_holds"] = 1
                else: values[1]["attempt"]["native_done_sha256"] = "f"*64
                owner.persistent_metadata.side_effect = values
            with self.subTest(change=change), self.assertRaises(fixture.AcceptanceRefused):
                run_owner(owner)
            owner.report_exit.assert_not_called()

    def test_nonempty_baseline_refuses_before_any_worker_or_approval(self):
        _, _, owner, *_ = vector(run=False)
        with self.assertRaises(fixture.AcceptanceRefused):
            run_owner(owner, [{"path":"/preexisting"}])
        owner.worker.assert_not_called()
        owner.approve.assert_not_called()

    def test_poll_bound_does_not_restart_or_request_operator_stop(self):
        _, _, owner, _, running, _ = vector(run=False)
        owner.worker_action.side_effect = None
        owner.worker_action.return_value = running
        with patch.object(fixture.time, "monotonic", side_effect=[100, 101, 102, 176]), patch.object(fixture.time, "sleep"):
            with self.assertRaisesRegex(fixture.AcceptanceRefused, "idle_native_exit_not_observed"):
                owner.persistent_idle_limit([])
        self.assertEqual([call.args[0] for call in owner.worker_action.call_args_list], ["status"])
        owner.report_exit.assert_not_called()

    def test_reader_refuses_mutations_even_when_status_flags_still_claim_success(self):
        raw, selection, *_ = vector()
        paths = [
            (("physical", "exit_code"), 125), (("physical", "exit_code"), True),
            (("physical", "operator_stop_state"), "stopped_observed"),
            (("proof", "admission", "limits", "idle_timeout_seconds"), None),
            (("proof", "after_idle", "counts", "claims"), 2),
            (("proof", "local", "grants", "grants", 0, "issued_at"), "2026-11-06T02:00:01.000000+00:00"),
            (("proof", "after_idle", "remaining_local_holds"), 1),
            (("proof", "retained", "attempt", "native_done_sha256"), "f"*64),
            (("proof", "retirement", "runtime_sequence"), "1"),
            (("proof", "observation_seconds"), True), (("proof", "observation_seconds"), 76),
            (("proof", "status_after_idle", "stop_state"), "observed"),
            (("proof", "selection", "review_input", "authorization_id"), "changed-authorization"),
        ]
        for path, value in paths:
            altered = copy.deepcopy(raw)
            node = altered["cases"][reader.CASE]
            for key in path[:-1]: node = node[key]
            node[path[-1]] = value
            with self.subTest(path=path), self.assertRaisesRegex(availability.ProjectionRefused, "^nm2_idle_projection_refused$"):
                reader.project(altered, selection)

        altered = copy.deepcopy(raw)
        altered["fixture_stop"]["stop_requested_ids"].append(
            altered["cases"][reader.CASE]["physical"]["identity"]["container_id"])
        with self.assertRaises(availability.ProjectionRefused):
            reader.project(altered, selection)

    def test_reader_refuses_drift_with_rehashed_review_but_unchanged_registered_context(self):
        raw, selection, *_ = vector()
        original = raw["cases"][reader.CASE]["proof"]["selection"]
        original["review_authority"]["authority_revision"] += 1
        original["review_context"]["authority_revision"] += 1
        original["review_context"]["authority_sha256"] = host.digest(original["review_authority"])
        with self.assertRaises(availability.ProjectionRefused):
            reader.project(raw, selection)

    def test_idle_status_presence_joins_same_incarnation_at_nanosecond_boundaries(self):
        raw, selection, *_ = vector()
        proof = raw["cases"][reader.CASE]["proof"]
        for observed in ("2026-11-06T02:00:00Z", "2026-11-06T02:02:01Z"):
            altered = copy.deepcopy(raw)
            presence = altered["cases"][reader.CASE]["proof"]["status_before_idle"]["availability"]
            presence.update(observed_at=observed, fresh_until=(datetime.fromisoformat(
                observed.replace("Z", "+00:00"))+timedelta(seconds=15)).isoformat().replace("+00:00", "Z"))
            with self.subTest(observed=observed), self.assertRaises(availability.ProjectionRefused):
                reader.project(altered, selection)
        # Map emits UTCZ seconds; Docker started/finished timestamps retain9 digits.
        for started, accepted in (("2026-11-06T02:00:01Z", True),
                                  ("2026-11-06T02:00:01.000000001Z", False)):
            selected = copy.deepcopy(proof)
            admission = copy.deepcopy(proof["admission"])
            physical = copy.deepcopy(raw["cases"][reader.CASE]["physical"])
            admission["identity"]["started_at"] = started
            for key in ("status_before_idle", "status_after_idle"):
                selected[key]["identity"] = copy.deepcopy(admission["identity"])
            selected["status_before_idle"]["availability"].update(
                observed_at="2026-11-06T02:00:01Z", fresh_until="2026-11-06T02:00:16Z")
            if accepted:
                reader.statuses(selected, admission, physical)
            else:
                with self.assertRaises(availability.ProjectionRefused):
                    reader.statuses(selected, admission, physical)
        selected = copy.deepcopy(proof)
        physical = copy.deepcopy(raw["cases"][reader.CASE]["physical"])
        physical["finished_at"] = "2026-11-06T02:00:04.999999999Z"
        selected["status_after_idle"]["finished_at"] = physical["finished_at"]
        with self.assertRaises(availability.ProjectionRefused):
            reader.statuses(selected, proof["admission"], physical)

    def test_count_public_review_keeps_original_whitelist_after_private_extraction(self):
        raw, selection, *_ = vector()
        proof = raw["cases"][reader.CASE]["proof"]
        with self.assertRaises(availability.ProjectionRefused):
            count_reader.review(proof["selection"], proof["admission"], proof["fixed"]["before_worker"],
                raw["image_sources"]["runner"]["executables"]["/usr/local/bin/vardrgate"], selection["project"])


if __name__ == "__main__":
    unittest.main()
