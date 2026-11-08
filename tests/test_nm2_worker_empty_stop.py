"""Explicit zero-issued-job lifecycle; all external I/O is synthetic and mocked."""

import copy
from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

import nm2_worker_acceptance as fixture
import nm2_worker_hosted as hosted
import nm2_worker_persistent_projection as common
import test_nm2_worker_persistent_projection as vectors
import worker_host as host
import worker_host_persistent as persistent


SCENARIO = "persistent-empty-stop"
CASE = "persistent_empty_stop"


def vector(*, run=True, desktop=False):
    if desktop:
        raw, selection, before, after = vectors.desktop_vector()
    else:
        raw, selection = vectors.vector()
        before = after = None
    selection.setdefault("docker_context", "default")
    old = raw["cases"]["persistent_availability"]
    admission = copy.deepcopy(old["proof"]["idle"]["admission"])
    physical = copy.deepcopy(old["physical"])
    physical["operator_enable_state"] = "enabled"
    ready = copy.deepcopy(old["proof"]["idle"]["status"])
    ready["availability"].update(observed_at="2026-11-06T02:00:00Z", fresh_until="2026-11-06T02:00:15Z")
    audit = {"schema":"vardr.worker-state-audit/1", "status":"empty_unissued", "reason":None,
        "complete":True, "binding":{key:admission[key] for key in (
            "runner_id", "runtime_id", "runtime_sha256", "admission_sha256")},
        "parent":{"state":"idle", "last_sequence":"0", "head_sequence":None, "active_sequence":None},
        "counts":{"attempts":0, "selections":0, "associated_runs":0, "associated_claims":0},
        "retirement_receipt_sha256":None, "global_holds":0}
    stop = {"schema":"vardr.worker-cli/1", "state":"stopped_observed",
        "runtime_id":admission["runtime_id"], "identity":admission["identity"],
        "exit_code":physical["exit_code"], "finished_at":physical["finished_at"],
        "new_work_disable_state":"acknowledged", "local_runner_reconciliation":"required"}
    report = {key:physical[key] for key in ("runtime_sha256", "admission_sha256", "finished_at", "exit_code")}
    report.update(last_sequence="0", observation_sha256=host.digest({
        key:physical[key] for key in ("identity", "finished_at", "exit_code")}))
    retirement = {"schema":"vardr.worker-retirement/3",
        **{key:admission[key] for key in ("runtime_id", "runtime_sha256", "admission_sha256", "origin", "runner_id", "enrollment_id")},
        "runtime_sequence":None, "last_sequence":"0", "binding":None, "attempt_receipt":None,
        "report_sha256":persistent._purpose({"runtime_id":admission["runtime_id"]}, report), "retired":True}
    retirement["receipt_sha256"] = host.digest(retirement)
    lookup = {"schema":"vardr.worker-receipt-observation/3",
        **{key:admission[key] for key in ("runtime_id", "runtime_sha256", "admission_sha256")},
        "cursor":{"last_sequence":"0", "phase":"idle"}, "active":None,
        "retirement":retirement, "new_work_disabled":True, "reporting_revoked":False,
        "availability":{"state":"stopped", "observed_at":None, "fresh_until":None,
            "cursor":{"last_sequence":"0", "phase":"idle"}}}
    reconciled = {"schema":"vardr.worker-cli/1", "state":"terminal_observed",
        "runtime_id":admission["runtime_id"], "receipt":lookup, "local_runner_reconciliation":"required"}
    raw.update(schema="vardr.nm2-worker-empty-acceptance/1", scenario=SCENARIO,
        acceptance_scope="persistent_empty_stop_only", status="prepared", stage="managed_setup")
    raw["cases"] = {name:{"status":"not_run"} for name in fixture.INITIAL_CASES}
    raw["cases"]["default_disabled"] = {
        "status":"passed", "services":["api","db","proxy","web"],
        "managed_pending_status":404, "csrf_write_status":403, "unauthenticated_read_status":401}
    raw["cases"][CASE] = {"status":"not_run"}
    raw["fixture_stop"]["stop_requested_ids"] = []
    owner = object.__new__(fixture.Fixture)
    owner.scenario, owner.protocol = SCENARIO, "persistent-v3"
    owner.project, owner.m, owner.images = selection["project"], selection, selection["images"]
    owner.environment = {}
    owner.receipt, owner.issuer_origin = raw, admission["origin"]
    owner.enroll_runner = Mock(return_value=(admission["runner_id"], admission["enrollment_id"]))
    owner.api = Mock()
    owner.api.request = Mock(side_effect=lambda route: {"engagements":[], "programs":[]} if route == "/engagements" else (_ for _ in ()).throw(AssertionError("job_api_not_authorized")))
    owner.traffic = Mock(return_value=[])
    owner.persistent_idle = Mock(return_value=ready)
    volume = {"daemon_id":admission["identity"]["daemon_id"], "endpoint":"unix:///var/run/docker.sock",
        "root":"/var/lib/docker", "name":selection["project"]+"_runner-state", "driver":"local",
        "scope":"local", "options":None, "source":"/var/lib/docker/volumes/"+selection["project"]+"_runner-state/_data",
        "created_at":"2026-11-06T01:00:00Z", "project":selection["project"], "volume":"runner-state"}
    owner.empty_audit_volumes = []
    owner.empty_audit_volume = Mock(return_value=volume)
    def synthetic_audit(_admission):
        owner.empty_audit_volumes.append({"before":copy.deepcopy(volume), "after":copy.deepcopy(volume)})
        return copy.deepcopy(audit)
    owner.empty_worker_state = Mock(side_effect=synthetic_audit)
    owner.worker_action = Mock(side_effect=[stop, reconciled])
    owner.report_exit = Mock(return_value=retirement)
    owner.worker = Mock(side_effect=lambda *_args, on_running: (on_running(admission), physical)[1])
    owner.new_job = Mock(side_effect=AssertionError("job_creation_not_authorized"))
    owner.approve = Mock(side_effect=AssertionError("approval_not_authorized"))
    owner.inventory = Mock(side_effect=AssertionError("distribution_sql_not_authorized"))
    owner.helper = Mock(side_effect=AssertionError("no_original_run_exists"))
    if run:
        with patch.object(fixture, "datetime", wraps=datetime) as clock:
            clock.now.return_value = datetime(2026,11,6,2,0,6,123456,tzinfo=timezone.utc)
            owner.persistent_empty_stop()
    return raw, selection, owner, admission, audit, before, after


class EmptyStop(unittest.TestCase):
    def test_explicit_choice_is_inert_and_unlimited(self):
        self.assertIn(SCENARIO, fixture.SCENARIOS)
        self.assertEqual(fixture.persistent_limits(SCENARIO), {"max_attempts":None, "idle_timeout_seconds":None})
        self.assertEqual(fixture.persistent_enable_args(SCENARIO), ["--protocol", "persistent-v3"])
        self.assertEqual(fixture.target_environment(SCENARIO), {})

    def test_actual_source_only_entrypoint_selects_empty_explicitly_and_keeps_healthy_default(self):
        _, selection, *_ = vector(run=False)
        for args, expected in (([], list(fixture.INITIAL_CASES)),
                (["--scenario",SCENARIO,"--database-revision","0041persistentruntime"], ["default_disabled", CASE])):
            output = io.StringIO()
            with patch.object(fixture, "manifest", return_value=selection), \
                    patch.object(fixture.Fixture, "run", side_effect=AssertionError("runtime_not_authorized")) as run, \
                    patch.object(fixture, "command", side_effect=AssertionError("command_not_authorized")) as command, redirect_stdout(output):
                self.assertEqual(fixture.main(["--cohort","unused-source-only.json",*args]), 0)
            value = json.loads(output.getvalue())
            self.assertEqual(value["initial_cases"], expected)
            self.assertEqual(value["docker_calls"], 0)
            run.assert_not_called()
            command.assert_not_called()

    def test_actual_producer_and_independent_reader_prove_empty_not_local_retired(self):
        import nm2_worker_empty_projection as reader
        raw, selection, owner, admission, *_ = vector()
        result = reader.project(raw, selection)
        self.assertEqual(result["measurements"]["issued_attempts"], 0)
        self.assertEqual(result["measurements"]["local_retirement"], "not_applicable_empty_unissued")
        self.assertEqual(hosted.public_projection(raw, selection), result)
        owner.persistent_idle.assert_called_once_with(admission, 0)
        self.assertEqual([call.args[0] for call in owner.worker_action.call_args_list], ["stop", "reconcile"])
        self.assertEqual(owner.empty_worker_state.call_count, 2)
        owner.new_job.assert_not_called()
        owner.approve.assert_not_called()
        owner.inventory.assert_not_called()
        owner.helper.assert_not_called()
        self.assertEqual([call.args for call in owner.api.request.call_args_list], [("/engagements",), ("/engagements",)])

    def test_false_empty_dto_or_nonempty_map_or_traffic_never_passes_producer(self):
        for kind in ("count", "hold", "incomplete", "unsupported", "binding", "parent", "digest", "map", "traffic"):
            with self.subTest(kind=kind):
                _, _, owner, _, audit, *_ = vector(run=False)
                changed = copy.deepcopy(audit)
                if kind == "count": changed["counts"]["associated_runs"] = 1
                if kind == "hold": changed["global_holds"] = 1
                if kind == "incomplete": changed.update(complete=False, counts=None, parent=None, global_holds=None)
                if kind == "unsupported": changed["schema"] = "unsupported"
                if kind == "binding": changed["binding"]["runtime_sha256"] = "f"*64
                if kind == "parent": changed["parent"]["last_sequence"] = "1"
                if kind == "digest": changed["retirement_receipt_sha256"] = "f"*64
                owner.empty_worker_state.side_effect = [changed, copy.deepcopy(audit)]
                if kind == "map": owner.api.request.return_value = {"engagements":[{}], "programs":[{}]}; owner.api.request.side_effect = None
                if kind == "traffic": owner.traffic.return_value = [{"path":"/unexpected"}]
                with self.assertRaises(ValueError): owner.persistent_empty_stop()

    def test_reader_rejects_independent_tampering_and_old_readers_refuse_scope(self):
        import nm2_worker_empty_projection as reader
        import nm2_worker_count_projection as count
        import nm2_worker_idle_projection as idle
        for kind in ("count", "bool", "hold", "binding", "retire-sequence", "retire-active", "traffic", "inventory", "missing-stop", "status-before-start"):
            with self.subTest(kind=kind):
                raw, selection, *_ = vector()
                proof = raw["cases"][CASE]["proof"]
                if kind == "count": proof["audit_after"]["counts"]["attempts"] = 1
                if kind == "bool": proof["audit_before"]["global_holds"] = False
                if kind == "hold": proof["audit_before"]["global_holds"] = 1
                if kind == "binding": proof["audit_after"]["binding"]["runner_id"] = vectors.identifier(987)
                if kind == "retire-sequence": proof["retirement"]["last_sequence"] = "1"
                if kind == "retire-active": proof["host_reconciled"]["receipt"]["active"] = {}
                if kind == "traffic": proof["traffic_after"] = [{"path":"/unexpected"}]
                if kind == "inventory": proof["engagements_after"] = {"engagements":[], "programs":[{}]}
                if kind == "missing-stop": proof["operator_stop"]["new_work_disable_state"] = "unknown"
                if kind == "status-before-start": proof["status"]["availability"]["observed_at"] = "2026-11-05T02:00:00Z"
                with self.assertRaises(common.ProjectionRefused): reader.project(raw, selection)
        raw, selection, *_ = vector()
        for old in (count, idle, common):
            with self.assertRaises(common.ProjectionRefused): old.project(raw, selection)

    def test_offline_audit_command_has_only_named_state_volume_and_no_network_credentials(self):
        _, _, owner, admission, *_ = vector(run=False)
        del owner.empty_worker_state
        result = subprocess.CompletedProcess([], 0, json.dumps(vector(run=False)[4]).encode(), b"")
        with patch("nm2_worker_acceptance.subprocess.run", return_value=result) as run:
            self.assertEqual(owner.empty_worker_state(admission)["status"], "empty_unissued")
        call = run.call_args
        self.assertEqual(call.args[0][:3], ["docker", "--context", owner.m["docker_context"]])
        args = list(call.args[0][3:])
        self.assertEqual(args[:8], ["run", "--rm", "--pull", "never", "--user", "10001:10001", "--read-only", "--network"])
        self.assertEqual(args[8], "none")
        self.assertEqual(args.count("--mount"), 1)
        mount = args[args.index("--mount")+1]
        self.assertEqual(mount, "type=volume,source="+owner.project+"_runner-state,target=/home/runner/.vardrmap")
        self.assertEqual([args[i+1] for i,a in enumerate(args) if a == "--env"], ["HOME=/home/runner", "PYTHONDONTWRITEBYTECODE=1"])
        self.assertEqual(args[args.index("--cap-drop")+1], "ALL")
        self.assertEqual(args[args.index("--security-opt")+1], "no-new-privileges:true")
        self.assertEqual(args[args.index("--entrypoint")+1], "vardrrunner")
        self.assertIn(owner.images["worker"], args)
        self.assertIn("worker-state", args)
        self.assertNotIn("audit", args)
        self.assertEqual(call.kwargs, {"env": owner.environment, "capture_output": True,
                                      "timeout": 45, "check": True})

    def test_auditor_has_project_ownership_and_its_own_fixed_resource_bounds(self):
        _, _, owner, admission, audit, *_ = vector(run=False)
        del owner.empty_worker_state
        result = subprocess.CompletedProcess([], 0, json.dumps(audit).encode(), b"")
        with patch("nm2_worker_acceptance.subprocess.run", return_value=result) as run:
            owner.empty_worker_state(admission)
        args = list(run.call_args.args[0][3:])
        for flag,value in (("--label","com.docker.compose.project="+owner.project),
                ("--pids-limit","64"), ("--memory","512m"), ("--cpus","1")):
            with self.subTest(flag=flag):
                self.assertIn(flag,args)
                self.assertEqual(args[args.index(flag)+1],value)
        self.assertEqual(args.count("--label"),1)

    def test_ready_status_requires_recorded_fresh_sample_not_merely_physical_interval(self):
        import nm2_worker_empty_projection as reader
        for observed,ending in (("2026-11-06T01:59:01Z","2026-11-06T01:59:16Z"),
                ("2026-11-06T02:00:07Z","2026-11-06T02:00:22Z")):
            raw, selection, *_ = vector()
            proof = raw["cases"][CASE]["proof"]
            proof["status"]["availability"].update(observed_at=observed,fresh_until=ending)
            with self.subTest(observed=observed), self.assertRaises(common.ProjectionRefused):
                reader.project(raw,selection)

    def test_missing_fresh_sample_is_unobserved_and_sample_boundaries_keep_precision(self):
        import nm2_worker_empty_projection as reader
        raw, selection, *_ = vector()
        proof = raw["cases"][CASE]["proof"]
        proof.pop("status_observed_at",None)
        with self.assertRaises(common.ProjectionRefused): reader.project(raw,selection)
        for sample in ("2026-11-06T02:00:15Z", "2026-11-06T01:59:59.999999999Z",
                "2026-11-06T02:02:00.123456790Z", False):
            raw, selection, *_ = vector()
            raw["cases"][CASE]["proof"]["status_observed_at"] = sample
            with self.subTest(sample=sample), self.assertRaises(common.ProjectionRefused): reader.project(raw,selection)
        raw, _, _, _, _, *_ = vector()
        proof = raw["cases"][CASE]["proof"]
        physical = copy.deepcopy(raw["cases"][CASE]["physical"])
        cursor = {"last_sequence":"0", "phase":"idle"}
        ending_presence = {"state":"idle-ready", "observed_at":"2026-11-06T02:02:00Z",
            "fresh_until":"2026-11-06T02:02:15Z", "cursor":cursor}
        with self.assertRaises(common.ProjectionRefused):
            reader.presence(ending_presence, cursor=cursor,
                state="idle-ready", physical=physical, sampled_at="2026-11-06T02:02:00.123456790Z")
        reader.presence(ending_presence, cursor=cursor,
            state="idle-ready", physical=physical, sampled_at="2026-11-06T02:02:00.123456789Z")
        reader.presence(proof["status"]["availability"], cursor=cursor,
            state="idle-ready", physical=raw["cases"][CASE]["physical"], sampled_at="2026-11-06T02:00:06Z")

    def test_missing_preexisting_volume_refuses_before_auditor_without_creating_anything(self):
        _, _, owner, admission, *_ = vector(run=False)
        del owner.empty_worker_state
        owner.empty_audit_volume.side_effect = fixture.AcceptanceRefused("empty_audit_volume_not_bound")
        owner.docker = Mock(side_effect=AssertionError("audit_run_must_not_happen"))
        with self.assertRaises(fixture.AcceptanceRefused): owner.empty_worker_state(admission)
        owner.docker.assert_not_called()

    def test_exact_local_volume_metadata_and_daemon_are_rechecked_around_audit(self):
        _, _, owner, admission, audit, *_ = vector(run=False)
        volume = owner.empty_audit_volume.return_value
        del owner.empty_audit_volume
        projected = {key:value for key,value in volume.items() if key not in {"daemon_id", "endpoint", "root"}}
        def docker(*args, **kwargs):
            if args[:2] == ("context", "inspect"): return json.dumps(volume["endpoint"]).encode()
            if args[:3] == ("info", "--format", "{{json .ID}}"): return json.dumps(volume["daemon_id"]).encode()
            if args[:2] == ("info", "--format"): return b'{"root":"/var/lib/docker","os":"linux"}'
            if args[:2] == ("volume", "inspect"): return json.dumps(projected).encode()
            raise AssertionError("unexpected_synthetic_docker_route")
        owner.docker = Mock(side_effect=docker)
        self.assertEqual(owner.empty_audit_volume(admission), volume)
        self.assertEqual(owner.docker.call_count, 4)
        for key,value in (("project","other"), ("volume","other"), ("driver","remote"),
                ("source","/outside"), ("created_at",None), ("options",{"device":"/outside"})):
            changed = dict(projected)
            changed[key] = value
            owner.docker.side_effect = lambda *a, **kw: json.dumps(changed).encode() if a[:2] == ("volume","inspect") else docker(*a, **kw)
            with self.subTest(key=key), self.assertRaises((ValueError, TypeError)): owner.empty_audit_volume(admission)

    def test_changed_post_volume_metadata_is_held_with_no_empty_credit(self):
        _, _, owner, admission, audit, *_ = vector(run=False)
        del owner.empty_worker_state
        before = owner.empty_audit_volume.return_value
        owner.empty_audit_volume.side_effect = [before, {**before,"created_at":"2026-11-06T03:00:00Z"}]
        result = subprocess.CompletedProcess([], 0, json.dumps(audit).encode(), b"")
        with patch("nm2_worker_acceptance.subprocess.run", return_value=result), self.assertRaisesRegex(
                ValueError, "empty_audit_volume_changed"):
            owner.empty_worker_state(admission)
        self.assertEqual(owner.empty_audit_volumes, [])

    def test_desktop_reader_uses_the_same_independent_inventory_guard(self):
        import nm2_worker_empty_projection as reader
        raw, selection, _, _, _, before, after = vector(desktop=True)
        result = reader.project_desktop(raw, selection, before, after)
        self.assertEqual(result["schema"], "vardr.nm2-worker-empty-desktop-public/1")
        self.assertEqual(result["measurements"]["issued_attempts"], 0)
        after["containers"][raw["cases"][CASE]["physical"]["identity"]["container_id"]]["state"]["exit_code"] = 99
        with self.assertRaises(common.ProjectionRefused): reader.project_desktop(raw, selection, before, after)

    def test_reader_refuses_changed_volume_metadata_independent_of_closed_empty_dto(self):
        import nm2_worker_empty_projection as reader
        for key,value in (("created_at","2026-11-06T03:00:00Z"), ("source","/different"),
                ("daemon_id","other"), ("name","other_runner-state"), ("volume","other")):
            raw, selection, *_ = vector()
            raw["cases"][CASE]["proof"]["audit_volumes"][1]["after"][key] = value
            with self.subTest(key=key), self.assertRaises(common.ProjectionRefused): reader.project(raw, selection)

    def test_existing_enrollment_logic_has_two_actual_callers_without_approval_side_effect(self):
        _, _, owner, admission, *_ = vector(run=False)
        del owner.enroll_runner
        owner.owner, owner.key = "owner-synthetic", {"id":"synthetic-key-id", "token":"synthetic-token"}
        owner.helper = Mock(return_value=("Runner ID: "+admission["runner_id"]+"\n").encode())
        owner.compose = Mock(return_value=json.dumps({"enrollment_id":admission["enrollment_id"]}).encode())
        self.assertEqual(owner.enroll_runner(), (admission["runner_id"], admission["enrollment_id"]))
        owner.helper.assert_called_once_with("identity", "show")
        owner.compose.assert_called_once()
        self.assertEqual(owner.runner_binding, (admission["runner_id"], admission["enrollment_id"]))


if __name__ == "__main__":
    unittest.main()
