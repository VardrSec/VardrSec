"""Inert single-job source models; no fault, worker or SDK operation."""
import ast
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import nm2_worker_runner_loss as loss
import nm2_worker_boundary_pair as boundary
import nm2_worker_boundary_build as build
from nm2_worker_acceptance import AcceptanceRefused, canonical, digest
from test_nm2_worker_boundary_pair import joined_vector, synthetic_linux_fixture, protocol_plan, guard_files


def vector():
    oldq,oldbinding = synthetic_linux_fixture()
    q = json.loads(oldq)
    wrapper = digest(build.render_boundary_wrapper(oldbinding["genuine_gate_sha256"],operand="runner-loss"))
    q["source_recipe"].update(template_sha256=build.RUNNER_LOSS_TEMPLATE_SHA,rendered_wrapper_sha256=wrapper)
    for name in (build.GATE,build.WRAPPER): q["file_hashes"][name] = wrapper
    expected = canonical(q),build.binding_for_qualification(q,q["source_recipe"]["sources"],q["source_recipe"]["source_trees"],operand="runner-loss")
    raw,selection,inventories = joined_vector(expected_fixture=expected)
    old = raw.pop("boundary_pair"); s = old["second"]; local = s["original"]
    case = s["case"]; case[2]["spec"] = boundary.fixed_case(boundary.RUNNER_LOSS_MODE)
    plan = protocol_plan(case[2]["spec"],wrapper)
    s["review"]["input"]["plan"] = plan
    s["review"]["context"]["plan_sha256"] = digest(canonical(plan))
    local["claim"].update(plan_sha256=digest(canonical(plan)),case_sha256=plan["case_hash"],tool_sha256=wrapper,utc_anchor="2026-01-01T00:00:00Z")
    local["started_at"]="2026-01-01T00:00:00Z"
    local["guards"] = guard_files(plan,boundary.RUNNER_LOSS_MODE,expected[1]["genuine_gate_sha256"])
    local["attempt"]["binding"]["runtime_sequence"] = "1"
    zero = boundary.stamp("2026-01-01T00:00:00Z")
    row = local["records"][0]
    local["records"] = []
    for i,(role,event,pid,ppid) in enumerate((("wrapper","begin",10,7),("wrapper","gate-return",10,7),("leaf","ready",12,10),("wrapper","parent-kill-intent",10,7))):
        local["records"].append({**deepcopy(row),"mode":boundary.RUNNER_LOSS_MODE,"role":role,"event":event,"pid":pid,"ppid":ppid,
            "boottime_ns":(i+1)*boundary.NS,"utc_ns":zero+(i+1)*boundary.NS,
            "counters":dict(allocated_bytes=33554432,steps=1,touches=1) if role=="leaf" else None})
    local["marker"] = dict(loss.MARKER)
    before = s["before"]; runtime = before["runtimes"][0]
    runtime.update(last_sequence="1",head_sequence="1",active_sequence="1",attempts=[runtime["attempts"][1]])
    runtime["attempts"][0]["runtime_sequence"] = "1"
    physical = old["physical"]; physical["finished_at"] = raw["launch"]["finished_at"] = "2026-01-01T00:00:05Z"
    inventories[1]["containers"][raw["launch"]["container_id"]]["state"]["finished_at"] = physical["finished_at"]
    retired = old["retirement"]; retired.update(last_sequence="1",runtime_sequence="1")
    retired["receipt_sha256"] = digest(canonical({k:v for k,v in retired.items() if k!="receipt_sha256"}))
    raw["launch"]["retirement_sha256"] = retired["receipt_sha256"]
    terminal = retired["attempt_receipt"]
    after = {**deepcopy(before),"job_status":"failed","capacity_reserved_count":0,
        "execution":{**before["execution"],"state":"failed","capacity_reserved":False},
        "runtimes":[{**deepcopy(runtime),"retired":True,"new_work_disabled":True,"report_sha256":retired["report_sha256"]}],
        "stops":[{k:terminal[k] for k in ("contract_id","receipt_sha256","outcome","cause")}]}
    audit = old["audit"]; audit.update(parent=dict(state="retired",last_sequence="1",head_sequence="1",active_sequence=None),
        counts=dict.fromkeys(("attempts","selections","associated_runs","associated_claims"),1),retirement_receipt_sha256=retired["receipt_sha256"])
    reconciliation = old["reconciliation"]; reconciliation.update(selected_sequence="1",retirement_receipt_sha256=retired["receipt_sha256"])
    host = old["host_reconciled"]; host["receipt"]["retirement"] = retired
    host["receipt"]["cursor"]["last_sequence"] = host["receipt"]["active"]["runtime_sequence"] = "1"
    held = {**deepcopy(audit),"status":"held","reason":"local_holds","parent":dict(state="active",last_sequence="1",head_sequence="1",active_sequence="1"),"global_holds":1,"retirement_receipt_sha256":None}
    traffic = old["traffic"][5:]
    for i,r in enumerate(traffic):
        r["path"] = r["path"].replace(boundary.MODES[1][4:],boundary.RUNNER_LOSS_MODE[4:]); r["received_utc_ns"] = zero+boundary.NS+(i+1)*100000000
    retained = deepcopy(local); retained["phase"] = "failed"
    retained["attempt"].update(state="physical_retirement_observed",retired_from_state="bound")
    raw.update(scenario=loss.SCENARIO,acceptance_scope="single_live_runner_loss_only",status="selected_runner_loss_passed",stage="selected_runner_loss_complete",
        after_sha256=digest(canonical(inventories[1])))
    raw["runner_loss"] = dict(case=case,run_id=s["run_id"],review=s["review"],original=local,before=before,held_audit=held,
        admission=old["admission"],physical=physical,retirement=retired,audit=audit,reconciliation=reconciliation,after=after,
        traffic=traffic,retained=retained,host_reconciled=host)
    return raw,selection,inventories,expected


class RunnerLossTests(unittest.TestCase):
    def test_complete_original_retirement_and_retention_join(self):
        raw,selection,inventories,expected = vector()
        result = loss.runner_loss_projection(raw,selection,inventories,expected_fixture=expected)
        self.assertEqual(result["schema"],"vardr.nm2-hosted/27")
        self.assertEqual(result["owned_stopped_container_count"],6)
        self.assertTrue(result["post_signal_call_returned"])
        self.assertFalse(result["done_or_artifact_promoted"])
        self.assertEqual((result["capacity_before"],result["capacity_after"]),(1,0))

    def test_missing_marker_late_exit_done_and_history_never_pass(self):
        for kind in ("marker","byte","late","bool125","done","promotion","release","charges","holds","disabled","identity","traffic","retained","parent"):
            raw,selection,inventories,expected = vector(); s=raw["runner_loss"]
            if kind=="marker": s["original"]["marker"]=None
            elif kind=="byte": s["original"]["marker"]["sha256"]="0"*64
            elif kind=="late":
                s["physical"]["finished_at"]=raw["launch"]["finished_at"]="2026-01-01T00:00:10Z"
                inventories[1]["containers"][raw["launch"]["container_id"]]["state"]["finished_at"]=s["physical"]["finished_at"]
                raw["after_sha256"]=digest(canonical(inventories[1]))
            elif kind=="bool125": s["physical"]["exit_code"]=True
            elif kind=="done": s["original"]["attempt"]["native_done_sha256"]="0"*64
            elif kind=="promotion": s["retained"]["artifact_sha256"]="0"*64
            elif kind=="release": s["original"]["attempt"]["release_ack"]={}
            elif kind=="charges": s["after"]["targets_spent"]=0
            elif kind=="holds": s["audit"]["global_holds"]=1
            elif kind=="disabled": s["after"]["runtimes"][0]["new_work_disabled"]=False
            elif kind=="identity": s["physical"]["identity"]={**s["physical"]["identity"],"owner_nonce":"0"*64}
            elif kind=="traffic": s["traffic"][-1]["method"]="POST"
            elif kind=="retained": s["retained"]["guards"][boundary.GUARD_NAMES[0]]["sha256"]="0"*64
            else: s["original"]["records"][-1]["ppid"]=8
            with self.subTest(kind=kind),self.assertRaises((AcceptanceRefused,ValueError)):
                loss.runner_loss_projection(raw,selection,inventories,expected_fixture=expected)

    def test_marker_operand_is_closed_and_requires_original_child_guard(self):
        raw,selection,inventories,expected=vector()
        with self.assertRaises(ValueError): build.render_boundary_wrapper("b"*64,operand="arbitrary")
        self.assertEqual(digest(build.render_boundary_wrapper(build.ORIGINAL_SHA)),boundary.WRAPPER)
        self.assertEqual(digest(build.render_boundary_wrapper(build.ORIGINAL_SHA,operand="runner-loss")),build.RUNNER_LOSS_TEMPLATE_SHA)
        with self.assertRaises(ValueError): build.binding_for_qualification(json.loads(expected[0]),expected[1]["source_recipe"]["sources"],expected[1]["source_recipe"]["source_trees"])
        raw["runner_loss"]["original"]["guards"][boundary.GUARD_NAMES[1]]["size"]=1
        with self.assertRaises(AcceptanceRefused): loss.runner_loss_projection(raw,selection,inventories,expected_fixture=expected)

    def test_observe_uses_one_exact_wait_typed_exit_and_held_adapter(self):
        raw,_,_,_=vector(); s=raw["runner_loss"]
        f=object.__new__(loss.RunnerLossFixture); f.runner_loss_review=s["review"]
        f.traffic=Mock(return_value=s["traffic"]);f.docker=Mock()
        f.helper=Mock(return_value=canonical([dict(job_id=s["case"][1],run_id=s["run_id"])]))
        f.unreported_attempt=Mock(return_value=s["before"]);f.worker_state=Mock(return_value=s["held_audit"])
        identity=SimpleNamespace(container_id="c"*64); exited=SimpleNamespace(exit_code=125)
        observer=Mock();observer.observe_exit.return_value=exited
        with patch.object(loss,"read_original",return_value=s["original"]):
            self.assertIs(f.observe_runner_loss(observer,identity,s["admission"],s["case"],None),exited)
        f.docker.assert_called_once_with("container","wait",identity.container_id,timeout=40)
        observer.observe_exit.assert_called_once_with(identity);observer.confirm_exit.assert_called_once_with(exited)
        f.worker_state.assert_called_once_with(s["admission"],expected_held="issued_unknown")
        f.unreported_attempt.assert_called_once_with(s["admission"],s["case"],identity,disabled=False)

    def test_close_reuses_original_host_exit_once_without_successor(self):
        raw,_,_,_=vector(); s=raw["runner_loss"]
        f=object.__new__(loss.RunnerLossFixture);f.receipt={};f.runner_loss_state={k:s[k] for k in ("case","run_id","review","original","before","held_audit","admission")}
        f.verify_host_exit_reconciliation=Mock(return_value=s["audit"])
        f.runner_loss_reconciliation=s["reconciliation"];f.retired_predecessor_inventory=s["after"];f.traffic=Mock(return_value=s["traffic"])
        with patch.object(loss,"read_original",return_value=s["retained"]): f.close_runner_loss(s["physical"],s["admission"],s["retirement"],s["case"])
        f.verify_host_exit_reconciliation.assert_called_once_with(s["admission"],s["retirement"],s["case"],s["run_id"],s["before"],proof_key="runner_loss")
        self.assertEqual(f.receipt["runner_loss"]["retained"],s["retained"])

    def test_default_cli_is_inert_before_manifest_or_constructor(self):
        with patch.object(loss,"manifest",side_effect=AssertionError),patch.object(loss,"RunnerLossFixture",side_effect=AssertionError):
            self.assertEqual(loss.main(["--cohort","unused","--compose-executable","unused","--compose-sha256","a"*64,"--docker-config","unused","--qualification","unused","--qualification-sha256","b"*64]),2)

    def test_readback_excludes_optional_json_but_refuses_natural_leaf_exit(self):
        source=(Path(loss.__file__).parent/"nm2_worker_boundary_read.py").read_text()
        tree=ast.parse(source)
        self.assertIn("assert boundary or path.name == mode+'.wrapper.parent-kill-returned.json'",source)
        self.assertIn("data == b'1'",source)
        self.assertIn("before.st_size == 1",source)
        self.assertFalse(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr in {"kill","system","Popen"} for n in ast.walk(tree)))

    def test_host_guard_uses_only_fixed_branch_for_its_closed_scenario(self):
        import stat
        import tempfile
        import nm2_worker_hosted as hosted
        from test_nm2_worker_hosted import environment
        original = Path.stat
        def measured(path,*args,**kwargs):
            if path.as_posix() == "/var/run/docker.sock":
                return SimpleNamespace(st_mode=stat.S_IFSOCK,st_uid=0)
            return original(path,*args,**kwargs)
        with tempfile.TemporaryDirectory() as temporary:
            for scenario,branch,accepted in (
                (hosted.RUNNER_LOSS_SCENARIO,hosted.RUNNER_LOSS_BRANCH,True),
                (hosted.RUNNER_LOSS_SCENARIO,hosted.BRANCH,False),
                (hosted.BOUNDARY_SCENARIO,hosted.BRANCH,True),
                (hosted.BOUNDARY_SCENARIO,hosted.RUNNER_LOSS_BRANCH,False),
            ):
                with self.subTest(scenario=scenario,branch=branch), \
                     patch.object(hosted.platform,"freedesktop_os_release",return_value={"ID":"ubuntu","VERSION_ID":"24.04"}), \
                     patch.object(hosted.platform,"system",return_value="Linux"), \
                     patch.object(hosted.platform,"machine",return_value="x86_64"), \
                     patch.object(Path,"stat",measured),patch.object(hosted.subprocess,"run") as run:
                    env={**environment(temporary),"NM2_SCENARIO":scenario,"GITHUB_REF":branch}
                    if accepted: self.assertEqual(hosted.host_guard(env),Path(temporary))
                    else:
                        with self.assertRaises(hosted.HostedRefused): hosted.host_guard(env)
                    run.assert_not_called()

    def test_managed_readback_uses_original_journal_directory_not_run_id(self):
        import re
        import tempfile
        source=(Path(loss.__file__).parent/"nm2_worker_boundary_read.py").read_text()
        functions=[n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=="managed_run_folder"]
        self.assertEqual(len(functions),1)
        scope={"re":re}
        exec(compile(ast.Module(body=functions,type_ignores=[]),str(Path(loss.__file__).parent/"nm2_worker_boundary_read.py"),"exec"),scope)
        validate=scope["managed_run_folder"]
        with tempfile.TemporaryDirectory() as temporary:
            runs=Path(temporary)/"runs";runs.mkdir()
            # Actual SDK uses a fresh managed-* UUID independent of the run's UUID.
            run_id="a"*32;folder=runs/("managed-"+"b"*32);folder.mkdir()
            self.assertNotEqual(folder.name,run_id)
            self.assertEqual(validate(folder,runs),folder)
            for name in (run_id,"managed-short","managed-"+"D"*32):
                invalid=runs/name;invalid.mkdir()
                with self.subTest(name=name),self.assertRaises(AssertionError):validate(invalid,runs)
            outside=Path(temporary)/("managed-"+"c"*32);outside.mkdir()
            with self.assertRaises(AssertionError):validate(outside,runs)
            original=Path.is_symlink
            # Inert link metadata models refusal without privileged Windows link creation.
            with patch.object(Path,"is_symlink",lambda p:True if p==folder else original(p)):
                with self.assertRaises(AssertionError):validate(folder,runs)

    def test_trusted_linux_bytes_cannot_be_chosen_by_raw_receipt(self):
        raw,selection,inventories,expected=vector()
        with self.assertRaises(AcceptanceRefused): loss.runner_loss_projection(raw,selection,inventories)
        with self.assertRaises(AcceptanceRefused): loss.runner_loss_projection(raw,selection,inventories,expected_fixture=(expected[0]+b" ",expected[1]))
        self.assertEqual(boundary.MODES,("nm2-c07-orphan-drain","nm2-c09-loaded-authority"))


if __name__ == "__main__":
    unittest.main()
