"""Inactive, separately approved single Runner-loss fixture; no default effects."""
import argparse
import json
from pathlib import Path
import re
import sys
import time
from nm2_worker_acceptance import EXECUTION, canonical, digest, manifest, require
from nm2_worker_launch_acceptance import LaunchFixture
from nm2_worker_boundary_pair import (BOUNDARY_SOURCES, RUNNER_LOSS_MODE, NS, stamp, fixed_case,
    fixture_binding, fixed_records, guard_joins, read_original)

SCENARIO = "persistent-fixed-runner-loss"
HOSTED = "vardr.nm2-hosted/27"
MARKER = dict(size=1,sha256="6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",post_signal_call_returned=True)


class RunnerLossFixture(LaunchFixture):
    runner_loss = True

    def __init__(self, selection, *, qualification, qualification_sha256, expected_fixture=None, **kwargs):
        require(set(kwargs) == {"compose","compose_sha256","docker_config"}, "runner_loss_mode_refused")
        super().__init__(selection, completed=True, **kwargs)
        require(all(selection["sources"][n]["commit"] == v for n,v in BOUNDARY_SOURCES.items()), "runner_loss_source_refused")
        require(type(qualification) is bytes and digest(qualification) == qualification_sha256, "runner_loss_image_refused")
        self.fixture_binding = fixture_binding(qualification,selection,desktop=sys.platform == "win32",
            expected_fixture=expected_fixture,operand="runner-loss")
        self.receipt.update(scenario=SCENARIO,acceptance_scope="single_live_runner_loss_only",
            fixture_image=json.loads(qualification),fixture_qualification_sha256=qualification_sha256,
            fixture_qualification_document=qualification.decode("utf-8"))

    def target_environment(self):
        return {"NM2_FIXTURE_UTC_TIMING":"1"}

    def new_job(self, name, **kwargs):
        return super().new_job("c08-live-runner-loss" if name == "launch-completed" else name, **kwargs)

    def approve(self, name, engagement, authorization, job, case, **kwargs):
        require(case["spec"]["id"] == RUNNER_LOSS_MODE and kwargs.pop("review_context",None) is None,
                "runner_loss_case_refused")
        review,context,authority = {},{},{}
        result = super().approve(name,engagement,authorization,job,case,review_snapshot=review,
            review_context=context,review_authority=authority,**kwargs)
        self.runner_loss_review = dict(input=review,context=context,authority=authority)
        return result

    def observe_runner_loss(self, observer, identity, admission, case, binding):
        until = time.monotonic()+40
        while len(self.traffic()) < 5:
            require(time.monotonic() < until,"runner_loss_traffic_unobserved")
            time.sleep(.1)
        # This bounded wait is not physical proof; the unchanged typed observer is.
        self.docker("container","wait",identity.container_id,timeout=40)
        exited = observer.observe_exit(identity); observer.confirm_exit(exited)
        require(type(exited.exit_code) is int and exited.exit_code == 125,"runner_loss_native_exit_refused")
        runs = json.loads(self.helper("audit","list","--json","--engagement",case[0]))
        selected = [r for r in runs if r["job_id"] == case[1]]
        require(len(selected) == 1 and re.fullmatch("[a-f0-9]{32}",selected[0]["run_id"]),"runner_loss_original_run_refused")
        run_id = selected[0]["run_id"]
        original = read_original(self,run_id,case,mode=RUNNER_LOSS_MODE)
        require(canonical(original["marker"]) == canonical(MARKER),"runner_loss_return_unobserved")
        self.runner_loss_state = dict(case=case,run_id=run_id,review=self.runner_loss_review,
            original=original,before=self.unreported_attempt(admission,case,identity,disabled=False),
            held_audit=self.worker_state(admission,expected_held="issued_unknown"),admission=admission)
        return exited

    def close_runner_loss(self, physical, admission, retired, case):
        state = self.runner_loss_state
        self.receipt["runner_loss"] = {}
        audit = self.verify_host_exit_reconciliation(admission,retired,case,state["run_id"],state["before"],proof_key="runner_loss")
        state.update(physical=physical,retirement=retired,audit=audit,reconciliation=self.runner_loss_reconciliation,
            after=self.retired_predecessor_inventory,traffic=self.traffic(),
            retained=read_original(self,state["run_id"],case,mode=RUNNER_LOSS_MODE))
        self.receipt["runner_loss"] = state


def runner_loss_projection(raw, selection, inventories, *, desktop=False, expected_fixture=None):
    """Require actual post-syscall evidence plus original accounting and retirement."""
    from worker_host import _terminal
    from worker_host_persistent import retirement, original_local_audit
    from nm2_worker_hosted import _launch_retention, _launch_row, _requests
    require(raw["scenario"] == SCENARIO and raw["acceptance_scope"] == "single_live_runner_loss_only"
        and raw["status"] == "selected_runner_loss_passed" and raw["stage"] == "selected_runner_loss_complete"
        and raw["sources"] == selection["sources"] and all(selection["sources"][n]["commit"] == v for n,v in BOUNDARY_SOURCES.items())
        and raw["images"] == selection["images"] and raw["project"] == selection["project"]
        and raw["platform"] == ("win32" if desktop else "linux") and raw["retained"] is True
        and raw["nm2_exit_status"] == "incomplete" and raw["expected_database_revision"] == "0041persistentruntime",
        "runner_loss_scope_refused")
    document = raw["fixture_qualification_document"].encode("utf-8")
    require(digest(document) == raw["fixture_qualification_sha256"] and json.loads(document) == raw["fixture_image"],"runner_loss_image_refused")
    fixture = fixture_binding(document,selection,desktop=desktop,expected_fixture=expected_fixture,operand="runner-loss")
    measured = raw["image_sources"]["runner"]
    require(measured["image_id"] == fixture["image_id"] and type(measured["python_file_count"]) is int and measured["python_file_count"] == 80
        and measured["executables"] == {"/usr/local/bin/vardr-worker-owner":fixture["owner_sha256"],"/usr/local/bin/vardrgate":fixture["wrapper_sha256"]}
        and (fixture["source_recipe"] is None or measured["python_inventory_sha256"] == fixture["source_recipe"]["sdk_inventory_sha256"]),"runner_loss_image_refused")
    s = raw["runner_loss"]
    require(set(s) == set("case run_id review original before held_audit admission physical retirement audit reconciliation after traffic retained host_reconciled".split()),"runner_loss_scope_refused")
    case,local,before,after,physical = s["case"],s["original"],s["before"],s["after"],s["physical"]
    launch = raw["launch"]; _launch_row(launch,1)
    require(type(physical["exit_code"]) is int and physical["exit_code"] == 125 and physical["operator_stop_state"] == "not_requested"
        and launch["container_id"] == physical["identity"]["container_id"] and launch["runtime_id"] == physical["runtime_id"]
        and launch["finished_at"] == physical["finished_at"],"runner_loss_physical_refused")
    require(canonical(case[2]["spec"]) == canonical(fixed_case(RUNNER_LOSS_MODE))
        and re.fullmatch("[a-f0-9]{32}",s["run_id"]) and local["run_id"] == s["run_id"]
        and local["engagement_id"] == case[0] and local["job_id"] == case[1],"runner_loss_original_refused")
    rows = fixed_records(local["records"],RUNNER_LOSS_MODE,physical)
    require(canonical(local["marker"]) == canonical(MARKER) and len(s["traffic"]) == 5
        and _requests(s["traffic"]) == RUNNER_LOSS_MODE[4:]
        and all(rows["wrapper","begin"]["utc_ns"] <= r["received_utc_ns"] <= rows["wrapper","gate-return"]["utc_ns"] for r in s["traffic"]),"runner_loss_positive_witness_refused")
    require(stamp(physical["finished_at"]) < min(rows["wrapper","gate-return"]["utc_ns"]+8*NS,
        rows["wrapper","begin"]["utc_ns"]+35*NS),"runner_loss_leaf_lifetime_unobserved")
    review,claim = s["review"],local["claim"]
    plan = review["input"]["plan"]
    require(canonical(plan["execution"]) == canonical(EXECUTION) and plan["case_hash"] == digest(canonical(case[2]["spec"]))
        and review["context"]["job_id"] == case[1] and review["context"]["engagement_id"] == case[0]
        and review["context"]["plan_sha256"] == claim["plan_sha256"] == digest(canonical(plan))
        and review["context"]["max_duration_seconds"] == 30 and claim["case_sha256"] == plan["case_hash"]
        and claim["tool_sha256"] == fixture["wrapper_sha256"],"runner_loss_authority_refused")
    require(stamp(local["started_at"]) <= stamp(claim["utc_anchor"]) <= rows["wrapper","begin"]["utc_ns"],"runner_loss_original_time_refused")
    delegation = guard_joins(local,RUNNER_LOSS_MODE,plan,claim["plan_sha256"],fixture)
    require(len(before["contracts"]) == len(before["runtimes"]) == 1 and before["contracts"][0]["consumed"] is True
        and before["job_status"] == "running" and before["results"] == before["stops"] == []
        and canonical(before["execution"]) == b'{"capacity_reserved":true,"duration_seconds":30,"state":"active","target_charge":1}'
        and canonical([before["capacity_reserved_count"],before["targets_spent"],before["duration_allocated"]]) == b'[1,1,30]',"runner_loss_capacity_not_held")
    runtime = before["runtimes"][0]; original = s["admission"]
    require(runtime["identity"] == physical["identity"] and runtime["admission"] == original
        and all(physical[k] == original[k] == runtime[k if k != "runtime_id" else "id"] for k in ("runtime_id","runtime_sha256","admission_sha256"))
        and runtime["last_sequence"] == runtime["head_sequence"] == runtime["active_sequence"] == "1"
        and runtime["retired"] is runtime["new_work_disabled"] is False and runtime["report_sha256"] is None and len(runtime["attempts"]) == 1,"runner_loss_binding_refused")
    attempt = runtime["attempts"][0]; contract = before["contracts"][0]
    require(attempt["binding"] == {**{k:original[k] for k in ("origin","runner_id")},"job_id":case[1],"contract_id":contract["id"],**{k:contract[k] for k in ("attempt_id","fence","contract_sha256")}}
        and attempt["runtime_id"] == original["runtime_id"] and attempt["runtime_sequence"] == "1" and attempt["job_id"] == case[1] and attempt["confirmed_at"] is not None
        and all(attempt[k] is None for k in ("released_at","terminal_receipt","terminal_receipt_sha256","native_done_sha256","release_receipt")),"runner_loss_original_refused")
    require(local["phase"] == "executing" and local["artifact_sha256"] is None and local["local_stop_requested"] is False
        and claim["state"] in {"consume_acknowledged","held_after_claim"} and canonical([claim["consumption_sent"],claim["consumption_acknowledged"]]) == b'[1,1]'
        and local["attempt"]["state"] == "bound" and local["attempt"]["binding"] == {**attempt["binding"],**{k:original[k] for k in ("runtime_id","runtime_sha256","admission_sha256")},"runtime_sequence":"1"}
        and all(local["attempt"][k] is None for k in ("completion","native_done_sha256","release_intent","release_ack")),"runner_loss_native_hold_refused")
    audit_binding = {k:original[k] for k in ("runner_id","runtime_id","runtime_sha256","admission_sha256")}
    held = s["held_audit"]
    require(held == dict(schema="vardr.worker-state-audit/1",status="held",reason="local_holds",complete=True,binding=audit_binding,
        parent=dict(state="active",last_sequence="1",head_sequence="1",active_sequence="1"),counts=dict.fromkeys(("attempts","selections","associated_runs","associated_claims"),1),global_holds=held["global_holds"],retirement_receipt_sha256=None)
        and type(held["global_holds"]) is int and held["global_holds"] > 0,"runner_loss_held_audit_refused")
    record = dict(runtime_id=original["runtime_id"],admission=original,registration={k:v for k,v in original.items() if k not in {"schema","runtime_id","runtime_sha256","admission_sha256"}},registration_state="acknowledged",stop_state="observed",receipt=s["retirement"],revocation_state="none",disable_state="none")
    retired = retirement(record,s["retirement"]); terminal = _terminal(attempt["binding"],retired["attempt_receipt"])
    require(retired["last_sequence"] == retired["runtime_sequence"] == "1" and terminal["cause"] == "observed_exit" and terminal["outcome"] == "failed"
        and retired["receipt_sha256"] == launch["retirement_sha256"],"runner_loss_retirement_refused")
    require(canonical(after) == canonical({**before,"job_status":"failed","capacity_reserved_count":0,"execution":{**before["execution"],"state":"failed","capacity_reserved":False},
        "runtimes":[{**runtime,"retired":True,"new_work_disabled":True,"report_sha256":retired["report_sha256"]}],"stops":[{k:terminal[k] for k in ("contract_id","receipt_sha256","outcome","cause")}]}),"runner_loss_history_changed")
    host = s["host_reconciled"]
    require(host["schema"] == "vardr.worker-cli/1" and host["state"] == "terminal_observed" and host["runtime_id"] == original["runtime_id"] and host["receipt"]["retirement"] == retired,"runner_loss_host_receipt_refused")
    original_local_audit(record,host["receipt"],output=canonical(s["audit"]),returncode=0)
    reconciliation = s["reconciliation"]
    require(reconciliation == dict(schema="vardr.worker-reconciliation/1",status="reconciled",reason=None,complete=True,binding=audit_binding,
        selected_run_id=s["run_id"],selected_sequence="1",reconciliation_state="terminal_host_exit_observed",remaining_local_holds=0,retirement_receipt_sha256=retired["receipt_sha256"])
        and canonical(s["audit"]["parent"]) == b'{"active_sequence":null,"head_sequence":"1","last_sequence":"1","state":"retired"}'
        and canonical(s["audit"]["counts"]) == canonical(dict.fromkeys(("attempts","selections","associated_runs","associated_claims"),1))
        and type(s["audit"]["global_holds"]) is int and s["audit"]["global_holds"] == 0,"runner_loss_reconciliation_refused")
    retained = s["retained"]
    require(all(retained[k] == local[k] for k in ("run_id","engagement_id","job_id","records","guards","files","marker"))
        and len(local["files"]) == 1 and local["files"][0]["name"] == "vardrgate_result.json"
        and type(local["files"][0]["size"]) is int and 0 < local["files"][0]["size"] <= 1024*1024 and re.fullmatch("[a-f0-9]{64}",local["files"][0]["sha256"])
        and retained["artifact_sha256"] is None and retained["attempt"]["state"] == "physical_retirement_observed" and retained["attempt"]["retired_from_state"] == "bound"
        and retained["attempt"]["binding"] == local["attempt"]["binding"] and all(retained["attempt"][k] is None for k in ("completion","native_done_sha256","release_intent","release_ack")),"runner_loss_promotion_or_retention_refused")
    owned,admitted = _launch_retention(raw,selection,(launch,),inventories,desktop=desktop)
    return dict(schema=HOSTED,scope="single_live_runner_loss_only",fixture_image_binding={**fixture,"qualification_sha256":digest(document)},
        genuine_get_count=5,post_signal_call_returned=True,live_leaf_at_intent=True,native_exit_code=125,guard_delegation=delegation,
        capacity_before=1,capacity_after=0,targets_spent=1,duration_allocated=30,remaining_local_holds=0,
        done_or_artifact_promoted=False,owned_stopped_container_count=owned,empty_builtin_bridge_id_change_count=admitted,
        resources_retained=True,nm2_exit_status="incomplete",kernel_signal_latency="not_measured",termination_ack="not_observed")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("cohort","compose-executable","docker-config","qualification"):
        parser.add_argument("--"+key,required=True,type=Path)
    parser.add_argument("--compose-sha256",required=True); parser.add_argument("--qualification-sha256",required=True)
    parser.add_argument("--execute",action="store_true"); args = parser.parse_args(argv)
    if not args.execute:
        print("Single Runner-loss fixture requires explicit --execute; no commands run"); return 2
    try:
        selection = manifest(args.cohort); data = args.qualification.read_bytes()
        require(0 < len(data) <= 65536 and digest(data) == args.qualification_sha256,"runner_loss_image_refused")
        expected = None
        if sys.platform == "linux":
            from nm2_worker_boundary_build import binding_for_qualification
            q = json.loads(data)
            expected = data,binding_for_qualification(q,{n:v["commit"] for n,v in selection["sources"].items()},q["source_recipe"]["source_trees"],operand="runner-loss")
        fixture = RunnerLossFixture(selection,qualification=data,qualification_sha256=args.qualification_sha256,expected_fixture=expected,
            compose=args.compose_executable,compose_sha256=args.compose_sha256,docker_config=args.docker_config)
        fixture.run(); return 0 if fixture.receipt["status"] == "selected_runner_loss_passed" else 1
    except Exception:
        print("Single Runner-loss fixture held; retain owned resources.",file=sys.stderr); return 1


if __name__ == "__main__":
    raise SystemExit(main())
