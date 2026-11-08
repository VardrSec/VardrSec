"""Explicit selected C09 fixture; default inert, no automatic host power action."""
import argparse
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys
import time

from nm2_worker_acceptance import EXECUTION, canonical, digest, manifest, require
from nm2_worker_launch_acceptance import LaunchFixture
from nm2_worker_boundary_pair import (BOUNDARY_SOURCES, MODES, fixed_case,
    fixture_binding, fixed_records, guard_joins, read_original, stamp)
from worker_host import _json

SCENARIO = "persistent-fixed-clock-suspend"
HOSTED = "vardr.nm2-hosted/28"
MODE = MODES[1]
NS = 1_000_000_000
FILETIME_EPOCH = 116444736000000000
HELPER_SHA = "f784cdc68899542161f0ea85573a494d9e8521e123ba2b458185f13fc1ab2968"
WINDOWS_BINARY_SHA = "5c29732082fda2dbb21b615b8707840e4a6d7049e82647938aac4743c35c5842"
WINDOWS_RECEIPT_SHA = "b36a956d7322e06c4a90587db1d9196e8d4762ad2f88a6a1d6fcbf4bd84ee27e"
GUEST_SOURCE = '''import json,time,uuid
from pathlib import Path
b=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
assert str(uuid.UUID(b))==b
s=dict(schema='vardr.nm2-guest-clock/1',boot_id=b,utc_before_ns=time.time_ns(),boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME),monotonic_ns=time.clock_gettime_ns(time.CLOCK_MONOTONIC),utc_after_ns=time.time_ns())
print(json.dumps(s,separators=(',',':')))
'''


def bounded_file(path, bound=16384):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= bound,
            "clock_suspend_input_refused")
    data = path.read_bytes(); after = path.lstat()
    require(len(data) == before.st_size and all(getattr(before,k) == getattr(after,k)
            for k in ("st_dev","st_ino","st_mode","st_size","st_mtime_ns")), "clock_suspend_input_changed")
    return data


def wake_input_root(selection):
    return Path(selection["private_root"]).parent/"c09-wake"


def wake_binding(qualification, selected, *, desktop):
    q,s = _json(qualification),_json(selected)
    require(set(s) == {"schema","platform","seconds","boot_identity","primitive_sha256","rtc_device"}
        and s["schema"] == "vardr.nm2-c09-wake-selection/1" and s["platform"] == ("win32" if desktop else "linux")
        and type(s["seconds"]) is int and s["seconds"] == 20 and type(s["boot_identity"]) is str
        and 0 < len(s["boot_identity"]) <= 80 and type(s["primitive_sha256"]) is str and re.fullmatch("[a-f0-9]{64}",s["primitive_sha256"])
        and s["rtc_device"] == (None if desktop else "/dev/rtc0"), "clock_suspend_input_refused")
    if desktop:
        require(digest(qualification) == WINDOWS_RECEIPT_SHA and q["status"] == "passed_compile_only"
            and q["output_binary_sha256"] == s["primitive_sha256"] == WINDOWS_BINARY_SHA
            and q["source_unchanged"] is q["compiler_unchanged"] is True
            and canonical([q["compiler_exit_code"],q["helper_executions"],q["power_operations"]]) == b"[0,0,0]",
            "clock_suspend_qualification_refused")
    else:
        require(set(q) == {"schema","platform","helper_sha256","primitive_path","primitive_sha256","boot_identity_sha256"}
            and q["schema"] == "vardr.nm2-c09-host-qualification/1" and q["platform"] == "linux"
            and q["helper_sha256"] == HELPER_SHA and q["primitive_path"] == "/usr/sbin/rtcwake"
            and q["primitive_sha256"] == s["primitive_sha256"]
            and q["boot_identity_sha256"] == digest(s["boot_identity"].encode("ascii")), "clock_suspend_qualification_refused")
    return dict(selection_sha256=digest(selected),qualification_sha256=digest(qualification),
                boot_identity_sha256=digest(s["boot_identity"].encode("ascii")),primitive_sha256=s["primitive_sha256"])


def guest_sample(value):
    from worker_host import _uuid
    require(type(value) is dict and set(value) == {"schema","boot_id","utc_before_ns","boottime_ns","monotonic_ns","utc_after_ns"}
        and value["schema"] == "vardr.nm2-guest-clock/1" and _uuid(value["boot_id"]) == value["boot_id"]
        and all(type(value[k]) is int and 0 < value[k] < 2**63 for k in ("utc_before_ns","boottime_ns","monotonic_ns","utc_after_ns"))
        and 0 <= value["utc_after_ns"]-value["utc_before_ns"] <= 50_000_000, "clock_suspend_guest_refused")
    return value


def _host_sample(value, windows):
    keys = {"utc_before","utc_after","biased","unbiased"} if windows else {"utc_before","utc_after","boot","mono"}
    require(type(value) is dict and set(value) == keys and all(type(v) is int and 0 < v < 2**63 for v in value.values()),
            "clock_suspend_host_refused")
    start,end = value["utc_before"],value["utc_after"]
    biased,unbiased = (value["biased"],value["unbiased"]) if windows else (value["boot"],value["mono"])
    if windows:
        require(start > FILETIME_EPOCH and end > FILETIME_EPOCH,"clock_suspend_host_refused")
        start,end,biased,unbiased = (start-FILETIME_EPOCH)*100,(end-FILETIME_EPOCH)*100,biased*100,unbiased*100
    require(0 <= end-start <= 50_000_000,"clock_suspend_host_refused")
    return start,end,biased,unbiased


def original_cap(original,review):
    begin=next(r for r in original["records"] if (r["role"],r["event"])==("wrapper","begin"))
    require(stamp(original["started_at"]) <= stamp(original["claim"]["utc_anchor"]) <= begin["utc_ns"],"clock_suspend_authority_order_refused")
    duration=min(review["input"]["plan"]["execution"]["timeout_seconds"],30,review["context"]["max_duration_seconds"])
    return min(stamp(original["claim"]["utc_anchor"])+duration*NS,
        *(stamp(review["context"][k]) for k in ("expires_at","testing_end")),
        *(stamp(g["expires_at"]) for g in review["context"]["credential_grants"]))


def rtc_readback(value):
    allowed = dict(device={"unchanged","changed","unavailable"},
        alarm={"disabled","still_set","unavailable"},mem_sleep={"unchanged","changed","unavailable"})
    if type(value) is dict and set(value)==set(allowed) and all(type(value[k]) is str and value[k] in allowed[k] for k in allowed):
        return dict(value)
    return None


def helper_failure_detail(reply):
    code=reply.returncode
    value=dict(returncode=code if type(code) is int and -(2**31)<=code<2**32 else None,helper_status=None,rtc_readback=None)
    try:
        require(type(reply.stdout) is bytes and 0<len(reply.stdout)<=16384,"clock_suspend_helper_held")
        data=_json(reply.stdout)
        require(type(data) is dict,"clock_suspend_helper_held")
        if data.get("status")=="returned_unqualified": value["helper_status"]="returned_unqualified"
        if (set(data) in ({"status","reason"},{"status","reason","rtc_readback"})
                and data["status"]=="held" and data["reason"]=="wake_operation_unconfirmed"):
            value["helper_status"]="held"
            value["rtc_readback"]=rtc_readback(data.get("rtc_readback"))
    except (ValueError,KeyError,TypeError):
        pass
    return value


def clock_joins(clocks, original, review, physical, traffic, *, desktop):
    require(type(clocks) is dict and set(clocks) == {"guest_before","guest_after","host"}, "clock_suspend_clock_refused")
    guests = []
    for name in ("guest_before","guest_after"):
        outer = clocks[name]
        require(type(outer) is dict and set(outer) == {"operator_before_ns","sample","operator_after_ns"}
            and all(type(outer[k]) is int and 0 < outer[k] < 2**63 for k in ("operator_before_ns","operator_after_ns")), "clock_suspend_bridge_refused")
        g = guest_sample(outer["sample"])
        require(outer["operator_before_ns"] <= g["utc_before_ns"] <= g["utc_after_ns"] <= outer["operator_after_ns"], "clock_suspend_bridge_refused")
        guests.append(g)
    first,last = guests
    require(first["boot_id"] == last["boot_id"], "clock_suspend_guest_boot_changed")
    boot,mono = last["boottime_ns"]-first["boottime_ns"],last["monotonic_ns"]-first["monotonic_ns"]
    require(0 <= mono <= boot and 15*NS <= boot-mono <= 30*NS
        and abs((last["utc_before_ns"]-first["utc_before_ns"])-boot) <= NS, "clock_suspend_guest_sleep_refused")
    host = clocks["host"]
    windows = desktop
    require(type(host) is dict and host.get("status") == "returned_unqualified"
        and host.get("platform") == ("win32" if windows else "linux"), "clock_suspend_host_refused")
    if windows:
        require(set(host) == {"platform","status","native","boot_identity_sha256"}, "clock_suspend_host_refused")
        native = host["native"]
        require(type(native) is dict and set(native) == {"schema","stage","return_error","returned","timer_signaled","cleanup_failed","due_filetime","before","after"}
            and native["schema"] == "vardr.nm2-c09-windows-observation/1" and native["stage"] == "returned_unqualified"
            and native["returned"] is native["timer_signaled"] is True and native["cleanup_failed"] is False
            and type(native["return_error"]) is int and native["return_error"] == 0
            and type(native["due_filetime"]) is int and native["due_filetime"] > FILETIME_EPOCH, "clock_suspend_host_refused")
        h0,h1 = _host_sample(native["before"],True),_host_sample(native["after"],True)
        require(h1[0] >= (native["due_filetime"]-FILETIME_EPOCH)*100,"clock_suspend_host_refused")
    else:
        require(set(host) == {"platform","status","before","after","boot_identity_sha256"},"clock_suspend_host_refused")
        h0,h1 = _host_sample(host["before"],False),_host_sample(host["after"],False)
    host_boot,host_mono = h1[2]-h0[2],h1[3]-h0[3]
    require(0 <= host_mono <= host_boot and 15*NS <= host_boot-host_mono <= 30*NS
        and abs((h1[0]-h0[0])-host_boot) <= NS,"clock_suspend_host_sleep_refused")
    records = {(r["role"],r["event"]):r for r in original["records"]}
    begin,returned = records["wrapper","begin"],records["wrapper","gate-return"]
    cap=original_cap(original,review)
    finished = stamp(physical["finished_at"])
    require(returned["utc_ns"] <= first["utc_before_ns"] <= first["utc_after_ns"] <= h0[0] <= h0[1] < cap < h1[0]
        and h1[1] <= last["utc_before_ns"] and first["boottime_ns"] >= returned["boottime_ns"]
        and cap < finished <= h1[1]+2*NS and finished < begin["utc_ns"]+35*NS
        and len(traffic) == 5 and all(type(r["received_utc_ns"]) is int and begin["utc_ns"] <= r["received_utc_ns"] <= returned["utc_ns"] < h0[0] for r in traffic), "clock_suspend_order_or_exit_refused")
    return dict(guest_sleep_ns=boot-mono,host_sleep_ns=host_boot-host_mono,
                exit_observation_bound_seconds=2,guest_boot_same=True)


class ClockSuspendFixture(LaunchFixture):
    runner_loss = True  # Existing first-issued-failure transport, no signal actuator.

    def __init__(self, selection, *, qualification, qualification_sha256, wake_selection_sha256,
                 wake_qualification_sha256, expected_fixture=None, **kwargs):
        require(set(kwargs) == {"compose","compose_sha256","docker_config"},"clock_suspend_mode_refused")
        super().__init__(selection,completed=True,**kwargs)
        require(all(selection["sources"][n]["commit"] == v for n,v in BOUNDARY_SOURCES.items()),"clock_suspend_source_refused")
        require(type(qualification) is bytes and digest(qualification) == qualification_sha256,"clock_suspend_image_refused")
        self.fixture_binding = fixture_binding(qualification,selection,desktop=sys.platform=="win32",expected_fixture=expected_fixture)
        self.wake_root = wake_input_root(self.m)
        require(self.wake_root.is_dir() and self.wake_root.resolve() == self.wake_root,"clock_suspend_input_refused")
        self.wake_documents = (bounded_file(self.wake_root/"qualification.json"),bounded_file(self.wake_root/"selection.json"))
        require(tuple(map(digest,self.wake_documents)) == (wake_qualification_sha256,wake_selection_sha256),"clock_suspend_input_refused")
        self.wake_binding = wake_binding(*self.wake_documents,desktop=sys.platform=="win32")
        require(digest(bounded_file(self.wake_root/"wake_once.py",65536)) == HELPER_SHA,"clock_suspend_helper_refused")
        if sys.platform=="win32":
            require(digest(bounded_file(self.wake_root/"windows_s3_once.exe",200000)) == WINDOWS_BINARY_SHA,"clock_suspend_helper_refused")
        self.receipt.update(scenario=SCENARIO,acceptance_scope="single_clock_sleep_then_original_retirement_only",
            fixture_image=json.loads(qualification),fixture_qualification_sha256=qualification_sha256,
            fixture_qualification_document=qualification.decode("utf-8"))

    def target_environment(self):
        return {"NM2_FIXTURE_UTC_TIMING":"1"}

    def new_job(self,name,**kwargs):
        return super().new_job("c09-loaded-authority" if name=="launch-completed" else name,**kwargs)

    def approve(self,name,engagement,authorization,job,case,**kwargs):
        require(case["spec"]["id"] == MODE and kwargs.pop("review_context",None) is None,"clock_suspend_case_refused")
        review,context,authority = {},{},{}
        result=super().approve(name,engagement,authorization,job,case,review_snapshot=review,review_context=context,review_authority=authority,**kwargs)
        self.clock_review=dict(input=review,context=context,authority=authority)
        return result

    def guest_clock(self):
        before=time.time_ns()
        raw=self.docker("run","--rm","--pull","never","--user","10001:10001","--read-only","--network","none",
            "--cap-drop","ALL","--security-opt","no-new-privileges:true","--label","com.docker.compose.project="+self.project,
            "--pids-limit","64","--memory","512m","--cpus","1","--env","PYTHONDONTWRITEBYTECODE=1",
            "--entrypoint","/usr/local/bin/python",self.images["worker"],"-I","-S","-B","-c",GUEST_SOURCE,timeout=45)
        after=time.time_ns(); require(type(raw) is bytes and len(raw)<=4096,"clock_suspend_guest_refused")
        return dict(operator_before_ns=before,sample=guest_sample(_json(raw)),operator_after_ns=after)

    def suspend_once(self):
        require(tuple(digest(bounded_file(self.wake_root/name)) for name in ("qualification.json","selection.json"))
            == tuple(map(digest,self.wake_documents)) and digest(bounded_file(self.wake_root/"wake_once.py",65536))==HELPER_SHA,"clock_suspend_input_changed")
        args=[sys.executable,"-I","-S","-B",str(self.wake_root/"wake_once.py"),"--execute","--selection",str(self.wake_root/"selection.json"),
              "--reviewed-selection-sha256",self.wake_binding["selection_sha256"]]
        if sys.platform=="linux": args=["/usr/bin/sudo","--non-interactive",*args]
        require(sys.platform in {"linux","win32"},"clock_suspend_platform_refused")
        env={k:v for k,v in os.environ.items() if k in {"SystemRoot","WINDIR","PATH","COMSPEC"}}
        env.update(HOME=str(self.wake_root),USERPROFILE=str(self.wake_root),APPDATA=str(self.wake_root),LOCALAPPDATA=str(self.wake_root),
                   TEMP=str(self.wake_root),TMP=str(self.wake_root),LC_ALL="C")
        try:
            reply=subprocess.run(args,cwd=self.wake_root,env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=150,check=False)
        except (OSError,subprocess.SubprocessError):
            self.receipt["clock_suspend_failure"]=dict(returncode=None,helper_status=None,rtc_readback=None)
            require(False,"clock_suspend_helper_held")
        self.receipt["clock_suspend_failure"]=helper_failure_detail(reply)
        require(type(reply.returncode) is int and reply.returncode==0 and reply.stderr==b""
            and type(reply.stdout) is bytes and 0<len(reply.stdout)<=16384,"clock_suspend_helper_held")
        value=_json(reply.stdout)
        require(value.get("status")=="returned_unqualified" and value.get("boot_identity_sha256")==self.wake_binding["boot_identity_sha256"],"clock_suspend_helper_held")
        self.receipt.pop("clock_suspend_failure",None)
        return value

    def observe_runner_loss(self,observer,identity,admission,case,binding):
        self.receipt["stage"]="clock_suspend_active"
        until=time.monotonic()+40
        while len(self.traffic())<5:
            require(time.monotonic()<until,"clock_suspend_traffic_unobserved");time.sleep(.1)
        run_id=self.observe_executing_run_id(*case[:2])
        original=read_original(self,run_id,case)
        kinds={(r["role"],r["event"]) for r in original["records"]}
        require(kinds=={("wrapper","begin"),("wrapper","gate-return"),("leaf","ready")} and original["phase"]=="executing","clock_suspend_not_active")
        self.unreported_attempt(admission,case,identity,disabled=False)
        self.receipt["stage"]="clock_suspend_guest_before"
        clocks=dict(guest_before=self.guest_clock())
        self.receipt["clock_suspend_observed"]={"clocks":clocks}
        require(observer.capture_running(container_id=identity.container_id,image_id=identity.image_id,project=identity.project)==identity
            and clocks["guest_before"]["sample"]["utc_after_ns"]<original_cap(original,self.clock_review)
            and time.time_ns()<original_cap(original,self.clock_review),"clock_suspend_not_active")
        self.receipt["stage"]="clock_suspend_host"
        clocks["host"]=self.suspend_once()
        self.receipt["stage"]="clock_suspend_guest_after"
        clocks["guest_after"]=self.guest_clock()
        self.receipt["stage"]="clock_suspend_exit"
        self.docker("container","wait",identity.container_id,timeout=40)
        exited=observer.observe_exit(identity);observer.confirm_exit(exited)
        require(type(exited.exit_code) is int and exited.exit_code==125,"clock_suspend_native_exit_refused")
        self.clock_state=dict(case=case,run_id=run_id,review=self.clock_review,original=original,
            before=self.unreported_attempt(admission,case,identity,disabled=False),held_audit=self.worker_state(admission,expected_held="issued_unknown"),
            admission=admission,clocks=clocks,wake_documents=[v.decode("utf-8") for v in self.wake_documents])
        return exited

    def close_runner_loss(self,physical,admission,retired,case):
        state=self.clock_state;self.receipt["runner_loss"]={}
        audit=self.verify_host_exit_reconciliation(admission,retired,case,state["run_id"],state["before"],proof_key="runner_loss")
        state.update(physical=physical,retirement=retired,audit=audit,reconciliation=self.runner_loss_reconciliation,
            after=self.retired_predecessor_inventory,traffic=self.traffic(),retained=read_original(self,state["run_id"],case))
        self.receipt["runner_loss"]=state

    def launch_pair(self):
        super().launch_pair()
        self.receipt["clock_suspend"]=self.receipt.pop("runner_loss")
        self.receipt.update(status="selected_clock_suspend_passed",stage="selected_clock_suspend_complete")


def clock_suspend_projection(raw,selection,inventories,*,desktop=False,expected_fixture=None,expected_wake=None):
    """Actual clock-sleep only; precise S-state and wake causality are unattributed."""
    from worker_host import _terminal
    from worker_host_persistent import retirement, original_local_audit
    from nm2_worker_hosted import _launch_retention, _launch_row, _requests
    require(raw["schema"]=="vardr.nm2-worker-launch-acceptance/1" and raw["scenario"]==SCENARIO and raw["acceptance_scope"]=="single_clock_sleep_then_original_retirement_only"
        and raw["status"]=="selected_clock_suspend_passed" and raw["stage"]=="selected_clock_suspend_complete"
        and raw["sources"]==selection["sources"] and all(selection["sources"][n]["commit"]==v for n,v in BOUNDARY_SOURCES.items())
        and raw["images"]==selection["images"] and raw["project"]==selection["project"]
        and raw["platform"]==("win32" if desktop else "linux") and raw["retained"] is True
        and raw["nm2_exit_status"]=="incomplete" and raw["expected_database_revision"]=="0041persistentruntime","clock_suspend_scope_refused")
    document=raw["fixture_qualification_document"].encode("utf-8")
    require(digest(document)==raw["fixture_qualification_sha256"] and _json(document)==raw["fixture_image"],"clock_suspend_image_refused")
    fixture=fixture_binding(document,selection,desktop=desktop,expected_fixture=expected_fixture)
    measured=raw["image_sources"]["runner"]
    require(measured["image_id"]==fixture["image_id"] and type(measured["python_file_count"]) is int and measured["python_file_count"]==80
        and measured["executables"]=={"/usr/local/bin/vardr-worker-owner":fixture["owner_sha256"],"/usr/local/bin/vardrgate":fixture["wrapper_sha256"]}
        and (fixture["source_recipe"] is None or measured["python_inventory_sha256"]==fixture["source_recipe"]["sdk_inventory_sha256"]),"clock_suspend_image_refused")
    s=raw["clock_suspend"]
    require(set(s)==set("case run_id review original before held_audit admission clocks wake_documents physical retirement audit reconciliation after traffic retained host_reconciled".split()),"clock_suspend_scope_refused")
    require(type(expected_wake) is tuple and len(expected_wake)==2 and all(type(v) is bytes for v in expected_wake)
        and s["wake_documents"]==[v.decode("utf-8") for v in expected_wake],"clock_suspend_qualification_refused")
    wake=wake_binding(*expected_wake,desktop=desktop)
    require(s["clocks"]["host"]["boot_identity_sha256"]==wake["boot_identity_sha256"],"clock_suspend_host_boot_changed")
    case,local,before,after,physical=s["case"],s["original"],s["before"],s["after"],s["physical"]
    launch=raw["launch"];_launch_row(launch,1)
    require(type(physical["exit_code"]) is int and physical["exit_code"]==125 and physical["operator_stop_state"]=="not_requested"
        and launch["container_id"]==physical["identity"]["container_id"] and launch["runtime_id"]==physical["runtime_id"]
        and launch["finished_at"]==physical["finished_at"],"clock_suspend_physical_refused")
    require(canonical(case[2]["spec"])==canonical(fixed_case(MODE)) and re.fullmatch("[a-f0-9]{32}",s["run_id"])
        and all(local[k]==v for k,v in (("run_id",s["run_id"]),("engagement_id",case[0]),("job_id",case[1]))),"clock_suspend_original_refused")
    rows=fixed_records(local["records"],MODE,physical)
    require(_requests(s["traffic"])==MODE[4:] and len(s["traffic"])==5
        and all(rows["leaf","ready"]["utc_ns"]<=r["received_utc_ns"]<=rows["wrapper","gate-return"]["utc_ns"] for r in s["traffic"]),"clock_suspend_traffic_refused")
    review,claim=s["review"],local["claim"];plan=review["input"]["plan"]
    require(canonical(plan["execution"])==canonical(EXECUTION) and plan["case_hash"]==digest(canonical(case[2]["spec"]))
        and review["context"]["job_id"]==case[1] and review["context"]["engagement_id"]==case[0]
        and review["context"]["plan_sha256"]==claim["plan_sha256"]==digest(canonical(plan))
        and type(review["context"]["max_duration_seconds"]) is int and review["context"]["max_duration_seconds"]==30
        and claim["case_sha256"]==plan["case_hash"] and claim["tool_sha256"]==fixture["wrapper_sha256"],"clock_suspend_authority_refused")
    delegation=guard_joins(local,MODE,plan,claim["plan_sha256"],fixture)
    require(len(before["contracts"])==len(before["runtimes"])==1 and before["contracts"][0]["consumed"] is True
        and before["job_status"]=="running" and before["results"]==before["stops"]==[]
        and canonical(before["execution"])==b'{"capacity_reserved":true,"duration_seconds":30,"state":"active","target_charge":1}'
        and canonical([before["capacity_reserved_count"],before["targets_spent"],before["duration_allocated"]])==b'[1,1,30]',"clock_suspend_capacity_not_held")
    runtime=before["runtimes"][0];original=s["admission"];attempt=runtime["attempts"][0];contract=before["contracts"][0]
    require(runtime["identity"]==physical["identity"] and runtime["admission"]==original
        and all(physical[k]==original[k]==runtime[k if k!="runtime_id" else "id"] for k in ("runtime_id","runtime_sha256","admission_sha256"))
        and runtime["last_sequence"]==runtime["head_sequence"]==runtime["active_sequence"]=="1"
        and runtime["retired"] is runtime["new_work_disabled"] is False and runtime["report_sha256"] is None and len(runtime["attempts"])==1,"clock_suspend_binding_refused")
    require(attempt["binding"]=={**{k:original[k] for k in ("origin","runner_id")},"job_id":case[1],"contract_id":contract["id"],**{k:contract[k] for k in ("attempt_id","fence","contract_sha256")}}
        and attempt["runtime_id"]==original["runtime_id"] and attempt["runtime_sequence"]=="1" and attempt["job_id"]==case[1] and attempt["confirmed_at"] is not None
        and all(attempt[k] is None for k in ("released_at","terminal_receipt","terminal_receipt_sha256","native_done_sha256","release_receipt")),"clock_suspend_original_refused")
    require(local["phase"]=="executing" and local["artifact_sha256"] is None and local["local_stop_requested"] is False
        and claim["state"] in {"consume_acknowledged","held_after_claim"} and canonical([claim["consumption_sent"],claim["consumption_acknowledged"]])==b'[1,1]'
        and local["attempt"]["state"]=="bound" and local["attempt"]["binding"]=={**attempt["binding"],**{k:original[k] for k in ("runtime_id","runtime_sha256","admission_sha256")},"runtime_sequence":"1"}
        and all(local["attempt"][k] is None for k in ("completion","native_done_sha256","release_intent","release_ack")),"clock_suspend_native_hold_refused")
    audit_binding={k:original[k] for k in ("runner_id","runtime_id","runtime_sha256","admission_sha256")};held=s["held_audit"]
    require(canonical(held)==canonical(dict(schema="vardr.worker-state-audit/1",status="held",reason="local_holds",complete=True,binding=audit_binding,
        parent=dict(state="active",last_sequence="1",head_sequence="1",active_sequence="1"),counts=dict.fromkeys(("attempts","selections","associated_runs","associated_claims"),1),global_holds=held["global_holds"],retirement_receipt_sha256=None))
        and type(held["global_holds"]) is int and held["global_holds"]>0,"clock_suspend_held_audit_refused")
    clock=clock_joins(s["clocks"],local,review,physical,s["traffic"],desktop=desktop)
    record=dict(runtime_id=original["runtime_id"],admission=original,registration={k:v for k,v in original.items() if k not in {"schema","runtime_id","runtime_sha256","admission_sha256"}},
        registration_state="acknowledged",stop_state="observed",receipt=s["retirement"],revocation_state="none",disable_state="none")
    retired=retirement(record,s["retirement"]);terminal=_terminal(attempt["binding"],retired["attempt_receipt"])
    require(retired["last_sequence"]==retired["runtime_sequence"]=="1" and terminal["cause"]=="observed_exit" and terminal["outcome"]=="failed"
        and retired["receipt_sha256"]==launch["retirement_sha256"],"clock_suspend_retirement_refused")
    require(canonical(after)==canonical({**before,"job_status":"failed","capacity_reserved_count":0,"execution":{**before["execution"],"state":"failed","capacity_reserved":False},
        "runtimes":[{**runtime,"retired":True,"new_work_disabled":True,"report_sha256":retired["report_sha256"]}],
        "stops":[{k:terminal[k] for k in ("contract_id","receipt_sha256","outcome","cause")}]}),"clock_suspend_history_changed")
    host=s["host_reconciled"]
    require(host["schema"]=="vardr.worker-cli/1" and host["state"]=="terminal_observed" and host["runtime_id"]==original["runtime_id"] and host["receipt"]["retirement"]==retired,"clock_suspend_host_receipt_refused")
    original_local_audit(record,host["receipt"],output=canonical(s["audit"]),returncode=0)
    require(canonical(s["reconciliation"])==canonical(dict(schema="vardr.worker-reconciliation/1",status="reconciled",reason=None,complete=True,binding=audit_binding,
        selected_run_id=s["run_id"],selected_sequence="1",reconciliation_state="terminal_host_exit_observed",remaining_local_holds=0,retirement_receipt_sha256=retired["receipt_sha256"]))
        and canonical(s["audit"]["counts"])==canonical(dict.fromkeys(("attempts","selections","associated_runs","associated_claims"),1))
        and type(s["audit"]["global_holds"]) is int and s["audit"]["global_holds"]==0,"clock_suspend_reconciliation_refused")
    retained=s["retained"]
    require(all(retained[k]==local[k] for k in ("run_id","engagement_id","job_id","records","guards","files"))
        and len(local["files"])==1 and local["files"][0]["name"]=="vardrgate_result.json" and type(local["files"][0]["size"]) is int
        and 0<local["files"][0]["size"]<=1024*1024 and re.fullmatch("[a-f0-9]{64}",local["files"][0]["sha256"])
        and retained["artifact_sha256"] is None and retained["attempt"]["state"]=="physical_retirement_observed" and retained["attempt"]["retired_from_state"]=="bound"
        and retained["attempt"]["binding"]==local["attempt"]["binding"] and all(retained["attempt"][k] is None for k in ("completion","native_done_sha256","release_intent","release_ack")),"clock_suspend_promotion_or_retention_refused")
    owned,admitted=_launch_retention(raw,selection,(launch,),inventories,desktop=desktop)
    return dict(schema=HOSTED,scope="single_clock_sleep_then_original_retirement_only",**clock,
        fixture_qualification_sha256=digest(document),wake_qualification_sha256=wake["qualification_sha256"],wake_selection_sha256=wake["selection_sha256"],
        genuine_get_count=5,native_exit_code=125,capacity_before=1,capacity_after=0,targets_spent=1,duration_allocated=30,remaining_local_holds=0,
        guard_delegation=delegation,done_or_artifact_promoted=False,owned_stopped_container_count=owned,empty_builtin_bridge_id_change_count=admitted,
        resources_retained=True,nm2_exit_status="incomplete",precise_s_state="unattributed",wake_causality="unattributed",kernel_resume_latency="not_measured")


def prepare_windows_wake(selection,qualification_path,binary_path):
    """Trusted Desktop preflight: exact bytes and read-only CIM, no power call."""
    require(sys.platform=="win32","clock_suspend_platform_refused")
    root=wake_input_root(selection)
    require(root.is_absolute() and not root.exists() and root.parent.resolve(strict=True)==root.parent,
        "clock_suspend_input_refused")
    q=bounded_file(qualification_path,65536);binary=bounded_file(binary_path,200000)
    require(digest(q)==WINDOWS_RECEIPT_SHA and digest(binary)==WINDOWS_BINARY_SHA,"clock_suspend_qualification_refused")
    helper_path=Path(__file__).parent/"fixtures/nm2-clock-suspend/wake_once.py"
    helper=bounded_file(helper_path,65536)
    require(digest(helper)==HELPER_SHA,"clock_suspend_helper_refused")
    # Reuse only the pinned source helper's existing read-only boot/CIM function.
    source=runpy.run_path(str(helper_path),run_name="nm2_c09_readonly_boot_preflight")
    boot=source["boot_identity"]()
    require(bounded_file(helper_path,65536)==helper,"clock_suspend_input_changed")
    s=canonical(dict(schema="vardr.nm2-c09-wake-selection/1",platform="win32",seconds=20,
        boot_identity=boot,primitive_sha256=WINDOWS_BINARY_SHA,rtc_device=None))
    wake_binding(q,s,desktop=True)
    root.mkdir(mode=0o700)
    for name,data in (("wake_once.py",helper),("windows_s3_once.exe",binary),("qualification.json",q),("selection.json",s)):
        with (root/name).open("xb") as stream:stream.write(data)
        (root/name).chmod(0o600)
    return q,s


def prepare_linux_wake(selection):
    """Trusted hosted preflight: bind existing system bytes, no sudo or power call."""
    root=wake_input_root(selection)
    require(sys.platform=="linux" and not root.exists(),"clock_suspend_input_refused")
    root.mkdir(mode=0o700,parents=True)
    helper=(Path(__file__).parent/"fixtures/nm2-clock-suspend/wake_once.py").read_bytes()
    require(digest(helper)==HELPER_SHA,"clock_suspend_helper_refused")
    primitive=Path("/usr/sbin/rtcwake");require(primitive.is_file() and not primitive.is_symlink(),"clock_suspend_input_refused")
    boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    from worker_host import _uuid
    _uuid(boot)
    q=dict(schema="vardr.nm2-c09-host-qualification/1",platform="linux",helper_sha256=HELPER_SHA,
           primitive_path=str(primitive),primitive_sha256=digest(primitive.read_bytes()),boot_identity_sha256=digest(boot.encode("ascii")))
    s=dict(schema="vardr.nm2-c09-wake-selection/1",platform="linux",seconds=20,boot_identity=boot,primitive_sha256=q["primitive_sha256"],rtc_device="/dev/rtc0")
    documents=canonical(q),canonical(s)
    for name,data in (("wake_once.py",helper),("qualification.json",documents[0]),("selection.json",documents[1])):
        with (root/name).open("xb") as stream: stream.write(data)
        (root/name).chmod(0o600)
    wake_binding(*documents,desktop=False)
    return documents


def failure_projection(raw,selection):
    require(type(raw) is dict and raw.get("schema")=="vardr.nm2-worker-launch-acceptance/1"
        and raw.get("expected_database_revision")=="0041persistentruntime" and raw.get("scenario")==SCENARIO and raw.get("status")=="held"
        and raw.get("sources")==selection["sources"] and raw.get("images")==selection["images"]
        and raw.get("project")==selection["project"] and raw.get("platform")=="linux","clock_suspend_scope_refused")
    stages={"clock_suspend_active","clock_suspend_guest_before","clock_suspend_host","clock_suspend_guest_after","clock_suspend_exit",
            "launch_host_exit_verification","launch_reconcile_original","launch_audit_retired"}
    reasons={"clock_suspend_not_active","clock_suspend_helper_held","clock_suspend_helper_refused","clock_suspend_native_exit_refused",
        "clock_suspend_input_changed","clock_suspend_input_refused","clock_suspend_traffic_unobserved","clock_suspend_guest_refused",
        "clock_suspend_bridge_refused","clock_suspend_guest_boot_changed","clock_suspend_guest_sleep_refused","clock_suspend_host_refused",
        "clock_suspend_host_sleep_refused","clock_suspend_order_or_exit_refused","clock_suspend_authority_order_refused","fixture_stage_failed","fixture_command_failed"}
    result=dict(stage=raw.get("stage") if type(raw.get("stage")) is str and raw["stage"] in stages else "unclassified",
                reason=raw.get("reason") if type(raw.get("reason")) is str and raw["reason"] in reasons else "unclassified_refusal")
    detail=raw.get("clock_suspend_failure")
    if (result["reason"]=="clock_suspend_helper_held" and type(detail) is dict and set(detail)=={"returncode","helper_status","rtc_readback"}
            and (detail["returncode"] is None or type(detail["returncode"]) is int and -(2**31)<=detail["returncode"]<2**32)
            and (detail["helper_status"] is None or type(detail["helper_status"]) is str and detail["helper_status"] in {"held","returned_unqualified"})):
        if detail["rtc_readback"] is None or rtc_readback(detail["rtc_readback"]) is not None:
            result["helper_failure"]=dict(detail)
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ("cohort","compose-executable","docker-config","qualification"): parser.add_argument("--"+key,required=True,type=Path)
    for key in ("compose-sha256","qualification-sha256","wake-selection-sha256","wake-qualification-sha256"): parser.add_argument("--"+key,required=True)
    parser.add_argument("--execute",action="store_true");args=parser.parse_args(argv)
    if not args.execute: print("Clock-sleep fixture requires explicit --execute; no commands run");return 2
    try:
        selection=manifest(args.cohort);document=bounded_file(args.qualification,65536);expected=None
        if sys.platform=="linux":
            from nm2_worker_boundary_build import binding_for_qualification
            q=_json(document);expected=document,binding_for_qualification(q,{n:v["commit"] for n,v in selection["sources"].items()},q["source_recipe"]["source_trees"])
        fixture=ClockSuspendFixture(selection,qualification=document,qualification_sha256=args.qualification_sha256,expected_fixture=expected,
            wake_selection_sha256=args.wake_selection_sha256,wake_qualification_sha256=args.wake_qualification_sha256,
            compose=args.compose_executable,compose_sha256=args.compose_sha256,docker_config=args.docker_config)
        fixture.run();return 0 if fixture.receipt["status"]=="selected_clock_suspend_passed" else 1
    except Exception:
        print("Clock-sleep fixture held; retain owned resources.",file=sys.stderr);return 1


if __name__=="__main__": raise SystemExit(main())
