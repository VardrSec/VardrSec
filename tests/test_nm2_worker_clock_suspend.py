"""Source-authored inert clock/lifecycle models; no native or container action."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

import nm2_worker_clock_suspend as clock
import nm2_worker_boundary_pair as boundary
from nm2_worker_acceptance import AcceptanceRefused,canonical,digest
from test_nm2_worker_boundary_pair import joined_vector,synthetic_linux_fixture


def vector():
    expected=synthetic_linux_fixture();raw,selection,inventories=joined_vector(expected_fixture=expected)
    old=raw.pop("boundary_pair");s=old["second"];local=s["original"];before=s["before"]
    local["claim"]["utc_anchor"]="2026-01-01T00:00:00Z";local["started_at"]="2026-01-01T00:00:00Z"
    local["attempt"]["binding"]["runtime_sequence"]="1"
    zero=boundary.stamp("2026-01-01T00:00:00Z");template=local["records"][0];local["records"]=[]
    for i,(role,event,pid,ppid) in enumerate((("wrapper","begin",10,7),("leaf","ready",12,10),("wrapper","gate-return",10,7))):
        local["records"].append({**deepcopy(template),"mode":clock.MODE,"role":role,"event":event,"pid":pid,"ppid":ppid,
            "boottime_ns":(i+1)*clock.NS,"utc_ns":zero+(i+1)*clock.NS,
            "counters":dict(allocated_bytes=33554432,steps=1,touches=1) if role=="leaf" else None})
    runtime=before["runtimes"][0];runtime.update(last_sequence="1",head_sequence="1",active_sequence="1",attempts=[runtime["attempts"][1]])
    runtime["attempts"][0]["runtime_sequence"]="1"
    physical=old["physical"];physical["finished_at"]=raw["launch"]["finished_at"]="2026-01-01T00:00:25.500000Z"
    inventories[1]["containers"][raw["launch"]["container_id"]]["state"]["finished_at"]=physical["finished_at"]
    retired=old["retirement"];retired.update(last_sequence="1",runtime_sequence="1")
    retired["receipt_sha256"]=digest(canonical({k:v for k,v in retired.items() if k!="receipt_sha256"}))
    raw["launch"]["retirement_sha256"]=retired["receipt_sha256"]
    terminal=retired["attempt_receipt"]
    after={**deepcopy(before),"job_status":"failed","capacity_reserved_count":0,"execution":{**before["execution"],"state":"failed","capacity_reserved":False},
        "runtimes":[{**deepcopy(runtime),"retired":True,"new_work_disabled":True,"report_sha256":retired["report_sha256"]}],
        "stops":[{k:terminal[k] for k in ("contract_id","receipt_sha256","outcome","cause")}]}
    audit=old["audit"];audit.update(parent=dict(state="retired",last_sequence="1",head_sequence="1",active_sequence=None),
        counts=dict.fromkeys(("attempts","selections","associated_runs","associated_claims"),1),retirement_receipt_sha256=retired["receipt_sha256"])
    reconciliation=old["reconciliation"];reconciliation.update(selected_sequence="1",retirement_receipt_sha256=retired["receipt_sha256"])
    host=old["host_reconciled"];host["receipt"]["retirement"]=retired
    host["receipt"]["cursor"]["last_sequence"]=host["receipt"]["active"]["runtime_sequence"]="1"
    held={**deepcopy(audit),"status":"held","reason":"local_holds","parent":dict(state="active",last_sequence="1",head_sequence="1",active_sequence="1"),"global_holds":1,"retirement_receipt_sha256":None}
    traffic=old["traffic"][5:]
    for i,r in enumerate(traffic): r["received_utc_ns"]=zero+2*clock.NS+(i+1)*100000000
    retained=deepcopy(local);retained["phase"]="failed";retained["attempt"].update(state="physical_retirement_observed",retired_from_state="bound")
    boot="d2e60968-721f-4ddf-a306-cf5fa4e7e969"
    selected=canonical(dict(schema="vardr.nm2-c09-wake-selection/1",platform="linux",seconds=20,boot_identity=boot,primitive_sha256="6"*64,rtc_device="/dev/rtc0"))
    qualification=canonical(dict(schema="vardr.nm2-c09-host-qualification/1",platform="linux",helper_sha256=clock.HELPER_SHA,primitive_path="/usr/sbin/rtcwake",primitive_sha256="6"*64,boot_identity_sha256=digest(boot.encode())))
    def guest(at,boottime,mono):
        return dict(operator_before_ns=zero+at-1000000,operator_after_ns=zero+at+1000000,
            sample=dict(schema="vardr.nm2-guest-clock/1",boot_id=boot,utc_before_ns=zero+at,utc_after_ns=zero+at+1000,boottime_ns=boottime,monotonic_ns=mono))
    clocks=dict(guest_before=guest(4_500_000_000,4_500_000_000,4_500_001_000),guest_after=guest(25_200_000_000,25_200_000_000,5_200_001_000),
        host=dict(platform="linux",status="returned_unqualified",boot_identity_sha256=digest(boot.encode()),
                  before=dict(utc_before=zero+5*clock.NS,utc_after=zero+5*clock.NS+1000,boot=5*clock.NS,mono=5*clock.NS+1000),
                  after=dict(utc_before=zero+25*clock.NS,utc_after=zero+25*clock.NS+1000,boot=25*clock.NS,mono=5*clock.NS+1000)))
    raw.update(scenario=clock.SCENARIO,acceptance_scope="single_clock_sleep_then_original_retirement_only",status="selected_clock_suspend_passed",stage="selected_clock_suspend_complete",after_sha256=digest(canonical(inventories[1])))
    raw["clock_suspend"]=dict(case=s["case"],run_id=s["run_id"],review=s["review"],original=local,before=before,held_audit=held,admission=old["admission"],physical=physical,
        retirement=retired,audit=audit,reconciliation=reconciliation,after=after,traffic=traffic,retained=retained,host_reconciled=host,clocks=clocks,wake_documents=[qualification.decode(),selected.decode()])
    return raw,selection,inventories,expected,(qualification,selected)


def windows_clocks(s):
    value=deepcopy(s["clocks"]);host=value["host"]
    def sample(row):
        return dict(utc_before=clock.FILETIME_EPOCH+row["utc_before"]//100,utc_after=clock.FILETIME_EPOCH+row["utc_after"]//100,
                    biased=row["boot"]//100,unbiased=row["mono"]//100)
    native=dict(schema="vardr.nm2-c09-windows-observation/1",stage="returned_unqualified",return_error=0,returned=True,timer_signaled=True,cleanup_failed=False,
                due_filetime=clock.FILETIME_EPOCH+host["after"]["utc_before"]//100,before=sample(host["before"]),after=sample(host["after"]))
    value["host"]=dict(platform="win32",status="returned_unqualified",native=native,boot_identity_sha256=host["boot_identity_sha256"])
    return value


class ClockSuspendTests(unittest.TestCase):
    def test_source_authored_positive_full_retirement_and_both_clock_forms(self):
        raw,sel,inventories,expected,wake=vector();s=raw["clock_suspend"]
        result=clock.clock_suspend_projection(raw,sel,inventories,expected_fixture=expected,expected_wake=wake)
        self.assertEqual((result["schema"],result["genuine_get_count"],result["guest_sleep_ns"]),(clock.HOSTED,5,20*clock.NS))
        self.assertEqual((result["capacity_before"],result["capacity_after"],result["remaining_local_holds"]),(1,0,0))
        self.assertEqual(result["precise_s_state"],"unattributed");self.assertEqual(result["wake_causality"],"unattributed")
        result=clock.clock_joins(windows_clocks(s),s["original"],s["review"],s["physical"],s["traffic"],desktop=True)
        self.assertEqual((result["guest_sleep_ns"],result["host_sleep_ns"],result["exit_observation_bound_seconds"]),(20*clock.NS,20*clock.NS,2))

    def test_clock_types_bridges_cap_crossing_exit_and_unknown_guest_sleep_refuse(self):
        for windows in (False,True):
            for change in ("bool","bridge_before","bridge_after","boot","guest_sleep","utc_boot","host_sleep","late_exit","early_exit","ceiling","traffic","before_cap","after_cap","anchor_after_begin","extra"):
                raw,_,_,_,_=vector();s=raw["clock_suspend"];c=windows_clocks(s) if windows else deepcopy(s["clocks"])
                if change=="bool":c["guest_before"]["sample"]["boottime_ns"]=True
                elif change=="bridge_before":c["guest_before"]["operator_before_ns"]=c["guest_before"]["sample"]["utc_before_ns"]+1
                elif change=="bridge_after":c["guest_after"]["operator_after_ns"]=c["guest_after"]["sample"]["utc_after_ns"]-1
                elif change=="boot":c["guest_after"]["sample"]["boot_id"]="021df345-3551-4ebf-9d03-aa22bfa39a14"
                elif change=="guest_sleep":c["guest_after"]["sample"]["monotonic_ns"]+=20*clock.NS
                elif change=="utc_boot":c["guest_after"]["sample"]["boottime_ns"]+=2*clock.NS
                elif change=="host_sleep":
                    h=c["host"]["native"] if windows else c["host"]
                    h["after"]["unbiased" if windows else "mono"]+=20*clock.NS//(100 if windows else 1)
                elif change=="late_exit":s["physical"]["finished_at"]="2026-01-01T00:00:27.000002Z"
                elif change=="early_exit":s["physical"]["finished_at"]="2026-01-01T00:00:19Z"
                elif change=="ceiling":s["original"]["records"][0]["utc_ns"]-=20*clock.NS
                elif change=="traffic":s["traffic"][-1]["received_utc_ns"]+=30*clock.NS
                elif change in {"before_cap","after_cap"}:
                    s["original"]["claim"]["utc_anchor"]="2025-12-31T23:59:40Z" if change=="before_cap" else "2026-01-01T00:01:00Z"
                elif change=="anchor_after_begin":s["original"]["claim"]["utc_anchor"]="2026-01-01T00:00:02Z"
                else:c["private-canary"]="private-canary"
                with self.subTest(windows=windows,change=change),self.assertRaises((AcceptanceRefused,ValueError)):
                    clock.clock_joins(c,s["original"],s["review"],s["physical"],s["traffic"],desktop=windows)

    def test_accounting_retention_done_and_untrusted_qualification_refuse(self):
        for change in ("charge","slot","done","release","promote","records","qualification","unknown_qualification"):
            raw,sel,inv,expected,wake=vector();s=raw["clock_suspend"]
            if change=="charge":s["after"]["targets_spent"]=0
            elif change=="slot":s["after"]["capacity_reserved_count"]=1
            elif change=="done":s["original"]["attempt"]["native_done_sha256"]="a"*64
            elif change=="release":s["original"]["attempt"]["release_ack"]={}
            elif change=="promote":s["retained"]["artifact_sha256"]="a"*64
            elif change=="records":s["retained"]["records"].append(deepcopy(s["retained"]["records"][-1]))
            elif change=="qualification":wake=(wake[0]+b" ",wake[1])
            else:wake=None
            with self.subTest(change=change),self.assertRaises((AcceptanceRefused,ValueError)):
                clock.clock_suspend_projection(raw,sel,inv,expected_fixture=expected,expected_wake=wake)

    def test_observe_and_close_reuse_exact_first_failure_no_successor(self):
        raw,_,_,_,_=vector();s=raw["clock_suspend"];f=object.__new__(clock.ClockSuspendFixture)
        f.receipt={};f.clock_review=s["review"];f.wake_documents=tuple(v.encode() for v in s["wake_documents"])
        f.traffic=Mock(return_value=s["traffic"]);f.observe_executing_run_id=Mock(return_value=s["run_id"])
        f.unreported_attempt=Mock(return_value=s["before"]);f.worker_state=Mock(return_value=s["held_audit"])
        f.guest_clock=Mock(side_effect=[s["clocks"]["guest_before"],s["clocks"]["guest_after"]]);f.suspend_once=Mock(return_value=s["clocks"]["host"]);f.docker=Mock()
        identity=SimpleNamespace(container_id="c"*64,image_id="sha256:"+"a"*64,project="fixture");exited=SimpleNamespace(exit_code=125)
        observer=Mock();observer.observe_exit.return_value=exited;observer.capture_running.return_value=identity
        with patch.object(clock,"read_original",return_value=s["original"]),patch.object(clock.time,"time_ns",return_value=boundary.stamp("2026-01-01T00:00:05Z")):
            self.assertIs(f.observe_runner_loss(observer,identity,s["admission"],s["case"],None),exited)
        f.suspend_once.assert_called_once();self.assertEqual(f.guest_clock.call_count,2)
        f.observe_executing_run_id.assert_called_once_with(*s["case"][:2])
        f.worker_state.assert_called_once_with(s["admission"],expected_held="issued_unknown")
        f.docker.assert_called_once_with("container","wait",identity.container_id,timeout=40)
        observer.capture_running.assert_called_once_with(container_id=identity.container_id,image_id=identity.image_id,project=identity.project)
        f.verify_host_exit_reconciliation=Mock(return_value=s["audit"]);f.runner_loss_reconciliation=s["reconciliation"];f.retired_predecessor_inventory=s["after"]
        with patch.object(clock,"read_original",return_value=s["retained"]):f.close_runner_loss(s["physical"],s["admission"],s["retirement"],s["case"])
        f.verify_host_exit_reconciliation.assert_called_once_with(s["admission"],s["retirement"],s["case"],s["run_id"],s["before"],proof_key="runner_loss")
        expected=f.receipt["runner_loss"]
        with patch.object(clock.LaunchFixture,"launch_pair",autospec=True) as parent:
            clock.LaunchFixture.persistent_empty_stop(f)
        parent.assert_called_once_with(f)
        self.assertEqual(f.receipt["clock_suspend"],expected)
        self.assertEqual(f.receipt["status"],"selected_clock_suspend_passed")

    def test_default_cli_is_inert_and_fixed_host_command_has_no_shell_or_callback(self):
        args=["--cohort","unused","--compose-executable","unused","--compose-sha256","a"*64,"--docker-config","unused","--qualification","unused","--qualification-sha256","b"*64,"--wake-selection-sha256","c"*64,"--wake-qualification-sha256","d"*64]
        with patch.object(clock,"manifest",side_effect=AssertionError),patch.object(clock,"ClockSuspendFixture",side_effect=AssertionError):self.assertEqual(clock.main(args),2)
        raw,_,_,_,wake=vector();f=object.__new__(clock.ClockSuspendFixture);f.receipt={};f.wake_root=Path("/private/c09-wake");f.wake_documents=wake;f.wake_binding=clock.wake_binding(*wake,desktop=False)
        mapping={"qualification.json":wake[0],"selection.json":wake[1],"wake_once.py":b"source-authored-placeholder"}
        with patch.object(clock,"bounded_file",side_effect=lambda p,*a:mapping[p.name]),patch.object(clock,"HELPER_SHA",digest(mapping["wake_once.py"])), \
             patch.object(clock.sys,"platform","linux"),patch.object(clock.subprocess,"run",return_value=SimpleNamespace(returncode=0,stdout=canonical(raw["clock_suspend"]["clocks"]["host"]),stderr=b"")) as run:
            f.suspend_once()
        call=run.call_args
        self.assertEqual(call.args[0][:2],["/usr/bin/sudo","--non-interactive"]);self.assertEqual(call.args[0][-2:],["--reviewed-selection-sha256",digest(wake[1])])
        self.assertNotIn("shell",call.kwargs);self.assertEqual(call.kwargs["cwd"],f.wake_root)
        self.assertEqual(run.call_count,1)
        readback=dict(device="unchanged",alarm="still_set",mem_sleep="unavailable")
        held=dict(status="held",reason="wake_operation_unconfirmed",rtc_readback=readback)
        with patch.object(clock,"bounded_file",side_effect=lambda p,*a:mapping[p.name]),patch.object(clock,"HELPER_SHA",digest(mapping["wake_once.py"])), \
             patch.object(clock.sys,"platform","linux"),patch.object(clock.subprocess,"run",return_value=SimpleNamespace(returncode=1,stdout=canonical(held),stderr=b"private-canary")):
            with self.assertRaises(AcceptanceRefused):f.suspend_once()
        self.assertEqual(f.receipt["clock_suspend_failure"],dict(returncode=1,helper_status="held",rtc_readback=readback))

    def test_guest_helper_is_separate_uncredentialed_and_failure_projection_is_fixed(self):
        raw,sel,_,_,_=vector();f=object.__new__(clock.ClockSuspendFixture);f.project="fixture";f.images={"worker":"sha256:"+"a"*64}
        sample=raw["clock_suspend"]["clocks"]["guest_before"]["sample"];f.docker=Mock(return_value=canonical(sample))
        with patch.object(clock.time,"time_ns",side_effect=[sample["utc_before_ns"]-1,sample["utc_after_ns"]+1]):self.assertEqual(f.guest_clock()["sample"],sample)
        args=f.docker.call_args.args
        self.assertNotIn("--mount",args);self.assertNotIn("exec",args);self.assertIn("none",args);self.assertIn("--cap-drop",args)
        self.assertEqual(clock.wake_input_root({"private_root":"/owned/controller/custody"}),Path("/owned/controller/c09-wake"))
        failed={**raw,"status":"held","platform":"linux","stage":"clock_suspend_host","reason":"clock_suspend_helper_held","stdout":"private-canary","clock_suspend_observed":{"private":"private-canary"}}
        public=clock.failure_projection(failed,sel)
        self.assertEqual(public,{"stage":"clock_suspend_host","reason":"clock_suspend_helper_held"});self.assertNotIn("private-canary",json.dumps(public))
        failed["clock_suspend_failure"]=dict(returncode=1,helper_status="held",rtc_readback=dict(device="unchanged",alarm="still_set",mem_sleep="unavailable"))
        self.assertEqual(clock.failure_projection(failed,sel)["helper_failure"],failed["clock_suspend_failure"])
        for bad in ({"private":"private-canary"},{"returncode":True,"helper_status":"held","rtc_readback":None},
                {"returncode":1,"helper_status":{},"rtc_readback":None},
                {"returncode":1,"helper_status":"held","rtc_readback":dict(device="unchanged",alarm="private-canary",mem_sleep="unavailable")}):
            failed["clock_suspend_failure"]=bad
            self.assertNotIn("helper_failure",clock.failure_projection(failed,sel))
        q=canonical(dict(status="passed_compile_only",output_binary_sha256=digest(b"inert-native"),source_unchanged=True,
            compiler_unchanged=True,compiler_exit_code=0,helper_executions=0,power_operations=0))
        with tempfile.TemporaryDirectory() as temporary:
            parent=Path(temporary).resolve(strict=True);selection={"private_root":str(parent/"custody")}
            helper=(Path(clock.__file__).parent/"fixtures/nm2-clock-suspend/wake_once.py").read_bytes()
            reads=lambda p,*_:q if p.name=="compile.json" else b"inert-native" if p.name=="compile.exe" else helper
            boot=Mock(return_value="2026-10-31T07:45:19.9995590Z")
            with patch.object(clock.sys,"platform","win32"),patch.object(clock,"bounded_file",side_effect=reads), \
                 patch.object(clock,"WINDOWS_RECEIPT_SHA",digest(q)),patch.object(clock,"WINDOWS_BINARY_SHA",digest(b"inert-native")), \
                 patch.object(clock.runpy,"run_path",return_value={"boot_identity":boot}) as load:
                documents=clock.prepare_windows_wake(selection,parent/"compile.json",parent/"compile.exe")
            boot.assert_called_once_with();load.assert_called_once_with(str(Path(clock.__file__).parent/"fixtures/nm2-clock-suspend/wake_once.py"),run_name="nm2_c09_readonly_boot_preflight")
            self.assertFalse((parent/"custody").exists());self.assertEqual(documents[0],q)
            self.assertEqual((parent/"c09-wake/windows_s3_once.exe").read_bytes(),b"inert-native")
            self.assertEqual((parent/"c09-wake/selection.json").read_bytes(),documents[1])


if __name__=="__main__":unittest.main()
