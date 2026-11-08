"""Prepared inert flow/record tests; no actual worker/SDK/engine operation."""
import ast
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch
import nm2_worker_boundary_pair as boundary
from nm2_worker_acceptance import AcceptanceRefused, EXECUTION, canonical, digest
from test_nm2_worker_stopped_predecessor_hosted import evidence
import worker_host_persistent as persistent


def records(mode):
    ns = boundary.NS
    zero = boundary.stamp("2026-01-01T00:00:00Z")
    pairs = [("wrapper","begin",10,7),("wrapper","gate-return",10,7)]
    pairs += ([("intermediate","begin",11,10),("leaf","ready",12,11),("intermediate","exit",11,10),
               ("wrapper","exit",10,7),("leaf","exit",12,7)] if mode == boundary.MODES[0]
              else [("leaf","ready",12,10)])
    if mode == boundary.MODES[1]: pairs = [pairs[0],pairs[2],pairs[1]]
    rows=[]
    for i,(role,event,pid,ppid) in enumerate(pairs):
        rows.append(dict(schema="vardr.nm2-fixed-boundary/1",mode=mode,role=role,event=event,
            uid=[10001]*3,gid=[10001]*3,groups=[],capabilities=dict.fromkeys(("CapEff","CapPrm","CapInh","CapAmb","CapBnd"),"0000000000000000"),
            no_new_privs=True,fd3_absent=True,pid=pid,ppid=ppid,pgrp=10,session=10,boottime_ns=(i+1)*ns,
            utc_ns=zero+(i+1)*ns,cpu_ns=100,counters=dict(allocated_bytes=33554432,steps=1,touches=1) if role=="leaf" else None))
    return rows,dict(identity=dict(started_at="2026-01-01T00:00:00Z"),finished_at="2026-01-01T00:00:34Z")


# Source-authored protocol models; emitted compiler/Docker outputs stay private.
REAL_QUALIFICATION_SHA = "7439d6eecc551bd20333933e0e3e54b140fd6b2e3bda55032ecee50c522e8490"
REAL_FIXTURE_IMAGE = "sha256:7e058ceb7118c462e26bb13376b1132509514a8fab0d7a01456e1de777e715b3"
MODEL_IMAGE = "sha256:"+"a"*64


def protocol_plan(case, wrapper):
    identities = case["identities"]
    selected = [(i["id"],"preflight",i["preflight"]["url"]) for i in identities if "preflight" in i]
    selected += [(i["id"],"resource",case["request"]["url"]) for i in identities]
    return dict(schema="vardr.execution-plan/1",profile="gate-fixed-http/1",tool_sha256=wrapper,
        case_hash=digest(canonical(case)),execution=dict(EXECUTION),max_http_dispatches=5,
        credential_references=[dict(identity_id=i["id"],name=i["credential"]["value_env"],source="value_env")
                               for i in identities if "preflight" in i],
        dispatches=[dict(identity_id=identity,phase=phase,max_dispatches=1,
                        request=dict(method="GET",url=url,headers={},query_params={},body=None))
                    for identity,phase,url in selected])


def source_qualification():
    from nm2_worker_boundary_build import CONFIG_FIELDS
    return canonical(dict(schema="vardr.nm2-fixture-image-byte-qualification/1",status="passed_fixture_image_byte_qualification",
        scope="fixture_image_byte_qualification_only",fixture_only=True,fixture_runtime_approval=False,
        genuine_gate_qualified_at_wrapper_path=False,image=MODEL_IMAGE,file_hashes=dict(boundary.FILE_HASHES),python_files=80,
        runner_commit=boundary.BOUNDARY_SOURCES["runner"],gate_commit=boundary.BOUNDARY_SOURCES["gate"],
        source_before_after=True,project_imports=False,native_startups=0,registry_pull=False,publication=False,
        image_defaults=dict(all_config_field_names_checked=True,compared_non_env_fields=list(CONFIG_FIELDS),identical=True,
            environment_values_selected_or_output=False,environment_preservation="same base; COPY-only/no OnBuild/no ENV or RUN")))


QUALIFICATION_DOCUMENT = source_qualification()
MODEL_QUALIFICATION_SHA = digest(QUALIFICATION_DOCUMENT)


def guard_files(plan, mode, genuine_sha=boundary.GATE_SHA):
    def entry(document):
        data = canonical(document)
        return dict(size=len(data),sha256=digest(data),canonical_sha256=digest(data),document=deepcopy(document))
    original = entry(plan)
    child = entry({**plan,"tool_sha256":genuine_sha})
    provenance = entry(dict(schema="vardr.nm2-fixed-guard-delegation/1",mode=mode,changed_field="tool_sha256",child_signed=False,
        original_raw_sha256=original["sha256"],original_plan_sha256=original["canonical_sha256"],
        child_guard_sha256=child["sha256"],guard_rest_sha256=boundary.GUARD_REST[mode]))
    return dict(zip(boundary.GUARD_NAMES,(original,child,provenance)))


def synthetic_linux_fixture():
    """Inert TrustedHost value with distinct Linux bytes, never runtime evidence."""
    from nm2_worker_boundary_build import binding_for_qualification, render_boundary_wrapper
    _,selection,_=evidence()
    sources={n:v["commit"] for n,v in selection["sources"].items()}
    sources.update(boundary.BOUNDARY_SOURCES)
    trees={n:str(i)*40 for i,n in enumerate(sorted(sources),1)}
    genuine,owner="b"*64,"c"*64
    wrapper=digest(render_boundary_wrapper(genuine))
    recipe=dict(schema="vardr.nm2-fixed-fixture-linux-source/1",sources=sources,source_trees=trees,
        base_image_id="sha256:"+"e"*64,template_sha256=boundary.WRAPPER,rendered_wrapper_sha256=wrapper,
        genuine_gate_sha256=genuine,owner_sha256=owner,sdk_inventory_sha256="d"*64,defaults_sha256="a"*64,
        copy_only=True,template_changed_field="ORIGINAL_SHA")
    hashes={**boundary.FILE_HASHES,"/usr/local/bin/vardr-worker-owner":owner,
        "/usr/local/libexec/vardrgate-"+boundary.BOUNDARY_SOURCES["gate"]:genuine,
        "/usr/local/bin/vardrgate":wrapper,"/opt/vardr-nm2-boundary/wrapper.py":wrapper}
    q=dict(schema="vardr.nm2-fixture-image-byte-qualification/1",status="passed_fixture_image_byte_qualification",
        scope="fixture_image_byte_qualification_only",image="sha256:"+"f"*64,file_hashes=hashes,
        python_files=80,python_inventory_sha256=recipe["sdk_inventory_sha256"],source_recipe=recipe,
        runner_commit=sources["runner"],gate_commit=sources["gate"],source_before_after=True,native_startups=0,
        project_imports=False,registry_pull=False,publication=False,fixture_runtime_approval=False,fixture_only=True,
        genuine_gate_qualified_at_wrapper_path=False,image_defaults=json.loads(QUALIFICATION_DOCUMENT)["image_defaults"])
    return canonical(q),binding_for_qualification(q,sources,trees)


def joined_vector(*, expected_fixture=None):
    raw,selection,(before,after)=evidence()
    qualification_document,fixture = expected_fixture if expected_fixture else (QUALIFICATION_DOCUMENT,None)
    image = fixture["image_id"] if fixture else boundary.FIXTURE_IMAGE
    wrapper = fixture["wrapper_sha256"] if fixture else boundary.WRAPPER
    genuine = fixture["genuine_gate_sha256"] if fixture else boundary.GATE_SHA
    owner = fixture["owner_sha256"] if fixture else boundary.FILE_HASHES["/usr/local/bin/vardr-worker-owner"]
    old_image=selection["images"]["worker"]
    selection["images"]["worker"]=image
    for inventory in (before,after):
        inventory["images"].pop(old_image)
        inventory["images"][image]={"id":image}
        for container in inventory["containers"].values():
            if container["image"]==old_image: container["image"]=image
    launches=raw.pop("launch_pair");launch=launches[0]
    after["containers"].pop(launches[1]["container_id"])
    after["volumes"].pop(selection["project"]+"_worker-ready-"+launches[1]["runtime_id"])
    launch.update(started_at="2026-01-01T00:00:00Z",finished_at="2026-01-01T00:00:30Z")
    after["containers"][launch["container_id"]]["state"].update(started_at=launch["started_at"],finished_at=launch["finished_at"])
    raw.pop("stopped_predecessor")
    for name,commit in boundary.BOUNDARY_SOURCES.items(): selection["sources"][name]["commit"]=commit
    selection["https_port"]=8443
    physical=dict(daemon_id="fixture-daemon",container_id=launch["container_id"],image_id=image,
        project=selection["project"],started_at=launch["started_at"],owner_nonce="a"*64)
    registration=dict(identity=physical,origin="https://vardrsec.localhost:8443/backend",
        runner_id="90b0b081-8af2-4d02-b543-333d8fba07b6",enrollment_id="fixture-enrollment",capability_sha256="d"*64,
        mode="persistent",limits=dict(max_attempts=None,idle_timeout_seconds=None),reporting_authority=dict(purpose="worker-stop-only",expires_at=None))
    admission=persistent.expected_admission(dict(runtime_id=launch["runtime_id"],registration=registration))
    physical=dict(identity=physical,runtime_id=admission["runtime_id"],runtime_sha256=admission["runtime_sha256"],
        admission_sha256=admission["admission_sha256"],finished_at=launch["finished_at"],exit_code=125,operator_stop_state="not_requested")
    cases=[];originals=[];reviews=[];traffic=[];attempts=[]
    for i,mode in enumerate(boundary.MODES):
        engagement,job,run_id="engagement"+str(i),"job"+str(i),str(i+1)*32
        stored={"spec":boundary.fixed_case(mode)}
        plan=protocol_plan(stored["spec"],wrapper)
        context=dict(job_id=job,engagement_id=engagement,runner_id=admission["runner_id"],plan_sha256=digest(canonical(plan)),max_duration_seconds=30,
            expires_at="2026-01-01T00:10:00Z",testing_end="2026-01-01T00:10:00Z",credential_grants=[])
        reviews.append(dict(input=dict(plan=plan),context=context,authority={}))
        contract=dict(id=("ab3f0ddc-c14a-4944-8c59-f2c44c9575f0" if i==0 else "cb3f0ddc-c14a-4944-8c59-f2c44c9575f0"),
            attempt_id=("28c8a482-dca8-4c96-8bba-d4e6a5465bea" if i==0 else "38c8a482-dca8-4c96-8bba-d4e6a5465bea"),fence=1,ordinal=1,consumed=True,contract_sha256=str(i+3)*64)
        binding={**{k:admission[k] for k in ("origin","runner_id")},"job_id":job,"contract_id":contract["id"],
            **{k:contract[k] for k in ("attempt_id","fence","contract_sha256")}}
        attempt=dict(runtime_id=admission["runtime_id"],runtime_sequence=str(i+1),job_id=job,binding=binding,
            confirmed_at="2026-01-01T00:00:00Z",**dict.fromkeys(("released_at","terminal_receipt","terminal_receipt_sha256","native_done_sha256","release_receipt")))
        part_records,_=records(mode)
        if i:
            for row in part_records: row["boottime_ns"]+=9*boundary.NS;row["utc_ns"]+=9*boundary.NS
        claim=dict(state="persistent_released" if i==0 else "held_after_claim",utc_anchor="2026-01-01T00:00:00Z" if i==0 else "2026-01-01T00:00:09Z",mono_anchor=float(i*9),
            plan_sha256=context["plan_sha256"],case_sha256=plan["case_hash"],tool_sha256=wrapper,consumption_sent=1,consumption_acknowledged=1)
        local_binding={**binding,**{k:admission[k] for k in ("runtime_id","runtime_sha256","admission_sha256")},"runtime_sequence":str(i+1)}
        native=dict(state="released" if i==0 else "bound",binding=local_binding,completion=None,native_done_sha256=None,release_intent=None,release_ack=None,retired_from_state=None)
        original=dict(run_id=run_id,engagement_id=engagement,job_id=job,phase="done" if i==0 else "executing",started_at="2026-01-01T00:00:00Z" if i==0 else "2026-01-01T00:00:08.500000Z",artifact_sha256="9"*64 if i==0 else None,
            local_stop_requested=False,claim=claim,attempt=native,files=[dict(name="vardrgate_result.json",size=128,sha256="9"*64 if i==0 else "8"*64)],records=part_records,guards=guard_files(plan,mode,genuine))
        originals.append(original);attempts.append(attempt)
        cases.append((engagement,job,stored,dict(job_status="pending",contracts=[],approvals=[],targets_spent=0,duration_allocated=0)))
        start=boundary.stamp("2026-01-01T00:00:00Z")+(1 if i==0 else 11)*boundary.NS
        for j,identity in enumerate(("owner","peer","owner","peer","anonymous")):
            traffic.append(dict(method="GET",identity=identity,path=("/session?" if j<2 else "/fixed/records/42?view=full&include=owner&")+"nm2_case="+mode[4:],received_utc_ns=start+(j+1)*100000000))
        cases[-1][2]["_contract"]=contract
    contractA=cases[0][2].pop("_contract");contractB=cases[1][2].pop("_contract")
    # Recompute case/plan fingerprints after removing test construction metadata.
    for i in range(2):
        plan=reviews[i]["input"]["plan"];plan["case_hash"]=digest(canonical(cases[i][2]["spec"]))
        reviews[i]["context"]["plan_sha256"]=originals[i]["claim"]["plan_sha256"]=digest(canonical(plan))
    a=attempts[0]
    result=dict(contract_id=a["binding"]["contract_id"],artifact_sha256="9"*64,
        receipt_sha256=digest(canonical({"schema":"vardr.managed-result/1",**a["binding"],"artifact_sha256":"9"*64,"case_sha256":digest(canonical(cases[0][2]["spec"]))})),outcome="completed",evidence_created=5,scan_items_created=0)
    completion={"schema":"vardr.managed-completion/1",**a["binding"],"receipt_sha256":result["receipt_sha256"],"outcome":"completed","capacity_reserved":False}
    a.update(released_at="2026-01-01T00:00:08Z",terminal_receipt=completion,terminal_receipt_sha256=digest(canonical(completion)),native_done_sha256="7"*64)
    release={"schema":"vardr.worker-idle-release/2",**{k:admission[k] for k in ("runtime_id","runtime_sha256","admission_sha256")},"runtime_sequence":"1","binding":a["binding"],"terminal_receipt_sha256":a["terminal_receipt_sha256"],"native_done_sha256":a["native_done_sha256"],"released":True}
    release["receipt_sha256"]=digest(canonical(release));a["release_receipt"]=release
    originals[0]["attempt"].update(completion=completion,native_done_sha256=a["native_done_sha256"],release_intent=release,release_ack=release)
    runtime=dict(id=admission["runtime_id"],runtime_sha256=admission["runtime_sha256"],admission_sha256=admission["admission_sha256"],identity=physical["identity"],admission=admission,
        last_sequence="1",head_sequence="1",active_sequence=None,retired=False,new_work_disabled=False,report_sha256=None,attempts=[deepcopy(a)])
    ainv=dict(schema="vardr.nm2-fixture-inventory/3",schema_revision="0041persistentruntime",database_user="vardrmap_app",job_status="done",contracts=[contractA],results=[result],stops=[],
        execution=dict(state="completed",capacity_reserved=False,target_charge=1,duration_seconds=30),targets_spent=1,duration_allocated=30,capacity_reserved_count=0,runtimes=[deepcopy(runtime)])
    localA=dict(last_sequence="1",active_sequence=None,remaining_local_holds=0,attempt=dict(run_id=originals[0]["run_id"],state="released",native_done_sha256=a["native_done_sha256"],release=release))
    runtime.update(last_sequence="2",head_sequence="2",active_sequence="2",attempts=attempts)
    binv=dict(job_status="running",contracts=[contractB],results=[],stops=[],execution=dict(state="active",capacity_reserved=True,target_charge=1,duration_seconds=30),
        targets_spent=1,duration_allocated=30,capacity_reserved_count=1,runtimes=[runtime])
    b=attempts[1];terminal={"schema":"vardr.managed-stop-receipt/1",**b["binding"],"outcome":"failed","cause":"observed_exit","capacity_reserved":False,
        "receipt_sha256":digest(canonical({"schema":"vardr.managed-stop/1",**b["binding"],"outcome":"failed","cause":"observed_exit","termination_confirmed":True}))}
    retired={"schema":"vardr.worker-retirement/3",**{k:admission[k] for k in ("runtime_id","runtime_sha256","admission_sha256","origin","runner_id","enrollment_id")},
        "runtime_sequence":"2","last_sequence":"2","binding":b["binding"],"attempt_receipt":terminal,"report_sha256":"f"*64,"retired":True}
    retired["receipt_sha256"]=digest(canonical(retired));launch["retirement_sha256"]=retired["receipt_sha256"]
    afterB={**deepcopy(binv),"job_status":"failed","capacity_reserved_count":0,"execution":{**binv["execution"],"state":"failed","capacity_reserved":False},
        "runtimes":[{**deepcopy(runtime),"retired":True,"report_sha256":retired["report_sha256"],"new_work_disabled":True}],"stops":[{k:terminal[k] for k in ("contract_id","receipt_sha256","outcome","cause")} ]}
    audit_binding={k:admission[k] for k in ("runner_id","runtime_id","runtime_sha256","admission_sha256")}
    audit=dict(schema="vardr.worker-state-audit/1",status="retired",reason=None,complete=True,binding=audit_binding,parent=dict(state="retired",last_sequence="2",head_sequence="2",active_sequence=None),
        counts=dict.fromkeys(("attempts","selections","associated_runs","associated_claims"),2),global_holds=0,retirement_receipt_sha256=retired["receipt_sha256"])
    reconciliation=dict(schema="vardr.worker-reconciliation/1",status="reconciled",reason=None,complete=True,binding=audit_binding,selected_run_id=originals[1]["run_id"],selected_sequence="2",
        reconciliation_state="terminal_host_exit_observed",remaining_local_holds=0,retirement_receipt_sha256=retired["receipt_sha256"])
    cursor=dict(last_sequence="2",phase="active")
    observation=dict(schema="vardr.worker-receipt-observation/3",runtime_id=admission["runtime_id"],runtime_sha256=admission["runtime_sha256"],admission_sha256=admission["admission_sha256"],
        cursor=cursor,active=dict(runtime_sequence="2",binding=b["binding"],receipt=terminal),retirement=retired,new_work_disabled=True,reporting_revoked=False,
        availability=dict(state="stopped",observed_at=None,fresh_until=None,cursor=cursor))
    retained=deepcopy(originals[1]);retained["phase"]="failed";retained["attempt"].update(state="physical_retirement_observed",retired_from_state="bound")
    raw.update(scenario=boundary.SCENARIO,status="selected_boundary_pair_passed",stage="selected_boundary_pair_complete",acceptance_scope="fixed_orphan_drain_and_bounded_load_only",launch=launch,
        fixture_qualification_document=qualification_document.decode(),fixture_qualification_sha256=digest(qualification_document),fixture_image=json.loads(qualification_document),
        image_sources=dict(runner=dict(image_id=image,python_file_count=80,python_inventory_sha256=fixture["source_recipe"]["sdk_inventory_sha256"] if fixture else "0"*64,executables={"/usr/local/bin/vardr-worker-owner":owner,"/usr/local/bin/vardrgate":wrapper})))
    raw["boundary_pair"]=dict(first=dict(case=cases[0],local=localA,inventory=ainv,original=originals[0],retained=deepcopy(originals[0]),review=reviews[0],measured={}),
        second=dict(case=cases[1],run_id=originals[1]["run_id"],original=originals[1],review=reviews[1],before=binv,after=afterB,retained=retained),
        admission=admission,physical=physical,retirement=retired,audit=audit,traffic=traffic,reconciliation=reconciliation,
        host_reconciled=dict(schema="vardr.worker-cli/1",state="terminal_observed",runtime_id=admission["runtime_id"],receipt=observation))
    raw.update(before_sha256=digest(canonical(before)),after_sha256=digest(canonical(after)),fixture_stop=dict(status="stopped_retained",container_ids=sorted(after["containers"]),stop_requested_ids=sorted(set(after["containers"])-{launch["container_id"]})))
    return raw,selection,(before,after)


class FixedBoundaryPairTests(unittest.TestCase):
    def setUp(self):
        # Only this imported fixture module is modeled; the runtime constants stay literal.
        self.assertEqual(boundary.QUALIFICATION_SHA,REAL_QUALIFICATION_SHA)
        self.assertEqual(boundary.FIXTURE_IMAGE,REAL_FIXTURE_IMAGE)
        modeled=patch.multiple(boundary,QUALIFICATION_SHA=MODEL_QUALIFICATION_SHA,FIXTURE_IMAGE=MODEL_IMAGE)
        modeled.start();self.addCleanup(modeled.stop)

    def test_full_positive_reader_joins_original_retirement_audit_and_retention(self):
        for desktop in (True,False):
            expected=None if desktop else synthetic_linux_fixture()
            raw,selection,inventories=joined_vector(expected_fixture=expected)
            if desktop: raw["platform"]="win32";selection["docker_context"]="desktop-linux"
            value=boundary.boundary_projection(raw,selection,inventories,desktop=desktop,expected_fixture=expected)
            self.assertEqual(value["schema"],boundary.HOSTED)
            self.assertEqual(value["owned_stopped_container_count"],6)
            self.assertTrue(value["ordinary_orphan_drain"] and value["bounded_load_observed"])
            self.assertEqual(value["load_observation"]["plan_seconds"],20)
            self.assertEqual(value["load_observation"]["allocation_seconds"],30)
            self.assertEqual(value["guard_delegation"][boundary.MODES[1]]["original_plan_sha256"],raw["boundary_pair"]["second"]["original"]["claim"]["plan_sha256"])
            self.assertNotIn("private/synthetic",canonical(value).decode())
            if not desktop:
                with self.assertRaises(AcceptanceRefused): boundary.boundary_projection(raw,selection,inventories)
                changed=(expected[0]+b" ",expected[1])
                with self.assertRaises(AcceptanceRefused): boundary.boundary_projection(raw,selection,inventories,expected_fixture=changed)

    def test_final_server_floor_interval_does_not_require_exact_memory_only_lease(self):
        raw,selection,inventories=joined_vector()
        # Physical exit before anchor+20 is legitimate within the exact <1s server floor.
        finish="2026-01-01T00:00:28.500000Z"
        raw["launch"]["finished_at"]=raw["boundary_pair"]["physical"]["finished_at"]=finish
        inventories[1]["containers"][raw["launch"]["container_id"]]["state"]["finished_at"]=finish
        raw["after_sha256"]=digest(canonical(inventories[1]))
        raw["platform"]="win32";selection["docker_context"]="desktop-linux"
        value=boundary.boundary_projection(raw,selection,inventories,desktop=True)
        self.assertEqual(value["native_exit_trigger"],"not_attributed")
        self.assertEqual(value["renewal_precision"],"exact_last_native_lease_memory_only")
        # Much earlier exit is not silently called an authorization-expiry result.
        raw["boundary_pair"]["physical"]["finished_at"]=raw["launch"]["finished_at"]="2026-01-01T00:00:20Z"
        with self.assertRaises(AcceptanceRefused): boundary.boundary_projection(raw,selection,inventories,desktop=True)

    def test_full_reader_rejects_wrong_cap_history_native_done_and_promotion(self):
        for change in ("cap","allocation","history","nativeA","nativeB","promotion","retirement","audit","preload","method","case","original_guard","child_guard","provenance","immutable_guard","canonical_size"):
            raw,selection,inventories=joined_vector();state=raw["boundary_pair"];second=state["second"]
            raw["platform"]="win32";selection["docker_context"]="desktop-linux"
            if change=="cap": second["original"]["started_at"]="2026-01-01T00:00:20Z";second["original"]["claim"]["utc_anchor"]="2026-01-01T00:00:20Z"
            elif change=="allocation": second["before"]["execution"]["duration_seconds"]=20
            elif change=="history": second["after"]["runtimes"][0]["attempts"][0]["native_done_sha256"]="f"*64
            elif change=="nativeA": state["first"]["local"]["attempt"]["native_done_sha256"]="f"*64
            elif change=="nativeB": second["original"]["attempt"]["native_done_sha256"]="f"*64
            elif change=="promotion": second["retained"]["artifact_sha256"]="f"*64
            elif change=="retirement": state["retirement"]["last_sequence"]="1"
            elif change=="audit": state["audit"]["global_holds"]=1
            elif change=="preload":
                for row in state["traffic"][5:]: row["received_utc_ns"]=boundary.stamp("2026-01-01T00:00:10.500000Z")
            elif change=="method": state["traffic"][5]["method"]="POST"
            elif change=="case": second["case"][2]["spec"]["request"]["method"]="POST"
            elif change in {"original_guard","child_guard","provenance"}:
                name=boundary.GUARD_NAMES[{"original_guard":0,"child_guard":1,"provenance":2}[change]]
                entry=second["original"]["guards"][name]
                if change=="original_guard": entry["document"]["tool_sha256"]="f"*64
                elif change=="child_guard": entry["document"]["execution"]["timeout_seconds"]=30
                else: entry["document"]["child_signed"]=True
                encoded=canonical(entry["document"])
                entry.update(size=len(encoded),sha256=digest(encoded),canonical_sha256=digest(encoded))
            elif change=="canonical_size": second["original"]["guards"][boundary.GUARD_NAMES[1]]["size"]=1
            elif change=="immutable_guard": state["first"]["retained"]["guards"][boundary.GUARD_NAMES[0]]["sha256"]="f"*64
            with self.subTest(change=change),self.assertRaises((AcceptanceRefused,ValueError)):
                boundary.boundary_projection(raw,selection,inventories,desktop=True)

    def test_source_authored_b20_vectors_and_default_helpers(self):
        pins={n.targets[0].id:n.value.value for n in ast.parse(Path(boundary.__file__).read_text()).body
              if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and isinstance(n.value,ast.Constant)}
        self.assertEqual(pins["QUALIFICATION_SHA"],REAL_QUALIFICATION_SHA)
        self.assertEqual(pins["FIXTURE_IMAGE"],REAL_FIXTURE_IMAGE)
        self.assertNotEqual(MODEL_QUALIFICATION_SHA,REAL_QUALIFICATION_SHA)
        self.assertNotEqual(MODEL_IMAGE,REAL_FIXTURE_IMAGE)
        for mode in boundary.MODES:
            plan=protocol_plan(boundary.fixed_case(mode),boundary.WRAPPER)
            self.assertEqual(plan["execution"],EXECUTION)
            self.assertEqual(digest(canonical({k:v for k,v in plan.items() if k != "tool_sha256"})),boundary.GUARD_REST[mode])
            self.assertEqual(plan["case_hash"],digest(canonical(boundary.fixed_case(mode))))
        tree=ast.parse((Path(boundary.__file__).parent/"nm2_worker_acceptance.py").read_text(encoding="utf-8-sig"))
        self.assertNotIn("fixture_execution",{n.name for n in ast.walk(tree) if isinstance(n,ast.FunctionDef)})
        for node in ast.walk(tree):
            if isinstance(node,ast.FunctionDef) and node.name in {"new_job","job_in_engagement","approval_review_input","approve"}:
                self.assertNotIn("execution",{a.arg for a in (*node.args.args,*node.args.kwonlyargs)})
        self.assertEqual(EXECUTION["timeout_seconds"],20)

    def test_fixed_orphan_and_loaded_graphs(self):
        self.assertEqual(boundary.stamp("2026-01-01T00:00:00.123456789Z"),boundary.stamp("2026-01-01T00:00:00Z")+123456789)
        self.assertEqual(boundary.stamp("2026-01-01T00:00:00.123456789+00:00"),boundary.stamp("2026-01-01T00:00:00.123456789Z"))
        rows,physical=records(boundary.MODES[0])
        physical["finished_at"]="2026-01-01T00:00:07.000000101Z"
        rows[-1]["utc_ns"]=boundary.stamp("2026-01-01T00:00:07Z")+100  # valid1ns before exact end
        boundary.fixed_records(rows,boundary.MODES[0],physical)
        for mode in boundary.MODES:
            rows,physical=records(mode)
            value=boundary.fixed_records(rows,mode,physical)
            self.assertIn(("leaf","ready"),value)
            self.assertEqual(("leaf","exit") in value,mode==boundary.MODES[0])

    def test_malformed_foreign_late_and_ceiling_records_refuse(self):
        for change in ("uid","fd3","cap","lineage","duplicate","time","ceiling","counter","foreign","prestart1ns"):
            rows,physical=records(boundary.MODES[0])
            if change=="uid": rows[0]["uid"][0]=0
            elif change=="fd3": rows[0]["fd3_absent"]=False
            elif change=="cap": rows[0]["capabilities"]["CapEff"]="0000000000000001"
            elif change=="lineage": rows[-1]["ppid"]=10
            elif change=="duplicate": rows[-1]=deepcopy(rows[0])
            elif change=="time": rows[-1]["boottime_ns"]=40*boundary.NS
            elif change=="ceiling": rows[-1]["event"]="ceiling"
            elif change=="counter": rows[3]["counters"]["allocated_bytes"]=True
            elif change=="foreign": rows[-1]["mode"]=boundary.MODES[1]
            elif change=="prestart1ns": physical["identity"]["started_at"]="2026-01-01T00:00:00.000000101Z";rows[0]["utc_ns"]=boundary.stamp("2026-01-01T00:00:00Z")+100
            with self.subTest(change=change),self.assertRaises(AcceptanceRefused):
                boundary.fixed_records(rows,boundary.MODES[0],physical)

    def test_b_eligibility_follows_a_closed_idle_without_stop(self):
        fixture=boundary.BoundaryFixture.__new__(boundary.BoundaryFixture)
        events=[];binding=("runner","enrollment")
        fixture.await_completed_job=Mock(side_effect=lambda *a:(events.append("A_DONE_release_idle1") or {"attempt":{"run_id":"a"*32}}))
        fixture.inventory=Mock(return_value={})
        fixture.new_job=Mock(side_effect=lambda *a,**kw:(events.append("B_create") or ("engagementB","authorizationB","jobB",{"spec":{"id":boundary.MODES[1]}})))
        fixture.approve=Mock(side_effect=lambda *a,**kw:(events.append("B_fresh_sign_register") or binding))
        fixture.traffic=Mock(return_value=[{}]*10)
        fixture.helper=Mock(return_value=b'[{"job_id":"jobB","run_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]')
        fixture.reviews={mode:{} for mode in boundary.MODES}
        fixture.worker_action=Mock(side_effect=AssertionError("no stop or fake physical receipt"))
        identity=SimpleNamespace(container_id="c"*64)
        fixture.docker=Mock(return_value=b"125")
        exit_proof=SimpleNamespace(exit_code=125)
        observer=Mock(observe_exit=Mock(return_value=exit_proof))
        with patch.object(boundary,"read_original",return_value={}):
            value=fixture.observe_boundary_pair(observer,identity,{},("A","jobA",{},{}),binding)
        self.assertIs(value,exit_proof)
        self.assertEqual(events,["A_DONE_release_idle1","B_create","B_fresh_sign_register"])
        fixture.worker_action.assert_not_called()
        fixture.docker.assert_called_once_with("container","wait",identity.container_id,timeout=40)
        observer.observe_exit.assert_called_once_with(identity)
        observer.confirm_exit.assert_called_once_with(exit_proof)
        self.assertEqual(fixture.new_job.call_args.kwargs,{"marker":True})

    def test_existing_default_dispatch_and_fixture_constructor_stay_explicit(self):
        root=Path(boundary.__file__).parent
        tree=ast.parse((root/"nm2_worker_launch_acceptance.py").read_text(encoding="utf-8-sig"))
        main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="main")
        self.assertNotIn("BoundaryFixture",ast.dump(main))
        self.assertNotIn("--boundary-pair",ast.dump(main))
        import nm2_worker_hosted as hosted
        env={"NM2_SCENARIO":boundary.SCENARIO,"NM2_DATABASE_REVISION":"0041persistentruntime",
             **{"NM2_"+n.upper()+"_SHA":v for n,v in boundary.BOUNDARY_SOURCES.items()}}
        self.assertEqual(hosted.execution_options(env),(boundary.SCENARIO,"0041persistentruntime"))
        with self.assertRaises(ValueError): hosted.execution_options({**env,"NM2_RUNNER_SHA":"0"*40})
        with TemporaryDirectory() as folder:
            q=Path(folder)/"qualification.json";q.write_bytes(QUALIFICATION_DOCUMENT)
            args=["--cohort","inert-cohort.json","--compose-executable","inert-compose","--compose-sha256","a"*64,
                  "--docker-config","inert-docker-config","--qualification",str(q),"--qualification-sha256",MODEL_QUALIFICATION_SHA]
            with patch.object(boundary,"sys",SimpleNamespace(platform="win32",stderr=None)),patch.object(boundary,"BoundaryFixture") as constructor,patch.object(boundary,"manifest",return_value={"inert":True}):
                self.assertEqual(boundary.main(args),2)
                constructor.assert_not_called()
                constructor.return_value.receipt={"status":"selected_boundary_pair_passed"}
                self.assertEqual(boundary.main([*args,"--execute"]),0)
                constructor.return_value.run.assert_called_once_with()
                self.assertEqual(constructor.call_args.kwargs["qualification"],QUALIFICATION_DOCUMENT)
                self.assertIsNone(constructor.call_args.kwargs["expected_fixture"])
        readback=(root/"nm2_worker_boundary_read.py").read_text()
        self.assertIn("O_NOFOLLOW",readback)
        self.assertNotIn("os.kill",readback)
        self.assertNotIn("socket",readback)
        self.assertNotIn("subprocess",readback)


if __name__=="__main__":
    unittest.main()
