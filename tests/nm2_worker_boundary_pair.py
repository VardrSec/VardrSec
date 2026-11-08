"""Inactive fixed two-job boundary fixture; owner runtime decision still required."""
import argparse
import json
from pathlib import Path
import re
import sys
import time
from nm2_worker_acceptance import EXECUTION, canonical, digest, manifest, require
from nm2_worker_launch_acceptance import LaunchFixture, engine_timestamp_ns

SCENARIO = "persistent-fixed-boundary-pair"
HOSTED = "vardr.nm2-hosted/26"
BOUNDARY_SOURCES = {"map":"05dc78cf9a385255de459c8a5b833842d6528a63","runner":"f3dc7e92ea0cc04f5aca4bb74cc739fd79f5be19",
                    "gate":"57cfedfaf59b11cf626288c343f34a34c7b1df13"}
MODES = ("nm2-c07-orphan-drain", "nm2-c09-loaded-authority")
WRAPPER = "39c3f2b0f3df91eb36a464f1168bd66cf90462411fce9a0293f3aae1570e59f9"
FILE_HASHES = {
    "/usr/local/bin/vardr-worker-owner": "8880528d5043b89b1e164769ec3b49a2cefe81db3545c5ef9093fe28192ad104",
    "/usr/local/libexec/vardrgate-57cfedfaf59b11cf626288c343f34a34c7b1df13": "cc08e48efe7c6a42bcb0bc02ec4fca7ec70c739451cfd54109064cc59e934ae7",
    "/usr/local/bin/vardrgate": WRAPPER,
    "/opt/vardr-nm2-boundary/wrapper.py": WRAPPER,
    "/opt/vardr-nm2-boundary/leaf.py": "341713cdebc59e190e097f9aa6f0321101b445cf8ee19d5a33053bd605b4fc40",
}
QUALIFICATION_SHA = "7439d6eecc551bd20333933e0e3e54b140fd6b2e3bda55032ecee50c522e8490"
FIXTURE_IMAGE = "sha256:7e058ceb7118c462e26bb13376b1132509514a8fab0d7a01456e1de777e715b3"
NS = 1_000_000_000
GUARD_NAMES = ("nm2-original-request-guard.json", "nm2-child-request-guard.json", "nm2-guard-delegation.json")
GUARD_REST = dict(zip(MODES,("53b011334dbd118b9e52ada4ea98a6a592bc57d1799c112064823d7a5db27d18", "ed6673566f7bafc72aa097793ef4dab4e8dd1a6fe1454324eaa62ea3531e8317")))
RUNNER_LOSS_MODE = 'nm2-c08-live-runner-loss'
GUARD_REST[RUNNER_LOSS_MODE] = '3681d4c927e7870e697a964c00de5f4944ae4912e88e5d1a130d193d4c9aac4e'
GATE_SHA = "cc08e48efe7c6a42bcb0bc02ec4fca7ec70c739451cfd54109064cc59e934ae7"

def fixed_case(mode):
    from gate_acceptance import ORIGIN as original, reviewed_cases
    from nm2_worker_acceptance import ORIGIN
    spec = next(row["spec"] for row in reviewed_cases() if row["name"] == "fixed")
    spec["id"] = mode
    for request in [spec["request"], *(i["preflight"] for i in spec["identities"] if i.get("preflight"))]:
        request["url"] = ORIGIN+request["url"][len(original):]+("&" if "?" in request["url"] else "?")+"nm2_case="+mode[4:]
    return spec

def fixture_binding(document, selection, *, desktop, expected_fixture=None, operand="boundary"):
    """Linux expectations come from the trusted host recipe before either job."""
    require(type(document) is bytes, "boundary_fixture_image_refused")
    require(type(operand) is str and operand in {"boundary","runner-loss"}, "boundary_mode_refused")
    qualification_sha,image,wrapper = QUALIFICATION_SHA,FIXTURE_IMAGE,WRAPPER
    if operand == "runner-loss":
        qualification_sha = "e70bc79bd30c02c93e857e98e31dbf390db003da2792e06e5603fd99e9346927"
        image = "sha256:b5f1cb3310e4a0bf2c71af18d13c8679509d5bf28a62d4d0c06147e00c023572"
        wrapper = "df6543705d10dc371b8587f6f5ed6de64c126cb467ac23ad82df79f0faed919d"
    q = json.loads(document)
    if desktop:
        require(expected_fixture is None and qualification_sha is not None
                and digest(document) == qualification_sha, "boundary_fixture_image_refused")
        binding = dict(image_id=image,wrapper_sha256=wrapper,genuine_gate_sha256=GATE_SHA,
                       owner_sha256=FILE_HASHES["/usr/local/bin/vardr-worker-owner"],source_recipe=None)
    else:
        from nm2_worker_boundary_build import binding_for_qualification
        require(type(expected_fixture) is tuple and len(expected_fixture) == 2
                and document == expected_fixture[0] and type(expected_fixture[1]) is dict,
                "boundary_fixture_image_refused")
        binding = expected_fixture[1]
        require(set(binding) == {"image_id","wrapper_sha256","genuine_gate_sha256","owner_sha256","source_recipe"}
                and type(binding["source_recipe"]) is dict, "boundary_fixture_image_refused")
        validated = binding_for_qualification(q,{n:v["commit"] for n,v in selection["sources"].items()},
                                            binding["source_recipe"]["source_trees"],operand=operand)
        require(canonical(validated) == canonical(binding), "boundary_fixture_image_refused")
    expected_files = {**FILE_HASHES,"/usr/local/bin/vardr-worker-owner":binding["owner_sha256"],
        "/usr/local/libexec/vardrgate-"+BOUNDARY_SOURCES["gate"]:binding["genuine_gate_sha256"],
        "/usr/local/bin/vardrgate":binding["wrapper_sha256"],"/opt/vardr-nm2-boundary/wrapper.py":binding["wrapper_sha256"]}
    require(q["schema"] == "vardr.nm2-fixture-image-byte-qualification/1" and q["status"] == "passed_fixture_image_byte_qualification"
            and q["fixture_only"] is True and q["fixture_runtime_approval"] is False and q["genuine_gate_qualified_at_wrapper_path"] is False
            and q["file_hashes"] == expected_files and type(q["python_files"]) is int and q["python_files"] == 80
            and q["image"] == selection["images"]["worker"] == binding["image_id"]
            and q["runner_commit"] == BOUNDARY_SOURCES["runner"] and q["gate_commit"] == BOUNDARY_SOURCES["gate"]
            and q["source_before_after"] is True and q["project_imports"] is False and type(q["native_startups"]) is int and q["native_startups"] == 0
            and q["registry_pull"] is q["publication"] is False, "boundary_fixture_image_refused")
    return binding

def stamp(value):
    return engine_timestamp_ns(value[:-6]+"Z" if type(value) is str and value.endswith("+00:00") else value)

def fixed_records(rows, mode, physical):
    """Closed ordinary descendant facts, never owner/channel or credential isolation."""
    keys = set("schema mode role event uid gid groups capabilities no_new_privs fd3_absent pid ppid pgrp session boottime_ns utc_ns cpu_ns counters".split())
    require(mode in {*MODES,RUNNER_LOSS_MODE}, 'boundary_mode_refused')
    expected = {("wrapper", event) for event in ("begin", "gate-return")}
    expected |= ({("wrapper", "exit"), ("intermediate", "begin"), ("intermediate", "exit"), ("leaf", "ready"), ("leaf", "exit")}
                 if mode == MODES[0] else {("leaf", "ready")})
    if mode == RUNNER_LOSS_MODE: expected.add(('wrapper','parent-kill-intent'))
    require(type(rows) is list and len(rows) == len(expected), "boundary_records_refused")
    selected = {}
    for row in rows:
        require(type(row) is dict and set(row) == keys and row["schema"] == "vardr.nm2-fixed-boundary/1"
                and row["mode"] == mode and (row["role"], row["event"]) in expected,
                "boundary_records_refused")
        pair = row["role"], row["event"]
        require(pair not in selected and canonical([row["uid"], row["gid"], row["groups"]]) == b"[[10001,10001,10001],[10001,10001,10001],[]]"
                and row["no_new_privs"] is row["fd3_absent"] is True
                and row["capabilities"] == dict.fromkeys(("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"), "0000000000000000"), "boundary_identity_refused")
        require(all(type(row[key]) is int and 0 < row[key] < 2**63 for key in ("pid", "ppid", "pgrp", "session", "boottime_ns", "utc_ns"))
                and type(row["cpu_ns"]) is int and 0 <= row["cpu_ns"] <= 3*NS
                and stamp(physical["identity"]["started_at"]) <= row["utc_ns"] < stamp(physical["finished_at"]), "boundary_time_refused")
        if row["role"] == "leaf":
            c = row["counters"]
            require(type(c) is dict and set(c) == {"allocated_bytes", "steps", "touches"}
                    and all(type(v) is int and 0 <= v <= 2**40 for v in c.values())
                    and c["allocated_bytes"] == 32*1024*1024 and c["touches"] >= 1, "boundary_load_refused")
        else:
            require(row["counters"] is None, "boundary_records_refused")
        selected[pair] = row
    begin = selected["wrapper", "begin"]
    require(all(begin["boottime_ns"] <= r["boottime_ns"] < begin["boottime_ns"]+35*NS
                and r["pgrp"] == begin["pgrp"] and r["session"] == begin["session"] for r in rows), "boundary_lineage_refused")
    require(selected["wrapper", "gate-return"]["pid"] == begin["pid"], "boundary_lineage_refused")
    if mode == MODES[0]:
        middle, leaf = selected["intermediate", "begin"], selected["leaf", "ready"]
        chain = [begin, selected["wrapper", "gate-return"], middle, leaf, selected["intermediate", "exit"], selected["wrapper", "exit"], selected["leaf", "exit"]]
        require(middle["ppid"] == begin["pid"] and leaf["ppid"] == middle["pid"]
                and selected["leaf", "exit"]["ppid"] == begin["ppid"]
                and len({begin["pid"], middle["pid"], leaf["pid"]}) == 3
                and selected["intermediate", "exit"]["pid"] == middle["pid"]
                and selected["wrapper", "exit"]["pid"] == begin["pid"]
                and selected["leaf", "exit"]["pid"] == leaf["pid"]
                and selected["leaf", "exit"]["boottime_ns"]-leaf["boottime_ns"] <= 8*NS, "boundary_lineage_refused")
    elif mode == RUNNER_LOSS_MODE:
        leaf, intent = selected['leaf','ready'], selected['wrapper','parent-kill-intent']
        chain = [begin,selected['wrapper','gate-return'],leaf,intent]
        require(begin['ppid'] > 1 and leaf['ppid'] == begin['pid'] and leaf['pid'] != begin['pid']
                and intent['pid'] == begin['pid'] and intent['ppid'] == begin['ppid']
                and selected['wrapper','gate-return']['ppid'] == begin['ppid'], 'boundary_lineage_refused')
    else:
        leaf = selected["leaf", "ready"]
        chain = [begin, leaf, selected["wrapper", "gate-return"]]
        require(leaf["ppid"] == begin["pid"] and leaf["pid"] != begin["pid"], "boundary_lineage_refused")
    require(all(a["boottime_ns"] < b["boottime_ns"] and a["utc_ns"] < b["utc_ns"] for a,b in zip(chain,chain[1:])), "boundary_order_refused")
    return selected

def guard_joins(original, mode, plan, claim_plan_sha256, fixture):
    """Reconstruct the unsigned child; descriptive files confer no authority."""
    guards = original["guards"]
    require(type(guards) is dict and set(guards) == set(GUARD_NAMES), "boundary_guard_files_refused")
    for entry in guards.values():
        require(type(entry) is dict and set(entry) == {"size","sha256","canonical_sha256","document"}
                and type(entry["size"]) is int and 0 < entry["size"] <= 131072
                and all(type(entry[k]) is str and re.fullmatch("[a-f0-9]{64}",entry[k]) for k in ("sha256","canonical_sha256")),
                "boundary_guard_files_refused")
        require(entry["canonical_sha256"] == digest(canonical(entry["document"])), "boundary_guard_hash_refused")
    source, child, provenance = (guards[name] for name in GUARD_NAMES)
    rest = {k:v for k,v in plan.items() if k != "tool_sha256"}
    require(plan["tool_sha256"] == fixture["wrapper_sha256"] and digest(canonical(rest)) == GUARD_REST[mode]
            and canonical(source["document"]) == canonical(plan)
            and source["canonical_sha256"] == claim_plan_sha256, "boundary_original_guard_refused")
    expected_child = {**plan,"tool_sha256":fixture["genuine_gate_sha256"]}
    require(canonical(child["document"]) == canonical(expected_child)
            and child["sha256"] == child["canonical_sha256"] == digest(canonical(expected_child))
            and child["size"] == len(canonical(expected_child)), "boundary_child_guard_refused")
    expected = dict(schema="vardr.nm2-fixed-guard-delegation/1",mode=mode,changed_field="tool_sha256",child_signed=False,
                    original_raw_sha256=source["sha256"],original_plan_sha256=claim_plan_sha256,
                    child_guard_sha256=child["sha256"],guard_rest_sha256=GUARD_REST[mode])
    require(canonical(provenance["document"]) == canonical(expected)
            and provenance["sha256"] == provenance["canonical_sha256"] == digest(canonical(expected))
            and provenance["size"] == len(canonical(expected)), "boundary_guard_provenance_refused")
    return {**{k:expected[k] for k in ("original_raw_sha256","original_plan_sha256","child_guard_sha256","guard_rest_sha256","child_signed")},
            "provenance_sha256":provenance["sha256"]}

def read_original(fixture, run_id, case, *, mode=None):
    require(mode is None or mode == RUNNER_LOSS_MODE, 'boundary_mode_refused')
    source = (fixture.install/"tests/nm2_worker_boundary_read.py").read_text(encoding="utf-8")
    return json.loads(fixture.helper("-I", "-c", source, python=True,
        stdin=canonical(dict(run_id=run_id, engagement_id=case[0], job_id=case[1], **({'mode':mode} if mode is not None else {})))))

class BoundaryFixture(LaunchFixture):
    boundary_pair = True

    def __init__(self, selection, *, qualification, qualification_sha256, expected_fixture=None, **kwargs):
        require(set(kwargs) == {"compose", "compose_sha256", "docker_config"}, "boundary_mode_refused")
        super().__init__(selection, completed=True, **kwargs)
        require(all(selection["sources"][name]["commit"] == commit for name,commit in BOUNDARY_SOURCES.items()), "boundary_source_refused")
        require(type(qualification) is bytes and digest(qualification) == qualification_sha256, "boundary_fixture_image_refused")
        self.qualification_document = qualification.decode("utf-8")
        self.fixture_binding = fixture_binding(qualification,selection,desktop=sys.platform == "win32",expected_fixture=expected_fixture)
        qualification = json.loads(qualification)
        self.reviews = {}
        self.receipt.update(scenario=SCENARIO, acceptance_scope="fixed_orphan_drain_and_bounded_load_only",
                            fixture_image=qualification, fixture_qualification_sha256=qualification_sha256, fixture_qualification_document=self.qualification_document)

    def target_environment(self):
        return {"NM2_FIXTURE_UTC_TIMING": "1"}

    def new_job(self, name, **kwargs):
        return super().new_job("c07-orphan-drain" if name == "launch-completed" else name, **kwargs)

    def approve(self, name, engagement, authorization, job, case, **kwargs):
        mode = case["spec"]["id"]
        require(mode in MODES, "boundary_mode_refused")
        review, context, authority = {}, {}, {}; require(kwargs.pop("review_context",None) is None,"boundary_review_refused")
        result = super().approve(name, engagement, authorization, job, case, review_snapshot=review,
            review_context=context, review_authority=authority, **kwargs)
        self.reviews[mode] = dict(input=review, context=context, authority=authority)
        return result

    def observe_boundary_pair(self, observer, identity, admission, case, binding):
        local = self.await_completed_job(admission, case)
        a_inventory = self.inventory(*case[:2], include_capacity=True)
        first = dict(case=case, local=local, inventory=a_inventory,
                     original=read_original(self, local["attempt"]["run_id"], case), review=self.reviews[MODES[0]])
        # B does not exist until original A DONE/release, idle parent1 and zero holds.
        engagement, authorization, job, stored = self.new_job("c09-loaded-authority", marker=True)
        second_case = engagement, job, stored, self.inventory(engagement, job, include_capacity=True)
        require(self.approve("c09-loaded-authority", engagement, authorization, job, stored) == binding, "boundary_enrollment_changed")
        until = time.monotonic()+40
        while len(self.traffic()) < 10:
            require(time.monotonic() < until, "boundary_traffic_unobserved")
            time.sleep(.1)
        self.docker("container", "wait", identity.container_id, timeout=40)
        exited = observer.observe_exit(identity)
        observer.confirm_exit(exited)
        require(type(exited.exit_code) is int and exited.exit_code == 125, "boundary_native_exit_refused")
        runs = json.loads(self.helper("audit", "list", "--json", "--engagement", engagement))
        selected = [r for r in runs if r["job_id"] == job]
        require(len(selected) == 1, "boundary_original_run_refused")
        run_id = selected[0]["run_id"]
        self.boundary_state = dict(first=first, second=dict(case=second_case, run_id=run_id,
            original=read_original(self, run_id, second_case), review=self.reviews[MODES[1]],
            before=self.inventory(engagement, job, include_capacity=True)), admission=admission)
        return exited

    def close_boundary_pair(self, physical, admission, retired, case):
        state = self.boundary_state
        second = state["second"]
        audit = self.reconcile_original(admission, retired, host_exit_run_id=second["run_id"],
                                        expected_sequence="2", expected_attempts=2)
        state.update(physical=physical, retirement=retired, audit=audit, traffic=self.traffic(), reconciliation=self.boundary_reconciliation)
        state["first"]["measured"] = self.verify_fixed(*case[:3], physical, case[3], state["traffic"][:5],
            state["first"]["inventory"], persistent=True, boundary_failure=True)[1]
        second.update(after=self.inventory(*second["case"][:2], include_capacity=True),
                      retained=read_original(self, second["run_id"], second["case"]))
        state["first"]["retained"] = read_original(self, state["first"]["local"]["attempt"]["run_id"], case)
        self.receipt["boundary_pair"] = state

def boundary_projection(raw, selection, inventories, *, desktop=False, expected_fixture=None):
    """Fixed pair only; generic Gate qualification and all other gates remain separate."""
    from worker_host import _terminal
    from worker_host_persistent import retirement, original_local_audit
    from nm2_worker_hosted import _launch_retention, _launch_row, _requests
    require(raw["scenario"] == SCENARIO and raw["acceptance_scope"] == "fixed_orphan_drain_and_bounded_load_only"
            and raw["status"] == "selected_boundary_pair_passed" and raw["stage"] == "selected_boundary_pair_complete"
            and raw["sources"] == selection["sources"] and all(selection["sources"][name]["commit"] == commit for name,commit in BOUNDARY_SOURCES.items()) and raw["images"] == selection["images"]
            and raw["project"] == selection["project"] and raw["nm2_exit_status"] == "incomplete"
            and raw["platform"] == ("win32" if desktop else "linux") and raw["retained"] is True
            and raw["expected_database_revision"] == "0041persistentruntime", "boundary_scope_refused")
    document = raw["fixture_qualification_document"].encode("utf-8")
    require(digest(document) == raw["fixture_qualification_sha256"] and json.loads(document) == raw["fixture_image"], "boundary_fixture_image_refused")
    fixture = fixture_binding(document,selection,desktop=desktop,expected_fixture=expected_fixture)
    measured = raw["image_sources"]["runner"]
    require(measured["image_id"] == selection["images"]["worker"] and measured["python_file_count"] == 80
            and measured["executables"] == {"/usr/local/bin/vardr-worker-owner":fixture["owner_sha256"],"/usr/local/bin/vardrgate":fixture["wrapper_sha256"]}
            and (fixture["source_recipe"] is None or measured["python_inventory_sha256"] == fixture["source_recipe"]["sdk_inventory_sha256"]), "boundary_fixture_image_refused")
    state = raw["boundary_pair"]; first, second, physical = state["first"], state["second"], state["physical"]
    require(set(state) == {"first","second","admission","physical","retirement","audit","traffic","reconciliation","host_reconciled"}, "boundary_scope_refused")
    launch = raw["launch"]; _launch_row(launch,1)
    require(launch["container_id"] == physical["identity"]["container_id"]
            and launch["runtime_id"] == state["admission"]["runtime_id"] == physical["runtime_id"]
            and launch["finished_at"] == physical["finished_at"] and physical["exit_code"] == 125
            and physical["operator_stop_state"] == "not_requested", "boundary_physical_refused")
    records, delegations = [], {}
    for index, part in enumerate((first,second)):
        mode = MODES[index]; case = part["case"]; original = part["original"]
        require(canonical(case[2]["spec"]) == canonical(fixed_case(mode)) and original["run_id"] == (part["local"]["attempt"]["run_id"] if index == 0 else part["run_id"])
                and original["engagement_id"] == case[0] and original["job_id"] == case[1], "boundary_original_run_refused")
        require(all(type(f["size"]) is int and 0 < f["size"] <= 1024*1024 and re.fullmatch("[a-f0-9]{64}",f["sha256"]) for f in original["files"]), "boundary_file_metadata_refused")
        rows = fixed_records(original["records"],mode,physical); records.append(rows)
        review = part["review"]; expected = EXECUTION
        require(review["input"]["plan"]["execution"] == expected
                and review["input"]["plan"]["case_hash"] == digest(canonical(case[2]["spec"]))
                and review["input"]["plan"]["tool_sha256"] == fixture["wrapper_sha256"]
                and review["context"]["job_id"] == case[1] and review["context"]["engagement_id"] == case[0]
                and review["context"]["plan_sha256"] == digest(canonical(review["input"]["plan"]))
                and original["claim"]["plan_sha256"] == review["context"]["plan_sha256"]
                and original["claim"]["case_sha256"] == digest(canonical(case[2]["spec"]))
                and original["claim"]["tool_sha256"] == fixture["wrapper_sha256"]
                and review["context"]["max_duration_seconds"] == 30, "boundary_authority_refused")
        delegations[mode] = guard_joins(original, mode, review["input"]["plan"], original["claim"]["plan_sha256"], fixture)
        requests = state["traffic"][index*5:index*5+5]
        require(_requests(requests) == mode[4:], "boundary_traffic_refused")
        require(all((rows["leaf","ready"] if index else rows["wrapper","begin"])["utc_ns"] <= r["received_utc_ns"] <= rows["wrapper","gate-return"]["utc_ns"] for r in requests), "boundary_traffic_time_refused")
    require(len(state["traffic"]) == 10 and first["local"]["last_sequence"] == "1"
            and first["local"]["active_sequence"] is None and first["local"]["remaining_local_holds"] == 0
            and first["local"]["attempt"]["state"] == "released"
            and first["local"]["attempt"]["native_done_sha256"] is not None, "boundary_drain_refused")
    a_attempt = first["inventory"]["runtimes"][0]["attempts"][0]
    a_terminal = _terminal(a_attempt["binding"],a_attempt["terminal_receipt"])
    a_result = first["inventory"]["results"][0]
    require(a_terminal["schema"] == "vardr.managed-completion/1" and a_terminal["outcome"] == "completed"
            and a_terminal["receipt_sha256"] == digest(canonical({"schema":"vardr.managed-result/1",**a_attempt["binding"],
                "artifact_sha256":a_result["artifact_sha256"],"case_sha256":digest(canonical(first["case"][2]["spec"]))}))
            and first["original"]["files"] == [{"name":"vardrgate_result.json","size":first["original"]["files"][0]["size"],"sha256":a_result["artifact_sha256"]}]
            and first["original"]["artifact_sha256"] == a_result["artifact_sha256"]
            and first["local"]["attempt"]["release"] == a_attempt["release_receipt"] and first["local"]["attempt"]["native_done_sha256"] == a_attempt["native_done_sha256"] == first["original"]["attempt"]["native_done_sha256"]
            and stamp(a_attempt["released_at"]) > records[0]["leaf","exit"]["utc_ns"]
            and stamp(second["original"]["claim"]["utc_anchor"]) > stamp(a_attempt["released_at"]), "boundary_drain_refused")
    a_release = a_attempt["release_receipt"]
    require(canonical(a_release) == canonical({"schema":"vardr.worker-idle-release/2","runtime_id":physical["runtime_id"],"runtime_sha256":physical["runtime_sha256"],"admission_sha256":physical["admission_sha256"],"runtime_sequence":"1","binding":a_attempt["binding"],"terminal_receipt_sha256":digest(canonical(a_terminal)),"native_done_sha256":a_attempt["native_done_sha256"],"released":True,"receipt_sha256":digest(canonical({k:v for k,v in a_release.items() if k != "receipt_sha256"}))}), "boundary_release_refused")
    require(second["case"][3]["job_status"] == "pending" and second["case"][3]["contracts"] == second["case"][3]["approvals"] == [] and second["case"][3]["targets_spent"] == second["case"][3]["duration_allocated"] == 0, "boundary_unapproved_queue_refused")
    before, after = second["before"], second["after"]
    runtime = before["runtimes"][0]; attempt = runtime["attempts"][1]
    require(runtime["last_sequence"] == runtime["head_sequence"] == runtime["active_sequence"] == "2" and len(runtime["attempts"]) == 2 and runtime["retired"] is False and runtime["new_work_disabled"] is False and runtime["report_sha256"] is None
            and attempt["binding"]["job_id"] == second["case"][1]
            and canonical(runtime["attempts"][0]) == canonical(first["inventory"]["runtimes"][0]["attempts"][0])
            and all(attempt[k] is None for k in ("released_at","terminal_receipt","native_done_sha256","release_receipt"))
            and before["job_status"] == "running" and canonical(before["execution"]) == b'{"capacity_reserved":true,"duration_seconds":30,"state":"active","target_charge":1}' and before["results"] == before["stops"] == [] and before["capacity_reserved_count"] == 1
            and canonical([before["capacity_reserved_count"],before["targets_spent"],before["duration_allocated"]]) == b"[1,1,30]", "boundary_original_held_refused")
    local = second["original"]
    require(local["phase"] == "executing" and local["artifact_sha256"] is None and local["local_stop_requested"] is False
            and local["claim"]["state"] in {"consume_acknowledged","held_after_claim"}
            and canonical([local["claim"]["consumption_sent"],local["claim"]["consumption_acknowledged"]]) == b"[1,1]"
            and local["attempt"]["state"] == "bound" and local["attempt"]["binding"] == {**attempt["binding"],**{k:runtime[k] for k in ("runtime_sha256","admission_sha256")},"runtime_id":runtime["id"],"runtime_sequence":"2"}
            and all(local["attempt"][k] is None for k in ("completion","native_done_sha256","release_intent","release_ack")), "boundary_native_hold_refused")
    begin = records[1]["wrapper","begin"]; ready = records[1]["leaf","ready"]
    duration = min(second["review"]["input"]["plan"]["execution"]["timeout_seconds"],
                   before["execution"]["duration_seconds"], second["review"]["context"]["max_duration_seconds"])
    end = min(stamp(local["claim"]["utc_anchor"])+duration*NS,
        *(stamp(second["review"]["context"][k]) for k in ("expires_at","testing_end")),
        *(stamp(g["expires_at"]) for g in second["review"]["context"]["credential_grants"]))
    lower = min(end, stamp(local["started_at"])+duration*NS)-NS
    require(stamp(a_attempt["released_at"]) < stamp(local["started_at"]) <= stamp(local["claim"]["utc_anchor"]) <= begin["utc_ns"]
            and ready["utc_ns"] < end and all(r["received_utc_ns"] < end for r in state["traffic"][5:])
            and lower < stamp(physical["finished_at"]) < begin["utc_ns"]+35*NS,
            "boundary_cap_unobserved")
    require(len(local["files"]) == 1 and local["files"][0]["name"] == "vardrgate_result.json" and second["retained"]["artifact_sha256"] is None and second["retained"]["attempt"]["state"] == "physical_retirement_observed" and second["retained"]["attempt"]["retired_from_state"] == "bound" and all(second["retained"]["attempt"][k] is None for k in ("completion","native_done_sha256","release_intent","release_ack")), "boundary_artifact_promotion_refused")
    require(second["retained"]["files"] == local["files"] and second["retained"]["records"] == local["records"] and second["retained"]["guards"] == local["guards"]
            and all(first["retained"][k] == first["original"][k] for k in ("files","records","guards")), "boundary_retained_bytes_changed")
    original = state["admission"]; require(original == runtime["admission"] and runtime["identity"] == physical["identity"] and all(physical[k] == original[k] == runtime[k if k != "runtime_id" else "id"] for k in ("runtime_id","runtime_sha256","admission_sha256")), "boundary_runtime_binding_refused")
    record = dict(runtime_id=original["runtime_id"],admission=original,registration={k:v for k,v in original.items() if k not in {"schema","runtime_id","runtime_sha256","admission_sha256"}},registration_state="acknowledged",stop_state="observed",receipt=state["retirement"],revocation_state="none",disable_state="none")
    retained = retirement(record,state["retirement"]); terminal = _terminal(attempt["binding"],retained["attempt_receipt"])
    require(retained["last_sequence"] == retained["runtime_sequence"] == "2" and terminal["cause"] == "observed_exit" and terminal["outcome"] == "failed"
            and retained["receipt_sha256"] == launch["retirement_sha256"], "boundary_retirement_refused")
    require(canonical(after) == canonical({**before,"job_status":"failed","capacity_reserved_count":0,
        "execution":{**before["execution"],"state":"failed","capacity_reserved":False},
        "runtimes":[{**runtime,"retired":True,"report_sha256":retained["report_sha256"],"new_work_disabled":True}],
        "stops":[{k:terminal[k] for k in ("contract_id","receipt_sha256","outcome","cause")}]}), "boundary_history_changed")
    host = state["host_reconciled"]
    require(host["schema"] == "vardr.worker-cli/1" and host["state"] == "terminal_observed"
            and host["runtime_id"] == original["runtime_id"] and host["receipt"]["retirement"] == retained, "boundary_host_receipt_refused")
    original_local_audit(record,host["receipt"],output=canonical(state["audit"]),returncode=0)
    reconciled = state["reconciliation"]
    require(reconciled["schema"] == "vardr.worker-reconciliation/1" and reconciled["status"] == "reconciled"
            and reconciled["complete"] is True and reconciled["reason"] is None and reconciled["binding"] == state["audit"]["binding"]
            and reconciled["selected_run_id"] == second["run_id"] and reconciled["selected_sequence"] == "2"
            and reconciled["reconciliation_state"] == "terminal_host_exit_observed"
            and type(reconciled["remaining_local_holds"]) is int and reconciled["remaining_local_holds"] == 0
            and reconciled["retirement_receipt_sha256"] == retained["receipt_sha256"], "boundary_reconciliation_refused")
    require(state["audit"]["parent"] == {"state":"retired","last_sequence":"2","head_sequence":"2","active_sequence":None}
            and state["audit"]["counts"] == dict.fromkeys(("attempts","selections","associated_runs","associated_claims"),2)
            and state["audit"]["global_holds"] == 0 and state["audit"]["retirement_receipt_sha256"] == retained["receipt_sha256"], "boundary_audit_refused")
    owned,admitted = _launch_retention(raw,selection,(launch,),inventories,desktop=desktop)
    return dict(schema=HOSTED,scope="fixed_orphan_drain_and_bounded_load_only",ordinary_orphan_drain=True,guard_delegation=delegations,
        fixture_image_binding={**fixture,"qualification_sha256":digest(document)},
        bounded_load_observed=True,load_observation=dict(plan_seconds=second["review"]["input"]["plan"]["execution"]["timeout_seconds"],
            allocation_seconds=before["execution"]["duration_seconds"],permission_seconds=second["review"]["context"]["max_duration_seconds"],
            cap_utc_ns=end,physical_exit_utc_ns=stamp(physical["finished_at"]),
            exit_minus_cap_ns=stamp(physical["finished_at"])-end,independent_ceiling_seconds=35),
        owned_stopped_container_count=owned,empty_builtin_bridge_id_change_count=admitted,
        resources_retained=True,nm2_exit_status="incomplete",credential_isolation="shared_uid_assumption",suspend="not_observed",
        renewal_precision="exact_last_native_lease_memory_only",cap="original_anchor_permission_allocation_plan_upper_cap",failure_window="source_earlier_run_start_min_plan_allocation_permission_minus1s_floor_bound",native_exit_trigger="not_attributed")


def main(argv=None):
    """Explicit two-job fixture only; no original launch CLI or default changes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", required=True, type=Path)
    parser.add_argument("--compose-executable", required=True, type=Path)
    parser.add_argument("--compose-sha256", required=True)
    parser.add_argument("--docker-config", required=True, type=Path)
    parser.add_argument("--qualification", required=True, type=Path)
    parser.add_argument("--qualification-sha256", required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print("Fixed boundary pair requires explicit --execute; no commands run")
        return 2
    try:
        selection = manifest(args.cohort); data = args.qualification.read_bytes()
        require(0 < len(data) <= 65536 and digest(data) == args.qualification_sha256, "boundary_fixture_image_refused")
        expected = None
        if sys.platform == "linux":
            from nm2_worker_boundary_build import binding_for_qualification
            q = json.loads(data)
            expected = data,binding_for_qualification(q,{n:v["commit"] for n,v in selection["sources"].items()},q["source_recipe"]["source_trees"])
        fixture = BoundaryFixture(selection,qualification=data,qualification_sha256=args.qualification_sha256,expected_fixture=expected,
            compose=args.compose_executable,compose_sha256=args.compose_sha256,docker_config=args.docker_config)
        fixture.run()
        return 0 if fixture.receipt["status"] == "selected_boundary_pair_passed" else 1
    except Exception:
        print("Fixed boundary pair held; retain owned resources.",file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
