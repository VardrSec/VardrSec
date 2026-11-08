"""Synthetic original-claim response loss; all transport/process calls are mocked."""

from copy import deepcopy
import ast
from itertools import product
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import nm2_worker_hosted as hosted
import nm2_worker_launch_acceptance as local
from nm2_worker_acceptance import AcceptanceRefused, canonical, digest
import test_nm2_worker_stopped_predecessor_hosted as retained
from worker_runtime import RuntimeIdentity


SCENARIO = local.CLAIM_REPLY_LOSS_SCENARIO
OPERATIONS = ("claim", "consume", "runtime-bind")
JOB, RUN, ENGAGEMENT, RUNNER, APPROVAL, CONTRACT, ATTEMPT, ENROLLMENT = (
    f"00000000-0000-4000-8000-{index:012d}" for index in range(1, 9)
)
RUN = "0123456789abcdef0123456789abcdef"
APPROVAL = "nm2-fixture-synthetic:" + APPROVAL
PROXY_CID = "3" * 64
PROXY_OLD, PROXY_ARMED = (
    "2026-11-07T00:55:00.000000001Z",
    "2026-11-07T00:56:00.000000001Z",
)


def evidence(*, desktop=False, operation="claim"):
    raw, selected, (before, after) = (
        retained.desktop_evidence() if desktop else retained.evidence()
    )
    launch, unused = raw.pop("launch_pair")
    raw.pop("stopped_predecessor")
    selected["https_port"] = 28443
    sources = (
        local.CLAIM_REPLY_LOSS_SOURCES
        if operation == "claim"
        else local.POST_CLAIM_REPLY_LOSS_SOURCES
    )
    for name, commit in sources.items():
        selected["sources"][name]["commit"] = commit
    del after["containers"][unused["container_id"]]
    del after["volumes"][f"{selected['project']}_worker-ready-{unused['runtime_id']}"]
    raw["fixture_stop"]["container_ids"].remove(unused["container_id"])
    identity = dict(
        daemon_id="synthetic-daemon",
        container_id=launch["container_id"],
        image_id=selected["images"]["worker"],
        project=selected["project"],
        started_at=launch["started_at"],
        owner_nonce="e" * 64,
    )
    binding = dict(
        runner_id=RUNNER,
        runtime_id=launch["runtime_id"],
        runtime_sha256=digest(canonical(identity)),
        admission_sha256="a" * 64,
    )
    original = dict(
        origin=f"https://vardrsec.localhost:{selected['https_port']}/backend",
        runner_id=RUNNER,
        job_id=JOB,
        contract_id=CONTRACT,
        attempt_id=ATTEMPT,
        fence=1,
        contract_sha256="c" * 64,
    )
    initial = dict(
        schema="vardr.nm2-fixture-inventory/3",
        schema_revision="0041persistentruntime",
        database_user="synthetic",
        engagement_id=ENGAGEMENT,
        job_id=JOB,
        runtime_attempt_bound=35,
        job_status="pending",
        targets_spent=0,
        duration_allocated=0,
        execution=None,
        approvals=[],
        contracts=[],
        results=[],
        stops=[],
        runtimes=[],
        capacity_reserved_count=0,
        concurrency_limit=None,
    )
    attempt = dict(
        runtime_id=binding["runtime_id"],
        runtime_sequence="1",
        runtime_mode="persistent",
        previous_sequence=None,
        job_id=JOB,
        binding=original,
        bound_at="2026-11-07T01:00:01.000000Z",
        confirmed_at=None,
        released_at=None,
        terminal_receipt=None,
        terminal_receipt_sha256=None,
        native_done_sha256=None,
        release_receipt=None,
    )
    runtime = dict(
        id=binding["runtime_id"],
        runner_id=RUNNER,
        enrollment_id=ENROLLMENT,
        runtime_sha256=binding["runtime_sha256"],
        admission_sha256=binding["admission_sha256"],
        identity=identity,
        max_attempts=None,
        mode="persistent",
        last_sequence="1",
        head_sequence="1",
        active_sequence="1",
        retired=False,
        new_work_disabled=False,
        reporting_revoked=False,
        report_sha256=None,
        admission={},
        legacy_binding={},
        attempts=[attempt],
    )
    admission = dict(
        schema="vardr.worker-admission/3",
        runtime_id=binding["runtime_id"],
        runtime_sha256=binding["runtime_sha256"],
        enrollment_id=ENROLLMENT,
        runner_id=RUNNER,
        origin=original["origin"],
        capability_sha256="d" * 64,
        identity=identity,
        mode="persistent",
        limits={"max_attempts": None, "idle_timeout_seconds": None},
        reporting_authority={"purpose": "worker-stop-only", "expires_at": None},
    )
    admission["admission_sha256"] = digest(canonical(admission))
    binding["admission_sha256"] = runtime["admission_sha256"] = admission[
        "admission_sha256"
    ]
    runtime["admission"] = admission
    runtime["legacy_binding"] = dict.fromkeys(
        (
            "job_id",
            "contract_id",
            "attempt_id",
            "fence",
            "contract_sha256",
            "bound_at",
            "confirmed_at",
        )
    )
    committed = {
        **initial,
        "job_status": "running",
        "targets_spent": 1,
        "duration_allocated": 30,
        "capacity_reserved_count": 1,
        "execution": dict(
            state="active", capacity_reserved=True, target_charge=1, duration_seconds=30
        ),
        "contracts": [
            dict(
                id=CONTRACT,
                attempt_id=ATTEMPT,
                ordinal=1,
                fence=1,
                consumed=False,
                contract_sha256=original["contract_sha256"],
            )
        ],
        "approvals": [dict(id=APPROVAL, issued=1, revoked=False)],
        "runtimes": [runtime],
    }
    terminal = dict(
        schema="vardr.managed-stop-receipt/1",
        **original,
        outcome="failed",
        cause="observed_exit",
        capacity_reserved=False,
    )
    terminal["receipt_sha256"] = digest(
        canonical(
            dict(
                schema="vardr.managed-stop/1",
                **original,
                outcome="failed",
                cause="observed_exit",
                termination_confirmed=True,
            )
        )
    )
    retired = dict(
        schema="vardr.worker-retirement/3",
        **binding,
        origin=original["origin"],
        enrollment_id=ENROLLMENT,
        runtime_sequence="1",
        last_sequence="1",
        binding=original,
        attempt_receipt=terminal,
        report_sha256="b" * 64,
        retired=True,
    )
    retired["receipt_sha256"] = digest(canonical(retired))
    launch["retirement_sha256"] = retired["receipt_sha256"]
    audit = dict(
        schema="vardr.worker-state-audit/1",
        status="held",
        reason="local_holds",
        complete=True,
        binding=binding,
        parent=dict(
            state="idle", last_sequence="0", head_sequence=None, active_sequence=None
        ),
        counts=dict(attempts=0, selections=1, associated_runs=1, associated_claims=1),
        retirement_receipt_sha256=None,
        global_holds=2,
    )
    final_audit = {
        **audit,
        "status": "retired",
        "reason": None,
        "global_holds": 0,
        "parent": {**audit["parent"], "state": "retired"},
        "retirement_receipt_sha256": retired["receipt_sha256"],
    }
    run = dict(
        run_id=RUN,
        job_id=JOB,
        engagement_id=ENGAGEMENT,
        phase="claiming",
        status="claim_unknown",
        pid=None,
        artifact_sha256=None,
    )
    metadata = dict(
        run_id=RUN,
        job_id=JOB,
        engagement_id=ENGAGEMENT,
        phase="claiming",
        status="claim_unknown",
        claim_state="claim_unknown",
        consumption_sent=0,
        consumption_acknowledged=0,
        partial_files=[],
        partial_result=None,
    )
    after_map = {
        **committed,
        "job_status": "failed",
        "capacity_reserved_count": 0,
        "execution": {
            **committed["execution"],
            "state": "failed",
            "capacity_reserved": False,
        },
        "runtimes": [
            {
                **runtime,
                "retired": True,
                "new_work_disabled": True,
                "report_sha256": retired["report_sha256"],
            }
        ],
        "stops": [
            {
                key: terminal[key]
                for key in ("contract_id", "receipt_sha256", "outcome", "cause")
            }
        ],
    }
    mounts = [
        dict(
            Type="bind",
            Destination="/etc/caddy/Caddyfile",
            Source="/private/Caddyfile",
            RW=False,
        ),
        dict(
            Type="volume",
            Destination="/data",
            Name=selected["project"] + "_proxy-data",
            RW=True,
        ),
        dict(
            Type="volume",
            Destination="/config",
            Name=selected["project"] + "_proxy-config",
            RW=True,
        ),
    ]
    mounts.sort(key=lambda row: row["Destination"])
    labels = {
        "com.docker.compose.project": selected["project"],
        "com.docker.compose.service": "proxy",
        "com.docker.compose.oneoff": "False",
    }
    proxy = dict(
        id=PROXY_CID,
        image=selected["images"]["proxy"],
        labels=labels,
        state=dict(
            Status="running",
            Running=True,
            Health={"Status": "healthy"},
            StartedAt=PROXY_OLD,
            Paused=False,
            Restarting=False,
            Dead=False,
            OOMKilled=False,
        ),
        restarts=0,
        mounts=mounts,
        profile={"synthetic_profile": "unchanged"},
    )
    armed = {**proxy, "state": {**proxy["state"], "StartedAt": PROXY_ARMED}}
    after["containers"][PROXY_CID].update(labels=labels, mounts=mounts)
    after["containers"][PROXY_CID]["state"]["started_at"] = PROXY_ARMED
    config = (hosted.SOURCE / "Caddyfile").read_bytes()
    proxy_binding = dict(
        before=proxy,
        armed=armed,
        base_config_sha256=digest(config),
        config_sha256=digest(local.claim_reply_loss_config(config, JOB)),
        adapter_sha256="f" * 64,
        ca_sha256="e" * 64,
        caddy_version="v2.11.7",
        ready_http_status=200,
        web_http_status=200,
    )
    proof = dict(
        job_id=JOB,
        run_id=RUN,
        approval_record_id=APPROVAL,
        initial=initial,
        committed=committed,
        after=after_map,
        local_unknown=dict(run=run, metadata=metadata, audit=audit),
        proxy=proxy_binding,
        target_requests=0,
        retirement=retired,
        audit=final_audit,
        reconciliation=dict(
            schema="vardr.worker-reconciliation/1",
            status="reconciled",
            reason=None,
            complete=True,
            binding=binding,
            selected_run_id=RUN,
            selected_sequence="1",
            reconciliation_state="terminal_host_exit_observed",
            remaining_local_holds=0,
            retirement_receipt_sha256=retired["receipt_sha256"],
        ),
        physical=dict(
            identity=identity,
            **{
                key: binding[key]
                for key in ("runtime_id", "runtime_sha256", "admission_sha256")
            },
            finished_at=launch["finished_at"],
            exit_code=125,
            operator_stop_state="not_requested",
        ),
        audit_sha256=digest(canonical(final_audit)),
        retirement_sha256=retired["receipt_sha256"],
        host_retirement_sha256=digest(canonical(retired)),
        terminal_sha256=digest(canonical(terminal)),
        terminal_cause="observed_exit",
        capacity_before=1,
        capacity_after=0,
        targets_spent=1,
        duration_allocated=30,
        remaining_local_holds=0,
    )
    if operation != "claim":
        committed["contracts"][0]["consumed"] = True
        attempt["confirmed_at"] = (
            "2026-11-07T01:00:02.000000Z" if operation == "runtime-bind" else None
        )
        for row in (run, metadata):
            row.update(phase="executing", status="held_after_claim")
        metadata.update(claim_state="held_after_claim", consumption_sent=1)
        audit["parent"].update(
            state="active", last_sequence="1", head_sequence="1", active_sequence="1"
        )
        final_audit["parent"].update(last_sequence="1", head_sequence="1")
        audit["counts"]["attempts"] = 1
        proof["audit_sha256"] = digest(canonical(final_audit))
        proxy_binding["config_sha256"] = digest(
            local.claim_reply_loss_config(config, JOB, operation=operation)
        )
    scenario = next(
        name
        for name, value in hosted.REPLY_LOSS_OPERATIONS.items()
        if value == operation
    )
    slug = operation.replace("-", "_")
    raw.update(
        sources=selected["sources"],
        scenario=scenario,
        acceptance_scope=hosted.LAUNCH_SCOPES[scenario],
        status="selected_" + slug + "_reply_loss_slice_passed",
        stage="selected_" + slug + "_reply_loss_complete",
        launch=launch,
        claim_reply_loss=proof,
        after_sha256=digest(canonical(after)),
    )
    return raw, selected, (before, after)


class ClaimReplyLossHostedTests(unittest.TestCase):
    def test_explicit_route_requires_all_new_sources_and_preserves_default(self):
        for operation in OPERATIONS:
            env = {
                "NM2_SCENARIO": next(
                    name
                    for name, value in hosted.REPLY_LOSS_OPERATIONS.items()
                    if value == operation
                ),
                "NM2_DATABASE_REVISION": "0041persistentruntime",
                **{
                    "NM2_" + name.upper() + "_SHA": sha
                    for name, sha in (
                        local.CLAIM_REPLY_LOSS_SOURCES
                        if operation == "claim"
                        else local.POST_CLAIM_REPLY_LOSS_SOURCES
                    ).items()
                },
            }
            self.assertEqual(
                hosted.execution_options(env),
                (env["NM2_SCENARIO"], "0041persistentruntime"),
            )
            self.assertEqual(
                hosted.execution_options({}), ("healthy", "0040runtimesequence")
            )
            self.assertEqual(hosted.CLAIM_REPLY_LOSS_HOSTED, "vardr.nm2-hosted/18")
            for key in (
                "NM2_MAP_SHA",
                "NM2_RUNNER_SHA",
                "NM2_GATE_SHA",
                "NM2_DATABASE_REVISION",
            ):
                with self.subTest(key=key), self.assertRaises(hosted.HostedRefused):
                    hosted.execution_options({**env, key: "0" * 40})
            with patch.object(local, "LaunchFixture") as fixture:
                self.assertEqual(
                    local.main(
                        [
                            "--cohort",
                            "unused",
                            "--compose-executable",
                            "unused-compose",
                            "--compose-sha256",
                            "0" * 64,
                            "--docker-config",
                            "unused-config",
                            "--" + operation + "-reply-loss",
                        ]
                    ),
                    2,
                )
            fixture.assert_not_called()
            tree = ast.parse(Path(local.__file__).read_text(encoding="utf-8"))
            method = next(
                node
                for cls in tree.body
                if isinstance(cls, ast.ClassDef) and cls.name == "LaunchFixture"
                for node in cls.body
                if isinstance(node, ast.FunctionDef) and node.name == "launch_pair"
            )
            call = next(
                node.value
                for node in ast.walk(method)
                if isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == "before"
                    for target in node.targets
                )
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Attribute)
                and node.value.func.attr == "inventory"
            )
            for flag in (False, True):
                owner = SimpleNamespace(claim_reply_loss=flag, inventory=Mock())
                eval(
                    compile(ast.Expression(call), local.__file__, "eval"),
                    {"self": owner, "engagement": ENGAGEMENT, "job": JOB},
                )
                owner.inventory.assert_called_once_with(
                    ENGAGEMENT, JOB, **({"include_capacity": True} if flag else {})
                )

    def test_proxy_config_exact_post_success_abort_preserves_other_routes_and_tls(self):
        for operation in OPERATIONS:
            original = (hosted.SOURCE / "Caddyfile").read_bytes()
            rendered = local.claim_reply_loss_config(
                original, JOB, operation=operation
            ).decode()
            self.assertIn("admin off", rendered)
            self.assertIn("tls internal", rendered)
            self.assertIn("reverse_proxy web:3000", rendered)
            self.assertIn(
                "method POST\n        path /jobs/" + JOB + "/managed/" + operation,
                rendered,
            )
            self.assertEqual(rendered.count("@committed status 200"), 1)
            self.assertEqual(rendered.count("abort"), 1)
            self.assertNotIn("log ", rendered)
            for job in ("x\nabort", "../other", "x*", "", "/jobs/x"):
                with self.subTest(job=job), self.assertRaises(AcceptanceRefused):
                    local.claim_reply_loss_config(original, job)
            with self.assertRaises(AcceptanceRefused):
                local.claim_reply_loss_config(b"unknown source", JOB)

    def test_reader_joins_positive_commit_original_unknown_and_retirement_on_both_platforms(
        self,
    ):
        for desktop, operation in product((False, True), OPERATIONS):
            raw, selected, inventory = evidence(desktop=desktop, operation=operation)
            result = (
                hosted.claim_reply_loss_desktop_projection(
                    raw, selected, inventories=inventory
                )
                if desktop
                else hosted.public_projection(raw, selected, inventories=inventory)
            )
            proof = result[operation.replace("-", "_") + "_reply_loss"]
            self.assertEqual(proof["map_issued_sequence"], "1")
            self.assertEqual(
                proof["local_last_sequence"], str(int(operation != "claim"))
            )
            self.assertEqual(
                (proof["capacity_before"], proof["capacity_after"]), (1, 0)
            )
            self.assertEqual(proof["owned_stopped_container_count"], 6)
            self.assertEqual(
                (
                    proof["consumed"],
                    proof["runtime_bind_confirmed"],
                    proof["operator_stop_requested"],
                ),
                (operation != "claim", operation == "runtime-bind", False),
            )
            for private in (
                JOB,
                RUN,
                ENGAGEMENT,
                RUNNER,
                PROXY_CID,
                "/private/",
                raw["launch"]["container_id"],
            ):
                self.assertNotIn(private.encode(), canonical(result))

    def test_reader_refuses_missing_commit_consumption_bind_or_capacity_release(self):
        for operation, change in product(
            OPERATIONS,
            (
                "no_contract",
                "consumed",
                "confirmed",
                "capacity",
                "target",
                "local_ack",
                "local_attempt",
                "disabled_after_report",
            ),
        ):
            raw, selected, inventory = evidence(operation=operation)
            proof = raw["claim_reply_loss"]
            if change == "no_contract":
                proof["committed"]["contracts"] = []
            elif change == "consumed":
                proof["committed"]["contracts"][0]["consumed"] = operation == "claim"
            elif change == "confirmed":
                proof["committed"]["runtimes"][0]["attempts"][0]["confirmed_at"] = (
                    None
                    if operation == "runtime-bind"
                    else "2026-11-07T01:00:02.000000Z"
                )
            elif change == "capacity":
                proof["committed"]["capacity_reserved_count"] = 0
            elif change == "target":
                proof["target_requests"] = 1
            elif change == "local_ack":
                proof["local_unknown"]["metadata"]["consumption_acknowledged"] = 1
            elif change == "disabled_after_report":
                proof["after"]["runtimes"][0]["new_work_disabled"] = False
            else:
                proof["audit"]["counts"]["attempts"] = int(operation == "claim")
            with self.subTest(change=change), self.assertRaises(hosted.HostedRefused):
                hosted.public_projection(raw, selected, inventories=inventory)

    def test_reader_refuses_foreign_original_recovery_or_rehashed_joins(self):
        for operation, change in product(
            OPERATIONS,
            (
                "run",
                "job",
                "sequence",
                "receipt",
                "source",
                "terminal",
                "audit_extra",
                "reconciliation_extra",
                "retirement_extra",
                "final_reason",
                "run_format",
                "approval_binding",
            ),
        ):
            raw, selected, inventory = evidence(operation=operation)
            proof = raw["claim_reply_loss"]
            if change == "run":
                proof["reconciliation"]["selected_run_id"] = ENGAGEMENT
            elif change == "job":
                proof["local_unknown"]["run"]["job_id"] = ENGAGEMENT
            elif change == "sequence":
                proof["retirement"]["last_sequence"] = "2"
            elif change == "receipt":
                proof["retirement"]["report_sha256"] = "d" * 64
            elif change == "source":
                selected["sources"]["runner"]["commit"] = "0" * 40
            elif change == "audit_extra":
                proof["audit"]["unknown"] = "private-canary"
                proof["audit_sha256"] = digest(canonical(proof["audit"]))
            elif change == "reconciliation_extra":
                proof["reconciliation"]["unknown"] = "private-canary"
            elif change == "retirement_extra":
                proof["retirement"]["unknown"] = "private-canary"
                receipt = digest(
                    canonical(
                        {
                            key: value
                            for key, value in proof["retirement"].items()
                            if key != "receipt_sha256"
                        }
                    )
                )
                proof["retirement"]["receipt_sha256"] = raw["launch"][
                    "retirement_sha256"
                ] = receipt
                proof["retirement_sha256"] = receipt
                proof["audit"]["retirement_receipt_sha256"] = receipt
                proof["reconciliation"]["retirement_receipt_sha256"] = receipt
                proof["host_retirement_sha256"] = digest(canonical(proof["retirement"]))
                proof["audit_sha256"] = digest(canonical(proof["audit"]))
            elif change == "final_reason":
                proof["audit"]["reason"] = "unexpected"
                proof["audit_sha256"] = digest(canonical(proof["audit"]))
            elif change == "run_format":
                proof["run_id"] = JOB
                proof["local_unknown"]["run"]["run_id"] = JOB
                proof["local_unknown"]["metadata"]["run_id"] = JOB
                proof["reconciliation"]["selected_run_id"] = JOB
            elif change == "approval_binding":
                proof["approval_record_id"] = "nm2-fixture-other:" + JOB
            else:
                proof["retirement"]["attempt_receipt"]["cause"] = "tool_timeout"
            with self.subTest(change=change), self.assertRaises(hosted.HostedRefused):
                hosted.public_projection(raw, selected, inventories=inventory)

    def test_reader_refuses_wrong_proxy_physical_identity_or_typed_values(self):
        for operation, change in product(
            OPERATIONS,
            (
                "proxy",
                "ca",
                "config",
                "exit_bool",
                "operator",
                "early_arm",
                "profile",
                "counts_bool",
            ),
        ):
            raw, selected, inventory = evidence(operation=operation)
            proof = raw["claim_reply_loss"]
            if change == "proxy":
                proof["proxy"]["armed"]["id"] = "8" * 64
            elif change == "ca":
                proof["proxy"]["ca_sha256"] = "unknown"
            elif change == "config":
                proof["proxy"]["config_sha256"] = digest(
                    local.claim_reply_loss_config(
                        (hosted.SOURCE / "Caddyfile").read_bytes(),
                        JOB,
                        operation="consume" if operation == "claim" else "claim",
                    )
                )
            elif change == "exit_bool":
                proof["physical"]["exit_code"] = True
            elif change == "operator":
                proof["physical"]["operator_stop_state"] = "requested"
            elif change == "early_arm":
                proof["proxy"]["armed"]["state"]["StartedAt"] = (
                    "2026-11-07T01:00:01.000000Z"
                )
            elif change == "profile":
                proof["proxy"]["armed"]["profile"] = {"changed": True}
            else:
                proof["targets_spent"] = True
            with self.subTest(change=change), self.assertRaises(hosted.HostedRefused):
                hosted.public_projection(raw, selected, inventories=inventory)

    def test_original_producer_requires_positive_committed_inventory_and_keeps_unknown(
        self,
    ):
        for operation in OPERATIONS:
            raw, _, _ = evidence(operation=operation)
            proof = raw["claim_reply_loss"]
            fixture = local.LaunchFixture.__new__(local.LaunchFixture)
            fixture.receipt, fixture.pending_approval = {}, {"synthetic_approval": True}
            fixture.reply_loss_operation = operation
            fixture.api = SimpleNamespace(
                request=Mock(return_value={"approval_record_id": APPROVAL})
            )
            fixture.traffic, fixture.persistent_idle = Mock(return_value=[]), Mock()
            fixture.inventory = Mock(return_value=deepcopy(proof["committed"]))
            fixture.helper = Mock(
                return_value=json.dumps([proof["local_unknown"]["run"]])
            )
            fixture.local_metadata = Mock(
                return_value=proof["local_unknown"]["metadata"]
            )
            fixture.worker_state = Mock(return_value=proof["local_unknown"]["audit"])
            identity = RuntimeIdentity(**proof["physical"]["identity"])
            physical = SimpleNamespace(
                identity=identity,
                exit_code=125,
                finished_at=proof["physical"]["finished_at"],
            )
            observer = SimpleNamespace(
                observe_exit=Mock(return_value=physical), confirm_exit=Mock()
            )
            runtime = proof["committed"]["runtimes"][0]
            admission = {
                **proof["local_unknown"]["audit"]["binding"],
                "origin": proof["retirement"]["origin"],
            }
            with TemporaryDirectory() as folder:
                fixture.install = Path(folder)
                (fixture.install / "Caddyfile").write_bytes(b"synthetic armed config")
                fixture.claim_loss_proxy_binding = {
                    "config_sha256": digest(b"synthetic armed config")
                }
                result = fixture.observe_claim_reply_loss(
                    observer,
                    identity,
                    admission,
                    (ENGAGEMENT, JOB, {}, proof["initial"]),
                )
                self.assertEqual(result[0], RUN)
                self.assertEqual(
                    fixture.receipt["claim_reply_loss"]["committed"], proof["committed"]
                )
                fixture.persistent_idle.assert_called_once_with(admission, 0)
                fixture.worker_state.assert_called_once_with(
                    admission,
                    expected_held="claim_unknown"
                    if operation == "claim"
                    else "issued_unknown",
                )
                self.assertEqual(fixture.api.request.call_count, 1)
                fixture.inventory.return_value = {**runtime, "job_status": "pending"}
                with self.assertRaises(AcceptanceRefused):
                    fixture.observe_claim_reply_loss(
                        observer,
                        identity,
                        admission,
                        (ENGAGEMENT, JOB, {}, proof["initial"]),
                    )

    def test_original_reconcile_keeps_parent_zero_without_local_attempt(self):
        for operation in OPERATIONS:
            raw, _, _ = evidence(operation=operation)
            proof = deepcopy(raw["claim_reply_loss"])
            fixture = local.LaunchFixture.__new__(local.LaunchFixture)
            fixture.receipt, fixture.claim_reply_loss = (
                {"claim_reply_loss": proof},
                True,
            )
            fixture.reply_loss_operation = operation
            fixture.inventory = Mock(return_value=proof["after"])
            fixture.helper = Mock(return_value=json.dumps(proof["reconciliation"]))
            fixture.worker_state = Mock(return_value=proof["audit"])
            admission = proof["audit"]["binding"]
            self.assertEqual(
                fixture.verify_host_exit_reconciliation(
                    admission,
                    proof["retirement"],
                    (ENGAGEMENT, JOB, {}, proof["initial"]),
                    RUN,
                    proof["committed"],
                    proof_key="claim_reply_loss",
                ),
                proof["audit"],
            )
            self.assertEqual(
                fixture.receipt["claim_reply_loss"]["reconciliation"],
                proof["reconciliation"],
            )
            fixture.worker_state.return_value = {
                **proof["audit"],
                "counts": {
                    **proof["audit"]["counts"],
                    "attempts": int(operation == "claim"),
                },
            }
            with self.assertRaises(AcceptanceRefused):
                fixture.verify_host_exit_reconciliation(
                    admission,
                    proof["retirement"],
                    (ENGAGEMENT, JOB, {}, proof["initial"]),
                    RUN,
                    proof["committed"],
                    proof_key="claim_reply_loss",
                )

    def arm_fixture(self, folder, *, wrong_ca=False, operation="claim"):
        raw, selected, _ = evidence(operation=operation)
        proxy = deepcopy(raw["claim_reply_loss"]["proxy"])
        fixture = local.LaunchFixture.__new__(local.LaunchFixture)
        fixture.install = Path(folder) / "install"
        fixture.install.mkdir()
        fixture.source = hosted.SOURCE
        fixture.docker_config = Path(folder) / "docker"
        fixture.project, fixture.images, fixture.m = (
            selected["project"],
            selected["images"],
            selected,
        )
        fixture.receipt = {}
        fixture.reply_loss_operation = operation
        target = fixture.install / "Caddyfile"
        target.write_bytes((hosted.SOURCE / "Caddyfile").read_bytes())
        (fixture.install / "trust").mkdir()
        (fixture.install / "trust/root.crt").write_bytes(b"synthetic public fixture CA")
        for item in (proxy["before"], proxy["armed"]):
            next(row for row in item["mounts"] if row["Type"] == "bind")["Source"] = (
                str(target)
            )
        stopped = {
            **proxy["before"],
            "state": {**proxy["before"]["state"], "Status": "exited", "Running": False},
        }
        fixture.claim_loss_proxy = Mock(
            side_effect=[proxy["before"], stopped, proxy["armed"]]
        )
        core = [
            dict(
                service="proxy",
                container_id=PROXY_CID,
                image_id=selected["images"]["proxy"],
            ),
            dict(
                service="api", container_id="2" * 64, image_id=selected["images"]["api"]
            ),
        ]
        initial = {"all_worker_ids": [], "core": core}
        armed = {"all_worker_ids": [], "core": [{**core[0], "armed": True}, core[1]]}
        observer = SimpleNamespace(
            daemon=Mock(return_value="synthetic-daemon"),
            capture_project_containers=Mock(return_value=armed),
        )
        calls = []

        def docker(*args, **kwargs):
            calls.append(args)
            if "cat" in args:
                return (
                    b"wrong public CA" if wrong_ca else b"synthetic public fixture CA"
                )
            if "version" in args:
                return b"v2.11.7\n"
            if "adapt" in args:
                return b'{"apps":{}}'
            if "curl" in args:
                return b"200"
            if "start" in args:
                self.assertEqual(
                    target.read_bytes(),
                    local.claim_reply_loss_config(
                        (hosted.SOURCE / "Caddyfile").read_bytes(), JOB, operation=operation
                    ),
                )
            return b""

        fixture.docker, fixture.api = (
            Mock(side_effect=docker),
            SimpleNamespace(request=Mock(return_value={"ready": True})),
        )
        return fixture, observer, initial, armed, calls

    def test_proxy_arms_before_worker_with_same_cid_mount_inode_ca_and_other_core(self):
        for operation in OPERATIONS:
            with TemporaryDirectory() as folder:
                fixture, observer, initial, armed, calls = self.arm_fixture(
                    folder, operation=operation
                )
                target = fixture.install / "Caddyfile"
                before = target.stat().st_dev, target.stat().st_ino
                self.assertEqual(
                    fixture.arm_claim_reply_loss(observer, initial, JOB), armed
                )
                self.assertEqual((target.stat().st_dev, target.stat().st_ino), before)
                effects = [args for args in calls if "container" in args]
                self.assertEqual([args[-1] for args in effects], [PROXY_CID, PROXY_CID])
                self.assertIn("stop", effects[0])
                self.assertIn("start", effects[1])
                self.assertEqual(
                    fixture.claim_loss_proxy_binding["ready_http_status"], 200
                )
                self.assertEqual(
                    fixture.claim_loss_proxy_binding["web_http_status"], 200
                )

    def test_wrong_ca_or_existing_worker_refuses_before_proxy_stop_or_registration(
        self,
    ):
        for wrong_ca in (False, True):
            with self.subTest(wrong_ca=wrong_ca), TemporaryDirectory() as folder:
                fixture, observer, initial, _, calls = self.arm_fixture(
                    folder, wrong_ca=wrong_ca
                )
                if not wrong_ca:
                    initial["all_worker_ids"] = ["6" * 64]
                with self.assertRaises(AcceptanceRefused):
                    fixture.arm_claim_reply_loss(observer, initial, JOB)
                self.assertFalse(
                    any("stop" in args or "start" in args for args in calls)
                )
                fixture.api.request.assert_not_called()
