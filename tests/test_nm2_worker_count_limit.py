"""Private count-control fixture/oracle vectors; no runtime acceptance credit."""

import copy
from datetime import datetime, timezone
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import Mock, patch

import nm2_worker_acceptance as acceptance
import nm2_worker_hosted as hosted
import test_nm2_persistent_availability as healthy
import test_nm2_worker_acceptance as finite
import test_nm2_worker_status_decode as status_vectors
from worker_host_persistent import _purpose


def vector():
    old = healthy.vector()
    admission = old.idle["admission"]
    previous = admission["admission_sha256"]
    admission["limits"] = acceptance.persistent_limits(acceptance.COUNT_SCENARIO)
    admission["admission_sha256"] = acceptance.digest(
        acceptance.canonical(
            {k: v for k, v in admission.items() if k != "admission_sha256"}
        )
    )

    def rewrite(value):
        if isinstance(value, dict):
            for key, item in value.items():
                value[key] = rewrite(item)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                value[i] = rewrite(item)
        elif value == previous:
            return admission["admission_sha256"]
        return value

    for value in (old.physical, old.runtime, old.measured):
        rewrite(value)
    measured = old.measured[0]
    measured["binding"] = old.runtime["attempts"][0]["binding"]
    release = measured["release_receipt"]
    release["receipt_sha256"] = acceptance.digest(
        acceptance.canonical(
            {k: v for k, v in release.items() if k != "receipt_sha256"}
        )
    )
    measured["release_receipt_sha256"] = release["receipt_sha256"]
    runtime = old.runtime
    runtime.update(
        max_attempts=1,
        last_sequence="1",
        head_sequence="1",
        attempts=runtime["attempts"][:1],
    )
    physical = old.physical
    physical.update(
        exit_code=0,
        operator_stop_state="not_requested",
        finished_at="2026-11-06T02:00:03Z",
    )
    report = {
        **{
            k: physical[k]
            for k in ("runtime_sha256", "admission_sha256", "finished_at", "exit_code")
        },
        "observation_sha256": acceptance.digest(
            acceptance.canonical(
                {k: physical[k] for k in ("identity", "finished_at", "exit_code")}
            )
        ),
        "last_sequence": "1",
    }
    runtime["report_sha256"] = _purpose({"runtime_id": physical["runtime_id"]}, report)
    issued = old.inventories[0]
    pending = dict(
        job_id="job-2",
        engagement_id="eng-2",
        job_status="pending",
        execution=None,
        contracts=[],
        results=[],
        stops=[],
        runtimes=[],
        targets_spent=0,
        duration_allocated=0,
        approvals=copy.deepcopy(old.inventories[1]["approvals"]),
    )
    pending["approvals"][0]["issued"] = 0
    eligibility = dict(
        observed_at="2026-11-06T02:00:04Z",
        context=dict(
            job_id="job-2",
            engagement_id="eng-2",
            runner_id=admission["runner_id"],
            expires_at=pending["approvals"][0]["expires_at"],
            max_executions=1,
            max_duration_seconds=30,
        ),
        authority_snapshot=dict(limits=dict(concurrency=1, targets=5, duration=120)),
    )
    grants = old.measured[1]["local"]["grants"]
    local = measured["local"]
    retirement = dict(
        schema="vardr.worker-retirement/3",
        **{
            k: admission[k]
            for k in (
                "runtime_id",
                "runtime_sha256",
                "admission_sha256",
                "origin",
                "runner_id",
                "enrollment_id",
            )
        },
        runtime_sequence=None,
        last_sequence="1",
        binding=None,
        attempt_receipt=None,
        report_sha256=runtime["report_sha256"],
        retired=True,
    )
    retirement["receipt_sha256"] = acceptance.digest(acceptance.canonical(retirement))
    retained = copy.deepcopy(local)
    retained.update(state="retired", retirement=retirement)
    retained["attempt"].update(
        state="physical_retirement_observed", retired_from_state="released"
    )
    # Exact public catalog/reference shapes; no credential values or stores.
    for number, snapshot in enumerate((local["grants"], grants), 1):
        for index, who in enumerate(("owner", "peer")):
            snapshot["grants"][index].update(
                issuer=admission["origin"],
                origin=acceptance.ORIGIN,
                source="env",
                name="FIXTURE_" + who.upper() + "_TOKEN",
                id=str(uuid.UUID(int=3000 + 2 * number + index)),
            )
    for inventory in (issued, pending):
        for index, who in enumerate(("owner", "peer")):
            inventory["approvals"][0]["credential_grants"][index].update(
                identity_id=who,
                source="value_env",
                name="FIXTURE_" + who.upper() + "_TOKEN",
                revision=1,
            )
    eligibility["authority_snapshot"].update(
        origin=admission["origin"],
        enrollment={
            "id": admission["enrollment_id"],
            "runner_id": admission["runner_id"],
        },
    )
    eligibility["context"].update(
        authority_revision=1,
        authority_sha256=acceptance.digest(
            acceptance.canonical(eligibility["authority_snapshot"])
        ),
        plan_sha256="a" * 64,
        mode="strict",
        exceptions=[],
        control="managed_online",
        scope=[
            {
                "origin": acceptance.ORIGIN,
                "path": "/fixed/records/42",
                "method": "GET",
                "excluded": False,
                "reason": "",
            }
        ],
        max_http_dispatches=5,
        max_artifact_bytes=1024 * 1024,
        not_before=eligibility["observed_at"],
        credential_grants=copy.deepcopy(pending["approvals"][0]["credential_grants"]),
    )
    eligibility["original_context"] = copy.deepcopy(eligibility["context"])
    eligibility["original_context"]["not_before"] = "2026-11-06T02:00:01Z"
    original_contexts = [
        {
            **copy.deepcopy(eligibility["original_context"]),
            "job_id": measured["job_id"],
            "engagement_id": measured["engagement_id"],
        },
        copy.deepcopy(eligibility["original_context"]),
    ]
    for inventory, context in zip((issued, pending), original_contexts, strict=True):
        inventory["schema"] = "vardr.nm2-fixture-inventory/4"
        inventory["approval_context_sha256"] = {
            inventory["approvals"][0]["id"]: acceptance.digest(
                acceptance.canonical(context)
            )
        }
    old.fixture.scenario = acceptance.COUNT_SCENARIO
    return SimpleNamespace(
        fixture=old.fixture,
        physical=physical,
        admission=admission,
        measured=measured,
        inventories=[issued, pending],
        local=local,
        retirement=retirement,
        retained=retained,
        eligibility=eligibility,
        grants=grants,
        original_contexts=original_contexts,
    )


def verify(data):
    return data.fixture.verify_count_limit(
        data.physical,
        data.admission,
        data.measured,
        data.inventories,
        data.local,
        data.retirement,
        data.retained,
        data.eligibility,
        data.grants,
        data.original_contexts,
    )


def orchestration_vector():
    from gate_acceptance import ORIGIN as reviewed_origin, reviewed_cases

    d = vector()
    f = d.fixture
    f.receipt = {"cases": {}}
    f.protocol = "persistent-v3"
    template = next(
        case["spec"] for case in reviewed_cases() if case["name"] == "fixed"
    )
    cases, plans = {}, {}
    for job, name in (("job-2", "count-a"), ("job-1", "count-b")):
        spec = copy.deepcopy(template)
        spec["id"] = "nm2-" + name
        requests = [spec["request"]] + [
            identity["preflight"]
            for identity in spec["identities"]
            if "preflight" in identity
        ]
        for request in requests:
            request["url"] = acceptance.ORIGIN + request["url"][len(reviewed_origin) :]
            request["url"] += (
                ("&" if "?" in request["url"] else "?") + "nm2_case=" + name
            )
        cases[job] = {"spec": spec}
        # Public retention fixture, not a substitute for the real plan compiler.
        plans[job] = {
            "retention_fixture": job,
            "case_hash": acceptance.digest(acceptance.canonical(spec)),
            "credential_references": [
                {
                    "identity_id": who,
                    "source": "value_env",
                    "name": "FIXTURE_" + who.upper() + "_TOKEN",
                }
                for who in ("owner", "peer")
            ],
        }
    plan_sha = acceptance.digest(acceptance.canonical(plans["job-2"]))
    for context in (d.eligibility["context"], d.eligibility["original_context"]):
        context["plan_sha256"] = plan_sha
    f.new_job = Mock(
        side_effect=[
            ("eng-2", "auth-2", "job-2", cases["job-2"]),
            ("eng-1", "auth-1", "job-1", cases["job-1"]),
        ]
    )
    f.test_cases, f.test_inputs, f.test_contexts, f.test_authorities = cases, {}, {}, {}

    def approved(_name, engagement, authorization, job, _case, **options):
        review = {
            "original_request_for": job,
            "enrollment_id": d.admission["enrollment_id"],
            "authorization_id": authorization,
            "plan": copy.deepcopy(plans[job]),
            "expires_at": d.inventories[1]["approvals"][0]["expires_at"],
            "credential_grants": copy.deepcopy(
                d.inventories[1]["approvals"][0]["credential_grants"]
            ),
        }
        context = copy.deepcopy(d.eligibility["original_context"])
        context.update(
            job_id=job,
            engagement_id=engagement,
            plan_sha256=acceptance.digest(acceptance.canonical(plans[job])),
        )
        options["review_snapshot"].update(review)
        options["review_context"].update(context)
        authority = copy.deepcopy(d.eligibility["authority_snapshot"])
        authority["retention_fixture"] = job
        options["review_authority"].update(authority)
        f.test_inputs[job], f.test_contexts[job] = review, context
        f.test_authorities[job] = authority
        index = 0 if job == "job-1" else 1
        registered = {
            d.inventories[index]["approvals"][0]["id"]: acceptance.digest(
                acceptance.canonical(context)
            )
        }
        d.inventories[index]["approval_context_sha256"] = registered
        f.test_before[job]["approval_context_sha256"] = copy.deepcopy(registered)
        return d.admission["runner_id"], d.admission["enrollment_id"]

    f.approve = Mock(side_effect=approved)
    first = copy.deepcopy(d.inventories[0])
    first.update(
        job_status="pending",
        execution=None,
        contracts=[],
        results=[],
        stops=[],
        runtimes=[],
        targets_spent=0,
        duration_allocated=0,
    )
    first["approvals"][0]["issued"] = 0
    f.test_before = {"job-1": first, "job-2": copy.deepcopy(d.inventories[1])}
    exited = []
    f.inventory = Mock(
        side_effect=lambda _eng, job: copy.deepcopy(
            d.inventories[0 if job == "job-1" else 1] if exited else f.test_before[job]
        )
    )
    f.api = Mock()
    f.api.request.side_effect = [
        {"jobs": [{"id": "job-1", "status": "done"}]},
        copy.deepcopy(d.eligibility),
    ]
    f.persistent_metadata = Mock(side_effect=[d.local, d.retained])
    f.grant_snapshot = Mock(side_effect=[d.local["grants"], d.grants])

    def worker(*_args, on_running):
        on_running(d.admission)
        exited.append(True)
        return d.physical

    f.worker = Mock(side_effect=worker)
    f.report_exit = Mock(return_value=d.retirement)
    f.worker_action = Mock(
        return_value={
            "state": "terminal_observed",
            "receipt": {"retirement": d.retirement},
        }
    )
    f.helper = Mock(
        return_value=b'{"state":"terminal_completed","remaining_local_holds":0}'
    )
    f.traffic = Mock(
        side_effect=lambda: copy.deepcopy(d.measured["requests"] if exited else [])
    )
    f.verify_fixed = Mock(return_value=({"before_worker": first}, d.measured))
    return d, f


def run_count(fixture, zero=None):
    with patch.object(acceptance, "datetime", wraps=datetime) as clock:
        clock.now.return_value = datetime(2026, 11, 6, 2, 0, 4, tzinfo=timezone.utc)
        fixture.persistent_count_limit([] if zero is None else zero)


class CountLimit(unittest.TestCase):
    def test_count_only_arguments_do_not_change_unlimited_or_finite_profiles(self):
        self.assertIn(acceptance.COUNT_SCENARIO, acceptance.SCENARIOS)
        self.assertEqual(
            acceptance.persistent_enable_args(acceptance.COUNT_SCENARIO),
            ["--protocol", "persistent-v3", "--max-attempts", "1"],
        )
        self.assertEqual(
            acceptance.persistent_enable_args("persistent-availability"),
            ["--protocol", "persistent-v3"],
        )
        self.assertEqual(acceptance.target_environment(acceptance.COUNT_SCENARIO), {})
        self.assertEqual(
            acceptance.target_environment("persistent-availability"),
            {"NM2_FIXTURE_REQUEST_CEILING": "175"},
        )
        for name in ("healthy", "unknown"):
            with self.assertRaises(acceptance.AcceptanceRefused):
                acceptance.persistent_enable_args(name)
        with self.assertRaises(hosted.HostedRefused):
            hosted.public_projection(
                {"schema": "vardr.nm2-worker-count-acceptance/1"}, {}
            )

    def test_positive_count_proof_is_separate_from_availability_acceptance(self):
        value = verify(vector())
        self.assertEqual((value["issued_attempts"], value["evidence_count"]), (1, 5))
        self.assertEqual(value["unissued_target_charge"], 0)
        self.assertNotIn("idle_seconds", value)

    def test_optional_count_status_matches_the_exact_admission(self):
        data = status_vectors.WorkerStatusDecode("runTest")
        data.setUp()
        data.admission["limits"] = acceptance.persistent_limits(
            acceptance.COUNT_SCENARIO
        )
        data.admission["admission_sha256"] = acceptance.digest(
            acceptance.canonical(
                {k: v for k, v in data.admission.items() if k != "admission_sha256"}
            )
        )
        data.value["limits"] = data.admission["limits"]
        data.decode()  # Advisory hold, never readiness.
        with self.assertRaises(acceptance.AcceptanceRefused):
            data.decode(
                value={
                    **data.value,
                    "limits": {"max_attempts": "2", "idle_timeout_seconds": None},
                }
            )

    def test_existing_fixed_proof_requires_an_explicit_count_only_self_exit(self):
        data = finite.AcceptanceGuards().sequence_fixture()
        data.fixture.scenario = acceptance.COUNT_SCENARIO
        data.fixture.database_revision = "0041persistentruntime"
        data.physical.update(exit_code=0, operator_stop_state="not_requested")
        inventory = data.inventories[0]
        inventory.update(
            schema="vardr.nm2-fixture-inventory/4",
            schema_revision="0041persistentruntime",
        )
        runtime = inventory["runtimes"][0]
        runtime["admission_sha256"] = "e" * 64
        attempt = runtime["attempts"][0]
        attempt["runtime_sequence"] = "1"
        release = attempt["release_receipt"]
        release.update(
            schema="vardr.worker-idle-release/2",
            runtime_sequence="1",
            admission_sha256="e" * 64,
        )
        release["receipt_sha256"] = acceptance.digest(
            acceptance.canonical(
                {k: v for k, v in release.items() if k != "receipt_sha256"}
            )
        )
        args = (*data.selections[0], data.physical, {}, data.traffic[0], inventory)
        data.fixture.verify_fixed(*args, persistent=True, self_exit=True)
        with self.assertRaisesRegex(
            acceptance.AcceptanceRefused, "happy_worker_exit_not_clean"
        ):
            data.fixture.verify_fixed(*args, persistent=True)
        data.fixture.scenario = "persistent-availability"
        inventory["schema"] = "vardr.nm2-fixture-inventory/3"
        with self.assertRaisesRegex(
            acceptance.AcceptanceRefused, "count_self_exit_scope_refused"
        ):
            data.fixture.verify_fixed(*args, persistent=True, self_exit=True)

    def test_count_oracle_refuses_substitution_replay_and_ineligible_second_job(self):
        changes = (
            lambda d: d.physical.update(exit_code=125),
            lambda d: d.physical.update(exit_code=False),
            lambda d: d.physical.update(operator_stop_state="stopped_observed"),
            lambda d: d.admission["limits"].update(idle_timeout_seconds=15),
            lambda d: d.inventories[0]["runtimes"][0].update(last_sequence="2"),
            lambda d: d.inventories[0]["runtimes"][0]["attempts"].append({}),
            lambda d: d.local["attempt"].update(consumption_acknowledged=0),
            lambda d: d.local["grants"]["grants"][0].update(status="revoked"),
            lambda d: d.inventories[0]["approvals"][0].update(
                expires_at="2026-11-06T01:00:00Z"
            ),
            lambda d: d.local["attempt"].update(native_done_sha256="0" * 64),
            lambda d: d.retained["attempt"].update(artifact_sha256="0" * 64),
            lambda d: d.inventories[1].update(targets_spent=1),
            lambda d: d.inventories[1].update(contracts=[{}]),
            lambda d: d.inventories[1].update(execution={"state": "running"}),
            lambda d: d.inventories[1]["approvals"][0].update(issued=1),
            lambda d: d.inventories[1]["approvals"][0].update(max_executions=True),
            lambda d: d.inventories[1]["approvals"][0].update(revoked=True),
            lambda d: d.eligibility["context"].update(job_id="foreign"),
            lambda d: d.eligibility["authority_snapshot"]["limits"].update(
                concurrency=True
            ),
            lambda d: d.eligibility["authority_snapshot"]["limits"].update(
                concurrency=1.0
            ),
            lambda d: d.eligibility["authority_snapshot"]["limits"].update(targets=5.0),
            lambda d: d.eligibility["authority_snapshot"]["limits"].update(
                duration=120.0
            ),
            lambda d: d.grants.update(policy_reason="grant_expired_or_revoked"),
            lambda d: d.grants["grants"][0].update(expires_at="2026-11-06T01:00:00Z"),
            lambda d: d.retirement.update(report_sha256="0" * 64),
        )
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                data = vector()
                change(data)
                with self.assertRaises(acceptance.AcceptanceRefused):
                    verify(data)

    def test_catalog_binding_metadata_cannot_be_substituted(self):
        changes = (
            ("issuer", "https://foreign.example/backend"),
            ("origin", "http://foreign.example:8080"),
            ("source", "keyring"),
            ("name", "UNREVIEWED_TOKEN"),
        )
        for which in ("first", "pending"):
            for key, value in changes:
                with self.subTest(which=which, key=key):
                    data = vector()
                    snapshot = data.local["grants"] if which == "first" else data.grants
                    snapshot["grants"][0][key] = value
                    with self.assertRaises(acceptance.AcceptanceRefused):
                        verify(data)

    def test_reference_revision_and_review_context_cannot_be_substituted(self):
        for key, value in (
            ("revision", 2),
            ("revision", True),
            ("source", "env"),
            ("name", "UNREVIEWED_TOKEN"),
        ):
            with self.subTest(key=key, value=value):
                data = vector()
                for refs in (
                    data.inventories[1]["approvals"][0]["credential_grants"],
                    data.eligibility["context"]["credential_grants"],
                    data.eligibility["original_context"]["credential_grants"],
                ):
                    refs[0][key] = value
                with self.assertRaises(acceptance.AcceptanceRefused):
                    verify(data)
        data = vector()
        data.eligibility["context"]["credential_grants"][0]["revision"] = 2
        with self.assertRaises(acceptance.AcceptanceRefused):
            verify(data)

    def test_fresh_review_is_bound_to_original_context_and_admitted_authority(self):
        changes = (
            ("authority_revision", 2),
            ("authority_sha256", "0" * 64),
            ("plan_sha256", "0" * 64),
        )
        for key, value in changes:
            with self.subTest(key=key):
                data = vector()
                data.eligibility["context"][key] = value
                with self.assertRaises(acceptance.AcceptanceRefused):
                    verify(data)
        for key in ("origin", "enrollment"):
            with self.subTest(snapshot=key):
                data = vector()
                snapshot = data.eligibility["authority_snapshot"]
                if key == "origin":
                    snapshot["origin"] = "https://foreign.example/backend"
                else:
                    snapshot["enrollment"]["id"] = "foreign-enrollment"
                changed = acceptance.digest(acceptance.canonical(snapshot))
                for context in (
                    data.eligibility["context"],
                    data.eligibility["original_context"],
                ):
                    context["authority_sha256"] = changed
                with self.assertRaises(acceptance.AcceptanceRefused):
                    verify(data)

    def test_map_done_does_not_trigger_local_proof_before_exact_exit(self):
        d, f = orchestration_vector()
        exited = []

        class LocalProofReached(Exception):
            pass

        def local_proof(*_args):
            self.assertEqual(exited, [True], "Map done is not local release ACK")
            raise LocalProofReached

        f.persistent_metadata = Mock(side_effect=local_proof)
        f.grant_snapshot = Mock()
        f.report_exit = Mock()

        def observed_worker(*_args, on_running):
            on_running(d.admission)  # Map reports done while native DONE/ACK may lag.
            self.assertEqual(f.api.request.call_count, 1)
            f.persistent_metadata.assert_not_called()
            f.grant_snapshot.assert_not_called()
            exited.append(True)  # Model the independent exact-incarnation observer.
            return d.physical

        f.worker = Mock(side_effect=observed_worker)
        with self.assertRaises(LocalProofReached):
            f.persistent_count_limit([])
        f.persistent_metadata.assert_called_once_with(d.admission, 1)
        f.grant_snapshot.assert_not_called()
        f.report_exit.assert_not_called()

    def test_count_orchestration_only_reads_after_two_initial_approvals(self):
        d, f = orchestration_vector()
        with patch.object(acceptance, "datetime", wraps=datetime) as clock:
            clock.now.return_value = datetime(2026, 11, 6, 2, 0, 4, tzinfo=timezone.utc)
            f.persistent_count_limit([])
        self.assertEqual(f.receipt["status"], "selected_count_control_slice_passed")
        self.assertEqual(f.approve.call_count, 2)
        self.assertEqual(f.worker_action.call_args.args[0], "reconcile")
        self.assertEqual(f.worker_action.call_count, 1)  # No stop or retry.
        self.assertEqual(f.helper.call_args.args[:2], ("audit", "reconcile-managed"))
        self.assertEqual(
            f.api.request.call_args.args[0], "/jobs/job-2/managed/approval/review"
        )
        self.assertEqual(f.api.request.call_args.args[1], f.test_inputs["job-2"])
        self.assertTrue(f.verify_fixed.call_args.kwargs["self_exit"])

    def test_originals_are_frozen_before_launch_and_retained_without_values(self):
        d, f = orchestration_vector()
        originals = copy.deepcopy(f.test_cases)
        observed_admission = copy.deepcopy(d.admission)
        original_authorities = {}
        worker = f.worker.side_effect

        def after_originals(*args, on_running):
            self.assertEqual(f.approve.call_count, 2)
            self.assertEqual(f.inventory.call_count, 2)
            self.assertEqual(f.traffic.call_count, 1)
            original_authorities.update(copy.deepcopy(f.test_authorities))
            for authority in f.test_authorities.values():
                authority["origin"] = "https://later.example/backend"
            for case in f.test_cases.values():
                case["spec"]["id"] = "later-mutation"
            return worker(*args, on_running=on_running)

        f.worker.side_effect = after_originals
        run_count(f)
        proof = f.receipt["cases"]["persistent_count_limit"]["proof"]
        self.assertEqual(proof["admission"], observed_admission)
        d.admission["origin"] = "https://later.example/backend"
        self.assertEqual(proof["admission"], observed_admission)
        self.assertEqual(proof["pending_before"], f.test_before["job-2"])
        self.assertEqual(proof["fixed"]["before_worker"], f.test_before["job-1"])
        self.assertEqual(
            proof["traffic"], {"before": [], "after": d.measured["requests"]}
        )
        self.assertEqual(
            [row["job_id"] for row in proof["selections"]], ["job-1", "job-2"]
        )
        for row in proof["selections"]:
            self.assertEqual(
                set(row),
                {
                    "engagement_id",
                    "job_id",
                    "case_spec",
                    "review_input",
                    "review_context",
                    "review_authority",
                },
            )
            job = row["job_id"]
            self.assertEqual(row["case_spec"], originals[job]["spec"])
            self.assertEqual(row["review_input"], f.test_inputs[job])
            self.assertEqual(row["review_context"], f.test_contexts[job])
            self.assertEqual(row["review_authority"], original_authorities[job])
            credentials = [
                identity["credential"] for identity in row["case_spec"]["identities"]
            ]
            self.assertEqual(
                [value["value_env"] for value in credentials[:2]],
                ["FIXTURE_OWNER_TOKEN", "FIXTURE_PEER_TOKEN"],
            )
            self.assertTrue(all("value" not in value for value in credentials[:2]))
            self.assertEqual(credentials[2]["value"], "")
        self.assertEqual(f.worker_action.call_args.args[0], "reconcile")

    def test_nonempty_original_or_fresh_baseline_refuses_before_launch(self):
        extra = {"path": "/unexpected-before-worker"}
        for initial in (True, False):
            with self.subTest(initial=initial):
                _d, f = orchestration_vector()
                if not initial:
                    f.traffic.side_effect = lambda: [extra]
                with self.assertRaises(acceptance.AcceptanceRefused):
                    run_count(f, [extra] if initial else [])
                f.worker.assert_not_called()
                f.report_exit.assert_not_called()

    def test_complete_final_traffic_cannot_hide_prefix_suffix_or_substitution(self):
        for mutation in ("prefix", "suffix", "same-length-change"):
            with self.subTest(mutation=mutation):
                d, f = orchestration_vector()
                final = copy.deepcopy(d.measured["requests"])
                if mutation == "prefix":
                    final.insert(0, {"path": "/hidden-second-job"})
                elif mutation == "suffix":
                    final.append({"path": "/hidden-second-job"})
                else:
                    final[0]["received_monotonic_ns"] = True
                f.traffic.side_effect = [[], final]
                with self.assertRaises(acceptance.AcceptanceRefused):
                    run_count(f)


if __name__ == "__main__":
    unittest.main()
