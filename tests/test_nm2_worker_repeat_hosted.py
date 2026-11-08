"""Inert C05 installed repetition, separate from the existing PostgreSQL race."""

from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import nm2_worker_hosted as hosted
import nm2_worker_launch_acceptance as launch
from nm2_worker_acceptance import AcceptanceRefused, canonical, digest
from test_nm2_worker_stopped_predecessor_hosted import evidence
from worker_runtime import RuntimeIdentity


def model():
    identity = RuntimeIdentity(
        "fixture-daemon", "6" * 64, "sha256:" + "2" * 64,
        "vardrsec-nm2-synthetic", "2026-11-07T01:00:00.000001Z", "a" * 64,
    )
    admission = dict(
        runtime_id="e4a346a6-3982-4a13-a0a5-5b025bedbde0", runtime_sha256="a" * 64,
        admission_sha256="b" * 64, runner_id="90b0b081-8af2-4d02-b543-333d8fba07b6",
        origin="https://map.example.test", identity=asdict(identity),
    )
    contract = dict(id="ab3f0ddc-c14a-4944-8c59-f2c44c9575f0",
                    attempt_id="28c8a482-dca8-4c96-8bba-d4e6a5465bea", ordinal=1,
                    fence=1, consumed=True, contract_sha256="c" * 64)
    binding = dict(origin=admission["origin"], runner_id=admission["runner_id"], job_id="selected-job",
                   contract_id=contract["id"], **{k: contract[k] for k in ("attempt_id", "fence", "contract_sha256")})
    attempt = dict(runtime_id=admission["runtime_id"], runtime_sequence="1", job_id="selected-job",
                   binding=binding, confirmed_at="2026-11-07T01:00:01.000001Z",
                   **dict.fromkeys(("released_at", "terminal_receipt", "terminal_receipt_sha256",
                                    "native_done_sha256", "release_receipt")))
    runtime = {**{k: admission[k] for k in ("runtime_sha256", "admission_sha256", "identity")},
               "id": admission["runtime_id"], "last_sequence": "1", "head_sequence": "1",
               "active_sequence": "1", "new_work_disabled": False, "retired": False,
               "report_sha256": None, "attempts": [attempt]}
    inventory = dict(job_status="running", targets_spent=1, duration_allocated=30,
                     capacity_reserved_count=1, concurrency_limit=1,
                     execution=dict(state="active", capacity_reserved=True, target_charge=1, duration_seconds=30),
                     approvals=[dict(id="fixture-approval", issued=1, revoked=False)],
                     contracts=[contract], runtimes=[runtime], results=[], stops=[])
    fixture = launch.LaunchFixture.__new__(launch.LaunchFixture)
    fixture.receipt, fixture.url = {}, "https://fixture.example.test"
    fixture.api, fixture.key = SimpleNamespace(ca=Path("synthetic-ca")), {"token": "vmap_private_canary"}
    fixture.inventory = Mock(side_effect=[deepcopy(inventory), deepcopy(inventory)])
    requests = [{"identity": name} for name in ("owner", "peer", "owner")]
    fixture.traffic = Mock(return_value=requests)
    case = "engagement", "selected-job", {"spec": {"id": "reviewed-synthetic-case"}}, {}
    return fixture, admission, case, identity, requests, inventory


def vector():
    raw, selection, inventories = evidence()
    raw.update(scenario=hosted.LAUNCH_REPEAT_SCENARIO,
               acceptance_scope=hosted.LAUNCH_SCOPES[hosted.LAUNCH_REPEAT_SCENARIO])
    fixture, admission, case, identity, requests, inventory = model()
    first = raw["launch_pair"][0]
    selection["https_port"] = 8443
    admission["origin"] = "https://vardrsec.localhost:8443/backend"
    physical = {**asdict(identity), "image_id": selection["images"]["worker"],
                "container_id": first["container_id"], "started_at": first["started_at"]}
    identity = RuntimeIdentity(**physical)
    admission["identity"], admission["runtime_sha256"] = physical, digest(canonical(physical))
    runtime = inventory["runtimes"][0]
    runtime.update(identity=physical, runtime_sha256=admission["runtime_sha256"])
    binding = runtime["attempts"][0]["binding"]
    binding["origin"] = admission["origin"]
    fixture.inventory.side_effect = [deepcopy(inventory), deepcopy(inventory)]
    client = Mock(request=Mock(return_value={"detail": "managed_request_refused"}))
    with patch.object(launch, "OwnerAPI", return_value=client):
        fixture.observe_repeated_managed_claim(admission, case, identity, "e" * 32, {"requests": requests})
    terminal = {
        **binding, "schema": "vardr.managed-stop-receipt/1", "outcome": "failed",
        "cause": "observed_exit", "capacity_reserved": False,
        "receipt_sha256": digest(canonical({
            **binding, "schema": "vardr.managed-stop/1", "outcome": "failed",
            "cause": "observed_exit", "termination_confirmed": True,
        })),
    }
    raw["repeated_managed_claim"] = {**fixture.receipt["repeated_managed_claim"], "terminal_receipt": terminal}
    raw["stopped_predecessor"]["terminal_sha256"] = digest(canonical(terminal))
    return raw, selection, inventories


class RepeatedManagedClaimTests(unittest.TestCase):
    def test_active_repeat_uses_one_original_key_claim_and_preserves_accounting(self):
        fixture, admission, case, identity, requests, inventory = model()
        client = Mock()
        client.request.return_value = {"detail": "managed_request_refused"}
        with patch.object(launch, "OwnerAPI", return_value=client) as constructor:
            fixture.observe_repeated_managed_claim(admission, case, identity, "e" * 32, {"requests": requests})
        constructor.assert_called_once_with(fixture.url, fixture.api.ca)
        client.request.assert_called_once()
        args, kwargs = client.request.call_args
        self.assertEqual(args[0], "/jobs/selected-job/managed/claim")
        self.assertEqual(args[1], {
            "origin": admission["origin"], "runner_id": admission["runner_id"],
            "concurrency_budget": True, "duration_seconds": 30,
            "target_binding": {"profile": "gate-fixed-http/1", "origins": [launch.ORIGIN],
                               "case_sha256": digest(canonical(case[2]["spec"]))},
            **{key: admission[key] for key in ("runtime_id", "runtime_sha256", "admission_sha256")},
            "runtime_sequence": "1",
        })
        self.assertEqual(kwargs, dict(method="POST", csrf=False, expected=409, bearer=fixture.key["token"]))
        proof = fixture.receipt["repeated_managed_claim"]
        self.assertEqual(proof["state_before_sha256"], proof["state_after_sha256"])
        self.assertEqual((proof["issued_attempts"], proof["capacity_before"], proof["capacity_after"]), (1, 1, 1))
        self.assertNotIn("vmap_private_canary", canonical(fixture.receipt).decode())
        self.assertNotIn("binding", proof)

    def test_legitimate_advisory_timestamp_changes_do_not_change_owned_fingerprint(self):
        _, _, _, _, _, before = model()
        after = deepcopy(before)
        before["runtimes"][0]["presence_at"] = "before"
        after["runtimes"][0]["presence_at"] = "after"
        before["control_refresh_at"], after["control_refresh_at"] = "before", "after"
        self.assertEqual(launch.repeated_claim_state(before), launch.repeated_claim_state(after))

    def test_original_ordinal_and_fence_must_be_exact_first_integers(self):
        for field, invalid in (("ordinal", 2), ("ordinal", True), ("fence", 1.0)):
            _, _, _, _, _, before = model()
            before["contracts"][0][field] = invalid
            with self.subTest(field=field, invalid=invalid), self.assertRaises(AcceptanceRefused):
                launch.repeated_claim_state(before)

    def test_changed_ordinal_attempt_reservation_or_traffic_cannot_pass(self):
        for key in ("ordinal", "contract", "charge", "slot", "traffic", "refusal"):
            with self.subTest(key=key):
                fixture, admission, case, identity, requests, before = model()
                after = deepcopy(before)
                if key == "ordinal":
                    after["approvals"][0]["issued"] = 2
                elif key == "contract":
                    after["contracts"].append(deepcopy(after["contracts"][0]))
                elif key == "charge":
                    after["duration_allocated"] = 60
                elif key == "slot":
                    after["capacity_reserved_count"] = 0
                fixture.inventory.side_effect = [before, after]
                if key == "traffic":
                    fixture.traffic.side_effect = [requests, requests + [{"identity": "peer"}]]
                client = Mock()
                client.request.return_value = {"detail": "unexpected" if key == "refusal" else "managed_request_refused"}
                with patch.object(launch, "OwnerAPI", return_value=client), self.assertRaises(AcceptanceRefused):
                    fixture.observe_repeated_managed_claim(admission, case, identity, "e" * 32, {"requests": requests})
                self.assertNotIn("repeated_managed_claim", fixture.receipt)

    def test_linux_and_desktop_projection_keep_repeat_scope_and_fixed_only_proof(self):
        for desktop in (False, True):
            raw, selection, inventories = vector()
            if desktop:
                raw["platform"], selection["docker_context"] = "win32", "desktop-linux"
            value = hosted.launch_projection(raw, selection, inventories=inventories, desktop=desktop)
            proof = value["repeated_managed_claim"]
            self.assertEqual(proof["repeat_count"], 1)
            self.assertEqual(value["stopped_predecessor"]["capacity_after"], 0)
            self.assertEqual(value["stopped_predecessor"]["owned_stopped_container_count"], 7)
            self.assertNotIn("runtime_id", proof)
            self.assertNotIn("launch_pair", value)
            self.assertEqual(value["nm2_exit_status"], "incomplete")

    def test_projection_rejects_changed_types_binding_counts_and_refusal(self):
        for key, changed in (("repeat_count", True), ("issued_attempts", 2), ("capacity_after", 0),
                             ("duration_allocated", 30.0), ("state_after_sha256", "f" * 64),
                             ("runtime_id", "980d0f49-75c3-4f02-84cc-3fba35ff2e3d"),
                             ("refusal_sha256", "f" * 64), ("unsafe", "private-canary")):
            raw, selection, inventories = vector()
            raw["repeated_managed_claim"][key] = changed
            with self.subTest(key=key), self.assertRaises(hosted.HostedRefused):
                hosted.public_projection(raw, selection, inventories=inventories)

    def test_reader_recomputes_retained_rows_binding_request_and_terminal(self):
        for change in ("state", "body", "path", "run", "binding", "terminal", "counter"):
            raw, selection, inventories = vector()
            proof = raw["repeated_managed_claim"]
            if change == "state":
                proof["state_before"]["approval"]["issued"] = 2
                proof["state_after"]["approval"]["issued"] = 2
            elif change == "body":
                proof["request"]["runtime_sequence"] = "2"
            elif change == "path":
                proof["request_path"] = "/jobs/other-job/managed/claim"
            elif change == "run":
                proof["original_run_id"] = "f" * 32
            elif change == "binding":
                proof["state_before"]["runtime"]["attempts"][0]["binding"]["contract_id"] = "980d0f49-75c3-4f02-84cc-3fba35ff2e3d"
                proof["state_after"] = deepcopy(proof["state_before"])
            elif change == "terminal":
                proof["terminal_receipt"]["fence"] = True
            elif change == "counter":
                proof["state_before"]["targets_spent"] = True
                proof["state_after"] = deepcopy(proof["state_before"])
            # Equal replacement hashes alone must never make changed rows valid.
            for key in ("before", "after"):
                proof[f"state_{key}_sha256"] = digest(canonical(proof[f"state_{key}"]))
            proof["request_sha256"] = digest(canonical(proof["request"]))
            with self.subTest(change=change), self.assertRaises(hosted.HostedRefused):
                hosted.public_projection(raw, selection, inventories=inventories)

    def test_explicit_routing_preserves_original_modes_and_exact_source_guard(self):
        env = dict(NM2_SCENARIO=hosted.LAUNCH_REPEAT_SCENARIO,
                   NM2_DATABASE_REVISION="0041persistentruntime",
                   **{"NM2_" + name.upper() + "_SHA": commit for name, commit in launch.MAP_DISCONNECT_SOURCES.items()})
        self.assertEqual(hosted.execution_options(env), (hosted.LAUNCH_REPEAT_SCENARIO, "0041persistentruntime"))
        with self.assertRaises(hosted.HostedRefused):
            hosted.execution_options({**env, "NM2_MAP_SHA": "f" * 40})
        fixture = SimpleNamespace(receipt={"status": "selected_launch_slice_passed"}, run=Mock())
        with patch.object(launch, "LaunchFixture", return_value=fixture) as constructor, patch.object(launch, "manifest", return_value={}):
            self.assertEqual(launch.main([
                "--cohort", "cohort", "--compose-executable", "compose", "--compose-sha256", "a" * 64,
                "--docker-config", "config", "--repeat-managed-claim", "--execute",
            ]), 0)
        self.assertTrue(constructor.call_args.kwargs["repeat_managed_claim"])
        self.assertFalse(constructor.call_args.kwargs["stopped_predecessor"])
        self.assertIn("persistent-launch-repeat-managed-claim", (hosted.SOURCE / '.github/workflows/compose.yml').read_text())
        self.assertEqual(hosted.REPEAT_HOSTED, "vardr.nm2-hosted/19")


if __name__ == '__main__':
    unittest.main()
