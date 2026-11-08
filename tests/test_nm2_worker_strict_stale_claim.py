"""Inert regressions for the installed stale registered-approval claim witness."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import unittest
from unittest.mock import MagicMock, Mock, patch

import nm2_worker_acceptance as fixture
import nm2_worker_hosted as hosted
import nm2_worker_strict_projection as projection
from test_nm2_worker_strict_hosted import vector

CANARY = "vmap_" + "synthetic-canary-" * 3


def digest(value):
    return fixture.digest(fixture.canonical(value))


def stale_vector(*, desktop=False):
    raw, selection, engine_before, engine_after, run, *_ = vector(desktop=desktop)
    base = raw["cases"].pop(fixture.STRICT_DRIFT_CASE)["proof"]["before"]
    selection["sources"]["map"]["commit"] = fixture.STALE_CLAIM_MAP
    raw.update(schema=fixture.STALE_CLAIM_SCHEMA, scenario=fixture.STALE_CLAIM_SCENARIO,
               acceptance_scope=fixture.STALE_CLAIM_SCOPE)
    engagement, job, authorization = "private-eng", "private-job", "private-auth"
    runner, enrollment = "private-runner", "private-enrollment"
    spec = {"id": "private-case"}
    plan = {"profile": "gate-fixed-http/1", "case_hash": digest(spec)}
    authority = {
        "schema": "vardr.map-managed-authority/1", "authority_revision": 10,
        "origin": "https://vardrsec.localhost:28443/backend",
        "limits": {"concurrency": 1, "duration": 120, "targets": 5},
        "authority": {"engagement_id": engagement, "authorization": {"id": authorization, "status": "active"}},
        "enrollment": {"id": enrollment, "runner_id": runner},
    }
    context = {
        "mode": "strict", "control": "managed_online", "runner_id": runner,
        "engagement_id": engagement, "job_id": job, "authority_revision": 10,
        "authority_sha256": digest(authority), "plan_sha256": digest(plan),
        "not_before": "2026-11-07T20:00:00Z", "expires_at": "2026-11-07T20:05:00Z",
        "max_executions": 1, "max_duration_seconds": 30, "credential_grants": [],
    }
    refreshed = {**authority, "authority_revision": 11, "limits": {**authority["limits"], "targets": 4}}
    fresh = {
        "context": {**context, "authority_revision": 11, "authority_sha256": digest(refreshed),
                    "not_before": "2026-11-07T20:00:10Z"},
        "authority_snapshot": refreshed,
    }
    approval_id = "private-issuer:fixture-" + fixture.STALE_CLAIM_SCENARIO
    inventory = {
        **base, "approval_context_sha256": {approval_id: digest(context)},
        "approvals": [{
            "id": approval_id, "issued": 0, "revoked": False, "approved_at": "2026-11-07T20:00:01Z",
            **{key: context[key] for key in (
                "expires_at", "max_executions", "max_duration_seconds", "credential_grants",
            )},
        }],
    }

    def approve(*args, **kwargs):
        assert kwargs["local_grants"] is False
        kwargs["review_snapshot"].update({"plan": plan})
        kwargs["review_context"].update(context)
        kwargs["review_authority"].update(authority)
        return runner, enrollment

    run.new_job = Mock(return_value=(engagement, authorization, job, {"spec": spec}))
    run.approve = Mock(side_effect=approve)
    run.issuer_id = "private-issuer"
    run.issuer_origin = authority["origin"]
    run.url = "https://localhost:28443"
    run.key = {"token": CANARY}
    run.traffic = Mock(side_effect=[[], []])
    run.inventory = Mock(side_effect=[inventory, deepcopy(inventory)])
    run.api = Mock()
    run.api.ca_sha256 = "a" * 64
    run.api.request.side_effect = [
        {"limit": 4, "spent": 0, "unit": "represented_origin_attempts/1"},
        fresh, {"evidence": []},
    ]
    api = {"id": "1" * 64}
    run.stale_claim_marker = Mock(side_effect=[(api, 0), (api, 1)])
    transport = Mock(ca_sha256=run.api.ca_sha256)
    transport.request.return_value = {"detail": "managed_request_refused"}
    with (
        patch.object(fixture, "OwnerAPI", return_value=transport),
        patch.object(fixture, "datetime", wraps=datetime) as clock,
    ):
        clock.now.return_value = datetime(2026, 11, 7, 20, 0, 11, tzinfo=timezone.utc)
        run.strict_stale_registered_claim()
    return raw, selection, engine_before, engine_after, run, transport


class StaleRegisteredClaim(unittest.TestCase):
    def test_exact_no_worker_producer_and_projection_on_both_hosts(self):
        for desktop in (False, True):
            with self.subTest(desktop=desktop):
                raw, selection, before, after, run, transport = stale_vector(desktop=desktop)
                call = transport.request.call_args
                self.assertEqual(call.args[0], "/jobs/private-job/managed/claim")
                self.assertEqual(set(call.args[1]), {
                    "origin", "runner_id", "concurrency_budget", "duration_seconds", "target_binding",
                })
                self.assertEqual(call.kwargs, {"method": "POST", "csrf": False, "expected": 409, "bearer": CANARY})
                self.assertEqual(run.approve.call_count, 1)
                self.assertEqual(run.stale_claim_marker.call_count, 2)
                run.worker.assert_not_called()
                if desktop:
                    result = projection.project_desktop(raw, selection, before, after)
                else:
                    result = hosted.public_projection(raw, selection, inventories=(before, after))
                self.assertEqual(result["schema"], "vardr.nm2-strict-stale-claim-public/1")
                self.assertEqual(result["stopped_owned_container_count"], 5)
                self.assertEqual(result["measurements"]["approval_issued"], 0)
                self.assertNotIn(CANARY, json.dumps(raw))
                self.assertNotIn("private-job", json.dumps(result))

    def test_projection_rejects_stale_evidence_substitution(self):
        raw, selection, before, after, *_ = stale_vector()
        for field, replacement in (
            ("marker_counts", [0, True]), ("api_container_id", "2" * 64),
            ("observed_at", "2026-11-07T20:05:00Z"), ("traffic_after", [{}]),
        ):
            altered = deepcopy(raw)
            altered["cases"][fixture.STALE_CLAIM_CASE]["proof"][field] = replacement
            with self.subTest(field=field), self.assertRaises(hosted.HostedRefused):
                hosted.public_projection(altered, selection, inventories=(before, after))
        for field, value in (("issued", 1), ("revoked", True)):
            altered = deepcopy(raw)
            altered["cases"][fixture.STALE_CLAIM_CASE]["proof"]["after"]["approvals"][0][field] = value
            with self.subTest(field=field), self.assertRaises(hosted.HostedRefused):
                hosted.public_projection(altered, selection, inventories=(before, after))

    def test_map_pin_and_inert_default(self):
        env = {"NM2_SCENARIO": fixture.STALE_CLAIM_SCENARIO,
               "NM2_DATABASE_REVISION": "0041persistentruntime", "NM2_MAP_SHA": fixture.STALE_CLAIM_MAP}
        self.assertEqual(hosted.execution_options(env), (fixture.STALE_CLAIM_SCENARIO, "0041persistentruntime"))
        with self.assertRaises(hosted.HostedRefused):
            hosted.execution_options({**env, "NM2_MAP_SHA": fixture.STRICT_REVIEW_MAP})
        with patch.object(hosted, "STALE_CLAIM_MAP", None), self.assertRaises(hosted.HostedRefused):
            hosted.execution_options({**env, "NM2_MAP_SHA": None})
        self.assertEqual(hosted.execution_options({}), ("healthy", "0040runtimesequence"))
        self.assertEqual(fixture.target_environment(fixture.STALE_CLAIM_SCENARIO), {})

    def test_bearer_is_only_sent_on_cookie_empty_expected_refusal(self):
        api = object.__new__(fixture.OwnerAPI)
        api.url = "https://localhost:28443"
        api.ca = Mock()
        api.ca.read_bytes.return_value = b"synthetic-ca"
        api.ca_sha256 = fixture.digest(b"synthetic-ca")
        api.csrf, api.jar = None, []
        api.opener = MagicMock()
        response = api.opener.open.return_value
        response.status = 409
        response.headers = {"Cache-Control": "no-store"}
        response.read.return_value = b'{"detail":"managed_request_refused"}'
        path = "/jobs/selected/managed/claim"
        kwargs = {"method": "POST", "csrf": False, "expected": 409, "bearer": CANARY}
        self.assertEqual(api.request(path, {}, **kwargs), {"detail": "managed_request_refused"})
        request = api.opener.open.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer " + CANARY)
        self.assertIsNone(request.get_header("Cookie"))
        self.assertIsNone(request.get_header("X-csrf-token"))
        api.opener.reset_mock()
        with self.assertRaises(fixture.AcceptanceRefused):
            api.request("/jobs/selected/managed/current", {}, **kwargs)
        api.jar = [object()]
        with self.assertRaises(fixture.AcceptanceRefused):
            api.request(path, {}, **kwargs)
        api.opener.open.assert_not_called()
        api.jar = []
        response.headers = {}
        with self.assertRaises(fixture.AcceptanceRefused):
            api.request(path, {}, **kwargs)
