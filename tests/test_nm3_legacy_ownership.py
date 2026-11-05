"""Offline safety assertions for legacy metadata recovery; never contact Docker."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error
import uuid

import nm3_legacy_ci as ci
import nm3_legacy_ownership as lane


class LegacyOwnershipTests(unittest.TestCase):
    def specimen(self):
        eid, jid, rid = [str(uuid.uuid4()) for _ in range(3)]
        body = {'runner_id': rid, 'origin': lane.ORIGIN, 'token': 'synthetic-control'}
        key = 'vmap_synthetic'
        value = {'execution': {'job_id': jid, 'runner_id': rid, 'origin': lane.ORIGIN,
            'owner': 'synthetic-owner', 'principal_hash': hashlib.sha256(('Bearer ' + key).encode()).hexdigest(),
            'token_hash': hashlib.sha256(body['token'].encode()).hexdigest(), 'state': 'active',
            'capacity_reserved': True, 'duration_seconds': 30, 'target_charge': 0},
            'budget': {'id': eid, 'owner_github_id': 'synthetic-owner', 'duration_allocated': 30,
            'duration_limit': 120, 'concurrency_limit': 1, 'target_limit': None, 'targets_spent': 0}}
        return value, eid, jid, body, key

    def test_hash_accounting_and_binding_changes_cannot_pass(self):
        args = self.specimen()
        lane.verify_records(*args)
        for group, field, changed in [('execution', 'principal_hash', '0' * 64),
                ('execution', 'token_hash', '0' * 64), ('execution', 'owner', 'other'),
                ('execution', 'capacity_reserved', False), ('execution', 'duration_seconds', 0),
                ('budget', 'duration_allocated', 0), ('budget', 'target_limit', 10)]:
            with self.subTest(field=field):
                value = copy.deepcopy(args[0]); value[group][field] = changed
                with self.assertRaises(ValueError): lane.verify_records(value, *args[1:])

    def test_fixture_pins_do_not_change_bound_manifest(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = Path(folder)
            original = {'components': {k: {'commit': v, 'review': 'old'} for k, v in ci.PINS.items()}}
            path = fixture / 'versions.json'; path.write_text(json.dumps(original))
            bound = (ci.SOURCE / 'versions.json').read_bytes()
            ci.apply_fixture_pins(fixture)
            changed = json.loads(path.read_text())
            self.assertEqual({k: v['commit'] for k, v in changed['components'].items()}, ci.UPGRADE_TARGET_PINS)
            self.assertEqual((ci.SOURCE / 'versions.json').read_bytes(), bound)
            with self.assertRaises(ValueError): ci.apply_fixture_pins(fixture)

    def test_refusal_must_be_actual_404_not_generic_or_success(self):
        api = lane.API.__new__(lane.API); api.csrf = None
        for status in (404, 401, 403, 500):
            error = urllib.error.HTTPError(lane.ORIGIN, status, 'synthetic-private', {}, io.BytesIO(b'private'))
            with patch.object(lane.urllib.request, 'build_opener'):
                api.client = SimpleNamespace(open=lambda *a, **kw: (_ for _ in ()).throw(error))
                if status == 404:
                    self.assertIsNone(api.request('/jobs/synthetic/control', {}, key='vmap_test', expected=404))
                else:
                    with self.assertRaises(ValueError): api.request('/jobs/synthetic/control', {}, key='vmap_test', expected=404)
        class Success:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): pass
        api.client = SimpleNamespace(open=lambda *a, **kw: Success())
        with self.assertRaises(ValueError): api.request('/jobs/synthetic/control', {}, key='vmap_test', expected=404)

    def test_records_require_nonempty_single_execution_and_budget(self):
        for executions, budgets in (([], []), ([{}], []), ([{}, {}], [{}])):
            with patch.object(lane.recovery, 'sql', side_effect=[json.dumps(executions), json.dumps(budgets)]), self.assertRaises(ValueError):
                lane.records(Path('/synthetic'), 'synthetic')

    def test_seed_uses_existing_api_contract_and_same_owner_distinct_principal(self):
        eid, jid = str(uuid.uuid4()), str(uuid.uuid4())
        calls = []
        def request(path, data=None, **kwargs):
            calls.append((path, data, kwargs))
            if path == '/engagements': return {'id': eid}
            if path.endswith('/jobs'): return {'id': jid}
            if path.endswith('/claim'):
                return {'status': 'running', 'execution_control': {'capacity_reserved': True,
                    'duration_budget': {'allocated_seconds': 30}, 'token': 'synthetic-control'}}
        keys = [{'token': 'vmap_owner'}, {'token': 'vmap_other'}]
        _, _, body = lane.seed(SimpleNamespace(request=request), keys)
        self.assertEqual(calls[-1][2], {'key': 'vmap_other', 'expected': 404})
        self.assertEqual(calls[-2][2], {'key': 'vmap_owner'})
        self.assertEqual(body['duration_seconds'], 30)
        self.assertTrue(body['concurrency_budget'])
        self.assertEqual(calls[3][1], {'tool_type': 'httpx', 'target_source': 'scope'})
        self.assertEqual(len(calls), 6)


if __name__ == '__main__': unittest.main()
