"""Original public authority retention only; no real Runner compiler or signer."""

import json
import sys
from types import ModuleType
import unittest
from unittest.mock import Mock, patch

import nm2_worker_acceptance as fixture


class AuthorityRetention(unittest.TestCase):
    def test_actual_approve_captures_original_public_authority_without_resolving_secrets(
        self,
    ):
        owner = object.__new__(fixture.Fixture)
        owner.owner, owner.issuer_id = "synthetic-owner", "synthetic-issuer"
        owner.operator_key = b"synthetic-unusable-key"
        owner.issuer_origin = "https://map.example/backend"
        owner.key = {"id": "synthetic-key-id", "token": "synthetic-unusable-token"}
        runner = "00000000-0000-4000-8000-000000000080"
        authority = {"schema": "public-authority-retention-fixture", "revision": 1}
        context = {"authority_sha256": fixture.digest(fixture.canonical(authority))}
        plan = {"credential_references": []}
        owner.compose = Mock(
            return_value=fixture.canonical({"enrollment_id": "enrolled"})
        )
        owner.helper = Mock(side_effect=[("Runner ID: " + runner).encode(), b"a" * 64])
        owner.api = Mock()
        owner.api.request.side_effect = [
            {"context": context, "authority_snapshot": authority},
            {},
        ]
        fake = {
            name: ModuleType(name)
            for name in (
                "vardrrunner",
                "vardrrunner.authorization",
                "vardrrunner.authorization.contracts",
                "vardrrunner.authorization.plan",
            )
        }
        fake["vardrrunner"].__path__ = []
        fake["vardrrunner.authorization"].__path__ = []
        fake["vardrrunner.authorization.contracts"].approve = Mock(
            return_value={"synthetic": "approval-placeholder"}
        )
        fake["vardrrunner.authorization.plan"].compile_gate_plan = Mock(
            return_value=plan
        )
        for module in fake.values():
            module.PRIVATE_UNIT_STUB = True
        reviewed_input, reviewed_context, reviewed_authority = {}, {}, {}
        with patch.dict(sys.modules, fake):
            result = owner.approve(
                "count-a",
                "engagement",
                "authorization",
                "job",
                {"spec": {}},
                local_grants=False,
                review_snapshot=reviewed_input,
                review_context=reviewed_context,
                review_authority=reviewed_authority,
            )
        self.assertEqual(result, (runner, "enrolled"))
        self.assertEqual(reviewed_authority, authority)
        self.assertEqual(reviewed_context, context)
        self.assertEqual(reviewed_input["plan"], plan)
        self.assertNotIn("synthetic-unusable", json.dumps(reviewed_authority))
        self.assertNotIn("synthetic-unusable", json.dumps(reviewed_input))
        self.assertEqual(owner.helper.call_count, 2)
        self.assertTrue(all(not name.startswith("vardrrunner") for name in sys.modules))
