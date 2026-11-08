"""Existing read-only inventory pass with fake DB/models only; no provider import."""

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import nm2_worker_acceptance as fixture


class CountInventoryContexts(unittest.TestCase):
    def model(self, *, invalid_context=False):
        names = (
            "Engagement",
            "JobExecution",
            "ManagedApproval",
            "ManagedContract",
            "ManagedResult",
            "ManagedRuntime",
            "ManagedRuntimeAttempt",
            "ManagedStop",
            "ScanJob",
        )
        models = {name: type(name, (), {"runtime_sequence": 0}) for name in names}
        context = {
            "expires_at": "2026-11-06T02:05:00Z",
            "max_executions": 1,
            "max_duration_seconds": 30,
            "credential_grants": [],
            "mode": "strict",
        }
        if invalid_context:
            context["malformed"] = float("nan")
        approval = SimpleNamespace(
            id="original-approval",
            job_id="job-1",
            issued=0,
            revoked=False,
            context=context,
            envelope={"payload": "private-envelope-canary"},
        )
        foreign = SimpleNamespace(
            id="foreign-approval",
            job_id="another-job",
            issued=0,
            revoked=False,
            context={"private": "foreign-context-canary"},
        )
        queries, statements = [], []

        class Query:
            def __init__(self, model):
                self.model = model
                self.rows = (
                    [approval, foreign] if model is models["ManagedApproval"] else []
                )

            def filter_by(self, **values):
                self.rows = [
                    row
                    for row in self.rows
                    if all(getattr(row, key) == value for key, value in values.items())
                ]
                return self

            def all(self):
                return self.rows

        class Database:
            rolled_back = False

            def __enter__(self):
                return self

            def __exit__(self, *unused):
                return False

            def execute(self, statement):
                statements.append(statement)
                return SimpleNamespace(
                    scalar_one=lambda: (
                        "0041persistentruntime"
                        if "version_num" in statement
                        else "vardrmap_app"
                    )
                )

            def get(self, model, identifier):
                if model is models["Engagement"]:
                    return SimpleNamespace(
                        id=identifier, targets_spent=0, duration_allocated=0
                    )
                if model is models["ScanJob"]:
                    return SimpleNamespace(
                        id=identifier, program_id="eng-1", status="pending"
                    )
                return None

            def query(self, model):
                queries.append(model.__name__)
                return Query(model)

            def rollback(self):
                self.rolled_back = True

        database = Database()
        session = Mock(return_value=database)
        spec = importlib.util.spec_from_file_location(
            "count_inventory_private_unit",
            Path(fixture.__file__).with_name("nm2_worker_inventory.py"),
        )
        module = importlib.util.module_from_spec(spec)
        stubs = {
            "models": SimpleNamespace(**models),
            "db": SimpleNamespace(SessionLocal=session),
            "sqlalchemy": SimpleNamespace(text=lambda value: value),
            "managed_wire": SimpleNamespace(
                unb64=lambda *unused: b"synthetic",
                parse=lambda *unused: {"approved_at": "2026-11-06T02:00:00Z"},
            ),
        }
        with patch.dict(sys.modules, stubs):
            spec.loader.exec_module(module)
        return SimpleNamespace(
            module=module,
            context=context,
            database=database,
            session=session,
            statements=statements,
            queries=queries,
            stubs=stubs,
        )

    def test_count_schema4_adds_only_registered_context_digest_in_same_read_pass(self):
        for count in (False, True):
            with self.subTest(count=count):
                data = self.model()
                selection = {
                    "engagement_id": "eng-1",
                    "job_id": "job-1",
                    "runtime_attempt_bound": 35,
                }
                if count:
                    selection["count_approval_contexts"] = True
                with patch.dict(sys.modules, data.stubs):
                    observed = data.module.observe(selection)
                self.assertEqual(
                    observed["schema"],
                    "vardr.nm2-fixture-inventory/4"
                    if count
                    else "vardr.nm2-fixture-inventory/3",
                )
                self.assertEqual(len(observed["approvals"][0]), 8)
                self.assertNotIn("count_approval_contexts", observed)
                if count:
                    self.assertEqual(
                        observed["approval_context_sha256"],
                        {
                            "original-approval": fixture.digest(
                                fixture.canonical(data.context)
                            )
                        },
                    )
                else:
                    self.assertNotIn("approval_context_sha256", observed)
                self.assertEqual(data.queries.count("ManagedApproval"), 1)
                self.assertEqual(data.statements[0], "SET TRANSACTION READ ONLY")
                self.assertTrue(data.database.rolled_back)
                self.assertNotIn("private-", json.dumps(observed))
                self.assertNotIn("foreign-", json.dumps(observed))

    def test_count_flag_is_exact_paired_and_rejects_before_any_database_read(self):
        base = {
            "engagement_id": "eng-1",
            "job_id": "job-1",
            "runtime_attempt_bound": 35,
            "count_approval_contexts": True,
        }
        changes = [
            dict(base, count_approval_contexts=False),
            dict(base, count_approval_contexts="true"),
            dict(base, runtime_attempt_bound=True),
            dict(base, runtime_attempt_bound=1),
            dict(base, unreviewed=True),
        ]
        missing = dict(base)
        missing.pop("runtime_attempt_bound")
        changes.append(missing)
        for selection in changes:
            with self.subTest(selection=selection):
                data = self.model()
                with self.assertRaises(ValueError):
                    data.module.observe(selection)
                data.session.assert_not_called()

    def test_noncanonical_registered_context_refuses_and_rolls_back(self):
        data = self.model(invalid_context=True)
        with patch.dict(sys.modules, data.stubs), self.assertRaises(ValueError):
            data.module.observe(
                {
                    "engagement_id": "eng-1",
                    "job_id": "job-1",
                    "runtime_attempt_bound": 35,
                    "count_approval_contexts": True,
                }
            )
        self.assertTrue(data.database.rolled_back)

    def test_reader_maps_require_exact_approval_ids_typed_hashes_and_original_context(
        self,
    ):
        context = {"public": "context"}
        valid = {
            "schema": "vardr.nm2-fixture-inventory/4",
            "approvals": [{"id": "original"}],
            "approval_context_sha256": {
                "original": fixture.digest(fixture.canonical(context))
            },
        }
        fixture.count_approval_context(valid, context)
        changes = [
            dict(valid, schema="vardr.nm2-fixture-inventory/3"),
            dict(valid, approval_context_sha256={}),
            dict(valid, approval_context_sha256={"foreign": "0" * 64}),
            dict(valid, approval_context_sha256={"original": True}),
            dict(valid, approval_context_sha256={"original": "0" * 64}),
            dict(
                valid,
                approval_context_sha256={
                    **valid["approval_context_sha256"],
                    "extra": "0" * 64,
                },
            ),
        ]
        for value in changes:
            with (
                self.subTest(value=value),
                self.assertRaises(fixture.AcceptanceRefused),
            ):
                fixture.count_approval_context(value, context)
        with self.assertRaises(fixture.AcceptanceRefused):
            fixture.count_approval_context(valid, {"public": "another"})

    def test_existing_inventory_command_adds_count_flag_only_for_explicit_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner = object.__new__(fixture.Fixture)
            owner.install = Path(temporary)
            (owner.install / "tests").mkdir()
            (owner.install / "tests/nm2_worker_inventory.py").write_text(
                "# inert source fixture\n"
            )
            owner.compose = Mock(return_value=b"{}")
            for scenario, protocol in (
                ("healthy", "finite-v2"),
                ("persistent-availability", "persistent-v3"),
                ("persistent-count-limit", "persistent-v3"),
            ):
                with self.subTest(scenario=scenario):
                    owner.scenario, owner.protocol = scenario, protocol
                    owner.inventory("eng-1", "job-1")
                    selection = json.loads(owner.compose.call_args.kwargs["stdin"])
                    self.assertEqual(
                        selection.get("count_approval_contexts"),
                        True if scenario == "persistent-count-limit" else None,
                    )
                    self.assertEqual(
                        selection.get("runtime_attempt_bound"),
                        35 if protocol == "persistent-v3" else None,
                    )
