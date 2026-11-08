import copy
import json
import unittest
from unittest.mock import patch

import test_worker_lifecycle_intent as cases
import worker_host as host
import worker_lifecycle_intent as intent


class FirstEnableEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.f = cases.LifecycleIntentTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def bootstrap_document(self, **changes):
        return {
            "schema": "vardr.worker-bootstrap-audit/1",
            "status": "clear",
            "reason": None,
            "complete": True,
            "runner_id": self.f.row["registration_policy"]["runner_id"],
            "worker_history": False,
            "global_holds": 0,
            **changes,
        }

    def first(self, operation, *, output=None, returncode=0):
        audit = self.bootstrap_document()
        return self.f.store.first_enable_evidence(
            operation=operation,
            runner_id=audit["runner_id"],
            output=host.canonical(audit) if output is None else output,
            returncode=returncode,
        )

    def initial_intent(self):
        row = copy.deepcopy(self.f.row)
        row["predecessors"] = []
        row["resources"]["expected_ordinal"] = 1
        raw = host.canonical(self.bootstrap_document())
        row["bootstrap_audit_sha256"] = host.digest(self.bootstrap_document())
        return row, raw

    def test_first_intent_requires_the_original_audit_and_keeps_it_immutable(self):
        row, raw = self.initial_intent()
        with self.f.records.operation() as operation:
            with self.assertRaises(intent.IntentRefused):
                self.f.store.create(row, operation=operation)
            self.assertEqual(self.f.backend.calls, [])
            saved = self.f.store.create(row, operation=operation, first_audit=raw)
            self.assertEqual(
                self.f.store.inventory(operation=operation)["intents"],
                {row["operation_id"]: row},
            )
            with self.assertRaises(intent.IntentRefused):
                self.f.next(
                    saved,
                    operation,
                    lambda value: value.update(bootstrap_audit_sha256="a" * 64),
                )
            self.assertEqual(
                self.f.store.read(row["operation_id"], operation=operation), saved
            )
        self.assertEqual(
            host._json(self.f.path.read_bytes())["schema"],
            "vardr.worker-lifecycle-intent/4",
        )

    def test_first_intent_never_treats_a_preexisting_catalog_as_empty(self):
        row, raw = self.initial_intent()
        with self.f.records.operation() as operation:
            self.f.store.create(self.f.row, operation=operation)
            with self.assertRaises(intent.IntentRefused):
                self.f.store.create(row, operation=operation, first_audit=raw)
            self.assertEqual(
                self.f.store.read(row["operation_id"], operation=operation), self.f.row
            )

    def test_first_enable_joins_exact_empty_original_catalog_and_bootstrap_audit(self):
        audit = self.bootstrap_document()
        with self.f.records.operation() as operation:
            self.assertEqual(
                self.first(operation, output=json.dumps(audit, indent=2).encode()),
                {"runner_id": audit["runner_id"], "sha256": host.digest(audit)},
            )
            self.assertEqual(list(self.f.records.directory.iterdir()), [])
        self.assertEqual(self.f.backend.calls, [])

    def test_first_enable_refuses_stale_operation_before_catalog_read(self):
        with self.f.records.operation() as operation:
            pass
        with patch.object(self.f.store, "inventory") as inventory:
            with self.assertRaises(intent.IntentRefused):
                self.first(operation)
            inventory.assert_not_called()

    def test_first_enable_refuses_missing_journal_history_holds_or_bad_types(self):
        with self.f.records.operation() as operation:
            with patch.object(self.f.store, "inventory") as inventory:
                for changes in (
                    dict(
                        status="held",
                        reason="journal_not_initialized",
                        complete=False,
                        worker_history=None,
                        global_holds=None,
                    ),
                    dict(worker_history=True),
                    dict(global_holds=1),
                    dict(global_holds=False),
                    dict(worker_history=0),
                    dict(complete=1),
                    dict(runner_id=cases.PREVIOUS),
                    dict(extra="unused"),
                ):
                    with (
                        self.subTest(changes=changes),
                        self.assertRaises(intent.IntentRefused),
                    ):
                        self.first(
                            operation,
                            output=host.canonical(self.bootstrap_document(**changes)),
                        )
                inventory.assert_not_called()

    def test_first_enable_refuses_nonzero_exit_duplicate_keys_and_oversize_output(self):
        raw = host.canonical(self.bootstrap_document())
        with self.f.records.operation() as operation:
            with patch.object(self.f.store, "inventory") as inventory:
                for output, code in (
                    (raw, 1),
                    (raw, False),
                    (b'{"status":"clear",' + raw[1:], 0),
                    (raw + b" " * 65536, 0),
                    (b"", 0),
                ):
                    with (
                        self.subTest(size=len(output), code=code),
                        self.assertRaises(intent.IntentRefused),
                    ):
                        self.first(operation, output=output, returncode=code)
                inventory.assert_not_called()

    def test_first_enable_holds_unfinished_intent_without_discarding_it(self):
        with self.f.records.operation() as operation:
            self.f.store.create(self.f.row, operation=operation)
            with self.assertRaises(intent.IntentRefused):
                self.first(operation)
        self.assertTrue(self.f.path.exists())
