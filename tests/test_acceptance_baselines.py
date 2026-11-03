"""Offline checks for explicitly selected installed acceptance baselines."""

import ast
import hashlib
import inspect
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import recovery_acceptance
import update_acceptance


class AcceptanceBaselineTests(unittest.TestCase):
    def test_restored_application_requires_exact_selected_head(self):
        for actual, error, calls in (
            ("0038managedstops", RuntimeError, 2),
            ("0031localauth", AssertionError, 1),
        ):
            with (self.subTest(actual=actual), tempfile.TemporaryDirectory() as directory,
                  patch.object(recovery_acceptance.recovery, "compose"),
                  patch.object(recovery_acceptance.recovery, "sql", side_effect=[actual, RuntimeError("past exact head check")]) as sql):
                restored = Path(directory)
                (restored / "trust").mkdir()
                (restored / "trust/root.crt").write_bytes(b"synthetic public CA")
                fingerprint = hashlib.sha256(b"synthetic public CA").hexdigest()
                with self.assertRaises(error):
                    recovery_acceptance.verify_application(restored, fingerprint, {}, "0038managedstops")
                self.assertEqual(sql.call_count, calls)

    def test_legacy_default_and_current_synthetic_revision_chains(self):
        self.assertEqual(inspect.signature(recovery_acceptance.main).parameters["expected_head"].default, "0031localauth")
        self.assertEqual(inspect.signature(update_acceptance.main).parameters["expected_head"].default, "0031localauth")
        for head, recovery_ids, update_ids in (
            ("0031localauth", ("0032restorefixture", "0033failedfixture"),
             ("0032updatebad", "0032updategood", "0033updatefailed")),
            ("0038managedstops", ("0039restorefixture", "0040failedfixture"),
             ("0039updatebad", "0039updategood", "0040updatefailed")),
        ):
            with self.subTest(head=head):
                self.assertEqual(recovery_acceptance.fixture_revisions(head), recovery_ids)
                self.assertEqual(update_acceptance.fixture_revisions(head), update_ids)
                self.assertNotIn(head, recovery_ids + update_ids)

    def test_wrong_or_unsupported_installed_head_refuses_before_fixture_mutations(self):
        for module in (recovery_acceptance, update_acceptance):
            for head, actual, error in (
                ("0038managedstops", "0031localauth", AssertionError),
                ("0031localauth", "0038managedstops", AssertionError),
                ("unreviewed", "unreviewed", ValueError),
            ):
                with (self.subTest(module=module.__name__, head=head),
                      tempfile.TemporaryDirectory() as directory,
                      patch.object(module, "ROOT", Path(directory)),
                      patch.object(module, "ARTIFACTS", Path(directory) / "not-created"),
                      patch.object(module.recovery, "sql", return_value=actual),
                      patch.object(module.recovery, "compose") as compose,
                      patch.object(module.recovery, "command") as command):
                    with self.assertRaises(error):
                        module.main(head)
                    self.assertFalse(module.ARTIFACTS.exists())
                    compose.assert_not_called()
                    command.assert_not_called()

    def test_generated_current_fixture_children_have_exact_parent_revision(self):
        for module in (recovery_acceptance, update_acceptance):
            with (self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as directory,
                  patch.object(module, "ARTIFACTS", Path(directory)),
                  patch.object(module.recovery, "command", return_value=subprocess.CompletedProcess([], 0, stdout="sha256:fixture"))):
                ids = module.fixture_revisions("0038managedstops")
                if module is recovery_acceptance:
                    module.candidate("first", "0038managedstops", ids[0])
                    module.candidate("failure", ids[0], ids[1], fail=True)
                    expected = (("first", "0038managedstops", ids[0]), ("failure", ids[0], ids[1]))
                else:
                    module.image("bad", "0038managedstops", ids[0], "synthetic:base", "raise RuntimeError('fixture')")
                    module.image("good", "0038managedstops", ids[1], "synthetic:base")
                    module.image("failure", ids[1], ids[2], "synthetic:good", "raise RuntimeError('fixture')")
                    expected = (("bad", "0038managedstops", ids[0]), ("good", "0038managedstops", ids[1]), ("failure", ids[1], ids[2]))
                for name, parent, revision in expected:
                    tree = ast.parse((Path(directory) / name / "migration.py").read_text())
                    values = {n.targets[0].id: ast.literal_eval(n.value)
                              for n in tree.body if isinstance(n, ast.Assign)
                              and isinstance(n.targets[0], ast.Name)
                              and n.targets[0].id in {"revision", "down_revision"}}
                    self.assertEqual(values, {"revision": revision, "down_revision": parent})


if __name__ == "__main__":
    unittest.main()
