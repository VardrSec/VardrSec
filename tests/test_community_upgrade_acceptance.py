"""Offline contract tests; no installed-stack acceptance is implied."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import community_upgrade_acceptance as drill


class CommunityUpgradeTests(unittest.TestCase):
    def test_state_snapshot_prepares_stopped_runner_without_execution(self):
        calls = []
        def lookup(root, service, project):
            self.assertEqual(calls, ["create"])
            return {"Mounts": [{"Type": "volume", "Name": name, "Destination": mount}
                for name, (owner, mount) in drill.recovery.VOLUMES.items() if owner == service]}
        with patch.object(drill.recovery, "compose", side_effect=lambda *a, **kw: calls.append(a[1])) as compose, patch.object(
            drill.recovery, "container", side_effect=lookup), patch.object(
                drill.recovery, "volume_fingerprint", side_effect=lambda image, volume: volume):
            result = drill.state_fingerprints(Path("/synthetic"), "owned", {"runner": "immutable"})
        compose.assert_called_once_with(Path("/synthetic"), "create", "--no-build", "--no-recreate",
            "--pull", "never", "runner", project="owned", capture_output=True, text=True)
        self.assertEqual(set(result), set(drill.recovery.VOLUMES))

    def test_failed_runner_preparation_does_not_read_state(self):
        with patch.object(drill.recovery, "compose", side_effect=ValueError("fixture preparation failed")), patch.object(
            drill.recovery, "container") as lookup:
            with self.assertRaises(ValueError):
                drill.state_fingerprints(Path("/synthetic"), "owned", {"runner": "immutable"})
        lookup.assert_not_called()

    def test_sequence_snapshot_includes_definition_and_is_called(self):
        metadata = [{"sequencename": 'odd"sequence', "increment_by": 1, "last_value": 4}]
        with patch.object(drill.recovery, "sql", side_effect=[json.dumps(metadata), "4|t"]) as sql:
            snapshot = drill.sequences(Path("unused"), "owned")
        self.assertEqual(snapshot, [{"definition": metadata[0], "state": "4|t"}])
        self.assertIn('SELECT last_value,is_called FROM public."odd""sequence"', sql.call_args.args[1])

    def test_anonymous_readback_requires_authentication_denial(self):
        for status in (401, 403, 404, 500, 200):
            with (self.subTest(status=status),
                  patch.object(drill.ssl, "create_default_context"),
                  patch.object(drill.urllib.request, "build_opener") as opener):
                if status != 200:
                    opener.return_value.open.side_effect = urllib.error.HTTPError("https://localhost:8443", status, "synthetic", {}, None)
                if status in (401, 403):
                    drill.verify_anonymous_denied("https://localhost:8443", Path("synthetic-public-ca"))
                else:
                    with self.assertRaises(ValueError):
                        drill.verify_anonymous_denied("https://localhost:8443", Path("synthetic-public-ca"))

    def test_source_scope_requires_exact_owned_ci_copy_and_project(self):
        root = Path("/fresh-ci-temp/community-run")
        with (patch.object(drill, "ROOT", root),
              patch.dict(os.environ, {"RUNNER_TEMP": "/fresh-ci-temp"}),
              patch.object(drill.acceptance_retention, "enabled", return_value=True)):
            drill.require_owned_source(root, "vardrsec-compose-review")
            for path, project in ((root, "unrelated"), (root.parent / "other", "vardrsec-compose-review")):
                with self.subTest(path=path, project=project), self.assertRaises(ValueError):
                    drill.require_owned_source(path, project)
        with (patch.object(drill, "ROOT", root),
              patch.dict(os.environ, {"RUNNER_TEMP": "/fresh-ci-temp"}),
              patch.object(drill.acceptance_retention, "enabled", return_value=False)):
            with self.assertRaises(ValueError):
                drill.require_owned_source(root, "vardrsec-compose-review")

    def test_telemetry_exception_is_one_column_of_exact_owned_key_only(self):
        key_id = "11111111-1111-4111-8111-111111111111"
        names = ["id", "github_id", "key_hash", "label", "scope", "created_at", "last_used_at"]
        with patch.object(drill.recovery, "sql", return_value="a" * 64) as sql:
            drill.projected_rows(Path("unused"), "owned", {"api_keys": names, "users": ["id", "created_at"]}, key_id)
        key_sql, user_sql = [call.args[1] for call in sql.call_args_list]
        self.assertEqual(key_sql.count("CASE WHEN"), 1)
        self.assertIn(f'CASE WHEN "id"=\'{key_id}\' THEN NULL ELSE "last_used_at" END AS "last_used_at"', key_sql)
        for authority in names[:-1]:
            self.assertIn('"' + authority + '"', key_sql)
        self.assertNotIn("CASE WHEN", user_sql)
        # Every non-normalized old-row digest remains mandatory, including any
        # other key's timestamp and this key's scope/hash/owner/creation time.
        with self.assertRaises(ValueError):
            drill.assert_retained({"api_keys": ["a" * 64, "b" * 64]}, {"api_keys": ["a" * 64, "c" * 64]})

    def test_diagnostic_telemetry_requires_single_key_and_valid_bounded_use(self):
        before = {"count": 1, "last_used_at": None, "observed_at": "2026-11-03T00:00:01"}
        after = {"count": 1, "last_used_at": "2026-11-03T00:00:02", "observed_at": "2026-11-03T00:00:03"}
        drill.assert_key_telemetry(before, after)
        for change in ({"count": 0}, {"count": True}, {"last_used_at": None}, {"last_used_at": "garbage"}, {"last_used_at": "2026-11-03T00:00:00"}, {"last_used_at": "2026-11-03T00:00:04"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                drill.assert_key_telemetry(before, {**after, **change})
        with self.assertRaises(ValueError):
            drill.assert_key_telemetry({**before, "last_used_at": "2026-11-03T00:00:05"}, after)

    def test_projection_quotes_original_columns_and_keeps_duplicate_rows(self):
        digest = "a" * 64
        with patch.object(drill.recovery, "sql", return_value="SET\n" + digest + "\n" + digest) as sql:
            rows = drill.projected_rows(Path("unused"), "owned", {'odd"table': ['odd"column'], "alembic_version": ["version_num"]})
        self.assertEqual(rows, {'odd"table': [digest, digest]})
        self.assertIn('SELECT "odd""column" FROM public."odd""table"', sql.call_args.args[1])
        with self.assertRaises(ValueError):
            drill.assert_retained(rows, {'odd"table': [digest]})
        drill.assert_retained(rows, {'odd"table': [digest, digest, "b" * 64]})
        with patch.object(drill.recovery, "sql", return_value="raw fixture row"):
            with self.assertRaises(ValueError):
                drill.projected_rows(Path("unused"), "owned", {"table": ["id"]})

    def execute(self, sequence_changed=False, candidate_changed=False, updater_fails=False):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            (root / "versions.json").write_text(json.dumps({"components": {key: {"commit": value} for key, value in drill.OLD.items()}}))
            (root / "trust").mkdir()
            (root / "trust/root.crt").write_text("synthetic public CA")
            (root / "artifacts/installed-gate").mkdir(parents=True)
            (root / "artifacts/installed-gate/accepted.json").write_text("{}")
            candidate_path = root / "candidate.json"
            candidate = {"components": dict(drill.CURRENT), "images": {s: "sha256:" + "a" * 64 for s in drill.recovery.SERVICES}}
            if candidate_changed:
                candidate["components"]["map"] = "0" * 40
            candidate_path.write_text(json.dumps(candidate))
            config = {"name": "vardrsec-compose-review", "services": {"web": {"environment": {"AUTH_URL": "https://localhost:8443"}}}}
            stack.enter_context(patch.object(drill.updater, "image_set", return_value=(config, candidate["images"])))
            stack.enter_context(patch.object(drill.updater, "candidate_set", return_value=candidate))
            stack.enter_context(patch.object(drill.recovery, "sql", side_effect=["0031localauth", "0038managedstops"]))
            stack.enter_context(patch.object(drill, "require_owned_source"))
            stack.enter_context(patch.object(drill, "key_telemetry", side_effect=[{
                "count": 1, "last_used_at": None, "observed_at": "2026-11-03T00:00:00"}, {
                "count": 1, "last_used_at": "2026-11-03T00:00:01", "observed_at": "2026-11-03T00:00:02"}]))
            client = stack.enter_context(patch.object(drill, "operator_client"))
            def request(path, data=None, csrf=None):
                return {"csrfToken": "private-csrf"} if path.endswith("session") else {"token": "private-disposable-key", "id": "11111111-1111-4111-8111-111111111111"}
            client.return_value = request
            stack.enter_context(patch.object(drill, "verify_retained"))
            stack.enter_context(patch.object(drill, "verify_anonymous_denied"))
            stack.enter_context(patch.object(drill, "columns", return_value={"users": ["id"]}))
            stack.enter_context(patch.object(drill, "projected_rows", return_value={"users": ["a" * 64]}))
            stack.enter_context(patch.object(drill, "sequences", side_effect=["sequence|1", "sequence|2" if sequence_changed else "sequence|1"]))
            stack.enter_context(patch.object(drill, "state_fingerprints", return_value={"runner-state": "synthetic"}))
            stack.enter_context(patch.object(drill.database_roles, "read_password", return_value="private-app-password"))
            stack.enter_context(patch.object(drill.database_roles, "verify"))
            # No Docker transport is available to this test, even accidentally.
            stack.enter_context(patch.object(drill.recovery, "command", side_effect=AssertionError("Docker forbidden in offline test")))
            def update(actual_root, path, backup, rehearsal, project):
                self.assertEqual(actual_root, root)
                self.assertEqual(path, candidate_path)
                self.assertEqual(os.environ["VARDRMAP_API_KEY"], "private-disposable-key")
                if updater_fails:
                    raise ValueError("synthetic updater failure")
                backup.mkdir()
                (backup / "snapshot.json").write_text("{}")
                (root / ".last-update.json").write_text(json.dumps({"status": "success", "candidate": candidate}))
            updater = stack.enter_context(patch.object(drill.updater, "update", side_effect=update))
            stack.enter_context(patch.dict(os.environ, {"VARDRMAP_API_KEY": "previous-private-key"}))
            output = root / "evidence"
            if sequence_changed or candidate_changed or updater_fails:
                with self.assertRaises(ValueError):
                    drill.run(root, candidate_path, output, "vardrsec-restore-nm2-community-unit")
            else:
                drill.run(root, candidate_path, output, "vardrsec-restore-nm2-community-unit")
            self.assertEqual(os.environ["VARDRMAP_API_KEY"], "previous-private-key")
            if candidate_changed:
                updater.assert_not_called()
                client.assert_not_called()
                self.assertFalse(output.exists())
            else:
                updater.assert_called_once()
                report = json.loads((output / ("failure.json" if sequence_changed or updater_fails else "result.json")).read_text())
                self.assertEqual(report["status"], "failed" if sequence_changed or updater_fails else "passed")
                self.assertFalse(report["acceptance_claimed"])
                for value in ("private-disposable-key", "previous-private-key", "private-app-password", "private-csrf"):
                    self.assertNotIn(value, json.dumps(report))
                if not sequence_changed and not updater_fails:
                    self.assertEqual(report["final_revision"], "0038managedstops")
                    self.assertIn("Not seeded", report["nm2_nonempty_state"])

    def test_normal_updater_receipt_and_private_key_scope(self):
        self.execute()

    def test_changed_sequence_refuses_success_receipt(self):
        self.execute(sequence_changed=True)

    def test_wrong_component_candidate_refuses_before_operator_reset(self):
        self.execute(candidate_changed=True)

    def test_updater_failure_restores_key_and_writes_only_sanitized_failure(self):
        self.execute(updater_fails=True)


if __name__ == "__main__":
    unittest.main()
