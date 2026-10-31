"""Offline coverage for the least-privilege PostgreSQL application role.

No Docker, network access or PostgreSQL is required: Compose is replaced by a
recording fake. Run: python -m unittest discover -s tests -p 'test_database_roles.py'
"""

import base64
import contextlib
import hashlib
import hmac
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import database_roles
import recovery

PASSWORD = "a" * 64


class Verifier(unittest.TestCase):
    def test_matches_the_rfc_7677_scram_sha_256_exchange(self):
        # RFC 7677 section 3: user "user", password "pencil".
        salt = base64.b64decode("W22ZaJ0SNY7soEsUEjb6gQ==")
        verifier = database_roles.scram_verifier("pencil", salt)
        head, keys = verifier.rsplit("$", 1)
        stored, server = (base64.b64decode(k) for k in keys.split(":"))
        self.assertEqual(head, "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==")
        message = (
            "n=user,r=rOprNGfwEbeRWgbNEkqO,"
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
            "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,c=biws,"
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
        ).encode()
        signature = base64.b64encode(hmac.new(server, message, "sha256").digest())
        self.assertEqual(signature, b"6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
        proof = base64.b64decode("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
        client_key = bytes(
            a ^ b for a, b in zip(proof, hmac.new(stored, message, "sha256").digest())
        )
        self.assertEqual(hashlib.sha256(client_key).digest(), stored)

    def test_each_verifier_has_its_own_salt_and_never_contains_the_password(self):
        first = database_roles.scram_verifier(PASSWORD)
        second = database_roles.scram_verifier(PASSWORD)
        self.assertNotEqual(first, second)
        self.assertNotIn(PASSWORD, first)


class Sql(unittest.TestCase):
    def test_role_is_unprivileged_and_the_script_is_one_transaction(self):
        sql = database_roles.role_sql(PASSWORD)
        for attribute in (
            "NOSUPERUSER",
            "NOCREATEDB",
            "NOCREATEROLE",
            "NOREPLICATION",
            "NOBYPASSRLS",
        ):
            self.assertIn(attribute, sql)
        self.assertNotIn(PASSWORD, sql)
        self.assertNotIn("__VERIFIER__", sql)
        self.assertIn("PASSWORD 'SCRAM-SHA-256$4096:", sql)
        self.assertEqual(sql.count("BEGIN;"), 1)
        self.assertTrue(sql.rstrip().endswith("COMMIT;"))
        self.assertLess(sql.index("SET log_min_error_statement"), sql.index("BEGIN;"))
        self.assertNotIn("SUPERUSER;", sql.replace("NOSUPERUSER", ""))
        self.assertNotIn("CREATEDB", sql.replace("NOCREATEDB", ""))
        self.assertNotIn("DROP ", sql)

    def test_a_trailer_runs_inside_the_transaction(self):
        sql = database_roles.role_sql(PASSWORD, "SELECT 1/0;\n")
        self.assertLess(sql.index("SELECT 1/0;"), sql.rindex("COMMIT;"))

    def test_passwords_outside_the_safe_alphabet_are_refused(self):
        for bad in ("", "short", "a" * 31, "a" * 129, "a" * 40 + "'", "a" * 40 + " ;"):
            with self.assertRaises(ValueError):
                database_roles.check_password(bad)
        self.assertEqual(database_roles.check_password(PASSWORD), PASSWORD)


class EnvironmentFile(unittest.TestCase):
    def test_reads_the_last_value_and_reports_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "configure"):
                database_roles.read_password(root)
            (root / ".env").write_text("POSTGRES_PASSWORD=x\n")
            self.assertIsNone(database_roles.read_password(root))
            (root / ".env").write_text(f"POSTGRES_APP_PASSWORD={PASSWORD}\n")
            self.assertEqual(database_roles.read_password(root), PASSWORD)
            (root / ".env").write_text("POSTGRES_APP_PASSWORD=bad value\n")
            with self.assertRaises(ValueError):
                database_roles.read_password(root)

    def test_append_keeps_existing_content_and_adds_a_missing_newline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_bytes(b"A=1\nPOSTGRES_PASSWORD=keep")
            database_roles.append_password(root, PASSWORD)
            self.assertEqual(
                (root / ".env").read_bytes(),
                b"A=1\nPOSTGRES_PASSWORD=keep\n"
                + f"POSTGRES_APP_PASSWORD={PASSWORD}\n".encode(),
            )
            self.assertEqual(database_roles.read_password(root), PASSWORD)

    def test_credential_is_visible_only_while_the_block_runs(self):
        import os

        os.environ.pop("POSTGRES_APP_PASSWORD", None)
        with database_roles.credential(PASSWORD):
            self.assertEqual(os.environ["POSTGRES_APP_PASSWORD"], PASSWORD)
        self.assertNotIn("POSTGRES_APP_PASSWORD", os.environ)


class ComposeContract(unittest.TestCase):
    """The API must never be configured with the administrator."""

    def test_api_uses_the_application_role_and_never_the_administrator_password(self):
        text = (Path(__file__).resolve().parents[1] / "compose.yaml").read_text(
            encoding="utf-8"
        )
        api = text.split("\n  api:\n", 1)[1].split("\n  web:\n", 1)[0]
        url = next(l for l in api.splitlines() if l.strip().startswith("DATABASE_URL:"))
        self.assertIn("postgresql://vardrmap_app:${POSTGRES_APP_PASSWORD:?", url)
        self.assertNotIn("POSTGRES_PASSWORD", api)
        self.assertNotIn("postgresql://vardrmap:", api)


class FakeCompose:
    """Records Compose calls and answers the module's queries."""

    def __init__(self, role=False, objects=0, foreign=0, running=(), fail_sql=False):
        self.state = f"{int(role)}|{objects}|{foreign}\n"
        self.running = running
        self.fail_sql = fail_sql
        self.calls = []
        self.inputs = []

    def __call__(self, root, *args, project=None, **kwargs):
        self.calls.append(args)
        if args[:1] == ("ps",):
            return subprocess.CompletedProcess([], 0, stdout="\n".join(self.running))
        if args[:1] == ("up",):
            return subprocess.CompletedProcess([], 0, stdout="")
        text = " ".join(args)
        if "-f -" in text:
            self.inputs.append(kwargs["input"])
            if self.fail_sql:
                raise subprocess.CalledProcessError(
                    3,
                    ["docker"],
                    stderr="psql: ERROR:  boom\nLINE 1: ALTER ROLE ... PASSWORD 'SCRAM-SHA-256$4096:AAAA$BBBB:CCCC'",
                )
            return subprocess.CompletedProcess([], 0, stdout="")
        if "-U vardrmap_app" in text:
            return subprocess.CompletedProcess([], 0, stdout="f|f|f|f|f|0|0|vardrmap_app\n")
        return subprocess.CompletedProcess([], 0, stdout=self.state)


class Apply(unittest.TestCase):
    def run_apply(self, fake, env="POSTGRES_PASSWORD=keep\n", **options):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text(env)
            with patch.object(recovery, "compose", fake):
                try:
                    result = database_roles.apply(root, "p", **options)
                    error = None
                except ValueError as exc:
                    result, error = None, exc
            return result, error, (root / ".env").read_text()

    def test_fresh_database_needs_no_backup_and_stores_a_new_password(self):
        fake = FakeCompose()
        result, error, env = self.run_apply(fake)
        self.assertIsNone(error)
        self.assertTrue(result["created_password"])
        self.assertEqual(len(fake.inputs), 1)
        password = database_roles.parse_password(env)
        self.assertNotIn(password, fake.inputs[0])

    def test_an_existing_password_is_reused_and_never_rewritten(self):
        env = f"POSTGRES_APP_PASSWORD={PASSWORD}\n"
        result, error, after = self.run_apply(FakeCompose(role=True), env=env)
        self.assertIsNone(error)
        self.assertFalse(result["created_password"])
        self.assertEqual(after, env)

    def test_existing_data_without_a_backup_changes_nothing(self):
        fake = FakeCompose(objects=40, foreign=40)
        _, error, env = self.run_apply(fake)
        self.assertRegex(str(error), "Take a backup")
        self.assertEqual(fake.inputs, [])
        self.assertEqual(env, "POSTGRES_PASSWORD=keep\n")

    def test_running_applications_block_an_ownership_change(self):
        fake = FakeCompose(objects=40, foreign=40, running=("db", "api"))
        _, error, env = self.run_apply(fake)
        self.assertRegex(str(error), "stop api")
        self.assertEqual(fake.inputs, [])
        self.assertEqual(env, "POSTGRES_PASSWORD=keep\n")

    def test_a_backup_that_no_longer_matches_is_refused(self):
        fake = FakeCompose(objects=40, foreign=40)
        with (
            patch.object(recovery, "validate", return_value={"database": {"t": "1"}}),
            patch.object(recovery, "database_fingerprint", return_value={"t": "2"}),
        ):
            _, error, env = self.run_apply(fake, backup=Path("backup"))
        self.assertRegex(str(error), "does not match")
        self.assertEqual(fake.inputs, [])
        self.assertEqual(env, "POSTGRES_PASSWORD=keep\n")

    def test_a_matching_backup_allows_the_change(self):
        fake = FakeCompose(objects=40, foreign=40)
        with (
            patch.object(recovery, "validate", return_value={"database": {"t": "1"}}),
            patch.object(recovery, "database_fingerprint", return_value={"t": "1"}),
        ):
            result, error, _ = self.run_apply(fake, backup=Path("backup"))
        self.assertIsNone(error)
        self.assertEqual(result["reassigned"], 40)
        self.assertEqual(len(fake.inputs), 1)

    def test_restoring_hands_over_data_without_a_backup_or_stopped_services(self):
        fake = FakeCompose(objects=40, foreign=40, running=("api",))
        result, error, _ = self.run_apply(fake, restoring=True)
        self.assertIsNone(error)
        self.assertEqual(result["reassigned"], 40)

    def test_repeat_run_with_everything_owned_needs_no_backup(self):
        env = f"POSTGRES_APP_PASSWORD={PASSWORD}\n"
        fake = FakeCompose(role=True, objects=40, foreign=0, running=("api", "web"))
        result, error, _ = self.run_apply(fake, env=env)
        self.assertIsNone(error)
        self.assertEqual(result["reassigned"], 0)

    def test_sql_failure_reports_no_secret_and_keeps_a_new_password_recoverable(self):
        fake = FakeCompose(fail_sql=True)
        _, error, env = self.run_apply(fake)
        message = str(error)
        self.assertIn("boom", message)
        self.assertNotIn("SCRAM", message)
        self.assertNotIn("LINE 1", message)
        # The credential was stored before the transaction so a retry reuses it.
        self.assertIsNotNone(database_roles.parse_password(env))

    def test_verification_failure_is_reported_without_values(self):
        class Wrong(FakeCompose):
            def __call__(self, root, *args, **kwargs):
                if "-U vardrmap_app" in " ".join(args):
                    return subprocess.CompletedProcess(
                        [], 0, stdout="t|f|f|f|f|0|0|vardrmap_app\n"
                    )
                return super().__call__(root, *args, **kwargs)

        _, error, _ = self.run_apply(Wrong())
        self.assertRegex(str(error), "rolsuper")
        self.assertNotIn(PASSWORD, str(error))

    def test_restore_of_a_pre_role_configuration_leaves_it_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text("POSTGRES_PASSWORD=keep\n")
            with (
                patch.object(recovery, "compose") as compose,
                contextlib.redirect_stdout(io.StringIO()) as out,
            ):
                database_roles.restore_role(root, "p")
            self.assertIn("pre-role configuration", out.getvalue())
            compose.assert_not_called()


if __name__ == "__main__":
    unittest.main()
