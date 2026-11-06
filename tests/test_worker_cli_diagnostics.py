"""Fixed CLI failure evidence; no Docker, credentials, signals or HTTP calls."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import test_worker_cli as fixtures
import worker_cli as cli


PRIVATE = "private-canary-password-capability-path-header-body"


class PrivateFailure(Exception):
    def __str__(self):
        raise AssertionError("exception messages must never be rendered")


class WorkerCLIDiagnostics(unittest.TestCase):
    def arguments(self, root, f):
        values = {
            "api-url": f.record["client"]["base_url"],
            "ca": f.record["client"]["ca_file"],
            "private-root": str(root),
            "context": f.observer.context,
            "container-id": f.identity.container_id,
            "image-id": f.identity.image_id,
            "project": f.identity.project,
            "trust-source": str(f.trust),
            "admission-source": str(f.public),
            "state-volume": f.observer.layout.state_volume,
            "readiness-volume": f.observer.layout.readiness_volume,
            "enrollment-id": "enrollment-1",
            "runner-id": fixtures.RUNNER,
            "origin": "https://vardrsec.localhost:8443/backend",
            "public-trust": str(root / "reviewed-public-trust.json"),
            "runtime-id": fixtures.RID,
        }
        return [
            "enable",
            *[item for key, value in values.items() for item in ("--" + key, value)],
        ]

    def invoke(self, arguments, root):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = cli.main(arguments, installation=root)
        self.assertNotIn(PRIVATE, output.getvalue() + errors.getvalue())
        self.assertEqual(errors.getvalue(), "")
        return code, json.loads(output.getvalue())

    def test_enable_boundaries_report_fixed_phase_without_publication_or_retry(self):
        scenarios = (
            ("public_trust", "enable_inputs", "validation_refused"),
            ("observer", "enable_observer_setup", "runtime_refused"),
            ("client", "enable_api_setup", "host_refused"),
            ("records", "enable_custody", "secret_custody_refused"),
            ("owner", "enable_owner_auth", "operation_failed"),
            ("capture", "enable_capture", "runtime_refused"),
            ("register", "enable_registration", "host_refused"),
            ("read", "enable_publication_checks", "host_refused"),
            ("recapture", "enable_recapture", "runtime_refused"),
            ("mounts", "enable_mount_custody", "runtime_refused"),
            ("publish", "enable_publish_trust", "local_io_failed"),
        )
        for boundary, phase, reason in scenarios:
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as t:
                root = Path(t)
                f = fixtures.WorkerCLI().fixture(root)
                observer = Mock(return_value=f.observer)
                client = Mock(return_value=f.client)
                records = Mock(return_value=f.records)
                owner = Mock(return_value=contextlib.nullcontext(Mock()))
                public_trust = Mock(return_value=b"reviewed-public-trust")
                register = Mock(return_value=f.record["admission"])
                publish = Mock()
                if boundary == "public_trust":
                    public_trust.side_effect = cli.CLIRefused(PRIVATE)
                elif boundary == "observer":
                    observer.side_effect = cli.runtime.RuntimeRefused(PRIVATE)
                elif boundary == "client":
                    client.side_effect = cli.host.HostRefused(PRIVATE)
                elif boundary == "records":
                    records.side_effect = cli.host.custody.SecretRefused(PRIVATE)
                elif boundary == "owner":
                    owner.side_effect = PrivateFailure(PRIVATE)
                elif boundary == "capture":
                    f.observer.capture_running = Mock(
                        side_effect=cli.runtime.RuntimeRefused(PRIVATE)
                    )
                elif boundary == "register":
                    register.side_effect = cli.host.HostRefused(PRIVATE)
                elif boundary == "read":
                    f.records.read = Mock(side_effect=cli.host.HostRefused(PRIVATE))
                elif boundary == "recapture":
                    f.observer.capture_running = Mock(
                        side_effect=[
                            f.identity,
                            cli.runtime.RuntimeRefused(PRIVATE),
                        ]
                    )
                elif boundary == "mounts":
                    f.records.outside_mounts.side_effect = cli.runtime.RuntimeRefused(
                        PRIVATE
                    )
                else:
                    publish.side_effect = OSError(PRIVATE)
                with (
                    patch.object(cli, "public_trust", public_trust),
                    patch.object(cli.runtime, "LocalDocker", observer),
                    patch.object(cli.host, "HostClient", client),
                    patch.object(cli, "records_for", records),
                    patch.object(cli, "owner", owner),
                    patch.object(cli.host, "register_runtime", register),
                    patch.object(cli, "publish_public", publish),
                    patch.object(cli.host, "_client"),
                    patch.object(cli.host, "_observer"),
                    patch.object(cli.host, "replay_registration") as replay,
                ):
                    code, reply = self.invoke(self.arguments(root, f), root)
                self.assertEqual(code, 1)
                self.assertEqual(
                    reply,
                    {
                        "schema": "vardr.worker-cli/1",
                        "state": "held",
                        "runtime_id": fixtures.RID,
                        "failure_phase": phase,
                        "failure_code": reason,
                    },
                )
                self.assertLessEqual(register.call_count, 1)
                replay.assert_not_called()
                self.assertFalse((f.public / "admission.json").exists())
                if boundary != "publish":
                    publish.assert_not_called()

    def test_admission_publication_failure_keeps_trust_but_never_retries(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            f = fixtures.WorkerCLI().fixture(root)
            original = cli.publish_public

            def publish(path, data):
                if path.name == "admission.json":
                    raise OSError(PRIVATE)
                original(path, data)

            with (
                patch.object(cli, "public_trust", return_value=b"public-trust"),
                patch.object(cli.runtime, "LocalDocker", return_value=f.observer),
                patch.object(cli.host, "HostClient", return_value=f.client),
                patch.object(cli, "records_for", return_value=f.records),
                patch.object(cli, "owner", return_value=contextlib.nullcontext(Mock())),
                patch.object(
                    cli.host, "register_runtime", return_value=f.record["admission"]
                ) as register,
                patch.object(cli, "publish_public", side_effect=publish),
                patch.object(cli.host, "_client"),
                patch.object(cli.host, "_observer"),
            ):
                code, reply = self.invoke(self.arguments(root, f), root)
            self.assertEqual(code, 1)
            self.assertEqual(reply["failure_phase"], "enable_publish_admission")
            self.assertEqual(reply["failure_code"], "local_io_failed")
            register.assert_called_once()
            self.assertEqual((f.public / "trust.json").read_bytes(), b"public-trust")
            self.assertFalse((f.public / "admission.json").exists())

    def test_untrusted_phase_and_exception_metadata_never_enter_reply(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)

            def refused(installation, args):
                args._failure_phase = PRIVATE
                raise PrivateFailure(PRIVATE)

            with patch.object(cli, "dispatch", side_effect=refused):
                code, reply = self.invoke(
                    [
                        "status",
                        "--runtime-id",
                        fixtures.RID,
                        "--private-root",
                        str(root),
                    ],
                    root,
                )
            self.assertEqual(code, 1)
            self.assertEqual(reply["failure_phase"], "dispatch")
            self.assertEqual(reply["failure_code"], "operation_failed")
            code, reply = self.invoke(["--unknown", PRIVATE], root)
            self.assertEqual(code, 1)
            self.assertEqual(reply["failure_phase"], "arguments")
            self.assertEqual(reply["failure_code"], "validation_refused")

    def test_success_and_keyboard_interrupt_keep_existing_outcomes(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            arguments = [
                "status",
                "--runtime-id",
                fixtures.RID,
                "--private-root",
                str(root),
            ]
            expected = {
                "schema": "vardr.worker-cli/1",
                "state": "observed",
                "runtime_id": fixtures.RID,
            }
            with patch.object(cli, "dispatch", return_value=expected):
                code, reply = self.invoke(arguments, root)
            self.assertEqual((code, reply), (0, expected))
            with patch.object(cli, "dispatch", side_effect=KeyboardInterrupt):
                code, reply = self.invoke(arguments, root)
            self.assertEqual(code, 130)
            self.assertEqual(reply["state"], "held_interrupted")
            self.assertEqual(reply["failure_phase"], "dispatch")
            self.assertEqual(reply["failure_code"], "interrupted")


if __name__ == "__main__":
    unittest.main()
