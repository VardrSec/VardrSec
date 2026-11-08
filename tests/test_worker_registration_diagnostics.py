"""Registration boundary evidence using inert transport/storage failures only."""

from contextlib import contextmanager, redirect_stdout
import copy
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import nm2_worker_acceptance as acceptance
import nm2_worker_hosted as hosted
import test_worker_host_persistent as fixtures
import worker_cli as cli
import worker_host as host


PRIVATE = "private-secret-cookie-url-header-path-body-canary"


def detail(checkpoint, request_stage=None, http_status=None):
    return dict(
        checkpoint=checkpoint, request_stage=request_stage, http_status=http_status
    )


class RegistrationDiagnostics(unittest.TestCase):
    @contextmanager
    def transport(self, *, stage=None, status=200, body=b'{"accepted":true}'):
        client = object.__new__(host.HostClient)
        client.host, client.port, client.prefix = "localhost", 8443, "/backend"
        plain, secure, connection = Mock(), Mock(), Mock()
        client._tls = Mock()
        client._tls.wrap_socket.return_value = secure
        response = Mock(status=status)
        response.getheaders.return_value = []
        headers = {
            "Content-Type": "application/json",
            "Content-Encoding": "identity",
            "Content-Length": str(len(body)),
        }
        response.getheader.side_effect = lambda key, default=None: headers.get(
            key, default
        )
        response.read1.side_effect = [body, b""]
        connection.getresponse.return_value = response
        if stage == "connect":
            plain.connect.side_effect = OSError(PRIVATE)
        elif stage == "tls":
            client._tls.wrap_socket.side_effect = host.ssl.SSLError(PRIVATE)
        elif stage == "send":
            connection.request.side_effect = OSError(PRIVATE)
        elif stage == "status":
            connection.getresponse.side_effect = host.http.client.HTTPException(PRIVATE)
        elif stage == "headers":
            headers["Content-Type"] = PRIVATE
        elif stage == "body":
            response.read1.side_effect = OSError(PRIVATE)
        with (
            patch.object(
                host, "_addresses", return_value=[(2, 1, 6, "", ("127.0.0.1", 8443))]
            ),
            patch.object(host.socket, "socket", return_value=plain),
            patch.object(host.http.client, "HTTPConnection", return_value=connection),
        ):
            yield client, connection

    def test_actual_request_boundaries_remain_distinct_without_secret_text(self):
        for stage in ("connect", "tls", "send", "status", "headers", "body", "json"):
            with (
                self.subTest(stage=stage),
                self.transport(
                    stage=stage, body=b'{"x":1,"x":2}' if stage == "json" else b"{}"
                ) as (client, connection),
            ):
                with self.assertRaises(host.HostRefused) as caught:
                    client._request("POST", "/managed/runtimes/owned/register", {})
                actual = getattr(caught.exception, "registration_failure", None)
                self.assertEqual(
                    actual,
                    detail(
                        "request",
                        stage,
                        200 if stage in {"headers", "body", "json"} else None,
                    ),
                )
                self.assertNotIn(PRIVATE, str(caught.exception) + json.dumps(actual))
                self.assertLessEqual(connection.request.call_count, 1)

    def test_only_actual_strict_http_status_is_retained_and_error_body_is_not_read(
        self,
    ):
        for status in (100, 401, 403, 409, 422, 503, 599):
            with (
                self.subTest(status=status),
                self.transport(status=status) as (client, connection),
            ):
                with self.assertRaises(host.HostRefused) as caught:
                    client._request("POST", "/managed/runtimes/owned/register", {})
                self.assertEqual(
                    getattr(caught.exception, "registration_failure", None),
                    detail("request", "status", status),
                )
                connection.request.assert_called_once()
                connection.getresponse.return_value.read1.assert_not_called()
        for status in (True, 401.0, "403", 99, 600):
            with (
                self.subTest(invalid=status),
                self.transport(status=status) as (client, _),
            ):
                with self.assertRaises(host.HostRefused) as caught:
                    client._request("POST", "/managed/runtimes/owned/register", {})
                self.assertEqual(
                    getattr(caught.exception, "registration_failure", None),
                    detail("request", "status"),
                )

    @contextmanager
    def registration(self):
        fixture = fixtures.PersistentHostTests()
        fixture.setUp()
        try:
            yield fixture, fixture.f
        finally:
            fixture.doCleanups()

    def test_actual_registration_local_boundaries_have_no_extra_send_or_publication(
        self,
    ):
        for checkpoint in (
            "local_capture",
            "mount_custody",
            "secret_store",
            "initial_store",
        ):
            with (
                self.subTest(checkpoint=checkpoint),
                self.registration() as (fixture, f),
            ):
                if checkpoint == "local_capture":
                    target, name, error = (
                        f.observer,
                        "capture_running",
                        host.runtime.RuntimeRefused(PRIVATE),
                    )
                elif checkpoint == "mount_custody":
                    target, name, error = (
                        f.records,
                        "outside_mounts",
                        host.HostRefused(PRIVATE),
                    )
                elif checkpoint == "secret_store":
                    target, name, error = f.backend, "create", OSError(PRIVATE)
                else:
                    target, name, error = f.records, "write", OSError(PRIVATE)
                with patch.object(target, name, side_effect=error):
                    with self.assertRaises(host.HostRefused) as caught:
                        fixture.register()
                self.assertEqual(
                    getattr(caught.exception, "registration_failure", None),
                    detail(checkpoint),
                )
                f.session.register.assert_not_called()
                self.assertFalse((f.root / "admission/admission.json").exists())

    def test_request_ack_and_final_write_keep_the_existing_unknown_hold(self):
        for checkpoint in ("request", "ack", "final_store", "unknown_store"):
            with (
                self.subTest(checkpoint=checkpoint),
                self.registration() as (fixture, f),
            ):
                original_write = f.records.write
                if checkpoint in {"request", "unknown_store"}:
                    f.session.register.side_effect = host.HostRefused(PRIVATE)
                elif checkpoint == "ack":
                    f.session.register.side_effect = None
                    f.session.register.return_value = {"schema": PRIVATE}

                def write(value, **kwargs):
                    if not kwargs.get("create") and (
                        checkpoint == "unknown_store"
                        or checkpoint == "final_store"
                        and value["registration_state"] == "acknowledged"
                    ):
                        raise OSError(PRIVATE)
                    return original_write(value, **kwargs)

                with patch.object(f.records, "write", side_effect=write):
                    with self.assertRaises(host.HostRefused) as caught:
                        fixture.register()
                self.assertEqual(
                    getattr(caught.exception, "registration_failure", None),
                    detail(checkpoint),
                )
                f.session.register.assert_called_once()
                record = f.records.read(f.runtime_id)
                self.assertEqual(
                    record["registration_state"],
                    "prepared" if checkpoint == "unknown_store" else "unknown",
                )
                secret = f.backend.read(f.runtime_id)
                with self.assertRaises(host.HostRefused):
                    fixture.register()
                f.session.register.assert_called_once()
                self.assertEqual(f.backend.read(f.runtime_id), secret)
                self.assertFalse((f.root / "admission/admission.json").exists())

    def test_request_detail_survives_both_unknown_record_and_lock_wrappers(self):
        with (
            self.registration() as (fixture, f),
            self.transport(status=409) as (client, _),
        ):
            f.session.register.side_effect = lambda *_: client._request(
                "POST", "/owned/register", {}
            )[0]
            with self.assertRaises(host.HostRefused) as caught:
                fixture.register()
            self.assertEqual(
                getattr(caught.exception, "registration_failure", None),
                detail("request", "status", 409),
            )
            self.assertEqual(
                f.records.read(f.runtime_id)["registration_state"], "unknown"
            )
            f.session.register.assert_called_once()

    def cli_output(self, value, *, phase="enable_registration", kind=host.HostRefused):
        error = kind(PRIVATE)
        error.registration_failure = copy.deepcopy(value)

        def dispatch(_, args):
            args._failure_phase = phase
            raise error

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(cli, "dispatch", side_effect=dispatch),
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                code = cli.main(
                    [
                        "status",
                        "--runtime-id",
                        "00000000-0000-0000-0000-000000000001",
                        "--private-root",
                        temporary,
                    ],
                    installation=Path(temporary).resolve(),
                )
        self.assertEqual(code, 1)
        self.assertNotIn(PRIVATE, output.getvalue())
        return json.loads(output.getvalue())

    def harness(self, value):
        completed = subprocess.CompletedProcess(
            ["inert"], 1, json.dumps(value).encode(), PRIVATE.encode()
        )
        with patch.object(acceptance.subprocess, "run", return_value=completed):
            with self.assertRaises(acceptance.AcceptanceRefused) as caught:
                acceptance.worker_cli_command(["inert"])
        return caught.exception

    def projection(self, value):
        selected = {"sources": {}, "images": {}, "project": "owned"}
        raw = {
            "schema": "vardr.nm2-worker-acceptance/2",
            "status": "held",
            "platform": "linux",
            **selected,
            "stage": "operator_worker_enable",
            "reason": "fixture_command_failed",
            "command_failure": value,
            "stdout": PRIVATE,
            "stderr": PRIVATE,
        }
        return hosted.failure_projection(raw, selected)

    def test_cli_harness_and_hosted_projection_revalidate_the_exact_fixed_detail(self):
        for checkpoint in host.REGISTRATION_CHECKPOINTS:
            selected = detail(checkpoint)
            reply = self.cli_output(selected)
            expected = {
                "failure_phase": "enable_registration",
                "failure_code": "host_refused",
                "registration_failure": selected,
            }
            self.assertEqual(self.harness(reply).public, expected)
            self.assertEqual(self.projection(expected)["command_failure"], expected)
        selected = detail("request", "status", 503)
        reply = self.cli_output(selected)
        expected = self.harness(reply).public
        self.assertEqual(self.projection(expected)["command_failure"], expected)
        self.assertNotIn(PRIVATE, json.dumps(expected))

    def test_unknown_nested_values_cannot_smuggle_secrets_or_typed_status_aliases(self):
        valid = detail("request", "status", 403)
        malformed = [None, [], PRIVATE, {**valid, "body": PRIVATE}]
        for key, replacement in (
            ("checkpoint", PRIVATE),
            ("checkpoint", {}),
            ("request_stage", PRIVATE),
            ("request_stage", []),
            ("http_status", True),
            ("http_status", 403.0),
            ("http_status", "403"),
            ("http_status", 99),
            ("http_status", 600),
        ):
            malformed.append({**valid, key: replacement})
        malformed.extend([detail("ack", "json", 200), detail("request", "tls", 403)])
        for value in malformed:
            with self.subTest(value=value):
                reply = self.cli_output(value)
                self.assertEqual(len(reply), 5)
                raw = {**reply, "registration_failure": value}
                error = self.harness(raw)
                self.assertFalse(hasattr(error, "public"))
                projected = self.projection(
                    {
                        "failure_phase": "enable_registration",
                        "failure_code": "host_refused",
                        "registration_failure": value,
                    }
                )
                self.assertNotIn("command_failure", projected)
                self.assertNotIn(PRIVATE, json.dumps(projected))

    def test_other_phases_and_exception_types_keep_legacy_five_key_failures(self):
        value = detail("request", "status", 409)
        for phase, kind in (
            ("enable_owner_auth", host.HostRefused),
            ("enable_registration", OSError),
        ):
            with self.subTest(phase=phase, kind=kind):
                reply = self.cli_output(value, phase=phase, kind=kind)
                self.assertEqual(len(reply), 5)
                self.assertNotIn("registration_failure", self.harness(reply).public)
                raw = {**reply, "registration_failure": value}
                self.assertFalse(hasattr(self.harness(raw), "public"))


if __name__ == "__main__":
    unittest.main()
