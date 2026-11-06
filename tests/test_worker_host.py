"""Host protocol/custody tests; no Docker, real credentials or target traffic."""

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import ssl
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

import worker_host as host
import worker_runtime as runtime
import worker_volumes


class MemorySecrets:
    def __init__(self):
        self.values = {}

    def read(self, key):
        return self.values.get(key)

    def create(self, key, value):
        if key in self.values:
            raise ValueError("refused")
        self.values[key] = value


class Observer(runtime.LocalDocker):
    def __init__(self, identity, layout, volume, events):
        super().__init__("owned-context", layout)
        self.identity, self.volume, self.events = identity, volume, events
        self.failed_confirmation = False

    def capture_running(self, **_):
        return self.identity

    def _bound(self, identity):
        if identity != self.identity:
            raise runtime.RuntimeRefused("worker_runtime_refused")
        return {
            "mounts": [
                {
                    "Type": "bind",
                    "Source": self.layout.trust_source,
                    "Destination": "/trust",
                    "RW": False,
                },
                {
                    "Type": "bind",
                    "Source": self.layout.admission_source,
                    "Destination": "/run/vardr-worker-admission",
                    "RW": False,
                },
                *[
                    {
                        "Type": "volume",
                        "Name": name,
                        "Source": "/var/lib/docker/volumes/" + name + "/_data",
                        "Destination": destination,
                        "RW": True,
                    }
                    for name, destination in (
                        (self.layout.state_volume, "/home/runner/.vardrmap"),
                        (self.layout.readiness_volume, "/run/vardr-worker-ready"),
                    )
                ],
            ]
        }

    def _command(self, *args, **_):
        if args == ("info", "--format", worker_volumes.DAEMON_FORMAT):
            return json.dumps({"root": "/var/lib/docker", "os": "linux"})
        if args[:4] == ("volume", "inspect", "--format", worker_volumes.VOLUME_FORMAT):
            name = args[4]
            if name not in (self.layout.state_volume, self.layout.readiness_volume):
                raise AssertionError("unrecognized synthetic volume")
            ready = name == self.layout.readiness_volume
            return json.dumps(
                {
                    "name": name,
                    "driver": "local",
                    "scope": "local",
                    "options": None,
                    "source": "/var/lib/docker/volumes/" + name + "/_data",
                    "project": self.identity.project,
                    "volume": "worker-ready" if ready else "runner-state",
                    "ready": "1" if ready else None,
                }
            )
        raise AssertionError("unit fixture must never contact Docker")

    def confirm_exit(self, proof):
        self.events.append("confirm")
        if self.failed_confirmation or proof.identity != self.identity:
            raise runtime.RuntimeRefused("worker_runtime_refused")


class Session(host.OwnerSession):
    def __init__(self, client):
        super().__init__(client, "ephemeral-cookie", "f" * 64)
        self.calls, self.original = [], None
        self.lose_reply = False

    def register(self, runtime_id, body):
        self.calls.append((runtime_id, json.loads(json.dumps(body))))
        if self.original is None:
            self.original = {
                "schema": "vardr.worker-admission/1",
                "runtime_id": runtime_id,
                "runtime_sha256": host.digest(body["identity"]),
                **{
                    key: body[key]
                    for key in (
                        "enrollment_id",
                        "runner_id",
                        "origin",
                        "capability_sha256",
                        "identity",
                    )
                },
                "expires_at": (
                    datetime.now(timezone.utc)
                    + timedelta(seconds=body["expires_in_seconds"])
                )
                .isoformat()
                .replace("+00:00", "Z"),
            }
        if self.lose_reply:
            self.lose_reply = False
            raise host.HostRefused("worker_host_refused")
        return self.original

    def revoke(self, runtime_id):
        return {"runtime_id": runtime_id, "revoked": True}


class HostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        original_resolve = Path.resolve

        def resolve(path, *args, **kwargs):
            if str(path).startswith("/var/lib/docker/volumes/"):
                raise PermissionError("synthetic default-local daemon path")
            return original_resolve(path, *args, **kwargs)

        resolving = patch.object(Path, "resolve", resolve)
        resolving.start()
        self.addCleanup(resolving.stop)
        for name in ("private", "trust", "admission", "volume"):
            (self.root / name).mkdir(mode=0o700)
        self.ca = self.root / "trust/root.crt"
        self.ca.write_text("TEST PUBLIC CA", encoding="ascii")
        tls = Mock(check_hostname=True, verify_mode=ssl.CERT_REQUIRED)
        with patch.object(host.ssl, "SSLContext", return_value=tls):
            self.client = host.HostClient("https://localhost:8443/backend", self.ca)
        tls.load_verify_locations.assert_called_once_with(cadata="TEST PUBLIC CA")
        self.assertIsNone(tls.keylog_filename)
        self.backend = MemorySecrets()
        self.records = host.HostRecords(
            self.root, self.root / "private", backend=self.backend
        )
        self.identity = runtime.RuntimeIdentity(
            "daemon-id",
            "a" * 64,
            "sha256:" + "b" * 64,
            "owned-fixture",
            "2026-11-05T20:00:00.123456789Z",
            "c" * 64,
        )
        self.layout = runtime.WorkerLayout(
            str(self.root / "trust"),
            str(self.root / "admission"),
            "owned-state",
            "owned-ready-fresh",
        )
        self.events = []
        self.observer = Observer(
            self.identity, self.layout, self.root / "volume", self.events
        )
        self.session = Session(self.client)
        self.runtime_id, self.runner_id = str(uuid.uuid4()), str(uuid.uuid4())
        self.binding = {
            "origin": "https://map.internal",
            "job_id": "job-1",
            "runner_id": self.runner_id,
            "contract_id": str(uuid.uuid4()),
            "attempt_id": str(uuid.uuid4()),
            "fence": 2,
            "contract_sha256": "d" * 64,
        }
        self.proof = runtime.ObservedExit(
            self.identity, "2026-11-05T20:01:00.123456789Z", 125, _proof=runtime._PROOF
        )

    def tearDown(self):
        self.temp.cleanup()

    def register(self):
        return host.register_runtime(
            self.client,
            self.records,
            self.session,
            issuer_origin="https://map.internal",
            enrollment_id="enrolled-1",
            runner_id=self.runner_id,
            identity=self.identity,
            observer=self.observer,
            expires_in_seconds=300,
            runtime_id=self.runtime_id,
        )

    def lookup(self, receipt=None, binding=True):
        return {
            "schema": "vardr.worker-receipt-observation/1",
            "runtime_id": self.runtime_id,
            "runtime_sha256": host.digest(asdict(self.identity)),
            "binding": self.binding if binding else None,
            "receipt": receipt,
        }

    def terminal(self):
        fields = {
            "schema": "vardr.managed-stop/1",
            **self.binding,
            "outcome": "failed",
            "cause": "observed_exit",
            "termination_confirmed": True,
        }
        return {
            "schema": "vardr.managed-stop-receipt/1",
            **self.binding,
            "outcome": "failed",
            "cause": "observed_exit",
            "receipt_sha256": host.digest(fields),
            "capacity_reserved": False,
        }

    def test_registration_is_exact_mac_authenticated_and_contains_no_secret(self):
        admission = self.register()
        record = self.records.read(self.runtime_id)
        secret = self.backend.read(self.runtime_id)
        self.assertEqual(record["registration_state"], "acknowledged")
        self.assertEqual(admission["origin"], "https://map.internal")
        self.assertEqual(record["client"]["base_url"], "https://localhost:8443/backend")
        self.assertEqual(
            admission["capability_sha256"],
            hashlib.sha256(host._CAPABILITY + secret.encode()).hexdigest(),
        )
        text = self.records._path(self.runtime_id).read_text(encoding="utf-8")
        for private in (secret, "ephemeral-cookie", "f" * 64):
            self.assertNotIn(private, text)
        with self.assertRaises(host.HostRefused):
            self.register()

    def test_distinct_logical_issuer_keeps_existing_backend_prefix(self):
        result = host.register_runtime(
            self.client,
            self.records,
            self.session,
            issuer_origin="https://vardrsec.localhost:8443/backend",
            enrollment_id="enrolled-1",
            runner_id=self.runner_id,
            identity=self.identity,
            observer=self.observer,
            expires_in_seconds=300,
            runtime_id=self.runtime_id,
        )
        self.assertEqual(result["origin"], "https://vardrsec.localhost:8443/backend")
        self.assertEqual(
            self.records.read(self.runtime_id)["client"]["base_url"],
            "https://localhost:8443/backend",
        )

    def test_unknown_registration_requires_explicit_identical_replay(self):
        self.session.lose_reply = True
        with self.assertRaises(host.HostRefused):
            self.register()
        before = self.records.read(self.runtime_id)
        self.assertEqual(before["registration_state"], "unknown")
        secret = self.backend.read(self.runtime_id)
        with self.assertRaises(host.HostRefused):
            self.register()
        result = host.replay_registration(
            self.client, self.records, self.session, self.runtime_id
        )
        self.assertEqual(self.session.calls[0], self.session.calls[1])
        self.assertEqual(result, self.session.original)
        self.assertEqual(secret, self.backend.read(self.runtime_id))

    def test_tampered_record_refuses_before_authority_use(self):
        self.register()
        path = self.records._path(self.runtime_id)
        value = json.loads(path.read_text(encoding="utf-8"))
        value["payload"]["client"]["base_url"] = "https://replacement.invalid"
        path.write_text(json.dumps(value), encoding="utf-8")
        self.client.receipt = Mock()
        with self.assertRaises(host.HostRefused):
            host.reconcile_exit(self.client, self.records, self.runtime_id)
        self.client.receipt.assert_not_called()

    def test_endpoint_or_ca_context_change_refuses_before_secret_transmission(self):
        self.register()
        self.client.ca_sha256 = "e" * 64
        self.client.receipt = Mock()
        with self.assertRaises(host.HostRefused):
            host.reconcile_exit(self.client, self.records, self.runtime_id)
        self.client.receipt.assert_not_called()

    def test_authenticated_record_cannot_move_to_another_installation_lock(self):
        self.register()
        other = self.root / "other-installation"
        other.mkdir()
        records = host.HostRecords(other, self.root / "private", backend=self.backend)
        self.client.receipt = Mock()
        with self.assertRaises(host.HostRefused):
            host.reconcile_exit(self.client, records, self.runtime_id)
        self.client.receipt.assert_not_called()

    def test_final_direct_proof_follows_lookup_and_precedes_durable_intent(self):
        self.register()
        self.client.receipt = lambda *args: (
            self.events.append("lookup") or self.lookup()
        )

        def report(runtime_id, body, secret):
            self.events.append("report")
            record = self.records.read(runtime_id)
            self.assertEqual(record["stop_state"], "prepared")
            self.assertEqual(record["stop_intent"], body)
            self.assertEqual(secret, self.backend.read(runtime_id))
            return {
                "schema": "vardr.worker-host-stop/1",
                "runtime_id": runtime_id,
                "runtime_sha256": host.digest(asdict(self.identity)),
                "receipt": self.terminal(),
            }

        self.client.observed_exit = report
        result = host.report_observed_exit(
            self.client, self.records, self.runtime_id, self.proof, self.observer
        )
        self.assertEqual(self.events, ["lookup", "confirm", "report"])
        self.assertFalse(result["receipt"]["capacity_reserved"])

    def test_lost_report_reply_is_never_resent_and_reconciles_readonly(self):
        self.register()
        self.client.receipt = Mock(return_value=self.lookup())
        self.client.observed_exit = Mock(
            side_effect=host.HostRefused("worker_host_refused")
        )
        with self.assertRaises(host.HostRefused):
            host.report_observed_exit(
                self.client, self.records, self.runtime_id, self.proof, self.observer
            )
        self.assertEqual(self.records.read(self.runtime_id)["stop_state"], "unknown")
        with self.assertRaises(host.HostRefused):
            host.report_observed_exit(
                self.client, self.records, self.runtime_id, self.proof, self.observer
            )
        self.client.observed_exit.assert_called_once()

        self.client.receipt.return_value = self.lookup(self.terminal())
        reply = host.reconcile_exit(self.client, self.records, self.runtime_id)
        self.assertEqual(reply["receipt"], self.terminal())
        self.client.observed_exit.assert_called_once()

    def test_fresh_report_accepts_only_failed_completion_recovery(self):
        for outcome in ("failed", "completed", "cancelled"):
            with self.subTest(outcome=outcome):
                self.runtime_id = str(uuid.uuid4())
                self.session = Session(self.client)
                self.register()
                self.client.receipt = Mock(return_value=self.lookup())
                terminal = {
                    "schema": "vardr.managed-completion/1",
                    **self.binding,
                    "outcome": outcome,
                    "receipt_sha256": "e" * 64,
                    "capacity_reserved": False,
                }
                self.client.observed_exit = Mock(
                    return_value={
                        "schema": "vardr.worker-host-stop/1",
                        "runtime_id": self.runtime_id,
                        "runtime_sha256": host.digest(asdict(self.identity)),
                        "receipt": terminal,
                    }
                )
                if outcome == "failed":
                    reply = host.report_observed_exit(
                        self.client,
                        self.records,
                        self.runtime_id,
                        self.proof,
                        self.observer,
                    )
                    self.assertEqual(reply["receipt"], terminal)
                    self.assertEqual(
                        self.records.read(self.runtime_id)["stop_state"], "observed"
                    )
                else:
                    with self.assertRaises(host.HostRefused):
                        host.report_observed_exit(
                            self.client,
                            self.records,
                            self.runtime_id,
                            self.proof,
                            self.observer,
                        )
                    self.assertEqual(
                        self.records.read(self.runtime_id)["stop_state"], "unknown"
                    )
                self.client.observed_exit.assert_called_once()

    def test_stale_direct_proof_and_changed_server_binding_do_not_report(self):
        self.register()
        self.client.receipt = Mock(return_value=self.lookup())
        self.client.observed_exit = Mock()
        self.observer.failed_confirmation = True
        with self.assertRaises(host.HostRefused):
            host.report_observed_exit(
                self.client, self.records, self.runtime_id, self.proof, self.observer
            )
        self.assertEqual(self.records.read(self.runtime_id)["stop_state"], "none")
        self.client.observed_exit.assert_not_called()
        self.binding["runner_id"] = str(uuid.uuid4())
        with self.assertRaises(host.HostRefused):
            host.report_observed_exit(
                self.client, self.records, self.runtime_id, self.proof, self.observer
            )
        self.client.observed_exit.assert_not_called()

    def test_raw_json_is_not_exit_proof_and_unbound_runtime_remains_held(self):
        self.register()
        self.client.receipt = Mock(return_value=self.lookup(binding=False))
        self.client.observed_exit = Mock()
        for proof in (asdict(self.proof), self.proof):
            with self.assertRaises(host.HostRefused):
                host.report_observed_exit(
                    self.client, self.records, self.runtime_id, proof, self.observer
                )
        self.client.observed_exit.assert_not_called()

    def test_storage_under_actual_worker_source_refuses_registration(self):
        self.layout = runtime.WorkerLayout(
            str(self.root / "private"),
            str(self.root / "admission"),
            "owned-state",
            "owned-ready-fresh",
        )
        self.observer.layout = self.layout
        with self.assertRaises(host.HostRefused):
            self.register()
        self.assertIsNone(self.backend.read(self.runtime_id))

    def test_revocation_preserves_secret_for_expired_grant_receipt_lookup(self):
        self.register()
        secret = self.backend.read(self.runtime_id)
        host.revoke_runtime(self.client, self.records, self.session, self.runtime_id)
        self.assertEqual(
            self.records.read(self.runtime_id)["revocation_state"], "acknowledged"
        )
        self.assertEqual(secret, self.backend.read(self.runtime_id))
        self.client.receipt = Mock(return_value=self.lookup(self.terminal()))
        self.assertIsNotNone(
            host.reconcile_exit(self.client, self.records, self.runtime_id)["receipt"]
        )


class TransportTests(unittest.TestCase):
    def test_managed_source_fallback_is_only_permission_or_windows_vm(self):
        source = PurePosixPath("/var/lib/docker/volumes/owned/_data")
        with patch.object(Path, "resolve", side_effect=PermissionError):
            self.assertEqual(host._managed_source(source, windows_vm=False), source)
        for error in (FileNotFoundError(), OSError("unknown filesystem failure")):
            with (
                self.subTest(error=type(error).__name__),
                patch.object(Path, "resolve", side_effect=error),
                self.assertRaises(type(error)),
            ):
                host._managed_source(source, windows_vm=False)
        with patch.object(Path, "resolve") as resolve:
            self.assertIsNone(host._managed_source(source, windows_vm=True))
        resolve.assert_not_called()

    def test_https_wire_is_bounded_verified_and_never_follows_redirects(self):
        for fault in (
            None,
            "redirect",
            "encoding",
            "type",
            "declared_size",
            "truncated",
            "stream_size",
            "duplicate",
        ):
            with self.subTest(fault=fault):
                client = object.__new__(host.HostClient)
                client.host, client.port, client.prefix = "localhost", 8443, "/backend"
                secure, plain = Mock(), Mock()
                client._tls = Mock()
                client._tls.wrap_socket.return_value = secure
                response = Mock(status=302 if fault == "redirect" else 200)
                headers = {
                    "Content-Encoding": "gzip" if fault == "encoding" else "identity",
                    "Content-Type": "text/plain"
                    if fault == "type"
                    else "application/json",
                    "Content-Length": "16385"
                    if fault == "declared_size"
                    else ("999" if fault == "truncated" else None),
                }
                response.getheader.side_effect = lambda key, default=None: headers.get(
                    key, default
                )
                body = (
                    b'{"ok":true}'
                    if fault != "duplicate"
                    else b'{"ok":true,"ok":false}'
                )
                blocks = [b"x" * 1024] * 17 if fault == "stream_size" else [body, b""]
                response.read1.side_effect = blocks
                response.getheaders.return_value = []
                connection = Mock()
                connection.getresponse.return_value = response
                with (
                    patch.object(
                        host,
                        "_addresses",
                        return_value=[(2, 1, 6, "", ("127.0.0.1", 8443))],
                    ),
                    patch.object(host.socket, "socket", return_value=plain),
                    patch.object(
                        host.http.client, "HTTPConnection", return_value=connection
                    ),
                ):
                    if fault is None:
                        self.assertEqual(
                            client._request("POST", "/fixed", {"value": 1})[0],
                            {"ok": True},
                        )
                    else:
                        with self.assertRaises(host.HostRefused):
                            client._request("POST", "/fixed", {"value": 1})
                client._tls.wrap_socket.assert_called_once_with(
                    plain, server_hostname="localhost"
                )
                connection.request.assert_called_once()
                self.assertEqual(connection.request.call_args.args[1], "/backend/fixed")
                self.assertEqual(
                    connection.request.call_args.kwargs["headers"]["Accept-Encoding"],
                    "identity",
                )
                connection.close.assert_called_once()

    def test_oversized_request_never_opens_connection(self):
        client = object.__new__(host.HostClient)
        with (
            patch.object(host, "_addresses") as addresses,
            self.assertRaises(host.HostRefused),
        ):
            client._request("POST", "/fixed", {"value": "x" * 8192})
        addresses.assert_not_called()

    def test_absolute_timer_shuts_down_socket_during_header_wait(self):
        client = object.__new__(host.HostClient)
        client.host, client.port, client.prefix = "localhost", 8443, "/backend"
        plain, secure, connection = Mock(), Mock(), Mock()
        client._tls = Mock()
        client._tls.wrap_socket.return_value = secure
        callbacks = []

        def timer_factory(seconds, callback):
            self.assertGreater(seconds, 0)
            self.assertLessEqual(seconds, 10)
            callbacks.append(callback)
            return Mock()

        def waiting_headers():
            callbacks[0]()
            raise OSError("deadline shutdown")

        connection.getresponse.side_effect = waiting_headers
        with (
            patch.object(
                host, "_addresses", return_value=[(2, 1, 6, "", ("127.0.0.1", 8443))]
            ),
            patch.object(host.socket, "socket", return_value=plain),
            patch.object(host.http.client, "HTTPConnection", return_value=connection),
            patch.object(host.threading, "Timer", side_effect=timer_factory),
            self.assertRaises(host.HostRefused),
        ):
            client._request("POST", "/fixed", {})
        secure.shutdown.assert_called_once_with(host.socket.SHUT_RDWR)
        secure.close.assert_called_once()
        connection.request.assert_called_once()

    def test_strict_json_rejects_duplicate_keys_constants_and_nonobjects(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b"[]", b"\xff"):
            with self.subTest(raw=raw), self.assertRaises(host.HostRefused):
                host._json(raw)

    def test_endpoint_aliases_and_credentials_are_refused(self):
        for value in (
            "http://localhost",
            "https://u:p@localhost",
            "https://localhost/",
            "https://localhost/backend/",
            "https://localhost/%62ackend",
            "https://localhost?x=1",
            "https://localhost#fragment",
        ):
            with self.subTest(value=value), self.assertRaises(host.HostRefused):
                host._url(value, external=True)

    def test_stop_scheme_only_reaches_the_two_fixed_routes(self):
        client = object.__new__(host.HostClient)
        client._request = Mock(return_value=({}, []))
        runtime_id = str(uuid.uuid4())
        client.receipt(runtime_id, "a" * 64, "b" * 64)
        self.assertEqual(
            client._request.call_args.args[1], f"/managed/runtimes/{runtime_id}/receipt"
        )
        self.assertEqual(
            client._request.call_args.args[3],
            {"Authorization": "VardrStop " + "b" * 64},
        )
        client.observed_exit(runtime_id, {}, "b" * 64)
        self.assertEqual(
            client._request.call_args.args[1],
            f"/managed/runtimes/{runtime_id}/observed-exit",
        )

    def test_owner_cookie_and_csrf_are_ephemeral_and_never_stop_credentials(self):
        client = object.__new__(host.HostClient)
        client.origin = "https://localhost:8443"
        cookie = "x" * 43
        client._request = Mock(
            side_effect=[
                (
                    {"authenticated": True},
                    [
                        (
                            "Set-Cookie",
                            f"{host._COOKIE}={cookie}; Secure; HttpOnly; Path=/; SameSite=lax",
                        )
                    ],
                ),
                ({"authMethod": "local", "csrfToken": "a" * 64, "user": {}}, []),
                (
                    {
                        "runtime_id": "00000000-0000-0000-0000-000000000001",
                        "revoked": True,
                    },
                    [],
                ),
                ({"authenticated": False}, []),
            ]
        )
        with client.owner_session("operator", "disposable-password") as session:
            session.revoke("00000000-0000-0000-0000-000000000001")
        headers = client._request.call_args_list[2].args[3]
        self.assertEqual(headers["Origin"], client.origin)
        self.assertEqual(headers["X-CSRF-Token"], "a" * 64)
        self.assertNotIn("Authorization", headers)
        with self.assertRaises(host.HostRefused):
            session.revoke("00000000-0000-0000-0000-000000000001")


if __name__ == "__main__":
    unittest.main()
