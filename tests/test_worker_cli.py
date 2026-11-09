"""Prepared host CLI protocol tests; no Docker, login or credential-store access."""

import base64
import contextlib
import copy
from dataclasses import asdict, replace
import io
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import vardrsec
import worker_cli as cli
import worker_runtime as runtime

RID = "11111111-1111-4111-8111-111111111111"
RUNNER = "22222222-2222-4222-8222-222222222222"


class Records:
    def __init__(self, record, installation):
        self.record = record
        self.installation = installation
        self.depth = 0
        self.active_operation = None
        self.outside_mounts = Mock()

    def _require_operation(self, operation):
        assert operation is not None and operation is self.active_operation
        assert self.depth == 1

    @contextlib.contextmanager
    def locked(self, *, operation=None):
        if operation is not None:
            assert operation is self.active_operation and self.depth == 1
            yield
            return
        if self.depth:
            raise AssertionError("installation lock must not be nested")
        self.depth += 1
        try:
            yield
        finally:
            self.depth -= 1

    @contextlib.contextmanager
    def operation(self, existing=None):
        if existing is not None:
            assert existing is self.active_operation and self.depth == 1
            yield existing
            return
        with self.locked():
            self.active_operation = object()
            try:
                yield self.active_operation
            finally:
                self.active_operation = None

    def read(self, selected_id):
        if selected_id != RID:
            raise ValueError("wrong runtime")
        return copy.deepcopy(self.record)


class Observer(runtime.LocalDocker):
    def __init__(self, record):
        super().__init__(record["context"], runtime.WorkerLayout(**record["layout"]))
        self.identity = runtime.RuntimeIdentity(**record["registration"]["identity"])
        self.actual = self.identity
        self.commands = []
        self.state = {"Status": "running", "Running": True}

    def _bound(self, identity):
        if identity != self.actual:
            raise runtime.RuntimeRefused("worker_runtime_refused")
        return {"state": dict(self.state)}

    def capture_running(self, **kwargs):
        assert kwargs == {
            "container_id": self.identity.container_id,
            "image_id": self.identity.image_id,
            "project": self.identity.project,
        }
        self._bound(self.identity)
        return self.identity

    def _command(self, *args, **kwargs):
        self.commands.append((args, kwargs))
        if args[:2] == ("container", "inspect"):
            return '"SIGTERM"'
        if args[:2] != ("container", "stop"):
            raise AssertionError("unexpected Docker mutation")
        self.state = {"Status": "exited", "Running": False}
        return self.identity.container_id

    def observe_exit(self, identity):
        self._bound(identity)
        return runtime.ObservedExit(
            identity, "2026-11-05T21:00:01.000000001Z", 137, _proof=runtime._PROOF
        )


class WorkerCLI(unittest.TestCase):
    def fixture(self, directory):
        trust, public = directory / "trust", directory / "public"
        trust.mkdir()
        public.mkdir()
        layout = runtime.WorkerLayout(
            str(trust), str(public), "fixture_runner-state", "fixture_worker-ready"
        )
        identity = runtime.RuntimeIdentity(
            "daemon-id",
            "a" * 64,
            "sha256:" + "b" * 64,
            "fixture",
            "2026-11-05T21:00:00.000000001Z",
            "c" * 64,
        )
        record = {
            "runtime_id": RID,
            "context": "desktop-linux",
            "layout": asdict(layout),
            "client": {
                "base_url": "https://localhost:8443/backend",
                "ca_file": str(trust / "root.crt"),
                "ca_sha256": "d" * 64,
            },
            "registration": {"identity": asdict(identity)},
            "admission": {"runtime_sha256": "e" * 64},
            "registration_state": "acknowledged",
            "stop_state": "none",
            "revocation_state": "none",
            "receipt": None,
        }
        records = Records(record, directory)
        observer = Observer(record)
        client = Mock(spec=cli.host.HostClient)
        client.pin.return_value = record["client"]
        return SimpleNamespace(
            record=record,
            records=records,
            observer=observer,
            client=client,
            identity=identity,
            public=public,
            trust=trust,
        )

    def test_bad_arguments_never_echo_secrets_or_contact_docker(self):
        for arguments in (
            ["enable", "--password", "synthetic-private-secret"],
            [
                "status",
                "--runtime-id",
                "synthetic-private-secret",
                "--private-root",
                "/missing",
            ],
            [
                "stop",
                "--runtime-id",
                RID,
                "--private-root",
                "/missing",
                "--container-id",
                "synthetic-private-secret",
            ],
        ):
            output, errors = io.StringIO(), io.StringIO()
            with (
                self.subTest(arguments=arguments),
                contextlib.redirect_stdout(output),
                contextlib.redirect_stderr(errors),
                patch("subprocess.run", side_effect=AssertionError("no Docker")),
            ):
                self.assertEqual(cli.main(arguments), 1)
            self.assertNotIn(
                "synthetic-private-secret", output.getvalue() + errors.getvalue()
            )
            self.assertEqual(json.loads(output.getvalue())["state"], "held")

    def test_password_requires_hidden_tty_or_bounded_explicit_line(self):
        with (
            patch.object(cli.sys, "stdin", SimpleNamespace(isatty=lambda: False)),
            patch.object(cli.getpass, "getpass") as prompt,
        ):
            with self.assertRaises(cli.CLIRefused):
                cli.password(False)
            prompt.assert_not_called()
        for value, valid in (
            (b"fixture-password\n", True),
            (b"x" * 129 + b"\n", False),
            (b"x" * 600 + b"\n", False),
            (b"missing-newline", False),
            (b"bad\x00password\n", False),
        ):
            stream = SimpleNamespace(isatty=lambda: False, buffer=io.BytesIO(value))
            with self.subTest(size=len(value)), patch.object(cli.sys, "stdin", stream):
                if valid:
                    self.assertEqual(cli.password(True), "fixture-password")
                else:
                    with self.assertRaises(cli.CLIRefused):
                        cli.password(True)

    def test_worker_dispatch_is_before_global_guard_and_normal_start_stays_inert(self):
        with (
            patch.object(
                sys, "argv", ["vardrsec.py", "worker", "status", "--runtime-id", RID]
            ),
            patch.object(cli, "main", return_value=0) as worker,
            patch(
                "updater.operation_guard", side_effect=AssertionError("no double lock")
            ),
        ):
            vardrsec.main()
        worker.assert_called_once_with(
            ["status", "--runtime-id", RID], installation=vardrsec.ROOT
        )
        with (
            patch.object(sys, "argv", ["vardrsec.py", "start"]),
            patch.object(cli, "main") as worker,
            patch("updater.operation_guard", return_value=contextlib.nullcontext()),
            patch.object(vardrsec, "dispatch") as ordinary,
        ):
            vardrsec.main()
        worker.assert_not_called()
        self.assertEqual(ordinary.call_args.args[0].action, "start")

    def test_enable_uses_exact_prepared_registration_then_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            f = self.fixture(root)
            anchors = [
                {
                    "issuer_id": "fixture",
                    "key_id": purpose,
                    "public_key": base64.urlsafe_b64encode(bytes([index]) * 32)
                    .rstrip(b"=")
                    .decode(),
                    "purposes": [purpose],
                    "origins": ["map"],
                    "revoked": False,
                }
                for index, purpose in enumerate(("approval", "contract"), 1)
            ]
            public_file = root / "public-trust.json"
            public_file.write_text(json.dumps(anchors))
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
                "runner-id": RUNNER,
                "origin": "https://vardrsec.localhost:8443/backend",
                "public-trust": str(public_file),
                "runtime-id": RID,
            }
            arguments = [
                "enable",
                "--protocol",
                "legacy-v1",
                *[
                    item
                    for key, value in values.items()
                    for item in ("--" + key, value)
                ],
            ]
            args = cli.parser().parse_args(arguments)
            session = Mock()
            calls = []

            def registered(*positional, **kwargs):
                self.assertEqual(positional, (f.client, f.records, session))
                self.assertEqual(
                    kwargs,
                    {
                        "issuer_origin": values["origin"],
                        "enrollment_id": "enrollment-1",
                        "runner_id": RUNNER,
                        "identity": f.identity,
                        "observer": f.observer,
                        "expires_in_seconds": 900,
                        "runtime_id": RID,
                        "operation": f.records.active_operation,
                    },
                )
                self.assertFalse((f.public / "admission.json").exists())
                calls.append("registration_ack")
                return f.record["admission"]

            original_publish = cli.publish_public

            def publish(path, data):
                calls.append(path.name)
                original_publish(path, data)

            with (
                patch.object(cli, "records_for", return_value=f.records),
                patch.object(cli.runtime, "LocalDocker", return_value=f.observer),
                patch.object(cli.host, "HostClient", return_value=f.client),
                patch.object(
                    cli, "owner", return_value=contextlib.nullcontext(session)
                ),
                patch.object(cli.host, "register_runtime", side_effect=registered),
                patch.object(cli, "publish_public", side_effect=publish),
                patch.object(cli.host, "_client"),
                patch.object(cli.host, "_observer"),
            ):
                reply = cli.enable(root, args)
            self.assertEqual(reply["state"], "enabled")
            self.assertEqual(
                calls, ["registration_ack", "trust.json", "admission.json"]
            )
            self.assertEqual(
                json.loads((f.public / "admission.json").read_bytes()),
                f.record["admission"],
            )
            self.assertEqual(f.observer.commands, [])

    def test_normal_enable_selects_persistent_and_finite_protocols_are_explicit(self):
        names = (
            "api-url",
            "ca",
            "private-root",
            "context",
            "container-id",
            "image-id",
            "project",
            "trust-source",
            "admission-source",
            "state-volume",
            "readiness-volume",
            "enrollment-id",
            "runner-id",
            "origin",
            "public-trust",
        )
        arguments = [
            "enable",
            *[item for name in names for item in ("--" + name, "unused")],
        ]
        parser = cli.parser()
        self.assertEqual(parser.parse_args(arguments).protocol, "persistent-v3")
        self.assertIsNone(parser.parse_args(arguments).max_attempts)
        self.assertIsNone(parser.parse_args(arguments).expires_in)
        for protocol in ("legacy-v1", "finite-v2"):
            with self.subTest(protocol=protocol):
                self.assertEqual(
                    parser.parse_args([*arguments, "--protocol", protocol]).protocol,
                    protocol,
                )

    def test_persistent_stop_still_stops_exact_incarnation_when_disable_is_unreachable(
        self,
    ):
        import worker_host_persistent

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            f = self.fixture(root)
            f.record["registration"]["mode"] = "persistent"
            f.record["disable_state"] = "none"
            args = SimpleNamespace(
                action="stop", runtime_id=RID, private_root=str(root), report=False
            )
            with (
                patch.object(cli, "records_for", return_value=f.records),
                patch.object(
                    cli, "components", return_value=(f.client, f.observer, f.identity)
                ),
                patch.object(
                    worker_host_persistent,
                    "disable",
                    side_effect=cli.host.HostRefused(),
                ) as disable,
            ):
                reply = cli.dispatch(root, args)
            self.assertEqual(reply["state"], "stopped_observed")
            disable.assert_called_once_with(f.client, f.records, RID)
            stops = [
                arguments
                for arguments, _ in f.observer.commands
                if arguments[:2] == ("container", "stop")
            ]
            self.assertEqual(
                stops, [("container", "stop", "-t", "10", f.identity.container_id)]
            )

    def test_default_enable_passes_explicit_persistent_policy_before_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            f = self.fixture(root)
            args = SimpleNamespace(
                protocol="persistent-v3",
                max_attempts=None,
                idle_timeout_seconds=None,
                expires_in=None,
                container_id=f.identity.container_id,
                image_id=f.identity.image_id,
                project=f.identity.project,
                runner_id=RUNNER,
                public_trust=str(root / "public.json"),
                admission_source=str(f.public),
                trust_source=str(f.trust),
                context=f.observer.context,
                state_volume=f.observer.layout.state_volume,
                readiness_volume=f.observer.layout.readiness_volume,
                api_url=f.record["client"]["base_url"],
                ca=f.record["client"]["ca_file"],
                private_root=str(root),
                origin="https://map.internal",
                enrollment_id="enrollment-1",
                runtime_id=RID,
            )
            session = Mock()

            def registered(*positional, **kwargs):
                self.assertEqual(kwargs["protocol"], "persistent-v3")
                self.assertEqual(
                    kwargs["limits"],
                    {"max_attempts": None, "idle_timeout_seconds": None},
                )
                self.assertNotIn("expires_in_seconds", kwargs)
                self.assertNotIn("max_attempts", kwargs)
                self.assertFalse((f.public / "admission.json").exists())
                return f.record["admission"]

            with (
                patch.object(cli, "public_trust", return_value=b"[]"),
                patch.object(cli, "records_for", return_value=f.records),
                patch.object(
                    cli.runtime, "LocalDocker", return_value=f.observer
                ) as observer,
                patch.object(cli.host, "HostClient", return_value=f.client),
                patch.object(
                    cli, "owner", return_value=contextlib.nullcontext(session)
                ),
                patch.object(
                    cli.host, "register_runtime", side_effect=registered
                ) as register,
                patch.object(cli.host, "_client"),
                patch.object(cli.host, "_observer"),
            ):
                self.assertEqual(cli.enable(root, args)["state"], "enabled")
            self.assertEqual(observer.call_args.kwargs, {"protocol": "persistent-v3"})
            register.assert_called_once()
            self.assertEqual(
                json.loads((f.public / "admission.json").read_bytes()),
                f.record["admission"],
            )

    def test_advisory_held_status_is_a_nonzero_cli_result(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(
                cli,
                "dispatch",
                return_value={
                    "schema": "vardr.worker-status/1",
                    "state": "held",
                    "runtime_id": RID,
                },
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                cli.main(
                    ["status", "--runtime-id", RID, "--private-root", temporary],
                    installation=Path(temporary),
                ),
                1,
            )

    def test_publication_never_overwrites_existing_permission(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "admission.json"
            cli.publish_public(path, b"original-public-admission")
            with self.assertRaises(cli.CLIRefused):
                cli.publish_public(path, b"replacement")
            self.assertEqual(path.read_bytes(), b"original-public-admission")

    def test_lost_registration_ack_never_publishes_or_replays(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            f = self.fixture(root)
            args = SimpleNamespace(
                protocol="legacy-v1",
                expires_in=900,
                container_id=f.identity.container_id,
                image_id=f.identity.image_id,
                project=f.identity.project,
                runner_id=RUNNER,
                public_trust=str(root / "already-reviewed-public-trust.json"),
                admission_source=str(f.public),
                context=f.observer.context,
                trust_source=str(f.trust),
                state_volume=f.observer.layout.state_volume,
                readiness_volume=f.observer.layout.readiness_volume,
                api_url=f.record["client"]["base_url"],
                ca=f.record["client"]["ca_file"],
                private_root=str(root),
                origin="https://vardrsec.localhost:8443/backend",
                enrollment_id="enrollment-1",
                runtime_id=RID,
            )

            def lost(*args, **kwargs):
                f.record["registration_state"] = "unknown"
                raise cli.host.HostRefused("worker_host_refused")

            with (
                patch.object(
                    cli, "public_trust", return_value=b"reviewed-public-trust"
                ),
                patch.object(cli, "records_for", return_value=f.records),
                patch.object(cli.runtime, "LocalDocker", return_value=f.observer),
                patch.object(cli.host, "HostClient", return_value=f.client),
                patch.object(cli, "owner", return_value=contextlib.nullcontext(Mock())),
                patch.object(
                    cli.host, "register_runtime", side_effect=lost
                ) as register,
                patch.object(cli.host, "replay_registration") as replay,
                patch.object(cli, "publish_public") as publish,
            ):
                with self.assertRaises(cli.host.HostRefused):
                    cli.enable(root, args)
            self.assertEqual(register.call_count, 1)
            replay.assert_not_called()
            publish.assert_not_called()
            self.assertEqual(f.record["registration_state"], "unknown")
            self.assertFalse((f.public / "admission.json").exists())

    def test_stop_is_exact_mac_record_incarnation_and_typed_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = self.fixture(Path(temporary))
            with patch.object(
                cli, "components", return_value=(None, f.observer, f.identity)
            ):
                record, observer, proof = cli.stop(f.records, RID)
            self.assertIs(observer, f.observer)
            self.assertEqual(record, f.record)
            self.assertIsInstance(proof, runtime.ObservedExit)
            self.assertEqual(
                f.observer.commands[-1],
                (
                    ("container", "stop", "-t", "10", f.identity.container_id),
                    {"timeout": 25},
                ),
            )
            f.observer.commands.clear()
            f.observer.actual = replace(
                f.identity, started_at="2026-11-05T21:05:00.000000001Z"
            )
            with (
                patch.object(
                    cli, "components", return_value=(None, f.observer, f.identity)
                ),
                self.assertRaises(runtime.RuntimeRefused),
            ):
                cli.stop(f.records, RID)
            self.assertEqual(f.observer.commands, [])

    def test_unknown_receipt_reconciliation_does_not_replay_or_stop(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            f = self.fixture(root)
            f.record["stop_state"] = "unknown"
            args = cli.parser().parse_args(
                ["reconcile", "--runtime-id", RID, "--private-root", str(root)]
            )
            with (
                patch.object(cli, "records_for", return_value=f.records),
                patch.object(
                    cli, "components", return_value=(f.client, f.observer, f.identity)
                ),
                patch.object(
                    cli.host, "reconcile_exit", return_value={"receipt": None}
                ) as lookup,
                patch.object(cli.host, "register_runtime") as register,
                patch.object(cli.host, "report_observed_exit") as report,
            ):
                reply = cli.dispatch(root, args)
            lookup.assert_called_once_with(f.client, f.records, RID)
            register.assert_not_called()
            report.assert_not_called()
            self.assertEqual(f.observer.commands, [])
            self.assertEqual(reply["state"], "held_no_terminal_receipt")

    def test_stop_uses_one_pre_stop_deadline_and_resets_before_exit_observation(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = self.fixture(Path(temporary))
            observer = runtime.LocalDocker(f.observer.context, f.observer.layout)
            ticks, timeouts = [0.0], []

            def bound(identity):
                self.assertEqual(identity, f.identity)
                ticks[0] += 5
                return {"state": {"Status": "running", "Running": True}}

            def run(arguments, **kwargs):
                timeouts.append(kwargs["timeout"])
                ticks[0] += 8
                output = (
                    '"SIGTERM"' if "inspect" in arguments else f.identity.container_id
                )
                return SimpleNamespace(returncode=0, stdout=output)

            proof = runtime.ObservedExit(
                f.identity, "2026-11-05T21:00:01.000000001Z", 137, _proof=runtime._PROOF
            )

            def observed(identity):
                self.assertIsNone(observer._deadline)
                self.assertTrue(observer._observation_lock.acquire(blocking=False))
                observer._observation_lock.release()
                return proof

            with (
                patch.object(
                    cli, "components", return_value=(None, observer, f.identity)
                ),
                patch.object(observer, "_bound", side_effect=bound),
                patch.object(observer, "observe_exit", side_effect=observed),
                patch.object(cli.time, "monotonic", side_effect=lambda: ticks[0]),
                patch("subprocess.run", side_effect=run),
            ):
                self.assertEqual(cli.stop(f.records, RID)[2], proof)
            self.assertEqual(timeouts, [15, 12])
            self.assertIsNone(observer._deadline)

    def test_stop_refusal_releases_observation_lock_and_never_waits_or_stops(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = self.fixture(Path(temporary))
            with (
                patch.object(
                    cli, "components", return_value=(None, f.observer, f.identity)
                ),
                patch.object(
                    f.observer,
                    "_bound",
                    side_effect=runtime.RuntimeRefused("worker_runtime_refused"),
                ),
                patch.object(f.observer, "observe_exit") as observe,
            ):
                with self.assertRaises(runtime.RuntimeRefused):
                    cli.stop(f.records, RID)
            observe.assert_not_called()
            self.assertIsNone(f.observer._deadline)
            self.assertTrue(f.observer._observation_lock.acquire(blocking=False))
            f.observer._observation_lock.release()
            self.assertEqual(f.observer.commands, [])

    def test_status_reads_bound_incarnation_without_server_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            f = self.fixture(root)
            args = cli.parser().parse_args(
                ["status", "--runtime-id", RID, "--private-root", str(root)]
            )
            before = copy.deepcopy(f.record)
            with (
                patch.object(cli, "records_for", return_value=f.records),
                patch.object(
                    cli, "components", return_value=(None, f.observer, f.identity)
                ) as components,
                patch.object(cli.host, "reconcile_exit") as lookup,
                patch.object(cli.host, "report_observed_exit") as report,
            ):
                reply = cli.dispatch(root, args)
            components.assert_called_once_with(f.record, client=False)
            lookup.assert_not_called()
            report.assert_not_called()
            self.assertEqual(reply["container_state"], "running")
            self.assertEqual(f.record, before)
            self.assertEqual(f.observer.commands, [])

    def test_explicit_report_uses_only_direct_typed_exit_and_existing_reporter(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            f = self.fixture(root)
            f.observer.state = {"Status": "exited", "Running": False}
            args = cli.parser().parse_args(
                ["report-exit", "--runtime-id", RID, "--private-root", str(root)]
            )
            with (
                patch.object(cli, "records_for", return_value=f.records),
                patch.object(
                    cli, "components", return_value=(f.client, f.observer, f.identity)
                ),
                patch.object(
                    cli.host,
                    "report_observed_exit",
                    return_value={"receipt": {"outcome": "failed"}},
                ) as report,
            ):
                reply = cli.dispatch(root, args)
            positional = report.call_args.args
            self.assertEqual(positional[:3], (f.client, f.records, RID))
            self.assertIsInstance(positional[3], runtime.ObservedExit)
            self.assertEqual(positional[3].identity, f.identity)
            self.assertIs(positional[4], f.observer)
            self.assertEqual(reply["state"], "terminal_observed")
            self.assertEqual(f.observer.commands, [])

    def test_revoke_uses_actual_owner_context_and_preserves_custody(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            f = self.fixture(root)
            args = cli.parser().parse_args(
                ["revoke", "--runtime-id", RID, "--private-root", str(root)]
            )
            session = Mock()
            with (
                patch.object(cli, "records_for", return_value=f.records),
                patch.object(
                    cli, "components", return_value=(f.client, f.observer, f.identity)
                ),
                patch.object(
                    cli, "owner", return_value=contextlib.nullcontext(session)
                ) as owner,
                patch.object(
                    cli.host, "revoke_runtime", return_value={"revoked": True}
                ) as revoke,
            ):
                reply = cli.dispatch(root, args)
            owner.assert_called_once_with(f.client, args)
            revoke.assert_called_once_with(f.client, f.records, session, RID)
            self.assertEqual(reply["state"], "revoked")
            self.assertEqual(f.observer.commands, [])


    def test_job_signing_requires_tty_and_registration_binds_exact_review(self):
        import worker_job as job

        value = {"owner_id": "owner"}
        document = {"schema": "vardr.worker-job-review/1", "setup_sha256": cli.host.digest(value),
                    "job_id": "job-1", "selection": {"plan": {}}, "review": {
                        "context": {"expires_at": "2099-01-01T00:00:00Z"}}}
        args = SimpleNamespace(setup="setup", review="review", approval="approval", output="uncreated")
        with (patch.object(job, "setup", return_value=(value, {}, Mock())),
              patch.object(job, "read", return_value=document),
              patch.object(job.sys.stdin, "isatty", return_value=False),
              patch("builtins.input", side_effect=AssertionError("nonTTY must not prompt")),
              patch.object(job, "helper") as signer):
            with self.assertRaises(ValueError):
                job.approve(Path.cwd(), args)
        signer.assert_not_called()
        signed = {"schema": "vardr.worker-job-approval/1", "review_sha256": cli.host.digest(document),
                  "job_id": "job-1", "selection": document["selection"], "approval": {}}
        document["review"]["context"]["expires_at"] = "2099-01-02T00:00:00Z"
        session = Mock()
        session.owner_id.return_value = "owner"
        with (patch.object(job, "setup", return_value=(value, {}, Mock())),
              patch.object(job, "read", side_effect=[document, signed])):
            with self.assertRaises(ValueError):
                job.register(Path.cwd(), args, session)
        session.register_job.assert_not_called()


if __name__ == "__main__":
    unittest.main()
