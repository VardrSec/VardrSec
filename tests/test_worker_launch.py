"""Exercise the explicit command with real intent storage and fake effects."""

from contextlib import ExitStack, nullcontext
from dataclasses import asdict
import hashlib
import io
import json
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_worker_lifecycle_intent as cases
import worker_cli as cli
import worker_host as host
import worker_launch as launcher
import worker_runtime as runtime

CID = "e" * 64
OLD_CID = "9" * 64
NETWORK = "8" * 64
RUNTIME_ID = "805bc17a-37f8-4089-b153-6141a76ba928"
ORIGIN = "https://vardrsec.localhost:8443/backend"
ENDPOINT = "unix:///owned/docker.sock"


class WorkerLaunchTests(unittest.TestCase):
    def setUp(self):
        self.f = cases.LifecycleIntentTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.install = self.f.records.installation.resolve()
        self.private = self.f.records.private_root.resolve()
        self.trust = self.install / "trust"
        self.trust.mkdir()
        self.ca = self.trust / "root.crt"
        self.ca.write_bytes(b"fake public CA")
        self.public = self.install / "admissions"
        self.public.mkdir()
        empty = self.private / "empty.env"
        empty.write_bytes(b"")
        override = self.private / "override.json"
        override.write_bytes(b"{}")
        image = self.f.row["source"]["runner_image"]
        core = [
            {"service": role, "container_id": str(index) * 64, "image_id": image}
            for index, role in enumerate(("api", "db", "proxy", "web"), 1)
        ]
        core_images = {item["service"]: image for item in core}
        self.binding = {
            "context": "local",
            "local_endpoint": ENDPOINT,
            "daemon_id": "daemon",
        }
        self.args = [
            "launch",
            "--runtime-id",
            RUNTIME_ID,
            "--api-url",
            "https://localhost:8443/backend",
            "--ca",
            str(self.ca),
            "--private-root",
            str(self.private),
            "--context",
            "local",
            "--image-id",
            image,
            "--project",
            "fixture",
            "--state-volume",
            "fixture_runner-state",
            "--enrollment-id",
            "enrollment-fixture",
            "--runner-id",
            self.f.row["registration_policy"]["runner_id"],
            "--origin",
            ORIGIN,
            "--public-trust",
            str(self.ca),
            "--admission-root",
            str(self.public),
            "--runner-network",
            "fixture_runner",
            "--launch-config",
            str(self.private / "config.json"),
        ]
        self.config = {
            "docker": str(self.private / "docker"),
            "docker_sha256": "5" * 64,
            "compose": str(self.private / "compose"),
            "compose_sha256": "6" * 64,
            "docker_config": str(self.private),
            "local_endpoint": ENDPOINT,
            "daemon_id": "daemon",
            "override": str(override),
            "empty_env": str(empty),
            "credential_file": str(empty),
            "credential_names": [],
            "https_port": 8443,
            "core_images": core_images,
            "source": {
                **self.f.row["source"],
                "compose_executable_sha256": "6" * 64,
                "unresolved_model_sha256": launcher.compose._MODEL_SHA256,
                "closed_override_sha256": hashlib.sha256(b"{}").hexdigest(),
                "environment_contract_sha256": host.digest(
                    {"credential_names": [], "https_port": 8443}
                ),
                "core_image_set_sha256": host.digest(core_images),
            },
        }
        (self.private / "config.json").write_bytes(host.canonical(self.config))
        if os.name != "nt":
            empty.chmod(0o600)
        self.identity = runtime.RuntimeIdentity(
            "daemon", CID, image, "fixture", "2026-11-06T20:00:00Z", "7" * 64
        )
        self.first = {**self.binding, "core": core, "all_worker_ids": []}
        self.state = {
            **self.binding,
            "volume": {
                "name": "fixture_runner-state",
                "source": "/daemon/volumes/fixture_runner-state/_data",
                "created_at": "2026-11-06T18:00:00Z",
            },
        }
        self.network = {
            **self.binding,
            "network": {"id": NETWORK, "name": "fixture_runner"},
        }
        self.ready = {"name": f"fixture_worker-ready-{RUNTIME_ID}", "config_hash": None}
        self.engine = Mock()
        self.engine.layout = runtime.WorkerLayout(
            str(self.trust),
            str(self.public / RUNTIME_ID),
            "fixture_runner-state",
            self.ready["name"],
        )
        self.engine._daemon_binding.return_value = (ENDPOINT, "daemon")
        self.engine.capture_created.return_value = SimpleNamespace(
            daemon_id="daemon", container_id=CID, image_id=image, project="fixture"
        )
        self.engine.capture_running.return_value = self.identity
        self.audit = host.canonical(
            {
                "schema": "vardr.worker-bootstrap-audit/1",
                "status": "clear",
                "reason": None,
                "complete": True,
                "runner_id": self.f.row["registration_policy"]["runner_id"],
                "worker_history": False,
                "global_holds": 0,
            }
        )
        self.calls = []
        self.mode = None

    def on_disk(self):
        (path,) = self.f.records.directory.glob("*.intent.json")
        return host._json(path.read_bytes())["payload"]

    def command(self, *argv):
        if argv[:2] == ("volume", "ls"):
            return ""
        if argv[:2] == ("volume", "create"):
            self.calls.append("volume")
            self.assertTrue(
                self.on_disk()["effects"]["readiness_may_have_been_created"]
            )
            self.ready["intent_id"] = argv[-2].split("=", 1)[1]
            return argv[-1]
        self.assertEqual(argv, ("container", "start", CID))
        self.calls.append("start")
        row = self.on_disk()
        self.assertTrue(row["effects"]["start_may_have_sent"])
        self.assertEqual(row["observations"]["created"]["container_id"], CID)
        if self.mode == "start":
            raise runtime.RuntimeRefused("sensitive text must stay out of the CLI")
        return CID

    def create(self, selected, project, ordinal, *, before_send, **_):
        self.assertEqual(project.ready_volume, self.ready["name"])
        self.assertEqual(ordinal, 2 if self.first["all_worker_ids"] else 1)
        before_send()
        self.calls.append("create")
        self.assertTrue(self.on_disk()["effects"]["container_create_may_have_sent"])
        if self.mode == "create":
            raise runtime.RuntimeRefused("sensitive text must stay out of the CLI")

    def admit(self, args, records, operation, setup, **selected):
        self.calls.append("admit")
        self.assertEqual(args.container_id, CID)
        self.assertEqual(
            self.on_disk()["observations"]["running"], asdict(self.identity)
        )
        self.assertIsNotNone(selected["registration_capability"])
        self.assertIsNotNone(selected["preauthenticated_owner"])
        self.assertIs(setup[0], self.engine)
        records._require_operation(operation)
        return {"runtime_sha256": "a" * 64}, self.identity

    def exercise(self, *, successor=False):
        old = dict.fromkeys(
            (
                "ordinal",
                "container_id",
                "image_id",
                "runtime_id",
                "runtime_sha256",
                "admission_sha256",
                "host_retirement_sha256",
                "original_local_audit_sha256",
            )
        )
        old.update(
            ordinal=1,
            container_id=OLD_CID,
            image_id=self.identity.image_id,
            runtime_id=cases.PREVIOUS,
        )
        for name in (
            "runtime_sha256",
            "admission_sha256",
            "host_retirement_sha256",
            "original_local_audit_sha256",
        ):
            old[name] = "3" * 64
        prior_ready = []
        if successor:
            self.first["all_worker_ids"] = [OLD_CID]
            prior_ready = [{"name": "old-ready"}]
        base = (self.first, self.state, self.network, prior_ready)
        prepared = (*base[:3], [*prior_ready, self.ready])
        created = (
            {
                **self.first,
                "all_worker_ids": sorted([*self.first["all_worker_ids"], CID]),
            },
            *prepared[1:],
        )
        output = io.StringIO()
        self.engine._command.side_effect = self.command
        with ExitStack() as stack:

            def substitute(target, name, **options):
                return stack.enter_context(patch.object(target, name, **options))

            substitute(
                os, "environ", new={**os.environ, "VARDRMAP_API_KEY": "vmap_synthetic"}
            )
            substitute(launcher, "_Engine", return_value=self.engine)
            substitute(
                launcher, "_inventory", side_effect=[base, base, prepared, created]
            )
            audit = substitute(launcher, "_audit", return_value=self.audit)
            substitute(
                launcher, "_retired", return_value=([old] if successor else [], [])
            )
            substitute(launcher, "_ordinal", return_value=2 if successor else 1)
            substitute(
                launcher.volumes,
                "capture_volume_resource",
                return_value={"volume": self.ready},
            )
            substitute(launcher.compose, "create_worker", side_effect=self.create)
            substitute(launcher.cli, "records_for", return_value=self.f.records)
            substitute(
                launcher.cli, "public_trust", return_value=b"fake reviewed trust"
            )
            substitute(
                launcher.cli,
                "_preauthenticate_enable_owner",
                return_value=nullcontext(object()),
            )
            substitute(launcher.cli, "_enable_owned", side_effect=self.admit)
            substitute(launcher.host, "HostClient", return_value=object())
            substitute(self.f.records, "outside_mounts")
            substitute(
                launcher.intent.IntentStore,
                "registration_capability",
                return_value=object(),
            )
            with patch("sys.stdout", output):
                status = cli.main(self.args, installation=self.install)
            self.assertEqual(audit.call_count, 0 if successor else 1)
        return status, json.loads(output.getvalue())

    def test_cli_first_launch_uses_bootstrap_audit_and_fences_exact_effects(self):
        status, reply = self.exercise()
        self.assertEqual((status, reply["state"]), (0, "enabled"), reply)
        self.assertEqual(self.calls, ["volume", "create", "start", "admit"])
        self.assertEqual(self.engine._network.call_count, 2)
        self.engine._network.assert_called_with(CID, created=True)
        self.assertEqual(
            self.on_disk()["bootstrap_audit_sha256"],
            host.digest(host._json(self.audit)),
        )

    def test_cli_successor_uses_retired_predecessors_and_creates_only_one_worker(self):
        status, reply = self.exercise(successor=True)
        self.assertEqual((status, reply["state"]), (0, "enabled"), reply)
        self.assertEqual(self.calls, ["volume", "create", "start", "admit"])
        self.assertEqual(self.on_disk()["predecessors"][0]["container_id"], OLD_CID)
        self.assertNotIn("bootstrap_audit_sha256", self.on_disk())

    def test_lost_create_reply_holds_without_start_or_admission(self):
        self.mode = "create"
        status, reply = self.exercise()
        self.assertEqual(
            (status, reply["state"], reply["failure_phase"]),
            (1, "held", "launch_create"),
            reply,
        )
        self.assertEqual(self.calls, ["volume", "create"])
        self.assertTrue(self.on_disk()["effects"]["container_create_may_have_sent"])
        self.assertFalse(self.on_disk()["effects"]["start_may_have_sent"])

    def test_lost_start_reply_holds_without_admission(self):
        self.mode = "start"
        status, reply = self.exercise()
        self.assertEqual(
            (status, reply["state"], reply["failure_phase"]),
            (1, "held", "launch_start"),
            reply,
        )
        self.assertEqual(self.calls, ["volume", "create", "start"])
        self.assertTrue(self.on_disk()["effects"]["start_may_have_sent"])
        self.assertIsNone(self.on_disk()["observations"]["running"])

    def test_offline_audit_refusal_identifies_the_runner_step(self):
        args = SimpleNamespace()
        project = SimpleNamespace(name="fixture")
        self.engine._command.return_value = json.dumps(
            {"id": self.identity.image_id, "volumes": None}
        )
        self.engine.worker_state.side_effect = runtime.RuntimeRefused("private")
        with patch.object(
            launcher.volumes, "capture_volume_resource", return_value=self.state
        ):
            with self.assertRaises(runtime.RuntimeRefused):
                launcher._audit(
                    self.engine,
                    project,
                    self.state,
                    self.identity.image_id,
                    "worker-bootstrap-state",
                    ("--runner-id", cases.PREVIOUS),
                    args,
                )
        self.assertEqual(
            cli.failure_diagnostic(args, runtime.RuntimeRefused("private")),
            {"failure_code": "runtime_refused", "failure_phase": "launch_audit_run"},
        )

    def test_reviewed_credential_names_can_use_the_native_name_range(self):
        names = ["_mixedCase" + "a" * 117] + [f"reader_{index}" for index in range(31)]
        config = {**self.config, "credential_names": names}
        path = self.private / "config.json"
        path.write_bytes(host.canonical(config))
        self.assertEqual(launcher._config(str(path))["credential_names"], names)
