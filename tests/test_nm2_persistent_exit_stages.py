"""Pure boundary diagnostics; no daemon, Runner, credentials or target access."""

import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import nm2_worker_acceptance as acceptance
import nm2_worker_hosted as hosted
import worker_runtime


class PersistentExitStages(unittest.TestCase):
    def fixture(self, directory, *, persistent=True):
        sources = {
            name: {"path": str(directory / name), "commit": "d" * 40}
            for name in ("distribution", "map", "runner", "gate")
        }
        sources["distribution"]["path"] = str(Path(acceptance.__file__).parents[1])
        selection = {
            "sources": sources,
            "images": {
                name: "sha256:" + "b" * 64
                for name in ("db", "api", "web", "proxy", "worker")
            },
            "installation": str(directory / "installation"),
            "private_root": str(directory / "custody"),
            "project": "vardrsec-nm2-stageunit",
            "https_port": 28443,
            "docker_context": "synthetic-context",
        }
        fixture = acceptance.Fixture(
            selection,
            scenario="persistent-availability" if persistent else "healthy",
            database_revision=(
                "0041persistentruntime" if persistent else "0040runtimesequence"
            ),
        )
        fixture.install.mkdir()
        fixture.private.mkdir()
        fixture.trust, fixture.password = [], "synthetic-unit-passphrase"
        identity = worker_runtime.RuntimeIdentity(
            "owned-daemon",
            "a" * 64,
            fixture.images["worker"],
            fixture.project,
            "2026-11-06T02:00:00.000000Z",
            "c" * 64,
        )
        admission = {
            "schema": (
                "vardr.worker-admission/3" if persistent else "vardr.worker-admission/2"
            ),
            "runtime_id": "00000000-0000-4000-8000-000000000090",
            "runtime_sha256": acceptance.digest(
                acceptance.canonical(acceptance.asdict(identity))
            ),
        }
        if persistent:
            admission.update(
                mode="persistent",
                limits={"max_attempts": None, "idle_timeout_seconds": None},
                reporting_authority={"purpose": "worker-stop-only", "expires_at": None},
            )
            admission["admission_sha256"] = acceptance.digest(
                acceptance.canonical(admission)
            )
        else:
            admission["max_attempts"] = 2
        observer = Mock()
        observer.capture_running.return_value = identity
        observer.observe_exit.return_value = SimpleNamespace(
            exit_code=0, finished_at="2026-11-06T02:01:00.000000Z"
        )
        fixture.compose = Mock(
            side_effect=lambda *args, **kwargs: (
                identity.container_id.encode() if "ps" in args else b""
            )
        )

        def enable(arguments, **kwargs):
            if persistent:
                self.assertNotIn("--max-attempts", arguments)
            else:
                self.assertEqual(arguments[arguments.index("--max-attempts") + 1], "2")
            (fixture.install / "worker-public" / "admission.json").write_bytes(
                acceptance.canonical(admission)
            )
            return acceptance.canonical(
                {
                    "schema": "vardr.worker-cli/1",
                    "state": "enabled",
                    "identity": acceptance.asdict(identity),
                    **{key: admission[key] for key in ("runtime_id", "runtime_sha256")},
                }
            )

        def stopped(selected):
            self.assertEqual(selected, admission)
            fixture.receipt["stage"] = (
                "persistent_operator_stop" if persistent else "happy_verification"
            )
            fixture.operator_stop = {
                "identity": acceptance.asdict(identity),
                "exit_code": 0,
                "finished_at": "2026-11-06T02:01:00.000000Z",
                "state": "stopped_observed",
            }

        return SimpleNamespace(
            fixture=fixture,
            selection=selection,
            identity=identity,
            admission=admission,
            observer=observer,
            enable=enable,
            stopped=stopped,
        )

    def invoke(self, model, callback=None):
        with (
            patch.object(worker_runtime, "LocalDocker", return_value=model.observer),
            patch.object(acceptance, "worker_cli_command", side_effect=model.enable),
        ):
            return model.fixture.worker(
                "runner", "enrollment", on_running=callback or model.stopped
            )

    def test_observer_refusal_follows_stop_and_retains_observation_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            model = self.fixture(Path(temporary))
            order = []

            def stopped(admission):
                order.append("stop")
                model.stopped(admission)

            def refused(identity):
                order.append("observer")
                self.assertEqual(identity, model.identity)
                self.assertEqual(
                    model.fixture.receipt["stage"], "persistent_exit_observation"
                )
                raise worker_runtime.RuntimeRefused("worker_runtime_refused")

            model.observer.observe_exit.side_effect = refused
            with self.assertRaises(worker_runtime.RuntimeRefused):
                self.invoke(model, stopped)
            self.assertEqual(order, ["stop", "observer"])
            self.assertEqual(
                model.fixture.receipt["stage"], "persistent_exit_observation"
            )
            model.observer.observe_exit.assert_called_once_with(model.identity)

    def test_stop_failure_retains_stop_stage_without_observing_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            model = self.fixture(Path(temporary))

            def refused(admission):
                model.stopped(admission)
                raise acceptance.AcceptanceRefused("fixture_command_failed")

            with self.assertRaisesRegex(
                acceptance.AcceptanceRefused, "^fixture_command_failed$"
            ):
                self.invoke(model, refused)
            self.assertEqual(model.fixture.receipt["stage"], "persistent_operator_stop")
            model.observer.observe_exit.assert_not_called()

    def test_mismatched_exit_retains_binding_stage_and_refuses_return(self):
        with tempfile.TemporaryDirectory() as temporary:
            model = self.fixture(Path(temporary))

            def changed(admission):
                model.stopped(admission)
                model.fixture.operator_stop["exit_code"] = 1

            with self.assertRaisesRegex(
                acceptance.AcceptanceRefused, "^persistent_stop_exit_changed$"
            ):
                self.invoke(model, changed)
            self.assertEqual(model.fixture.receipt["stage"], "persistent_exit_binding")
            model.observer.observe_exit.assert_called_once_with(model.identity)

    def test_matching_exit_preserves_original_persistent_reply(self):
        with tempfile.TemporaryDirectory() as temporary:
            model = self.fixture(Path(temporary))
            result = self.invoke(model)
            self.assertEqual(model.fixture.receipt["stage"], "persistent_exit_binding")
            self.assertEqual(
                result,
                {
                    "identity": acceptance.asdict(model.identity),
                    "runtime_id": model.admission["runtime_id"],
                    "runtime_sha256": model.admission["runtime_sha256"],
                    "exit_code": 0,
                    "finished_at": "2026-11-06T02:01:00.000000Z",
                    "operator_enable_state": "enabled",
                    "admission_sha256": model.admission["admission_sha256"],
                    "operator_stop_state": "stopped_observed",
                },
            )

    def test_finite_worker_preserves_previous_stage_and_reply(self):
        with tempfile.TemporaryDirectory() as temporary:
            model = self.fixture(Path(temporary), persistent=False)
            result = self.invoke(model)
            self.assertEqual(model.fixture.receipt["stage"], "happy_verification")
            self.assertEqual(
                set(result),
                {
                    "identity",
                    "runtime_id",
                    "runtime_sha256",
                    "exit_code",
                    "finished_at",
                    "operator_enable_state",
                },
            )
            model.observer.observe_exit.assert_called_once_with(model.identity)

    def held(self):
        selection = {
            "sources": {
                name: {"commit": "d" * 40}
                for name in ("distribution", "map", "runner", "gate")
            },
            "images": {"worker": "sha256:" + "b" * 64},
            "project": "vardrsec-nm2-stageunit",
        }
        raw = {
            **copy.deepcopy(selection),
            "schema": "vardr.nm2-worker-persistent-acceptance/1",
            "status": "held",
            "platform": "linux",
            "scenario": "persistent-availability",
            "expected_database_revision": "0041persistentruntime",
            "reason": "fixture_stage_failed",
            "detail": "private-error-text-canary",
            "stdout": "private-stdout-canary",
            "stderr": "private-stderr-canary",
            "exception_type": "private-exception-canary",
        }
        return raw, selection

    def test_projection_keeps_only_fixed_stop_and_exit_stages(self):
        for stage in (
            "persistent_operator_stop",
            "persistent_exit_observation",
            "persistent_exit_binding",
        ):
            with self.subTest(stage=stage):
                raw, selection = self.held()
                raw["stage"] = stage
                public = hosted.failure_projection(raw, selection)
                self.assertEqual(
                    public, {"stage": stage, "reason": "fixture_stage_failed"}
                )
                self.assertNotIn("private-", json.dumps(public))

    def test_projection_does_not_export_unknown_stage_or_nested_error_values(self):
        raw, selection = self.held()
        raw["stage"] = "persistent_exit_private-error-canary"
        raw["command_failure"] = {"failure_phase": "private-phase-canary"}
        raw["status_failure"] = {"checkpoint": "private-checkpoint-canary"}
        self.assertEqual(
            hosted.failure_projection(raw, selection),
            {"stage": "unclassified", "reason": "fixture_stage_failed"},
        )
