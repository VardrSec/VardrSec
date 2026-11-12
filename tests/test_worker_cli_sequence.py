"""Explicit sequence CLI routing; all transport/observation is mocked."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_worker_cli as fixtures
import worker_cli as cli
import worker_runtime as runtime


class SequenceCLITests(unittest.TestCase):
    def test_reconcile_guidance_preserves_receipt_states_and_never_replays(self):
        for schema in (1, 2, 3):
            for terminal, disabled in (
                (None, False), ({"retired": True}, False), (None, True)
            ):
                if disabled and schema != 3:
                    continue
                with (
                    self.subTest(schema=schema, terminal=terminal, disabled=disabled),
                    tempfile.TemporaryDirectory() as t,
                ):
                    root = Path(t)
                    f = fixtures.WorkerCLI().fixture(root)
                    observed = (
                        {"receipt": terminal}
                        if schema == 1
                        else {
                            "schema": f"vardr.worker-receipt-observation/{schema}",
                            "active": {"receipt": {"outcome": "completed"}},
                            "retirement": terminal,
                        }
                    )
                    output = io.StringIO()
                    with (
                        patch.object(cli, "records_for", return_value=f.records),
                        patch.object(cli, "components", return_value=(
                            f.client, f.observer, f.identity
                        )),
                        patch.object(cli, "load", return_value={
                            "disable_state": "observed" if disabled else "none"
                        }),
                        patch.object(
                            cli.host, "reconcile_exit", return_value=observed
                        ) as lookup,
                        patch.object(cli.host, "register_runtime") as register,
                        patch.object(cli.host, "report_observed_exit") as report,
                        patch.object(cli.host, "continue_observed_exit") as continuation,
                        contextlib.redirect_stdout(output),
                    ):
                        code = cli.main(
                            ["reconcile", "--runtime-id", fixtures.RID,
                             "--private-root", str(root)],
                            installation=root,
                        )
                    reply = json.loads(output.getvalue())
                    held = terminal is None and not disabled
                    self.assertEqual(code, 1 if held else 0)
                    self.assertEqual(reply["receipt"], observed)
                    self.assertEqual(reply["runtime_id"], fixtures.RID)
                    expected_state = (
                        "new_work_disabled_observed" if disabled
                        else "terminal_observed" if terminal is not None
                        else "held_no_terminal_receipt" if schema == 1
                        else "held_no_retirement_receipt"
                    )
                    self.assertEqual(reply["state"], expected_state)
                    if held:
                        self.assertEqual(
                            reply["next_action"],
                            "Keep Map and the original custody available. Follow the recovery "
                            "guide; do not resend an uncertain report or start a replacement worker."
                        )
                        self.assertEqual(
                            reply["help"], "docs/local-managed-setup.md#recovery-boundary"
                        )
                    else:
                        self.assertNotIn("next_action", reply)
                        self.assertNotIn("help", reply)
                    lookup.assert_called_once_with(f.client, f.records, fixtures.RID)
                    register.assert_not_called()
                    report.assert_not_called()
                    continuation.assert_not_called()
                    self.assertEqual(f.observer.commands, [])

    def test_continuation_is_separate_explicit_action_with_typed_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            f = fixtures.WorkerCLI().fixture(root)
            f.observer.state = {"Status": "exited", "Running": False}
            args = cli.parser().parse_args(
                [
                    "report-exit",
                    "--runtime-id",
                    fixtures.RID,
                    "--private-root",
                    str(root),
                    "--continue-after-transition",
                ]
            )
            with (
                patch.object(cli, "records_for", return_value=f.records),
                patch.object(
                    cli, "components", return_value=(f.client, f.observer, f.identity)
                ),
                patch.object(
                    cli.host,
                    "continue_observed_exit",
                    return_value={"receipt": {"retired": True}},
                ) as continuation,
                patch.object(cli.host, "report_observed_exit") as initial,
            ):
                cli.dispatch(root, args)
            self.assertIsInstance(continuation.call_args.args[3], runtime.ObservedExit)
            self.assertIs(continuation.call_args.args[4], f.observer)
            initial.assert_not_called()

    def test_v2_reconcile_needs_retirement_not_just_completed_job(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            f = fixtures.WorkerCLI().fixture(root)
            args = cli.parser().parse_args(
                ["reconcile", "--runtime-id", fixtures.RID, "--private-root", str(root)]
            )
            observed = {
                "schema": "vardr.worker-receipt-observation/2",
                "active": {"receipt": {"outcome": "completed"}},
                "retirement": None,
            }
            with (
                patch.object(cli, "records_for", return_value=f.records),
                patch.object(
                    cli, "components", return_value=(f.client, f.observer, f.identity)
                ),
                patch.object(cli.host, "reconcile_exit", return_value=observed),
            ):
                reply = cli.dispatch(root, args)
            self.assertEqual(reply["state"], "held_no_retirement_receipt")

    def test_explicit_maximum_is_bounded_before_any_observation(self):
        from types import SimpleNamespace

        for maximum in (0, 33, True):
            with (
                self.subTest(maximum=maximum),
                patch.object(cli.runtime, "LocalDocker") as observer,
            ):
                with self.assertRaises(cli.CLIRefused):
                    cli.enable(
                        Path("."), SimpleNamespace(expires_in=900, max_attempts=maximum)
                    )
                observer.assert_not_called()
