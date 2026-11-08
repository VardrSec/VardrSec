"""Explicit sequence CLI routing; all transport/observation is mocked."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_worker_cli as fixtures
import worker_cli as cli
import worker_runtime as runtime


class SequenceCLITests(unittest.TestCase):
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
