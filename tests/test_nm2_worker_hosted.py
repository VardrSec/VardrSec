"""Hosted authorization/refusal and sanitized-receipt checks; no Docker/network."""

from contextlib import redirect_stdout
import copy
import io
import json
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import nm2_worker_hosted as hosted


def environment(temporary):
    return {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_REPOSITORY": "VardrSec/VardrSec",
        "GITHUB_REF": hosted.BRANCH,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "NM2_COUPLED": "true",
        "GITHUB_WORKSPACE": str(hosted.SOURCE),
        "RUNNER_TEMP": str(temporary),
        "GITHUB_SHA": "a" * 40,
        "GITHUB_RUN_ID": "123456789",
        "GITHUB_RUN_ATTEMPT": "1",
        **{
            "NM2_" + name.upper() + "_SHA": value * 40
            for name, value in (
                ("distribution", "a"),
                ("map", "b"),
                ("runner", "c"),
                ("gate", "d"),
            )
        },
        "GITHUB_TOKEN": "private-do-not-publish",
        "PATH": "fixture-path",
        "HOME": str(temporary),
    }


def raw_receipt(selection):
    value = {
        "schema": "vardr.nm2-worker-acceptance/1",
        "status": "initial_stages_passed",
        "sources": selection["sources"],
        "images": selection["images"],
        "project": selection["project"],
        "readiness_volume": selection["project"] + "_worker-ready",
        "platform": "linux",
        "retained": True,
        "cases": {
            name: {
                "status": "not_run" if name == "missing_local_grant" else "passed",
                "raw_secret": "private-do-not-publish",
            }
            for name in hosted.CASES
        },
        "image_sources": {
            name: {
                "image_id": selection["images"][image],
                "python_file_count": 10,
                "python_inventory_sha256": "e" * 64,
                **(
                    {
                        "executables": {
                            path: "f" * 64
                            for path in (
                                "/usr/local/bin/vardr-worker-owner",
                                "/usr/local/bin/vardrgate",
                            )
                        }
                    }
                    if name == "runner"
                    else {}
                ),
            }
            for name, image in (("map", "api"), ("runner", "worker"))
        },
        "private_path": "/private/custody",
        "logs": "private-do-not-publish",
    }
    value["cases"]["happy_fixed"].update(
        requests=[
            {"identity": identity, "path": "/private/raw-record"}
            for identity in ("owner", "owner", "peer", "peer", "anonymous")
        ],
        evidence_count=5,
        evidence_sha256="4" * 64,
        case_sha256="6" * 64,
        inventory={
            "results": [
                {
                    "artifact_sha256": "1" * 64,
                    "receipt_sha256": "2" * 64,
                    "outcome": "completed",
                    "evidence_created": 5,
                    "scan_items_created": 0,
                }
            ]
        },
    )
    value["public_ca_der_sha256"] = "5" * 64
    value["fixture_stop"] = {
        "status": "stopped_retained",
        "container_ids": ["0123456789abcdef" * 4, "fedcba9876543210" * 4],
        "stop_requested_ids": ["0123456789abcdef" * 4],
    }
    return value


class HostedGuards(unittest.TestCase):
    def test_default_mode_and_invalid_sha_never_touch_docker_or_network(self):
        output = io.StringIO()
        with patch.object(hosted.subprocess, "run") as run, redirect_stdout(output):
            self.assertEqual(hosted.main([]), 2)
        run.assert_not_called()
        with tempfile.TemporaryDirectory() as temporary:
            valid = environment(temporary)
            for name, value in (
                ("NM2_MAP_SHA", "main"),
                ("NM2_GATE_SHA", ""),
                ("NM2_RUNNER_SHA", "a" * 39),
                ("GITHUB_SHA", "e" * 40),
            ):
                with (
                    self.subTest(name=name),
                    patch.object(hosted, "host_guard") as guard,
                ):
                    with self.assertRaises(hosted.HostedRefused):
                        hosted.Hosted({**valid, name: value})
                    guard.assert_not_called()

    def test_wrong_host_ref_event_or_inherited_runtime_environment_refuses_before_commands(
        self,
    ):
        for name, value in (
            ("RUNNER_ENVIRONMENT", "self-hosted"),
            ("GITHUB_REF", "refs/heads/main"),
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_REPOSITORY", "other/repo"),
            ("NM2_COUPLED", "false"),
            ("DOCKER_HOST", "ssh://remote"),
            ("VARDRMAP_API_KEY", "private-do-not-publish"),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                with (
                    patch.object(
                        hosted.platform,
                        "freedesktop_os_release",
                        return_value={"ID": "ubuntu", "VERSION_ID": "24.04"},
                    ),
                    patch.object(hosted.platform, "system", return_value="Linux"),
                    patch.object(hosted.platform, "machine", return_value="x86_64"),
                    patch.object(hosted.subprocess, "run") as run,
                ):
                    with self.assertRaises(hosted.HostedRefused):
                        hosted.host_guard({**environment(temporary), name: value})
                    run.assert_not_called()

    def test_exact_host_needs_ubuntu24_and_root_owned_unix_socket(self):
        original = Path.stat
        with tempfile.TemporaryDirectory() as temporary:
            env = environment(temporary)
            for system, arch, version, mode, uid in (
                ("Linux", "x86_64", "24.04", stat.S_IFSOCK, 0),
                ("Linux", "x86_64", "26.04", stat.S_IFSOCK, 0),
                ("Linux", "aarch64", "24.04", stat.S_IFSOCK, 0),
                ("Linux", "x86_64", "24.04", stat.S_IFREG, 0),
                ("Linux", "x86_64", "24.04", stat.S_IFSOCK, 1000),
            ):

                def measured(path, *args, **kwargs):
                    if path.as_posix() == "/var/run/docker.sock":
                        return SimpleNamespace(st_mode=mode, st_uid=uid)
                    return original(path, *args, **kwargs)

                with (
                    self.subTest(version=version, uid=uid, mode=mode),
                    patch.object(
                        hosted.platform,
                        "freedesktop_os_release",
                        return_value={"ID": "ubuntu", "VERSION_ID": version},
                    ),
                    patch.object(hosted.platform, "system", return_value=system),
                    patch.object(hosted.platform, "machine", return_value=arch),
                    patch.object(Path, "stat", measured),
                ):
                    if (
                        version == "24.04"
                        and arch == "x86_64"
                        and mode == stat.S_IFSOCK
                        and uid == 0
                    ):
                        self.assertEqual(hosted.host_guard(env), Path(temporary))
                    else:
                        with self.assertRaises(hosted.HostedRefused):
                            hosted.host_guard(env)

    def test_nonlocal_nonempty_or_changed_daemon_refuses(self):
        info = {
            "os": "linux",
            "name": "fixture-host",
            "root": "/var/lib/docker",
            "swarm": "inactive",
        }
        for change in (
            None,
            "remote",
            "host",
            "root",
            "containers",
            "volumes",
            "networks",
        ):
            obj = hosted.Hosted.__new__(hosted.Hosted)

            def docker(*args, **kwargs):
                if args[0] == "context":
                    return json.dumps(
                        "ssh://remote"
                        if change == "remote"
                        else "unix:///var/run/docker.sock"
                    )
                if args[0] == "info":
                    return json.dumps(
                        {
                            **info,
                            **({"name": "another-host"} if change == "host" else {}),
                            **({"root": "/other"} if change == "root" else {}),
                        }
                    )
                if args[0] == "ps":
                    return "retained-container" if change == "containers" else ""
                if args[0] == "volume":
                    return "retained-volume" if change == "volumes" else ""
                return "bridge\nhost\nnone" + (
                    "\nunreviewed" if change == "networks" else ""
                )

            obj.docker = Mock(side_effect=docker)
            with (
                self.subTest(change=change),
                patch.object(hosted.socket, "gethostname", return_value="fixture-host"),
            ):
                if change is None:
                    obj.daemon_guard()
                else:
                    with self.assertRaises(hosted.HostedRefused):
                        obj.daemon_guard()
            self.assertFalse(
                any(
                    call.args[0] in {"build", "run", "rm", "prune"}
                    for call in obj.docker.call_args_list
                )
            )

    def test_existing_private_fixture_refuses_reuse_and_child_environment_excludes_secrets(
        self,
    ):
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(hosted, "host_guard", return_value=Path(temporary)),
        ):
            obj = hosted.Hosted(environment(temporary))
            self.assertNotIn("GITHUB_TOKEN", obj.environment)
            self.assertEqual(obj.environment["PYTHON_DOTENV_DISABLED"], "1")
            self.assertEqual(Path(obj.environment["HOME"]).parent, obj.root)
            with self.assertRaises(hosted.HostedRefused):
                hosted.Hosted(environment(temporary))
            with patch.object(
                hosted.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, b"public", b""),
            ) as run:
                self.assertEqual(
                    obj.command(["fixture", "metadata"], capture=True), "public"
                )
            self.assertNotIn("GITHUB_TOKEN", run.call_args.kwargs["env"])

    def test_public_receipt_excludes_raw_data_and_rejects_mismatched_cohort(self):
        selection = {
            "project": "vardrsec-nm2-12345678",
            "sources": {"map": {"path": "/private/source", "commit": "a" * 40}},
            "images": {"api": "sha256:" + "a" * 64, "worker": "sha256:" + "b" * 64},
        }
        raw = raw_receipt(selection)
        projected = hosted.public_projection(raw, selection)
        self.assertNotIn("private", json.dumps(projected))
        self.assertEqual(projected["cases"]["missing_local_grant"], "not_run")
        self.assertEqual(
            projected["measurements"],
            {
                "target_request_count": 5,
                "evidence_count": 5,
                "case_sha256": "6" * 64,
                "evidence_sha256": "4" * 64,
                "result_artifact_sha256": "1" * 64,
                "result_receipt_sha256": "2" * 64,
                "public_ca_der_sha256": "5" * 64,
                "stopped_owned_container_count": 2,
            },
        )
        self.assertNotIn("0123456789abcdef" * 4, json.dumps(projected))
        for mutation in ("image", "source", "case", "binary", "failure"):
            bad = copy.deepcopy(raw)
            if mutation == "image":
                bad["images"]["worker"] = "sha256:" + "c" * 64
            elif mutation == "source":
                bad["sources"]["map"]["commit"] = "c" * 40
            elif mutation == "case":
                bad["cases"]["happy_fixed"]["status"] = "not_run"
            elif mutation == "binary":
                bad["image_sources"]["runner"]["executables"][
                    "/usr/local/bin/vardrgate"
                ] = "not-a-hash"
            else:
                bad["status"] = "held"
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(hosted.HostedRefused),
            ):
                hosted.public_projection(bad, selection)

    def test_acceptance_measurement_tampering_never_becomes_public_success(self):
        selection = {
            "project": "vardrsec-nm2-12345678",
            "sources": {},
            "images": {"api": "sha256:" + "a" * 64, "worker": "sha256:" + "b" * 64},
        }
        for mutation in (
            "requests",
            "identities",
            "evidence",
            "boolean_count",
            "case_hash",
            "evidence_hash",
            "artifact_hash",
            "receipt_hash",
            "ca_hash",
            "result_count",
            "result_evidence",
            "stop_status",
            "stop_empty",
            "stop_duplicate",
            "stop_id",
        ):
            bad = raw_receipt(selection)
            happy = bad["cases"]["happy_fixed"]
            result = happy["inventory"]["results"][0]
            if mutation == "requests":
                happy["requests"].append(happy["requests"][0])
            elif mutation == "identities":
                happy["requests"][4]["identity"] = "unexpected"
            elif mutation == "evidence":
                happy["evidence_count"] = 4
            elif mutation == "boolean_count":
                happy["evidence_count"] = True
            elif mutation == "case_hash":
                happy["case_sha256"] = "private-do-not-publish"
            elif mutation == "evidence_hash":
                happy["evidence_sha256"] = "E" * 64
            elif mutation == "artifact_hash":
                result["artifact_sha256"] = None
            elif mutation == "receipt_hash":
                result["receipt_sha256"] = "not-a-hash"
            elif mutation == "ca_hash":
                bad["public_ca_der_sha256"] = "private-do-not-publish"
            elif mutation == "result_count":
                happy["inventory"]["results"].append(result)
            elif mutation == "result_evidence":
                result["evidence_created"] = 4
            elif mutation == "stop_status":
                bad["fixture_stop"]["status"] = "unknown_preserve_resources"
            elif mutation == "stop_empty":
                bad["fixture_stop"]["container_ids"] = []
            elif mutation == "stop_duplicate":
                bad["fixture_stop"]["container_ids"] *= 2
            else:
                bad["fixture_stop"]["container_ids"][0] = "/private/not-an-id"
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(hosted.HostedRefused),
            ):
                hosted.public_projection(bad, selection)

    def test_mismatched_or_dirty_checkout_refuses_before_any_image_build(self):
        for fault in ("head", "tracked"):
            with (
                self.subTest(fault=fault),
                tempfile.TemporaryDirectory() as temporary,
                patch.object(hosted, "host_guard", return_value=Path(temporary)),
            ):
                obj = hosted.Hosted(environment(temporary))

                def git(args, **kwargs):
                    if args[:2] == ["git", "rev-parse"]:
                        return obj.pins["distribution"]
                    if args[:2] == ["git", "-C"]:
                        name = Path(args[2]).name
                        tail = args[3:]
                        if tail == ["rev-parse", "HEAD"]:
                            return (
                                "e" * 40
                                if fault == "head" and name == "runner"
                                else obj.pins.get(name, obj.pins["distribution"])
                            )
                        if "status" in tail:
                            return (
                                " M vardrrunner/changed.py"
                                if fault == "tracked" and name == "runner"
                                else ""
                            )
                        if tail == ["rev-parse", "HEAD^{tree}"]:
                            return "e" * 40

                obj.command, obj.docker = Mock(side_effect=git), Mock()
                with self.assertRaises(hosted.HostedRefused):
                    obj.prepare_sources()
                obj.docker.assert_not_called()
                fetches = [
                    call.args[0]
                    for call in obj.command.call_args_list
                    if "fetch" in call.args[0]
                ]
                self.assertTrue(all(args[-1] in obj.pins.values() for args in fetches))

    def test_existing_unique_image_tag_is_preserved_instead_of_rebuilt(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(hosted, "host_guard", return_value=Path(temporary)),
        ):
            obj = hosted.Hosted(environment(temporary))
            obj.docker = Mock(return_value="retained-image-id")
            with self.assertRaises(hosted.HostedRefused):
                obj.build("api", Path(temporary))
            self.assertEqual(obj.docker.call_count, 1)
            self.assertEqual(obj.docker.call_args.args[:2], ("image", "ls"))

    def test_fixed_failure_output_never_echoes_private_exceptions(self):
        output = io.StringIO()
        with (
            patch.object(
                hosted, "Hosted", side_effect=RuntimeError("private-do-not-publish")
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(hosted.main(["--execute"]), 1)
        self.assertNotIn("private-do-not-publish", output.getvalue())

    def test_orchestrator_reuses_full_toolkit_named_gate_and_existing_harness(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(hosted, "host_guard", return_value=Path(temporary)),
            patch.object(hosted.socket, "socket"),
        ):
            obj = hosted.Hosted(environment(temporary))
            obj.sources.update({name: obj.root / name for name in hosted.REPOSITORIES})
            obj.daemon_guard, obj.prepare_sources = Mock(), Mock()
            calls, ids = [], {}

            def docker(*args, **kwargs):
                calls.append(args)
                if args[:2] == ("image", "ls"):
                    return ""
                if args[0] == "build":
                    tag = args[args.index("-t") + 1]
                    value = "sha256:" + str(len(ids) + 1) * 64
                    ids[tag] = value
                    Path(args[args.index("--iidfile") + 1]).write_text(value)
                else:
                    return ids[args[-1]]

            obj.docker = Mock(side_effect=docker)

            def command(args, **kwargs):
                if "--execute" in args:
                    selection = json.loads((obj.root / "cohort.json").read_text())
                    directory = obj.root / "installation"
                    directory.mkdir()
                    (directory / "nm2-worker-receipt.json").write_text(
                        json.dumps(raw_receipt(selection))
                    )

            obj.command = Mock(side_effect=command)
            obj.run()
            toolkit = next(args for args in calls if "toolkit" in args)
            self.assertIn("gate=" + str(obj.sources["gate"]), toolkit)
            worker = next(
                args
                for args in calls
                if "RUNNER_BASE_IMAGE=" + obj.project + ":toolkit" in args
            )
            self.assertIn(str(obj.sources["runner"] / "Dockerfile.worker"), worker)
            self.assertTrue(
                any(
                    str(hosted.SOURCE / "tests/nm2_worker_acceptance.py")
                    in call.args[0]
                    for call in obj.command.call_args_list
                )
            )
            public = json.loads((obj.public / "receipt.json").read_text())
            self.assertEqual(public["status"], "initial_stages_passed")
            self.assertNotIn("private", json.dumps(public))
            self.assertFalse(any(args[0] in {"push", "prune", "rm"} for args in calls))

    def test_workflow_opt_in_is_default_false_and_has_no_push_or_pr_activation(self):
        text = (hosted.SOURCE / ".github/workflows/compose.yml").read_text()
        block = text.split("      nm2_coupled:", 1)[1].split(
            "      nm2_distribution_sha:", 1
        )[0]
        self.assertIn("default: false", block)
        job = text.split("  nm2-coupled:", 1)[1].split("  certificate-renewal:", 1)[0]
        self.assertIn(
            "if: github.event_name == 'workflow_dispatch' && inputs.nm2_coupled == true",
            job,
        )
        self.assertIn("runs-on: ubuntu-24.04", job)
        self.assertEqual(job.count("path:"), 1)
        self.assertIn("${{ runner.temp }}/nm2-hosted-public/receipt.json", job)

    def test_invalid_measurement_keeps_public_stage_held_without_raw_payload(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(hosted, "host_guard", return_value=Path(temporary)),
            patch.object(hosted.socket, "socket"),
        ):
            obj = hosted.Hosted(environment(temporary))
            obj.sources.update({name: obj.root / name for name in hosted.REPOSITORIES})
            obj.daemon_guard, obj.prepare_sources = Mock(), Mock()
            obj.build = Mock(
                return_value=("sha256:" + "a" * 64, obj.project + ":toolkit")
            )
            obj.docker = Mock(return_value="sha256:" + "a" * 64)

            def command(args, **kwargs):
                if "--execute" in args:
                    selection = json.loads((obj.root / "cohort.json").read_text())
                    raw = raw_receipt(selection)
                    raw["public_ca_der_sha256"] = "private-do-not-publish"
                    directory = obj.root / "installation"
                    directory.mkdir()
                    (directory / "nm2-worker-receipt.json").write_text(json.dumps(raw))

            obj.command = Mock(side_effect=command)
            with self.assertRaises(hosted.HostedRefused):
                obj.run()
            public = json.loads((obj.public / "receipt.json").read_text())
            self.assertEqual((public["stage"], public["status"]), ("harness", "held"))
            self.assertNotIn("measurements", public)
            self.assertNotIn("private-do-not-publish", json.dumps(public))


if __name__ == "__main__":
    unittest.main()
