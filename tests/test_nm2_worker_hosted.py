"""Hosted authorization/refusal and sanitized-receipt checks; no Docker/network."""

from contextlib import redirect_stdout
import copy
import hashlib
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
        "schema": "vardr.nm2-worker-acceptance/2",
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

    def digest(item):
        return hashlib.sha256(
            json.dumps(
                item, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
        ).hexdigest()

    identity = {
        "daemon_id": "fixture-daemon",
        "container_id": "0123456789abcdef" * 4,
        "image_id": selection["images"]["worker"],
        "project": selection["project"],
        "started_at": "2026-11-06T02:00:00.000000001Z",
        "owner_nonce": "9" * 64,
    }
    runtime_id = "c52c1acc-5c25-4419-ae3b-90e14f744e3d"
    physical = {
        "identity": identity,
        "runtime_id": runtime_id,
        "runtime_sha256": digest(identity),
        "exit_code": 0,
        "finished_at": "2026-11-06T02:00:01.000001Z",
        "operator_enable_state": "enabled",
    }
    attempts = []
    for number in (1, 2):
        case_hash, artifact_hash, evidence_hash = (
            ("6", "1", "4") if number == 1 else ("7", "3", "8")
        )
        binding = {
            "origin": f"https://vardrsec.localhost:{selection['https_port']}/backend",
            "job_id": f"job-{number}",
            "runner_id": "ab6a22cf-29ae-4925-9fba-59aa331d4058",
            "contract_id": f"{number}" * 8
            + "-"
            + f"{number}" * 4
            + "-"
            + f"{number}" * 4
            + "-"
            + f"{number}" * 4
            + "-"
            + f"{number}" * 12,
            "attempt_id": f"{number + 2}" * 8
            + "-"
            + f"{number + 2}" * 4
            + "-"
            + f"{number + 2}" * 4
            + "-"
            + f"{number + 2}" * 4
            + "-"
            + f"{number + 2}" * 12,
            "fence": 1,
            "contract_sha256": str(number + 7) * 64,
        }
        result_hash = digest(
            {
                "schema": "vardr.managed-result/1",
                **binding,
                "artifact_sha256": artifact_hash * 64,
                "case_sha256": case_hash * 64,
            }
        )
        terminal = {
            "schema": "vardr.managed-completion/1",
            **binding,
            "outcome": "completed",
            "receipt_sha256": result_hash,
            "capacity_reserved": False,
        }
        release = {
            "schema": "vardr.worker-idle-release/1",
            "runtime_id": runtime_id,
            "runtime_sha256": physical["runtime_sha256"],
            "runtime_sequence": number,
            "binding": binding,
            "terminal_receipt_sha256": digest(terminal),
            "native_done_sha256": str(number + 4) * 64,
            "released": True,
        }
        release["receipt_sha256"] = digest(release)
        requests = [
            {
                "identity": who,
                "method": "GET",
                "path": ("/session" if index < 2 else "/fixed/records/42")
                + f"?nm2_case=job-{number}",
                "headers": {"private": "private-header-canary"},
                "received_monotonic_ns": number * 100 + index,
            }
            for index, who in enumerate(("owner", "peer", "owner", "peer", "anonymous"))
        ]
        attempts.append(
            {
                "runtime_sequence": number,
                "engagement_id": f"engagement-{number}",
                "job_id": binding["job_id"],
                "case_sha256": case_hash * 64,
                "evidence_count": 5,
                "evidence_sha256": evidence_hash * 64,
                "artifact_sha256": artifact_hash * 64,
                "result_receipt_sha256": result_hash,
                "terminal_receipt_sha256": digest(terminal),
                "release_receipt_sha256": release["receipt_sha256"],
                "native_done_sha256": release["native_done_sha256"],
                **{
                    key: f"2026-11-06T02:00:00.{(number - 1) * 3 + index:06d}Z"
                    for index, key in enumerate(
                        ("bound_at", "confirmed_at", "released_at"), 1
                    )
                },
                "binding": binding,
                "terminal_receipt": terminal,
                "release_receipt": release,
                "requests": requests,
                "assessment": {
                    "status": "conclusive",
                    "baseline_valid": True,
                    "case_snapshot_verified": True,
                    "preflight": {"status": "passed"},
                    "case_hash": case_hash * 64,
                    "candidate_findings": 0,
                },
                "target_charge": 1,
                "duration_seconds": 30,
                "capacity_reserved": False,
            }
        )
    first = attempts[0]
    value["cases"]["default_disabled"].update(
        services=["api", "db", "proxy", "web"],
        managed_pending_status=404,
        csrf_write_status=403,
        unauthenticated_read_status=401,
    )
    value["cases"]["strict_out_of_scope"].update(
        approval_http_status=409, traffic_delta=0
    )
    value["cases"]["happy_fixed"].update(
        physical=copy.deepcopy(physical),
        requests=copy.deepcopy(first["requests"]),
        **{
            key: first[key]
            for key in ("evidence_count", "evidence_sha256", "case_sha256")
        },
        inventory={
            "results": [
                {
                    "contract_id": first["binding"]["contract_id"],
                    "artifact_sha256": first["artifact_sha256"],
                    "receipt_sha256": first["result_receipt_sha256"],
                    "outcome": "completed",
                    "evidence_created": 5,
                    "scan_items_created": 0,
                }
            ]
        },
    )
    value["cases"]["healthy_sequence"] = {
        "status": "passed",
        "physical": physical,
        "runtime_id": runtime_id,
        "runtime_sha256": physical["runtime_sha256"],
        "max_attempts": 2,
        "last_sequence": 2,
        "active_sequence": None,
        "attempts": attempts,
        "target_request_count": 10,
        "evidence_count": 10,
        "targets_spent": 2,
        "duration_allocated": 60,
    }
    value["cases"]["happy_fixed"]["inventory"]["runtimes"] = [
        {
            "id": runtime_id,
            "runtime_sha256": physical["runtime_sha256"],
            "identity": copy.deepcopy(identity),
            "runner_id": attempts[0]["binding"]["runner_id"],
            "enrollment_id": "fixture-enrollment",
            "max_attempts": 2,
            "last_sequence": 2,
            "active_sequence": None,
            "retired": False,
            "report_sha256": None,
            "attempts": [
                {
                    "runtime_id": runtime_id,
                    **{
                        key: copy.deepcopy(attempt[key])
                        for key in (
                            "runtime_sequence",
                            "job_id",
                            "binding",
                            "bound_at",
                            "confirmed_at",
                            "released_at",
                            "terminal_receipt",
                            "terminal_receipt_sha256",
                            "native_done_sha256",
                            "release_receipt",
                        )
                    },
                }
                for attempt in attempts
            ],
        }
    ]
    value["public_ca_der_sha256"] = "5" * 64
    value["fixture_stop"] = {
        "status": "stopped_retained",
        "container_ids": [
            "0123456789abcdef" * 4,
            "fedcba9876543210" * 4,
            *[str(number) * 64 for number in (2, 4, 6, 8)],
        ],
        "stop_requested_ids": ["0123456789abcdef" * 4],
    }
    return value


class HostedGuards(unittest.TestCase):
    def test_physical_timestamps_preserve_nanoseconds_and_validate_calendar(self):
        whole = "2026-11-06T04:03:08"
        keys = [
            hosted._physical_time(whole + suffix)
            for suffix in (
                "Z",
                ".1Z",
                ".123Z",
                ".123456Z",
                ".123456001Z",
                ".123456002Z",
            )
        ]
        self.assertEqual(keys[0], whole + ".000000000Z")
        self.assertEqual(keys[1], whole + ".100000000Z")
        self.assertEqual(keys, sorted(set(keys)))
        self.assertLess(keys[-2], keys[-1])
        for value in (
            "2026-02-30T04:03:08.123456789Z",
            "2026-11-06T24:03:08.123456789Z",
            whole + ".1234567890Z",
            whole + ".Z",
            whole + ".123456789+00:00",
        ):
            with self.subTest(value=value), self.assertRaises(hosted.HostedRefused):
                hosted._physical_time(value)

    def failed_harness(self, *, mutate=None, raw_content=None, publish=True):
        """Exercise the real failure/read/projection/finally path with inert commands."""
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
                if "--execute" not in args:
                    return
                selection = json.loads((obj.root / "cohort.json").read_text())
                raw = raw_receipt(selection)
                raw.update(
                    status="held", stage="happy_setup", reason="fixture_http_status"
                )
                if mutate is not None:
                    mutate(raw)
                if publish:
                    directory = obj.root / "installation"
                    directory.mkdir()
                    (directory / "nm2-worker-receipt.json").write_bytes(
                        raw_content
                        if raw_content is not None
                        else json.dumps(raw).encode()
                    )
                raise subprocess.CalledProcessError(
                    1,
                    ["private-command-canary"],
                    output=b"private-output-canary",
                    stderr=b"private-stderr-canary",
                )

            obj.command = Mock(side_effect=command)
            output = io.StringIO()
            with (
                self.assertRaises(subprocess.CalledProcessError),
                redirect_stdout(output),
            ):
                obj.run()
            self.assertEqual(output.getvalue(), "")
            public = json.loads((obj.public / "receipt.json").read_text())
            self.assertEqual((public["stage"], public["status"]), ("harness", "held"))
            self.assertNotIn("measurements", public)
            self.assertNotIn("cases", public)
            self.assertNotIn("image_sources", public)
            self.assertNotIn("private", json.dumps(public))
            return public

    def test_failed_command_preserves_only_safe_inner_http_diagnostic(self):
        def diagnostic(raw):
            raw["http_failure"] = {
                "method": "POST",
                "route": "/jobs/{id}/managed/approval/review",
                "expected_status": 200,
                "actual_status": 409,
                "headers": {"Authorization": "private-header-canary"},
                "body": "private-body-canary",
                "extra": ["private-array-canary"],
            }
            raw["reason_detail"] = "private-reason-canary"
            raw["measurements"] = {"private": "private-partial-canary"}
            raw["cases"] = ["private-case-array-canary"]

        public = self.failed_harness(mutate=diagnostic)
        self.assertEqual(
            public["harness_failure"],
            {
                "stage": "happy_setup",
                "reason": "fixture_http_status",
                "http_failure": {
                    "method": "POST",
                    "route": "/jobs/{id}/managed/approval/review",
                    "expected_status": 200,
                    "actual_status": 409,
                },
            },
        )

    def test_actual_harness_command_failure_code_remains_actionable(self):
        public = self.failed_harness(
            mutate=lambda raw: raw.update(
                stage="managed_setup", reason="fixture_command_failed"
            )
        )
        self.assertEqual(
            public["harness_failure"],
            {"stage": "managed_setup", "reason": "fixture_command_failed"},
        )

    def test_v2_fixed_failure_reason_and_legacy_held_receipt_remain_redacted(self):
        public = self.failed_harness(
            mutate=lambda raw: raw.update(
                stage="healthy_sequence_verification",
                reason="healthy_sequence_release_after_next_binding",
                detail="private-new-stage-canary",
            )
        )
        self.assertEqual(
            public["harness_failure"],
            {
                "stage": "healthy_sequence_verification",
                "reason": "healthy_sequence_release_after_next_binding",
            },
        )
        legacy = self.failed_harness(
            mutate=lambda raw: raw.update(schema="vardr.nm2-worker-acceptance/1")
        )
        self.assertEqual(
            legacy["harness_failure"],
            {"stage": "happy_setup", "reason": "fixture_http_status"},
        )

    def test_unknown_failure_reason_stage_and_route_never_escape(self):
        def unknown(raw):
            raw.update(stage="private-stage-canary", reason="private-reason-canary")
            raw["http_failure"] = {
                "method": "GET",
                "route": "/private-route-canary?token=private-query-canary",
                "expected_status": 200,
                "actual_status": 403,
                "headers": ["private-header-canary"],
                "body": {"secret": "private-body-canary"},
            }

        public = self.failed_harness(mutate=unknown)
        self.assertEqual(
            public["harness_failure"],
            {
                "stage": "unclassified",
                "reason": "unclassified_refusal",
                "http_failure": {
                    "method": "GET",
                    "route": "other_route",
                    "expected_status": 200,
                    "actual_status": 403,
                },
            },
        )

    def test_invalid_http_statuses_do_not_export_partial_http_fields(self):
        for field, bad in (
            ("actual_status", True),
            ("actual_status", 600),
            ("expected_status", "private-status-canary"),
            ("expected_status", 99),
            ("method", "private-method-canary"),
        ):
            with self.subTest(field=field, bad=bad):

                def invalid(raw):
                    raw["http_failure"] = {
                        "method": "POST",
                        "route": "/auth/local/login",
                        "expected_status": 200,
                        "actual_status": 401,
                        field: bad,
                        "body": "private-body-canary",
                    }

                public = self.failed_harness(mutate=invalid)
                self.assertEqual(
                    public["harness_failure"],
                    {"stage": "happy_setup", "reason": "fixture_http_status"},
                )

    def test_missing_malformed_oversized_or_unbound_receipt_uses_fixed_fallback(self):
        scenarios = (
            {"publish": False},
            {"raw_content": b'{"secret":"private-json-canary"'},
            {"raw_content": b'["private-array-canary"]'},
            {"raw_content": b"x" * (4 * 1024 * 1024 + 1)},
            {"mutate": lambda raw: raw.update(status="initial_stages_passed")},
            {"mutate": lambda raw: raw.update(platform="private-platform-canary")},
            {"mutate": lambda raw: raw.update(project="private-project-canary")},
            {
                "mutate": lambda raw: raw.update(
                    images={"private": "private-image-canary"}
                )
            },
            {"mutate": lambda raw: raw.update(sources=["private-source-canary"])},
            {"mutate": lambda raw: raw.update(reason=["private-reason-array-canary"])},
            {
                "mutate": lambda raw: raw.update(
                    http_failure={
                        "method": "POST",
                        "route": {},
                        "actual_status": 409,
                        "expected_status": 200,
                    }
                )
            },
        )
        for index, scenario in enumerate(scenarios):
            with self.subTest(index=index):
                public = self.failed_harness(**scenario)
                self.assertEqual(
                    public["harness_failure"],
                    {"stage": "unobserved", "reason": "receipt_unavailable_or_invalid"},
                )

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
            "https_port": 28443,
            "sources": {"map": {"path": "/private/source", "commit": "a" * 40}},
            "images": {"api": "sha256:" + "a" * 64, "worker": "sha256:" + "b" * 64},
        }
        raw = raw_receipt(selection)
        projected = hosted.public_projection(raw, selection)
        self.assertNotIn("private", json.dumps(projected))
        self.assertEqual(projected["cases"]["missing_local_grant"], "not_run")
        measured = projected["measurements"]
        self.assertEqual(
            {
                key: measured[key]
                for key in (
                    "target_request_count",
                    "evidence_count",
                    "targets_spent",
                    "duration_allocated",
                    "max_attempts",
                    "last_sequence",
                    "active_sequence",
                    "stopped_owned_container_count",
                )
            },
            {
                "target_request_count": 10,
                "evidence_count": 10,
                "targets_spent": 2,
                "duration_allocated": 60,
                "max_attempts": 2,
                "last_sequence": 2,
                "active_sequence": None,
                "stopped_owned_container_count": 6,
            },
        )
        self.assertEqual(measured["public_ca_der_sha256"], "5" * 64)
        self.assertEqual(
            [row["runtime_sequence"] for row in measured["attempts"]], [1, 2]
        )
        for projected_attempt, actual in zip(
            measured["attempts"], raw["cases"]["healthy_sequence"]["attempts"]
        ):
            self.assertEqual(
                set(projected_attempt),
                {
                    "runtime_sequence",
                    "target_request_count",
                    "evidence_count",
                    "case_sha256",
                    "evidence_sha256",
                    "artifact_sha256",
                    "result_receipt_sha256",
                    "terminal_receipt_sha256",
                    "release_receipt_sha256",
                    "native_done_sha256",
                },
            )
            for key in projected_attempt:
                self.assertEqual(
                    projected_attempt[key],
                    5 if key == "target_request_count" else actual[key],
                )
        self.assertNotEqual(
            measured["attempts"][0]["terminal_receipt_sha256"],
            measured["attempts"][0]["result_receipt_sha256"],
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
            "https_port": 28443,
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

    def test_v2_sequence_correlations_refuse_mixed_or_incomplete_proof(self):
        selection = {
            "project": "vardrsec-nm2-12345678",
            "https_port": 28443,
            "sources": {"map": {"path": "/private/source", "commit": "a" * 40}},
            "images": {"api": "sha256:" + "a" * 64, "worker": "sha256:" + "b" * 64},
        }

        def digest(item):
            return hashlib.sha256(
                json.dumps(item, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()

        def sync(raw, attempt, *, rehash=False):
            if rehash:
                binding = attempt["binding"]
                result = digest(
                    {
                        "schema": "vardr.managed-result/1",
                        **binding,
                        "artifact_sha256": attempt["artifact_sha256"],
                        "case_sha256": attempt["case_sha256"],
                    }
                )
                attempt["result_receipt_sha256"] = result
                attempt["terminal_receipt"]["receipt_sha256"] = result
                attempt["terminal_receipt_sha256"] = digest(attempt["terminal_receipt"])
                attempt["release_receipt"]["terminal_receipt_sha256"] = attempt[
                    "terminal_receipt_sha256"
                ]
                attempt["release_receipt"]["receipt_sha256"] = digest(
                    {
                        key: value
                        for key, value in attempt["release_receipt"].items()
                        if key != "receipt_sha256"
                    }
                )
                attempt["release_receipt_sha256"] = attempt["release_receipt"][
                    "receipt_sha256"
                ]
            stored = raw["cases"]["happy_fixed"]["inventory"]["runtimes"][0][
                "attempts"
            ][1]
            for key in stored:
                if key != "runtime_id":
                    stored[key] = copy.deepcopy(attempt[key])

        for mutation in (
            "v1_success",
            "missing_case",
            "max_attempts",
            "active",
            "sequence_bool",
            "duplicate_sequence",
            "total_bool",
            "same_case",
            "same_artifact",
            "nested_result_hash",
            "release_digest",
            "release_binding",
            "release_bool",
            "release_after_bind",
            "confirmed_after_release",
            "naive_time",
            "request_marker",
            "request_count",
            "request_clock",
            "assessment",
            "runtime_snapshot",
            "history_missing",
            "not_all_stopped",
            "worker_missing",
            "scope_denial",
            "default_worker",
            "deferred_passed",
        ):
            with self.subTest(mutation=mutation):
                raw = raw_receipt(selection)
                cases = raw["cases"]
                sequence = cases["healthy_sequence"]
                first, second = sequence["attempts"]
                if mutation == "v1_success":
                    raw["schema"] = "vardr.nm2-worker-acceptance/1"
                elif mutation == "missing_case":
                    del cases["healthy_sequence"]
                elif mutation == "max_attempts":
                    sequence["max_attempts"] = 3
                elif mutation == "active":
                    sequence["active_sequence"] = 2
                elif mutation == "sequence_bool":
                    first["runtime_sequence"] = True
                elif mutation == "duplicate_sequence":
                    second["runtime_sequence"] = 1
                elif mutation == "total_bool":
                    sequence["target_request_count"] = True
                elif mutation == "same_case":
                    second["case_sha256"] = first["case_sha256"]
                    second["assessment"]["case_hash"] = first["case_sha256"]
                    sync(raw, second, rehash=True)
                elif mutation == "same_artifact":
                    second["artifact_sha256"] = first["artifact_sha256"]
                    sync(raw, second, rehash=True)
                elif mutation == "nested_result_hash":
                    second["terminal_receipt_sha256"] = second["result_receipt_sha256"]
                    sync(raw, second)
                elif mutation == "release_digest":
                    second["release_receipt"]["receipt_sha256"] = second[
                        "release_receipt_sha256"
                    ] = "0" * 64
                    sync(raw, second)
                elif mutation == "release_binding":
                    second["release_receipt"]["binding"] = copy.deepcopy(
                        first["binding"]
                    )
                    sync(raw, second)
                elif mutation == "release_bool":
                    second["release_receipt"]["runtime_sequence"] = True
                    sync(raw, second)
                elif mutation == "release_after_bind":
                    second["bound_at"] = first["confirmed_at"]
                    sync(raw, second)
                elif mutation == "confirmed_after_release":
                    second["confirmed_at"] = "2026-11-06T02:00:00.000007Z"
                    sync(raw, second)
                elif mutation == "naive_time":
                    second["bound_at"] = second["bound_at"].removesuffix("Z")
                    sync(raw, second)
                elif mutation == "request_marker":
                    for row in second["requests"]:
                        row["path"] = row["path"].replace("job-2", "job-1")
                elif mutation == "request_count":
                    second["requests"].pop()
                elif mutation == "request_clock":
                    second["requests"][0]["received_monotonic_ns"] = 1
                elif mutation == "assessment":
                    second["assessment"]["case_snapshot_verified"] = False
                elif mutation == "runtime_snapshot":
                    cases["happy_fixed"]["inventory"]["runtimes"][0][
                        "runtime_sha256"
                    ] = "0" * 64
                elif mutation == "history_missing":
                    cases["happy_fixed"]["inventory"]["runtimes"][0]["attempts"].pop()
                elif mutation == "not_all_stopped":
                    raw["fixture_stop"]["container_ids"].pop()
                elif mutation == "worker_missing":
                    raw["fixture_stop"]["container_ids"][0] = "f" * 64
                elif mutation == "scope_denial":
                    cases["strict_out_of_scope"]["approval_http_status"] = 403
                elif mutation == "default_worker":
                    cases["default_disabled"]["services"].append("managed-worker")
                else:
                    cases["missing_local_grant"]["status"] = "passed"
                with self.assertRaises(hosted.HostedRefused):
                    hosted.public_projection(raw, selection)

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
            self.assertEqual(public["schema"], "vardr.nm2-hosted/2")
            self.assertEqual(
                public["remaining_required_cases"],
                dict.fromkeys(hosted.REMAINING_REQUIRED_CASES, "not_run"),
            )
            self.assertEqual(public["cases"]["missing_local_grant"], "not_run")
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
                    raw["cases"]["healthy_sequence"]["attempts"][1][
                        "release_receipt_sha256"
                    ] = "private-do-not-publish"
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
