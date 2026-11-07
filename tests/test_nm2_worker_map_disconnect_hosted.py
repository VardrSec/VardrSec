"""Inert exact-service Map outage fixture and public receipt checks."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, current_thread
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import nm2_worker_hosted as hosted
import nm2_worker_launch_acceptance as local
from nm2_worker_acceptance import canonical, digest
import test_nm2_worker_stopped_predecessor_hosted as retained


API_BEFORE = "2026-11-07T00:55:00.001001001Z"
API_CUT = "2026-11-07T01:00:03.001001001Z"
WORKER_EXIT = "2026-11-07T01:00:06.001001001Z"
API_AFTER = "2026-11-07T01:00:07.001001001Z"
API_CID = "2" * 64
SCENARIO = local.MAP_DISCONNECT_SCENARIO
CASE = ("engagement", "job", {})


def evidence(*, desktop=False):
    raw, selection, (before, after) = (
        retained.desktop_evidence() if desktop else retained.evidence()
    )
    launch, unused = raw.pop("launch_pair")
    original = raw.pop("stopped_predecessor")
    selection["sources"] = {
        name: {**row, "commit": local.MAP_DISCONNECT_SOURCES.get(name, row["commit"])}
        for name, row in selection["sources"].items()
    }
    del after["containers"][unused["container_id"]]
    del after["volumes"][f"{selection['project']}_worker-ready-{unused['runtime_id']}"]
    after["containers"][API_CID]["state"].update(
        started_at=API_AFTER, finished_at="2026-11-07T01:00:09.001001001Z"
    )
    raw.update(
        sources=selection["sources"],
        scenario=SCENARIO,
        acceptance_scope=local.MAP_DISCONNECT_SCOPE,
        status=local.MAP_DISCONNECT_PASS,
        stage="selected_map_disconnect_complete",
        launch=launch,
        after_sha256=digest(canonical(after)),
    )
    raw["fixture_stop"]["container_ids"].remove(unused["container_id"])
    raw["map_disconnect"] = {
        **{
            key: original[key]
            for key in (
                "audit_sha256",
                "retirement_sha256",
                "host_retirement_sha256",
                "terminal_sha256",
                "terminal_cause",
                "target_requests",
                "capacity_before",
                "capacity_after",
                "targets_spent",
                "duration_allocated",
                "remaining_local_holds",
            )
        },
        "api_container_id": API_CID,
        "api_started_at": API_BEFORE,
        "api_finished_at": API_CUT,
        "api_restarted_at": API_AFTER,
        "api_cut_to_worker_exit_ns": 3_000_000_000,
        "physical_exit_elapsed_ns": 4_000_000_000,
    }
    return raw, selection, (before, after)


class MapDisconnectHostedTests(unittest.TestCase):
    def test_opt_in_route_requires_exact_candidate_and_new_schema(self):
        env = {
            "NM2_SCENARIO": SCENARIO,
            "NM2_DATABASE_REVISION": "0041persistentruntime",
            **{
                "NM2_" + name.upper() + "_SHA": value
                for name, value in local.MAP_DISCONNECT_SOURCES.items()
            },
        }
        self.assertEqual(
            hosted.execution_options(env), (SCENARIO, "0041persistentruntime")
        )
        self.assertEqual(
            hosted.execution_options({}), ("healthy", "0040runtimesequence")
        )
        for name in (
            "NM2_MAP_SHA",
            "NM2_RUNNER_SHA",
            "NM2_GATE_SHA",
            "NM2_DATABASE_REVISION",
        ):
            with self.subTest(name=name), self.assertRaises(hosted.HostedRefused):
                hosted.execution_options({**env, name: "0" * 40})
        self.assertEqual(hosted.MAP_DISCONNECT_HOSTED, "vardr.nm2-hosted/14")
        fixture = hosted.Hosted.__new__(hosted.Hosted)
        fixture.scenario, fixture.receipt, fixture.command = SCENARIO, {}, Mock()
        asset = b"synthetic pinned Compose bytes"
        with TemporaryDirectory() as folder:
            fixture.root = Path(folder)
            (fixture.root / "home").mkdir()
            (fixture.root / "docker-compose-5.6.1").write_bytes(asset)
            with patch.multiple(
                hosted,
                COMPOSE_BYTES=len(asset),
                COMPOSE_SHA256=hashlib.sha256(asset).hexdigest(),
            ):
                argv = fixture.launch_harness(fixture.root / "cohort.json")
        fixture.command.assert_called_once()
        self.assertEqual(argv[-2:], ["--map-disconnect", "--execute"])

    def test_public_reader_joins_api_restart_and_worker_exit_without_private_data(self):
        for desktop in (False, True):
            with self.subTest(desktop=desktop):
                raw, selection, inventories = evidence(desktop=desktop)
                project = (
                    hosted.map_disconnect_desktop_projection
                    if desktop
                    else hosted.public_projection
                )
                result = project(raw, selection, inventories=inventories)
                self.assertEqual(result["platform"], "win32" if desktop else "linux")
                self.assertEqual(
                    result["empty_builtin_bridge_id_change_count"], int(desktop)
                )
                self.assertEqual(
                    result["map_disconnect"]["lease_evidence"],
                    "configured_ceiling_only",
                )
                self.assertEqual(
                    result["map_disconnect"]["owned_stopped_container_count"], 6
                )
                for private in (
                    API_CID,
                    API_AFTER,
                    retained.CID_ONE,
                    retained.RUN_ONE,
                    retained.PRIVATE_CANARY,
                ):
                    self.assertNotIn(private.encode(), canonical(result))

    def test_optional_raw_audit_interval_is_strict_and_never_public(self):
        interval = {
            "started_monotonic_ns": 1,
            "finished_monotonic_ns": 5,
            "api_stop_call_monotonic_ns": 3,
            "exit_observed_monotonic_ns": 4,
        }
        for desktop in (False, True):
            raw, selection, inventories = evidence(desktop=desktop)
            project = (
                hosted.map_disconnect_desktop_projection
                if desktop
                else hosted.public_projection
            )
            legacy = project(raw, selection, inventories=inventories)
            self.assertEqual(
                project(
                    {**raw, "map_disconnect_audit": interval},
                    selection,
                    inventories=inventories,
                ),
                legacy,
            )
            self.assertNotIn(b"map_disconnect_audit", canonical(legacy))
            for bad in (
                None,
                {},
                {**interval, "raw": retained.PRIVATE_CANARY},
                {**interval, "started_monotonic_ns": True},
                {**interval, "finished_monotonic_ns": 0},
                {**interval, "started_monotonic_ns": 4},
                {**interval, "exit_observed_monotonic_ns": 2},
                {**interval, "api_stop_call_monotonic_ns": -1},
            ):
                with (
                    self.subTest(desktop=desktop, bad=bad),
                    self.assertRaises(hosted.HostedRefused),
                ):
                    project(
                        {**raw, "map_disconnect_audit": bad},
                        selection,
                        inventories=inventories,
                    )

    def test_false_disconnect_or_restart_evidence_is_rejected(self):
        raw, selection, inventories = evidence()
        proof = raw["map_disconnect"]
        for key, value in (
            ("api_container_id", retained.CID_ONE),
            ("api_finished_at", WORKER_EXIT),
            ("api_restarted_at", "2026-11-07T01:00:08.001001001Z"),
            ("api_cut_to_worker_exit_ns", 3_000_000_001),
            ("physical_exit_elapsed_ns", 15_000_000_000),
            ("capacity_before", True),
            ("capacity_after", 1),
            ("target_requests", 4),
            ("duration_allocated", 0),
            ("terminal_cause", "remote_stop_requested"),
            ("credential", retained.PRIVATE_CANARY),
        ):
            with self.subTest(key=key), self.assertRaises(hosted.HostedRefused):
                hosted.public_projection(
                    {**raw, "map_disconnect": {**proof, key: value}},
                    selection,
                    inventories=inventories,
                )
        with self.assertRaises(hosted.HostedRefused):
            hosted.public_projection(raw, selection)
        with self.assertRaises(hosted.HostedRefused):
            hosted.map_disconnect_desktop_projection(
                raw, selection, inventories=inventories
            )

    def test_failure_projects_only_fixed_stage_and_reason(self):
        raw, selection, _ = evidence()
        raw.update(
            status="held",
            stage="launch_map_disconnect_observe_worker",
            reason="launch_map_disconnect_exit_or_traffic",
            map_disconnect={"raw": retained.PRIVATE_CANARY},
        )
        for reason in (
            "launch_map_disconnect_exit_or_traffic",
            "launch_map_disconnect_worker_exit_code",
            "launch_map_disconnect_target_count_changed",
            "launch_map_disconnect_target_rows_changed",
            "launch_map_disconnect_api_exit_changed",
        ):
            with self.subTest(reason=reason):
                self.assertEqual(
                    hosted.failure_projection({**raw, "reason": reason}, selection),
                    {"stage": "launch_map_disconnect_observe_worker", "reason": reason},
                )

        self.assertEqual(
            hosted.failure_projection(
                {
                    **raw,
                    "stage": "launch_map_disconnect_journal_after_exit",
                    "reason": "cancellation_original_run_not_active",
                },
                selection,
            ),
            {
                "stage": "launch_map_disconnect_journal_after_exit",
                "reason": "cancellation_original_run_not_active",
            },
        )


class MapDisconnectLocalTests(unittest.TestCase):
    def fixture(self, *, worker_exit=WORKER_EXIT):
        fixture = object.__new__(local.LaunchFixture)
        fixture.receipt, fixture.docker_config, fixture.project = (
            {},
            Path("."),
            retained.PROJECT,
        )
        api = {"service": "api", "container_id": API_CID, "started_at": API_BEFORE}
        proxy = {"service": "proxy", "container_id": "3" * 64, "started_at": API_BEFORE}
        fixture.disconnect_core = [api, proxy]
        original = {
            "capacity_reserved_count": 1,
            "targets_spent": 1,
            "duration_allocated": 30,
        }
        fixture.unreported_attempt = Mock(return_value=original)
        healthy = {
            "Status": "running",
            "Running": True,
            "StartedAt": API_BEFORE,
            "Health": {"Status": "healthy"},
        }
        stopped = {
            "Status": "exited",
            "Running": False,
            "StartedAt": API_BEFORE,
            "FinishedAt": API_CUT,
            "ExitCode": 143,
        }
        fixture.disconnect_core_state = Mock(
            side_effect=[
                healthy,
                stopped,
                stopped,
                {**healthy, "StartedAt": API_AFTER},
                healthy,
            ]
        )
        received = local.engine_timestamp_ns("2026-11-07T01:00:02.001001001Z")
        requests = [{}, {}, {"received_utc_ns": received, "received_monotonic_ns": 1}]
        fixture.timed_traffic = Mock(
            return_value={
                "requests": requests,
                "observed_utc_ns": received + 5_000_000_000,
                "observed_monotonic_ns": 5_000_000_001,
            }
        )
        fixture.traffic = Mock(side_effect=[[], requests])
        fixture.persistent_idle = Mock()
        fixture.pending_approval = {
            "approval": {"synthetic": "signed"},
            "plan": {},
            "enrollment_id": "fixture",
            "authorization_id": "fixture",
        }
        fixture.api = SimpleNamespace(request=Mock())
        fixture.final_sample = {"requests": requests, "observed_monotonic_ns": 2}
        fixture.observe_target_prefix = Mock(
            side_effect=lambda _, minimum=3: (
                {"requests": requests[:1]} if minimum == 1 else fixture.final_sample,
                time.monotonic_ns(),
            )
        )
        fixture.observe_executing_run_id = Mock(return_value="f" * 32)
        identity = SimpleNamespace(
            container_id=retained.CID_ONE,
            daemon_id="owned",
            image_id="sha256:" + "1" * 64,
            project=retained.PROJECT,
        )
        proof = SimpleNamespace(
            exit_code=125, finished_at=worker_exit, identity=identity
        )
        observer = Mock()
        observer.daemon.return_value = identity.daemon_id
        observer.capture_running.return_value = identity
        observer.capture_project_containers.return_value = {
            "daemon_id": identity.daemon_id,
            "all_worker_ids": [identity.container_id],
            "core": [{**api, "started_at": API_AFTER}, proxy],
        }
        history = Mock()
        history.attach_mock(observer, "observer")
        for name, child in (
            ("idle", fixture.persistent_idle),
            ("core", fixture.disconnect_core_state),
            ("traffic", fixture.traffic),
            ("register", fixture.api.request),
            ("target", fixture.observe_target_prefix),
            ("map_read", fixture.unreported_attempt),
            ("audit", fixture.observe_executing_run_id),
        ):
            history.attach_mock(child, name)

        def executor_factory(*args, **kwargs):
            self.assertEqual(args, ())
            self.assertEqual(kwargs, {"max_workers": 1})
            pool = ThreadPoolExecutor(*args, **kwargs)
            submit = pool.submit

            def coordinated_submit(*args, **kwargs):
                future = submit(*args, **kwargs)
                # Instant main-thread mocks must not race the fast default audit.
                # Deliberate delay/refusal cases supply their own event ordering.
                if fixture.observe_executing_run_id.side_effect is None:
                    future.result(timeout=2)
                return future

            pool.submit = history.audit_submit = Mock(side_effect=coordinated_submit)
            return pool

        executor_patch = patch.object(
            local, "ThreadPoolExecutor", side_effect=executor_factory
        )
        executor_patch.start()
        self.addCleanup(executor_patch.stop)
        fixture.docker = history.docker
        observer.observe_exit.return_value = proof
        return fixture, observer, identity, requests, history

    def test_timing_requires_configured_lease_and_delayed_request_bounds(self):
        received = local.engine_timestamp_ns("2026-11-07T01:00:00Z")
        request = {"received_utc_ns": received, "received_monotonic_ns": 1}
        after = {
            "observed_utc_ns": received + 14_000_000_000,
            "observed_monotonic_ns": 14_000_000_001,
        }
        cut = "2026-11-07T01:00:02Z"
        self.assertEqual(
            local.map_disconnect_timing(request, after, cut, "2026-11-07T01:00:12Z"),
            (12_000_000_000, 10_000_000_000),
        )
        with self.assertRaisesRegex(
            local.AcceptanceRefused, "launch_map_disconnect_timing_refused"
        ):
            local.map_disconnect_timing(
                request, after, cut, "2026-11-07T01:00:12.000000001Z"
            )

    def test_restarts_only_exact_api_after_independent_worker_exit(self):
        fixture, observer, identity, _, history = self.fixture()
        run_id, _, _ = fixture.observe_map_disconnect(observer, identity, {}, CASE)
        self.assertEqual(run_id, "f" * 32)
        before_cut = [entry[0] for entry in history.mock_calls if entry[0] != "audit"]
        self.assertEqual(
            before_cut[: before_cut.index("docker")],
            [
                "idle",
                "observer.capture_running",
                "traffic",
                "core",
                "observer.daemon",
                "register",
                "target",
                "audit_submit",
                "map_read",
                "target",
            ],
        )
        fixture.api.request.assert_called_once_with(
            "/jobs/job/managed/approval/register", fixture.pending_approval
        )
        self.assertEqual(
            fixture.observe_target_prefix.call_args_list[0].kwargs, {"minimum": 1}
        )
        self.assertEqual(fixture.observe_target_prefix.call_args_list[1].kwargs, {})
        calls = [
            (name, args[3] if name == "docker" else None)
            for name, args, _ in history.mock_calls
            if name in {"docker", "observer.observe_exit", "observer.confirm_exit"}
        ]
        self.assertEqual(
            calls,
            [
                ("docker", "stop"),
                ("observer.observe_exit", None),
                ("observer.confirm_exit", None),
                ("docker", "start"),
                ("observer.confirm_exit", None),
            ],
        )
        self.assertEqual(
            [item.args[-1] for item in fixture.docker.call_args_list],
            [API_CID, API_CID],
        )
        self.assertEqual(
            fixture.receipt["map_disconnect"]["api_cut_to_worker_exit_ns"],
            3_000_000_000,
        )

    def test_refused_post_exit_audit_holds_before_api_restart_or_report(self):
        fixture, observer, identity, _, history = self.fixture()
        fixture.observe_executing_run_id.side_effect = local.AcceptanceRefused(
            "cancellation_original_run_not_active"
        )
        fixture.report_exit = Mock()
        with self.assertRaisesRegex(
            local.AcceptanceRefused, "^cancellation_original_run_not_active$"
        ):
            fixture.observe_map_disconnect(observer, identity, {}, CASE)
        self.assertEqual(
            fixture.receipt["stage"], "launch_map_disconnect_journal_after_exit"
        )
        fixture.docker.assert_called_once()
        self.assertEqual(fixture.docker.call_args.args[3], "stop")
        observer.observe_exit.assert_called_once_with(identity)
        fixture.observe_executing_run_id.assert_called_once_with("engagement", "job")
        observer.confirm_exit.assert_not_called()
        fixture.report_exit.assert_not_called()
        history.audit_submit.assert_called_once()
        self.assertNotIn("map_disconnect", fixture.receipt)

    def test_audit_can_finish_after_exit_without_delaying_cut(self):
        fixture, observer, identity, _, history = self.fixture()
        started, release, finished = Event(), Event(), Event()
        threads = []

        def audit(*args):
            threads.append(current_thread())
            started.set()
            self.assertTrue(release.wait(2))
            finished.set()
            return "f" * 32

        prefix = fixture.observe_target_prefix.side_effect

        def target(*args, **kwargs):
            if kwargs.get("minimum", 3) == 3:
                self.assertTrue(started.wait(2))
                self.assertFalse(finished.is_set())
            return prefix(*args, **kwargs)

        proof = observer.observe_exit.return_value

        def exited(_):
            self.assertFalse(finished.is_set())
            release.set()
            return proof

        fixture.observe_executing_run_id.side_effect = audit
        fixture.observe_target_prefix.side_effect = target
        observer.observe_exit.side_effect = exited
        fixture.observe_map_disconnect(observer, identity, {}, CASE)
        self.assertTrue(finished.is_set())
        self.assertEqual(len(threads), 1)
        self.assertIsNot(threads[0], current_thread())
        self.assertFalse(threads[0].is_alive())
        history.audit_submit.assert_called_once()
        interval = fixture.receipt["map_disconnect_audit"]
        self.assertEqual(
            set(interval),
            {
                "started_monotonic_ns",
                "finished_monotonic_ns",
                "api_stop_call_monotonic_ns",
                "exit_observed_monotonic_ns",
            },
        )
        self.assertLessEqual(
            interval["started_monotonic_ns"], interval["api_stop_call_monotonic_ns"]
        )
        self.assertLessEqual(
            interval["api_stop_call_monotonic_ns"],
            interval["exit_observed_monotonic_ns"],
        )
        self.assertLessEqual(
            interval["started_monotonic_ns"], interval["finished_monotonic_ns"]
        )

    def test_pending_audit_is_joined_when_fresh_sample_refuses(self):
        fixture, observer, identity, _, _ = self.fixture()
        started, release, finished = Event(), Event(), Event()
        threads = []

        def audit(*args):
            threads.append(current_thread())
            started.set()
            self.assertTrue(release.wait(2))
            finished.set()
            return "f" * 32

        prefix = fixture.observe_target_prefix.side_effect

        def target(*args, **kwargs):
            if kwargs.get("minimum", 3) == 3:
                self.assertTrue(started.wait(2))
                release.set()
            return prefix(*args, **kwargs)

        fixture.observe_executing_run_id.side_effect = audit
        fixture.observe_target_prefix.side_effect = target
        fixture.final_sample["observed_monotonic_ns"] = (
            local.MAP_DISCONNECT_CUT_WINDOW_NS + 1
        )
        with self.assertRaisesRegex(
            local.AcceptanceRefused, "^launch_map_disconnect_sample_stale$"
        ):
            fixture.observe_map_disconnect(observer, identity, {}, CASE)
        self.assertTrue(finished.is_set())
        self.assertEqual(len(threads), 1)
        self.assertFalse(threads[0].is_alive())
        fixture.docker.assert_not_called()
        observer.observe_exit.assert_not_called()

    def test_audit_start_after_cut_refuses_before_restart(self):
        fixture, observer, identity, _, _ = self.fixture()
        main_thread = current_thread()

        def clock():
            return 50 if current_thread() is main_thread else 100

        with (
            patch.object(local.time, "monotonic_ns", side_effect=clock),
            self.assertRaisesRegex(
                local.AcceptanceRefused, "^launch_map_disconnect_timing_refused$"
            ),
        ):
            fixture.observe_map_disconnect(observer, identity, {}, CASE)
        fixture.docker.assert_called_once()
        self.assertEqual(fixture.docker.call_args.args[3], "stop")
        observer.confirm_exit.assert_not_called()
        self.assertNotIn("map_disconnect", fixture.receipt)

    def test_freshness_accounts_for_target_age_and_entire_host_sample(self):
        observed = {
            "observed_monotonic_ns": 100,
            "requests": [{"received_monotonic_ns": 1}],
        }
        boundary = local.MAP_DISCONNECT_CUT_WINDOW_NS - 99
        local.require_fresh_map_disconnect_sample(observed, 1000, 1000 + boundary - 1)
        with self.assertRaisesRegex(
            local.AcceptanceRefused, "launch_map_disconnect_sample_stale"
        ):
            local.require_fresh_map_disconnect_sample(observed, 1000, 1000 + boundary)
        with self.assertRaisesRegex(
            local.AcceptanceRefused, "launch_map_disconnect_sample_stale"
        ):
            local.require_fresh_map_disconnect_sample(observed, 1000, 999)

    def test_stale_third_request_holds_before_api_stop(self):
        fixture, observer, identity, _, _ = self.fixture()
        fixture.final_sample["observed_monotonic_ns"] = (
            local.MAP_DISCONNECT_CUT_WINDOW_NS + 1
        )
        with self.assertRaisesRegex(
            local.AcceptanceRefused, "launch_map_disconnect_sample_stale"
        ):
            fixture.observe_map_disconnect(observer, identity, {}, CASE)
        fixture.docker.assert_not_called()
        fixture.api.request.assert_called_once()
        fixture.unreported_attempt.assert_called_once()
        fixture.observe_executing_run_id.assert_called_once_with("engagement", "job")
        observer.observe_exit.assert_not_called()

    def test_wrong_daemon_refuses_before_registration_or_stop(self):
        fixture, observer, identity, _, _ = self.fixture()
        observer.daemon.return_value = "foreign"
        with self.assertRaisesRegex(
            local.AcceptanceRefused, "launch_map_disconnect_api_identity"
        ):
            fixture.observe_map_disconnect(observer, identity, {}, CASE)
        fixture.api.request.assert_not_called()
        fixture.docker.assert_not_called()

    def test_shared_observer_preserves_existing_three_rows_before_audit(self):
        fixture = object.__new__(local.LaunchFixture)
        fixture.issuer_origin = "https://fixture"
        case = {
            "spec": {"request": {"url": "http://fixture/fixed/records/42?nm2_case=one"}}
        }
        requests = [
            {"identity": who, "path": path + "?nm2_case=one"}
            for who, path in (
                ("owner", "/session"),
                ("peer", "/session"),
                ("owner", "/fixed/records/42"),
            )
        ]
        history = Mock()
        fixture.timed_traffic, fixture.helper = history.target, history.audit
        fixture.timed_traffic.return_value = {"requests": requests}
        fixture.helper.return_value = json.dumps(
            [
                {
                    "job_id": "job",
                    "run_id": "f" * 32,
                    "phase": "executing",
                    "backend_url": fixture.issuer_origin,
                    "command_profile": {"controlled": True},
                }
            ]
        ).encode()
        run_id, observed = fixture.observe_active_run("engagement", "job", case)
        self.assertEqual((run_id, observed), ("f" * 32, {"requests": requests}))
        self.assertEqual(
            [entry[0] for entry in history.mock_calls], ["target", "audit"]
        )
        fixture.timed_traffic.return_value = {
            "requests": [{**requests[0], "identity": "foreign"}]
        }
        with self.assertRaisesRegex(
            local.AcceptanceRefused, "cancellation_request_binding_mismatch"
        ):
            fixture.observe_target_prefix(case, minimum=1)

    def test_no_api_restart_after_ambiguous_exit_timing(self):
        fixture, observer, identity, _, _ = self.fixture(worker_exit=API_CUT)
        with self.assertRaisesRegex(
            local.AcceptanceRefused, "launch_map_disconnect_timing_refused"
        ):
            fixture.observe_map_disconnect(observer, identity, {}, CASE)
        fixture.docker.assert_called_once()
        self.assertEqual(fixture.docker.call_args.args[3], "stop")
        fixture.observe_executing_run_id.assert_called_once_with("engagement", "job")
        self.assertNotIn("map_disconnect", fixture.receipt)

    def test_observation_refusals_are_distinct_and_never_restart_api(self):
        for change in (
            "worker_exit_code",
            "target_count_changed",
            "target_rows_changed",
            "api_exit_changed",
        ):
            with self.subTest(change=change):
                fixture, observer, identity, requests, _ = self.fixture()
                if change == "worker_exit_code":
                    observer.observe_exit.return_value.exit_code = 1
                elif change == "target_count_changed":
                    fixture.timed_traffic.return_value["requests"] = [*requests, {}]
                elif change == "target_rows_changed":
                    fixture.timed_traffic.return_value["requests"] = [
                        *requests[:-1],
                        {"opaque": retained.PRIVATE_CANARY},
                    ]
                else:
                    healthy, stopped, *_ = list(
                        fixture.disconnect_core_state.side_effect
                    )
                    fixture.disconnect_core_state.side_effect = [
                        healthy,
                        stopped,
                        {**stopped, "FinishedAt": WORKER_EXIT},
                    ]
                with self.assertRaisesRegex(
                    local.AcceptanceRefused, "^launch_map_disconnect_" + change + "$"
                ):
                    fixture.observe_map_disconnect(observer, identity, {}, CASE)
                fixture.docker.assert_called_once()
                self.assertEqual(fixture.docker.call_args.args[3], "stop")
                fixture.observe_executing_run_id.assert_called_once_with(
                    "engagement", "job"
                )
                self.assertNotIn("map_disconnect", fixture.receipt)

    def test_core_identity_refuses_foreign_service_before_mutation(self):
        fixture, _, _, _, _ = self.fixture()
        core = {
            "container_id": API_CID,
            "image_id": "sha256:" + "e" * 64,
            "service": "api",
        }
        row = {
            "id": API_CID,
            "image": core["image_id"],
            "restarts": 0,
            "labels": {
                "com.docker.compose.project": "foreign-project",
                "com.docker.compose.service": "api",
                "com.docker.compose.oneoff": "False",
            },
            "state": dict.fromkeys(
                ("Paused", "Restarting", "Dead", "OOMKilled"), False
            ),
        }
        fixture.docker.return_value = json.dumps(row).encode()
        with self.assertRaisesRegex(
            local.AcceptanceRefused, "launch_map_disconnect_api_identity"
        ):
            local.LaunchFixture.disconnect_core_state(fixture, core)
        fixture.docker.assert_called_once()
        self.assertEqual(fixture.docker.call_args.args[3], "inspect")
