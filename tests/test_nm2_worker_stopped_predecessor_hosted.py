"""Inert hosted stopped-predecessor routing and receipt checks."""

from copy import deepcopy
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

import nm2_worker_hosted as hosted
from nm2_worker_acceptance import canonical, digest


SCENARIO = hosted.LAUNCH_STOPPED_PREDECESSOR_SCENARIO
PROJECT = "vardrsec-nm2-synthetic"
RUN_ONE = "e4a346a6-3982-4a13-a0a5-5b025bedbde0"
RUN_TWO = "980d0f49-75c3-4f02-84cc-3fba35ff2e3d"
CID_ONE, CID_TWO = "6" * 64, "7" * 64
STATE_VOLUME = PROJECT + "_runner-state"
PRIVATE_CANARY = "/private/synthetic/opaque-canary"


def evidence():
    images = {
        name: "sha256:" + str(index) * 64
        for index, name in enumerate(("db", "api", "proxy", "web", "worker"), 1)
    }
    selection = {
        "project": PROJECT,
        "images": images,
        "sources": {
            name: {"commit": str(index) * 40, "path": PRIVATE_CANARY + "/" + name}
            for index, name in enumerate(("distribution", "map", "runner", "gate"), 1)
        },
        "docker_context": "default",
        "allow_empty_builtin_bridge_id_change": False,
    }
    pair = [
        {
            "ordinal": index,
            "runtime_id": runtime,
            "container_id": cid,
            "started_at": f"2026-11-07T0{index}:00:00.001001001Z",
            "finished_at": f"2026-11-07T0{index}:00:06.001001001Z",
            "intent_sha256": "a" * 64,
            "retirement_sha256": str(index) * 64,
            "predecessor_cids": [] if index == 1 else [CID_ONE],
            "bootstrap_audit_sha256": "b" * 64 if index == 1 else None,
            "runner_state_sha256": "c" * 64,
        }
        for index, runtime, cid in ((1, RUN_ONE, CID_ONE), (2, RUN_TWO, CID_TWO))
    ]
    proof = {
        "refused_runtime_id": RUN_TWO,
        "failure_phase": "launch_catalog",
        "failure_code": "validation_refused",
        "new_resources": 0,
        "target_requests": 3,
        "physical_exit_elapsed_ns": 5_000_000_000,
        "audit_sha256": "d" * 64,
        "retirement_sha256": pair[0]["retirement_sha256"],
        "host_retirement_sha256": "e" * 64,
        "terminal_sha256": "f" * 64,
        "terminal_cause": "observed_exit",
        "capacity_before": 1,
        "capacity_after": 0,
        "targets_spent": 1,
        "duration_allocated": 30,
        "remaining_local_holds": 0,
    }
    before = {
        "containers": {},
        "images": {value: {"id": value} for value in images.values()},
        "networks": {
            "old-net": {"id": "old-net", "name": "existing", "containers": {}}
        },
        "volumes": {"old-volume": {"id": "old-volume", "labels": {"retained": "true"}}},
    }
    after = deepcopy(before)
    services = (
        "db",
        "api",
        "proxy",
        "web",
        "gate-fixture",
        "managed-worker",
        "managed-worker",
    )
    for index, service in enumerate(services, 1):
        cid = str(index) * 64
        row = {
            "id": cid,
            "image": images.get(service, images["worker"]),
            "labels": {
                "com.docker.compose.project": PROJECT,
                "com.docker.compose.service": service,
            },
            "state": dict.fromkeys(("running", "paused", "restarting", "dead"), False),
            "restarts": 0,
            "mounts": [],
        }
        if index >= 6:
            launch = pair[index - 6]
            row["labels"]["com.docker.compose.container-number"] = str(
                launch["ordinal"]
            )
            row["state"].update(
                started_at=launch["started_at"],
                finished_at=launch["finished_at"],
                exit_code=125,
            )
            row["mounts"] = [
                {
                    "Type": "volume",
                    "Destination": "/home/runner/.vardrmap",
                    "Name": STATE_VOLUME,
                    "Source": PRIVATE_CANARY,
                    "RW": True,
                }
            ]
        after["containers"][cid] = row
    for name in (
        STATE_VOLUME,
        *(f"{PROJECT}_worker-ready-{run}" for run in (RUN_ONE, RUN_TWO)),
    ):
        after["volumes"][name] = {
            "id": name,
            "labels": {"com.docker.compose.project": PROJECT},
        }
    raw = {
        **selection,
        "schema": hosted.LAUNCH_SCHEMA,
        "scenario": SCENARIO,
        "status": "selected_launch_slice_passed",
        "stage": "selected_launch_complete",
        "acceptance_scope": "stopped_predecessor_then_next_launch",
        "expected_database_revision": "0041persistentruntime",
        "retained": True,
        "platform": "linux",
        "nm2_exit_status": "incomplete",
        "launch_pair": pair,
        "stopped_predecessor": proof,
        "private_log": PRIVATE_CANARY,
        "before_sha256": digest(canonical(before)),
        "after_sha256": digest(canonical(after)),
        "admitted_inventory_diffs": [],
        "fixture_stop": {
            "status": "stopped_retained",
            "container_ids": sorted(after["containers"]),
            "stop_requested_ids": sorted(set(after["containers"]) - {CID_ONE, CID_TWO}),
        },
    }
    return raw, selection, (before, after)


BRIDGE_BEFORE, BRIDGE_AFTER = "b" * 64, "c" * 64


def desktop_evidence():
    raw, selection, (before, after) = evidence()
    selection.update(
        docker_context="desktop-linux", allow_empty_builtin_bridge_id_change=True
    )
    raw.update(platform="win32")
    bridge = {
        "id": BRIDGE_BEFORE,
        "name": "bridge",
        "driver": "bridge",
        "scope": "local",
        "labels": {},
        "containers": {},
        "options": {
            "com.docker.network.bridge.default_bridge": "true",
            "com.docker.network.bridge.name": "docker0",
        },
        "ipam": {"Config": [{"Subnet": "172.17.0.0/16", "Gateway": "172.17.0.1"}]},
    }
    before["networks"][BRIDGE_BEFORE] = bridge
    after["networks"][BRIDGE_AFTER] = {**deepcopy(bridge), "id": BRIDGE_AFTER}
    raw["admitted_inventory_diffs"] = [
        {
            "kind": "empty_builtin_bridge_id",
            "before": BRIDGE_BEFORE,
            "after": BRIDGE_AFTER,
        }
    ]
    raw.update(
        before_sha256=digest(canonical(before)), after_sha256=digest(canonical(after))
    )
    return raw, selection, (before, after)


class DesktopStoppedPredecessorTests(unittest.TestCase):
    def test_only_desktop_admits_exact_empty_bridge_change(self):
        raw, selection, inventories = desktop_evidence()
        result = hosted.stopped_predecessor_desktop_projection(
            raw, selection, inventories=inventories
        )
        self.assertEqual(result["platform"], "win32")
        self.assertEqual(result["container_platform"], "linux")
        self.assertEqual(result["empty_builtin_bridge_id_change_count"], 1)
        self.assertEqual(
            result["stopped_predecessor"]["owned_stopped_container_count"], 7
        )
        for private in (
            BRIDGE_BEFORE,
            BRIDGE_AFTER,
            CID_ONE,
            CID_TWO,
            RUN_ONE,
            RUN_TWO,
        ):
            self.assertNotIn(private.encode(), canonical(result))
        for allow in (True, False):
            with self.subTest(allow=allow), self.assertRaises(hosted.HostedRefused):
                hosted.public_projection(
                    {**raw, "platform": "linux"},
                    {
                        **selection,
                        "docker_context": "default",
                        "allow_empty_builtin_bridge_id_change": allow,
                    },
                    inventories=inventories,
                )

    def test_desktop_requires_platform_context_and_exact_admission(self):
        raw, selection, inventories = desktop_evidence()
        for altered, options in (
            ({**raw, "platform": "linux"}, selection),
            (raw, {**selection, "docker_context": "default"}),
            (raw, {**selection, "allow_empty_builtin_bridge_id_change": False}),
            (raw, {**selection, "allow_empty_builtin_bridge_id_change": 1}),
            ({**raw, "admitted_inventory_diffs": []}, selection),
            (
                {
                    **raw,
                    "admitted_inventory_diffs": [
                        {
                            "kind": "empty_builtin_bridge_id",
                            "before": BRIDGE_BEFORE,
                            "after": "d" * 64,
                        },
                    ],
                },
                selection,
            ),
        ):
            with self.assertRaises(hosted.HostedRefused):
                hosted.stopped_predecessor_desktop_projection(
                    altered, options, inventories=inventories
                )

    def test_desktop_refuses_foreign_attached_or_mismatched_bridge(self):
        for name in (
            "foreign",
            "foreign_driver",
            "foreign_scope",
            "attached",
            "ipam_change",
            "old_id_present",
        ):
            raw, selection, (before, after) = desktop_evidence()
            old = before["networks"][BRIDGE_BEFORE]
            replacement = after["networks"][BRIDGE_AFTER]
            if name == "foreign":
                old["name"] = replacement["name"] = "foreign-bridge"
            elif name == "foreign_driver":
                old["driver"] = replacement["driver"] = "overlay"
            elif name == "foreign_scope":
                old["scope"] = replacement["scope"] = "swarm"
            elif name == "attached":
                old["containers"] = replacement["containers"] = {
                    "foreign-container": {}
                }
            elif name == "ipam_change":
                replacement["ipam"]["Config"][0]["Gateway"] = "172.17.0.2"
            else:
                after["networks"][BRIDGE_BEFORE] = {
                    **old,
                    "name": "unexpected",
                    "labels": {"com.docker.compose.project": PROJECT},
                }
            raw.update(
                before_sha256=digest(canonical(before)),
                after_sha256=digest(canonical(after)),
            )
            with self.subTest(name=name), self.assertRaises(hosted.HostedRefused):
                hosted.stopped_predecessor_desktop_projection(
                    raw, selection, inventories=(before, after)
                )


class HostedStoppedPredecessorTests(unittest.TestCase):
    def test_explicit_route_uses_existing_pinned_harness_and_revision(self):
        env = {"NM2_SCENARIO": SCENARIO}
        with self.assertRaises(hosted.HostedRefused):
            hosted.execution_options(env)
        env["NM2_DATABASE_REVISION"] = "0041persistentruntime"
        self.assertEqual(
            hosted.execution_options(env), (SCENARIO, "0041persistentruntime")
        )
        self.assertEqual(
            hosted.execution_options({}), ("healthy", "0040runtimesequence")
        )
        workflow = (hosted.SOURCE / ".github/workflows/compose.yml").read_text(
            encoding="utf-8"
        )
        options = next(
            line.strip()
            for line in workflow.splitlines()
            if line.strip().startswith("options: [healthy,")
        )
        self.assertIn(
            SCENARIO, options.removeprefix("options: [").removesuffix("]").split(", ")
        )
        fixture = hosted.Hosted.__new__(hosted.Hosted)
        fixture.scenario, fixture.receipt, fixture.command = SCENARIO, {}, Mock()
        asset = b"synthetic pinned Compose bytes"
        with TemporaryDirectory() as temporary:
            fixture.root = Path(temporary)
            (fixture.root / "home").mkdir()
            (fixture.root / "docker-compose-5.6.1").write_bytes(asset)
            with patch.multiple(
                hosted,
                COMPOSE_BYTES=len(asset),
                COMPOSE_SHA256=hashlib.sha256(asset).hexdigest(),
            ):
                argv = fixture.launch_harness(fixture.root / "cohort.json")
        fixture.command.assert_called_once()
        self.assertEqual(Path(argv[0]).name, "nm2_worker_launch_acceptance.py")
        self.assertEqual(argv[-2:], ["--stopped-predecessor", "--execute"])

    def test_joins_exact_refused_successor_and_projects_no_private_identifiers(self):
        raw, selection, inventories = evidence()
        result = hosted.public_projection(raw, selection, inventories=inventories)
        self.assertEqual(
            set(result),
            {"stopped_predecessor", "nm2_exit_status", "resources_retained"},
        )
        self.assertEqual(result["nm2_exit_status"], "incomplete")
        proof = raw["stopped_predecessor"]
        self.assertEqual(
            result["stopped_predecessor"],
            {
                **{
                    key: value
                    for key, value in proof.items()
                    if key != "refused_runtime_id"
                },
                "same_runner_state_volume": True,
                "owned_stopped_container_count": 7,
            },
        )
        for canary in (
            RUN_ONE,
            RUN_TWO,
            CID_ONE,
            CID_TWO,
            STATE_VOLUME,
            PRIVATE_CANARY,
        ):
            self.assertNotIn(canary.encode(), canonical(result))
        for key, value in (
            ("refused_runtime_id", RUN_ONE),
            ("new_resources", False),
            ("new_resources", 1),
            ("capacity_before", True),
            ("capacity_after", 1),
            ("duration_allocated", 30.0),
            ("targets_spent", 0),
            ("retirement_sha256", "0" * 64),
            ("terminal_cause", "control_lease_expired"),
            ("failure_code", "host_refused"),
            ("physical_exit_elapsed_ns", 15_000_000_000),
            ("private_log", PRIVATE_CANARY),
        ):
            changed = {**raw, "stopped_predecessor": {**proof, key: value}}
            with self.subTest(key=key), self.assertRaises(hosted.HostedRefused):
                hosted.public_projection(changed, selection, inventories=inventories)

    def test_rechecks_retained_engine_identity_and_shared_mount(self):
        raw, selection, (before, after) = evidence()
        for name in (
            "old_volume",
            "finished_at",
            "runner_volume",
            "image",
            "ordinal",
            "missing_ready_volume",
            "restarted",
            "running",
        ):
            observed = deepcopy(after)
            worker = observed["containers"][CID_TWO]
            if name == "old_volume":
                observed["volumes"]["old-volume"]["labels"]["retained"] = "false"
            elif name == "finished_at":
                worker["state"]["finished_at"] = raw["launch_pair"][0]["finished_at"]
            elif name == "runner_volume":
                worker["mounts"][0]["Name"] = "replacement"
            elif name == "image":
                worker["image"] = selection["images"]["api"]
            elif name == "ordinal":
                worker["labels"]["com.docker.compose.container-number"] = "1"
            elif name == "missing_ready_volume":
                del observed["volumes"][f"{PROJECT}_worker-ready-{RUN_TWO}"]
            elif name == "restarted":
                worker["restarts"] = 1
            else:
                worker["state"]["running"] = True
            changed = {**raw, "after_sha256": digest(canonical(observed))}
            with self.subTest(name=name), self.assertRaises(hosted.HostedRefused):
                hosted.public_projection(
                    changed, selection, inventories=(before, observed)
                )
        with self.assertRaises(hosted.HostedRefused):
            hosted.public_projection(raw, selection)
        with self.assertRaises(hosted.HostedRefused):
            hosted.public_projection(
                {**raw, "after_sha256": "0" * 64},
                selection,
                inventories=(before, after),
            )

    def test_failure_projects_fixed_phase_and_reason_without_raw_evidence(self):
        raw, selection, _ = evidence()
        raw.update(
            status="held",
            stage="launch_refuse_unresolved_predecessor",
            reason="launch_unresolved_refusal_changed_state",
        )
        self.assertEqual(
            hosted.failure_projection(raw, selection),
            {
                "stage": "launch_refuse_unresolved_predecessor",
                "reason": "launch_unresolved_refusal_changed_state",
            },
        )
        raw.update(stage=PRIVATE_CANARY, reason=PRIVATE_CANARY)
        self.assertEqual(
            hosted.failure_projection(raw, selection),
            {
                "stage": "unclassified",
                "reason": "unclassified_refusal",
            },
        )
