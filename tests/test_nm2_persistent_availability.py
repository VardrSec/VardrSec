"""Persistent receipt/selection oracles only; no Docker, traffic or 70-second run."""

from contextlib import redirect_stdout
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import nm2_worker_acceptance as acceptance
import test_nm2_worker_acceptance as finite_tests


def hashed(value):
    return acceptance.digest(value.encode())


def vector():
    fixture = object.__new__(acceptance.Fixture)
    fixture.issuer_origin = "https://map.example/backend"
    identity = dict(
        daemon_id="owned",
        container_id="a" * 64,
        image_id="sha256:" + "b" * 64,
        project="vardrsec-nm2-persistent",
        started_at="2026-11-06T01:59:00Z",
        owner_nonce="c" * 64,
    )
    admission = dict(
        schema="vardr.worker-admission/3",
        runtime_id="00000000-0000-4000-8000-000000000090",
        runtime_sha256=acceptance.digest(acceptance.canonical(identity)),
        enrollment_id="enrolled",
        runner_id="00000000-0000-4000-8000-000000000080",
        origin=fixture.issuer_origin,
        identity=identity,
        capability_sha256=hashed("stop"),
        mode="persistent",
        limits=dict(max_attempts=None, idle_timeout_seconds=None),
        reporting_authority=dict(purpose="worker-stop-only", expires_at=None),
    )
    admission["admission_sha256"] = acceptance.digest(acceptance.canonical(admission))
    physical = dict(
        identity=identity,
        runtime_id=admission["runtime_id"],
        runtime_sha256=admission["runtime_sha256"],
        admission_sha256=admission["admission_sha256"],
        exit_code=125,
        operator_stop_state="stopped_observed",
    )
    runtime = dict(
        id=admission["runtime_id"],
        runtime_sha256=admission["runtime_sha256"],
        identity=identity,
        runner_id=admission["runner_id"],
        enrollment_id="enrolled",
        origin=fixture.issuer_origin,
        max_attempts=None,
        last_sequence="35",
        head_sequence="35",
        active_sequence=None,
        retired=True,
        report_sha256=hashed("report"),
        legacy_binding=dict.fromkeys(
            (
                "job_id",
                "contract_id",
                "attempt_id",
                "fence",
                "contract_sha256",
                "bound_at",
                "confirmed_at",
            )
        ),
        mode="persistent",
        admission_sha256=admission["admission_sha256"],
        admission=admission,
        new_work_disabled=True,
        reporting_revoked=False,
        attempts=[],
    )

    def local(number, attempt=None):
        return dict(
            runtime_id=admission["runtime_id"],
            runtime_sha256=admission["runtime_sha256"],
            admission_sha256=admission["admission_sha256"],
            last_sequence=str(number),
            active_sequence=None,
            state="idle",
            retirement=None,
            remaining_local_holds=0,
            attempt=attempt,
            counts=dict.fromkeys(("runs", "claims", "contracts", "results"), number),
        )

    idle = dict(
        seconds=70.25,
        target_request_count=0,
        admission=admission,
        before=local(0),
        after=local(0),
    )
    measured, inventories = [], []
    start = datetime(2026, 11, 6, 2, tzinfo=timezone.utc)

    def stamp(value):
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")

    for n in range(1, 36):
        bound = start + timedelta(seconds=2 * n)
        binding = dict(
            origin=fixture.issuer_origin,
            runner_id=admission["runner_id"],
            job_id=f"job-{n}",
            contract_id=f"contract-{n}",
            attempt_id=f"attempt-{n}",
            fence=1,
            contract_sha256=hashed(f"contract{n}"),
        )
        case, artifact, native = (
            hashed(f"case{n}"),
            hashed(f"artifact{n}"),
            hashed(f"done{n}"),
        )
        result_sha = acceptance.digest(
            acceptance.canonical(
                dict(
                    schema="vardr.managed-result/1",
                    **binding,
                    artifact_sha256=artifact,
                    case_sha256=case,
                )
            )
        )
        terminal = dict(
            schema="vardr.managed-completion/1",
            **binding,
            receipt_sha256=result_sha,
            outcome="completed",
            capacity_reserved=False,
        )
        terminal_sha = acceptance.digest(acceptance.canonical(terminal))
        release = dict(
            schema="vardr.worker-idle-release/2",
            runtime_id=runtime["id"],
            runtime_sha256=runtime["runtime_sha256"],
            admission_sha256=admission["admission_sha256"],
            runtime_sequence=str(n),
            binding=binding,
            terminal_receipt_sha256=terminal_sha,
            native_done_sha256=native,
            released=True,
        )
        release["receipt_sha256"] = acceptance.digest(acceptance.canonical(release))
        attempt = dict(
            runtime_id=runtime["id"],
            runtime_sequence=str(n),
            previous_sequence=None if n == 1 else str(n - 1),
            runtime_mode="persistent",
            job_id=binding["job_id"],
            binding=binding,
            bound_at=stamp(bound),
            confirmed_at=stamp(bound + timedelta(milliseconds=100)),
            released_at=stamp(bound + timedelta(milliseconds=200)),
            terminal_receipt=terminal,
            terminal_receipt_sha256=terminal_sha,
            native_done_sha256=native,
            release_receipt=release,
        )
        runtime["attempts"].append(attempt)
        local_attempt = dict(
            run_id=f"run-{n}",
            job_id=binding["job_id"],
            phase="done",
            pid=None,
            state="released",
            retired_from_state=None,
            claim_state="persistent_released",
            consumption_sent=1,
            consumption_acknowledged=1,
            artifact_sha256=artifact,
            native_done_sha256=native,
            completion=terminal,
            release=release,
        )
        metadata = local(n, local_attempt)
        metadata["grants"] = dict(
            policy_reason="granted",
            grants=[
                dict(
                    id=f"grant-{n}-{who}",
                    status="active",
                    engagement_id=f"eng-{n}",
                    issued_at=stamp(bound - timedelta(seconds=1)),
                    expires_at=stamp(bound + timedelta(seconds=600)),
                )
                for who in ("owner", "peer")
            ],
        )
        measured.append(
            dict(
                runtime_sequence=str(n),
                engagement_id=f"eng-{n}",
                job_id=binding["job_id"],
                case_sha256=case,
                artifact_sha256=artifact,
                result_receipt_sha256=result_sha,
                terminal_receipt_sha256=terminal_sha,
                release_receipt_sha256=release["receipt_sha256"],
                native_done_sha256=native,
                evidence_count=5,
                requests=[
                    dict(
                        identity=who,
                        path=f"/fixed?nm2_case=persistent-{n}",
                        received_monotonic_ns=n * 100 + i,
                    )
                    for i, who in enumerate(
                        ("owner", "peer", "owner", "peer", "anonymous")
                    )
                ],
                target_charge=1,
                duration_seconds=30,
                capacity_reserved=False,
                local=metadata,
                terminal_receipt=terminal,
                release_receipt=release,
                **{k: attempt[k] for k in ("bound_at", "confirmed_at", "released_at")},
            )
        )
        inventories.append(
            dict(
                runtimes=[runtime],
                targets_spent=1,
                duration_allocated=30,
                approvals=[
                    dict(
                        id=f"approval-{n}",
                        issued=1,
                        revoked=False,
                        max_executions=1,
                        max_duration_seconds=30,
                        approved_at=stamp(bound - timedelta(seconds=1)),
                        expires_at=stamp(bound + timedelta(seconds=300)),
                        credential_grants=[
                            dict(expires_at=stamp(bound + timedelta(seconds=300)))
                            for _ in range(2)
                        ],
                    )
                ],
            )
        )
    retirement = dict(
        schema="vardr.worker-retirement/3",
        runtime_id=runtime["id"],
        runtime_sha256=runtime["runtime_sha256"],
        admission_sha256=admission["admission_sha256"],
        origin=fixture.issuer_origin,
        runner_id=admission["runner_id"],
        enrollment_id="enrolled",
        runtime_sequence=None,
        last_sequence="35",
        binding=None,
        attempt_receipt=None,
        report_sha256=runtime["report_sha256"],
        retired=True,
    )
    retirement["receipt_sha256"] = acceptance.digest(acceptance.canonical(retirement))
    retained = copy.deepcopy(measured[-1]["local"])
    retained.update(state="retired", retirement=retirement)
    retained["attempt"].update(
        state="physical_retirement_observed", retired_from_state="released"
    )
    return SimpleNamespace(
        fixture=fixture,
        physical=physical,
        idle=idle,
        measured=measured,
        inventories=inventories,
        retirement=retirement,
        retained=retained,
        runtime=runtime,
    )


class PersistentAvailability(unittest.TestCase):
    def verify(self, data):
        return data.fixture.verify_persistent_sequence(
            data.physical,
            data.idle,
            data.measured,
            data.inventories,
            data.retirement,
            data.retained,
        )

    def test_35_jobs_require_unlimited_admission_and_closed_original_proofs(self):
        value = self.verify(vector())
        self.assertEqual(value["last_sequence"], "35")
        self.assertEqual(value["target_request_count"], 175)
        self.assertEqual(value["evidence_count"], 175)
        self.assertEqual(
            value["limits"], dict(max_attempts=None, idle_timeout_seconds=None)
        )

    def test_missing_idle_history_reused_identity_or_ack_never_pass(self):
        faults = {
            "short_idle": lambda d: d.idle.update(seconds=60),
            "only32": lambda d: d.measured.__delitem__(slice(32, None)),
            "gap": lambda d: d.runtime["attempts"][20].update(previous_sequence="1"),
            "counter_number": lambda d: d.runtime.update(last_sequence=35),
            "finite_limit": lambda d: d.idle["admission"]["limits"].update(
                max_attempts="35"
            ),
            "idle_limit": lambda d: d.idle["admission"]["limits"].update(
                idle_timeout_seconds=60
            ),
            "hold": lambda d: d.measured[10]["local"].update(remaining_local_holds=1),
            "bool_count": lambda d: d.measured[0]["local"]["counts"].update(
                claims=True
            ),
            "lost_ack": lambda d: d.measured[10]["local"]["attempt"].update(
                consumption_acknowledged=0
            ),
            "active_pid": lambda d: d.measured[10]["local"]["attempt"].update(pid=123),
            "old_approval": lambda d: d.inventories[10]["approvals"][0].update(
                expires_at="2026-11-06T01:00:00Z"
            ),
            "missing_grants": lambda d: d.inventories[10]["approvals"][0].update(
                credential_grants=[]
            ),
            "revoked_grant": lambda d: d.measured[10]["local"]["grants"]["grants"][
                0
            ].update(status="revoked"),
            "next_bound_early": lambda d: d.measured[10].update(
                bound_at=d.measured[9]["bound_at"]
            ),
            "request_clock_bool": lambda d: d.measured[10]["requests"][0].update(
                received_monotonic_ns=True
            ),
            "request_order": lambda d: d.measured[10]["requests"][0].update(
                received_monotonic_ns=1
            ),
            "retirement_changed": lambda d: d.retirement.update(
                receipt_sha256="0" * 64
            ),
            "retained_job_changed": lambda d: d.retained["attempt"].update(
                artifact_sha256="0" * 64
            ),
        }
        for name, fault in faults.items():
            with self.subTest(name=name):
                data = vector()
                fault(data)
                with self.assertRaises(acceptance.AcceptanceRefused):
                    self.verify(data)

    def test_persistent_fixed_case_uses_release2_without_requiring_clean_operator_exit(
        self,
    ):
        data = finite_tests.AcceptanceGuards().sequence_fixture()
        data.fixture.database_revision = "0041persistentruntime"
        data.physical.update(exit_code=125, operator_stop_state="stopped_observed")
        for inventory in data.inventories:
            inventory["schema"] = "vardr.nm2-fixture-inventory/3"
            inventory["schema_revision"] = "0041persistentruntime"
            runtime = inventory["runtimes"][0]
            runtime["admission_sha256"] = "e" * 64
            for attempt in runtime["attempts"]:
                attempt["runtime_sequence"] = str(attempt["runtime_sequence"])
                release = attempt["release_receipt"]
                release.update(
                    schema="vardr.worker-idle-release/2",
                    runtime_sequence=attempt["runtime_sequence"],
                    admission_sha256="e" * 64,
                )
                release["receipt_sha256"] = acceptance.digest(
                    acceptance.canonical(
                        {k: v for k, v in release.items() if k != "receipt_sha256"}
                    )
                )
        for selection, inventory, traffic in zip(
            data.selections, data.inventories, data.traffic
        ):
            _, proof = data.fixture.verify_fixed(
                *selection, data.physical, {}, traffic, inventory, persistent=True
            )
            self.assertEqual(
                proof["release_receipt"]["schema"], "vardr.worker-idle-release/2"
            )

    def test_source_only_selection_requires_explicit0041_and_never_calls_docker(self):
        selection = dict(project="owned", sources={}, images={})
        with (
            patch.object(acceptance, "manifest", return_value=selection),
            patch.object(
                acceptance, "command", side_effect=AssertionError("Docker forbidden")
            ),
        ):
            with self.assertRaisesRegex(
                acceptance.AcceptanceRefused, "persistent_database_revision_required"
            ):
                acceptance.main(
                    ["--cohort", "unused", "--scenario", "persistent-availability"]
                )
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    acceptance.main(
                        [
                            "--cohort",
                            "unused",
                            "--scenario",
                            "persistent-availability",
                            "--database-revision",
                            "0041persistentruntime",
                        ]
                    ),
                    0,
                )
            value = json.loads(output.getvalue())
            self.assertEqual(value["docker_calls"], 0)
            self.assertIn("persistent_availability", value["initial_cases"])

    def test_inventory_fixture_bound_refuses_overflow_instead_of_truncating(self):
        fake_models = ModuleType("models")
        for name in (
            "Engagement",
            "JobExecution",
            "ManagedApproval",
            "ManagedContract",
            "ManagedResult",
            "ManagedRuntime",
            "ManagedRuntimeAttempt",
            "ManagedStop",
            "ScanJob",
        ):
            setattr(fake_models, name, Mock())
        sql = ModuleType("sqlalchemy")
        sql.text = lambda x: x
        db = ModuleType("db")
        db.SessionLocal = Mock()
        wire = ModuleType("managed_wire")
        wire.parse = Mock()
        wire.unb64 = Mock()
        path = Path(acceptance.__file__).with_name("nm2_worker_inventory.py")
        spec = importlib.util.spec_from_file_location(
            "persistent_inventory_projection_test", path
        )
        module = importlib.util.module_from_spec(spec)
        with patch.dict(
            sys.modules, models=fake_models, db=db, sqlalchemy=sql, managed_wire=wire
        ):
            spec.loader.exec_module(module)
        data = vector()
        runtime = SimpleNamespace(
            **data.runtime, **data.runtime["legacy_binding"], revoked=False
        )
        runtime.admission_snapshot = data.runtime["admission"]
        rows = [
            SimpleNamespace(
                **{k: v for k, v in row.items() if k != "binding"},
                **{k: v for k, v in row["binding"].items() if k not in row},
            )
            for row in data.runtime["attempts"]
        ]
        for row in rows:
            for key in ("bound_at", "confirmed_at", "released_at"):
                setattr(
                    row,
                    key,
                    datetime.fromisoformat(getattr(row, key).replace("Z", "+00:00")),
                )
        query = Mock()
        query.filter_by.return_value = query
        query.order_by.return_value = query
        query.limit.return_value = query
        engine = Mock()
        engine.query.return_value = query
        query.all.return_value = rows
        self.assertEqual(
            len(
                module.runtime_projection(engine, runtime, persistent_bound=35)[
                    "attempts"
                ]
            ),
            35,
        )
        query.all.return_value = rows + [rows[-1]]
        with self.assertRaisesRegex(ValueError, "fixture_runtime_history_bound"):
            module.runtime_projection(engine, runtime, persistent_bound=35)
        with self.assertRaisesRegex(ValueError, "fixture_runtime_history_bound"):
            module.runtime_projection(engine, runtime)


if __name__ == "__main__":
    unittest.main()
