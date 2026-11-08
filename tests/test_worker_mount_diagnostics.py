"""Pure mount-custody failure injection; no stores, files, daemon or Runner."""

from pathlib import PurePosixPath
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import worker_host as host
import worker_runtime as runtime
import worker_volumes as volumes

PRIVATE = "private-path-cookie-body-canary"
POINTS = (
    "mount_managed_metadata",
    "mount_bind_resolution",
    "mount_managed_resolution",
    "mount_private_resolution",
    "mount_separation",
)


def detail(checkpoint):
    return {"checkpoint": checkpoint, "request_stage": None, "http_status": None}


class VirtualPath:
    def __init__(self, value, fixture):
        self.value = (
            value.value if isinstance(value, VirtualPath) else PurePosixPath(value)
        )
        self.fixture = fixture

    def resolve(self, *, strict):
        assert strict is True
        self.fixture.calls.append(("resolve", str(self.value)))
        point = (
            "mount_bind_resolution"
            if str(self.value).startswith("/bind/")
            else "mount_managed_resolution"
            if str(self.value).startswith("/managed/")
            else "mount_private_resolution"
        )
        if self.fixture.failure == point:
            raise self.fixture.error
        return self

    def is_relative_to(self, other):
        self.fixture.calls.append(("relative", str(self.value), str(other.value)))
        if self.fixture.failure == "mount_separation":
            raise self.fixture.error
        return self.value.is_relative_to(other.value)


class CustodyFixture:
    def __init__(self, failure=None, error=None):
        self.failure, self.error, self.calls = failure, error, []
        self.records = object.__new__(host.HostRecords)
        self.records.directory = self.path("/private/records")
        self.records.backend = object.__new__(host.custody.PosixSecrets)
        self.records.backend.directory = self.path("/private/secrets")
        self.observer = object.__new__(runtime.LocalDocker)
        self.observer.layout = SimpleNamespace(
            trust_source="/bind/trust", admission_source="/bind/admission"
        )
        self.identity = object()

    def path(self, value):
        return VirtualPath(value, self)

    def metadata(self, observer, identity):
        assert observer is self.observer and identity is self.identity
        self.calls.append(("managed_metadata",))
        if self.failure == "mount_managed_metadata":
            raise self.error
        return (PurePosixPath("/managed/state"), PurePosixPath("/managed/ready"))

    def run(self, *, registering=True):
        with (
            patch.object(host, "Path", side_effect=self.path),
            patch.object(host, "os", SimpleNamespace(name="posix")),
            patch.object(volumes, "managed_sources", side_effect=self.metadata),
        ):
            if registering:
                with host.registration_step("mount_custody"):
                    self.records.outside_mounts(self.observer, self.identity)
            else:
                self.records.outside_mounts(self.observer, self.identity)


class MountDiagnostics(unittest.TestCase):
    def test_created_custody_uses_actual_volume_reader_and_both_private_ancestries(
        self,
    ):
        # Actual host/volume functions, synthetic profile and Docker replies only.
        from test_worker_volumes import ManagedVolumeTests

        model = ManagedVolumeTests()
        model.setUp()
        model.layout = runtime.WorkerLayout(
            "/bind/trust", "/bind/admission", "fixture-state", "fixture-ready-fresh"
        )
        observer, created = model.created_observer()
        fixture = CustodyFixture()
        fixture.observer, fixture.identity = observer, created
        for location in (
            "/private/records",
            "/bind/trust/private",
            "/bind",
            "/bind/admission/private",
        ):
            with self.subTest(location=location):
                fixture.records.directory = fixture.path(location)
                observer, created = model.created_observer()
                model.calls = []
                with (
                    patch.object(host, "Path", side_effect=fixture.path),
                    patch.object(host, "os", SimpleNamespace(name="posix")),
                    patch.object(runtime.subprocess, "run", model.command),
                ):
                    if location == "/private/records":
                        fixture.records.outside_mounts(observer, created)
                    else:
                        with self.assertRaises(host.HostRefused):
                            fixture.records.outside_mounts(observer, created)
                self.assertEqual(len(model.calls), 4)
                observer._bound.assert_not_called()
                self.assertFalse(observer._observation_lock.locked())

    def test_each_actual_block_has_a_fixed_subcheckpoint(self):
        for point in POINTS:
            with self.subTest(point=point):
                fixture = CustodyFixture(point, OSError(PRIVATE))
                with self.assertRaises(host.HostRefused) as caught:
                    fixture.run()
                self.assertEqual(
                    host.registration_diagnostic(caught.exception), detail(point)
                )
                self.assertEqual(str(caught.exception), "worker_host_refused")
                self.assertEqual(fixture.calls[0], ("managed_metadata",))
                self.assertEqual(fixture.calls.count(("managed_metadata",)), 1)
                self.assertNotIn(
                    PRIVATE, str(host.registration_diagnostic(caught.exception))
                )

    def test_success_preserves_existing_operation_order_without_extra_observations(
        self,
    ):
        fixture = CustodyFixture()
        fixture.run()
        sources = ("/bind/trust", "/bind/admission", "/managed/state", "/managed/ready")
        expected = [("managed_metadata",)] + [("resolve", source) for source in sources]
        for location in ("/private/records", "/private/secrets"):
            expected.append(("resolve", location))
            for source in sources:
                expected.extend(
                    [("relative", location, source), ("relative", source, location)]
                )
        self.assertEqual(fixture.calls, expected)

    def test_outside_registration_rethrows_identical_exception_and_chain(self):
        for point in POINTS:
            with self.subTest(point=point):
                original = OSError(PRIVATE)
                original.__cause__, original.__context__ = (
                    LookupError(PRIVATE),
                    TypeError(PRIVATE),
                )
                before = (original.args, original.__cause__, original.__context__)
                with self.assertRaises(OSError) as caught:
                    CustodyFixture(point, original).run(registering=False)
                self.assertIs(caught.exception, original)
                self.assertEqual(
                    (original.args, original.__cause__, original.__context__), before
                )

    def test_hostile_attributes_cannot_mask_error_or_escape_fixed_fallback(self):
        class RefusesAnnotation(OSError):
            def __setattr__(self, name, value):
                if name == "_mount_custody_checkpoint":
                    raise RuntimeError(PRIVATE)
                super().__setattr__(name, value)

        class RefusesDictionary(OSError):
            @property
            def __dict__(self):
                raise RuntimeError(PRIVATE)

        class RefusesHostDictionary(host.HostRefused):
            @property
            def __dict__(self):
                raise RuntimeError(PRIVATE)

        for kind in (RefusesAnnotation, RefusesDictionary, RefusesHostDictionary):
            with self.subTest(kind=kind.__name__):
                original = kind(PRIVATE)
                with self.assertRaises(kind) as caught:
                    CustodyFixture("mount_bind_resolution", original).run(
                        registering=False
                    )
                self.assertIs(caught.exception, original)
                with self.assertRaises(host.HostRefused) as caught:
                    CustodyFixture("mount_bind_resolution", kind(PRIVATE)).run()
                self.assertEqual(
                    host.registration_diagnostic(caught.exception),
                    detail("mount_custody"),
                )
                self.assertEqual(str(caught.exception), "worker_host_refused")

    def test_hostile_metadata_key_validation_cannot_replace_original_refusal(self):
        seen = []

        class MetadataKey:
            armed = False

            def __hash__(self):
                if self.armed:
                    seen.append("armed_hash")
                    raise RuntimeError(PRIVATE)
                return hash("checkpoint")

            def __eq__(self, other):
                if self.armed:
                    seen.append("armed_equality")
                    raise RuntimeError(PRIVATE)
                return other == "checkpoint"

        key = MetadataKey()
        metadata = {key: "mount_custody", "request_stage": None, "http_status": None}
        original = host.HostRefused(PRIVATE)
        original.registration_failure = metadata
        key.armed = True
        with self.assertRaises(host.HostRefused) as caught:
            CustodyFixture("mount_managed_metadata", original).run()
        self.assertEqual(str(caught.exception), "worker_host_refused")
        self.assertEqual(
            host.registration_diagnostic(caught.exception),
            detail("mount_managed_metadata"),
        )
        self.assertTrue(seen)
        self.assertNotIn(PRIVATE, str(host.registration_diagnostic(caught.exception)))

    def test_valid_innermost_host_detail_wins_over_outer_mount_annotations(self):
        selected = {
            "checkpoint": "request",
            "request_stage": "status",
            "http_status": 403,
        }
        original = host.HostRefused(PRIVATE, registration_failure=selected)
        with self.assertRaises(host.HostRefused) as caught:
            CustodyFixture("mount_bind_resolution", original).run()
        self.assertEqual(host.registration_diagnostic(caught.exception), selected)
        original = OSError(PRIVATE)
        original._mount_custody_checkpoint = "mount_separation"
        with self.assertRaises(host.HostRefused) as caught:
            CustodyFixture("mount_managed_metadata", original).run()
        self.assertEqual(
            host.registration_diagnostic(caught.exception), detail("mount_separation")
        )

    def test_closed_runtime_checkpoints_reach_the_registration_envelope(self):
        for checkpoint in runtime.CAPTURE_CHECKPOINTS:
            with self.subTest(checkpoint=checkpoint):
                original = runtime.RuntimeRefused(PRIVATE)
                original.checkpoint = checkpoint
                with self.assertRaises(host.HostRefused) as caught:
                    CustodyFixture("mount_managed_metadata", original).run()
                self.assertEqual(
                    host.registration_diagnostic(caught.exception),
                    detail("mount_capture_" + checkpoint),
                )
                self.assertNotIn(
                    PRIVATE, str(host.registration_diagnostic(caught.exception))
                )

    def test_unknown_and_secret_attributes_never_enter_the_envelope(self):
        class StringAlias(str):
            pass

        for value in (None, False, 1, [], {}, PRIVATE, StringAlias("daemon")):
            with self.subTest(kind=type(value).__name__):
                original = runtime.RuntimeRefused(PRIVATE)
                original.checkpoint = value
                original._mount_custody_checkpoint = value
                with self.assertRaises(host.HostRefused) as caught:
                    CustodyFixture("mount_managed_metadata", original).run()
                self.assertEqual(
                    host.registration_diagnostic(caught.exception),
                    detail("mount_managed_metadata"),
                )

    def test_managed_wrapper_preserves_only_closed_capture_metadata_and_fixed_message(
        self,
    ):
        identity = runtime.RuntimeIdentity(
            "daemon",
            "a" * 64,
            "sha256:" + "b" * 64,
            "fixture",
            "2026-11-06T18:00:00Z",
            "c" * 64,
        )
        values = tuple(runtime.CAPTURE_CHECKPOINTS) + (None, False, [], PRIVATE)
        for checkpoint in values:
            with self.subTest(kind=type(checkpoint).__name__):
                observer = runtime.LocalDocker(
                    "unit",
                    runtime.WorkerLayout(
                        "/bind/trust", "/bind/admission", "state", "ready"
                    ),
                )
                original = runtime.RuntimeRefused(PRIVATE)
                original.checkpoint = checkpoint
                observer._bound = Mock(side_effect=original)
                observer._command = Mock(side_effect=AssertionError("no process"))
                with self.assertRaises(runtime.RuntimeRefused) as caught:
                    volumes.managed_sources(observer, identity)
                self.assertEqual(str(caught.exception), "worker_runtime_refused")
                self.assertEqual(
                    getattr(caught.exception, "checkpoint", None),
                    checkpoint
                    if type(checkpoint) is str
                    and checkpoint in runtime.CAPTURE_CHECKPOINTS
                    else None,
                )
                observer._bound.assert_called_once_with(identity)
                observer._command.assert_not_called()
                self.assertIsNone(observer._deadline)
                self.assertFalse(observer._observation_lock.locked())

    def test_dynamic_capture_properties_are_not_evaluated_or_exported(self):
        seen = []

        class PropertyCapture(runtime.RuntimeRefused):
            @property
            def checkpoint(self):
                seen.append("property_called")
                raise RuntimeError(PRIVATE)

        original = PropertyCapture(PRIVATE)
        observer = runtime.LocalDocker(
            "unit",
            runtime.WorkerLayout("/bind/trust", "/bind/admission", "state", "ready"),
        )
        observer._bound = Mock(side_effect=original)
        identity = runtime.RuntimeIdentity(
            "daemon",
            "a" * 64,
            "sha256:" + "b" * 64,
            "fixture",
            "2026-11-06T18:00:00Z",
            "c" * 64,
        )
        with self.assertRaises(runtime.RuntimeRefused) as caught:
            volumes.managed_sources(observer, identity)
        self.assertEqual(str(caught.exception), "worker_runtime_refused")
        self.assertFalse(hasattr(caught.exception, "checkpoint"))
        with self.assertRaises(host.HostRefused) as caught:
            CustodyFixture("mount_managed_metadata", original).run()
        self.assertEqual(
            host.registration_diagnostic(caught.exception),
            detail("mount_managed_metadata"),
        )
        self.assertEqual(seen, [])

    def test_linux_permission_fallback_remains_successful_and_other_errors_stay_refused(
        self,
    ):
        fixture = CustodyFixture("mount_managed_resolution", PermissionError(PRIVATE))
        fixture.run()
        for error in (FileNotFoundError(PRIVATE), OSError(PRIVATE)):
            with (
                self.subTest(kind=type(error).__name__),
                self.assertRaises(host.HostRefused) as caught,
            ):
                CustodyFixture("mount_managed_resolution", error).run()
            self.assertEqual(
                host.registration_diagnostic(caught.exception),
                detail("mount_managed_resolution"),
            )

    def test_both_directions_of_mount_ancestry_still_refuse(self):
        for location in ("/bind", "/bind/trust/records"):
            with self.subTest(location=location):
                fixture = CustodyFixture()
                fixture.records.directory = fixture.path(location)
                with self.assertRaises(host.HostRefused) as caught:
                    fixture.run()
                self.assertEqual(
                    host.registration_diagnostic(caught.exception),
                    detail("mount_separation"),
                )


if __name__ == "__main__":
    unittest.main()
