"""Existing public writer fenced by one original ACK; private synthetic stores."""

import builtins
from contextlib import nullcontext
import copy
import hashlib
import hmac
from pathlib import Path
import pickle
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_worker_lifecycle_intent as intent_fixtures
import test_worker_registration_fence as fixtures
import worker_cli as cli
import worker_host as host
import worker_lifecycle_intent as intent


TRUST = intent_fixtures.SIGNING_TRUST


class PublicationFenceTests(unittest.TestCase):
    prepared = fixtures.RegistrationFenceTests.prepared
    mint = fixtures.RegistrationFenceTests.mint
    register = fixtures.RegistrationFenceTests.register

    def sequence(self, f, cap, admission):
        return intent.publication_sequence(
            cap,
            public=Path(f.layout.admission_source),
            trust=TRUST,
            admission=admission,
        )

    def publish(self, sequence, kind):
        path = sequence._public / (kind + ".json")
        data = TRUST if kind == "trust" else sequence._admission
        step = intent.publication_step(sequence, kind=kind, path=path, data=data)
        cli.publish_public(path, data, publication_step=step)
        return step

    def test_owned_enable_uses_existing_engines_writer_and_recapture_for_all_modes(
        self,
    ):
        for mode in ("legacy-v1", "finite-v2", "persistent-v3"):
            for existing in (False, True):
                with (
                    self.subTest(mode=mode, existing=existing),
                    self.prepared(mode) as state,
                ):
                    f, store, operation, current, cap, options, _ = state
                    public = Path(f.layout.admission_source)
                    if existing:
                        (public / "trust.json").write_bytes(TRUST)
                    args = SimpleNamespace(
                        runtime_id=f.runtime_id,
                        runner_id=f.runner_id,
                        origin=f.binding["origin"],
                        enrollment_id="enrolled-1",
                        container_id=f.identity.container_id,
                        image_id=f.identity.image_id,
                        project=f.identity.project,
                    )
                    selected = {
                        k: options[k]
                        for k in (
                            "protocol",
                            "limits",
                            "expires_in_seconds",
                            "max_attempts",
                        )
                        if k in options
                    }
                    setup = f.observer, f.client, public, TRUST, selected
                    with patch.object(
                        cli, "owner", return_value=nullcontext(f.session)
                    ):
                        admission, identity = cli._enable_owned(
                            args,
                            f.records,
                            operation,
                            setup,
                            registration_capability=cap,
                        )
                    self.assertEqual(identity, f.identity)
                    self.assertEqual(f.session.register.call_count, 1)
                    self.assertEqual((public / "trust.json").read_bytes(), TRUST)
                    self.assertEqual(
                        (public / "admission.json").read_bytes(),
                        host.canonical(admission),
                    )
                    observed = store.read(current["operation_id"], operation=operation)
                    self.assertEqual(observed["disposition"], "enabled")
                    self.assertTrue(
                        observed["effects"]["publication_may_have_happened"]
                    )
                    self.assertEqual(
                        observed["observations"]["host_record_sha256"],
                        cap._acknowledged[0],
                    )
                    self.assertEqual(
                        observed["observations"]["admission_sha256"],
                        host.digest(admission),
                    )

    def test_marker_is_durable_before_actual_first_open_and_pair_finishes(self):
        with self.prepared() as state:
            f, store, operation, current, cap, options, _ = state
            admission = self.register(f, operation, cap, options)
            real_open = cli.os.open
            seen = []

            def opened(path, *args, **kwargs):
                if Path(path).parent == Path(f.layout.admission_source):
                    value = store.read(current["operation_id"], operation=operation)
                    self.assertTrue(value["effects"]["publication_may_have_happened"])
                    self.assertEqual(
                        value["observations"]["host_record_sha256"],
                        cap._acknowledged[0],
                    )
                    self.assertEqual(
                        value["observations"]["admission_sha256"], cap._acknowledged[1]
                    )
                    seen.append(Path(path).name)
                return real_open(path, *args, **kwargs)

            with self.sequence(f, cap, admission) as sequence:
                with patch.object(cli.os, "open", side_effect=opened):
                    self.publish(sequence, "trust")
                    self.publish(sequence, "admission")
                intent.finish_publication(sequence)
            self.assertEqual(len(seen), 2)
            self.assertTrue(sequence._finished)

    def test_lost_or_retained_ack_cannot_mint_sequence_before_storage_io(self):
        with self.prepared() as state:
            f, store, operation, _, cap, options, _ = state
            respond = f.session.register.side_effect
            f.session.register.side_effect = host.HostRefused()
            with self.assertRaises(host.HostRefused):
                self.register(f, operation, cap, options)
            record = f.records.read(f.runtime_id)
            # Even authentic retained ACK metadata supplies no original-call marker.
            record.update(
                registration_state="acknowledged",
                admission=respond(f.runtime_id, record["registration"]),
            )
            f.records.write(record)
            with patch.object(store, "read", side_effect=AssertionError) as reads:
                with self.assertRaises(intent.IntentRefused):
                    self.sequence(f, cap, record["admission"])
            reads.assert_not_called()
            self.assertTrue(cap._publication_claimed)
            self.assertFalse(
                (Path(f.layout.admission_source) / "admission.json").exists()
            )

    def test_wrong_trust_path_or_admission_burns_one_sequence_without_public_write(
        self,
    ):
        for change in ("trust", "ca_hash", "path", "admission"):
            with self.subTest(change=change), self.prepared() as state:
                f, _, operation, _, cap, options, _ = state
                admission = self.register(f, operation, cap, options)
                kwargs = dict(
                    public=Path(f.layout.admission_source),
                    trust=TRUST,
                    admission=admission,
                )
                if change in {"trust", "ca_hash"}:
                    kwargs["trust"] = (
                        b"different"
                        if change == "trust"
                        else f.client.ca_sha256.encode()
                    )
                elif change == "path":
                    kwargs["public"] = Path(f.layout.admission_source) / "other"
                else:
                    kwargs["admission"] = {}
                with self.assertRaises(intent.IntentRefused):
                    intent.publication_sequence(cap, **kwargs)
                with self.assertRaises(intent.IntentRefused):
                    self.sequence(f, cap, admission)
                self.assertEqual(list(Path(f.layout.admission_source).iterdir()), [])

    def test_cas_or_committed_readback_failure_never_opens_public_file(self):
        for committed in (False, True):
            with self.subTest(committed=committed), self.prepared() as state:
                f, store, operation, current, cap, options, _ = state
                admission = self.register(f, operation, cap, options)
                advance = store.advance

                def failed(*args, **kwargs):
                    if committed:
                        advance(*args, **kwargs)
                    raise OSError()

                sequence = self.sequence(f, cap, admission)
                with self.assertRaises(OSError), sequence:
                    with patch.object(store, "advance", side_effect=failed):
                        self.publish(sequence, "trust")
                self.assertEqual(list(Path(f.layout.admission_source).iterdir()), [])
                observed = store.read(current["operation_id"], operation=operation)
                self.assertEqual(
                    observed["effects"]["publication_may_have_happened"], committed
                )
                with self.assertRaises(intent.IntentRefused):
                    self.sequence(f, cap, admission)

    def test_partial_write_or_publication_interruption_leaves_no_admission_or_retry(
        self,
    ):
        for failure_at in ("open", "short_write", "fsync", "publish", "interrupt"):
            with self.subTest(failure_at=failure_at), self.prepared() as state:
                f, store, operation, current, cap, options, _ = state
                admission = self.register(f, operation, cap, options)
                public = Path(f.layout.admission_source)
                real_open, real_fdopen, real_sync = (
                    cli.os.open,
                    cli.os.fdopen,
                    cli.os.fsync,
                )
                real_publish = cli.os.rename if cli.os.name == "nt" else cli.os.link
                public_fds = set()

                def opened(path, *args, **kwargs):
                    selected = Path(path).parent == public
                    if selected and failure_at == "open":
                        raise OSError()
                    fd = real_open(path, *args, **kwargs)
                    if selected:
                        public_fds.add(fd)
                    return fd

                class PartialFile:
                    def __init__(self, stream):
                        self.stream = stream

                    def __enter__(self):
                        return self

                    def __exit__(self, *args):
                        return self.stream.__exit__(*args)

                    def write(self, data):
                        return self.stream.write(data[:-1] if data == TRUST else data)

                    def flush(self):
                        return self.stream.flush()

                    def fileno(self):
                        return self.stream.fileno()

                def fdopen(fd, mode):
                    stream = real_fdopen(fd, mode)
                    return (
                        PartialFile(stream) if failure_at == "short_write" and mode == "wb" else stream
                    )

                def synced(fd):
                    if fd in public_fds and failure_at == "fsync":
                        raise OSError()
                    return real_sync(fd)

                def published(source, target, *args, **kwargs):
                    if Path(target).parent == public and failure_at in {
                        "publish",
                        "interrupt",
                    }:
                        raise (
                            KeyboardInterrupt()
                            if failure_at == "interrupt"
                            else OSError()
                        )
                    return real_publish(source, target, *args, **kwargs)

                sequence = self.sequence(f, cap, admission)
                with (
                    self.assertRaises((OSError, ValueError, KeyboardInterrupt)),
                    sequence,
                ):
                    with (
                        patch.object(cli.os, "open", side_effect=opened),
                        patch.object(cli.os, "fdopen", side_effect=fdopen),
                        patch.object(cli.os, "fsync", side_effect=synced),
                        patch.object(
                            cli.os,
                            "rename" if cli.os.name == "nt" else "link",
                            side_effect=published,
                        ),
                    ):
                        self.publish(sequence, "trust")
                self.assertFalse((public / "admission.json").exists())
                self.assertTrue(sequence._closed)
                observed = store.read(current["operation_id"], operation=operation)
                self.assertTrue(observed["effects"]["publication_may_have_happened"])
                with self.assertRaises(intent.IntentRefused):
                    self.sequence(f, cap, admission)

    def test_admission_requires_completed_trust_and_spent_steps_cannot_repeat(self):
        with self.prepared() as state:
            f, _, operation, _, cap, options, _ = state
            admission = self.register(f, operation, cap, options)
            with self.sequence(f, cap, admission) as sequence:
                with self.assertRaises(intent.IntentRefused):
                    self.publish(sequence, "admission")
                trust = self.publish(sequence, "trust")
                with self.assertRaises(intent.IntentRefused):
                    intent.before_public_open(trust, path=trust._path, data=trust._data)
                self.publish(sequence, "admission")
                intent.finish_publication(sequence)

    def test_drift_between_public_files_refuses_the_admission_open(self):
        for change in ("client", "observer", "intent", "record"):
            with self.subTest(change=change), self.prepared() as state:
                f, store, operation, current, cap, options, _ = state
                admission = self.register(f, operation, cap, options)
                with self.sequence(f, cap, admission) as sequence:
                    self.publish(sequence, "trust")
                    if change == "client":
                        f.client.ca_sha256 = "0" * 64
                    elif change == "observer":
                        f.observer.context = "different-context"
                    elif change == "record":
                        record = f.records.read(f.runtime_id)
                        record["revocation_state"] = "acknowledged"
                        f.records.write(record)
                    else:
                        previous = store.read(
                            current["operation_id"], operation=operation
                        )
                        updated = copy.deepcopy(previous)
                        updated.update(
                            revision=previous["revision"] + 1,
                            previous_sha256=host.digest(previous),
                        )
                        store.advance(
                            updated,
                            expected_revision=previous["revision"],
                            expected_sha256=host.digest(previous),
                            operation=operation,
                        )
                    with self.assertRaises(intent.IntentRefused):
                        self.publish(sequence, "admission")
                self.assertTrue((sequence._public / "trust.json").exists())
                self.assertFalse((sequence._public / "admission.json").exists())

    def test_existing_trust_is_validated_and_exact_before_admission_only_publication(
        self,
    ):
        with self.prepared() as state:
            f, store, operation, current, cap, options, _ = state
            admission = self.register(f, operation, cap, options)
            public = Path(f.layout.admission_source)
            (public / "trust.json").write_bytes(TRUST)
            with self.sequence(f, cap, admission) as sequence:
                intent.skip_existing_trust(
                    sequence,
                    path=public / "trust.json",
                    validated_trust=cli.public_trust(public / "trust.json"),
                )
                self.publish(sequence, "admission")
                intent.finish_publication(sequence)
            self.assertEqual((public / "trust.json").read_bytes(), TRUST)
            self.assertEqual(
                store.read(current["operation_id"], operation=operation)["disposition"],
                "enabled",
            )

    def test_closed_wrong_thread_and_copy_attempts_grant_no_publication(self):
        with self.prepared() as state:
            f, _, operation, _, cap, options, _ = state
            admission = self.register(f, operation, cap, options)
            sequence = self.sequence(f, cap, admission)
            for action in (
                lambda: copy.copy(sequence),
                lambda: copy.deepcopy(sequence),
                lambda: pickle.dumps(sequence),
            ):
                with self.assertRaises(intent.IntentRefused):
                    action()
            with sequence:
                with patch.object(
                    host.threading, "get_ident", return_value=operation._thread + 1
                ):
                    with self.assertRaises(host.HostRefused):
                        self.publish(sequence, "trust")
            with self.assertRaises(intent.IntentRefused):
                self.publish(sequence, "trust")
            with self.assertRaises(intent.IntentRefused):
                sequence.__enter__()
            self.assertEqual(list(sequence._public.iterdir()), [])

    def test_default_writer_has_no_lifecycle_import_or_hook(self):
        with self.prepared() as state:
            f, _, _, _, _, _, _ = state
            original = builtins.__import__
            attempted = []

            def imported(name, *args, **kwargs):
                if name == "worker_lifecycle_intent":
                    attempted.append(name)
                return original(name, *args, **kwargs)

            with (
                patch.object(builtins, "__import__", side_effect=imported),
                patch.object(intent, "before_public_open") as before,
                patch.object(intent, "complete_publication_step") as complete,
            ):
                cli.publish_public(
                    Path(f.layout.admission_source) / "trust.json", TRUST
                )
            self.assertEqual(attempted, [])
            before.assert_not_called()
            complete.assert_not_called()

    def test_old_schema2_is_held_before_key_access_and_never_migrated(self):
        with self.prepared() as state:
            f, store, operation, current, _, _, calls = state
            key = f.backend.read_intent(
                current["operation_id"], records=f.records, operation=operation
            )
            old = copy.deepcopy(current)
            del old["resources"]["signing_trust_sha256"]
            raw = host.canonical(
                {
                    "schema": "vardr.worker-lifecycle-intent/2",
                    "payload": old,
                    "mac": hmac.new(
                        bytes.fromhex(key),
                        b"vardr.worker-lifecycle-intent/2\0" + host.canonical(old),
                        hashlib.sha256,
                    ).hexdigest(),
                }
            )
            path = store._access(operation, current["operation_id"])
            path.write_bytes(raw)
            before = list(calls)
            with self.assertRaises(intent.IntentRefused):
                store.read(current["operation_id"], operation=operation)
            self.assertEqual(calls, before)
            self.assertEqual(path.read_bytes(), raw)

    def test_old_domain2_cannot_authenticate_a_relabelled_current_record(self):
        with self.prepared() as state:
            f, store, operation, current, _, _, _ = state
            key = f.backend.read_intent(
                current["operation_id"], records=f.records, operation=operation
            )
            raw = host.canonical(
                {
                    "schema": intent.SCHEMA,
                    "payload": current,
                    "mac": hmac.new(
                        bytes.fromhex(key),
                        b"vardr.worker-lifecycle-intent/2\0" + host.canonical(current),
                        hashlib.sha256,
                    ).hexdigest(),
                }
            )
            path = store._access(operation, current["operation_id"])
            path.write_bytes(raw)
            with self.assertRaises(intent.IntentRefused):
                store.read(current["operation_id"], operation=operation)
            self.assertEqual(path.read_bytes(), raw)

    def test_signing_trust_digest_is_mandatory_typed_and_immutable(self):
        with self.prepared() as state:
            _, store, operation, current, _, _, _ = state
            for malformed in (None, True, "", "e" * 63, "E" * 64):
                changed = copy.deepcopy(current)
                changed["resources"]["signing_trust_sha256"] = malformed
                with (
                    self.subTest(malformed=malformed),
                    self.assertRaises((ValueError, TypeError)),
                ):
                    intent._checked(changed)
            missing = copy.deepcopy(current)
            del missing["resources"]["signing_trust_sha256"]
            with self.assertRaises(intent.IntentRefused):
                intent._checked(missing)
            changed = copy.deepcopy(current)
            changed.update(
                revision=current["revision"] + 1, previous_sha256=host.digest(current)
            )
            changed["resources"]["signing_trust_sha256"] = "0" * 64
            with self.assertRaises(intent.IntentRefused):
                store.advance(
                    changed,
                    expected_revision=current["revision"],
                    expected_sha256=host.digest(current),
                    operation=operation,
                )
            self.assertEqual(
                store.read(current["operation_id"], operation=operation), current
            )

    def test_completion_save_failure_keeps_publication_uncertainty_without_retry(self):
        with self.prepared() as state:
            f, store, operation, current, cap, options, _ = state
            admission = self.register(f, operation, cap, options)
            sequence = self.sequence(f, cap, admission)
            with self.assertRaises(OSError), sequence:
                self.publish(sequence, "trust")
                self.publish(sequence, "admission")
                with patch.object(store, "advance", side_effect=OSError):
                    intent.finish_publication(sequence)
            observed = store.read(current["operation_id"], operation=operation)
            self.assertEqual(observed["disposition"], "active")
            self.assertTrue(observed["effects"]["publication_may_have_happened"])
            self.assertTrue((sequence._public / "admission.json").exists())
            with self.assertRaises(intent.IntentRefused):
                self.sequence(f, cap, admission)


if __name__ == "__main__":
    unittest.main()
