"""Real login/registration/logout code with private stores and mocked HTTP only."""

from contextlib import contextmanager
from pathlib import Path
import copy
import pickle
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_worker_lifecycle_intent as intent_fixtures
import test_worker_registration_fence as fixtures
import worker_cli as cli
import worker_host as host


class PreparedEnableOwnerTests(unittest.TestCase):
    prepared = fixtures.RegistrationFenceTests.prepared

    @contextmanager
    def authentication(self, f, *, fail=None):
        events = []
        error = (
            KeyboardInterrupt() if fail == "logout_interrupt" else host.HostRefused()
        )
        response = f.session.register.side_effect

        def request(method, path, body=None, headers=None):
            if (method, path) == ("POST", "/auth/local/login"):
                events.append("login")
                if fail == "login":
                    raise error
                return {"authenticated": True}, [
                    (
                        "Set-Cookie",
                        f"{host._COOKIE}={'x' * 43}; Secure; HttpOnly; Path=/; SameSite=lax",
                    )
                ]
            if (method, path) == ("GET", "/auth/local/session"):
                events.append("session")
                return {
                    "authMethod": "wrong" if fail == "session" else "local",
                    "csrfToken": "a" * 64,
                    "user": {},
                }, []
            if (method, path) == ("POST", f"/managed/runtimes/{f.runtime_id}/register"):
                events.append("register")
                if fail == "register":
                    raise error
                return response(f.runtime_id, body), []
            if (method, path) == ("POST", "/auth/local/logout"):
                events.append("logout")
                if fail in {"logout_interrupt", "logout_refused"}:
                    raise error
                return {"authenticated": False}, []
            raise AssertionError("unselected synthetic HTTP call")

        with (
            patch.object(f.client, "_request", side_effect=request),
            patch.object(cli, "password", return_value="synthetic-password") as prompt,
        ):
            yield events, error, prompt

    def inputs(self, f, options):
        args = SimpleNamespace(
            runtime_id=f.runtime_id,
            runner_id=f.runner_id,
            username="fixture-owner",
            password_stdin=False,
            origin=f.binding["origin"],
            enrollment_id="enrolled-1",
            container_id=f.identity.container_id,
            image_id=f.identity.image_id,
            project=f.identity.project,
        )
        admission = {
            k: options[k]
            for k in ("protocol", "limits", "expires_in_seconds", "max_attempts")
            if k in options
        }
        setup = (
            f.observer,
            f.client,
            Path(f.layout.admission_source),
            intent_fixtures.SIGNING_TRUST,
            admission,
        )
        return args, setup

    def test_one_real_session_spans_modelled_start_and_registration_then_closes_before_writes(
        self,
    ):
        for mode in ("legacy-v1", "finite-v2", "persistent-v3"):
            with self.subTest(mode=mode), self.prepared(mode) as state:
                f, store, operation, current, cap, options, _ = state
                args, setup = self.inputs(f, options)
                original = cli.publish_public
                with self.authentication(f) as (events, _, prompt):
                    with cli._preauthenticate_enable_owner(
                        f.records, operation, f.client, args
                    ) as selected:
                        session = selected._session
                        self.assertEqual(events, ["login", "session"])
                        events.append("start-model")  # No Docker action in this test.

                        def publish(path, data, **kwargs):
                            self.assertIsNone(session._cookie)
                            self.assertIsNone(session._csrf)
                            self.assertIn("logout", events)
                            events.append(path.name)
                            return original(path, data, **kwargs)

                        with patch.object(cli, "publish_public", side_effect=publish):
                            _, identity = cli._enable_owned(
                                args,
                                f.records,
                                operation,
                                setup,
                                registration_capability=cap,
                                preauthenticated_owner=selected,
                            )
                        self.assertEqual(identity, f.identity)
                        self.assertTrue(selected._used)
                        with self.assertRaises(cli.CLIRefused):
                            with selected._take(f.records, operation, f.client):
                                self.fail("used session cannot be borrowed")
                    prompt.assert_called_once_with(False)
                self.assertEqual(
                    events,
                    [
                        "login",
                        "session",
                        "start-model",
                        "register",
                        "logout",
                        "trust.json",
                        "admission.json",
                    ],
                )
                self.assertFalse(selected._active)
                self.assertIsNone(selected._session)
                self.assertEqual(
                    store.read(current["operation_id"], operation=operation)[
                        "disposition"
                    ],
                    "enabled",
                )

    def test_login_or_session_refusal_never_enters_prepared_body(self):
        for failure in ("login", "session"):
            with self.subTest(failure=failure), self.prepared() as state:
                f, _, operation, _, _, options, _ = state
                args, _ = self.inputs(f, options)
                with self.authentication(f, fail=failure) as (events, _, _):
                    with self.assertRaises(host.HostRefused):
                        with cli._preauthenticate_enable_owner(
                            f.records, operation, f.client, args
                        ):
                            self.fail("authentication refusal reached launch body")
                self.assertEqual(
                    events, ["login"] if failure == "login" else ["login", "session"]
                )
                self.assertFalse(f.records._path(f.runtime_id).exists())

    def test_invalid_operation_or_client_refuses_before_prompt_or_http(self):
        with self.prepared() as state:
            f, _, operation, _, _, options, _ = state
            args, _ = self.inputs(f, options)
            with self.authentication(f) as (events, _, prompt):
                for token, client in ((object(), f.client), (operation, object())):
                    with self.assertRaises((host.HostRefused, cli.CLIRefused)):
                        with cli._preauthenticate_enable_owner(
                            f.records, token, client, args
                        ):
                            self.fail("invalid identity reached login")
                prompt.assert_not_called()
                self.assertEqual(events, [])

    def test_unused_scope_closes_once_and_preserves_original_body_exception(self):
        with self.prepared() as state:
            f, _, operation, _, _, options, _ = state
            args, _ = self.inputs(f, options)
            failure = OSError()
            with self.authentication(f) as (events, _, _):
                with self.assertRaises(OSError) as caught:
                    with cli._preauthenticate_enable_owner(
                        f.records, operation, f.client, args
                    ) as selected:
                        session = selected._session
                        raise failure
            self.assertIs(caught.exception, failure)
            self.assertEqual(events, ["login", "session", "logout"])
            self.assertIsNone(session._cookie)
            self.assertIsNone(session._csrf)
            with self.assertRaises(cli.CLIRefused):
                with selected._take(f.records, operation, f.client):
                    self.fail("closed scope cannot be borrowed")

    def test_fenced_registration_required_before_borrow_or_local_effect(self):
        with self.prepared() as state:
            f, _, operation, _, cap, options, _ = state
            args, setup = self.inputs(f, options)
            with self.authentication(f) as (events, _, _):
                with cli._preauthenticate_enable_owner(
                    f.records, operation, f.client, args
                ) as selected:
                    with patch.object(
                        f.records, "locked", side_effect=AssertionError
                    ) as locked:
                        with self.assertRaises(cli.CLIRefused):
                            cli._enable_owned(
                                args,
                                f.records,
                                operation,
                                setup,
                                preauthenticated_owner=selected,
                            )
                        with self.assertRaises(cli.CLIRefused):
                            cli._enable_owned(
                                args,
                                f.records,
                                operation,
                                setup,
                                registration_capability=cap,
                                preauthenticated_owner=True,
                            )
                    locked.assert_not_called()
                    self.assertFalse(selected._used)
            self.assertEqual(events, ["login", "session", "logout"])

    def test_transport_drift_never_sends_a_register_or_logout_credential(self):
        for field, value in (
            ("ca_sha256", "0" * 64),
            ("host", "wrong.example"),
            ("_tls", object()),
        ):
            with self.subTest(field=field), self.prepared() as state:
                f, _, operation, _, cap, options, _ = state
                args, setup = self.inputs(f, options)
                original = getattr(f.client, field)
                try:
                    with self.authentication(f) as (events, _, _):
                        with cli._preauthenticate_enable_owner(
                            f.records, operation, f.client, args
                        ) as selected:
                            session = selected._session
                            setattr(f.client, field, value)
                            with self.assertRaises(cli.CLIRefused):
                                cli._enable_owned(
                                    args,
                                    f.records,
                                    operation,
                                    setup,
                                    registration_capability=cap,
                                    preauthenticated_owner=selected,
                                )
                            # A stale live session also cannot bypass the transport check directly.
                            with self.assertRaises(host.HostRefused):
                                session.register(f.runtime_id, {})
                    self.assertEqual(events, ["login", "session"])
                    self.assertIsNone(session._cookie)
                    self.assertIsNone(session._csrf)
                finally:
                    setattr(f.client, field, original)

    def test_registration_refusal_keeps_original_send_held_and_never_publishes(self):
        with self.prepared() as state:
            f, store, operation, current, cap, options, _ = state
            args, setup = self.inputs(f, options)
            with self.authentication(f, fail="register") as (events, _, _):
                with self.assertRaises(host.HostRefused):
                    with cli._preauthenticate_enable_owner(
                        f.records, operation, f.client, args
                    ) as selected:
                        session = selected._session
                        cli._enable_owned(
                            args,
                            f.records,
                            operation,
                            setup,
                            registration_capability=cap,
                            preauthenticated_owner=selected,
                        )
            self.assertEqual(events, ["login", "session", "register", "logout"])
            self.assertIsNone(session._cookie)
            observed = store.read(current["operation_id"], operation=operation)
            self.assertTrue(observed["effects"]["registration_may_have_sent"])
            self.assertFalse(observed["effects"]["publication_may_have_happened"])
            self.assertEqual(list(setup[2].iterdir()), [])

    def test_logout_interruption_clears_local_fields_and_holds_publication(self):
        with self.prepared() as state:
            f, store, operation, current, cap, options, _ = state
            args, setup = self.inputs(f, options)
            with self.authentication(f, fail="logout_interrupt") as (
                events,
                failure,
                _,
            ):
                with self.assertRaises(KeyboardInterrupt) as caught:
                    with cli._preauthenticate_enable_owner(
                        f.records, operation, f.client, args
                    ) as selected:
                        session = selected._session
                        cli._enable_owned(
                            args,
                            f.records,
                            operation,
                            setup,
                            registration_capability=cap,
                            preauthenticated_owner=selected,
                        )
            self.assertIs(caught.exception, failure)
            self.assertEqual(events, ["login", "session", "register", "logout"])
            self.assertIsNone(session._cookie)
            self.assertIsNone(session._csrf)
            self.assertTrue(selected._used)
            self.assertFalse(selected._active)
            self.assertFalse(
                store.read(current["operation_id"], operation=operation)["effects"][
                    "publication_may_have_happened"
                ]
            )
            self.assertEqual(list(setup[2].iterdir()), [])

    def test_scope_is_noncopyable_and_requires_the_same_live_thread(self):
        with self.prepared() as state:
            f, _, operation, _, _, options, _ = state
            args, _ = self.inputs(f, options)
            with self.authentication(f) as (events, _, _):
                with cli._preauthenticate_enable_owner(
                    f.records, operation, f.client, args
                ) as selected:
                    for action in (
                        lambda: copy.copy(selected),
                        lambda: copy.deepcopy(selected),
                        lambda: pickle.dumps(selected),
                        lambda: setattr(selected, "_used", False),
                    ):
                        with self.assertRaises(cli.CLIRefused):
                            action()
                    with patch.object(
                        host.threading, "get_ident", return_value=operation._thread + 1
                    ):
                        with self.assertRaises(host.HostRefused):
                            with selected._take(f.records, operation, f.client):
                                self.fail("wrong thread borrowed authenticated session")
            self.assertEqual(events, ["login", "session", "logout"])


if __name__ == "__main__":
    unittest.main()
