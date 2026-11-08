"""Synthetic Compose boundary checks; never invoke Docker or read real config."""
import argparse
import contextlib
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vardrsec


def model(root, project="recovered"):
    def mount(kind, source, target, readonly=False):
        return {"type": kind, "source": source, "target": target, "read_only": readonly}
    return {
        "name": project,
        "volumes": {n: {"name": f"{project}_{n}"} for n in
                    ("database", "runner-state", "proxy-data", "proxy-config")},
        "services": {
            "db": {"volumes": [mount("volume", "database", "/var/lib/postgresql")]},
            "runner": {"volumes": [mount("volume", "runner-state", "/home/runner/.vardrmap"),
                                    mount("bind", str(root / "trust"), "/trust", True)]},
            "proxy": {"volumes": [mount("bind", str(root / "Caddyfile"), "/etc/caddy/Caddyfile", True),
                                   mount("volume", "proxy-data", "/data"),
                                   mount("volume", "proxy-config", "/config")]},
            "api": {}, "web": {},
        },
    }


class ProjectResolutionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name, value in (("ROOT", self.root),):
            p = patch.object(vardrsec, name, value); p.start(); self.addCleanup(p.stop)
        p = patch.dict(vardrsec.os.environ, {}, clear=True); p.start(); self.addCleanup(p.stop)

    def reply(self, value):
        return subprocess.CompletedProcess([], 0, stdout=json.dumps(value), stderr="")

    def test_dotenv_project_and_process_override_use_compose_result(self):
        (self.root / ".env").write_text("COMPOSE_PROJECT_NAME=recovered\nPOSTGRES_PASSWORD=synthetic-secret\n")
        original = (self.root / ".env").read_bytes()
        for override, selected in ((None, "recovered"), ("override", "override")):
            env = {} if override is None else {"COMPOSE_PROJECT_NAME": override}
            with patch.dict(vardrsec.os.environ, env, clear=True), patch.object(
                vardrsec.subprocess, "run", side_effect=[self.reply(model(self.root, selected)),
                subprocess.CompletedProcess([], 0, stdout=f"{selected}_runner-state\n")]
            ) as run:
                self.assertTrue(vardrsec.has_installation_data())
                args = run.call_args_list[0].args[0]
                self.assertNotIn("--no-interpolate", args)
                self.assertIn("--profile", args)
                self.assertNotIn("--env-file", args)
                self.assertNotIn("-p", args)
                self.assertEqual(run.call_args_list[0].kwargs["cwd"], self.root)
                self.assertEqual(run.call_args_list[0].kwargs["timeout"], 30)
        self.assertEqual(original, (self.root / ".env").read_bytes())

    def test_existing_config_missing_secrets_refuses_without_configure_or_inventory(self):
        (self.root / ".env").write_text("# incomplete synthetic configuration\n")
        with patch.object(vardrsec.subprocess, "run", return_value=
             subprocess.CompletedProcess([], 1, stdout="", stderr="POSTGRES_PASSWORD required")
        ) as run, patch.object(vardrsec, "configure") as configure:
            with self.assertRaisesRegex(ValueError, "installation refused"):
                vardrsec.dispatch(argparse.Namespace(action="install"), argparse.ArgumentParser())
            self.assertEqual(run.call_count, 1)
            configure.assert_not_called()
            self.assertIsNone(run.call_args.kwargs["env"])
            self.assertNotIn("--no-interpolate", run.call_args.args[0])
        self.assertEqual([p.name for p in self.root.iterdir()], [".env"])

    def test_retained_proxy_state_prevents_install_and_preserves_configuration(self):
        original = b"COMPOSE_PROJECT_NAME=recovered\nPOSTGRES_PASSWORD=synthetic-secret\n"
        (self.root / ".env").write_bytes(original)
        dispatch = vardrsec.dispatch
        for volume in ("proxy-data", "proxy-config"):
            steps = []
            def route(args, parser):
                if args.action == "install":
                    return dispatch(args, parser)
                steps.append(args.action)
            with self.subTest(volume=volume), patch.object(
                vardrsec, "dispatch", side_effect=route
            ), patch.object(vardrsec.subprocess, "run", side_effect=[
                self.reply(model(self.root)),
                subprocess.CompletedProcess([], 0, stdout=f"recovered_{volume}\n"),
            ]), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    vardrsec.dispatch(argparse.Namespace(action="install"), argparse.ArgumentParser())
            self.assertEqual(steps, [])
            self.assertEqual((self.root / ".env").read_bytes(), original)

    def test_shipped_port_expression_uses_normal_interpolation(self):
        # Protocol fixture from the reviewed Compose 2.17 source behavior, not a
        # substitute Compose parser or a measured native compatibility test.
        (self.root / "compose.yaml").write_text(
            'ports: ["127.0.0.1:${HTTPS_PORT:-8443}:${HTTPS_PORT:-8443}"]\n'
        )
        response = model(self.root, "vardrsec")
        response["services"]["proxy"]["ports"] = [
            {"host_ip": "127.0.0.1", "published": "8443", "target": 8443}
        ]
        def command(args, **kwargs):
            if "config" in args:
                if "--no-interpolate" in args:
                    return subprocess.CompletedProcess([], 1, stdout="", stderr="invalid port")
                return self.reply(response)
            return subprocess.CompletedProcess([], 0, stdout="")
        with patch.object(vardrsec.subprocess, "run", side_effect=command):
            self.assertFalse(vardrsec.has_installation_data())

    def test_interpolated_project_checks_execution_volume_not_literal_normalization(self):
        (self.root / "compose.yaml").write_text('name: ${STACK}\n')
        (self.root / ".env").write_text('STACK=recovered\n')
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        def command(args, **kwargs):
            if "config" in args:
                # The old no-interpolate loader normalized ${STACK} to stack.
                project = "stack" if "--no-interpolate" in args else "recovered"
                return self.reply(model(self.root, project))
            return subprocess.CompletedProcess([], 0, stdout="recovered_database\n")
        with patch.object(vardrsec.subprocess, "run", side_effect=command), \
             patch.object(vardrsec, "configure") as configure, \
             patch.object(vardrsec, "sources") as sources, \
             contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                vardrsec.dispatch(argparse.Namespace(action="install"), argparse.ArgumentParser())
            configure.assert_not_called()
            sources.assert_not_called()
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_unsupported_or_unresolved_models_refuse_before_inventory(self):
        base = model(self.root)
        variants = [None, {}, {**base, "name": "${PROJECT}"}]
        for field, value in (("name", "custom"), ("external", True), ("driver_opts", {"device": "synthetic"})):
            item = copy.deepcopy(base); item["volumes"]["database"][field] = value; variants.append(item)
        for change in ("bind", "extra", "missing", "unknown-service"):
            item = copy.deepcopy(base)
            if change == "bind": item["services"]["db"]["volumes"][0]["type"] = "bind"
            elif change == "extra": item["services"]["runner"]["volumes"].append({"type": "bind", "source": "synthetic", "target": "/evidence"})
            elif change == "missing": del item["services"]["runner"]
            else: item["services"]["unknown"] = {}
            variants.append(item)
        for item in variants:
            with self.subTest(item=item), patch.object(vardrsec.subprocess, "run", return_value=self.reply(item)) as run:
                with self.assertRaisesRegex(ValueError, "^Cannot resolve supported installation state mappings; installation refused$"):
                    vardrsec.has_installation_data()
                self.assertEqual(run.call_count, 1)

    def test_errors_never_expose_output_or_enter_install_steps(self):
        (self.root / ".env").write_text("# synthetic existing config\n")
        secret = "synthetic-private-value"
        for reply in (subprocess.CompletedProcess([], 1, stdout=secret, stderr=secret),
                      subprocess.CompletedProcess([], 0, stdout=secret),
                      OSError(secret), subprocess.TimeoutExpired("compose", 30, output=secret)):
            with patch.object(vardrsec.subprocess, "run", side_effect=reply if isinstance(reply, Exception) else None,
                              return_value=reply), patch.object(vardrsec, "configure") as configure, \
                 patch.object(vardrsec, "sources") as sources, contextlib.redirect_stdout(io.StringIO()) as out, \
                 contextlib.redirect_stderr(io.StringIO()) as err:
                with self.assertRaises(ValueError) as caught:
                    vardrsec.dispatch(argparse.Namespace(action="install"), argparse.ArgumentParser())
                self.assertNotIn(secret, str(caught.exception) + out.getvalue() + err.getvalue())
                configure.assert_not_called(); sources.assert_not_called()

    def test_supported_resume_preserves_config_and_skips_configure(self):
        original = "COMPOSE_PROJECT_NAME=recovered\nPOSTGRES_PASSWORD=synthetic-secret\n"
        (self.root / ".env").write_text(original)
        resolved = model(self.root)
        resolved["services"]["db"]["environment"] = {"POSTGRES_PASSWORD": "synthetic-secret"}
        dispatch = vardrsec.dispatch
        steps = []
        def route(args, parser):
            if args.action == "install": return dispatch(args, parser)
            steps.append(args.action)
        with patch.object(vardrsec, "dispatch", side_effect=route), patch.object(
            vardrsec.subprocess, "run", side_effect=[self.reply(resolved), subprocess.CompletedProcess([], 0, stdout="")]
        ), patch.object(vardrsec, "select_full_installation"), contextlib.redirect_stdout(io.StringIO()) as output:
            vardrsec.dispatch(argparse.Namespace(action="install"), argparse.ArgumentParser())
        self.assertNotIn("synthetic-secret", output.getvalue())
        self.assertEqual(steps, [x for x in vardrsec.INSTALL_STEPS if x != "configure"])
        self.assertEqual((self.root / ".env").read_text(), original)
