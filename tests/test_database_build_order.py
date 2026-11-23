import argparse
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, call, patch

import vardrsec

class BuildOrdering(unittest.TestCase):
    def test_full_database_before_parallel_images(self):
        env={'example':'unchanged'}
        with patch.object(vardrsec,'compose') as compose:
            vardrsec.build_images(mapless=False,environment=env)
        self.assertEqual(compose.call_args_list,[call('--profile','tools','build','db',env=env),call('--profile','tools','build',env=env)])

    def test_mapless_does_not_build_database(self):
        with patch.object(vardrsec,'compose') as compose:
            vardrsec.build_images(mapless=True,environment={})
        compose.assert_called_once_with('--profile','tools','build',env={})

    def test_failed_database_stops_remaining_builds(self):
        with patch.object(vardrsec,'compose',side_effect=RuntimeError('db failure')) as compose:
            with self.assertRaises(RuntimeError):vardrsec.build_images(mapless=False,environment={})
        self.assertEqual(compose.call_count,1)


class VerifiedDatabaseBuildTests(unittest.TestCase):
    receipt = {"VARDRSEC_DATABASE_RECEIPT": "qualified.json"}
    image_id = "sha256:" + "a" * 64

    def test_missing_receipt_fails_before_writing_configuration_or_fetching_sources(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(vardrsec, "ROOT", Path(tmp)), \
                patch.dict(vardrsec.os.environ, self.receipt), \
                patch.object(vardrsec, "require_standard_fresh_layout"), \
                patch.object(vardrsec, "require_command"), patch.object(vardrsec, "build_prerequisites"), \
                patch.object(vardrsec, "configuration_values", return_value={}), \
                patch.object(vardrsec, "has_installation_data", return_value=False):
            with self.assertRaises(FileNotFoundError):
                vardrsec.dispatch(argparse.Namespace(action="install"), None)
            self.assertFalse((Path(tmp) / ".env").exists())
            self.assertFalse((Path(tmp) / ".sources").exists())

    def test_qualified_image_builds_only_the_other_services(self):
        model = {"services": dict.fromkeys(("api", "db", "proxy", "runner", "web"), {})}
        with patch.object(vardrsec, "compose") as compose, patch("database_image.select_verified") as select:
            compose.return_value.stdout = json.dumps(model)
            select.return_value = self.image_id
            result = vardrsec.build_images(mapless=False, environment=self.receipt)
        self.assertEqual(result, self.image_id)
        select.assert_called_once_with(vardrsec.ROOT, Path("qualified.json"), model)
        self.assertEqual(compose.call_args_list, [
            call("--profile", "tools", "config", "--format", "json",
                 env=self.receipt, capture_output=True, text=True),
            call("--profile", "tools", "build", "api", "web", "proxy", "runner", env=self.receipt),
        ])

    def test_verification_failure_stops_before_any_build(self):
        model = {"services": dict.fromkeys(("api", "db", "proxy", "runner", "web"), {})}
        with patch.object(vardrsec, "compose") as compose, patch("database_image.select_verified") as select:
            compose.return_value.stdout = json.dumps(model)
            select.side_effect = ValueError("Receipt mismatch")
            with self.assertRaisesRegex(ValueError, "Receipt mismatch"):
                vardrsec.build_images(mapless=False, environment=self.receipt)
        self.assertEqual(compose.call_count, 1)
        self.assertIn("config", compose.call_args.args)

    def test_custom_layout_refuses_explicit_receipt_and_mapless_ignores_it(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(vardrsec, "ROOT", Path(tmp)), \
                patch.object(vardrsec, "compose") as compose, patch("database_image.select_verified") as select:
            (Path(tmp) / "compose.yaml").write_text("services: {}\n")
            with self.assertRaisesRegex(ValueError, "shipped Full Compose"):
                vardrsec.build_images(mapless=False, environment=self.receipt)
            compose.assert_not_called()
            vardrsec.build_images(mapless=True, environment=self.receipt)
            compose.assert_called_once_with("--profile", "tools", "build", env=self.receipt)
            select.assert_not_called()

    def test_retagged_database_cannot_be_frozen(self):
        model = {"name": "test", "services": {
            service: {"image": service + ":local"} for service in ("api", "db", "proxy", "runner", "web")
        }}
        with tempfile.TemporaryDirectory() as tmp, patch.object(vardrsec, "ROOT", Path(tmp)), \
                patch.object(vardrsec, "compose", return_value=Mock(stdout=json.dumps(model))), \
                patch.object(vardrsec, "run", return_value=Mock(stdout="sha256:" + "b" * 64)):
            with self.assertRaisesRegex(ValueError, "changed after receipt verification"):
                vardrsec.select_full_installation(verified_db=self.image_id)
            self.assertFalse((Path(tmp) / ".active-images.json").exists())

    def test_frozen_install_retry_ignores_a_new_receipt(self):
        services = {name: {"image": f"sha256:{i:064x}"}
                    for i, name in enumerate(("api", "db", "proxy", "runner", "web"), 1)}
        frozen_networks = {
            name: {"ipam": {"config": [{"subnet": subnet}]}}
            for name, subnet in (("database", "172.22.1.0/24"), ("runner", "172.22.2.0/24"))
        }
        model = {
            "name": "test", "services": {**services, "proxy": {
                **services["proxy"], "networks": {"application": {"ipv4_address": "172.22.0.2"}},
            }},
            "networks": {"application": {"ipam": {"config": [{
                "subnet": "172.22.0.0/24", "ip_range": "172.22.0.128/25",
            }]}}},
        }
        with tempfile.TemporaryDirectory() as tmp, patch.object(vardrsec, "ROOT", Path(tmp)), \
                patch.dict(vardrsec.os.environ, self.receipt), \
                patch.object(vardrsec, "has_installation_data", return_value=False), \
                patch.object(vardrsec, "compose", return_value=Mock(stdout=json.dumps(model))), \
                patch.object(vardrsec, "run") as docker, \
                patch("database_image.select_verified") as select, patch("builtins.print"):
            root = Path(tmp)
            (root / ".env").write_text("retained")
            record = json.dumps({"services": services, "networks": frozen_networks})
            (root / ".active-images.json").write_text(record)
            dispatch = vardrsec.dispatch
            with patch.object(vardrsec, "dispatch", return_value=None) as step:
                dispatch(argparse.Namespace(action="install"), None)
            self.assertNotIn("build", [args.args[0].action for args in step.call_args_list])
            select.assert_not_called()
            self.assertEqual(docker.call_args_list, [
                call("docker", "image", "inspect", service["image"], capture_output=True)
                for service in services.values()
            ])
            self.assertEqual((root / ".active-images.json").read_text(), record)

    def test_frozen_start_disables_builds_and_pulls(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(vardrsec, "ROOT", Path(tmp)), \
                patch.object(vardrsec, "compose") as compose, patch("builtins.print"):
            for frozen in (False, True):
                with self.subTest(frozen=frozen):
                    if frozen:
                        (Path(tmp) / ".active-images.json").write_text("{}")
                    vardrsec.dispatch(argparse.Namespace(action="start"), None)
                    flags = ("--no-build", "--pull", "never") if frozen else ()
                    compose.assert_called_with("up", "-d", *flags, "--wait", "--wait-timeout", "180",
                                               "db", "api", "web", "proxy")
