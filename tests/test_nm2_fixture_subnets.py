"""Pure fixture subnet selection and overlay proofs; no runtime acceptance."""

import copy
import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

import nm2_worker_acceptance as acceptance


def cohort():
    root = Path.home() / "synthetic-fixture"
    return {
        "schema": "vardr.nm2-worker-cohort/1",
        "sources": {
            name: {"path": str(root / "sources" / name), "commit": "a" * 40}
            for name in acceptance.SOURCE_NAMES
        },
        "images": {name: "sha256:" + "b" * 64 for name in acceptance.IMAGE_NAMES},
        "docker_context": "desktop-linux",
        "project": "vardrsec-nm2-12345678",
        "installation": str(root / "installation"),
        "private_root": str(root / "custody"),
        "https_port": 28443,
        "application_subnet": "172.29.217.0/24",
        "allow_empty_builtin_bridge_id_change": False,
    }


def pair():
    return {"database": "10.230.1.0/24", "runner": "192.168.254.0/24"}


class FixtureSubnets(unittest.TestCase):
    def fixture(self, selection):
        fixture = object.__new__(acceptance.Fixture)
        fixture.m = selection
        fixture.install = MagicMock(spec=Path)
        fixture.overlay = {
            "services": {
                name: {"image": "sha256:" + "b" * 64, "profiles": [name]}
                for name in ("db", "api", "web", "proxy", "runner", "managed-worker")
            },
            "networks": {
                "database": {"internal": True},
                "application": {
                    "internal": True,
                    "ipam": {
                        "config": [
                            {
                                "subnet": selection["application_subnet"],
                                "ip_range": "172.29.217.128/25",
                            }
                        ]
                    },
                },
                "runner": {"attachable": False},
            },
        }
        return fixture

    def written(self, fixture):
        target = fixture.install.__truediv__.return_value
        fixture.install.__truediv__.assert_called_once_with("fixture.compose.json")
        target.write_bytes.assert_called_once()
        return target.write_bytes.call_args.args[0]

    def test_omitted_pair_keeps_exact_legacy_overlay_bytes(self):
        fixture = self.fixture(cohort())
        original = copy.deepcopy(fixture.overlay)
        fixture.write_overlay()
        self.assertEqual(self.written(fixture), acceptance.canonical(original))
        self.assertEqual(fixture.overlay, original)
        self.assertNotIn("fixture_subnets", fixture.m)

    def test_exact_override_adds_only_two_ipam_configs(self):
        selection = {**cohort(), "fixture_subnets": pair()}
        fixture = self.fixture(selection)
        original = copy.deepcopy(fixture.overlay)
        expected = copy.deepcopy(original)
        for name, subnet in pair().items():
            expected["networks"][name]["ipam"] = {"config": [{"subnet": subnet}]}
        fixture.write_overlay()
        self.assertEqual(json.loads(self.written(fixture)), expected)
        self.assertEqual(fixture.overlay["services"], original["services"])
        self.assertEqual(
            fixture.overlay["networks"]["application"],
            original["networks"]["application"],
        )
        self.assertEqual(fixture.m, selection)

    def test_default_overlay_without_network_section_stays_absent(self):
        fixture = self.fixture(cohort())
        del fixture.overlay["networks"]
        original = acceptance.canonical(fixture.overlay)
        fixture.write_overlay()
        self.assertEqual(self.written(fixture), original)
        self.assertNotIn("networks", fixture.overlay)

    def test_override_adds_only_pair_to_normal_service_only_overlay(self):
        fixture = self.fixture({**cohort(), "fixture_subnets": pair()})
        del fixture.overlay["networks"]
        services = copy.deepcopy(fixture.overlay["services"])
        fixture.write_overlay()
        self.assertEqual(
            json.loads(self.written(fixture)),
            {
                "services": services,
                "networks": {
                    name: {"ipam": {"config": [{"subnet": subnet}]}}
                    for name, subnet in pair().items()
                },
            },
        )

    def test_selection_is_additive_and_never_mutates_input(self):
        legacy = cohort()
        self.assertEqual(acceptance.fixture_subnets(legacy), {})
        selected = {**legacy, "fixture_subnets": pair()}
        original = copy.deepcopy(selected)
        self.assertEqual(acceptance.fixture_subnets(selected), pair())
        self.assertEqual(selected, original)
        self.assertIsNot(
            acceptance.fixture_subnets(selected), selected["fixture_subnets"]
        )

    def test_partial_extra_and_wrong_type_pairs_refuse(self):
        for value in (
            None,
            [],
            True,
            {},
            {"database": "10.230.1.0/24"},
            {"runner": "192.168.254.0/24"},
            {**pair(), "application": "10.1.0.0/24"},
            {**pair(), "driver": "bridge"},
            {**pair(), "runner": False},
            {**pair(), "database": 1234},
        ):
            with (
                self.subTest(value=value),
                self.assertRaises(acceptance.AcceptanceRefused),
            ):
                acceptance.fixture_subnets({**cohort(), "fixture_subnets": value})

    def test_only_canonical_rfc1918_ipv4_24s_are_accepted(self):
        invalid = (
            "8.8.8.0/24",
            "127.0.0.0/24",
            "169.254.1.0/24",
            "100.64.1.0/24",
            "198.18.1.0/24",
            "192.0.2.0/24",
            "0.0.0.0/24",
            "224.0.0.0/24",
            "240.0.0.0/24",
            "fd00::/24",
            "10.230.1.1/24",
            "10.230.1.0/25",
            "10.230.1.0/255.255.255.0",
            "10.230.001.0/24",
            "10.230.1.0/24 ",
            "",
        )
        for field in ("application", "database", "runner"):
            for subnet in invalid:
                selected = {**cohort(), "fixture_subnets": pair()}
                if field == "application":
                    selected["application_subnet"] = subnet
                else:
                    selected["fixture_subnets"][field] = subnet
                with (
                    self.subTest(field=field, subnet=subnet),
                    self.assertRaises(acceptance.AcceptanceRefused),
                ):
                    acceptance.fixture_subnets(selected)

    def test_any_pairwise_overlap_refuses_before_overlay_write(self):
        for field, subnet in (
            ("database", "172.29.217.0/24"),
            ("runner", "172.29.217.0/24"),
            ("runner", "10.230.1.0/24"),
        ):
            selected = {**cohort(), "fixture_subnets": {**pair(), field: subnet}}
            fixture = self.fixture(selected)
            with (
                self.subTest(field=field),
                self.assertRaises(acceptance.AcceptanceRefused),
            ):
                fixture.write_overlay()
            fixture.install.__truediv__.assert_not_called()

    def validated(self, value):
        def git_only(arguments, **_kwargs):
            self.assertEqual(arguments[0], "git")
            return b"a" * 40 + b"\n" if "rev-parse" in arguments else b""

        with (
            patch.object(Path, "read_bytes", return_value=json.dumps(value).encode()),
            patch.object(Path, "exists", return_value=False),
            patch.object(Path, "is_symlink", return_value=False),
            patch.object(Path, "is_dir", return_value=True),
            patch.object(Path, "is_file", return_value=True),
            patch.object(acceptance, "command", side_effect=git_only),
        ):
            return acceptance.manifest(Path.home() / "virtual-cohort.json")

    def test_closed_manifest_accepts_only_the_additive_exact_pair(self):
        legacy = self.validated(cohort())
        self.assertNotIn("fixture_subnets", legacy)
        selected = self.validated({**cohort(), "fixture_subnets": pair()})
        self.assertEqual(selected["fixture_subnets"], pair())
        self.assertEqual(selected["application_subnet"], legacy["application_subnet"])
        self.assertEqual(
            (selected["proxy_ip"], selected["application_ip_range"]),
            (legacy["proxy_ip"], legacy["application_ip_range"]),
        )
        for value in (
            {**cohort(), "database_subnet": "10.230.1.0/24"},
            {**cohort(), "fixture_subnets": pair(), "network_driver": "bridge"},
            {**cohort(), "fixture_subnets": {"runner": "10.230.1.0/24"}},
        ):
            with (
                self.subTest(value=value),
                self.assertRaises(acceptance.AcceptanceRefused),
            ):
                self.validated(value)


if __name__ == "__main__":
    unittest.main()
