"""The exposure finding must fail closed when its configuration assumptions change."""

import copy
import unittest

from proxy_jwk_boundary import validate


class ProxyJWKBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "admin": {"disabled": True},
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "routes": [
                                {
                                    "handle": [
                                        {
                                            "handler": "subroute",
                                            "routes": [
                                                {
                                                    "handle": [
                                                        {
                                                            "handler": "rewrite",
                                                            "strip_path_prefix": "/backend",
                                                        },
                                                        {
                                                            "handler": "reverse_proxy",
                                                            "upstreams": [
                                                                {"dial": "api:8000"}
                                                            ],
                                                        },
                                                    ]
                                                }
                                            ],
                                        },
                                        {
                                            "handler": "reverse_proxy",
                                            "upstreams": [{"dial": "web:3000"}],
                                        },
                                    ]
                                }
                            ]
                        }
                    }
                },
                "pki": {"certificate_authorities": {"local": {"install_trust": False}}},
                "tls": {
                    "automation": {"policies": [{"issuers": [{"module": "internal"}]}]}
                },
            },
        }

    def test_forwarding_only_configuration_is_accepted_without_mutation(self):
        before = copy.deepcopy(self.config)
        validate(self.config)
        self.assertEqual(self.config, before)

    def test_nested_acme_server_and_other_unreviewed_handlers_are_rejected(self):
        for handler in ("acme_server", "authentication", "static_response"):
            with self.subTest(handler=handler):
                config = copy.deepcopy(self.config)
                config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0][
                    "routes"
                ][0]["handle"].append({"handler": handler})
                with self.assertRaisesRegex(ValueError, "Unreviewed HTTP handler"):
                    validate(config)

    def test_admin_api_must_be_explicitly_disabled(self):
        for admin in ({}, {"disabled": False}):
            with self.subTest(admin=admin):
                self.config["admin"] = admin
                with self.assertRaisesRegex(ValueError, "admin API disabled"):
                    validate(self.config)

    def test_unreviewed_apps_and_upstreams_require_new_review(self):
        changed = copy.deepcopy(self.config)
        changed["apps"]["custom"] = {}
        with self.assertRaisesRegex(ValueError, "applications"):
            validate(changed)
        self.config["apps"]["http"] = {
            "servers": {
                "srv0": {
                    "routes": [
                        {
                            "handle": [
                                {
                                    "handler": "reverse_proxy",
                                    "upstreams": [{"dial": "unreviewed:8000"}],
                                }
                            ]
                        }
                    ]
                }
            }
        }
        with self.assertRaisesRegex(ValueError, "upstreams"):
            validate(self.config)

    def test_noninternal_or_missing_issuers_require_new_review(self):
        for policies in (
            [],
            [{"issuers": [{"module": "acme"}]}],
            [{"issuers": [{"module": "internal"}, {"module": "acme"}]}],
        ):
            with self.subTest(policies=policies):
                self.config["apps"]["tls"]["automation"]["policies"] = policies
                with self.assertRaisesRegex(ValueError, "internal TLS"):
                    validate(self.config)

    def test_fixture_can_never_install_trust(self):
        self.config["apps"]["pki"]["certificate_authorities"]["local"][
            "install_trust"
        ] = True
        with self.assertRaisesRegex(ValueError, "never install host trust"):
            validate(self.config)

    def test_additional_ca_cannot_bypass_the_host_trust_guard(self):
        self.config["apps"]["pki"]["certificate_authorities"]["other"] = {}
        with self.assertRaisesRegex(ValueError, "never install host trust"):
            validate(self.config)

    def test_operator_ca_keys_are_never_loaded_by_the_fixture(self):
        self.config["apps"]["pki"]["certificate_authorities"]["local"]["root"] = {
            "certificate": "operator.pem"
        }
        with self.assertRaisesRegex(ValueError, "operator CA keys"):
            validate(self.config)

    def test_unreviewed_certificate_loaders_are_rejected(self):
        self.config["apps"]["tls"]["certificates"] = {"load_files": []}
        with self.assertRaisesRegex(ValueError, "certificate loaders"):
            validate(self.config)

    def test_an_empty_http_graph_is_not_evidence(self):
        self.config["apps"]["http"] = {}
        with self.assertRaisesRegex(ValueError, "HTTP handler"):
            validate(self.config)


if __name__ == "__main__":
    unittest.main()
