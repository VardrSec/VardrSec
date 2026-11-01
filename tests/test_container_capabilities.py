"""Offline coverage for the container privilege-posture probe (register decision R1).

No Docker is required. Run: python -m unittest discover -s tests -p 'test_container_capabilities.py'
"""

import copy
import unittest

import container_capabilities_acceptance as probe

STATUS = """Name:\tpostgres
Uid:\t999\t999\t999\t999
CapInh:\t0000000000000000
CapPrm:\t0000000000000000
CapEff:\t0000000000000000
CapBnd:\t00000000a80425fb
NoNewPrivs:\t0
"""


def service(drop, add, effective=0, bounding=0, no_new=True, ports=()):
    return {
        "privileged": False,
        "cap_add": list(add),
        "cap_drop": list(drop),
        "no_new_privileges_configured": no_new,
        "pid_mode": "",
        "docker_socket_mounted": False,
        "published_ports": list(ports),
        "uid": 10001,
        "cap_effective": effective,
        "cap_bounding": bounding,
        "no_new_privileges": no_new,
    }


def good():
    bind = probe.BIND
    return {
        "api": service(["ALL"], []),
        "web": service(["ALL"], []),
        "proxy": service(["ALL"], ["NET_BIND_SERVICE"], bind, bind, ports=["127.0.0.1:8443"]),
        # Docker's default bounding set: no forbidden capability, unprivileged process.
        "db": service([], [], 0, 0xA80425FB, no_new=False),
        "runner": {"uid": 10001, "cap_effective": 0, "cap_bounding": 0, "no_new_privileges": True},
    }


class Parsing(unittest.TestCase):
    def test_status_fields(self):
        status = probe.parse_status(STATUS)
        self.assertEqual(status["uid"], 999)
        self.assertEqual(status["cap_effective"], 0)
        self.assertEqual(status["cap_bounding"], 0xA80425FB)
        self.assertFalse(status["no_new_privileges"])

    def test_named_capabilities(self):
        self.assertEqual(probe.held(probe.BIND), ["NET_BIND_SERVICE"])
        self.assertEqual(probe.held(1 << 21), ["SYS_ADMIN"])
        self.assertEqual(probe.held(0), [])

    def test_docker_default_set_holds_no_forbidden_capability(self):
        self.assertFalse(set(probe.held(0xA80425FB)) & set(probe.FORBIDDEN))

    def test_cap_prefix_is_ignored(self):
        self.assertEqual(probe.names(["CAP_NET_BIND_SERVICE", "ALL"]), ["ALL", "NET_BIND_SERVICE"])


class Expectations(unittest.TestCase):
    def test_the_documented_posture_passes(self):
        self.assertEqual(probe.check(good()), [])

    def failing(self, mutate):
        seen = copy.deepcopy(good())
        mutate(seen)
        return probe.check(seen)

    def test_privileged_container_fails(self):
        self.assertTrue(self.failing(lambda s: s["db"].update(privileged=True)))

    def test_docker_socket_fails(self):
        self.assertTrue(self.failing(lambda s: s["api"].update(docker_socket_mounted=True)))

    def test_forbidden_bounding_capability_fails(self):
        failures = self.failing(lambda s: s["db"].update(cap_bounding=0xA80425FB | 1 << 21))
        self.assertTrue(any("SYS_ADMIN" in line for line in failures))

    def test_extra_added_capability_fails(self):
        self.assertTrue(self.failing(lambda s: s["web"].update(cap_add=["NET_RAW"])))

    def test_missing_drop_all_fails(self):
        self.assertTrue(self.failing(lambda s: s["api"].update(cap_drop=[])))

    def test_missing_no_new_privileges_fails(self):
        self.assertTrue(self.failing(lambda s: s["proxy"].update(no_new_privileges=False)))

    def test_proxy_may_not_exceed_the_bind_capability(self):
        self.assertTrue(self.failing(lambda s: s["proxy"].update(cap_effective=probe.BIND | 1)))

    def test_published_ports_must_be_loopback_and_proxy_only(self):
        self.assertTrue(self.failing(lambda s: s["proxy"].update(published_ports=["0.0.0.0:8443"])))
        self.assertTrue(self.failing(lambda s: s["db"].update(published_ports=["127.0.0.1:5432"])))

    def test_runner_with_capabilities_fails(self):
        self.assertTrue(self.failing(lambda s: s["runner"].update(cap_effective=1)))


if __name__ == "__main__":
    unittest.main()
