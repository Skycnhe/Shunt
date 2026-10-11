import copy, unittest
from tests.helper import server


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self.d = copy.deepcopy(server.load())

    def test_mihomo_basics(self):
        c = server.build_config(self.d)
        self.assertTrue(c["rules"][-1].startswith("MATCH,"))
        self.assertEqual(c["dns"]["listen"], "0.0.0.0:1053")
        self.assertFalse(c["tun"]["enable"])
        names = {g["name"] for g in c["proxy-groups"]}
        for r in c["rules"]:
            pol = r.split(",")[server.rule_policy_index(r.split(","))]
            self.assertTrue(pol in names or pol in server.BUILTIN_POLICIES, r)

    def test_tun_and_ipv6(self):
        self.d.update(proxy_mode="tun", ipv6=True)
        c = server.build_config(self.d)
        self.assertTrue(c["tun"]["enable"])
        self.assertEqual(c["dns"]["listen"], "[::]:1053")

    def test_singbox_has_direct_and_final(self):
        conf, warn, need = server.build_singbox(self.d)
        tags = {o["tag"] for o in conf["outbounds"]}
        self.assertIn("DIRECT", tags)
        self.assertIn(conf["route"]["final"], tags)

    def test_no_password_fields(self):
        self.assertFalse({"password", "pw_hash", "pw_default"} & set(server.load()))


if __name__ == "__main__":
    unittest.main()
