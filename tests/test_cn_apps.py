"""内置国内 App 直连名单 cn-apps：mihomo / sing-box 规则与 DNS 都要带上"""
import unittest

from tests.helper import server


class TestCnApps(unittest.TestCase):
    def setUp(self):
        self.d = server.load()

    def test_list(self):
        doms = server.CN_APP_DOMAINS
        self.assertIn("+.snssdk.com", doms)  # 字节系 API，不在 geosite-cn 里
        self.assertIn("+.alipay.com", doms)
        self.assertEqual(len(doms), len(set(doms)))
        self.assertTrue(all(d.startswith("+.") and " " not in d for d in doms))

    def test_mihomo(self):
        c = server.build_config(self.d)
        self.assertEqual(c["rule-providers"]["cn-apps"]["type"], "inline")
        rules = c["rules"]
        i = rules.index("RULE-SET,cn-apps,DIRECT")
        self.assertLess(i, next(k for k, r in enumerate(rules) if "geolocation-!cn" in r))
        self.assertLess(i, next(k for k, r in enumerate(rules) if "category-ai-!cn" in r))

    def test_singbox(self):
        conf, warn, need = server.build_singbox(self.d)
        rules = conf["route"]["rules"]
        self.assertTrue(any(r.get("rule_set") == ["cn-apps"] and r.get("outbound") == "DIRECT" for r in rules))
        self.assertTrue(any(x["tag"] == "cn-apps" and x["type"] == "inline" for x in conf["route"]["rule_set"]))
        for r in rules:
            if r.get("action") == "resolve" and r.get("server"):
                self.assertEqual(r.get("client_subnet"), server.CN_ECS)


if __name__ == "__main__":
    unittest.main()
