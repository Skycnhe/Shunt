"""v8.4.3：自定义规则不写目标策略时自动补「🚀 节点选择」，不再把值当成策略名"""
import os
import sys
import unittest
from unittest import mock

from tests.helper import server
from tests.test_v1012 import ApiCase
from tests.test_v840 import base

assert server

B = sys.modules["shunt.base"]
RU = sys.modules["shunt.ruleutil"]
MH = sys.modules["shunt.mihomo"]
SBC = sys.modules["shunt.sb_config"]
WA = sys.modules["shunt.webapi"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEL = B.G_SEL


class VersionTest(unittest.TestCase):
    def test_version(self):
        self.assertEqual(B.PANEL_VERSION, "8.4.3")

    def test_changelog_top(self):
        with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as f:
            heads = [ln for ln in f if ln.startswith("## v")]
        self.assertTrue(heads[0].startswith("## v8.4.3"), heads[0])


class CompleteRuleTest(unittest.TestCase):
    def test_adds_default(self):
        c = RU.complete_rule
        self.assertEqual(c("DOMAIN-KEYWORD,nowtv100", SEL), f"DOMAIN-KEYWORD,nowtv100,{SEL}")
        self.assertEqual(c("domain-suffix,mytvsuper.com", SEL), f"domain-suffix,mytvsuper.com,{SEL}")
        self.assertEqual(c("IP-CIDR,1.2.3.4/32,no-resolve", SEL), f"IP-CIDR,1.2.3.4/32,{SEL},no-resolve")
        self.assertEqual(c("IP-CIDR,1.2.3.4/32", SEL), f"IP-CIDR,1.2.3.4/32,{SEL}")

    def test_keeps_complete_and_special(self):
        c = RU.complete_rule
        for r in ("DOMAIN-SUFFIX,a.com,DIRECT", "IP-CIDR,1.2.3.4/32,REJECT,no-resolve", "MATCH,DIRECT",
                  "AND,((DOMAIN,a.com),(NETWORK,udp)),REJECT", "# DOMAIN,a.com", "", "DOMAIN-SUFFIX,", "FOO,bar"):
            self.assertEqual(c(r, SEL), r)


class ConfigTest(unittest.TestCase):
    """data.json 里已有不带策略的规则（备份恢复 / 手改）：两种内核都按 节点选择 生成，值不丢"""

    def test_mihomo(self):
        d = base()
        d["rules"] = ["DOMAIN-SUFFIX,mytvsuper.com", "IP-CIDR,46.38.157.60/32,no-resolve"]
        rules = MH.build_config(d)["rules"]
        self.assertIn(f"DOMAIN-SUFFIX,mytvsuper.com,{SEL}", rules)
        self.assertIn(f"IP-CIDR,46.38.157.60/32,{SEL},no-resolve", rules)
        self.assertFalse([r for r in rules if r.startswith(f"DOMAIN-SUFFIX,{SEL}")])

    def test_singbox(self):
        d = base(core="singbox")
        d["rules"] = ["DOMAIN-SUFFIX,mytvsuper.com", "DOMAIN-KEYWORD,rthklive"]
        cfg = SBC.build_singbox(d)[0]
        rr = cfg["route"]["rules"]
        self.assertTrue(any(".mytvsuper.com" in (r.get("domain_suffix") or []) or "mytvsuper.com" in (r.get("domain_suffix") or [])
                            for r in rr), rr)
        self.assertTrue(any("rthklive" in (r.get("domain_keyword") or []) and r.get("outbound") == SEL for r in rr), rr)


class RulesApiTest(ApiCase):
    def test_put_without_policy_saved_completed(self):
        server.save(base())
        with mock.patch.object(WA, "reload_core", return_value=(True, "ok")):
            code, j = self.call("PUT", "/api/rules", {"rules": ["DOMAIN-KEYWORD,852851", "IP-CIDR,89.187.179.148/32,no-resolve",
                                                                "DOMAIN-SUFFIX,a.com,DIRECT"]})
        self.assertEqual(code, 200, j)
        self.assertEqual(server.load()["rules"], [f"DOMAIN-KEYWORD,852851,{SEL}", f"IP-CIDR,89.187.179.148/32,{SEL},no-resolve",
                                                  "DOMAIN-SUFFIX,a.com,DIRECT"])

    def test_put_bad_policy_still_400(self):
        server.save(base())
        with mock.patch.object(WA, "reload_core", return_value=(True, "ok")):
            code, j = self.call("PUT", "/api/rules", {"rules": ["DOMAIN-SUFFIX,a.com,不存在的组"]})
        self.assertEqual(code, 400, j)


if __name__ == "__main__":
    unittest.main()
