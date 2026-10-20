"""v8.4.4：嗅探跳过米家 / Apple 推送、自定义组容差留空跟随全局、group_sig 比较 use"""
import os
import sys
import unittest

from tests.helper import server
from tests.test_v840 import base, cg

assert server

B = sys.modules["shunt.base"]
G = sys.modules["shunt.groups"]
MH = sys.modules["shunt.mihomo"]
CO = sys.modules["shunt.core"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class VersionTest(unittest.TestCase):
    def test_version(self):
        self.assertEqual(B.PANEL_VERSION, "8.4.4")

    def test_changelog_top(self):
        with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as f:
            heads = [ln for ln in f if ln.startswith("## v")]
        self.assertTrue(heads[0].startswith("## v8.4.4"), heads[0])


class SnifferSkipTest(unittest.TestCase):
    def test_skip_domain(self):
        sk = MH.build_config(base())["sniffer"]["skip-domain"]
        self.assertIn("Mijia Cloud", sk)
        self.assertIn("+.push.apple.com", sk)


class ToleranceTest(unittest.TestCase):
    def clean(self, tol):
        return G.clean_custom_group({"name": "T", "type": "url-test", "proxies": ["DIRECT"], "tolerance": tol})

    def test_blank_is_none(self):
        self.assertIsNone(self.clean("")["tolerance"])
        self.assertIsNone(self.clean(None)["tolerance"])
        self.assertEqual(self.clean(0)["tolerance"], 0)
        self.assertEqual(self.clean(80)["tolerance"], 80)
        with self.assertRaises(ValueError):
            self.clean(5000)

    def test_none_follows_global(self):
        gc = dict(G.gcfg(base()), tolerance=50)
        self.assertEqual(G.group_opts("url-test", gc, {"tolerance": None})["tolerance"], 50)
        self.assertEqual(G.group_opts("url-test", gc, {"tolerance": 0})["tolerance"], 0)

    def test_config(self):
        d = base()
        d["groups_cfg"] = dict(d.get("groups_cfg") or {}, tolerance=60)
        g = dict(cg("🎯 测速", "url-test", proxies=["M1"]), tolerance=None, interval=0)
        d["custom_groups"] = [g]
        grp = next(x for x in MH.build_config(d)["proxy-groups"] if x["name"] == "🎯 测速")
        self.assertEqual(grp["tolerance"], 60)


class GroupSigTest(unittest.TestCase):
    def test_use_compared(self):
        a = {"proxy-groups": [{"name": "x", "type": "select", "use": ["A"], "proxies": ["M1"]}]}
        b = {"proxy-groups": [{"name": "x", "type": "select", "use": ["A", "B"], "proxies": ["M1"]}]}
        self.assertNotEqual(CO.group_sig(a), CO.group_sig(b))


if __name__ == "__main__":
    unittest.main()
