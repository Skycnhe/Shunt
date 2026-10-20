"""v8.4.1：v8.4.0 订阅节点勾选 / 删除的修复——不能删光一个订阅的节点（mihomo provider 解析失败）、部分恢复时现有自定义组的
订阅节点引用跟着改名、前端按值（而不是按会过期的序号）勾选订阅节点 / 恢复已删节点、节点页订阅快照；names_rx 只产生 regexp2 合法的转义"""
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import unittest
from unittest import mock

from tests.helper import server
from tests.test_v1012 import ApiCase
from tests.test_v840 import PN, SPACED, base, cg

assert server

G = sys.modules["shunt.groups"]
WA = sys.modules["shunt.webapi"]
B = sys.modules["shunt.base"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class VersionTest(unittest.TestCase):
    def test_version(self):
        self.assertEqual(B.PANEL_VERSION, "8.4.1")


class RemoveAllGuardTest(ApiCase):
    def setUp(self):
        super().setUp()
        server.save(base())
        self.p = [mock.patch.object(WA, "reload_core", return_value=(True, "ok")), mock.patch.object(WA, "refresh_later"),
                  mock.patch.object(G, "provider_nodes", return_value=copy.deepcopy(PN))]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()
        super().tearDown()

    def removed(self, name):
        return next(s for s in server.load()["subs"] if s["name"] == name).get("removed")

    def test_cannot_remove_every_node(self):
        code, j = self.call("POST", "/api/subs/nodes/remove", {"items": [{"sub": "B", "name": "TW 01"}, {"sub": "B", "name": SPACED}]})
        self.assertEqual(code, 400, j)
        self.assertIn("全部节点", j["message"])
        self.assertIsNone(self.removed("B"))
        WA.reload_core.assert_not_called()

    def test_last_remaining_node_counts_already_removed(self):
        code, j = self.call("POST", "/api/subs/nodes/remove", {"items": [{"sub": "B", "name": "TW 01"}]})
        self.assertEqual(code, 200, j)
        code, j = self.call("POST", "/api/subs/nodes/remove", {"items": [{"sub": "B", "name": SPACED}]})
        self.assertEqual(code, 400, j)
        self.assertEqual(self.removed("B"), ["TW 01"])

    def test_unknown_sub_not_blocked(self):
        with mock.patch.object(G, "provider_nodes", return_value={"A": PN["A"]}):  # B 的节点还没加载：无从判断，照常删除
            code, j = self.call("POST", "/api/subs/nodes/remove", {"items": [{"sub": "B", "name": "TW 01"}]})
        self.assertEqual(code, 200, j)


class RestoreRenameExistingGroupsTest(ApiCase):
    def test_partial_restore_renames_existing_refs(self):
        d = base(groups=[cg(sub_nodes=[("机场_A", "b2")])])
        d["subs"] = [{"name": "机场_A", "url": "https://b.example/s", "filter": "", "exclude": ""}]
        server.save(d)
        subs = [{"name": "机场 A", "url": "https://a.example/s", "filter": "", "exclude": ""},
                {"name": "机场_A", "url": "https://b.example/s", "filter": "", "exclude": ""}]
        with mock.patch.object(WA, "reload_core", return_value=(True, "ok")), mock.patch.object(WA, "tp_apply"), \
                mock.patch.object(WA, "ab_compose"):
            code, j = self.call("POST", "/api/restore", {"subs": subs})
        self.assertEqual(code, 200, j)
        d = server.load()
        self.assertEqual([s["name"] for s in d["subs"]], ["机场 A", "机场_A_2"])
        self.assertEqual(d["custom_groups"][0]["sub_nodes"], [{"sub": "机场_A_2", "name": "b2"}])


class NamesRxRegexp2Test(unittest.TestCase):
    """mihomo 的 filter / exclude-filter 用 dlclark/regexp2（RegexOptions.None）：反斜杠后跟单词字符且不是已知转义会报错。
    names_rx 只能产生「反斜杠 + 非单词字符」或 \\x60"""
    def test_only_safe_escapes(self):
        names = ["a b#c-d&e~f", "🇭🇰 香港 [01] (IEPL) | x.y+z*?^$", "US`03", "tab\there", "back\\slash`", "中文_节点"]
        pat = G.names_rx(names)
        for m in re.finditer(r"\\(.)", pat, re.S):
            ch = m.group(1)
            ok = ch == "x" and pat[m.end():m.end() + 2] == "60" or not (ch.isalnum() or ch == "_")
            self.assertTrue(ok, (ch, pat))
        self.assertNotIn("`", pat)
        r = re.compile(pat)
        for n in names:
            self.assertTrue(r.fullmatch(n), n)
        self.assertIsNone(r.search("a b#c-d&e~fX"))


class FrontendTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, "index.html"), encoding="utf-8") as f:
            self.html = f.read()

    def test_no_index_handlers(self):
        self.assertNotIn("restoreNodes(${i}", self.html)
        self.assertNotIn("cgSTog(${si}", self.html)
        self.assertNotIn("cgSAll(${si}", self.html)
        self.assertIn("$('#sn-list').innerHTML=SNS.map(", self.html)
        self.assertIn("const s=SNS[si]", self.html)
        self.assertIn("if(CGF)renderCGSChosen()", self.html)

    @unittest.skipUnless(shutil.which("node"), "需要 node")
    def test_value_based_handlers(self):
        out = subprocess.run(["node", os.path.join(ROOT, "tests", "v841_frontend.js"), ROOT], capture_output=True, text=True, timeout=30)
        self.assertFalse(out.stdout.startswith("ERR"), out.stdout + out.stderr)
        j = json.loads(out.stdout)
        odd = "HK \"01\" <b>'x'</b> & y"
        self.assertEqual(j["chips"], [["A", "n1"], ["A", odd]])
        self.assertEqual(j["after_tog"], [{"sub": "A", "name": "gone"}, {"sub": "A", "name": odd}])
        self.assertEqual(j["after_clear"], 0)  # 「取消全部」连同已失效的勾选一起去掉
        self.assertEqual(j["btns"], ["x", "y"])
        self.assertEqual(j["calls"], [{"sub": "S", "names": ["y"]}, {"sub": "S", "all": True}])


if __name__ == "__main__":
    unittest.main()
