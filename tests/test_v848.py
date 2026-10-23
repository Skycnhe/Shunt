"""v8.4.8：sing-box 内核下节点健康检查、定时全节点测速把「没轮到测」的节点记成失败；手机端顶栏放大。

真实 sing-box 1.14.3（clash_api）的应答（/workspace/work/sb/results*.txt 实测）：
- /group/{组}/delay 同时只测 10 个节点、整组共用 timeout，应答只列测通的节点：
  失效节点多时可用节点没轮到测，返回 200 {}；混合组返回 200 {"good-direct":40}
- /proxies/{节点}/delay：200 {"delay":39}、超时 504 {"message":"Timeout"}、出错 503、节点不存在 404
mihomo 的整组测速测完全部节点，缺席即失败、全部失败 504，行为不变。
"""
import json
import os
import re
import sys
import unittest
from unittest import mock
from urllib.parse import unquote

from tests.helper import server

assert server

B = sys.modules["shunt.base"]
HM = sys.modules["shunt.health"]
SC = sys.modules["shunt.schedule"]
NP = sys.modules["shunt.nodeprobe"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

GROUP_EMPTY = (200, b"{}\n")                    # 全部超时 / 可用节点没轮到测
GROUP_MIXED = (200, b'{"good-direct":40}\n')    # 只列测通的节点
NODE_OK = (200, b'{"delay":39}\n')
NODE_TIMEOUT = (504, b'{"message":"Timeout"}\n')
NODE_ERROR = (503, b'{"message":"An error occurred in the delay test"}\n')
NOT_FOUND = (404, b'{"message":"Resource not found"}\n')
UNREACHABLE = (502, json.dumps({"message": "mihomo 未运行或无法连接: refused"}).encode())


def fake_core_factory(group, nodes, calls):
    def fake_core(method, path, body=None, timeout=10):
        p = unquote(path)
        calls.append(p)
        if p.startswith("/group/"):
            return group
        return nodes.get(p.split("/")[2].split("?")[0], NOT_FOUND)
    return fake_core


class HealthSingBoxTest(unittest.TestCase):
    def setUp(self):
        self.orig = server.load()
        server.save(dict(self.orig, health={}))

    def tearDown(self):
        server.save(self.orig)

    def run_check(self, core_name, members, group, nodes):
        calls = []
        fc = fake_core_factory(group, nodes, calls)
        with mock.patch.object(HM, "core_json", return_value={"all": list(members)}), mock.patch.object(HM, "core", fc), \
                mock.patch.object(NP, "core", fc), mock.patch.object(HM, "active_core", return_value=core_name):
            ok, msg = HM.run_check()
        return ok, msg, [c for c in calls if c.startswith("/proxies/")]

    def test_singbox_absent_not_failed(self):
        # 整组 {}：逐个补测，n2 实际可用、n1 超时、n3 出错、n4 核心没应答（本轮不记）
        ok, msg, pc = self.run_check("singbox", ["n1", "n2", "n3", "n4", "DIRECT"], GROUP_EMPTY,
                                     {"n1": NODE_TIMEOUT, "n2": NODE_OK, "n3": NODE_ERROR, "n4": UNREACHABLE})
        self.assertTrue(ok, msg)
        h = server.load()["health"]
        self.assertEqual((h["n2"]["fail_days"], h["n2"]["latency"]), (0, 39))
        self.assertEqual((h["n1"]["fail_days"], h["n3"]["fail_days"]), (1, 1))
        self.assertNotIn("n4", h)
        self.assertNotIn("DIRECT", h)
        self.assertIn("1/4", msg)
        self.assertIn("1 个未测出结果", msg)
        self.assertEqual(sorted(c.split("/")[2] for c in pc), ["n1", "n2", "n3", "n4"])
        self.assertFalse(B.MASS_TEST["active"])  # 补测登记已注销

    def test_singbox_present_not_reprobed(self):
        ok, msg, pc = self.run_check("singbox", ["good-direct", "bad-ss"], GROUP_MIXED, {"bad-ss": NODE_TIMEOUT})
        self.assertTrue(ok, msg)
        self.assertEqual([c.split("/")[2] for c in pc], ["bad-ss"])
        h = server.load()["health"]
        self.assertEqual((h["good-direct"]["fail_days"], h["bad-ss"]["fail_days"]), (0, 1))

    def test_singbox_undecided_keeps_old_record(self):
        server.save(dict(server.load(), health={"n1": {"fail_days": 2, "fail_dates": ["2026-01-01", "2026-01-02"], "hidden": False}}))
        ok, msg, _ = self.run_check("singbox", ["n1", "n2"], GROUP_EMPTY, {"n1": UNREACHABLE, "n2": NODE_OK})
        self.assertTrue(ok, msg)
        h = server.load()["health"]
        self.assertEqual(h["n1"]["fail_days"], 2)  # 没有结论：不加一天失败，也不当「已删除节点」清掉
        self.assertEqual(h["n2"]["fail_days"], 0)

    def test_singbox_core_down_records_nothing(self):
        ok, msg, _ = self.run_check("singbox", ["n1", "n2"], GROUP_EMPTY, {"n1": UNREACHABLE, "n2": NOT_FOUND})
        self.assertFalse(ok)
        self.assertEqual(server.load()["health"], {})

    def test_mihomo_unchanged(self):
        ok, msg, pc = self.run_check("mihomo", ["good-direct", "bad-ss"], GROUP_MIXED, {"bad-ss": NODE_OK})
        self.assertTrue(ok, msg)
        self.assertEqual(pc, [])  # mihomo 测完整组：缺席即失败，不补测
        self.assertEqual(server.load()["health"]["bad-ss"]["fail_days"], 1)
        ok, msg, pc = self.run_check("mihomo", ["a"], (504, b'{"message":"get delay: all proxies timeout"}'), {})
        self.assertTrue(ok)
        self.assertEqual(pc, [])


class LatencyTaskTest(unittest.TestCase):
    def run_task(self, core_name, members, group, nodes):
        calls = []
        fc = fake_core_factory(group, nodes, calls)
        pg = {"type": "Selector", "name": B.G_MANUAL, "all": list(members)}
        with mock.patch.object(SC, "core_json", return_value=pg), mock.patch.object(SC, "core", fc), \
                mock.patch.object(NP, "core", fc), mock.patch.object(SC, "active_core", return_value=core_name):
            ok, msg = SC.run_task("latency")
        return ok, msg, [c for c in calls if c.startswith("/proxies/")]

    def test_singbox_probes_absent(self):
        ok, msg, pc = self.run_task("singbox", ["n1", "n2", "n3", "REJECT"], GROUP_EMPTY,
                                    {"n1": NODE_TIMEOUT, "n2": NODE_TIMEOUT, "n3": NODE_OK})
        self.assertTrue(ok, msg)
        self.assertIn("1 个节点可达", msg)
        self.assertEqual(sorted(c.split("/")[2] for c in pc), ["n1", "n2", "n3"])

    def test_singbox_mixed(self):
        ok, msg, pc = self.run_task("singbox", ["good-direct", "bad-ss"], GROUP_MIXED, {"bad-ss": NODE_TIMEOUT})
        self.assertIn("1 个节点可达", msg)
        self.assertEqual([c.split("/")[2] for c in pc], ["bad-ss"])

    def test_mihomo_unchanged(self):
        ok, msg, pc = self.run_task("mihomo", ["good-direct", "bad-ss"], GROUP_MIXED, {"bad-ss": NODE_OK})
        self.assertTrue(ok, msg)
        self.assertIn("1 个节点可达", msg)
        self.assertEqual(pc, [])


class ProbeTest(unittest.TestCase):
    def test_fill_absent(self):
        calls = []
        fc = fake_core_factory(GROUP_EMPTY, {"b": NODE_OK, "c": NODE_TIMEOUT, "d": NOT_FOUND}, calls)
        with mock.patch.object(NP, "core", fc):
            out = NP.fill_absent({"a": 20, "b": 0, "c": 0, "d": 0})
        self.assertEqual(out, {"a": 20, "b": 39, "c": 0})
        self.assertNotIn("a", [c.split("/")[2].split("?")[0] for c in calls])

    def test_node_delay(self):
        for resp, want in ((NODE_OK, 39), ((200, b'{"delay":true}'), 0), (NODE_TIMEOUT, 0), (NODE_ERROR, 0),
                           (NOT_FOUND, None), (UNREACHABLE, None)):
            with mock.patch.object(NP, "core", return_value=resp):
                self.assertEqual(NP.node_delay("x"), want, resp)

    def test_no_group_delay_elsewhere_treats_absent_as_failed(self):
        # 依赖整组测速结果的地方都已改走 nodeprobe：其余调用只是触发测速（retest / 前端），不据缺席记失败
        src = {}
        for fn in os.listdir(os.path.join(ROOT, "shunt")):
            if fn.endswith(".py"):
                with open(os.path.join(ROOT, "shunt", fn), encoding="utf-8") as f:
                    src[fn] = f.read()
        users = sorted(fn for fn, s in src.items() if re.search(r'f"/group/\{quote\(G_MANUAL\)\}/delay', s))
        self.assertEqual(users, ["health.py", "latency.py", "notify.py", "schedule.py", "webapi.py"])
        for fn in ("health.py", "notify.py", "schedule.py"):
            self.assertIn("from .nodeprobe import", src[fn])


class MobileHeaderCssTest(unittest.TestCase):
    def test_mobile_header_rules(self):
        with open(os.path.join(ROOT, "web", "style.css"), encoding="utf-8") as f:
            css = f.read()
        i = css.index("/* v8.4.8 手机端顶栏放大")
        blk = css[i:]
        self.assertIn(".brand b{display:inline}", blk)
        self.assertRegex(blk, r"\.logo\{width:38px;height:38px")
        self.assertRegex(blk, r"\.corebox \.ib\{height:40px;[^}]*font-size:15px")
        self.assertRegex(blk, r"\.corebox #h-mode\{[^}]*height:40px;[^}]*font-size:15px")
        self.assertIn("(hover:none) and (pointer:coarse)", blk)  # 触屏宽屏单独处理，鼠标桌面端不变
        with open(os.path.join(ROOT, "index.html"), encoding="utf-8") as f:
            self.assertIn("/* v8.4.8 手机端顶栏放大", f.read())


if __name__ == "__main__":
    unittest.main()
