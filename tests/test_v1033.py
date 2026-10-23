"""v10.3.3：sing-box 内核下误报「所有节点均测速超时」。

用真实 sing-box 1.14.3 实测（clash_api）：
- /group/{组}/delay：返回 200 + 只含测通节点的对象；全部超时也是 200 + {}（mihomo 是 504）；组不存在 404；缺 timeout 400
- /proxies/{节点}/delay：200 {"delay": n}、超时 504 {"message":"Timeout"}、出错 503、节点不存在 404
- 整组测速同时只测 10 个节点、整组共用 timeout：30 个失效节点中间夹 1 个可用节点，5 次里 3 次返回 {}（可用节点没轮到测）
"""
import json
import sys
import threading
import unittest
from unittest import mock
from urllib.parse import unquote

from tests.helper import server

assert server

B = sys.modules["shunt.base"]
N = sys.modules["shunt.notify"]
NP = sys.modules["shunt.nodeprobe"]  # v10.3.4 起逐个节点测速抽到 nodeprobe，notify / health / schedule 共用

TIMEOUT_ALL = (200, b"{}\n")  # sing-box 1.14.3 全部超时（或可用节点没轮到测）时的真实应答
NODE_TIMEOUT = (504, b'{"message":"Timeout"}\n')
NODE_ERROR = (503, b'{"message":"An error occurred in the delay test"}\n')
NOT_FOUND = (404, b'{"message":"Resource not found"}\n')
UNREACHABLE = (502, json.dumps({"message": "mihomo 未运行或无法连接: refused"}).encode())


class SingBoxCheckNodesTest(unittest.TestCase):
    def run_check(self, group, nodes, st=None, members=("n1", "n2", "n3")):
        """group：/group/…/delay 的应答；nodes：{节点: /proxies/节点/delay 的应答}"""
        calls = []
        lock = threading.Lock()

        def fake_core(method, path, body=None, timeout=10):
            p = unquote(path)
            with lock:
                calls.append(p)
            if p.startswith("/group/"):
                return group
            name = p.split("/")[2]
            return nodes.get(name, NOT_FOUND)

        d = dict(server.load(), tg_token="t", tg_chat="c", mode="rule")
        pg = {"type": "Selector", "name": B.G_MANUAL, "now": members[0] if members else "", "all": list(members)}
        with mock.patch.object(N, "load", return_value=d), mock.patch.object(N, "core_json", return_value=pg), \
                mock.patch.object(N, "core", side_effect=fake_core), mock.patch.object(NP, "core", side_effect=fake_core), \
                mock.patch.object(N, "load_notified", return_value=dict(st or {})), \
                mock.patch.object(N, "write_json") as wj, mock.patch.object(N, "notify") as nt:
            N.check_nodes()
        return wj, nt, calls

    def test_all_timeout_200_empty_alarms(self):
        wj, nt, calls = self.run_check(TIMEOUT_ALL, {"n1": NODE_TIMEOUT, "n2": NODE_TIMEOUT, "n3": NODE_ERROR})
        nt.assert_called_once()
        self.assertIn("所有节点均测速超时", nt.call_args[0][0])
        self.assertEqual(wj.call_args[0][1], {"allnodes": True})
        self.assertEqual(sorted(c.split("/")[2] for c in calls if c.startswith("/proxies/")), ["n1", "n2", "n3"])

    def test_untested_live_node_no_false_alarm(self):
        # 可用节点没轮到测：整组返回 {}，逐个复核发现 n3 可用 → 不告警
        wj, nt, _ = self.run_check(TIMEOUT_ALL, {"n1": NODE_TIMEOUT, "n2": NODE_TIMEOUT, "n3": (200, b'{"delay":31}\n')})
        nt.assert_not_called()
        wj.assert_not_called()

    def test_core_reload_during_confirm_no_alarm(self):
        # 复核时核心重载 / 重启（502）或节点已不在（404）：本轮不下结论，不重新引入 v8.4.5 修掉的误报
        for bad in (UNREACHABLE, NOT_FOUND):
            wj, nt, _ = self.run_check(TIMEOUT_ALL, {"n1": NODE_TIMEOUT, "n2": bad, "n3": NODE_TIMEOUT})
            nt.assert_not_called()
            wj.assert_not_called()

    def test_some_ok_200(self):
        wj, nt, calls = self.run_check((200, b'{"n2":40}\n'), {}, {"allnodes": True})
        nt.assert_called_once()
        self.assertIn("恢复", nt.call_args[0][0])
        self.assertFalse([c for c in calls if c.startswith("/proxies/")])  # 有结果时不必逐个复核

    def test_already_down_no_confirm(self):
        wj, nt, calls = self.run_check(TIMEOUT_ALL, {}, {"allnodes": True})
        nt.assert_not_called()
        wj.assert_not_called()
        self.assertFalse([c for c in calls if c.startswith("/proxies/")])

    def test_group_missing_or_core_down(self):
        for resp in (NOT_FOUND, UNREACHABLE, (400, b'{"message":"Body invalid"}\n')):
            wj, nt, _ = self.run_check(resp, {})
            nt.assert_not_called()
            wj.assert_not_called()

    def test_mihomo_504_unchanged(self):
        wj, nt, calls = self.run_check((504, b'{"message":"get delay: all proxies timeout"}'), {})
        nt.assert_called_once()
        self.assertIn("超时", nt.call_args[0][0])
        self.assertFalse([c for c in calls if c.startswith("/proxies/")])

    def test_confirm_budget_exceeded_no_conclusion(self):
        ev = threading.Event()

        def slow(name):
            ev.wait(5)
            return 0
        try:
            with mock.patch.object(NP, "node_delay", side_effect=slow):
                self.assertIsNone(NP.confirm_all_down(["a", "b"], budget=0.2))
        finally:
            ev.set()
        self.assertFalse(B.MASS_TEST["active"])  # 测速登记已注销，看门狗恢复判定

    def test_node_alive_parse(self):
        for resp, want in (((200, b'{"delay":31}'), True), ((200, b'{"delay":0}'), False), (NODE_TIMEOUT, False),
                           (NODE_ERROR, False), (NOT_FOUND, None), (UNREACHABLE, None), ((200, b"oops"), None)):
            with mock.patch.object(NP, "core", return_value=resp) as c:
                self.assertIs(NP.node_alive("香港 01/x"), want, resp)
            self.assertIn("/proxies/%E9%A6%99%E6%B8%AF%2001%2Fx/delay?", c.call_args[0][1])

    def test_empty_group(self):
        wj, nt, _ = self.run_check(TIMEOUT_ALL, {}, members=())
        nt.assert_called_once()  # 组里没有节点：与以前一样按全部不可用告警


if __name__ == "__main__":
    unittest.main()
