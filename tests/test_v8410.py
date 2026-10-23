"""v8.4.10（Hk002 v10.3.6 同步）：sing-box 下其余整组测速路径（前端「全部测速」/ 组测速 / 概览测速、订阅 healthcheck、重载后补测）补测缺席节点，
逐个测速全局限并发 + 同节点去重；/api/px 应答瘦身、sing-box 下 /api/px 少要一次 /proxies 并缓存订阅节点名单；连接页 2 秒拉一次。

sing-box 1.14.3 实测应答见 tests/test_v848.py 文件头（整组测速同时只测 10 个、只列测通的；单节点 200/504/503/404）。
"""
import json
import os
import re
import sys
import threading
import time
import unittest
from unittest import mock
from urllib.parse import unquote

from tests.helper import server
from tests.test_v1012 import ApiCase

assert server

B = sys.modules["shunt.base"]
NP = sys.modules["shunt.nodeprobe"]
WA = sys.modules["shunt.webapi"]
L = sys.modules["shunt.latency"]
G = sys.modules["shunt.groups"]
SBC = sys.modules["shunt.sb_config"]
D = sys.modules["shunt.data"]
def norm(d):
    D.normalize(d)
    return d


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*p):
    with open(os.path.join(ROOT, *p), encoding="utf-8") as f:
        return f.read()


class VersionTest(unittest.TestCase):
    def test_version(self):
        self.assertEqual(B.PANEL_VERSION, "8.4.10")

    def test_changelog_top(self):
        heads = [ln for ln in read("CHANGELOG.md").splitlines() if ln.startswith("## v")]
        self.assertTrue(heads[0].startswith("## v8.4.10"), heads[0])


GROUP = "🖐️ 手动选择"


def proxies_doc(members, groups=("🚀 子组",)):
    px = {GROUP: {"name": GROUP, "type": "Selector", "all": list(members) + list(groups) + ["DIRECT"], "now": members[0]}}
    for m in members:
        px[m] = {"name": m, "type": "VMess", "history": []}
    for g in groups:
        px[g] = {"name": g, "type": "URLTest", "all": list(members), "now": members[0]}
    px["DIRECT"] = {"name": "DIRECT", "type": "Direct"}
    return {"proxies": px}


def fake_core_factory(members, node_codes, group_resp, calls):
    """node_codes：{节点: (状态码, 应答)}；group_resp：整组测速应答"""
    doc = proxies_doc(members)

    def fake_core(method, path, body=None, timeout=10):
        p = unquote(path)
        calls.append(p)
        if p == "/proxies":
            return 200, json.dumps(doc).encode()
        if p.startswith("/group/"):
            return group_resp
        m = re.match(r"^/proxies/(.+?)/delay\?", p)
        if m:
            return node_codes.get(m.group(1), (404, b'{"message":"Resource not found"}'))
        return 404, b"{}"
    return fake_core


OK = lambda ms: (200, json.dumps({"delay": ms}).encode())  # noqa: E731
TIMEOUT = (504, b'{"message":"Timeout"}')


class ConcurrencyTest(unittest.TestCase):
    def test_global_limit_across_callers(self):
        # 两个调用方同时补测（如「全部测速」两个组 + 重载后补测）：合计并发不超过 PROBE_WORKERS
        cur = {"n": 0, "max": 0}
        lk = threading.Lock()

        def slow(name):
            with lk:
                cur["n"] += 1
                cur["max"] = max(cur["max"], cur["n"])
            time.sleep(0.03)
            with lk:
                cur["n"] -= 1
            return 10
        with mock.patch.object(NP, "node_delay", side_effect=slow), mock.patch.object(NP, "mass_begin", return_value=None), \
                mock.patch.object(NP, "mass_end"):
            out = [None, None]
            ts = [threading.Thread(target=lambda i=i: out.__setitem__(i, NP.probe_nodes([f"n{i}-{k}" for k in range(40)], 10))) for i in range(2)]
            [t.start() for t in ts]
            [t.join() for t in ts]
        self.assertLessEqual(cur["max"], NP.PROBE_WORKERS)
        self.assertGreater(cur["max"], 1)
        self.assertTrue(all(v == 10 for o in out for v in o.values()))
        self.assertLessEqual(NP.PROBE_WORKERS, 16)

    def test_same_node_probed_once(self):
        gate = threading.Event()
        n = {"calls": 0}

        def blocked(name):
            n["calls"] += 1
            gate.wait(5)
            return 42
        res = []
        with mock.patch.object(NP, "node_delay", side_effect=blocked):
            dl = time.monotonic() + 5
            ts = [threading.Thread(target=lambda: res.append(NP._probe_shared("x", dl))) for _ in range(3)]
            [t.start() for t in ts]
            time.sleep(0.1)
            gate.set()
            [t.join() for t in ts]
        self.assertEqual(n["calls"], 1)
        self.assertEqual(res, [42, 42, 42])
        self.assertEqual(NP._INFLIGHT, {})

    def test_budget_bounds_waiting(self):
        # 信号量被占满时，等待也受预算限制：到点返回 None（没有结论），不会在预算之后才去测
        taken = [NP._SEM.acquire(timeout=1) for _ in range(NP.PROBE_WORKERS)]
        try:
            with mock.patch.object(NP, "node_delay", return_value=10) as nd:
                t = time.monotonic()
                out = NP.probe_nodes(["a", "b"], budget=0.3)
                self.assertLess(time.monotonic() - t, 2)
            self.assertEqual(out, {"a": None, "b": None})
            time.sleep(0.4)
            nd.assert_not_called()
        finally:
            for ok in taken:
                if ok:
                    NP._SEM.release()


class FillGroupTest(unittest.TestCase):
    def run_fill(self, group_resp, node_codes):
        calls = []
        members = ["a", "b", "c"]
        with mock.patch.object(NP, "core", side_effect=fake_core_factory(members, node_codes, group_resp, calls)), \
                mock.patch.object(NP, "core_json", side_effect=lambda p, timeout=10: json.loads(fake_core_factory(members, node_codes, group_resp, calls)("GET", p)[1])):
            code, raw = NP.fill_group(GROUP, *group_resp)
        return code, json.loads(raw), calls

    def test_absent_nodes_probed(self):
        code, out, calls = self.run_fill((200, b'{"a":20}'), {"b": OK(30), "c": TIMEOUT})
        self.assertEqual(code, 200)
        self.assertEqual(out, {"a": 20, "b": 30})  # 与原格式一致：只列测通的
        probed = sorted(re.match(r"^/proxies/(.+?)/delay", c).group(1) for c in calls if "/delay" in c)
        self.assertEqual(probed, ["b", "c"])  # 测通的 a、子组、DIRECT 都不补测

    def test_all_down_still_200_empty(self):
        code, out, _ = self.run_fill((200, b"{}"), {"a": TIMEOUT, "b": TIMEOUT, "c": (503, b"{}")})
        self.assertEqual((code, out), (200, {}))

    def test_non_200_passthrough(self):
        for resp in ((504, b'{"message":"Timeout"}'), (404, b'{"message":"Resource not found"}'), (502, b'{"message":"x"}')):
            with mock.patch.object(NP, "probe_nodes") as pn:
                self.assertEqual(NP.fill_group(GROUP, *resp), resp)
            pn.assert_not_called()

    def test_group_keys_kept(self):
        code, out, _ = self.run_fill((200, '{"🚀 子组":15}'.encode()), {"a": OK(5), "b": TIMEOUT, "c": TIMEOUT})
        self.assertEqual(out, {"🚀 子组": 15, "a": 5})


class SingboxApiTest(ApiCase):
    def setUp(self):
        super().setUp()
        d = server.load()
        d["subs"] = [{"name": "S1", "url": "https://example.com/s1"}, {"name": "S2", "url": "https://example.com/s2"}]
        d["core"] = "singbox"
        server.save(d)
        os.makedirs(os.path.dirname(G.sub_cache_path("S1")), exist_ok=True)
        D.write_json(G.sub_cache_path("S1"), {"name": "S1", "updated": 1, "nodes": [{"name": "a", "type": "vmess"}, {"name": "b", "type": "vmess"}]})
        D.write_json(G.sub_cache_path("S2"), {"name": "S2", "updated": 1, "nodes": [{"name": "c", "type": "vmess"}]})

    def tearDown(self):
        for n in ("S1", "S2"):
            try:
                os.remove(G.sub_cache_path(n))
            except OSError:
                pass
        super().tearDown()

    def test_frontend_group_delay_fills(self):
        calls = []
        fc = fake_core_factory(["a", "b", "c"], {"b": OK(30), "c": TIMEOUT}, (200, b'{"a":20}'), calls)
        with mock.patch.object(WA, "active_core", return_value="singbox"), mock.patch.object(WA, "core", side_effect=fc), \
                mock.patch.object(NP, "core", side_effect=fc), \
                mock.patch.object(NP, "core_json", side_effect=lambda p, timeout=10: json.loads(fc("GET", p)[1])):
            from urllib.parse import quote
            code, j = self.call("GET", f"/api/core/group/{quote(GROUP)}/delay?url=x&timeout=5000")
        self.assertEqual(code, 200)
        self.assertEqual(j, {"a": 20, "b": 30})

    def test_mihomo_group_delay_unchanged(self):
        with mock.patch.object(WA, "active_core", return_value="mihomo"), mock.patch.object(WA, "core", return_value=(200, b'{"a":20}')), \
                mock.patch.object(WA, "fill_group") as fg:
            code, j = self.call("GET", "/api/core/group/G/delay?url=x&timeout=5000")
        self.assertEqual((code, j), (200, {"a": 20}))
        fg.assert_not_called()

    def test_sub_healthcheck_only_that_sub(self):
        seen = []
        with mock.patch.object(WA, "active_core", return_value="singbox"), \
                mock.patch.object(NP, "node_delay", side_effect=lambda n: seen.append(n) or 10), \
                mock.patch.object(WA, "core") as wc:
            code, _ = self.call("GET", "/api/core/providers/proxies/S1/healthcheck")
        self.assertEqual(code, 204)
        self.assertEqual(sorted(seen), ["a", "b"])
        wc.assert_not_called()  # 不再测整个手动选择组

    def test_sub_healthcheck_core_down(self):
        with mock.patch.object(WA, "active_core", return_value="singbox"), mock.patch.object(NP, "node_delay", return_value=None):
            code, j = self.call("GET", "/api/core/providers/proxies/S1/healthcheck")
        self.assertEqual(code, 502)
        with mock.patch.object(WA, "active_core", return_value="singbox"):
            code, j = self.call("GET", "/api/core/providers/proxies/NOPE/healthcheck")
        self.assertEqual(code, 404)


class RetestSoonTest(unittest.TestCase):
    def run_retest(self, kind):
        done = threading.Event()
        with mock.patch.object(L, "RETEST", {"pending": False, "last": 0}), mock.patch.object(L, "core_alive", return_value=True), \
                mock.patch.object(L, "fix_global"), mock.patch.object(L, "core_json", return_value={"all": ["a"]}), \
                mock.patch.object(L, "core", return_value=(200, b"{}")), mock.patch.object(L, "active_core", return_value=kind), \
                mock.patch.object(L, "proxies_merged", side_effect=lambda: done.set()), mock.patch.object(L, "fill_group") as fg:
            L.retest_soon(0)
            self.assertTrue(done.wait(5))
        return fg

    def test_singbox_fills(self):
        fg = self.run_retest("singbox")
        fg.assert_called_once()
        self.assertEqual(fg.call_args[0][0], B.G_MANUAL)
        self.assertEqual(fg.call_args[0][3], L.RETEST_BUDGET)

    def test_mihomo_unchanged(self):
        self.run_retest("mihomo").assert_not_called()


class PxSlimTest(unittest.TestCase):
    def test_keeps_last_entry(self):
        h = [{"time": f"t{k}", "delay": k} for k in range(10)]
        px = {"n": {"name": "n", "history": list(h), "extra": {"u1": {"alive": True, "history": list(h)}, "u2": {"history": []}}},
              "g": {"name": "g", "all": ["n"], "history": list(h)}, "x": {"name": "x"}}
        out = L.px_slim(px)
        self.assertEqual(out["n"]["history"], [h[-1]])
        self.assertEqual(out["n"]["extra"]["u1"], {"alive": True, "history": [h[-1]]})
        self.assertEqual(out["n"]["extra"]["u2"], {"history": []})
        self.assertEqual(out["g"]["history"], [h[-1]])
        self.assertEqual(out["x"], {"name": "x"})

    def test_frontend_uses_only_last(self):
        # 前端只读 history 最后一条（lastDelay、我的节点列表）：瘦身不改变显示
        js = "".join(read("web", "js", f) for f in sorted(os.listdir(os.path.join(ROOT, "web", "js"))) if f.endswith(".js"))
        for m in re.finditer(r"history", js):
            ctx = js[max(0, m.start() - 80):m.end() + 60]
            if "history[" in ctx and "replaceState" not in ctx and "pushState" not in ctx:
                self.assertRegex(ctx, r"h\[h\.length-1\]", ctx)

    def test_api_px_slimmed(self):
        self.assertIn('"proxies": px_slim(px)', read("shunt", "webapi.py"))


class SingboxProvidersCacheTest(unittest.TestCase):
    def setUp(self):
        os.makedirs(os.path.dirname(G.sub_cache_path("C1")), exist_ok=True)
        D.write_json(G.sub_cache_path("C1"), {"name": "C1", "updated": 5, "info": {"total": 1}, "nodes": [{"name": "x"}, {"name": "y"}]})
        self.d = norm({"subs": [{"name": "C1", "url": "https://example.com/c1"}]})

    def tearDown(self):
        try:
            os.remove(G.sub_cache_path("C1"))
        except OSError:
            pass

    def test_provider_nodes_cached_until_file_changes(self):
        with mock.patch.object(G, "sb_sub_cache", wraps=G.sb_sub_cache) as rc:
            a = G.sb_provider_nodes(self.d)
            b = G.sb_provider_nodes(self.d)
            self.assertEqual(a, b)
            self.assertEqual(a["C1"], ["x", "y"])
            n1 = rc.call_count
            a["C1"].append("mutated")  # 返回副本：调用方改了不影响缓存
            self.assertEqual(G.sb_provider_nodes(self.d)["C1"], ["x", "y"])
            self.assertEqual(rc.call_count, n1)
            D.write_json(G.sub_cache_path("C1"), {"name": "C1", "updated": 6, "nodes": [{"name": "z"}]})
            self.assertEqual(G.sb_provider_nodes(self.d)["C1"], ["z"])
            d2 = norm({"subs": [{"name": "C1", "url": "https://example.com/c1", "removed": ["z"]}]})
            self.assertEqual(G.sb_provider_nodes(d2)["C1"], [])  # 已删节点名单变化也会重算

    def test_meta_cached(self):
        self.assertEqual(G.sb_sub_meta("C1"), {"updated": 5, "info": {"total": 1}})
        D.write_json(G.sub_cache_path("C1"), {"name": "C1", "updated": 9, "nodes": []})
        self.assertEqual(G.sb_sub_meta("C1")["updated"], 9)

    def test_fake_providers_reuses_px(self):
        px = {"x": {"name": "x", "type": "VMess", "history": [{"time": "t", "delay": 3}]}}
        with mock.patch.object(SBC, "core_json") as cj:
            out = SBC.sb_fake_providers(self.d, px)
        cj.assert_not_called()  # /api/px 已经取过 /proxies，不再向核心要第二次
        names = [p["name"] for p in out["providers"]["C1"]["proxies"]]
        self.assertEqual(names, ["x", "y"])
        self.assertEqual(out["providers"]["C1"]["proxies"][0]["history"], [{"time": "t", "delay": 3}])

    def test_proxies_merged_one_core_call(self):
        calls = []

        def cj(path, timeout=10):
            calls.append(path)
            return {"proxies": {"x": {"name": "x", "type": "VMess", "history": []}}} if path == "/proxies" else None
        with mock.patch.object(L, "core_json", side_effect=cj), mock.patch.object(SBC, "core_json", side_effect=cj), \
                mock.patch.object(L, "active_core", return_value="singbox"), mock.patch.object(L, "load", return_value=self.d), \
                mock.patch.object(L, "retest_soon"):
            px = L.proxies_merged()
        self.assertEqual(calls, ["/proxies"])
        self.assertIn("y", px)


class ConnsPollTest(unittest.TestCase):
    def test_conns_every_two_seconds(self):
        js = read("web", "js", "05-live.js")
        self.assertIn("TAB==='连接'&&!$('#c-pause').checked&&(_cn%2===0||!CONNS.length)", js)
        self.assertIn("if(now-_lastConnRender<1500)return;", read("web", "js", "13-conns.js"))
        self.assertIn("_cn%2===0", read("index.html"))


if __name__ == "__main__":
    unittest.main()
