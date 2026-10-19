"""v8.4.0：自定义策略组勾选订阅节点（mihomo use + 精确 filter、sing-box 直接列出改名后的 tag、失效节点跳过）、
订阅节点单独删除（mihomo exclude-filter、sing-box 生成时跳过）、校验 / 恢复改名 / 旧 data.json 兼容、接口"""
import copy
import os
import re
import unittest
from unittest import mock

from tests.helper import server
from tests.test_v1012 import ApiCase

assert server

import sys  # noqa: E402

G = sys.modules["shunt.groups"]
M = sys.modules["shunt.mihomo"]
SBC = sys.modules["shunt.sb_config"]
V = sys.modules["shunt.validate"]
DA = sys.modules["shunt.data"]
WA = sys.modules["shunt.webapi"]

SPECIAL = "🇭🇰 HK [01] (IEPL) | x.y+z"
SPACED = "JP 02 Tokyo"
TICK = "US`03"
PLAIN = "SG 04"
NODES_A = [SPECIAL, SPACED, TICK, PLAIN, "HK 99"]
NODES_B = ["TW 01", SPACED]  # 与 A 重名的节点：sing-box 下会被改名为「JP 02 Tokyo (2)」


def base(core="mihomo", groups=(), removed_a=None):
    d = server.load()
    d = copy.deepcopy(d)
    d["core"] = core
    sa = {"name": "A", "url": "https://a.example/s", "filter": "", "exclude": ""}
    if removed_a is not None:
        sa["removed"] = list(removed_a)
    d["subs"] = [sa, {"name": "B", "url": "https://b.example/s", "filter": "", "exclude": ""}]
    d["nodes"] = [{"proxy": {"name": "M1", "type": "ss", "server": "1.2.3.4", "port": 8388, "cipher": "aes-128-gcm", "password": "x"}}]
    d["custom_groups"] = list(groups)
    d["rules"] = []
    return d


def cg(name="🎯 均衡", t="load-balance", proxies=(), sub_nodes=(), flt="", subs=True):
    return {"name": name, "type": t, "proxies": list(proxies), "filter": flt, "subs": subs, "expose": False, "icon": "",
            "sub_nodes": [{"sub": s, "name": n} for s, n in sub_nodes]}


def group(cfg, name):
    return next(g for g in cfg["proxy-groups"] if g["name"] == name)


PN = {"A": list(NODES_A), "B": list(NODES_B)}


def write_sb_cache():
    for sname, names in (("A", NODES_A), ("B", NODES_B)):
        nodes = [{"name": n, "type": "ss", "server": f"10.0.0.{i + 1}", "port": 8388, "cipher": "aes-128-gcm", "password": "p"}
                 for i, n in enumerate(names)]
        DA.write_json(G.sub_cache_path(sname), {"name": sname, "updated": 1, "nodes": nodes})


class RegexHelperTest(unittest.TestCase):
    def test_names_rx_exact_and_escaped(self):
        r = G.names_rx([SPECIAL, SPACED, TICK])
        self.assertNotIn("`", r)  # 反引号是 mihomo 的多条正则分隔符
        c = re.compile(r)
        for n in (SPECIAL, SPACED, TICK):
            self.assertTrue(c.search(n), n)
        for n in ("HK 01", SPACED + " x", "x" + SPACED, "US 03", "🇭🇰 HK [01] (IEPL) ", "JP 02"):
            self.assertFalse(c.search(n), n)

    def test_rx_or(self):
        self.assertEqual(G.rx_or("", "^(?:a)$"), "^(?:a)$")
        self.assertEqual(G.rx_or("港|HK", ""), "港|HK")
        self.assertEqual(G.rx_or("港|HK", "^(?:a)$"), "(?:港|HK)|^(?:a)$")
        self.assertEqual(G.rx_or("港`日", "^(?:a)$"), "港`日`^(?:a)$")
        c = re.compile(G.rx_or("港|HK", G.names_rx([SPACED])))
        self.assertTrue(c.search("HK 99") and c.search(SPACED))
        self.assertFalse(c.search("SG 04"))


class MihomoPickTest(unittest.TestCase):
    def setUp(self):
        self.p = mock.patch.object(G, "provider_nodes", return_value=copy.deepcopy(PN))
        self.p.start()

    def tearDown(self):
        self.p.stop()

    def test_picked_nodes_use_and_exact_filter(self):
        d = base(groups=[cg(proxies=["M1", "DIRECT"], sub_nodes=[("A", SPECIAL), ("A", SPACED), ("A", TICK)])])
        g = group(M.build_config(d), "🎯 均衡")
        self.assertEqual(g["use"], ["A"])  # 只引用涉及的订阅
        self.assertEqual(g["proxies"], ["M1", "DIRECT"])  # 手动节点 / 内置策略照常在 proxies
        c = re.compile(g["filter"])
        hit = [n for n in NODES_A if c.search(n)]
        self.assertEqual(hit, [SPECIAL, SPACED, TICK])
        self.assertTrue(g["filter"].startswith("^(?:") and g["filter"].endswith(")$"))
        self.assertNotIn("`", g["filter"])

    def test_two_subs_and_user_regex_union(self):
        d = base(groups=[cg(flt="HK", sub_nodes=[("A", PLAIN), ("B", "TW 01")])])
        g = group(M.build_config(d), "🎯 均衡")
        self.assertEqual(g["use"], ["A", "B"])
        c = re.compile(g["filter"])
        self.assertEqual([n for n in NODES_A + NODES_B if c.search(n)], [SPECIAL, PLAIN, "HK 99", "TW 01"])

    def test_user_regex_only_unchanged(self):
        d = base(groups=[cg(flt="(?i)hk")])
        g = group(M.build_config(d), "🎯 均衡")
        self.assertEqual(g["filter"], "(?i)hk")
        self.assertEqual(g["use"], ["A", "B"])

    def test_manual_only_regex_with_picks(self):
        """「包含订阅节点」关闭时用户正则只作用于手动节点：use / filter 只表达勾选的订阅节点"""
        d = base(groups=[cg(flt="M", subs=False, sub_nodes=[("B", "TW 01")])])
        g = group(M.build_config(d), "🎯 均衡")
        self.assertEqual(g["use"], ["B"])
        self.assertEqual(g["filter"], G.names_rx(["TW 01"]))
        self.assertIn("M1", g["proxies"])

    def test_stale_picks_skipped(self):
        d = base(groups=[cg(sub_nodes=[("A", "GONE"), ("ZZ", "x"), ("A", PLAIN)])])
        g = group(M.build_config(d), "🎯 均衡")
        self.assertEqual(g["filter"], G.names_rx([PLAIN]))
        d = base(groups=[cg(sub_nodes=[("A", "GONE"), ("ZZ", "x")])])
        g = group(M.build_config(d), "🎯 均衡")
        self.assertNotIn("use", g)
        self.assertEqual(g["proxies"], ["COMPATIBLE"])  # 全部失效：不让配置加载失败

    def test_unknown_sub_keeps_picks(self):
        """订阅还没加载过（不知道有哪些节点）时不判失效"""
        with mock.patch.object(G, "provider_nodes", return_value={}):
            d = base(groups=[cg(sub_nodes=[("A", "NEW 1")])])
            g = group(M.build_config(d), "🎯 均衡")
        self.assertEqual(g["filter"], G.names_rx(["NEW 1"]))

    def test_removed_nodes_excluded(self):
        d = base(removed_a=[SPECIAL, TICK])
        d["subs"][0]["exclude"] = "剩余|到期"
        pv = M.build_config(d)["proxy-providers"]["A"]
        c = re.compile(pv["exclude-filter"])
        self.assertEqual([n for n in NODES_A + ["剩余流量 10G"] if c.search(n)], [SPECIAL, TICK, "剩余流量 10G"])
        self.assertNotIn("exclude-filter", M.build_config(base())["proxy-providers"]["B"])
        d["subs"][0]["exclude"] = ""
        self.assertEqual(M.build_config(d)["proxy-providers"]["A"]["exclude-filter"], G.names_rx([SPECIAL, TICK]))

    def test_removed_pick_skipped(self):
        d = base(groups=[cg(sub_nodes=[("A", SPECIAL), ("A", PLAIN)])], removed_a=[SPECIAL])
        g = group(M.build_config(d), "🎯 均衡")
        self.assertEqual(g["filter"], G.names_rx([PLAIN]))

    def test_smart_core_same(self):
        d = base(core="smart", groups=[cg(t="fallback", sub_nodes=[("A", SPACED)])])
        g = group(M.build_config(d), "🎯 均衡")
        self.assertEqual((g["type"], g["use"], g["filter"]), ("fallback", ["A"], G.names_rx([SPACED])))

    def test_validate_groups_accepts_sub_only_group(self):
        d = base(groups=[cg(sub_nodes=[("A", PLAIN)])])
        self.assertEqual(WA.validate_groups(d), [])


class SingboxPickTest(unittest.TestCase):
    def setUp(self):
        write_sb_cache()

    def tearDown(self):
        for sname in ("A", "B"):
            if os.path.exists(G.sub_cache_path(sname)):
                os.remove(G.sub_cache_path(sname))

    def outs(self, d):
        conf = SBC.build_singbox(d)[0]
        return {o["tag"]: o for o in conf["outbounds"]}

    def test_members_are_renamed_tags(self):
        d = base(core="singbox", groups=[cg(proxies=["M1"], sub_nodes=[("B", SPACED), ("A", SPECIAL), ("A", TICK)])])
        o = self.outs(d)
        mem = o["🎯 均衡"]["outbounds"]
        self.assertEqual(mem[0], "M1")
        self.assertEqual(set(mem[1:]), {SPECIAL, TICK, SPACED + " (2)"})  # B 的重名节点用生成配置里的改名
        self.assertNotIn(SPACED, mem)  # 没勾 A 的同名节点
        for t in mem:
            self.assertIn(t, o)

    def test_user_regex_union(self):
        d = base(core="singbox", groups=[cg(flt="HK", sub_nodes=[("B", "TW 01")])])
        mem = self.outs(d)["🎯 均衡"]["outbounds"]
        self.assertEqual(set(mem), {SPECIAL, "HK 99", "TW 01"})

    def test_stale_skipped(self):
        d = base(core="singbox", groups=[cg(sub_nodes=[("A", "GONE"), ("ZZ", "x")])])
        self.assertEqual(self.outs(d)["🎯 均衡"]["outbounds"], ["DIRECT"])

    def test_removed_excluded_without_redownload(self):
        d = base(core="singbox", groups=[cg(sub_nodes=[("A", SPECIAL), ("A", PLAIN)])], removed_a=[SPECIAL, SPACED])
        o = self.outs(d)
        self.assertNotIn(SPECIAL, o)
        self.assertIn(SPACED, o)  # B 的同名节点不再撞名，不改名
        self.assertNotIn(SPACED + " (2)", o)
        self.assertEqual(o["🎯 均衡"]["outbounds"], [PLAIN])
        self.assertNotIn(SPECIAL, G.sb_provider_nodes(d)["A"])
        # 缓存里仍保留完整节点，恢复时不用重新下载
        self.assertIn(SPECIAL, [p["name"] for p in G.sb_sub_cache("A")["nodes"]])

    def test_sub_nodes_view(self):
        d = base(core="singbox", groups=[cg(sub_nodes=[("B", SPACED)])], removed_a=[TICK])
        v = WA.sub_nodes_view(d)
        a, b = v["subs"]
        self.assertEqual(a["removed"], [TICK])
        self.assertNotIn(TICK, [n["orig"] for n in a["nodes"]])
        nb = next(n for n in b["nodes"] if n["orig"] == SPACED)
        self.assertEqual((nb["name"], nb["groups"]), (SPACED + " (2)", ["🎯 均衡"]))


class ValidateTest(unittest.TestCase):
    def test_clean_custom_group_sub_nodes(self):
        g = G.clean_custom_group(cg(sub_nodes=[("A", "x"), ("A", "x"), ("B", "y")]))
        self.assertEqual(g["sub_nodes"], [{"sub": "A", "name": "x"}, {"sub": "B", "name": "y"}])
        g = G.clean_custom_group({"name": "g", "type": "select", "sub_nodes": [{"sub": "A", "name": "x"}]})  # 只有订阅节点也可以
        self.assertEqual(g["proxies"], [])
        for bad in ([{"sub": "A"}], [{"sub": "", "name": "x"}], "x", [{"sub": "A", "name": "a\nb"}], [{"sub": "A", "name": "x" * 301}]):
            with self.assertRaises(ValueError):
                G.clean_custom_group({"name": "g", "type": "select", "proxies": ["DIRECT"], "sub_nodes": bad})
        with self.assertRaises(ValueError):
            G.clean_custom_group({"name": "g", "type": "select", "sub_nodes": []})

    def test_clean_subs_removed(self):
        out = V.clean_subs([{"name": "A", "url": "https://a.example/s", "removed": ["x", "x", "y"]}])
        self.assertEqual(out[0]["removed"], ["x", "y"])
        for bad in ("x", [1], [""], ["a\nb"]):
            with self.assertRaises(ValueError):
                V.clean_subs([{"name": "A", "url": "https://a.example/s", "removed": bad}])
        old = V.clean_subs([{"name": "A", "url": "https://a.example/s"}])  # 旧备份没有 removed
        self.assertNotIn("removed", old[0])

    def test_rename_carries_lists(self):
        subs = [{"name": "机场 A", "url": "https://a.example/s", "removed": ["a1"]},
                {"name": "机场_A", "url": "https://b.example/s", "removed": ["b1", "b2"]}]
        new, ren = V.rename_sub_clashes(subs)
        self.assertEqual(ren, [("机场_A", "机场_A_2")])
        self.assertEqual(new[1], {"name": "机场_A_2", "url": "https://b.example/s", "removed": ["b1", "b2"]})
        groups = [cg(sub_nodes=[("机场_A", "b3"), ("机场 A", "a2")])]
        out = V.rename_sub_refs(groups, ren)
        self.assertEqual(out[0]["sub_nodes"], [{"sub": "机场_A_2", "name": "b3"}, {"sub": "机场 A", "name": "a2"}])

    def test_old_data_backward_compat(self):
        d = base()
        for s in d["subs"]:
            s.pop("removed", None)
        d["custom_groups"] = [{"name": "旧组", "type": "url-test", "proxies": ["DIRECT"], "filter": "HK", "subs": True}]
        with mock.patch.object(G, "provider_nodes", return_value=copy.deepcopy(PN)):
            cfg = M.build_config(d)
        g = group(cfg, "旧组")
        self.assertEqual((g["filter"], g["use"]), ("HK", ["A", "B"]))
        self.assertNotIn("exclude-filter", cfg["proxy-providers"]["A"])
        self.assertFalse(DA.normalize(copy.deepcopy(d)))  # 旧数据不需要迁移写回

    def test_normalize_drops_bad_shapes(self):
        d = base()
        d["subs"][0]["removed"] = ["ok", 3, "", "ok"]
        d["custom_groups"] = [dict(cg(sub_nodes=[("A", "x")]), sub_nodes=[{"sub": "A", "name": "x"}, {"sub": 1}, "zz"])]
        self.assertTrue(DA.normalize(d))
        self.assertEqual(d["subs"][0]["removed"], ["ok"])
        self.assertEqual(d["custom_groups"][0]["sub_nodes"], [{"sub": "A", "name": "x"}])


class SubNodesApiTest(ApiCase):
    def setUp(self):
        super().setUp()
        d = base(groups=[cg(sub_nodes=[("A", SPECIAL)])])
        server.save(d)
        self.p = [mock.patch.object(WA, "reload_core", return_value=(True, "ok")), mock.patch.object(WA, "refresh_later"),
                  mock.patch.object(G, "provider_nodes", return_value=copy.deepcopy(PN))]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()
        super().tearDown()

    def test_remove_and_restore(self):
        code, j = self.call("POST", "/api/subs/nodes/remove", {"items": [{"sub": "A", "name": SPECIAL}, {"sub": "A", "name": TICK},
                                                                         {"sub": "B", "name": "TW 01"}]})
        self.assertEqual(code, 200, j)
        self.assertIn("3", j["message"])
        subs = {s["name"]: s for s in server.load()["subs"]}
        self.assertEqual(subs["A"]["removed"], [SPECIAL, TICK])
        self.assertEqual(subs["B"]["removed"], ["TW 01"])
        WA.reload_core.assert_called_once()
        # 编辑订阅保留名单
        code, j = self.call("POST", "/api/subs", {"name": "A", "url": "https://a.example/s2", "filter": "", "exclude": ""})
        self.assertEqual(code, 200, j)
        self.assertEqual(next(s for s in server.load()["subs"] if s["name"] == "A")["removed"], [SPECIAL, TICK])
        code, j = self.call("POST", "/api/subs/nodes/restore", {"sub": "A", "names": [TICK]})
        self.assertEqual(code, 200, j)
        self.assertEqual(next(s for s in server.load()["subs"] if s["name"] == "A")["removed"], [SPECIAL])
        code, j = self.call("POST", "/api/subs/nodes/restore", {"sub": "B", "all": True})
        self.assertEqual(code, 200, j)
        self.assertNotIn("removed", next(s for s in server.load()["subs"] if s["name"] == "B"))

    def test_input_validation(self):
        for body in ({}, {"items": []}, {"items": "x"}, {"items": [{"sub": "A"}]}, {"items": [{"sub": "A", "name": 5}]},
                     {"items": [{"sub": "A", "name": "x" * 301}]}):
            code, j = self.call("POST", "/api/subs/nodes/remove", body)
            self.assertEqual(code, 400, (body, j))
        code, j = self.call("POST", "/api/subs/nodes/remove", {"items": [{"sub": "NOPE", "name": "x"}]})
        self.assertEqual(code, 404)
        for body in ({}, {"sub": "A"}, {"sub": "A", "names": []}, {"sub": "A", "names": [1]}):
            code, j = self.call("POST", "/api/subs/nodes/restore", body)
            self.assertEqual(code, 400, (body, j))
        code, j = self.call("POST", "/api/subs/nodes/restore", {"sub": "NOPE", "all": True})
        self.assertEqual(code, 404)
        WA.reload_core.assert_not_called()

    def test_nodes_view_marks_groups(self):
        code, j = self.call("GET", "/api/subs/nodes")
        self.assertEqual(code, 200, j)
        a = j["subs"][0]
        self.assertTrue(a["known"])
        n = next(x for x in a["nodes"] if x["orig"] == SPECIAL)
        self.assertEqual(n["groups"], ["🎯 均衡"])

    def test_restore_settings_renames_refs(self):
        subs = [{"name": "机场 A", "url": "https://a.example/s", "filter": "", "exclude": "", "removed": ["a1"]},
                {"name": "机场_A", "url": "https://b.example/s", "filter": "", "exclude": "", "removed": ["b1"]}]
        groups = [cg(sub_nodes=[("机场_A", "b2")])]
        with mock.patch.object(WA, "tp_apply"), mock.patch.object(WA, "ab_compose"):
            code, j = self.call("POST", "/api/restore", {"subs": subs, "custom_groups": groups})
        self.assertEqual(code, 200, j)
        d = server.load()
        self.assertEqual([(s["name"], s["removed"]) for s in d["subs"]], [("机场 A", ["a1"]), ("机场_A_2", ["b1"])])
        self.assertEqual(d["custom_groups"][0]["sub_nodes"], [{"sub": "机场_A_2", "name": "b2"}])

    def test_restore_rejects_bad_removed(self):
        code, j = self.call("POST", "/api/restore", {"subs": [{"name": "A", "url": "https://a.example/s", "removed": "x"}]})
        self.assertEqual(code, 400, j)

    def test_save_custom_group_with_sub_nodes(self):
        body = {"name": "🎯 新组", "type": "fallback", "proxies": [], "sub_nodes": [{"sub": "A", "name": PLAIN}], "filter": ""}
        code, j = self.call("POST", "/api/groups", body)
        self.assertEqual(code, 200, j)
        g = next(x for x in server.load()["custom_groups"] if x["name"] == "🎯 新组")
        self.assertEqual(g["sub_nodes"], [{"sub": "A", "name": PLAIN}])


if __name__ == "__main__":
    unittest.main()
