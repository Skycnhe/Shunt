"""v10.1.2 回归测试：设置 / 恢复的形状校验、定时任务补跑、策略组缓存失效、更新互斥、测速缓存并发、
load() 独立副本、reload_core 回滚、/api/conns/stats"""
import http.client
import json
import os
import sys
import tempfile
import threading
import unittest
from unittest import mock

from tests.helper import server

assert server

B = sys.modules["shunt.base"]
C = sys.modules["shunt.core"]
D = sys.modules["shunt.data"]
L = sys.modules["shunt.latency"]
N = sys.modules["shunt.notify"]
SC = sys.modules["shunt.schedule"]
V = sys.modules["shunt.validate"]
W = sys.modules["shunt.webapi"]
HT = sys.modules["shunt.https"]

RS_OK = {"name": "my-rs", "url": "https://example.com/rs.yaml", "behavior": "domain", "format": "yaml", "target": "DIRECT"}


class ApiCase(unittest.TestCase):
    """起一个真实的面板 HTTP 服务；用例里按需 mock 掉重载核心 / nftables"""
    @classmethod
    def setUpClass(cls):
        cls.srv = HT.Server(("127.0.0.1", 0), server.H)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        self.orig = server.load()

    def tearDown(self):
        server.save(self.orig)

    def call(self, method, path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        try:
            hdr = {"X-Shunt": "1", "Content-Type": "application/json"}
            c.request(method, path, body=json.dumps(body) if body is not None else None, headers=hdr)
            r = c.getresponse()
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
        finally:
            c.close()


class ValidateUnitTest(unittest.TestCase):
    def test_bad_shapes_rejected(self):
        bad = [
            {"rulesets": [{"name": "x"}]},  # 缺 url
            {"rulesets": [dict(RS_OK, behavior="nope")]},
            {"rulesets": [RS_OK, RS_OK]},  # 重名
            {"rulesets": "notalist"},
            {"bypass": [123]},
            {"bypass": ["not-an-ip"]},
            {"tests": [{"url": "https://a.com"}]},  # 缺 name
            {"tests": []},
            {"tests": [{"name": "a", "url": "ftp://a"}]},
            {"log_limit": "5"},
            {"watchdog": True, "tg_token": {"a": 1}},
            {"schedule": {"sub_update": "25:00"}},
            {"nodes": [{"proxy": {"name": "n", "type": "ss", "server": "1.1.1.1", "port": 70000}}]},
            {"mode": "weird"},
        ]
        for b in bad:
            with self.assertRaises(ValueError, msg=b):
                V.clean_fields(b, set(b))

    def test_good_shapes_normalised(self):
        out = V.clean_fields({"rulesets": [{"name": " a ", "url": "https://x.com/a.yaml"}],
                              "bypass": [" 192.168.1.5 ", "", "10.0.0.0/8", "AA:BB:CC:DD:EE:FF"],
                              "tests": [{"name": "G", "url": "https://www.google.com"}], "ignored": 1},
                             {"rulesets", "bypass", "tests"})
        self.assertEqual(out["rulesets"][0]["name"], "a")
        self.assertEqual(out["rulesets"][0]["behavior"], "domain")
        self.assertEqual(out["bypass"], ["192.168.1.5", "10.0.0.0/8", "AA:BB:CC:DD:EE:FF"])
        self.assertNotIn("ignored", out)

    def test_not_a_dict(self):
        with self.assertRaises(ValueError):
            V.clean_fields(["x"], {"bypass"})


class SettingsRestoreApiTest(ApiCase):
    def test_settings_bad_payloads_400_and_not_saved(self):
        before = server.load()
        with mock.patch.object(W, "reload_core", return_value=(True, "ok")) as rc, mock.patch.object(W, "tp_apply") as tp:
            for b in ({"rulesets": [{"name": "x"}]}, {"bypass": [1, 2]}, {"tests": [{"url": "https://a"}]},
                      {"log_limit": 3}, {"gh_proxy": "not a url"}):
                code, j = self.call("PUT", "/api/settings", b)
                self.assertEqual(code, 400, (b, j))
                self.assertTrue(j.get("message"))
        rc.assert_not_called()
        tp.assert_not_called()
        after = server.load()
        for k in ("rulesets", "bypass", "tests", "log_limit"):
            self.assertEqual(after[k], before[k], k)

    def test_settings_good_payload_saved(self):
        with mock.patch.object(W, "reload_core", return_value=(True, "配置已重载")) as rc, \
                mock.patch.object(W, "tp_apply", return_value=(0, "")):
            code, j = self.call("PUT", "/api/settings", {"rulesets": [RS_OK], "bypass": ["192.168.1.9"]})
        self.assertEqual(code, 200, j)
        rc.assert_called_once()
        d = server.load()
        self.assertEqual(d["rulesets"][0]["name"], "my-rs")
        self.assertEqual(d["bypass"], ["192.168.1.9"])

    def test_restore_bad_rejected(self):
        before = server.load()["rulesets"]
        with mock.patch.object(W, "reload_core", return_value=(True, "ok")) as rc:
            for b in ({"rulesets": [{"name": "x"}]}, {"subs": [{"name": "s"}]}, {"nodes": [{"x": 1}]}, {}, {"unknown": 1}):
                code, j = self.call("POST", "/api/restore", b)
                self.assertEqual(code, 400, (b, j))
                self.assertIn("备份内容无效", j["message"])
        rc.assert_not_called()
        self.assertEqual(server.load()["rulesets"], before)

    def test_restore_good_accepted(self):
        with mock.patch.object(W, "reload_core", return_value=(True, "配置已重载")), \
                mock.patch.object(W, "tp_apply", return_value=(0, "")), mock.patch.object(W, "ab_compose"):
            code, j = self.call("POST", "/api/restore", {"rulesets": [RS_OK], "bypass": ["10.0.0.2"], "mode": "rule"})
        self.assertEqual(code, 200, j)
        self.assertIn("已恢复", j["message"])
        self.assertEqual(server.load()["bypass"], ["10.0.0.2"])


class DailyDueTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sched-")
        self.p = mock.patch.object(SC, "DAILY_FILE", os.path.join(self.tmp, "sched_done.json"))
        self.p.start()
        SC.DAILY["data"] = {}

    def tearDown(self):
        self.p.stop()
        SC.DAILY["data"] = None

    def test_catch_up_after_missed_minute(self):
        self.assertFalse(SC.daily_due("t", "08:00", "07:59", "D1"))  # 先见到设定时刻
        self.assertTrue(SC.daily_due("t", "08:00", "08:20", "D1"))  # 08:00 那一分钟被长任务卡过去了，仍补跑
        self.assertFalse(SC.daily_due("t", "08:00", "08:21", "D1"))  # 不重复触发
        self.assertFalse(SC.daily_due("t", "08:00", "23:59", "D1"))
        self.assertTrue(SC.daily_due("t", "08:00", "09:30", "D2"))  # 第二天：过点后也补跑
        self.assertFalse(SC.daily_due("t", "08:00", "09:31", "D2"))

    def test_first_seen_after_time_does_not_fire(self):
        self.assertFalse(SC.daily_due("t", "03:00", "10:00", "D1"))  # 刚升级 / 开机时今天的时刻已过：不立刻跑
        self.assertFalse(SC.daily_due("t", "03:00", "11:00", "D1"))
        self.assertTrue(SC.daily_due("t", "03:00", "03:00", "D2"))

    def test_changed_time_does_not_fire_immediately(self):
        self.assertFalse(SC.daily_due("t", "08:00", "07:00", "D1"))
        self.assertFalse(SC.daily_due("t", "06:00", "07:00", "D1"))  # 改成已过去的时刻：今天不跑
        self.assertFalse(SC.daily_due("t", "06:00", "07:30", "D1"))
        self.assertTrue(SC.daily_due("t", "06:00", "06:05", "D2"))

    def test_changed_after_ran_today(self):
        self.assertFalse(SC.daily_due("t", "08:00", "07:00", "D1"))
        self.assertTrue(SC.daily_due("t", "08:00", "08:00", "D1"))
        self.assertFalse(SC.daily_due("t", "09:00", "09:00", "D1"))  # 今天已跑过又改了时刻：明天按新时刻
        self.assertTrue(SC.daily_due("t", "09:00", "09:00", "D2"))

    def test_invalid_time_never_fires(self):
        for at in ("25:00", "", "8:00", "12:60", "ab:cd", "08:00:00"):
            for day in ("D1", "D2", "D3"):
                for now in ("00:00", "12:00", "23:59"):
                    self.assertFalse(SC.daily_due("bad", at, now, day), (at, day, now))

    def test_persisted_across_restart(self):
        self.assertFalse(SC.daily_due("t", "08:00", "07:00", "D1"))
        self.assertTrue(SC.daily_due("t", "08:00", "08:00", "D1"))
        SC.DAILY["data"] = None  # 模拟面板重启：从文件读回
        self.assertFalse(SC.daily_due("t", "08:00", "08:30", "D1"))


class GroupCacheTest(unittest.TestCase):
    def setUp(self):
        W._GRP_CACHE.clear()

    def tearDown(self):
        W._GRP_CACHE.clear()

    def test_invalidated_on_node_list_change(self):
        rev = [1]
        cfg = {"proxy-groups": [{"name": "🇭🇰 香港竞技", "type": "url-test"}]}
        with mock.patch.object(W, "provider_nodes"), mock.patch.object(W, "provider_rev", side_effect=lambda: rev[0]), \
                mock.patch.object(W, "active_core", return_value="mihomo"), \
                mock.patch.object(W, "group_meta", return_value={}), \
                mock.patch.object(W, "build_config", return_value=cfg) as bc:
            d = server.load()
            self.assertEqual(W.state_groups(d)[0], ["🇭🇰 香港竞技"])
            W.state_groups(d)
            self.assertEqual(bc.call_count, 1)  # 命中缓存
            cfg["proxy-groups"].append({"name": "🇯🇵 日本竞技", "type": "url-test"})
            rev[0] = 2  # 订阅下载完、节点名单变了
            self.assertEqual(W.state_groups(d)[0], ["🇭🇰 香港竞技", "🇯🇵 日本竞技"])
            self.assertEqual(bc.call_count, 2)
            server.save(d)  # 配置版本变化同样失效
            W.state_groups(d)
            self.assertEqual(bc.call_count, 3)

    def test_provider_rev_bumps_when_names_change(self):
        G = sys.modules["shunt.groups"]
        old = dict(G.PROV)
        cur = [{"s1": ["a"]}]
        try:
            with mock.patch.object(G, "active_core", return_value="singbox"), \
                    mock.patch.object(G, "sb_provider_nodes", side_effect=lambda d: dict(cur[0])):
                G.provider_nodes(fresh=True)
                r1 = G.provider_rev()
                G.provider_nodes(fresh=True)
                self.assertEqual(G.provider_rev(), r1)  # 名单没变：版本不变
                cur[0] = {"s1": ["a", "b"]}
                G.provider_nodes(fresh=True)
                self.assertEqual(G.provider_rev(), r1 + 1)
        finally:
            G.PROV.update(old)


class UpdateMutexTest(unittest.TestCase):
    def tearDown(self):
        B.UPD_STATE["busy"] = False
        B.CORE_UPD["busy"] = False

    def test_panel_and_core_exclusive(self):
        self.assertTrue(B.upd_begin("panel"))
        self.assertFalse(B.upd_begin("core"))
        self.assertFalse(B.upd_begin("panel"))
        self.assertIn("面板", B.upd_busy_msg())
        B.UPD_STATE["busy"] = False
        self.assertTrue(B.upd_begin("core"))
        self.assertFalse(B.upd_begin("panel"))
        self.assertIn("内核", B.upd_busy_msg())

    def test_test_and_set_race_only_one_wins(self):
        for kind in ("panel", "core"):
            B.UPD_STATE["busy"] = B.CORE_UPD["busy"] = False
            n = 24
            bar = threading.Barrier(n)
            wins = []

            def go():
                bar.wait()
                if B.upd_begin(kind):
                    wins.append(1)
            ts = [threading.Thread(target=go) for _ in range(n)]
            for t in ts:
                t.start()
            for t in ts:
                t.join()
            self.assertEqual(len(wins), 1, kind)

    def test_panel_update_refused_while_core_busy(self):
        PU = sys.modules["shunt.panel_update"]
        B.CORE_UPD["busy"] = True
        with mock.patch.object(PU, "panel_manifest") as pm:
            ok, j = PU.self_update(apply=True)
        self.assertFalse(ok)
        self.assertIn("内核", j["message"])
        pm.assert_not_called()
        self.assertFalse(B.UPD_STATE["busy"])

    def test_core_job_refused_while_panel_busy(self):
        CU = sys.modules["shunt.core_update"]
        B.UPD_STATE["busy"] = True
        fn = mock.Mock()
        ok, msg = CU.core_job_start(fn)
        self.assertFalse(ok)
        self.assertIn("面板", msg)
        fn.assert_not_called()


class DelayMergeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="delay-")
        self.p = mock.patch.object(L, "DELAY_FILE", os.path.join(self.tmp, "delays.json"))
        self.p.start()
        L.DELAYS.update(data=None, saved=0, dirty=False)

    def tearDown(self):
        self.p.stop()
        L.DELAYS.update(data=None, saved=0, dirty=False)

    @staticmethod
    def px(names, ts="2026-01-01T00:00:00Z", d=100):
        return {n: {"name": n, "history": [{"delay": d, "time": ts}]} for n in names}

    def test_concurrent_no_errors(self):
        errs = []
        bar = threading.Barrier(8)

        def worker(i):
            bar.wait()
            try:
                for k in range(150):
                    names = [f"n{i}-{k}-{j}" for j in range(20)] + ["shared"]
                    L.delay_merge(self.px(names, ts=f"t{k}"), prov_ok=(k % 2 == 0))
            except Exception as e:  # dictionary changed size during iteration 等
                errs.append(repr(e))
        ts = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(errs, [])

    def test_prov_fail_keeps_cache(self):
        L.delay_merge(self.px(["a", "sub1"]))
        out = L.delay_merge(self.px(["a"]), prov_ok=False)  # 订阅节点列表没取到
        self.assertIn("sub1", L.DELAYS["data"])
        self.assertEqual(out["a"]["_d"], 100)
        L.delay_merge(self.px(["a"]), prov_ok=True)  # 拿到完整列表：已不存在的才删
        self.assertNotIn("sub1", L.DELAYS["data"])

    def test_cached_delay_filled_in(self):
        L.delay_merge(self.px(["a"], d=55))
        out = L.delay_merge({"a": {"name": "a", "history": []}})
        self.assertEqual(out["a"]["_d"], 55)


class LoadCopyTest(unittest.TestCase):
    def setUp(self):
        self.orig = server.load()

    def tearDown(self):
        server.save(self.orig)

    def test_mutating_result_does_not_corrupt_cache(self):
        server.save(dict(server.load(), bypass=["10.1.1.1"]))
        a = server.load()
        a["bypass"].append("10.9.9.9")
        a["tests"].clear()
        a["new_key"] = 1
        b = server.load()
        self.assertEqual(b["bypass"], ["10.1.1.1"])
        self.assertTrue(b["tests"])
        self.assertNotIn("new_key", b)
        self.assertIsNot(a, b)
        self.assertIsNot(server.load()["bypass"], server.load()["bypass"])

    def test_save_invalidates_even_same_mtime(self):
        d = server.load()
        d["bypass"] = ["10.2.2.2"]
        with mock.patch.object(D, "_data_key", return_value=("fixed",)):
            D._DATA_CACHE.pop("v", None)
            server.load()  # 以固定键缓存
            server.save(d)
            self.assertEqual(server.load()["bypass"], ["10.2.2.2"])  # 代数变化：不吃旧缓存


class ReloadRollbackTest(unittest.TestCase):
    def setUp(self):
        self.orig = server.load()
        server.save(dict(self.orig, bypass=["10.0.0.1"], core="mihomo"))
        N.WD["manual_stop"] = False
        self.hold = dict(N.WD_HOLD)

    def tearDown(self):
        N.WD["manual_stop"] = False
        N.WD_HOLD.update(self.hold)
        server.save(self.orig)

    def change(self):
        return server.update(lambda d: d.update(bypass=["10.0.0.99"]))

    def patches(self, core_fn):
        return [mock.patch.object(C, "active_core", return_value="mihomo"),
                mock.patch.object(C, "check_config", return_value=(True, "")),
                mock.patch.object(C, "core", side_effect=core_fn),
                mock.patch.object(C, "svc_restart", return_value=(0, "")),
                mock.patch.object(C, "retest_soon")]

    def run_reload(self, prev, core_fn):
        ps = self.patches(core_fn)
        for p in ps:
            p.start()
        try:
            return C.reload_core(prev), C.core
        finally:
            for p in reversed(ps):
                p.stop()

    def test_mihomo_put_rejected_rolls_back(self):
        prev = self.change()
        calls = []

        def core_fn(method, path, body=None, timeout=10):
            calls.append(body)
            return (400, b'{"message":"bad config"}') if len(calls) == 1 else (204, b"")
        (ok, msg), _ = self.run_reload(prev, core_fn)
        self.assertFalse(ok)
        self.assertIn("已撤销", msg)
        self.assertEqual(server.load()["bypass"], ["10.0.0.1"])
        self.assertEqual(len(calls), 2)  # 回滚后让核心重新加载旧配置
        with open(calls[1]["path"]) as f:
            self.assertTrue(json.load(f))

    def test_mihomo_put_ok(self):
        prev = self.change()
        (ok, msg), core = self.run_reload(prev, lambda *a, **k: (204, b""))
        self.assertTrue(ok, msg)
        self.assertEqual(server.load()["bypass"], ["10.0.0.99"])

    def test_check_failed_rolls_back(self):
        prev = self.change()
        with mock.patch.object(C, "check_config", return_value=(False, "level=error bad")), \
                mock.patch.object(C, "active_core", return_value="mihomo"), mock.patch.object(C, "core") as core:
            ok, msg = C.reload_core(prev)
        self.assertFalse(ok)
        self.assertIn("校验失败", msg)
        core.assert_not_called()
        self.assertEqual(server.load()["bypass"], ["10.0.0.1"])
        left = [n for n in os.listdir(C.CONF_DIR) if ".new" in n]
        self.assertEqual(left, [])  # 临时配置已清理

    def test_generation_exception_rolls_back(self):
        prev = self.change()
        with mock.patch.object(C, "write_config", side_effect=KeyError("url")), \
                mock.patch.object(C, "active_core", return_value="mihomo"), \
                mock.patch.object(C, "log_err"), mock.patch.object(C, "core") as core:
            ok, msg = C.reload_core(prev)
        self.assertFalse(ok)
        self.assertIn("生成配置失败", msg)
        core.assert_not_called()
        self.assertEqual(server.load()["bypass"], ["10.0.0.1"])

    def test_generation_exception_without_prev(self):
        with mock.patch.object(C, "write_config", side_effect=ValueError("boom")), \
                mock.patch.object(C, "active_core", return_value="mihomo"), mock.patch.object(C, "log_err"):
            ok, msg = C.reload_core()
        self.assertFalse(ok)
        self.assertIn("boom", msg)
        # 锁没有被泄漏：别的线程还能拿到
        got = []
        t = threading.Thread(target=lambda: got.append(B.LOCK.acquire(timeout=2)) or B.LOCK.release())
        t.start()
        t.join()
        self.assertEqual(got, [True])


class ConnStatsApiTest(ApiCase):
    def test_counts(self):
        snap = {"connections": [{"metadata": {"sourceIP": "192.168.1.2"}}, {"metadata": {"sourceIP": "192.168.1.2"}},
                                {"metadata": {"sourceIP": "192.168.1.3"}}, {"metadata": {"sourceIP": ""}}, {"metadata": {}}, {}]}
        with mock.patch.object(W, "conns_snapshot", return_value=snap):
            code, j = self.call("GET", "/api/conns/stats")
        self.assertEqual(code, 200)
        self.assertEqual(j, {"count": 6, "devices": 2})

    def test_empty_and_core_down(self):
        with mock.patch.object(W, "conns_snapshot", return_value={"connections": None}):
            self.assertEqual(self.call("GET", "/api/conns/stats"), (200, {"count": 0, "devices": 0}))
        with mock.patch.object(W, "conns_snapshot", return_value=None):
            code, j = self.call("GET", "/api/conns/stats")
        self.assertEqual(code, 502)
        self.assertTrue(j["message"])


if __name__ == "__main__":
    unittest.main()
