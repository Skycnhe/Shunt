"""v10.1.3 回归测试：测速计数原子 + 自愈、手动停止后保存不拉起核心、sing-box 重载确认、广告查询 400、
备份 600、/api/state 打码且保存不受影响、校验移出全局锁、广告列表缓存空闲释放"""
import json
import os
import signal
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from tests.helper import server
from tests.test_v1012 import ApiCase

assert server

A = sys.modules["shunt.adblock"]
B = sys.modules["shunt.base"]
BK = sys.modules["shunt.backup"]
C = sys.modules["shunt.core"]
N = sys.modules["shunt.notify"]
SBC = sys.modules["shunt.sb_config"]
W = sys.modules["shunt.webapi"]

SUB_URL = "https://sub.example.com/api/v1/client/subscribe?token=abcdef1234567890"
TG = "123456789:AAEexampletokenvalue"


class MassTestCounterTest(unittest.TestCase):
    def tearDown(self):
        B.MASS_TEST["active"].clear()
        B.MASS_TEST["n"] = 0

    def test_concurrent_begin_end_balanced(self):
        bar = threading.Barrier(16)

        def go():
            bar.wait()
            for _ in range(500):
                B.mass_end(B.mass_begin())
        ts = [threading.Thread(target=go) for _ in range(16)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertFalse(B.mass_testing())
        self.assertEqual(B.MASS_TEST["n"], 0)

    def test_stale_entry_self_heals(self):
        tok = B.mass_begin()
        self.assertTrue(B.mass_testing())
        B.MASS_TEST["active"][tok] = time.time() - B.MASS_MAX_AGE - 1  # 漏了注销、已超过 5 分钟
        self.assertFalse(B.mass_testing())
        B.mass_end(tok)  # 迟到的注销不出错、不变负
        self.assertEqual(B.MASS_TEST["n"], 0)

    def test_core_call_registers_and_releases(self):
        CH = sys.modules["shunt.corehttp"]
        seen = []

        def opener(req, timeout=10):
            seen.append(B.mass_testing())
            raise OSError("down")
        with mock.patch.object(CH.DIRECT_OPENER, "open", side_effect=opener):
            code, _ = CH.core("GET", "/group/x/delay?url=u")
        self.assertEqual(code, 502)
        self.assertEqual(seen, [True])
        self.assertFalse(B.mass_testing())

    def test_watchdog_paused_only_while_testing(self):
        orig = server.load()
        try:
            server.save(dict(orig, watchdog=True))
            N.WD_HOLD.update(until=0.0)
            tok = B.mass_begin()
            with mock.patch.object(N, "core_alive_confirmed", return_value=True) as ca:
                N.watchdog_tick()
                ca.assert_not_called()
                B.mass_end(tok)
                N.watchdog_tick()
                ca.assert_called_once()
        finally:
            server.save(orig)


class ManualStopTest(unittest.TestCase):
    def setUp(self):
        self.orig = server.load()
        server.save(dict(self.orig, core="mihomo"))
        self.hold = dict(N.WD_HOLD)

    def tearDown(self):
        N.WD["manual_stop"] = False
        N.WD_HOLD.update(self.hold)
        server.save(self.orig)

    def test_reload_writes_config_but_does_not_start(self):
        N.WD["manual_stop"] = True
        prev = server.update(lambda d: d.update(bypass=["10.3.3.3"]))
        final = os.path.join(C.CONF_DIR, "config.yaml")
        if os.path.exists(final):
            os.remove(final)
        with mock.patch.object(C, "active_core", return_value="mihomo"), \
                mock.patch.object(C, "check_config", return_value=(True, "")), \
                mock.patch.object(C, "core") as core, mock.patch.object(C, "svc_restart") as rs, \
                mock.patch.object(C, "sb_hot_reload") as hr, mock.patch.object(C, "retest_soon"):
            ok, msg = C.reload_core(prev)
        self.assertTrue(ok, msg)
        self.assertIn("下次启动", msg)
        core.assert_not_called()
        rs.assert_not_called()
        hr.assert_not_called()
        self.assertTrue(N.WD["manual_stop"])  # 标志保留
        self.assertTrue(os.path.isfile(final))
        self.assertEqual(server.load()["bypass"], ["10.3.3.3"])

    def test_tp_apply_skipped_when_stopped(self):
        with mock.patch.object(W, "sh", return_value=(0, "ok")) as sh:
            N.WD["manual_stop"] = True
            self.assertEqual(W.tp_apply(), (0, ""))
            sh.assert_not_called()
            N.WD["manual_stop"] = False
            self.assertEqual(W.tp_apply(), (0, "ok"))
            sh.assert_called_once()


class SbHotReloadTest(unittest.TestCase):
    def setUp(self):
        self.log = tempfile.mktemp(prefix="sblog-")
        with open(self.log, "w") as f:
            f.write("INFO old line\n")
        self.alive = True
        self.ps = [mock.patch.object(SBC, "MIHOMO_LOG", self.log), mock.patch.object(SBC, "core_pid", return_value=4242),
                   mock.patch.object(SBC, "SB_RELOAD_WAIT", 3.0), mock.patch.object(SBC, "SB_RELOAD_NOMARK", 1.5),
                   mock.patch.object(SBC, "svc_restart")]
        for p in self.ps:
            p.start()
        self.hold = dict(N.WD_HOLD)

    def tearDown(self):
        for p in reversed(self.ps):
            p.stop()
        N.WD_HOLD.update(self.hold)

    def run_reload(self, on_hup, core_alive=True):
        def kill(pid, sig):
            if sig == signal.SIGHUP:
                on_hup()
            elif not self.alive:
                raise ProcessLookupError()
        with mock.patch.object(SBC.os, "kill", side_effect=kill), mock.patch.object(SBC, "core_alive", return_value=core_alive):
            t0 = time.time()
            r = SBC.sb_hot_reload()
            return r, time.time() - t0

    def append(self, line):
        with open(self.log, "a") as f:
            f.write(line + "\n")

    def test_started_marker_success_fast(self):
        (ok, msg), dt = self.run_reload(lambda: self.append("+0800 2026-10-17 INFO sing-box started (0.31s)"))
        self.assertTrue(ok, msg)
        self.assertLess(dt, 1.4)  # 没等到「无标记」兜底
        self.assertLess(N.WD_HOLD["until"], time.time() + 10)  # 成功后缩短看门狗暂停

    def test_reload_rejected_fails(self):
        (ok, msg), _ = self.run_reload(lambda: self.append("+0800 2026-10-17 ERROR reload service: decode config: bad"))
        self.assertFalse(ok)
        self.assertIn("reload service", msg)

    def test_process_died_fails(self):
        def hup():
            self.alive = False
        (ok, msg), _ = self.run_reload(hup)
        self.assertFalse(ok)
        self.assertIn("退出", msg)

    def test_old_marker_before_sighup_ignored(self):
        self.append("INFO sing-box started (0.2s)")  # SIGHUP 之前的旧记录不算
        (ok, _), dt = self.run_reload(lambda: None)
        self.assertTrue(ok)
        self.assertGreaterEqual(dt, 1.5)  # 走的是无标记兜底

    def test_not_responding_fails(self):
        (ok, msg), _ = self.run_reload(lambda: self.append("INFO sing-box started (0.2s)"), core_alive=False)
        self.assertFalse(ok)
        self.assertIn("未响应", msg)


class AdblockCheckTest(ApiCase):
    def test_invalid_input_400(self):
        for b in ({"domain": "not a domain!"}, {"domain": ""}, {"domain": 123}, {"domain": ["a.com"]}, {}):
            code, j = self.call("POST", "/api/adblock/check", b)
            self.assertEqual(code, 400, (b, j))
            self.assertIn("有效域名", j["message"])

    def test_valid_domain_200(self):
        code, j = self.call("POST", "/api/adblock/check", {"domain": "https://ads.example.com/x"})
        self.assertEqual(code, 200, j)
        self.assertEqual(j["host"], "ads.example.com")


class AdblockCacheIdleTest(unittest.TestCase):
    def test_released_after_idle(self):
        d = tempfile.mkdtemp(prefix="ab-")
        p = os.path.join(d, "x.txt")
        with open(p, "w") as f:
            f.write("+.ads.example\nexact.example\n")
        with mock.patch.object(A, "AB_IDLE", 0.3):
            suf, ex = A.ab_sets(p)
            self.assertIn("ads.example", suf)
            self.assertIn(p, A.AB_CACHE)
            for _ in range(40):
                if p not in A.AB_CACHE:
                    break
                time.sleep(0.1)
            self.assertNotIn(p, A.AB_CACHE)
            self.assertIn("exact.example", A.ab_sets(p)[1])  # 释放后再查照常重新载入
        for _ in range(40):
            if A._AB_GC["timer"] is None:
                break
            time.sleep(0.1)


class BackupPermTest(unittest.TestCase):
    def test_created_0600_and_old_fixed(self):
        d = tempfile.mkdtemp(prefix="bk-")
        base = tempfile.mkdtemp(prefix="bkbase-")
        with open(os.path.join(base, "server.py"), "w") as f:
            f.write("x")
        bdir = os.path.join(d, "backups")
        with mock.patch.object(BK, "BACKUP_DIR", bdir), mock.patch.object(BK, "BASE", base):
            old_umask = os.umask(0o022)
            try:
                ok, name = BK.create("1.0")
            finally:
                os.umask(old_umask)
            self.assertTrue(ok, name)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(bdir, name)).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(bdir).st_mode), 0o700)
            old = os.path.join(bdir, "shunt-backup-v0.9-20250101-000000.tar.gz")
            with open(old, "wb") as f:
                f.write(b"x")
            os.chmod(old, 0o644)
            names = [x["name"] for x in BK.list()]
            self.assertIn(name, names)
            self.assertEqual(stat.S_IMODE(os.stat(old).st_mode), 0o600)
            import tarfile
            with tarfile.open(os.path.join(bdir, name)) as tf:
                self.assertIn("data.json", tf.getnames())


class MaskTest(unittest.TestCase):
    def test_mask_url(self):
        m = W.mask_url(SUB_URL)
        self.assertTrue(m.startswith("https://sub.example.com/"))
        self.assertNotIn("abcdef1234567890", m)
        self.assertNotIn("subscribe", m)
        self.assertNotIn("user", W.mask_url("https://user:pw@h.com/a/b"))
        self.assertEqual(W.mask_url("https://h.com"), "https://h.com")
        self.assertEqual(W.mask_url(""), "")

    def test_unmask(self):
        self.assertEqual(W.unmask(W.mask_url(SUB_URL), SUB_URL, W.mask_url), SUB_URL)
        self.assertEqual(W.unmask("https://new.example/x", SUB_URL, W.mask_url), "https://new.example/x")
        self.assertEqual(W.unmask(W.mask_secret(TG), TG, W.mask_secret), TG)
        self.assertEqual(W.unmask("", TG, W.mask_secret), "")  # 清空 = 真的要删掉
        self.assertEqual(W.mask_secret(""), "")


class StateMaskApiTest(ApiCase):
    def setUp(self):
        super().setUp()
        server.save(dict(server.load(), subs=[{"name": "s1", "url": SUB_URL, "filter": "", "exclude": ""}],
                         tg_token=TG, tg_chat="42"))
        W._SVC_CACHE["v"] = (time.time() + 60, "started", 200, "test")

    def tearDown(self):
        W._SVC_CACHE.clear()
        super().tearDown()

    def state(self):
        with mock.patch.object(W, "state_groups", return_value=([], {})):
            code, j = self.call("GET", "/api/state")
        self.assertEqual(code, 200, j)
        return j

    def test_state_masked(self):
        j = self.state()
        raw = json.dumps(j, ensure_ascii=False)
        self.assertNotIn("abcdef1234567890", raw)
        self.assertNotIn(TG, raw)
        self.assertEqual(j["subs"][0]["name"], "s1")
        self.assertEqual(j["tg_chat"], "42")
        self.assertTrue(j["tg_token"])  # 前端据此知道已配置
        self.assertEqual(server.load()["subs"][0]["url"], SUB_URL)  # 服务端原值不动

    def test_save_tg_with_masked_placeholder_keeps_token(self):
        j = self.state()
        code, r = self.call("PUT", "/api/settings", {"tg_token": j["tg_token"], "tg_chat": "43"})
        self.assertEqual(code, 200, r)
        d = server.load()
        self.assertEqual(d["tg_token"], TG)
        self.assertEqual(d["tg_chat"], "43")
        code, r = self.call("PUT", "/api/settings", {"tg_token": "999:NEW", "tg_chat": "43"})
        self.assertEqual(code, 200, r)
        self.assertEqual(server.load()["tg_token"], "999:NEW")
        self.call("PUT", "/api/settings", {"tg_token": "", "tg_chat": ""})
        self.assertEqual(server.load()["tg_token"], "")

    def test_tg_test_uses_real_token(self):
        j = self.state()
        got = []
        with mock.patch.object(W, "tg_send", side_effect=lambda msg, d: got.append(d["tg_token"]) or (True, "ok")):
            code, _ = self.call("POST", "/api/tg/test", {"tg_token": j["tg_token"], "tg_chat": "42"})
        self.assertEqual(code, 200)
        self.assertEqual(got, [TG])

    def test_edit_sub_with_masked_url_keeps_url(self):
        j = self.state()
        masked = j["subs"][0]["url"]
        with mock.patch.object(W, "reload_core", return_value=(True, "ok")), mock.patch.object(W, "refresh_after_sub"), \
                mock.patch.object(W, "active_core", return_value="mihomo"):
            code, r = self.call("POST", "/api/subs", {"name": "s1", "url": masked, "filter": "HK", "exclude": ""})
            self.assertEqual(code, 200, r)
            s = server.load()["subs"][0]
            self.assertEqual((s["url"], s["filter"]), (SUB_URL, "HK"))
            code, r = self.call("POST", "/api/subs", {"name": "s1", "url": "https://other.example/s", "filter": ""})
            self.assertEqual(code, 200, r)
            self.assertEqual(server.load()["subs"][0]["url"], "https://other.example/s")
            code, r = self.call("POST", "/api/subs", {"name": "s2", "url": masked})  # 别的订阅名不能借用打码值
            self.assertEqual(code, 200, r)
            self.assertEqual([x["url"] for x in server.load()["subs"] if x["name"] == "s2"], [masked])


class ReloadLockScopeTest(unittest.TestCase):
    def setUp(self):
        self.orig = server.load()
        server.save(dict(self.orig, core="mihomo", bypass=["10.0.0.1"]))
        N.WD["manual_stop"] = True  # 只测「生成 + 校验 + 替换」，不碰核心

    def tearDown(self):
        N.WD["manual_stop"] = False
        server.save(self.orig)

    def test_update_not_blocked_during_check(self):
        started, release = threading.Event(), threading.Event()

        def slow_check(path):
            started.set()
            release.wait(10)
            return True, ""
        res = []
        with mock.patch.object(C, "active_core", return_value="mihomo"), mock.patch.object(C, "check_config", side_effect=slow_check):
            t = threading.Thread(target=lambda: res.append(C.reload_core()))
            t.start()
            self.assertTrue(started.wait(10))
            done = threading.Event()
            u = threading.Thread(target=lambda: (server.update(lambda d: d.update(bypass=["10.0.0.7"])), done.set()))
            u.start()
            self.assertTrue(done.wait(3), "校验期间 update() 被全局锁卡住")
            release.set()
            t.join(20)
            u.join(5)
        self.assertTrue(res and res[0][0], res)

    def test_changed_during_check_regenerates_latest(self):
        n = [0]

        def check(path):
            n[0] += 1
            if n[0] == 1:  # 第一次校验期间配置被改
                server.update(lambda d: d.update(mode="global"))
            return True, ""
        real_write = C.write_config
        with mock.patch.object(C, "active_core", return_value="mihomo"), mock.patch.object(C, "check_config", side_effect=check), \
                mock.patch.object(C, "write_config", side_effect=real_write) as wc:
            ok, msg = C.reload_core()
        self.assertTrue(ok, msg)
        self.assertEqual(wc.call_count, 2)
        with open(os.path.join(C.CONF_DIR, "config.yaml")) as f:
            self.assertEqual(json.load(f)["mode"], "global")
        self.assertEqual([x for x in os.listdir(C.CONF_DIR) if ".new" in x], [])


if __name__ == "__main__":
    unittest.main()
