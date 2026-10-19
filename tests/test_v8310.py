"""v8.3.10 回归测试（同步 Hk002 v10.2.8）：sing-box 订阅 detour 重映射 / 保留 / 跳过、版本备份恢复先校验并保留 core 与 secret、
恢复时订阅名冲突自动改名、切换内核回滚恢复 block_bypass、规则集与广告列表整体超时、实时日志合并刷新"""
import json
import os
import shutil
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest import mock

from tests.helper import server
from tests.test_v1012 import ApiCase

assert server

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SBC = sys.modules["shunt.sb_config"]
BK = sys.modules["shunt.backup"]
SW = sys.modules["shunt.sb_switch"]
AB = sys.modules["shunt.adblock"]
WA = sys.modules["shunt.webapi"]


def node(name, tag, detour=None):
    o = {"type": "socks", "tag": name, "server": "1.1.1.1", "server_port": 1}
    if detour:
        o["detour"] = detour
    return (name, {"name": tag, "_sb": {"tag": tag}}, o)


class DetourTest(unittest.TestCase):
    def test_remap_after_rename(self):
        conv = [node("A 2", "A"), node("B", "B", detour="A")]  # 去重后 A 改名为「A 2」
        out, dropped = SBC.sb_fix_detour(conv)
        self.assertEqual(dropped, [])
        self.assertEqual(out[1][2]["detour"], "A 2")

    def test_detour_to_global_outbound_kept(self):
        conv = [node("X", "X", detour="direct"), node("Y", "Y", detour="DIRECT"), node("Z", "Z", detour="手动节点")]
        out, dropped = SBC.sb_fix_detour(conv, {"DIRECT", "direct", "手动节点"})
        self.assertEqual(dropped, [])
        self.assertEqual([o["detour"] for _, _, o in out], ["direct", "DIRECT", "手动节点"])

    def test_missing_target_and_cycle_skipped(self):
        conv = [node("A", "A", detour="nope"), node("B", "B", detour="A"), node("C", "C", detour="D"),
                node("D", "D", detour="C"), node("E", "E")]
        out, dropped = SBC.sb_fix_detour(conv, {"DIRECT"})
        self.assertEqual([x[0] for x in out], ["E"])
        self.assertEqual(sorted(dropped), ["A", "B", "C", "D"])

    def test_node_outbounds_keeps_direct_and_notes_missing(self):
        sub_out = {"s1": [("X", {"name": "X", "_sb": {"tag": "X", "detour": "direct"}}),
                          ("Y", {"name": "Y", "_sb": {"tag": "Y", "detour": "gone"}})],
                   "s2": [("W", {"name": "W", "_sb": {"tag": "W", "detour": "X"}})]}  # 指向另一个订阅的节点

        def fake_out(p, name):
            o = {"type": "socks", "tag": name, "server": "1.1.1.1", "server_port": 1}
            if p["_sb"].get("detour"):
                o["detour"] = p["_sb"]["detour"]
            return o
        warn = []
        with mock.patch.object(SBC, "sb_outbound", side_effect=fake_out), mock.patch.object(SBC, "log_err"):
            outs, _, prov = SBC.sb_node_outbounds({"subs": []}, {"proxies": [], "proxy-groups": []}, sub_out, warn)
        tags = {o["tag"]: o for o in outs}
        self.assertEqual(tags["X"]["detour"], "direct")
        self.assertEqual(tags["W"]["detour"], "X")
        self.assertIn("direct", tags)  # 补了同名直连出站，配置里引用有效
        self.assertNotIn("Y", tags)
        self.assertEqual(prov["s1"], ["X"])
        self.assertTrue(any("detour" in w and "Y" in w for w in warn))


class VersionRestoreTest(ApiCase):
    def setUp(self):
        super().setUp()
        self.dir = tempfile.mkdtemp(prefix="bk24-")
        self.base = tempfile.mkdtemp(prefix="base24-")
        for fn in ("server.py", "index.html"):
            with open(os.path.join(self.base, fn), "w") as f:
                f.write("cur")
        self.p = [mock.patch.object(BK, "BACKUP_DIR", self.dir), mock.patch.object(BK, "BASE", self.base),
                  mock.patch.object(WA, "reload_core", return_value=(True, "ok")),
                  mock.patch.object(WA, "tp_apply", return_value=(0, "")),
                  mock.patch.object(WA, "ab_compose")]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()
        shutil.rmtree(self.dir, ignore_errors=True)
        shutil.rmtree(self.base, ignore_errors=True)
        super().tearDown()

    def _mk(self, data):
        name = "shunt-backup-v9.9.9-20260101-000001.tar.gz"
        src = os.path.join(self.base, "src")
        os.makedirs(src, exist_ok=True)
        with open(os.path.join(src, "data.json"), "w") as f:
            json.dump(data, f)
        with open(os.path.join(src, "server.py"), "w") as f:
            f.write("old")
        with tarfile.open(os.path.join(self.dir, name), "w:gz") as tf:
            tf.add(os.path.join(src, "data.json"), arcname="data.json")
            tf.add(os.path.join(src, "server.py"), arcname="server.py")
        return name

    def test_invalid_data_changes_nothing(self):
        before = server.load()
        name = self._mk(dict(before, rulesets="notalist"))
        code, j = self.call("POST", "/api/backup/restore", {"name": name})
        self.assertNotEqual(code, 200, j)
        self.assertIn("未恢复", j.get("message", ""))
        self.assertEqual(server.load(), before)
        with open(os.path.join(self.base, "server.py")) as f:
            self.assertEqual(f.read(), "cur")  # 程序文件也没动
        self.assertEqual(os.listdir(self.dir), [name])  # 也没有先建「当前版本」备份
        WA.reload_core.assert_not_called()

    def test_success_keeps_core_secret_and_renames(self):
        cur = server.load()
        data = dict(cur, core="smart", secret="from-backup",
                    subs=[{"name": "机场 A", "url": "https://a.example/s", "filter": "", "exclude": ""},
                          {"name": "机场_A", "url": "https://b.example/s", "filter": "", "exclude": ""}])
        name = self._mk(data)
        code, j = self.call("POST", "/api/backup/restore", {"name": name})
        self.assertEqual(code, 200, j)
        self.assertIn("已自动改名", j["message"])
        now = server.load()
        self.assertEqual(now.get("core"), cur.get("core"))
        self.assertEqual(now["secret"], cur["secret"])
        self.assertEqual([s["name"] for s in now["subs"]], ["机场 A", "机场_A_2"])
        WA.reload_core.assert_called_once()

    def test_settings_restore_renames(self):
        subs = [{"name": "机场 A", "url": "https://a.example/s", "filter": "", "exclude": ""},
                {"name": "机场_A", "url": "https://b.example/s", "filter": "", "exclude": ""}]
        code, j = self.call("POST", "/api/restore", {"subs": subs})
        self.assertEqual(code, 200, j)
        self.assertIn("已自动改名", j["message"])
        self.assertEqual([s["name"] for s in server.load()["subs"]], ["机场 A", "机场_A_2"])


class SwitchRollbackTest(unittest.TestCase):
    def _run(self, start):
        state = {"d": start}

        def upd(fn):
            fn(state["d"])
            return state["d"]
        ps = [mock.patch.object(SW, "active_core", return_value="mihomo"),
              mock.patch.object(SW, "sb_version", return_value="1.12.0"),
              mock.patch.object(SW, "load", side_effect=lambda: json.loads(json.dumps(state["d"]))),
              mock.patch.object(SW, "update", side_effect=upd),
              mock.patch.object(SW, "sb_sync_assets", return_value=[]),
              mock.patch.object(SW, "write_sb_config", side_effect=lambda d, p: open(p, "w").close() or p),
              mock.patch.object(SW, "check_sb_config", return_value=(True, "")),
              mock.patch.object(SW, "SB_CONF", os.path.join(tempfile.mkdtemp(prefix="sw24-"), "config.json")),
              mock.patch.object(SW, "snapshot_selections"),
              mock.patch.object(SW, "write_core_file"), mock.patch.object(SW, "svc_restart"),
              mock.patch.object(SW, "set_manual_stop"), mock.patch.object(SW, "core_alive", return_value=False),
              mock.patch.object(SW, "sh", return_value=(0, "")), mock.patch.object(SW.time, "sleep"),
              mock.patch.object(SW, "notify"), mock.patch.object(SW, "_cu")]
        for p in ps:
            p.start()
        try:
            SW.core_switch_job("singbox", "")
        finally:
            for p in reversed(ps):
                p.stop()
        return state["d"]

    def test_rollback_removes_auto_block_bypass(self):
        d = self._run({"core": "mihomo", "subs": [], "dns": {"mode": "fake-ip"}})
        self.assertFalse(SW.CORE_UPD["ok"])
        self.assertEqual(d["core"], "mihomo")
        self.assertNotIn("block_bypass", d["dns"])

    def test_rollback_restores_previous_value(self):
        d = self._run({"core": "mihomo", "subs": [], "dns": {"mode": "fake-ip", "block_bypass": False}})
        self.assertEqual(d["core"], "mihomo")
        self.assertIs(d["dns"]["block_bypass"], False)


class OverallTimeoutTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="to24-")
        self.stop = threading.Event()

    def tearDown(self):
        self.stop.set()
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_rule_set_overall_timeout(self):
        class Opener:
            def open(s, *a, **k):
                self.stop.wait(5)
                raise IOError("late")
        need = {f"r{i}": {"kind": "srs", "path": f"r{i}.srs", "url": f"https://x.example/r{i}.srs"} for i in range(3)}
        with mock.patch.object(SBC, "SB_RULE_DIR", self.dir), mock.patch.object(SBC, "ASSETS_WAIT", 0.3), \
                mock.patch.object(SBC, "core_alive", return_value=False), mock.patch.object(SBC, "dl_check"), \
                mock.patch.object(SBC, "proxy_opener", return_value=Opener()):
            bad = SBC.sb_sync_assets({}, need=need)
        self.assertEqual(sorted(bad), [f"r{i}：下载超时" for i in range(3)])

    def test_adblock_overall_timeout(self):
        lists = [{"id": "l1", "name": "慢列表", "url": "https://x.example/1", "enabled": True},
                 {"id": "l2", "name": "快列表", "url": "https://x.example/2", "enabled": True}]

        def fetch(l, late=None):
            if l["id"] == "l1":
                self.stop.wait(5)
                raise IOError("late")
            return {"count": 1, "allow": 0, "skipped": 0, "updated": 1, "error": ""}
        with mock.patch.object(AB, "AB_DIR", self.dir), mock.patch.object(AB, "AB_WAIT", 0.3), \
                mock.patch.object(AB, "load", return_value={"adblock": {"lists": lists}}), \
                mock.patch.object(AB, "ab_fetch", side_effect=fetch), mock.patch.object(AB, "ab_compose"):
            ok, msg = AB.adblock_update(apply=False)
        self.assertFalse(ok)
        self.assertIn("慢列表", msg)
        self.assertNotIn("快列表", msg)
        with open(os.path.join(self.dir, "meta.json")) as f:
            meta = json.load(f)
        self.assertEqual(meta["l1"]["error"], "下载超时")
        self.assertEqual(meta["l2"]["error"], "")


class LiveLogTest(unittest.TestCase):
    def test_live_render_throttled(self):
        with open(os.path.join(ROOT, "web", "js", "15-logs.js"), encoding="utf-8") as f:
            js = f.read()
        self.assertIn("LIVE_MS=250", js)
        self.assertIn("LIVE_MAX=800", js)


if __name__ == "__main__":
    unittest.main()
