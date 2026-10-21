"""v10.3.1：sing-box 订阅更新后推进订阅节点名单版本、按设备分流在核心重启（--gen）后与实际配置保持一致、
订阅自动更新出错不再吞掉当天的定点任务、按设备分流删除条目后编辑序号调整"""
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tests.helper import server
from tests.test_v840 import base, write_sb_cache

assert server

B = sys.modules["shunt.base"]
G = sys.modules["shunt.groups"]
DR = sys.modules["shunt.devroute"]
SBC = sys.modules["shunt.sb_config"]
SBS = sys.modules["shunt.sb_subs"]
SCH = sys.modules["shunt.schedule"]
DA = sys.modules["shunt.data"]
WA = sys.modules["shunt.webapi"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAC = "aa:bb:cc:dd:ee:31"


class VersionTest(unittest.TestCase):
    def test_version(self):
        self.assertEqual(B.PANEL_VERSION, "10.3.1")

    def test_changelog_top(self):
        with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as f:
            heads = [ln for ln in f if ln.startswith("## v")]
        self.assertTrue(heads[0].startswith("## v10.3.1"), heads[0])


class SbProviderRevTest(unittest.TestCase):
    """sing-box：订阅更新后节点名单变化要推进 provider_rev()，/api/state 的策略组缓存才会失效"""

    def setUp(self):
        self.orig = server.load()
        self.prov = dict(G.PROV)
        d = base("singbox")
        server.save(d)
        write_sb_cache()
        WA._GRP_CACHE.clear()

    def tearDown(self):
        server.save(self.orig)
        G.PROV.clear()
        G.PROV.update(self.prov)
        WA._GRP_CACHE.clear()

    def fake_fetch(self, s, gh=""):
        nodes = [{"name": n, "type": "ss", "server": "10.9.0.1", "port": 8388, "cipher": "aes-128-gcm", "password": "p"}
                 for n in ("JP 02 Tokyo", "🇯🇵 日本 99")]
        DA.write_json(G.sub_cache_path(s["name"]), {"name": s["name"], "updated": 2, "nodes": nodes})
        return len(nodes), "ok"

    def test_update_bumps_rev_and_state_groups(self):
        G.provider_nodes(fresh=True)
        rev = G.provider_rev()
        d = server.load()
        groups0, _ = WA.state_groups(d)
        with mock.patch.object(SBS, "sb_fetch_sub", side_effect=self.fake_fetch):
            okl, bad = SBS.sb_update_subs(["B"], d)
        self.assertEqual(bad, [])
        G.provider_nodes()  # 缓存已过期：重新读取，名单变了
        self.assertGreater(G.provider_rev(), rev)
        groups1, _ = WA.state_groups(server.load())
        self.assertTrue(any("台湾" in g for g in groups0))
        self.assertFalse(any("台湾" in g for g in groups1))  # 唯一的台湾节点没了：地区组跟着消失

    def test_build_singbox_bumps_rev(self):
        G.provider_nodes(fresh=True)
        rev = G.provider_rev()
        self.fake_fetch({"name": "A"})
        SBC.build_singbox(server.load())  # 生成配置时按最新缓存写名单：同样要推进版本
        self.assertGreater(G.provider_rev(), rev)
        rev2 = G.provider_rev()
        SBC.build_singbox(server.load())  # 名单没变：不推进
        self.assertEqual(G.provider_rev(), rev2)


class DevrouteAppliedTest(unittest.TestCase):
    """核心每次启动前 init.d 跑 --gen（另一个进程）重写配置和已应用记录：面板要按文件里的记录比较；
    本进程没见过的设备沿用记录里的 IP"""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="dr1031-")
        self.saved = dict(DR.STATE)
        self.seen = dict(DR.SEEN)
        DR.SEEN.clear()
        DR._LOGGED.clear()
        DR.STATE.update(last=None, applied=None, loaded=False, stamp=None)
        self.arp = {}
        ps = [mock.patch.object(DR, "APPLIED_FILE", os.path.join(self.dir, "applied.json")),
              mock.patch.object(DR, "arp_table", lambda: dict(self.arp)),
              mock.patch.object(DR, "neigh6", lambda: {})]
        for p in ps:
            p.start()
            self.addCleanup(p.stop)
        self.d = copy.deepcopy(server.load())
        self.d.update(rules=[], device_routes=[{"name": "tv", "ip": "", "mac": MAC, "target": "DIRECT", "enabled": True}])

    def tearDown(self):
        DR.STATE.clear()
        DR.STATE.update(self.saved)
        DR.SEEN.clear()
        DR.SEEN.update(self.seen)
        shutil.rmtree(self.dir, ignore_errors=True)

    def write_file(self, sig):
        tmp = DR.APPLIED_FILE + ".x"
        with open(tmp, "w") as f:
            json.dump(sig, f)
        os.replace(tmp, DR.APPLIED_FILE)

    def dev_rules(self):
        return [r for r in server.build_config(self.d)["rules"] if r.startswith("SRC-IP-CIDR,")]

    def test_external_rewrite_is_reread(self):
        self.arp["192.168.1.20"] = MAC
        server.build_config(self.d)
        DR.mark_applied()
        self.assertIsNone(DR.mac_changed(self.d))
        self.write_file({MAC: []})  # --gen 进程写的配置里没有这台设备
        self.assertEqual(DR.applied_sig(), {MAC: []})
        self.assertEqual(DR.mac_changed(self.d), {MAC: ["192.168.1.20"]})  # 与实际配置不同：需要重载

    def test_new_process_keeps_applied_ip_for_sleeping_device(self):
        self.write_file({MAC: ["192.168.1.20"]})  # 正式配置里已有这台设备；新进程 SEEN 为空，设备此刻不在 ARP 表
        self.assertEqual(self.dev_rules(), ["SRC-IP-CIDR,192.168.1.20/32,DIRECT"])
        self.assertIsNone(DR.mac_changed(self.d))  # 不会因为面板重启而丢规则、重载核心

    def test_applied_ip_taken_by_other_device(self):
        self.write_file({MAC: ["192.168.1.20"]})
        self.arp["192.168.1.20"] = "11:22:33:44:55:66"
        self.assertEqual(self.dev_rules(), [])

    def test_arp_wins_over_applied(self):
        self.write_file({MAC: ["192.168.1.20"]})
        self.arp["192.168.1.30"] = MAC
        self.assertEqual(self.dev_rules(), ["SRC-IP-CIDR,192.168.1.30/32,DIRECT"])
        self.assertEqual(DR.mac_changed(self.d), {MAC: ["192.168.1.30"]})

    def test_bad_applied_file(self):
        self.write_file({MAC: "x"})
        self.assertEqual(self.dev_rules(), [])


class _Stop(BaseException):
    pass


class SchedSubsErrorTest(unittest.TestCase):
    """sing-box 订阅自动更新后刷新地区组出错：只记日志，本轮的定点任务照常执行"""

    def test_due_tasks_still_run(self):
        d = base("singbox")
        ran = []
        sleeps = iter([None])

        def sleep(_):
            try:
                next(sleeps)
            except StopIteration:
                raise _Stop()

        with mock.patch.object(SCH.time, "sleep", side_effect=sleep), mock.patch.object(SCH, "load", return_value=d), \
                mock.patch.object(SCH, "daily_due", side_effect=lambda k, *a: k == "core_restart"), \
                mock.patch.object(SCH, "sb_sub_cache", return_value={}), \
                mock.patch.object(SCH, "sb_update_subs", return_value=(["A"], [])), \
                mock.patch.object(SCH, "refresh_regions", side_effect=RuntimeError("boom")), \
                mock.patch.object(SCH, "log_err"), mock.patch.object(SCH, "bg_meta", return_value={}), \
                mock.patch.object(SCH, "run_task", side_effect=lambda k: ran.append(k) or (True, "ok")), \
                mock.patch.object(SCH, "sched_event"), mock.patch.dict(SCH.SCHED["done"], clear=True):
            with self.assertRaises(_Stop):
                SCH.sched_loop()
        self.assertIn("core_restart", ran)


class FrontendTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "需要 node")
    def test_dr_delete_keeps_edit_index(self):
        out = subprocess.run(["node", os.path.join(ROOT, "tests", "v1031_frontend.js"), ROOT], capture_output=True, text=True, timeout=30)
        self.assertFalse(out.stdout.startswith("ERR"), out.stdout + out.stderr)
        j = json.loads(out.stdout)
        self.assertEqual(j["edit_after_del_before"], 1)
        self.assertEqual(j["list1"], ["b|G1", "c2|DIRECT"])  # 改的是原来的 c，没有多出一条
        self.assertEqual(j["edit_after_del_self"], -1)
        self.assertEqual(j["form"], "")
        self.assertEqual(j["edit_after_fail"], 1)


if __name__ == "__main__":
    unittest.main()
