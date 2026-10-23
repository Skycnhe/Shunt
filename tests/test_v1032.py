"""v10.3.2：同步 Hk001 v8.4.5 / v8.4.6 的修复（按 Hk002 代码适配），并关闭 mihomo 的 store-fake-ip。

v8.4.5：改订阅链接后 mihomo 仍用旧缓存、编辑订阅后顺序变化、版本备份恢复后不重启 / 前端判断错字段、手动停止时更新内核把核心拉起、
节点全超时通知误报、广告拦截列表连续修改互相覆盖、概览快速切换按序号、内核更新复查不带内核参数、sing-box 定时更新 GEO 重载失败的提示。
v8.4.6：下载被截断、背景图并发写坏、恢复设置 / 快照 / 版本备份改订阅不清缓存、版本备份恢复与在线更新并发、改筛选后订阅只剩已删节点、
非对象请求体 / 字段类型错误回 500、无 PyYAML 时锚点节点丢失、背景大图显示前缩小"""
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock

from tests.helper import server
from tests.test_v1012 import ApiCase
from tests.test_v840 import base

assert server

B = sys.modules["shunt.base"]
BK = sys.modules["shunt.backup"]
CU = sys.modules["shunt.core_update"]
SW = sys.modules["shunt.sb_switch"]
N = sys.modules["shunt.notify"]
SC = sys.modules["shunt.schedule"]
M = sys.modules["shunt.mihomo"]
LT = sys.modules["shunt.latency"]
SBS = sys.modules["shunt.sb_subs"]
YL = sys.modules["shunt.sb_yaml"]
WA = sys.modules["shunt.webapi"]
D = sys.modules["shunt.data"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class VersionTest(unittest.TestCase):
    def test_version(self):
        self.assertEqual(B.PANEL_VERSION, "10.3.2")

    def test_changelog_top(self):
        with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as f:
            heads = [ln for ln in f if ln.startswith("## v")]
        self.assertTrue(heads[0].startswith("## v10.3.2"), heads[0])


class StoreFakeIpTest(unittest.TestCase):
    """mihomo store-fake-ip:true 时热重载会丢掉旧的 fake-ip 映射（Hk002 保存设置、MAC 变化都热重载）：改为 false"""

    def test_mihomo_profile(self):
        for mode in ("fake-ip", "redir-host"):
            d = base()
            d["dns"] = dict(d["dns"], mode=mode)
            prof = M.build_config(d)["profile"]
            self.assertIs(prof["store-fake-ip"], False)
            self.assertIs(prof["store-selected"], True)  # 节点选择照常在重启后保持

    def test_smart_profile(self):
        d = base(core="smart")
        d["dns"] = dict(d["dns"], mode="fake-ip")
        self.assertIs(M.build_config(d)["profile"]["store-fake-ip"], False)

    def test_singbox_cache_unchanged(self):
        """sing-box 的 cache_file.store_fakeip 不受影响（sing-box 热重载 / 重启的行为与 mihomo 不同，本次不改）"""
        d = base(core="singbox")
        d["dns"] = dict(d["dns"], mode="fake-ip")
        cf = server.build_singbox(d)[0]["experimental"]["cache_file"]
        self.assertTrue(cf["store_fakeip"])


class SubRefetchHk002Test(ApiCase):
    """Hk002：恢复后 sing-box 只用 sb_update_subs 下载变化的订阅，不走 schedule.subs_update（它会 refresh_regions 先重载一次），
    随后由 reload_core 统一重载；按设备分流等 Hk002 独有设置随恢复保留"""

    def setUp(self):
        super().setUp()
        server.save(base(core="singbox"))
        self.p = [mock.patch.object(WA, "reload_core", return_value=(True, "ok")),
                  mock.patch.object(WA, "active_core", side_effect=lambda *a: "singbox"),
                  mock.patch.object(WA, "tp_apply", return_value=(0, "")),
                  mock.patch.object(WA, "ab_compose"),
                  mock.patch.object(WA, "subs_update"),
                  mock.patch.object(WA, "refresh_regions"),
                  mock.patch.object(WA, "sb_update_subs", return_value=([], ["A：下载超时"]))]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()
        super().tearDown()

    def test_restore_singbox(self):
        subs = [{"name": "A", "url": "https://new.example/s", "filter": "", "exclude": ""},
                {"name": "B", "url": "https://b.example/s", "filter": "", "exclude": ""}]
        dr = [{"name": "电视", "ip": "192.168.1.50", "target": "DIRECT", "enabled": True}]
        code, j = self.call("POST", "/api/restore", {"subs": subs, "device_routes": dr})
        self.assertEqual(code, 200, j)
        WA.sb_update_subs.assert_called_once()
        self.assertEqual(WA.sb_update_subs.call_args[0][0], ["A"])
        WA.subs_update.assert_not_called()
        WA.refresh_regions.assert_not_called()
        WA.reload_core.assert_called_once()
        self.assertIn("订阅下载失败", j["message"])  # 下载失败如实提示，恢复本身照常完成
        self.assertEqual([x["name"] for x in server.load()["device_routes"]], ["电视"])

    def test_mihomo_no_refetch(self):
        with mock.patch.object(WA, "active_core", sys.modules["shunt.sb_common"].active_core):
            self.assertEqual(WA.sub_refetch(["A"], base()), "")  # 按传入数据里的内核判断（base() 是 mihomo）
            self.assertEqual(WA.sub_refetch([], base(core="singbox")), "")
        WA.sb_update_subs.assert_not_called()




def js_src(*files):
    out = ""
    for f in files:
        with open(os.path.join(ROOT, "web", "js", f), encoding="utf-8") as fh:
            out += fh.read() + "\n"
    return out


def run_node(js):
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise AssertionError(r.stderr)
    return json.loads(r.stdout)


class DeviceRouteBodyTest(ApiCase):
    """Hk002 独有的按设备分流：字段类型错误同样回 400，不写进 data.json"""

    def test_bad_shapes(self):
        before = server.load().get("device_routes")
        for v in ("x", [1], {"a": 1}):
            code, j = self.call("PUT", "/api/settings", {"device_routes": v})
            self.assertEqual(code, 400, (v, j))
        self.assertEqual(server.load().get("device_routes"), before)


class SubProviderCacheTest(ApiCase):
    """改了订阅链接 / 删除订阅：删掉 mihomo 的 ./providers/<名>.yaml（mihomo 有本地文件就先用，等满间隔才下载新链接）；
    编辑订阅时留在原位置"""

    def setUp(self):
        super().setUp()
        server.save(base())
        self.pdir = os.path.join(B.CONF_DIR, "providers")
        os.makedirs(self.pdir, exist_ok=True)
        for n in ("A", "B"):
            with open(os.path.join(self.pdir, n + ".yaml"), "w") as f:
                f.write("proxies: []\n")
        self.p = [mock.patch.object(WA, "reload_core", return_value=(True, "ok")),
                  mock.patch.object(WA, "active_core", return_value="mihomo"),
                  mock.patch.object(WA, "refresh_after_sub")]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()
        for n in ("A", "B"):
            try:
                os.remove(os.path.join(self.pdir, n + ".yaml"))
            except OSError:
                pass
        super().tearDown()

    def cached(self, n):
        return os.path.isfile(os.path.join(self.pdir, n + ".yaml"))

    def test_edit_same_url_keeps_cache_and_position(self):
        masked = WA.mask_url("https://a.example/s")  # 编辑表单提交回来的是打码后的链接
        code, j = self.call("POST", "/api/subs", {"name": "A", "url": masked, "filter": "HK", "exclude": ""})
        self.assertEqual(code, 200, j)
        d = server.load()
        self.assertEqual([s["name"] for s in d["subs"]], ["A", "B"])  # 以前被挪到末尾：B, A
        self.assertEqual(d["subs"][0]["url"], "https://a.example/s")
        self.assertEqual(d["subs"][0]["filter"], "HK")
        self.assertTrue(self.cached("A"))

    def test_edit_new_url_drops_cache(self):
        code, j = self.call("POST", "/api/subs", {"name": "A", "url": "https://new.example/s2", "filter": "", "exclude": ""})
        self.assertEqual(code, 200, j)
        self.assertFalse(self.cached("A"))
        self.assertTrue(self.cached("B"))
        self.assertEqual([s["name"] for s in server.load()["subs"]], ["A", "B"])

    def test_edit_keeps_removed(self):
        d = server.load()
        d["subs"][1]["removed"] = ["TW 01"]
        server.save(d)
        code, j = self.call("POST", "/api/subs", {"name": "B", "url": "https://b.example/s", "filter": "x", "exclude": ""})
        self.assertEqual(code, 200, j)
        subs = server.load()["subs"]
        self.assertEqual([s["name"] for s in subs], ["A", "B"])
        self.assertEqual(subs[1]["removed"], ["TW 01"])

    def test_new_sub_appended_and_stale_cache_dropped(self):
        with open(os.path.join(self.pdir, "C.yaml"), "w") as f:  # 以前删掉的同名订阅留下的缓存
            f.write("proxies: []\n")
        code, j = self.call("POST", "/api/subs", {"name": "C", "url": "https://c.example/s", "filter": "", "exclude": ""})
        self.assertEqual(code, 200, j)
        self.assertEqual([s["name"] for s in server.load()["subs"]], ["A", "B", "C"])
        self.assertFalse(self.cached("C"))

    def test_delete_drops_cache(self):
        code, j = self.call("DELETE", "/api/subs", {"name": "B"})
        self.assertEqual(code, 200, j)
        self.assertEqual([s["name"] for s in server.load()["subs"]], ["A"])
        self.assertFalse(self.cached("B"))
        self.assertTrue(self.cached("A"))

    def test_delete_failed_reload_keeps_cache(self):
        WA.reload_core.return_value = (False, "bad")
        code, _ = self.call("DELETE", "/api/subs", {"name": "B"})
        self.assertEqual(code, 500)
        self.assertTrue(self.cached("B"))


class VersionRestoreRestartTest(ApiCase):
    """版本备份恢复程序文件后自动重启面板，接口返回 restart；数据无效时什么都不动、不重启"""

    def setUp(self):
        super().setUp()
        self.dir = tempfile.mkdtemp(prefix="bk845-")
        self.base = tempfile.mkdtemp(prefix="base845-")
        for fn in ("server.py", "index.html"):
            with open(os.path.join(self.base, fn), "w") as f:
                f.write("cur")
        self.p = [mock.patch.object(BK, "BACKUP_DIR", self.dir), mock.patch.object(BK, "BASE", self.base),
                  mock.patch.object(WA, "reload_core", return_value=(True, "ok")),
                  mock.patch.object(WA, "tp_apply", return_value=(0, "")),
                  mock.patch.object(WA, "restart_self"),
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
        name = "shunt-backup-v9.9.8-20260101-000001.tar.gz"
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

    def test_success_restarts(self):
        name = self._mk(server.load())
        code, j = self.call("POST", "/api/backup/restore", {"name": name})
        self.assertEqual(code, 200, j)
        self.assertTrue(j["ok"])
        self.assertTrue(j["restart"])
        self.assertIn("面板正在重启", j["message"])
        self.assertNotIn("需重启面板", j["message"])
        WA.restart_self.assert_called_once()
        with open(os.path.join(self.base, "server.py")) as f:
            self.assertEqual(f.read(), "old")

    def test_reload_fail_still_restarts(self):
        """设置被撤销但程序文件已换：仍要重启（否则前后端不配套），返回 200 让前端刷新"""
        WA.reload_core.return_value = (False, "boom")
        name = self._mk(server.load())
        code, j = self.call("POST", "/api/backup/restore", {"name": name})
        self.assertEqual(code, 200, j)
        self.assertFalse(j["ok"])
        self.assertTrue(j["restart"])
        self.assertIn("设置已撤销", j["message"])
        WA.restart_self.assert_called_once()

    def test_invalid_no_restart(self):
        name = self._mk(dict(server.load(), rulesets="notalist"))
        code, j = self.call("POST", "/api/backup/restore", {"name": name})
        self.assertEqual(code, 500, j)
        self.assertFalse(j.get("restart"))
        WA.restart_self.assert_not_called()


class CoreUpdateManualStopTest(unittest.TestCase):
    """核心被手动停止时，更新 / 回滚内核只替换程序，不调用 svc_restart 把核心拉起来"""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cu845-")
        self.bin = os.path.join(self.dir, "mihomo")
        with open(self.bin, "w") as f:
            f.write("old")
        self.new = self.bin + ".new"
        with open(self.new, "w") as f:
            f.write("new")
        self.ms = N.WD["manual_stop"]
        self.upd = dict(CU.CORE_UPD, log=None)

    def tearDown(self):
        N.WD["manual_stop"] = self.ms
        CU.CORE_UPD.update({k: v for k, v in self.upd.items() if k != "log"})
        shutil.rmtree(self.dir, ignore_errors=True)

    def swap(self, manual):
        N.WD["manual_stop"] = manual
        with mock.patch.object(CU, "mh_bin", return_value=self.bin), mock.patch.object(CU, "active_core", return_value="mihomo"), \
                mock.patch.object(CU, "svc_restart", return_value=(0, "")) as rs, mock.patch.object(CU, "core_alive", return_value=True), \
                mock.patch.object(CU.time, "sleep"):
            res = CU._core_swap_and_restart(self.new, "v9", "mihomo")
        return res, rs

    def test_manual_stop_no_restart(self):
        (ok, note), rs = self.swap(True)
        self.assertTrue(ok)
        self.assertEqual(note, CU.MANUAL_NOTE)
        rs.assert_not_called()
        with open(self.bin) as f:
            self.assertEqual(f.read(), "new")
        with open(self.bin + ".bak") as f:
            self.assertEqual(f.read(), "old")

    def test_running_restarts(self):
        (ok, note), rs = self.swap(False)
        self.assertTrue(ok)
        self.assertEqual(note, "")
        rs.assert_called_once()

    def test_rollback_job_message(self):
        N.WD["manual_stop"] = True
        with open(self.bin + ".bak", "w") as f:
            f.write("bak")
        with mock.patch.object(CU, "mh_bin", return_value=self.bin), mock.patch.object(CU, "active_core", return_value="mihomo"), \
                mock.patch.object(CU, "bin_version", side_effect=lambda p: "v-old" if p.endswith(".bak") else "v-cur"), \
                mock.patch.object(CU, "svc_restart") as rs:
            CU.core_rollback_job("mihomo")
        rs.assert_not_called()
        self.assertTrue(CU.CORE_UPD["ok"])
        self.assertIn("手动停止", CU.CORE_UPD["message"])

    def test_sb_update_job(self):
        N.WD["manual_stop"] = True
        with mock.patch.object(SW, "sb_version", return_value="1.0"), mock.patch.object(SW, "sb_install", return_value=("1.1", True)), \
                mock.patch.object(SW, "active_core", return_value="singbox"), \
                mock.patch.object(SW, "check_sb_config", return_value=(True, "")) as chk, \
                mock.patch.object(SW, "svc_restart") as rs:
            SW.sb_update_job("stable", "")
        chk.assert_called_once()  # 配置兼容性照常检查
        rs.assert_not_called()
        self.assertTrue(CU.CORE_UPD["ok"])
        self.assertIn("手动停止", CU.CORE_UPD["message"])


class SbRollbackManualStopTest(ApiCase):
    def setUp(self):
        super().setUp()
        self.dir = tempfile.mkdtemp(prefix="sb845-")
        self.bin = os.path.join(self.dir, "sing-box")
        for p, t in ((self.bin, "cur"), (self.bin + ".bak", "bak")):
            with open(p, "w") as f:
                f.write(t)
        self.ms = N.WD["manual_stop"]

    def tearDown(self):
        N.WD["manual_stop"] = self.ms
        WA.CORE_UPD["busy"] = False
        shutil.rmtree(self.dir, ignore_errors=True)
        super().tearDown()

    def test_no_restart_when_stopped(self):
        N.WD["manual_stop"] = True
        with mock.patch.object(WA, "SB_BIN", self.bin), mock.patch.object(WA, "active_core", return_value="singbox"), \
                mock.patch.object(WA, "sb_version", return_value="1.0"), mock.patch.object(WA, "svc_restart") as rs:
            code, j = self.call("POST", "/api/coreupdate", {"action": "rollback", "core": "singbox"})
        self.assertEqual(code, 200, j)
        rs.assert_not_called()
        self.assertIn("手动停止", j["message"])
        with open(self.bin) as f:
            self.assertEqual(f.read(), "bak")


class CheckNodesNotifyTest(unittest.TestCase):
    """核心没应答（502 等）不是测速结论，不发「所有节点均测速超时」；504（mihomo 全部超时）照常通知"""

    def run_check(self, code, raw, st=None):
        d = dict(server.load(), tg_token="t", tg_chat="c", mode="rule")
        with mock.patch.object(N, "load", return_value=d), mock.patch.object(N, "core_json", return_value={"type": "Selector"}), \
                mock.patch.object(N, "core", return_value=(code, raw)), mock.patch.object(N, "load_notified", return_value=dict(st or {})), \
                mock.patch.object(N, "write_json") as wj, mock.patch.object(N, "notify") as nt:
            N.check_nodes()
        return wj, nt

    def test_core_unreachable_no_alarm(self):
        wj, nt = self.run_check(502, b'{"message":"mihomo \\u672a\\u8fd0\\u884c"}')
        nt.assert_not_called()
        wj.assert_not_called()

    def test_unreachable_does_not_clear_alarm(self):
        wj, nt = self.run_check(502, b"{}", {"allnodes": True})
        nt.assert_not_called()  # 以前不会误发「已恢复」，但会先误发「全部超时」；这里状态保持不变
        wj.assert_not_called()

    def test_504_all_timeout(self):
        wj, nt = self.run_check(504, b'{"message":"get delay: all proxies timeout"}')
        nt.assert_called_once()
        self.assertIn("超时", nt.call_args[0][0])

    def test_200_some_ok(self):
        wj, nt = self.run_check(200, b'{"n1": 120, "n2": 0}', {"allnodes": True})
        nt.assert_called_once()
        self.assertIn("恢复", nt.call_args[0][0])

    def test_200_garbage(self):
        wj, nt = self.run_check(200, b"not json")
        nt.assert_not_called()


class SbGeoTaskMessageTest(unittest.TestCase):
    def test_reload_fail_message(self):
        d = base(core="singbox")
        with mock.patch.object(SC, "load", return_value=d), mock.patch.object(SC, "active_core", return_value="singbox"), \
                mock.patch.object(SC, "sb_sync_assets", return_value=[]), mock.patch.object(SC, "reload_core", return_value=(False, "boom")):
            ok, msg = SC.run_task("geo_update")
        self.assertFalse(ok)
        self.assertIn("重载核心失败", msg)
        self.assertIn("boom", msg)

    def test_ok_and_partial(self):
        d = base(core="singbox")
        with mock.patch.object(SC, "load", return_value=d), mock.patch.object(SC, "active_core", return_value="singbox"), \
                mock.patch.object(SC, "sb_sync_assets", return_value=[]), mock.patch.object(SC, "reload_core", return_value=(True, "ok")):
            self.assertEqual(SC.run_task("geo_update"), (True, "GEO / 规则集已更新"))
        with mock.patch.object(SC, "load", return_value=d), mock.patch.object(SC, "active_core", return_value="singbox"), \
                mock.patch.object(SC, "sb_sync_assets", return_value=["geosite-x：超时"]), mock.patch.object(SC, "reload_core", return_value=(True, "ok")):
            ok, msg = SC.run_task("geo_update")
        self.assertFalse(ok)
        self.assertIn("部分规则集更新失败", msg)


@unittest.skipUnless(shutil.which("node"), "需要 node")
class FrontendTest(unittest.TestCase):
    STUB = """const els={};const document={documentElement:{dataset:{}},addEventListener(){},querySelectorAll(){return []},hidden:false,
  querySelector(s){return els[s]||(els[s]={value:'',innerHTML:'',textContent:'',checked:false,disabled:false,
  classList:{toggle(){},add(){},remove(){},contains(){return false}},style:{},querySelector(){return {textContent:''}}})}};
const localStorage={getItem(){return null},setItem(){}};
let TOASTS=[],CALLS=[],TIMERS=[];const confirm=()=>true;const setTimeout=(f,ms)=>{TIMERS.push(ms);return 0};const clearTimeout=()=>{};
"""

    def test_adblock_busy_blocks_stale_list(self):
        js = self.STUB + "let API_RES=null;const api=(p,m,b)=>{CALLS.push([p,m,b]);return new Promise(r=>{API_RES=r})};\n" + \
            js_src("00-core.js", "12-adblock.js") + """
toast=t=>TOASTS.push(t);
let RENDERS=0;renderAB=()=>{RENDERS++};
let SERVER=null;loadAB=async()=>{AB=JSON.parse(JSON.stringify(SERVER))};
AB={lists:[{id:'a',name:'A',url:'https://a/1',enabled:true},{id:'b',name:'B',url:'https://b/2',enabled:true}],presets:[]};
(async()=>{
  abToggle(0,false);                       // 第一次保存进行中（重载核心要几秒）
  const n1=CALLS.length;
  abToggle(1,false);abDel(1);abAdd();       // 期间再改：拦住，不提交旧列表
  const n2=CALLS.length,blocked=TOASTS.filter(t=>t.includes('稍候')).length;
  SERVER={lists:[{id:'a',name:'A',url:'https://a/1',enabled:false},{id:'b',name:'B',url:'https://b/2',enabled:true}],presets:[]};
  API_RES({message:'已保存并生效'});await new Promise(r=>process.nextTick(r));await new Promise(r=>process.nextTick(r));
  await new Promise(r=>process.nextTick(r));
  abToggle(1,false);                       // 保存完成后再改：基于最新列表
  console.log(JSON.stringify({n1,n2,blocked,renders:RENDERS,first:CALLS[0][2].lists,second:CALLS[1][2].lists}));
})();"""
        out = run_node(js)
        self.assertEqual(out["n1"], 1)
        self.assertEqual(out["n2"], 1)
        self.assertEqual(out["blocked"], 3)
        self.assertGreaterEqual(out["renders"], 2)  # 被拦住的开关重画回原状态
        self.assertEqual([x["enabled"] for x in out["first"]], [False, True])
        self.assertEqual([x["enabled"] for x in out["second"]], [False, False])  # 第一次的修改没有被改回去

    def test_qs_pick_by_name(self):
        js = self.STUB + "const api=async()=>({});const core=async(p,m,b)=>{CALLS.push([p,m,b]);return {}};\n" + \
            js_src("00-core.js", "04-overview.js") + """
toast=t=>TOASTS.push(t);
loadQS=()=>{};
PROXIES={'🚀 节点选择':{all:['🇭🇰 香港竞技','🇯🇵 日本竞技'],now:'🇭🇰 香港竞技'}};
(async()=>{await qsPick('🇯🇵 日本竞技');await qsPick(1);console.log(JSON.stringify(CALLS))})();"""
        out = run_node(js)
        self.assertEqual(len(out), 1)  # 旧式序号参数不再被当成节点
        self.assertEqual(out[0][2], {"name": "🇯🇵 日本竞技"})
        src = js_src("04-overview.js")
        self.assertIn('onclick="qsPick(${jsq(n)})"', src)

    def test_restore_backup_ui(self):
        js = self.STUB + "let MODE='ok';const api=async(p,m,b)=>{CALLS.push([p,m,b]);if(MODE==='err')throw new Error('备份里的设置无效，未恢复');" + \
            "return {message:'已恢复；面板正在重启',ok:true,restart:true}};\n" + js_src("00-core.js", "28-backup.js") + """
toast=t=>TOASTS.push(t);
let LOADS=0;loadBackups=()=>{LOADS++};
(async()=>{await restoreBackup('x.tar.gz');const t1=TIMERS.slice();MODE='err';await restoreBackup('x.tar.gz');
console.log(JSON.stringify({t1,toasts:TOASTS,loads:LOADS}))})();"""
        out = run_node(js)
        self.assertEqual(out["t1"], [5000])  # 面板重启后刷新页面
        self.assertIn("恢复失败：备份里的设置无效，未恢复", out["toasts"])
        self.assertEqual(out["loads"], 1)

    def test_core_poll_passes_kind(self):
        src = js_src("21-coreswitch.js")
        i = src.index("function corePoll")
        seg = src[i:src.index("\n", src.index("if(j.ok)", i))]
        self.assertRegex(seg, r"/api/coreupdate\?channel='\+coreCh\(\)\+'&core='\+coreKind\(\)")


class DropProviderCacheTest(unittest.TestCase):
    def test_safe_name(self):
        pdir = os.path.join(B.CONF_DIR, "providers")
        os.makedirs(pdir, exist_ok=True)
        p = os.path.join(pdir, "机场_A.yaml")
        with open(p, "w") as f:
            f.write("x")
        self.assertTrue(M.drop_provider_cache("机场 A"))
        self.assertFalse(os.path.exists(p))
        self.assertFalse(M.drop_provider_cache("机场 A"))
        # 与生成配置里的 provider path 一致
        d = base()
        d["subs"] = [{"name": "机场 A", "url": "https://a.example/s", "filter": "", "exclude": ""}]
        self.assertEqual(M.build_config(d)["proxy-providers"]["机场 A"]["path"], "./providers/" + os.path.basename(p))




class FakeResp:
    """模拟 http.client 的 read(n)：对方中途断开时只返回收到的部分，length 留下没收到的字节数"""

    def __init__(self, data, declared=None):
        self.data, self.length = data, (declared if declared is not None else len(data))
        self.headers = {}

    def read(self, n=-1):
        out = self.data[:n] if n >= 0 else self.data
        self.data = self.data[len(out):]
        if self.length is not None:
            self.length -= len(out)
        return out

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class ReadFullTest(unittest.TestCase):
    def test_complete(self):
        self.assertEqual(B.read_full(FakeResp(b"abc"), 10), b"abc")

    def test_no_length(self):
        r = FakeResp(b"abc")
        r.length = None  # 没有 Content-Length：无法判断，照常返回
        self.assertEqual(B.read_full(r, 10), b"abc")

    def test_truncated_raises(self):
        with self.assertRaises(IOError):
            B.read_full(FakeResp(b"abc", declared=100), 1000)

    def test_over_limit_not_truncation(self):
        self.assertEqual(B.read_full(FakeResp(b"x" * 20), 11), b"x" * 11)  # 超过上限由调用方按长度判断


JPEG = b"\xff\xd8\xff\xe0" + b"j" * 200 + b"\xff\xd9"


class BgTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bg846-")
        self.p = mock.patch.object(LT, "BG_FILE", os.path.join(self.tmp, "bg.img"))
        self.p.start()

    def tearDown(self):
        self.p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def opener(self, resp):
        o = mock.Mock()
        o.open.side_effect = lambda *a, **k: resp()
        return o

    def test_truncated_download_rejected(self):
        """以前只收到一半也当成功保存：浏览器只画出上半截"""
        with mock.patch.object(LT, "dl_check"), \
                mock.patch.object(LT, "proxy_opener", return_value=self.opener(lambda: FakeResp(JPEG[:100], declared=len(JPEG)))):
            ok, msg = LT.bg_fetch("https://img.example/a.jpg")
        self.assertFalse(ok)
        self.assertIn("不完整", msg)
        self.assertFalse(os.path.exists(LT.BG_FILE))

    def test_complete_download_saved(self):
        with mock.patch.object(LT, "dl_check"), mock.patch.object(LT, "proxy_opener", return_value=self.opener(lambda: FakeResp(JPEG))):
            ok, msg = LT.bg_fetch("https://img.example/a.jpg")
        self.assertTrue(ok, msg)
        with open(LT.BG_FILE, "rb") as f:
            self.assertEqual(f.read(), JPEG)
        self.assertEqual(os.listdir(self.tmp), ["bg.img"])  # 没有留下临时文件

    def test_concurrent_writes_not_mixed(self):
        """上传与每日刷新同时写：以前共用 bg.img.tmp，可能换上两张图拼起来的坏文件"""
        a, b = b"\xff\xd8\xff" + b"a" * 300000, b"\xff\xd8\xff" + b"b" * 100000

        def run(x):
            for _ in range(15):
                LT._bg_write(x)
        ts = [threading.Thread(target=run, args=(x,)) for x in (a, b)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        with open(LT.BG_FILE, "rb") as f:
            self.assertIn(f.read(), (a, b))
        self.assertEqual(os.listdir(self.tmp), ["bg.img"])


class SubDownloadTruncTest(unittest.TestCase):
    def test_sub_truncated_falls_back(self):
        """订阅只收到前半段：以前按半截内容解析，节点悄悄变少并写进缓存；现在当作下载失败"""
        full = "\n".join(f"ss://YWVzLTEyOC1nY206eA@1.2.3.{i}:8388#N{i}" for i in range(1, 9)).encode()
        o = mock.Mock()
        o.open.side_effect = lambda *a, **k: FakeResp(full[:len(full) // 2], declared=len(full))
        with mock.patch.object(SBS, "dl_check"), mock.patch.object(SBS, "core_alive", return_value=False), \
                mock.patch.object(SBS, "proxy_opener", return_value=o), mock.patch.object(SBS, "write_json") as wj:
            with self.assertRaises(IOError) as cm:
                SBS.sb_fetch_sub({"name": "T846", "url": "https://sub.example/x"})
        self.assertIn("不完整", str(cm.exception))
        wj.assert_not_called()


class YamlAnchorTest(unittest.TestCase):
    TEXT = """proxies:
  - &a {name: A, type: ss, server: 1.1.1.1, port: 1, cipher: aes-128-gcm, password: x}
  - <<: *a
    name: B
  - &c
    name: C
    type: ss
    server: 2.2.2.2
    port: 2
  - name: D
    type: vmess
    server: 3.3.3.3
    port: 3
    ws-opts: &w
      path: /p
  - name: E
    type: vmess
    server: 3.3.3.3
    port: 4
    ws-opts: *w
  - just-a-string
"""

    def test_lite_parser_anchors(self):
        with mock.patch.object(SBS, "_yaml_full", return_value=None):  # 模拟没装 PyYAML
            nodes, errs = SBS.parse_sub_text(self.TEXT)
        by = {n["name"]: n for n in nodes}
        self.assertEqual(sorted(by), ["A", "B", "C", "D", "E"])  # 以前只剩 D、E（A 成了字符串，C 整段丢失，B 缺 type）
        self.assertEqual(by["B"]["server"], "1.1.1.1")
        self.assertEqual(by["B"]["port"], 1)
        self.assertEqual(by["E"]["ws-opts"], {"path": "/p"})
        self.assertEqual(len(errs), 1)  # 读不出的条目有提示（以前静默丢弃）

    def test_own_keys_override_merge(self):
        y = YL.yaml_lite("base: &b {x: 1, y: 2}\nk:\n  y: 9\n  <<: *b\n")
        self.assertEqual(y["k"], {"x": 1, "y": 9})

    def test_plain_unchanged(self):
        y = YL.yaml_lite("a:\n  - {name: 'x&y', v: '*z'}\n  - name: q\n    t: 1\n")
        self.assertEqual(y, {"a": [{"name": "x&y", "v": "*z"}, {"name": "q", "t": 1}]})


class BodyTypeTest(ApiCase):
    def raw(self, method, path, raw):
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        try:
            c.request(method, path, body=raw, headers={"X-Shunt": "1", "Content-Type": "application/json"})
            r = c.getresponse()
            return r.status, json.loads(r.read() or b"{}")
        finally:
            c.close()

    def test_non_object_body(self):
        for raw in ("[1]", '"x"', "123", "null"):
            code, j = self.raw("POST", "/api/subs", raw)
            self.assertEqual(code, 400, (raw, j))
            self.assertIn("JSON 对象", j["message"])

    def test_latency_bad_type(self):
        code, j = self.call("PUT", "/api/schedule", {"latency": "abc"})
        self.assertEqual(code, 400, j)
        code, j = self.call("PUT", "/api/schedule", {"latency": [1]})
        self.assertEqual(code, 400, j)

    def test_adblock_bad_shapes(self):
        before = server.load()["adblock"]
        for b in ({"lists": [1]}, {"lists": "x"}, {"black": "ads.com"}, {"white": {"a": 1}}, {"interval": "abc"}):
            code, j = self.call("PUT", "/api/adblock", b)
            self.assertEqual(code, 400, (b, j))
        self.assertEqual(server.load()["adblock"], before)


class RestoreSubCacheTest(ApiCase):
    """恢复设置 / 快照 / 版本备份把订阅换了链接：删 mihomo 的 provider 缓存；sing-box 重新下载变化的订阅"""

    def setUp(self):
        super().setUp()
        server.save(base())
        self.pdir = os.path.join(B.CONF_DIR, "providers")
        os.makedirs(self.pdir, exist_ok=True)
        for n in ("A", "B", "C"):
            with open(os.path.join(self.pdir, n + ".yaml"), "w") as f:
                f.write("proxies: []\n")
        try:
            with open(D.HISTORY_FILE) as f:
                self.hist = f.read()
        except OSError:
            self.hist = None
        self.core = "mihomo"
        self.p = [mock.patch.object(WA, "reload_core", return_value=(True, "ok")),
                  mock.patch.object(WA, "active_core", side_effect=lambda *a: self.core),
                  mock.patch.object(WA, "tp_apply", return_value=(0, "")),
                  mock.patch.object(WA, "ab_compose"),
                  mock.patch.object(WA, "sb_update_subs", return_value=([], []))]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()
        for n in ("A", "B", "C"):
            try:
                os.remove(os.path.join(self.pdir, n + ".yaml"))
            except OSError:
                pass
        if self.hist is None:
            try:
                os.remove(D.HISTORY_FILE)
            except OSError:
                pass
        else:
            with open(D.HISTORY_FILE, "w") as f:
                f.write(self.hist)
        super().tearDown()

    def cached(self, n):
        return os.path.isfile(os.path.join(self.pdir, n + ".yaml"))

    def subs(self, a_url="https://a.example/s", b_filter=""):
        return [{"name": "A", "url": a_url, "filter": "", "exclude": ""},
                {"name": "B", "url": "https://b.example/s", "filter": b_filter, "exclude": ""}]

    def test_restore_changed_url_drops(self):
        code, j = self.call("POST", "/api/restore", {"subs": self.subs(a_url="https://new.example/s")})
        self.assertEqual(code, 200, j)
        self.assertFalse(self.cached("A"))  # 以前保留：mihomo 继续用旧链接的节点到下个更新间隔
        self.assertTrue(self.cached("B"))
        WA.sb_update_subs.assert_not_called()

    def test_restore_same_keeps(self):
        code, j = self.call("POST", "/api/restore", {"subs": self.subs()})
        self.assertEqual(code, 200, j)
        self.assertTrue(self.cached("A") and self.cached("B"))

    def test_restore_removed_and_new_sub(self):
        subs = [self.subs()[0], {"name": "C", "url": "https://c.example/s", "filter": "", "exclude": ""}]
        code, j = self.call("POST", "/api/restore", {"subs": subs})
        self.assertEqual(code, 200, j)
        self.assertTrue(self.cached("A"))
        self.assertFalse(self.cached("B"))  # 恢复后不再有的订阅
        self.assertFalse(self.cached("C"))  # 新出现的同名订阅：旧缓存不能用

    def test_restore_singbox_refetch(self):
        self.core = "singbox"
        code, j = self.call("POST", "/api/restore", {"subs": self.subs(b_filter="HK")})
        self.assertEqual(code, 200, j)
        WA.sb_update_subs.assert_called_once()  # 筛选变了：sing-box 缓存里是按旧筛选过滤的节点
        names, d = WA.sb_update_subs.call_args[0]
        self.assertEqual(names, ["B"])
        self.assertEqual(d["subs"][1]["filter"], "HK")  # Hk002：显式传入恢复后的数据（sb_update_subs(names, d)）

    def test_history_snapshot(self):
        snap = dict(server.load(), subs=self.subs(a_url="https://snap.example/s"))
        with open(D.HISTORY_FILE, "w") as f:
            json.dump([{"id": "s846", "t": int(time.time()), "changed": ["subs"], "data": snap}], f)
        code, j = self.call("POST", "/api/history", {"id": "s846"})
        self.assertEqual(code, 200, j)
        self.assertEqual(server.load()["subs"][0]["url"], "https://snap.example/s")
        self.assertFalse(self.cached("A"))
        self.assertTrue(self.cached("B"))


class BackupRestoreLockTest(ApiCase):
    def setUp(self):
        super().setUp()
        server.save(base())
        self.dir = tempfile.mkdtemp(prefix="bk846-")
        self.base = tempfile.mkdtemp(prefix="base846-")
        with open(os.path.join(self.base, "server.py"), "w") as f:
            f.write("cur")
        self.pdir = os.path.join(B.CONF_DIR, "providers")
        os.makedirs(self.pdir, exist_ok=True)
        with open(os.path.join(self.pdir, "A.yaml"), "w") as f:
            f.write("proxies: []\n")
        self.p = [mock.patch.object(BK, "BACKUP_DIR", self.dir), mock.patch.object(BK, "BASE", self.base),
                  mock.patch.object(WA, "reload_core", return_value=(True, "ok")),
                  mock.patch.object(WA, "tp_apply", return_value=(0, "")),
                  mock.patch.object(WA, "restart_self"),
                  mock.patch.object(WA, "active_core", return_value="mihomo"),
                  mock.patch.object(WA, "ab_compose")]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()
        B.UPD_STATE["busy"] = False
        shutil.rmtree(self.dir, ignore_errors=True)
        shutil.rmtree(self.base, ignore_errors=True)
        try:
            os.remove(os.path.join(self.pdir, "A.yaml"))
        except OSError:
            pass
        super().tearDown()

    def _mk(self, data):
        name = "shunt-backup-v9.9.7-20260101-000001.tar.gz"
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

    def test_busy_rejected(self):
        name = self._mk(server.load())
        B.UPD_STATE["busy"] = True  # 面板在线更新进行中
        code, j = self.call("POST", "/api/backup/restore", {"name": name})
        self.assertEqual(code, 409, j)
        with open(os.path.join(self.base, "server.py")) as f:
            self.assertEqual(f.read(), "cur")
        WA.restart_self.assert_not_called()

    def test_ok_releases_and_drops_cache(self):
        d = server.load()
        d["subs"][0]["url"] = "https://changed.example/s"
        name = self._mk(d)
        code, j = self.call("POST", "/api/backup/restore", {"name": name})
        self.assertEqual(code, 200, j)
        for _ in range(50):  # 响应先发出，忙标志在 finally 里随后清除
            if not B.UPD_STATE["busy"]:
                break
            time.sleep(0.02)
        self.assertFalse(B.UPD_STATE["busy"])
        self.assertFalse(os.path.isfile(os.path.join(self.pdir, "A.yaml")))


class FilterRemovedOnlyTest(ApiCase):
    """mihomo：编辑订阅筛选后 provider 只剩已删节点 → 订阅为空、mihomo 加载失败；拒绝保存"""

    def setUp(self):
        super().setUp()
        server.save(base(removed_a=["HK 01", "HK 02"]))
        self.pdir = os.path.join(B.CONF_DIR, "providers")
        os.makedirs(self.pdir, exist_ok=True)
        with open(os.path.join(self.pdir, "A.yaml"), "w") as f:
            f.write("proxies:\n" + "".join(f"  - {{name: '{n}', type: ss, server: 1.1.1.1, port: 1}}\n" for n in ("HK 01", "HK 02", "US 01")))
        self.p = [mock.patch.object(WA, "reload_core", return_value=(True, "ok")),
                  mock.patch.object(WA, "active_core", return_value="mihomo"),
                  mock.patch.object(WA, "refresh_after_sub")]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()
        try:
            os.remove(os.path.join(self.pdir, "A.yaml"))
        except OSError:
            pass
        super().tearDown()

    def post(self, flt, exc=""):
        return self.call("POST", "/api/subs", {"name": "A", "url": WA.mask_url("https://a.example/s"), "filter": flt, "exclude": exc})

    def test_only_removed_rejected(self):
        code, j = self.post("HK")
        self.assertEqual(code, 400, j)
        self.assertIn("已从订阅删除", j["message"])
        self.assertEqual(server.load()["subs"][0]["filter"], "")

    def test_exclude_rejected(self):
        code, j = self.post("", "US")
        self.assertEqual(code, 400, j)

    def test_ok_when_something_left(self):
        code, j = self.post("HK|US")
        self.assertEqual(code, 200, j)
        self.assertEqual(server.load()["subs"][0]["filter"], "HK|US")

    def test_matches_nothing_not_our_business(self):
        """筛选本身一个都不匹配（与已删节点无关）：沿用以前的行为，不在这里拦"""
        code, j = self.post("JP")
        self.assertEqual(code, 200, j)


class BgFrontendTest(unittest.TestCase):
    """链接 / 每日壁纸大图显示前缩到 2560px；外链和小图原样使用"""

    def test_bgfit(self):
        js = r"""
const fs=require('fs');
let BLOBS=0;
global.URL={createObjectURL:()=>'blob:'+(++BLOBS),revokeObjectURL:()=>{}};
const SIZES={'/bg?v=1':[6000,4000],'/bg?v=2':[1920,1080]};
global.Image=class{set src(v){this._s=v;const z=SIZES[v];setTimeout(()=>{if(z){this.naturalWidth=z[0];this.naturalHeight=z[1];this.onload()}else this.onerror()},0)}get src(){return this._s}};
let CANVAS=null;
global.document={createElement:()=>(CANVAS={getContext:()=>({drawImage(){}}),toBlob(cb){cb({})}}),documentElement:{classList:{toggle(){}}}};
const src=fs.readFileSync(process.argv[1]+'/web/js/01-theme.js','utf8');
eval(src.slice(src.indexOf('const BG_MAXPX'),src.indexOf('function bgApply'))+';global.bgFit=bgFit;global.BGFIT_GET=()=>BGFIT;');
const out={};
bgFit('https://x.example/a.jpg',u=>{out.ext=u});
bgFit('/bg?v=1',u=>{out.big=u;out.size=[CANVAS.width,CANVAS.height];
  bgFit('/bg?v=1',u2=>{out.cached=u2;
    bgFit('/bg?v=2',u3=>{out.small=u3;process.stdout.write(JSON.stringify(out))})})});
"""
        r = subprocess.run(["node", "-e", js, ROOT], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out["ext"], "https://x.example/a.jpg")
        self.assertTrue(out["big"].startswith("blob:"))
        self.assertEqual(out["size"], [2560, 1707])
        self.assertEqual(out["cached"], out["big"])
        self.assertEqual(out["small"], "/bg?v=2")

    def test_css_large_viewport(self):
        with open(os.path.join(ROOT, "web", "style.css"), encoding="utf-8") as f:
            css = f.read()
        rule = css[css.index("#bgimg{"):css.index("}", css.index("#bgimg{"))]
        self.assertIn("100lvh", rule)
        self.assertNotIn("inset:-30px", rule)



if __name__ == "__main__":
    unittest.main()
