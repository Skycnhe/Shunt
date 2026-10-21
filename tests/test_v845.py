"""v8.4.5：改订阅链接后 mihomo 仍用旧缓存、编辑订阅后顺序变化、版本备份恢复后不重启 / 前端判断错字段、
手动停止时更新内核把核心拉起、节点全超时通知误报、广告拦截列表连续修改互相覆盖、概览快速切换按序号、
内核更新复查不带内核参数、sing-box 定时更新 GEO 重载失败的提示"""
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
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
WA = sys.modules["shunt.webapi"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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


class VersionTest(unittest.TestCase):
    def test_version(self):
        self.assertEqual(B.PANEL_VERSION, "8.4.5")

    def test_changelog_top(self):
        with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as f:
            heads = [ln for ln in f if ln.startswith("## v")]
        self.assertTrue(heads[0].startswith("## v8.4.5"), heads[0])


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


if __name__ == "__main__":
    unittest.main()
