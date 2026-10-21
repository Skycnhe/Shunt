"""v8.4.2：深度审查修复——sing-box 订阅节点参数变化不重载、sing-box GET /configs/geo 绕过跨站防护、看门狗直连期间保存设置
重新挂上透明代理规则、名称含 / 的订阅 / 策略组调用核心接口路径被截断、订阅坏节点让整份 sing-box 配置生成失败、
前端按序号删除规则 / 规则集、TUN 失败回滚在锁外写 data.json"""
import json
import os
import shutil
import subprocess
import sys
import unittest
from unittest import mock

from tests.helper import server
from tests.test_v1012 import ApiCase
from tests.test_v840 import base, write_sb_cache

assert server

B = sys.modules["shunt.base"]
C = sys.modules["shunt.core"]
G = sys.modules["shunt.groups"]
N = sys.modules["shunt.notify"]
SBC = sys.modules["shunt.sb_config"]
SC = sys.modules["shunt.schedule"]
MG = sys.modules["shunt.migrate"]
DA = sys.modules["shunt.data"]
WA = sys.modules["shunt.webapi"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class SbRefreshNodeParamsTest(unittest.TestCase):
    """#1 sing-box：订阅更新后节点名字不变、参数变了（换密码 / 服务器）也要重载"""

    def setUp(self):
        self.orig = server.load()
        server.save(base(core="singbox"))
        write_sb_cache()
        os.makedirs(os.path.dirname(SBC.SB_CONF), exist_ok=True)
        DA.write_json(SBC.SB_CONF, SBC.build_singbox(server.load())[0])  # 当前生效的配置
        self.p = [mock.patch.object(C, "core_alive", return_value=True), mock.patch.object(C, "reload_core", return_value=(True, "ok"))]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()
        for sname in ("A", "B"):
            if os.path.exists(G.sub_cache_path(sname)):
                os.remove(G.sub_cache_path(sname))
        if os.path.exists(SBC.SB_CONF):
            os.remove(SBC.SB_CONF)
        server.save(self.orig)

    def test_unchanged_no_reload(self):
        ok, msg = C.refresh_regions()
        self.assertTrue(ok)
        self.assertIn("无变化", msg)
        C.reload_core.assert_not_called()

    def test_password_change_same_names_reloads(self):
        c = G.sb_sub_cache("A")
        for p in c["nodes"]:
            p["password"] = "rotated"
            p["server"] = "10.9.9.9"
        DA.write_json(G.sub_cache_path("A"), c)
        ok, msg = C.refresh_regions()
        self.assertTrue(ok)
        C.reload_core.assert_called_once()

    def test_sub_update_api_applies_changed_params(self):
        """手动「更新」订阅（sing-box）：下载完节点参数变了也要真正生效"""
        def fake_update(names=None, d=None):
            c = G.sb_sub_cache("B")
            c["nodes"][0]["port"] = 9999
            DA.write_json(G.sub_cache_path("B"), c)
            return ["B：2 个节点"], []
        # Hk002：/api/subs/update 走 schedule.subs_update（与定时任务共用）
        with mock.patch.object(SC, "sb_update_subs", side_effect=fake_update):
            h = mock.MagicMock()
            out = {}
            h.reply = lambda ok, msg: out.update(ok=ok, msg=msg)
            WA.ROUTES[("POST", "/api/subs/update")](h, "POST", "/api/subs/update", {"name": "B"}, "")
        self.assertTrue(out["ok"], out)
        C.reload_core.assert_called_once()


class SbGeoGetCsrfTest(ApiCase):
    """#2 sing-box：/api/core/configs/geo 只认 POST（GET 不要求 X-Shunt 头，可被跨站 <img> 触发）"""

    def test_get_rejected_post_ok(self):
        d = base(core="singbox")
        server.save(d)
        with mock.patch.object(WA, "sb_sync_assets", return_value=[]) as sync, \
                mock.patch.object(WA, "reload_core", return_value=(True, "ok")):
            code, _ = self.call("GET", "/api/core/configs/geo")
            self.assertEqual(code, 405)
            sync.assert_not_called()
            code, _ = self.call("POST", "/api/core/configs/geo", {})
            self.assertEqual(code, 204)
            sync.assert_called_once()


class TpApplyWatchdogDirectTest(unittest.TestCase):
    """#3 看门狗已撤规则直连（tp_off）时，保存设置不能把透明代理规则重新挂上"""

    def setUp(self):
        self.saved = dict(N.WD)

    def tearDown(self):
        N.WD.update(self.saved)

    def test_skip_when_tp_off(self):
        N.WD.update(manual_stop=False, tp_off=True)
        with mock.patch.object(WA, "sh", return_value=(0, "")) as sh:
            self.assertEqual(WA.tp_apply(), (0, ""))
            sh.assert_not_called()
        N.WD.update(tp_off=False)
        with mock.patch.object(WA, "sh", return_value=(0, "ok")) as sh:
            WA.tp_apply()
            sh.assert_called_once()

    def test_settings_save_keeps_direct(self):
        N.WD.update(manual_stop=False, tp_off=True)
        h = mock.MagicMock()
        out = {}
        h.send = lambda code, obj: out.update(code=code, obj=obj)
        orig = server.load()
        try:
            d = server.load()
            d["proxy_mode"] = "tproxy"
            server.save(d)
            with mock.patch.object(WA, "sh", return_value=(0, "")) as sh:
                WA.ROUTES[("PUT", "/api/settings")](h, "PUT", "/api/settings", {"bypass": ["192.168.1.9"]}, "")
                sh.assert_not_called()
            self.assertEqual(out["code"], 200, out)
        finally:
            server.save(orig)

    def test_watchdog_clears_stale_tp_off(self):
        """直连期间核心被手动停止、又由用户启动：恢复后清掉 tp_off 并补开规则，之后保存设置能正常重载规则"""
        N.WD.update(manual_stop=False, tp_off=True, status="stopped", fails=0)
        d = server.load()
        d["proxy_mode"], d["watchdog"] = "tproxy", True
        with mock.patch.object(N, "load", return_value=d), mock.patch.object(N, "core_alive_confirmed", return_value=True), \
                mock.patch.object(N, "mass_testing", return_value=False), mock.patch.object(N, "sh", return_value=(0, "")) as sh, \
                mock.patch.dict(N.WD_HOLD, {"until": 0}), mock.patch.dict(N.CORE_UPD, {"busy": False}):
            N.watchdog_tick()
        self.assertFalse(N.WD["tp_off"])
        self.assertEqual(N.WD["status"], "ok")
        sh.assert_called_once()
        self.assertIn("apply", sh.call_args[0][0])


class SlashNameQuoteTest(unittest.TestCase):
    """#4 名称含 / 的订阅 / 策略组：调用核心接口时 / 要编码成 %2F（mihomo 用 getEscapeParam 解码），否则路径被截断"""

    def test_schedule_sub_update(self):
        d = base()
        d["subs"] = [{"name": "机场/备用", "url": "https://a.example/s", "filter": "", "exclude": ""}]
        with mock.patch.object(SC, "load", return_value=d), mock.patch.object(SC, "core", return_value=(204, b"")) as core, \
                mock.patch.object(SC, "refresh_regions"):
            ok, _ = SC.run_task("sub_update")
        self.assertTrue(ok)
        self.assertEqual(core.call_args[0][1], "/providers/proxies/%E6%9C%BA%E5%9C%BA%2F%E5%A4%87%E7%94%A8")

    def test_api_sub_update(self):
        d = base()
        d["subs"] = [{"name": "a/b", "url": "https://a.example/s", "filter": "", "exclude": ""}]
        h = mock.MagicMock()
        with mock.patch.object(WA, "load", return_value=d), mock.patch.object(SC, "active_core", return_value="mihomo"), \
                mock.patch.object(SC, "core", return_value=(204, b"")) as core, mock.patch.object(SC, "refresh_regions", return_value=(True, "")):
            WA.ROUTES[("POST", "/api/subs/update")](h, "POST", "/api/subs/update", {"name": "a/b"}, "")
        self.assertEqual(core.call_args[0][1], "/providers/proxies/a%2Fb")

    def test_restore_selections(self):
        with mock.patch.object(MG, "read_json", return_value={"美/日": "n1"}), \
                mock.patch.object(MG, "core_json", return_value={"proxies": {"美/日": {"type": "Selector", "now": "n0", "all": ["n0", "n1"]}}}), \
                mock.patch.object(MG, "core", return_value=(204, b"")) as core, mock.patch.object(MG.os, "remove"):
            self.assertEqual(MG.restore_selections(), 1)
        self.assertEqual(core.call_args[0][1], "/proxies/%E7%BE%8E%2F%E6%97%A5")


class SbBadNodeTest(unittest.TestCase):
    """#5 订阅里字段类型不对的节点：跳过这一个，不让整份 sing-box 配置生成失败"""

    def setUp(self):
        self.orig = server.load()
        server.save(base(core="singbox"))
        write_sb_cache()

    def tearDown(self):
        for sname in ("A", "B"):
            if os.path.exists(G.sub_cache_path(sname)):
                os.remove(G.sub_cache_path(sname))
        server.save(self.orig)

    def test_malformed_nested_fields_skipped(self):
        c = G.sb_sub_cache("B")
        c["nodes"] += [
            {"name": "bad-grpc", "type": "vmess", "server": "1.1.1.1", "port": 443, "uuid": "u", "network": "grpc", "grpc-opts": "svc"},
            {"name": "bad-ws", "type": "vless", "server": "1.1.1.2", "port": 443, "uuid": "u", "network": "ws",
             "ws-opts": {"path": "/", "headers": ["Host", "a.com"]}},
            {"name": "bad-plugin", "type": "ss", "server": "1.1.1.3", "port": 443, "cipher": "aes-128-gcm", "password": "p",
             "plugin": "obfs", "plugin-opts": "obfs=http"},
        ]
        DA.write_json(G.sub_cache_path("B"), c)
        conf, warn, _ = SBC.build_singbox(server.load())
        tags = {o["tag"] for o in conf["outbounds"]}
        self.assertIn("TW 01", tags)
        for n in ("bad-grpc", "bad-ws", "bad-plugin"):
            self.assertNotIn(n, tags)
        self.assertTrue(any("3 个节点" in w for w in warn), warn)


class SaveUnderLockTest(unittest.TestCase):
    """#7 TUN 启动失败回滚时 save(prev) 要在全局锁内"""

    def test_source(self):
        with open(os.path.join(ROOT, "shunt", "webapi.py"), encoding="utf-8") as f:
            src = f.read()
        i = src.index("TUN 起不来时局域网会断网")
        seg = src[i:i + 300]
        self.assertRegex(seg, r"with LOCK:[^\n]*\n\s+save\(prev\)")


@unittest.skipUnless(shutil.which("node"), "需要 node")
class FrontendDeleteByValueTest(unittest.TestCase):
    """#6 前端删除自定义规则 / 规则集按内容（名称），不按会过期的序号"""

    def run_js(self, files, body):
        src = ""
        for f in files:
            with open(os.path.join(ROOT, "web", "js", f), encoding="utf-8") as fh:
                src += fh.read() + "\n"
        js = "const document={},localStorage={getItem(){return null},setItem(){}};let SAVED=null,TOASTS=[],RELOAD=0;\n" + src + \
             "\nsaveRules=r=>{SAVED=r};saveRS=r=>{SAVED=r};toast=t=>TOASTS.push(t);loadRules=()=>{RELOAD++};\n" + body
        r = subprocess.run(["node", "-e", js], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_del_rule_by_value(self):
        out = self.run_js(["00-core.js", "11-rules.js"], """
STATE={rules:['DOMAIN,a.com,DIRECT','DOMAIN,b.com,DIRECT','DOMAIN,c.com,DIRECT']};
const shown=STATE.rules[1];                       // 列表上显示的第 2 条
STATE={rules:['DOMAIN,x.com,DIRECT','DOMAIN,a.com,DIRECT','DOMAIN,b.com,DIRECT','DOMAIN,c.com,DIRECT']};  // 后台刷新：别处插入了一条
delRule(shown);const a=SAVED;SAVED=null;delRule('DOMAIN,gone.com,DIRECT');
console.log(JSON.stringify({a,b:SAVED,reload:RELOAD}))""")
        self.assertEqual(out["a"], ["DOMAIN,x.com,DIRECT", "DOMAIN,a.com,DIRECT", "DOMAIN,c.com,DIRECT"])
        self.assertIsNone(out["b"])
        self.assertEqual(out["reload"], 1)

    def test_del_ruleset_by_name(self):
        out = self.run_js(["00-core.js", "24-rulesets.js"], """
STATE={rulesets:[{name:'x'},{name:'a'},{name:'b'}]};delRS('a');const a=SAVED;SAVED=null;delRS('gone');
console.log(JSON.stringify({a,b:SAVED,reload:RELOAD}))""")
        self.assertEqual(out["a"], [{"name": "x"}, {"name": "b"}])
        self.assertIsNone(out["b"])
        self.assertEqual(out["reload"], 1)

    def test_buttons_pass_values(self):
        for f, pat in (("11-rules.js", r'delRule\(\$\{jsq\(r\)\}\)'), ("24-rulesets.js", r'delRS\(\$\{jsq\(r\.name\)\}\)')):
            with open(os.path.join(ROOT, "web", "js", f), encoding="utf-8") as fh:
                self.assertRegex(fh.read(), pat)


if __name__ == "__main__":
    unittest.main()
