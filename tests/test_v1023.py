"""v10.2.3 回归测试：配置原子写入、YAML 括号平方级解析、订阅数字节点名、订阅整体超时、sing-box 订阅节点只算一次、
备份恢复最旧一份、内核回滚不覆盖运行中的程序、面板更新半途失败恢复、透明代理绕过网段合并、订阅名冲突、
下载在核心未运行时不重复直连、前端内联事件参数转义、init.d 生成配置失败仍启动、tproxy.sh 删净重复策略路由"""
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock

from tests.helper import server, TMP
from tests.test_v1012 import ApiCase

assert server

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
M = sys.modules["shunt.mihomo"]
SBC = sys.modules["shunt.sb_config"]
SBS = sys.modules["shunt.sb_subs"]
Y = sys.modules["shunt.sb_yaml"]
BK = sys.modules["shunt.backup"]
CU = sys.modules["shunt.core_update"]
SW = sys.modules["shunt.sb_switch"]
PU = sys.modules["shunt.panel_update"]
CLI = sys.modules["shunt.cli"]
V = sys.modules["shunt.validate"]


class AtomicConfigWriteTest(unittest.TestCase):
    def test_mihomo_build_error_keeps_old_config(self):
        p = os.path.join(TMP, "atomic-mh.yaml")
        with open(p, "w") as f:
            f.write('{"old": 1}')
        with mock.patch.object(M, "build_config", side_effect=ValueError("boom")):
            with self.assertRaises(ValueError):
                M.write_config(server.load(), p)
        with open(p) as f:
            self.assertEqual(f.read(), '{"old": 1}')  # 以前被截断成空文件
        self.assertEqual([x for x in os.listdir(TMP) if x.startswith("atomic-mh.yaml.tmp")], [])

    def test_singbox_build_error_keeps_old_config(self):
        p = os.path.join(TMP, "atomic-sb.json")
        with open(p, "w") as f:
            f.write('{"old": 2}')
        with mock.patch.object(SBC, "build_singbox", side_effect=ValueError("boom")):
            with self.assertRaises(ValueError):
                SBC.write_sb_config(server.load(), p)
        with open(p) as f:
            self.assertEqual(f.read(), '{"old": 2}')

    def test_write_keeps_mode_and_content(self):
        p = os.path.join(TMP, "atomic-mode.yaml")
        with open(p, "w") as f:
            f.write("{}")
        os.chmod(p, 0o600)
        M.write_config(server.load(), p)
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
        with open(p) as f:
            self.assertIn("proxy-groups", json.load(f))


class YamlBracketTest(unittest.TestCase):
    def test_bracket_in_quoted_name_is_linear(self):
        lines = ["proxies:"] + [f'  - {{name: "HK[{i}", type: ss, server: a{i}.com, port: 1, cipher: x, password: y}}'
                                for i in range(2000)]
        t = time.time()
        with mock.patch.object(SBS, "_yaml_full", return_value=None):
            nodes, _ = SBS.parse_sub_text("\n".join(lines))
        self.assertEqual(len(nodes), 2000)
        self.assertEqual(nodes[5]["name"], "HK[5")
        self.assertLess(time.time() - t, 3)  # 以前约 13 秒

    def test_matches_full_parser(self):
        text = """proxies:
  - {name: "HK[1", type: ss, server: a.com, port: 1}
  - {name: Bob's node, type: ss, server: b.com, port: 2}
  - name: HK[02
    type: vmess
    server: c.com
    port: 3
    ws-opts: {path: /a, headers: {Host: "x.com"}}
  - {name: multi, type: trojan,
     server: d.com, port: 4,   # 注释
     alpn: [h2, http/1.1]}
  - name: 'it''s [x'
    type: ss
    port: 5
"""
        want = {"proxies": [
            {"name": "HK[1", "type": "ss", "server": "a.com", "port": 1},
            {"name": "Bob's node", "type": "ss", "server": "b.com", "port": 2},
            {"name": "HK[02", "type": "vmess", "server": "c.com", "port": 3, "ws-opts": {"path": "/a", "headers": {"Host": "x.com"}}},
            {"name": "multi", "type": "trojan", "server": "d.com", "port": 4, "alpn": ["h2", "http/1.1"]},
            {"name": "it's [x", "type": "ss", "port": 5}]}
        self.assertEqual(Y.yaml_lite(text), want)

    def test_unclosed_flow_is_capped(self):
        text = "a: [1, 2\n" + "".join(f"k{i}: {i}\n" for i in range(Y.FLOW_MAX + 50))
        t = time.time()
        with self.assertRaises(ValueError):  # 未闭合照旧报错（调用方会逐项容错），但不再把后面整份文件吞进来反复扫描
            Y.yaml_lite(text)
        self.assertLess(time.time() - t, 2)


class SubParseTest(unittest.TestCase):
    def test_numeric_names_become_text(self):
        nodes, _ = SBS.parse_sub_text("proxies:\n  - {name: 2024, type: ss, server: a.com, port: 1}\n"
                                      "  - {name: 0, type: ss, server: b.com, port: 2}\n")
        self.assertEqual([n["name"] for n in nodes], ["2024", "0"])
        rf = sys.modules["shunt.groups"].rx(sys.modules["shunt.base"].DEFAULT_EXCLUDE)
        [rf.search(n["name"]) for n in nodes]  # 以前数字名在这里 TypeError，整个订阅更新失败

    def test_json_array_and_bad_outbounds(self):
        self.assertEqual(SBS.parse_sub_text("[1, 2]")[0], [])  # 以前 AttributeError
        nodes, _ = SBS.parse_sub_text(json.dumps({"outbounds": ["x", {"type": "vless", "tag": 7, "server": "a.com"}]}))
        self.assertEqual([n["name"] for n in nodes], ["7"])

    def test_update_subs_overall_deadline(self):
        d = dict(server.load(), subs=[{"name": f"s{i}", "url": "https://a.example/"} for i in range(3)])
        gate = threading.Event()

        def slow(s, gh=""):
            gate.wait(5)
            return 1, "1 个节点"
        try:
            with mock.patch.object(SBS, "sb_fetch_sub", slow), mock.patch.object(SBS, "SUBS_WAIT", 0.5):
                t = time.time()
                ok, bad = SBS.sb_update_subs(d=d)
                self.assertLess(time.time() - t, 2)  # 以前逐个 join，最长 N×180 秒
        finally:
            gate.set()
        self.assertEqual(ok, [])
        self.assertEqual(len(bad), 3)
        self.assertTrue(all("超时" in x for x in bad))

    def test_fake_providers_computes_nodes_once(self):
        d = dict(server.load(), subs=[{"name": f"s{i}", "url": "https://a.example/"} for i in range(5)])
        with mock.patch.object(SBC, "sb_provider_nodes", return_value={}) as m, \
                mock.patch.object(SBC, "core_json", return_value={}):
            out = SBC.sb_fake_providers(d)
        self.assertEqual(m.call_count, 1)  # 以前每个订阅调用一次（N²）
        self.assertEqual(len(out["providers"]), 5)


class BackupRestoreOldestTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="bk-")
        self.base = tempfile.mkdtemp(prefix="bkbase-")
        self.data = os.path.join(self.base, "data.json")
        with open(self.data, "w") as f:
            f.write('{"cur": 1}')
        self.p = [mock.patch.object(BK, "BACKUP_DIR", self.dir), mock.patch.object(BK, "BASE", self.base),
                  mock.patch.object(BK, "DATA_FILE", self.data)]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()
        shutil.rmtree(self.dir, ignore_errors=True)
        shutil.rmtree(self.base, ignore_errors=True)

    def _mk(self, i):
        name = "shunt-backup-v1.0.%d-20260101-0000%02d.tar.gz" % (i, i)
        fp = os.path.join(self.dir, name)
        src = os.path.join(self.base, "src.json")
        with open(src, "w") as f:
            f.write('{"old": %d}' % i)
        with tarfile.open(fp, "w:gz") as tf:
            tf.add(src, arcname="data.json")
        os.utime(fp, (1000 + i, 1000 + i))
        return name

    def test_restore_oldest_of_full_set(self):
        names = [self._mk(i) for i in range(BK.KEEP_N)]
        ok, msg = BK.restore(names[0])  # 最旧的一个：以前被「先备份当前」的清理删掉，恢复失败
        self.assertTrue(ok, msg)
        with open(self.data) as f:
            self.assertEqual(json.load(f), {"old": 0})
        left = [b["name"] for b in BK.list()]
        self.assertEqual(len(left), BK.KEEP_N)
        self.assertIn(names[0], left)
        self.assertNotIn(names[1], left)  # 挤掉的是次旧的

    def test_cleanup_without_protect(self):
        [self._mk(i) for i in range(BK.KEEP_N + 2)]
        BK.cleanup()
        self.assertEqual(len(BK.list()), BK.KEEP_N)


class BinaryRollbackTest(unittest.TestCase):
    def test_copy_replace_new_inode(self):
        d = tempfile.mkdtemp(prefix="cr-")
        src, dst = os.path.join(d, "a.bak"), os.path.join(d, "a")
        with open(src, "w") as f:
            f.write("old")
        with open(dst, "w") as f:
            f.write("new")
        ino = os.stat(dst).st_ino
        CU.copy_replace(src, dst)
        with open(dst) as f:
            self.assertEqual(f.read(), "old")
        self.assertNotEqual(os.stat(dst).st_ino, ino)  # 换成新文件，不写正在运行的那个（ETXTBSY）
        self.assertFalse(os.path.exists(dst + ".rb"))
        shutil.rmtree(d)

    def test_sb_update_rollback_uses_replace(self):
        with mock.patch.object(SW, "sb_version", return_value="1.0"), \
                mock.patch.object(SW, "sb_install", return_value=("1.1", True)), \
                mock.patch.object(SW, "active_core", return_value="singbox"), \
                mock.patch.object(SW, "check_sb_config", return_value=(False, "bad")), \
                mock.patch.object(SW, "copy_replace") as cr, \
                mock.patch.object(SW, "_cu"):
            SW.sb_update_job("stable", "")
        cr.assert_called_once_with(SW.SB_BIN + ".bak", SW.SB_BIN)


class PanelUpdateUndoTest(unittest.TestCase):
    def test_undo_restores_and_removes(self):
        d = tempfile.mkdtemp(prefix="pu-")
        bak = os.path.join(d, ".backup")
        os.makedirs(bak)
        with open(os.path.join(bak, "server.py"), "w") as f:
            f.write("old")
        for n in ("server.py", "new.txt"):
            with open(os.path.join(d, n), "w") as f:
                f.write("new")
        with mock.patch.object(PU, "local_file", lambda f: os.path.join(d, f)):
            PU._undo_replace(["server.py", "new.txt"], bak)
        with open(os.path.join(d, "server.py")) as f:
            self.assertEqual(f.read(), "old")
        self.assertFalse(os.path.exists(os.path.join(d, "new.txt")))
        shutil.rmtree(d)

    def test_failure_midway_undoes(self):
        files = {"server.py": b"PANEL_VERSION = \"9\"\n", "index.html": b"<html><script></script></html>", "a.txt": b"x"}
        replaced = []
        real_replace = os.replace

        def flaky(a, b):
            if b.endswith("a.txt"):
                raise OSError(28, "No space left on device")
            replaced.append(b)
            return real_replace(a, b)
        d = tempfile.mkdtemp(prefix="pu2-")
        try:
            with mock.patch.object(PU, "BASE", d), mock.patch.object(PU, "local_file", lambda f: os.path.join(d, f)), \
                    mock.patch.object(PU, "panel_manifest", return_value=(None, {})), \
                    mock.patch.object(PU, "remote_file_list", return_value=list(files)), \
                    mock.patch.object(PU, "fetch_raw", lambda f, *a: files[f]), \
                    mock.patch.object(PU, "upd_begin", return_value=True), \
                    mock.patch.object(PU, "start_update_guard") as guard, mock.patch.object(PU, "restart_self") as rs, \
                    mock.patch.object(PU.os, "replace", flaky), mock.patch.object(BK, "create", return_value=(True, "x")):
                with open(os.path.join(d, "server.py"), "w") as f:
                    f.write("old-server")
                ok, info = PU.self_update(True, "")
            self.assertFalse(ok)
            self.assertIn("已恢复原文件", info["message"])
            guard.assert_not_called()
            rs.assert_not_called()
            with open(os.path.join(d, "server.py")) as f:
                self.assertEqual(f.read(), "old-server")  # 已替换的 server.py 放回旧版
            self.assertFalse(os.path.exists(os.path.join(d, "index.html")))  # 原来没有的文件删掉
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TpEnvTest(unittest.TestCase):
    def test_overlaps_merged_and_mode_quoted(self):
        d = dict(server.load(), bypass=["192.168.1.0/24", "192.168.1.5", "192.168.1.5", "10.0.0.1",
                                       "AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "fd00::/64", "fd00::1"],
                 proxy_mode="tproxy; touch /tmp/x")
        with mock.patch.object(CLI, "load", return_value=d), mock.patch.object(CLI, "sh", return_value=(0, "")):
            env = CLI.tp_env()
        self.assertIn("B_IP='10.0.0.1/32,192.168.1.0/24'", env)
        self.assertIn("B_MAC='aa:bb:cc:dd:ee:ff'\n", env)
        self.assertIn("B_IP6='fd00::/64'", env)
        self.assertIn("MODE='tproxy; touch /tmp/x'", env)
        out = subprocess.run(["sh", "-c", env + '\nprintf %s "$MODE"'], capture_output=True, text=True).stdout
        self.assertEqual(out, "tproxy; touch /tmp/x")  # eval 后只是一个值，不会执行


class SubNameClashTest(ApiCase):
    def test_clash_rejected(self):
        server.save(dict(server.load(), subs=[{"name": "机场 A", "url": "https://a.example/s", "filter": "", "exclude": ""}]))
        W = sys.modules["shunt.webapi"]
        with mock.patch.object(W, "reload_core", return_value=(True, "ok")), mock.patch.object(W, "refresh_after_sub"):
            code, j = self.call("POST", "/api/subs", {"name": "机场_A", "url": "https://b.example/s"})
            self.assertEqual(code, 400)
            self.assertIn("机场 A", j["message"])
            code, _ = self.call("POST", "/api/subs", {"name": "机场 A", "url": "https://a.example/s"})  # 编辑自己不算冲突
            self.assertNotEqual(code, 400)

    def test_helper(self):
        self.assertEqual(V.sub_name_clash("a b", ["a_b", "c"]), "a_b")
        self.assertIsNone(V.sub_name_clash("a b", ["a b", "c"]))


class OpenUrlTest(unittest.TestCase):
    def test_no_duplicate_direct_when_core_down(self):
        seen = []

        def opener(use_proxy):
            class O:
                def open(self, req, timeout=0):
                    seen.append((req.full_url, use_proxy))
                    raise OSError("down")
            return O()
        with mock.patch.object(CU, "core_alive", return_value=False), mock.patch.object(CU, "proxy_opener", opener), \
                mock.patch.object(CU, "dl_check"):
            with self.assertRaises(IOError):
                CU.open_url("https://github.com/x", "")
        self.assertEqual(seen, [("https://github.com/x", False)])  # 以前同一地址直连两遍


class FrontendHandlerEscapeTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, "index.html"), encoding="utf-8") as f:
            self.html = f.read()

    def test_no_unsafe_inline_string_args(self):
        self.assertNotRegex(self.html, r"\('\$\{esc\(")  # '${esc(x)}' 放进 onclick：&#39; 会还原成 '
        self.assertNotRegex(self.html, r"\('\$\{encodeURIComponent\(")  # encodeURIComponent 不转义 ' ( )
        self.assertIn("const jsq=", self.html)

    @unittest.skipUnless(shutil.which("node"), "需要 node")
    def test_jsq_roundtrip(self):
        js = r"""
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
%s
const unent=s=>s.replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&');
const names=["a');alert(1);//","a')-alert(1)-('",'x"y',"<img src=x onerror=alert(1)>","\\'\"`${1}","香港 01 🇭🇰"];
let got=[];for(const n of names){const attr=`f(${jsq(n)})`;new Function('f',unent(attr))(v=>got.push(v))}
process.stdout.write(JSON.stringify(got)===JSON.stringify(names)?'ok':'bad '+JSON.stringify(got))
""" % re.search(r"const jsq=.*\n", self.html).group(0)
        out = subprocess.run(["node", "-e", js], capture_output=True, text=True, timeout=20)
        self.assertEqual(out.stdout, "ok", out.stderr)


class ScriptsTest(unittest.TestCase):
    def test_init_start_pre_tolerates_gen_failure(self):
        for n in ("shunt-core", "mihomo"):
            with open(os.path.join(ROOT, "init.d", n), encoding="utf-8") as f:
                s = f.read()
            # v10.3.7 起 start_pre 写成多行（面板已生成配置时跳过 --gen），取整个函数体检查
            body = s[s.index("start_pre()"):]
            body = body[:body.index("\n}") + 2]
            self.assertIn("--gen >/dev/null ||", body)
            self.assertTrue(body.rstrip().endswith("return 0\n}"))

    def test_clear_route_loops(self):
        with open(os.path.join(ROOT, "tproxy.sh"), encoding="utf-8") as f:
            s = f.read()
        self.assertIn("while [ $n -lt 20 ] && ip rule del fwmark", s)
        self.assertIn("while [ $n -lt 20 ] && ip -6 rule del fwmark", s)


if __name__ == "__main__":
    unittest.main()
