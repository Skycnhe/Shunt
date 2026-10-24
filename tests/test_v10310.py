"""v10.3.10：订阅「更新」后节点没变的问题。

- sing-box：订阅内容用第一个 UA 没解析出节点时，以前直接读 mihomo 以前下载的 ./providers/<名>.yaml（常是切换内核前的旧文件），
  不再试下一个 UA，照常报「N 个节点」：订阅明明换了节点，「更新」一直显示成功、节点一直是旧的。现在先把每个 UA 都试完；
  都失败时只在面板没有缓存（或 mihomo 缓存更新）时才兜底并在提示里注明，否则报失败、保留上次的节点
- mihomo / sing-box：更新前后节点名单完全一样时在结果里注明（mihomo 默认 ETag，机场回 304 时 mihomo 照样回 204、继续用旧节点）
- 端到端：本地 HTTP 订阅服务器第一次返回 A/B，之后返回 B/C（同样大小、同一秒内），走面板 /api/subs/update，
  检查订阅节点列表、/api/core/providers/proxies、生成的配置都是新节点；mihomo 用一个模拟控制器（PUT 时重新下载订阅，
  可模拟 ETag 304），设了 SHUNT_TEST_MIHOMO=<mihomo 可执行文件> 时再用真实 mihomo 跑一遍
"""
import base64
import http.server
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

from tests.helper import server, TMP
from tests.test_v1012 import ApiCase
from tests.test_v840 import base

B = sys.modules["shunt.base"]
SBS = sys.modules["shunt.sb_subs"]
SBC = sys.modules["shunt.sb_config"]
G = sys.modules["shunt.groups"]
C = sys.modules["shunt.core"]
CH = sys.modules["shunt.corehttp"]
SC = sys.modules["shunt.schedule"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VER = "10.3.10"


def read(*p):
    with open(os.path.join(ROOT, *p), encoding="utf-8") as f:
        return f.read()


class VersionTest(unittest.TestCase):
    def test_version(self):
        self.assertEqual(B.PANEL_VERSION, VER)

    def test_changelog_top(self):
        heads = [ln for ln in read("CHANGELOG.md").splitlines() if ln.startswith("## v")]
        self.assertTrue(heads[0].startswith("## v" + VER), heads[0])

    def test_built(self):
        self.assertIn(f'PANEL_VERSION = "{VER}"', read("server.py"))


def b64_links(*names):
    ss = base64.b64encode(b"aes-128-gcm:pw").decode()
    return base64.b64encode("\n".join(f"ss://{ss}@1.2.3.{i}:8388#{n}" for i, n in enumerate(names, 1)).encode())


def clash_yaml(*names):
    return ("proxies:\n" + "".join(f"  - {{name: {n}, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-128-gcm, password: pw}}\n"
                                   for n in names)).encode()


class SubServer:
    """本地订阅服务器：body 可随时换；etag 非空时每次都回同一个 ETag，带 If-None-Match 时回 304（模拟 ETag 不随内容变化的机场 / CDN）。
    by_ua：{UA 前缀: 内容}，按 UA 返回不同内容"""

    def __init__(self):
        self.body, self.etag, self.by_ua, self.hits = b"", None, {}, []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                ua = self.headers.get("User-Agent") or ""
                outer.hits.append((ua, self.headers.get("If-None-Match")))
                if outer.etag and self.headers.get("If-None-Match") == outer.etag:
                    self.send_response(304)
                    self.send_header("ETag", outer.etag)
                    self.end_headers()
                    return
                body = next((v for k, v in outer.by_ua.items() if ua.startswith(k)), outer.body)
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                if outer.etag:
                    self.send_header("ETag", outer.etag)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/s"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def sb_names(code_body):
    return [p["name"] for p in code_body[1]["providers"]["A"]["proxies"]]


class SingboxEndToEndTest(ApiCase):
    """sing-box：订阅由面板下载。A/B → B/C，同样大小、同一秒内更新"""

    def setUp(self):
        super().setUp()
        self.sub = SubServer()
        d = base("singbox")
        d["subs"] = [{"name": "A", "url": self.sub.url, "filter": "", "exclude": ""}]
        server.save(d)
        for p in (G.sub_cache_path("A"), os.path.join(B.CONF_DIR, "providers", "A.yaml")):
            if os.path.exists(p):
                os.remove(p)
        G.PROV.update(t=0, data=None)
        self.patches = [mock.patch.object(SBS, "dl_check"), mock.patch.object(SBS, "core_alive", return_value=False),
                        mock.patch.object(C, "core_alive", return_value=True),
                        mock.patch.object(C, "reload_core", side_effect=self.fake_reload)]
        for p in self.patches:
            p.start()
        self.reloads = 0

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.sub.close()
        super().tearDown()

    def fake_reload(self, *a, **k):
        self.reloads += 1
        SBC.write_sb_config(server.load())
        return True, "ok"

    def written_outbounds(self):
        with open(SBC.SB_CONF) as f:
            return [o["tag"] for o in json.load(f)["outbounds"] if o.get("type") == "shadowsocks"]

    def test_update_replaces_nodes_same_size_same_second(self):
        self.sub.body = b64_links("NodeA1", "NodeB1")
        code, j = self.call("POST", "/api/subs/update", {"name": "A"})
        self.assertEqual(code, 200, j)
        self.assertEqual(sb_names(self.call("GET", "/api/core/providers/proxies")), ["NodeA1", "NodeB1"])
        size1 = os.path.getsize(G.sub_cache_path("A"))
        self.sub.body = b64_links("NodeB1", "NodeC1")  # 同样长度
        t0 = int(time.time())
        code, j = self.call("POST", "/api/subs/update", {"name": "A"})
        self.assertEqual(code, 200, j)
        self.assertNotIn("相同", j["message"])
        self.assertEqual(sb_names(self.call("GET", "/api/core/providers/proxies")), ["NodeB1", "NodeC1"])
        self.assertEqual([n["name"] for n in self.call("GET", "/api/subs/nodes")[1]["subs"][0]["nodes"]], ["NodeB1", "NodeC1"])
        self.assertEqual(self.written_outbounds(), ["M1", "NodeB1", "NodeC1"])
        self.assertEqual(G.provider_nodes()["A"], ["NodeB1", "NodeC1"])
        if int(time.time()) == t0:  # 通常在同一秒内完成；文件大小也一样
            self.assertEqual(os.path.getsize(G.sub_cache_path("A")), size1)
        self.assertGreaterEqual(self.reloads, 1)  # 节点变了：重新生成配置并重载

    def test_provider_rev_advances(self):
        """订阅节点名单变了，名单版本号要前进：/api/state 的策略组缓存与 /api/ping 版本号按它失效（Hk001 以前一直不变）"""
        self.sub.body = b64_links("NodeA1", "NodeB1")
        self.call("POST", "/api/subs/update", {"name": "A"})
        rev = G.provider_rev()
        self.sub.body = b64_links("NodeB1", "NodeC1")
        self.call("POST", "/api/subs/update", {"name": "A"})
        self.assertGreater(G.provider_rev(), rev)

    def test_signature_cache_survives_same_stat(self):
        """订阅节点名单缓存按文件签名：即使新文件与旧文件 mtime / 大小相同，inode 不同也会重新读（原子替换）"""
        self.sub.body = b64_links("NodeA1", "NodeB1")
        self.call("POST", "/api/subs/update", {"name": "A"})
        st = os.stat(G.sub_cache_path("A"))
        self.sub.body = b64_links("NodeB1", "NodeC1")
        self.call("POST", "/api/subs/update", {"name": "A"})
        os.utime(G.sub_cache_path("A"), ns=(st.st_atime_ns, st.st_mtime_ns))
        self.assertEqual(G.sb_provider_nodes(server.load())["A"], ["NodeB1", "NodeC1"])

    def test_unchanged_noted(self):
        self.sub.body = b64_links("NodeA1", "NodeB1")
        self.call("POST", "/api/subs/update", {"name": "A"})
        code, j = self.call("POST", "/api/subs/update", {"name": "A"})
        self.assertEqual(code, 200)
        self.assertIn("节点与上次相同", j["message"])

    def test_first_ua_unparsable_tries_next_not_stale_mihomo_cache(self):
        """根因：clash.meta 拿到的内容解析不出节点时，以前直接用 mihomo 的旧缓存并报成功；现在先试下一个 UA"""
        os.makedirs(os.path.join(B.CONF_DIR, "providers"), exist_ok=True)
        with open(os.path.join(B.CONF_DIR, "providers", "A.yaml"), "wb") as f:
            f.write(clash_yaml("OldX", "OldY"))  # 切换内核前 mihomo 留下的旧节点
        self.sub.by_ua = {"clash.meta": b"<html>please use another client</html>"}
        self.sub.body = b64_links("NodeB1", "NodeC1")
        code, j = self.call("POST", "/api/subs/update", {"name": "A"})
        self.assertEqual(code, 200, j)
        self.assertEqual(sb_names(self.call("GET", "/api/core/providers/proxies")), ["NodeB1", "NodeC1"])
        self.assertEqual(G.sb_sub_cache("A")["ua"], "v2rayN/6.45")
        self.assertEqual([u for u, _ in self.sub.hits], ["clash.meta", "v2rayN/6.45"])

    def test_all_unparsable_keeps_last_nodes_and_fails(self):
        self.sub.body = b64_links("NodeA1", "NodeB1")
        self.call("POST", "/api/subs/update", {"name": "A"})
        time.sleep(0.02)
        os.makedirs(os.path.join(B.CONF_DIR, "providers"), exist_ok=True)
        old = os.path.join(B.CONF_DIR, "providers", "A.yaml")
        with open(old, "wb") as f:
            f.write(clash_yaml("OldX", "OldY"))
        os.utime(old, (time.time() - 86400 * 30,) * 2)  # mihomo 缓存比面板缓存旧
        self.sub.body = b"garbage"
        code, j = self.call("POST", "/api/subs/update", {"name": "A"})
        self.assertEqual(code, 500)
        self.assertIn("更新失败", j["message"])
        self.assertIn("已保留上次的节点", j["message"])
        self.assertEqual(sb_names(self.call("GET", "/api/core/providers/proxies")), ["NodeA1", "NodeB1"])

    def test_mihomo_cache_fallback_only_when_newer_and_labelled(self):
        """刚从 mihomo 切过来、面板还没有缓存时仍可用 mihomo 缓存兜底，但提示里写明"""
        os.makedirs(os.path.join(B.CONF_DIR, "providers"), exist_ok=True)
        with open(os.path.join(B.CONF_DIR, "providers", "A.yaml"), "wb") as f:
            f.write(clash_yaml("OldX", "OldY"))
        self.sub.body = b"garbage"
        code, j = self.call("POST", "/api/subs/update", {"name": "A"})
        self.assertEqual(code, 200, j)
        self.assertIn("暂用 mihomo 之前下载的缓存", j["message"])
        self.assertEqual(sb_names(self.call("GET", "/api/core/providers/proxies")), ["OldX", "OldY"])


class FakeMihomo:
    """模拟 mihomo 控制器的 /providers/proxies：PUT 时重新下载订阅（带上次的 ETag），304 时保留旧节点、照样回 204"""

    def __init__(self, url):
        self.url, self.names, self.etag = url, [], None
        self.fetch()
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def _send(self, code, obj=None):
                raw = json.dumps(obj).encode() if obj is not None else b""
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _prov(self):
                return {"name": "A", "type": "Proxy", "vehicleType": "HTTP", "proxies": [{"name": n, "type": "Shadowsocks", "history": []} for n in outer.names]}

            def do_GET(self):
                if self.path == "/providers/proxies":
                    return self._send(200, {"providers": {"A": self._prov()}})
                if self.path == "/providers/proxies/A":
                    return self._send(200, self._prov())
                if self.path == "/proxies":
                    return self._send(200, {"proxies": {}})
                return self._send(404, {"message": "not found"})

            def do_PUT(self):
                if self.path == "/providers/proxies/A":
                    outer.fetch()
                    return self._send(204)
                return self._send(404, {"message": "not found"})

            def log_message(self, *a):
                pass
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.ctrl = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def fetch(self):
        import urllib.request
        import urllib.error
        req = urllib.request.Request(self.url, headers={"User-Agent": "clash.meta"})
        if self.etag:
            req.add_header("If-None-Match", self.etag)
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=5) as r:
                nodes, _ = SBS.parse_sub_text(r.read().decode())
                self.names = [p["name"] for p in nodes]
                self.etag = r.headers.get("ETag")
        except urllib.error.HTTPError as e:
            if e.code != 304:
                raise

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class MihomoEndToEndTest(ApiCase):
    """mihomo：订阅由核心自己拉取，面板只调 PUT /providers/proxies/<名>"""

    def run_flow(self, etag):
        sub = SubServer()
        sub.etag = etag
        sub.body = clash_yaml("NodeA1", "NodeB1")
        mh = FakeMihomo(sub.url)
        d = base("mihomo")
        d["subs"] = [{"name": "A", "url": sub.url, "filter": "", "exclude": ""}]
        server.save(d)
        env = {k: v for k, v in os.environ.items() if k != "PANEL_OFFLINE"}
        try:
            with mock.patch.object(CH, "CTRL", mh.ctrl), mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch.object(C, "core_alive", return_value=True), mock.patch.object(C, "reload_core", return_value=(True, "ok")):
                G.PROV.update(t=0, data=None)
                self.assertEqual(sb_names(self.call("GET", "/api/core/providers/proxies")), ["NodeA1", "NodeB1"])
                sub.body = clash_yaml("NodeB1", "NodeC1")
                code, j = self.call("POST", "/api/subs/update", {"name": "A"})
                self.assertEqual(code, 200, j)
                return j["message"], sb_names(self.call("GET", "/api/core/providers/proxies")), \
                    [n["name"] for n in self.call("GET", "/api/subs/nodes")[1]["subs"][0]["nodes"]], G.provider_nodes()["A"]
        finally:
            mh.close()
            sub.close()

    def test_update_replaces_nodes(self):
        msg, prov, nodes, pn = self.run_flow(None)
        self.assertEqual(prov, ["NodeB1", "NodeC1"])
        self.assertEqual(nodes, ["NodeB1", "NodeC1"])
        self.assertEqual(pn, ["NodeB1", "NodeC1"])
        self.assertIn("A：2 个节点", msg)
        self.assertNotIn("相同", msg)

    def test_stale_etag_304_is_reported(self):
        """机场 / CDN 的 ETag 不随内容变化：mihomo 拿到 304 继续用旧节点、更新接口照样 204。面板以前只报「已更新」"""
        msg, prov, nodes, _ = self.run_flow('W/"fixed"')
        self.assertEqual(prov, ["NodeA1", "NodeB1"])
        self.assertIn("节点与更新前完全相同", msg)
        self.assertIn("304", msg)


@unittest.skipUnless(os.environ.get("SHUNT_TEST_MIHOMO") and os.access(os.environ.get("SHUNT_TEST_MIHOMO", ""), os.X_OK),
                     "设置 SHUNT_TEST_MIHOMO=<mihomo 可执行文件> 时才跑真实 mihomo")
class RealMihomoTest(ApiCase):
    def run_flow(self, etag):
        sub = SubServer()
        sub.etag = etag
        sub.body = clash_yaml("NodeA1", "NodeB1")
        d = base("mihomo")
        d["subs"] = [{"name": "A", "url": sub.url, "filter": "", "exclude": ""}]
        d["secret"] = "t"
        server.save(d)
        wd = os.path.join(TMP, f"real-mh-{bool(etag)}")
        os.makedirs(wd, exist_ok=True)
        with open(os.path.join(wd, "config.yaml"), "w") as f:
            f.write(f"""external-controller: 127.0.0.1:19197
secret: t
proxy-providers:
  A: {{type: http, url: "{sub.url}", path: ./providers/A.yaml, interval: 86400, health-check: {{enable: false, url: "https://x/", interval: 300}}}}
proxy-groups:
  - {{name: sel, type: select, use: [A]}}
rules:
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - MATCH,sel
""")
        p = subprocess.Popen([os.environ["SHUNT_TEST_MIHOMO"], "-d", wd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        env = {k: v for k, v in os.environ.items() if k != "PANEL_OFFLINE"}
        try:
            time.sleep(2)
            with mock.patch.object(CH, "CTRL", "http://127.0.0.1:19197"), mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch.object(C, "core_alive", return_value=True), mock.patch.object(C, "reload_core", return_value=(True, "ok")):
                sub.body = clash_yaml("NodeB1", "NodeC1")
                code, j = self.call("POST", "/api/subs/update", {"name": "A"})
                with open(os.path.join(wd, "providers", "A.yaml")) as f:
                    return j["message"], sb_names(self.call("GET", "/api/core/providers/proxies")), f.read()
        finally:
            p.terminate()
            p.wait()
            sub.close()

    def test_plain(self):
        msg, prov, text = self.run_flow(None)
        self.assertEqual(prov, ["NodeB1", "NodeC1"])
        self.assertIn("NodeC1", text)

    def test_stale_etag(self):
        msg, prov, text = self.run_flow('W/"fixed"')
        self.assertEqual(prov, ["NodeA1", "NodeB1"])
        self.assertIn("节点与更新前完全相同", msg)


class MihomoNoteUnitTest(unittest.TestCase):
    def test_note(self):
        self.assertIn("完全相同", SC.mh_unchanged_note(["a"], ["a"]))
        self.assertEqual(SC.mh_unchanged_note(["a"], ["b"]), "：1 个节点")
        self.assertEqual(SC.mh_unchanged_note(None, ["b"]), "：1 个节点")
        self.assertEqual(SC.mh_unchanged_note([], []), "：0 个节点")
        self.assertEqual(SC.mh_unchanged_note(["a"], None), "")


if __name__ == "__main__":
    unittest.main()
