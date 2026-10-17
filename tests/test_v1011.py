"""v10.1.1 回归测试：favicon 只认位图且限定站点、健康检查记录失败、看门狗直连兜底撤规则、HTTP/1.1 长连接"""
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

S = sys.modules["shunt.sysopt"]
HM = sys.modules["shunt.health"]
N = sys.modules["shunt.notify"]
HT = sys.modules["shunt.https"]

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 80
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>' + b" " * 40


class FaviconTest(unittest.TestCase):
    def test_img_type(self):
        self.assertEqual(S.img_type(PNG), "image/png")
        self.assertEqual(S.img_type(b"\x00\x00\x01\x00" + b"\x00" * 10), "image/x-icon")
        self.assertEqual(S.img_type(b"GIF89a" + b"\x00" * 10), "image/gif")
        self.assertEqual(S.img_type(b"\xff\xd8\xff\xe0" + b"\x00" * 10), "image/jpeg")
        self.assertEqual(S.img_type(b"RIFF\x10\x00\x00\x00WEBPVP8 "), "image/webp")
        for bad in (SVG, b"  <svg>", b"<!doctype html><script>", b"RIFF\x10\x00\x00\x00WAVEfmt ", b""):
            self.assertIsNone(S.img_type(bad), bad[:20])

    def test_fav_hosts_from_tests(self):
        d = {"tests": [{"name": "a", "url": "https://www.google.com/generate_204"}, {"name": "b", "url": "http://GitHub.com"},
                       {"name": "坏的"}, "x"]}
        self.assertEqual(S.fav_hosts(d), {"www.google.com", "github.com"})

    def test_host_not_in_list_rejected_without_fetch(self):
        with mock.patch.object(S, "proxy_opener") as op:
            self.assertEqual(S.favicon("https://evil.tld/", allowed={"www.google.com"}), (None, None))
        op.assert_not_called()

    def test_cached_svg_dropped_png_served(self):
        tmp = tempfile.mkdtemp(prefix="fav-")
        with mock.patch.object(S, "FAV_DIR", tmp), mock.patch.object(S, "proxy_opener") as op:
            with open(os.path.join(tmp, "good.example"), "wb") as f:
                f.write(PNG)
            with open(os.path.join(tmp, "old.example"), "wb") as f:
                f.write(SVG)
            S.FAV_FAIL["old.example"] = S.time.time()  # 不再联网重试
            allowed = {"good.example", "old.example"}
            self.assertEqual(S.favicon("https://good.example/x", allowed=allowed), (PNG, "image/png"))
            self.assertEqual(S.favicon("https://old.example/", allowed=allowed), (None, None))
            self.assertFalse(os.path.exists(os.path.join(tmp, "old.example")))
        op.assert_not_called()


def fake_core(code, payload):
    def core(method, path, body=None, timeout=10):
        return code, (json.dumps(payload).encode() if payload is not None else b'{"message":"Timeout"}')
    return core


class HealthFailTest(unittest.TestCase):
    def setUp(self):
        self.orig = server.load()
        server.save(dict(self.orig, health={}))

    def tearDown(self):
        server.save(self.orig)

    def run_check(self, members, code, payload):
        with mock.patch.object(HM, "core_json", return_value={"all": members}), mock.patch.object(HM, "core", fake_core(code, payload)):
            return HM.run_check()

    def test_absent_nodes_recorded_as_failed(self):
        ok, msg = self.run_check(["A", "B", "DIRECT"], 200, {"A": 120})
        self.assertTrue(ok, msg)
        h = server.load()["health"]
        self.assertEqual(h["A"]["fail_days"], 0)
        self.assertEqual(h["A"]["latency"], 120)
        self.assertEqual(h["B"]["fail_days"], 1)
        self.assertNotIn("DIRECT", h)
        self.assertIn("1/2", msg)

    def test_all_timeout_504_records_all_failed(self):
        ok, msg = self.run_check(["A", "B"], 504, None)
        self.assertTrue(ok, msg)
        h = server.load()["health"]
        self.assertEqual((h["A"]["fail_days"], h["B"]["fail_days"]), (1, 1))

    def test_singbox_empty_result_all_failed(self):
        ok, _ = self.run_check(["A"], 200, {})
        self.assertTrue(ok)
        self.assertEqual(server.load()["health"]["A"]["fail_days"], 1)

    def test_removed_node_record_dropped_success_clears(self):
        server.save(dict(server.load(), health={"gone": {"fail_days": 2, "fail_dates": ["2026-01-01", "2026-01-02"]},
                                                 "A": {"fail_days": 2, "fail_dates": ["2026-01-01", "2026-01-02"], "hidden": True}}))
        self.run_check(["A"], 200, {"A": 80})
        h = server.load()["health"]
        self.assertNotIn("gone", h)
        self.assertEqual(h["A"]["fail_days"], 0)
        self.assertFalse(h["A"]["hidden"])

    def test_other_error_code_not_recorded(self):
        ok, _ = self.run_check(["A"], 502, {"message": "x"})
        self.assertFalse(ok)
        self.assertEqual(server.load()["health"], {})


class WatchdogDirectTest(unittest.TestCase):
    def setUp(self):
        self.orig = server.load()
        N.WD.update(status="direct", fails=9, tp_off=True, manual_stop=False)
        N.WD_HOLD.update(until=0.0, why="")

    def tearDown(self):
        N.WD.update(status="ok", fails=0, tp_off=False, manual_stop=False)
        server.save(self.orig)

    def tick(self, mode, alive_after):
        server.save(dict(server.load(), proxy_mode=mode, watchdog=True))
        with mock.patch.object(N, "core_alive_confirmed", return_value=False), \
                mock.patch.object(N, "core_alive", return_value=alive_after), \
                mock.patch.object(N, "svc_restart", return_value=(1, "")) as rs, \
                mock.patch.object(N, "sh", return_value=(0, "")) as sh:
            N.watchdog_tick()
        rs.assert_called_once()
        return [c.args[0] for c in sh.call_args_list]

    def test_restart_failed_rules_removed(self):
        calls = self.tick("tproxy", False)
        self.assertTrue(any(c.endswith(" stop") for c in calls), calls)
        self.assertTrue(N.WD["tp_off"])
        self.assertEqual(N.WD["status"], "direct")

    def test_restart_ok_rules_still_removed_until_confirmed(self):
        calls = self.tick("tproxy", True)
        self.assertTrue(any(c.endswith(" stop") for c in calls), calls)

    def test_proxy_off_no_rules_touched(self):
        self.assertEqual(self.tick("off", False), [])


class Http11Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HT.Server(("127.0.0.1", 0), server.H)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def conn(self):
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)

    def test_keepalive_reuses_connection(self):
        c = self.conn()
        try:
            for path in ("/api/ping", "/api/nope", "/manifest.webmanifest", "/api/ping"):
                c.request("GET", path)
                r = c.getresponse()
                body = r.read()
                self.assertEqual(r.version, 11)
                self.assertEqual(int(r.getheader("Content-Length")), len(body), path)
                self.assertNotEqual((r.getheader("Connection") or "").lower(), "close", path)
            self.assertIsNotNone(c.sock)  # 四个请求都走同一条连接
        finally:
            c.close()

    def test_post_body_consumed(self):
        c = self.conn()
        try:
            hdr = {"X-Shunt": "1", "Content-Type": "application/json"}
            c.request("POST", "/api/nope", body=json.dumps({"a": "x" * 5000}), headers=hdr)
            r = c.getresponse()
            r.read()
            self.assertEqual(r.status, 404)
            c.request("GET", "/api/ping")  # 上一个请求体若没读完，这里会解析出错
            r = c.getresponse()
            self.assertEqual(r.status, 200)
            self.assertTrue(json.loads(r.read())["ok"])
        finally:
            c.close()

    def test_denied_with_body_closes(self):
        c = self.conn()
        try:
            c.request("POST", "/api/nope", body=b"{}", headers={"Content-Type": "application/json"})  # 缺 X-Shunt
            r = c.getresponse()
            body = r.read()
            self.assertEqual(r.status, 403)
            self.assertEqual(int(r.getheader("Content-Length")), len(body))
            self.assertEqual(r.getheader("Connection").lower(), "close")
        finally:
            c.close()

    def test_static_304_no_body(self):
        c = self.conn()
        try:
            c.request("GET", "/")
            r = c.getresponse()
            body = r.read()
            self.assertEqual(int(r.getheader("Content-Length")), len(body))
            etag = r.getheader("ETag")
            c.request("GET", "/", headers={"If-None-Match": etag})
            r = c.getresponse()
            self.assertEqual(r.status, 304)
            self.assertEqual(r.read(), b"")
            c.request("GET", "/api/ping")
            self.assertEqual(c.getresponse().status, 200)
        finally:
            c.close()

    def test_favicon_headers(self):
        c = self.conn()
        sysmod = sys.modules["shunt.webapi"]
        try:
            with mock.patch.object(sysmod, "favicon", return_value=(PNG, "image/png")):
                c.request("GET", "/api/favicon?u=https%3A%2F%2Fwww.google.com%2F")
                r = c.getresponse()
                body = r.read()
            self.assertEqual(body, PNG)
            self.assertEqual(r.getheader("Content-Type"), "image/png")
            self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
            self.assertIn("sandbox", r.getheader("Content-Security-Policy"))
        finally:
            c.close()

    def test_204_passthrough_no_body(self):
        """核心透传返回 204 时不能写 body，否则污染下一个响应"""
        c = self.conn()
        W = sys.modules["shunt.webapi"]
        try:
            with mock.patch.object(W, "core", return_value=(204, b"")), mock.patch.object(W, "active_core", return_value="mihomo"):
                c.request("PUT", "/api/core/proxies/x", body=b'{"name":"a"}', headers={"X-Shunt": "1"})
                r = c.getresponse()
                self.assertEqual(r.status, 204)
                self.assertEqual(r.read(), b"")
            c.request("GET", "/api/ping")
            r = c.getresponse()
            self.assertEqual(r.status, 200)
            self.assertTrue(json.loads(r.read())["ok"])
        finally:
            c.close()


if __name__ == "__main__":
    unittest.main()
