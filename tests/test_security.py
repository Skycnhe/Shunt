import unittest
from tests.helper import server


class AccessTest(unittest.TestCase):
    def test_lan(self):
        for ip in ("192.168.1.2", "10.0.0.1", "127.0.0.1", "::1", "fe80::1", "100.100.1.1", "::ffff:192.168.1.5"):
            self.assertTrue(server.ip_is_lan(ip), ip)
        for ip in ("8.8.8.8", "2001:4860::8888"):
            self.assertFalse(server.ip_is_lan(ip), ip)

    def test_host(self):
        for h in ("192.168.1.1:8080", "[fd00::1]:8080", "router.lan", "nas.local", "localhost:8080", "myhost"):
            self.assertTrue(server.host_ok(h), h)
        self.assertFalse(server.host_ok("evil.example.com"))


class UpdateTest(unittest.TestCase):
    def test_git_blob_sha(self):
        self.assertEqual(server.git_blob_sha(b"hello\n"), "ce013625030ba8dba906f756967f9e9ca394464a")

    def test_file_list(self):
        lst = b"server.py\nindex.html\n# c\ninit.d/mihomo\n"
        shas = {"server.py": "1", "index.html": "2", "init.d/mihomo": "3", "update-files.txt": server.git_blob_sha(lst)}
        orig = server.shunt.panel_update.fetch_raw
        try:
            server.shunt.panel_update.fetch_raw = lambda *a, **k: lst
            self.assertEqual(server.remote_file_list("", "c", shas), ["server.py", "index.html", "init.d/mihomo"])
            server.shunt.panel_update.fetch_raw = lambda *a, **k: b"server.py\nindex.html\n../etc/passwd\n"
            with self.assertRaises(ValueError):
                server.remote_file_list("", "c", shas)
        finally:
            server.shunt.panel_update.fetch_raw = orig
        self.assertEqual(server.remote_file_list("", None, {}), server.UPD_FILES)

    def test_remote_version(self):
        self.assertEqual(server.remote_version(b'#!\nPANEL_VERSION = "9.9.9"\n'), "9.9.9")


class RoutesTest(unittest.TestCase):
    def test_routes(self):
        self.assertGreater(len(server.ROUTES), 40)
        for (m, p), fn in server.ROUTES.items():
            self.assertTrue(p.startswith("/api/"), p)
            self.assertIn(m, ("GET", "POST", "PUT", "DELETE", "PATCH"))
            self.assertTrue(fn.__name__.startswith("api_"))
        for gone in ("/api/login", "/api/password", "/api/logout"):
            self.assertFalse(any(p == gone for _, p in server.ROUTES))


class ErrLogTest(unittest.TestCase):
    def test_dedup(self):
        n = len(server.ERRS)
        server.log_err("测试", ValueError("x"))
        server.log_err("测试", ValueError("x"))
        self.assertEqual(len(server.ERRS), n + 1)


class AdblockTest(unittest.TestCase):
    def test_parse_filter(self):
        bs, be, as_, ae, skipped = server.parse_filter("||ads.example.com^\n@@||ok.example.com^\n! c\n0.0.0.0 t.example.com\n")
        self.assertIn("ads.example.com", bs)
        self.assertIn("ok.example.com", as_)
        self.assertIn("t.example.com", bs | be)


if __name__ == "__main__":
    unittest.main()
