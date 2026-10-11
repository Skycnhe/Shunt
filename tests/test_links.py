import base64, json, unittest
from tests.helper import server


def b64(s):
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


class LinkTest(unittest.TestCase):
    def test_vmess(self):
        j = {"ps": "HK", "add": "h.example.com", "port": "443", "id": "u", "aid": "0", "net": "ws", "path": "/ws", "host": "cdn", "tls": "tls"}
        p = server.parse_link("vmess://" + b64(json.dumps(j)))
        self.assertEqual((p["type"], p["server"], p["port"], p["tls"], p["servername"]), ("vmess", "h.example.com", 443, True, "cdn"))
        self.assertEqual(p["network"], "ws")

    def test_ss_sip002_and_legacy(self):
        p = server.parse_link("ss://" + b64("aes-256-gcm:pw") + "@1.2.3.4:8388#A")
        self.assertEqual((p["cipher"], p["password"], p["port"], p["name"]), ("aes-256-gcm", "pw", 8388, "A"))
        p = server.parse_link("ss://" + b64("aes-128-gcm:x@5.6.7.8:443") + "#old")
        self.assertEqual((p["server"], p["port"]), ("5.6.7.8", 443))

    def test_vless_reality(self):
        p = server.parse_link("vless://uuid@h:443?security=reality&pbk=K&sid=S&sni=a.com&flow=xtls-rprx-vision#R")
        self.assertEqual(p["reality-opts"], {"public-key": "K", "short-id": "S"})
        self.assertEqual(p["flow"], "xtls-rprx-vision")

    def test_hysteria2_port_hopping(self):
        p = server.parse_link("hy2://pw@h.example.com:443,20000-30000/?sni=h.example.com#H")
        self.assertEqual((p["port"], p["ports"], p["password"]), (443, "443,20000-30000", "pw"))

    def test_socks_base64_userinfo(self):
        p = server.parse_link("socks://" + b64("user:pass") + "@1.2.3.4:1080#S")
        self.assertEqual((p["type"], p["username"], p["password"]), ("socks5", "user", "pass"))

    def test_unsupported(self):
        with self.assertRaises(ValueError):
            server.parse_link("ssr://abc")

    def test_add_links_dedup(self):
        line = "trojan://pw@t.example.com:443?sni=t.example.com#T"
        nodes, errs = server.add_links(line + "\n" + line + "\nbad://x", [])
        self.assertEqual(len(nodes), 2)
        self.assertNotEqual(nodes[0]["proxy"]["name"], nodes[1]["proxy"]["name"])
        self.assertEqual(len(errs), 1)


if __name__ == "__main__":
    unittest.main()
