"""WARP：密码学向量、握手包、配置解析 / Endpoint 改写、WARP 实例不被当作残留核心、核心启动时 WARP 让路"""
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from tests.helper import server

assert server
WG = sys.modules["shunt.wgcrypto"]
WP = sys.modules["shunt.warp"]
S = sys.modules["shunt.sysopt"]
C = sys.modules["shunt.core"]

CONF = """[Interface]
PrivateKey = {priv}
Address = 172.16.0.2/32, 2606:4700:110:8a36::1/128
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408
Reserved = 12,34,56
"""


class Crypto(unittest.TestCase):
    def test_x25519_rfc7748(self):
        k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        self.assertEqual(WG.x25519(k, u).hex(), "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        a, b = WG.keypair(), WG.keypair()
        self.assertEqual(WG.x25519(a[0], b[1]), WG.x25519(b[0], a[1]))

    def test_chacha20poly1305_rfc8439(self):
        key = bytes(range(0x80, 0xa0))
        nonce = bytes.fromhex("070000004041424344454647")
        ad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
              b"sunscreen would be it.")
        otk = WG._block(key, 0, nonce)[:32]
        ct = WG.chacha20(key, 1, nonce, pt)
        tag = WG.poly1305(otk, ad + WG._pad16(ad) + ct + WG._pad16(ct) + WG.struct.pack("<QQ", len(ad), len(ct)))
        self.assertEqual(tag.hex(), "1ae10b594f09e26a7e902ecbd0600691")
        self.assertEqual(ct[:16].hex(), "d31a8d34648e60db7b86afbc53ef7ec2")
        k2 = os.urandom(32)
        box = WG.aead_encrypt(k2, 7, b"hello", b"ad")
        self.assertEqual(WG.aead_decrypt(k2, 7, box, b"ad"), b"hello")
        self.assertIsNone(WG.aead_decrypt(k2, 7, box, b"xx"))

    def test_handshake_responder_can_decrypt(self):
        """按 WireGuard 响应方的步骤解开发起包：静态公钥、时间戳都能还原，mac1 正确，时间戳递增"""
        ip, ipub = WG.keypair()
        rp, rpub = WG.keypair()
        ini = WG.Initiator(ip, rpub, (1, 2, 3))
        stamps = []
        for fresh in (True, False, False):
            pkt, idx = ini.packet(fresh=fresh)
            self.assertEqual(len(pkt), 148)
            self.assertEqual(pkt[:4], b"\x01\x01\x02\x03")
            self.assertEqual(pkt[4:8], idx)
            mac1 = WG.hashlib.blake2s(pkt[:116], digest_size=16, key=WG._hash(b"mac1----" + rpub)).digest()
            self.assertEqual(pkt[116:132], mac1)
            e_pub, st, ts = pkt[8:40], pkt[40:88], pkt[88:116]
            c = WG._kdf(WG._C0, e_pub, 1)[0]
            h = WG._hash(WG._hash(WG._H0 + rpub) + e_pub)
            c, k = WG._kdf(c, WG.x25519(rp, e_pub), 2)
            self.assertEqual(WG.aead_decrypt(k, 0, st, h), ipub)
            h = WG._hash(h + st)
            c, k = WG._kdf(c, WG.x25519(rp, ipub), 2)
            t = WG.aead_decrypt(k, 0, ts, h)
            self.assertIsNotNone(t)
            stamps.append(t)
        self.assertEqual(stamps, sorted(stamps))
        self.assertEqual(len(set(stamps)), 3)

    def test_is_reply(self):
        idx = b"abcd"
        self.assertTrue(WG.is_reply(b"\x02\x00\x00\x00" + b"zzzz" + idx + b"\x00" * 80, idx))
        self.assertTrue(WG.is_reply(b"\x03\x00\x00\x00" + idx + b"\x00" * 56, idx))
        self.assertFalse(WG.is_reply(b"\x02\x00\x00\x00" + b"zzzz" + b"nope" + b"\x00" * 80, idx))


class Conf(unittest.TestCase):
    def setUp(self):
        self.text = CONF.format(priv=WG.b64(WG.keypair()[0]))

    def test_parse(self):
        c = WP.parse_conf(self.text)
        self.assertEqual((c["v4"], c["host"], c["port"], c["reserved"], c["mtu"]),
                         ("172.16.0.2", "engage.cloudflareclient.com", 2408, [12, 34, 56], 1280))
        self.assertTrue(c["v6"].startswith("2606:4700"))
        c = WP.parse_conf(self.text.replace("Reserved = 12,34,56", "Reserved = DCI4"))  # client_id 的 base64 写法
        self.assertEqual(c["reserved"], [12, 34, 56])
        for bad in (self.text.replace("PrivateKey", "#"), self.text.replace("2408", "99999"),
                    self.text.replace("Reserved = 12,34,56", "Reserved = 1,2"), self.text.replace("Address = ", "Address = x")):
            with self.assertRaises(ValueError):
                WP.parse_conf(bad)

    def test_set_endpoint(self):
        t = WP.set_endpoint(self.text, "162.159.192.7:500")
        self.assertEqual(WP.parse_conf(t)["port"], 500)
        self.assertEqual(t.count("Endpoint"), 1)
        t2 = WP.set_endpoint(t.replace("Endpoint = 162.159.192.7:500\n", ""), WP.fmt_ep("2606:4700:d0::1", 2408))
        c = WP.parse_conf(t2)
        self.assertEqual((c["host"], c["port"]), ("2606:4700:d0::1", 2408))

    def test_build_configs(self):
        c = WP.parse_conf(self.text)
        m = WP.build_mihomo(c, {"ipv6": False}, cn=True)
        self.assertEqual((m["tproxy-port"], m["dns"]["listen"], m["rules"][-1]), (7893, "0.0.0.0:1053", "MATCH,WARP"))
        self.assertNotIn("external-controller", m)  # 不能占 9090：面板靠它判断核心是否在跑
        self.assertEqual(m["proxies"][0]["reserved"], [12, 34, 56])
        self.assertIn("GEOSITE,cn,DIRECT", m["rules"])
        sp = WP.build_mihomo(c, {}, cn=False, tproxy=False, mixed=40001)
        self.assertEqual((sp["mixed-port"], sp["rules"], sp.get("tproxy-port")), (40001, ["MATCH,WARP"], None))
        s = WP.build_singbox(c, {"ipv6": True}, cn=False)
        tags = {i["tag"]: i for i in s["inbounds"]}
        self.assertEqual((tags["tproxy-in"]["listen_port"], tags["tproxy-in"]["listen"], tags["dns-in"]["listen_port"]), (7893, "::", 1053))
        self.assertEqual(s["route"]["final"], "WARP")
        self.assertNotIn("experimental", s)

    def test_targets(self):
        t = WP._targets(["162.159.192.0/24", "bad", "1.2.3.4/32"], [2408, 500], 10)
        self.assertEqual(len(t), (10 + 1) * 2)
        self.assertTrue(all(p in (2408, 500) for _, p in t))
        self.assertEqual(len({ip for ip, _ in t if ip.startswith("162.159.192.")}), 10)


class Probe(unittest.TestCase):
    def test_probe_round_local_responder(self):
        """本地假装响应方：收到握手包回一个 type 2 应答，探测应统计到延迟"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        stop = [False]

        def serve():
            s.settimeout(0.2)
            while not stop[0]:
                try:
                    d, a = s.recvfrom(256)
                except socket.timeout:
                    continue
                if len(d) == 148 and d[0] == 1:
                    s.sendto(b"\x02\x00\x00\x00" + os.urandom(4) + d[4:8] + b"\x00" * 80, a)
        th = threading.Thread(target=serve, daemon=True)
        th.start()
        try:
            ini = WG.Initiator(WG.keypair()[0], WG.keypair()[1])
            res = WP._probe_round(ini, [("127.0.0.1", port), ("127.0.0.1", 9)], timeout=0.5, gap=0)
        finally:
            stop[0] = True
            th.join(1)
            s.close()
        self.assertIn(("127.0.0.1", port), res)
        self.assertNotIn(("127.0.0.1", 9), res)


class Procs(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="shunt-warp-")
        self.bin = os.path.join(self.d, "mihomo")
        os.symlink("/bin/sh", self.bin)
        self.ps = []

    def tearDown(self):
        for p in self.ps:
            p.kill()
            p.wait()

    def test_warp_instance_not_core(self):
        """WARP 实例与核心是同一个程序：命令行带 WARP 目录的不算核心，停止核心时不会被误杀"""
        warp_dir = os.path.join(self.d, "warp")
        os.makedirs(warp_dir)
        core = subprocess.Popen([self.bin, "-c", "sleep 300; :"])
        w = subprocess.Popen([self.bin, "-c", "sleep 300; :", warp_dir])
        self.ps += [core, w]
        time.sleep(0.2)
        with mock.patch.object(S, "CORE_BINS", (self.bin,)), mock.patch.object(S, "WARP_DIR", warp_dir):
            pids = S.core_procs()
        self.assertIn(core.pid, pids)
        self.assertNotIn(w.pid, pids)

    def test_core_start_stops_warp(self):
        """核心启动 / 重启前 WARP 让出端口；停止核心不影响 WARP"""
        pidf = os.path.join(self.d, "warp.pid")
        warp_dir = os.path.join(self.d, "warp")
        os.makedirs(warp_dir)
        w = subprocess.Popen([self.bin, "-c", "sleep 300; :", warp_dir])
        self.ps.append(w)
        with open(pidf, "w") as f:
            f.write(str(w.pid))
        rc = os.path.join(self.d, "rc")
        with open(rc, "w") as f:
            f.write("#!/bin/sh\necho \"$1\" >> " + os.path.join(self.d, "calls") + "\n")
        os.chmod(rc, 0o755)
        with mock.patch.object(WP, "WARP_PID", pidf), mock.patch.object(WP, "WARP_DIR", warp_dir), \
                mock.patch.object(WP, "WARP_STATE", os.path.join(self.d, "state.json")), mock.patch.object(S, "SVC", rc):
            self.assertTrue(WP.warp_running())
            S.rc_run("stop", timeout=10)
            self.assertTrue(WP.warp_running())
            S.rc_run("start", timeout=10)
            w.wait(10)
            self.assertFalse(WP.warp_running())
            self.assertFalse(WP._state()["on"])

    def test_reload_keeps_core_stopped_while_warp(self):
        with mock.patch.object(C, "warp_running", lambda: True), mock.patch.object(C, "check_config", lambda p: (True, "")), \
                mock.patch.object(C, "check_sb_config", lambda p: (True, "")), mock.patch.object(C, "svc_restart") as rs, \
                mock.patch.object(C, "core") as cr, mock.patch.object(C, "set_manual_stop") as ms:
            ok, msg = C.reload_core()
        self.assertTrue(ok)
        self.assertIn("WARP", msg)
        rs.assert_not_called()
        cr.assert_not_called()
        ms.assert_not_called()


if __name__ == "__main__":
    unittest.main()
