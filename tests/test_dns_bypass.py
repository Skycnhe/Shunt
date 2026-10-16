"""DNS 绕过检测：dns_bypass_devices()"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shunt import diag


def _conn(sip, dip, sniff="", host=""):
    return {"metadata": {"sourceIP": sip, "destinationIP": dip,
                         "sniffHost": sniff, "host": host}}


class TestDnsBypassDevices(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(diag.dns_bypass_devices({}), {})
        self.assertEqual(diag.dns_bypass_devices({"connections": []}), {})
        self.assertEqual(diag.dns_bypass_devices({"connections": None}), {})

    def test_normal_fakeip_not_flagged(self):
        # 正常：DNS 经过面板，目标是 Fake-IP
        conns = {"connections": [
            _conn("192.168.31.150", "198.18.0.25", sniff="rr1---sn.googlevideo.com"),
            _conn("192.168.31.150", "198.18.1.10", sniff="www.youtube.com"),
        ]}
        self.assertEqual(diag.dns_bypass_devices(conns), {})

    def test_bypassed_flagged(self):
        # DNS 绕过：嗅探到域名但目标是公网真实 IP
        conns = {"connections": [
            _conn("192.168.31.150", "142.250.190.14", sniff="rr1---sn.googlevideo.com"),
        ]}
        got = diag.dns_bypass_devices(conns)
        self.assertEqual(got, {"192.168.31.150": {"rr1---sn.googlevideo.com"}})

    def test_grouped_by_device(self):
        conns = {"connections": [
            _conn("192.168.31.150", "142.250.190.14", sniff="a.googlevideo.com"),
            _conn("192.168.31.150", "142.250.190.15", sniff="b.googlevideo.com"),
            _conn("192.168.31.151", "8.8.8.8", sniff="dns.google"),
        ]}
        got = diag.dns_bypass_devices(conns)
        self.assertEqual(got["192.168.31.150"], {"a.googlevideo.com", "b.googlevideo.com"})
        self.assertEqual(got["192.168.31.151"], {"dns.google"})

    def test_no_sniff_not_flagged(self):
        # 没有嗅探到域名：纯 IP 连接，不算 DNS 绕过
        conns = {"connections": [
            _conn("192.168.31.150", "142.250.190.14"),
        ]}
        self.assertEqual(diag.dns_bypass_devices(conns), {})

    def test_private_dest_not_flagged(self):
        # 目标是内网 IP：局域网直连，不算绕过
        conns = {"connections": [
            _conn("192.168.31.150", "192.168.1.1", sniff="router.local"),
            _conn("192.168.31.150", "10.0.0.5", sniff="nas.local"),
        ]}
        self.assertEqual(diag.dns_bypass_devices(conns), {})

    def test_mixed(self):
        # 混合：只有绕过的被挑出来
        conns = {"connections": [
            _conn("192.168.31.150", "198.18.0.25", sniff="ok.googlevideo.com"),  # 正常
            _conn("192.168.31.150", "142.250.1.1", sniff="bad.googlevideo.com"),  # 绕过
            _conn("192.168.31.150", "192.168.1.1", sniff="router.local"),  # 内网
        ]}
        got = diag.dns_bypass_devices(conns)
        self.assertEqual(got, {"192.168.31.150": {"bad.googlevideo.com"}})

    def test_sniff_case_insensitive(self):
        conns = {"connections": [
            _conn("192.168.31.150", "142.250.190.14", sniff="RR1---SN.GoogleVideo.COM"),
        ]}
        got = diag.dns_bypass_devices(conns)
        self.assertEqual(got, {"192.168.31.150": {"rr1---sn.googlevideo.com"}})


if __name__ == "__main__":
    unittest.main()
