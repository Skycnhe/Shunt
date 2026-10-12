"""v7.5.9：归属地去重、直连延迟测法、sing-box Fake-IP（TTL / 网段 / 持久化）"""
import json
import sys
import unittest
from unittest import mock

from tests.helper import server


class LocDedup(unittest.TestCase):
    def test_dedup(self):
        f = server.loc_dedup
        self.assertEqual(f("中国 重庆 重庆 电信"), "中国 重庆 电信")
        self.assertEqual(f("中国 重庆市 重庆 电信"), "中国 重庆 电信")
        self.assertEqual(f("中国 北京 北京市 联通"), "中国 北京 联通")
        self.assertEqual(f("中国  上海  上海  移动"), "中国 上海 移动")
        self.assertEqual(f("重庆市 重庆"), "重庆")

    def test_untouched(self):
        f = server.loc_dedup
        self.assertEqual(f("中国 广东省 深圳市 电信"), "中国 广东省 深圳市 电信")
        self.assertEqual(f("日本 东京都 Minato"), "日本 东京都 Minato")
        self.assertEqual(f("美国 加利福尼亚 洛杉矶"), "美国 加利福尼亚 洛杉矶")
        self.assertEqual(f("中国 吉林省 吉林市 联通"), "中国 吉林省 吉林市 联通")  # 省、市两级同名不算重复
        self.assertEqual(f(""), "")
        self.assertEqual(f(None), "")


class DirectRtt(unittest.TestCase):
    def _core(self, seq):
        calls = []

        def fake(method, path, body=None, timeout=10):
            calls.append(path)
            v = seq.pop(0)
            return (200, json.dumps({"delay": v}).encode()) if v else (502, b"{}")
        return fake, calls

    def test_core_direct_with_domestic_url_min_of_two(self):
        fake, calls = self._core([1015, 30])
        with mock.patch.object(sys.modules["shunt.corehttp"], "core", fake):
            self.assertEqual(server.direct_rtt(), 30)
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(c.startswith("/proxies/DIRECT/delay?url=") for c in calls))
        self.assertIn("connect.rom.miui.com", calls[0])
        self.assertNotIn("gstatic", calls[0])

    def test_fallback_when_core_down(self):
        fake, _ = self._core([0])
        with mock.patch.object(sys.modules["shunt.corehttp"], "core", fake), \
                mock.patch("subprocess.check_output", return_value="0.400\n0.031\n") as co:
            self.assertEqual(server.direct_rtt(), 31)
        cmd = co.call_args[0][0]
        self.assertEqual(cmd.count(server.DIRECT_HC), 2)  # 同一连接请求两次，取第二次


class SingboxFakeIP(unittest.TestCase):
    def test_fakeip_ttl_range_cache(self):
        d = server.load()
        d["dns"] = dict(d["dns"], mode="fake-ip")
        conf = server.build_singbox(d)[0]
        fake = [s for s in conf["dns"]["servers"] if s.get("type") == "fakeip"]
        self.assertEqual(fake[0]["inet4_range"], "198.18.0.0/16")
        rule = [r for r in conf["dns"]["rules"] if r.get("server") == "dns-fake"]
        self.assertEqual(rule[0].get("rewrite_ttl"), 1)
        cf = conf["experimental"]["cache_file"]
        self.assertTrue(cf["enabled"] and cf["store_fakeip"])

    def test_mihomo_same_range(self):
        d = server.load()
        d["dns"] = dict(d["dns"], mode="fake-ip")
        cfg = server.build_config(d)
        self.assertEqual(cfg["dns"]["fake-ip-range"], "198.18.0.1/16")
        self.assertTrue(cfg["profile"]["store-fake-ip"])


if __name__ == "__main__":
    unittest.main()
