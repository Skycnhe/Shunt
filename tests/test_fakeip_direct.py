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
    """直连延迟与概览「百度」卡片同口径（v7.6.1）"""
    S = sys.modules["shunt.sysopt"]

    def _core(self, mode, delays):
        calls = []
        delays = list(delays)

        def fake(method, path, body=None, timeout=10):
            calls.append(path)
            if path == "/configs":
                return (200, json.dumps({"mode": mode}).encode()) if mode else (502, b"{}")
            v = delays.pop(0) if delays else 0
            return (200, json.dumps({"delay": v}).encode()) if v else (502, b"{}")
        return fake, calls

    def test_rule_mode_same_as_baidu_card(self):
        fake, calls = self._core("rule", [])
        with mock.patch.object(sys.modules["shunt.corehttp"], "core", fake), \
                mock.patch.object(self.S, "site_rtt", return_value=31) as st:
            self.assertEqual(server.direct_rtt(), 31)
        st.assert_called_once()
        self.assertEqual(st.call_args[0][0], "https://www.baidu.com")
        self.assertFalse(any(c.startswith("/proxies/") for c in calls))

    def test_global_mode_uses_core_direct_min_of_two(self):
        fake, calls = self._core("global", [1015, 30])
        with mock.patch.object(sys.modules["shunt.corehttp"], "core", fake), \
                mock.patch.object(self.S, "site_rtt", return_value=999) as st:
            self.assertEqual(server.direct_rtt(), 30)
        st.assert_not_called()
        px = [c for c in calls if c.startswith("/proxies/DIRECT/delay?url=")]
        self.assertEqual(len(px), 2)
        self.assertIn("baidu.com", px[0])

    def test_fallback_when_core_down(self):
        fake, _ = self._core(None, [])
        with mock.patch.object(sys.modules["shunt.corehttp"], "core", fake), \
                mock.patch.object(self.S, "site_rtt", side_effect=OSError("refused")), \
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
        self.assertEqual(fake[0]["inet4_range"], "198.18.0.0/15")  # v8.2.2：/15 兼容老版本分配的 198.19.x.x
        rule = [r for r in conf["dns"]["rules"] if r.get("server") == "dns-fake"]
        self.assertEqual(rule[0].get("rewrite_ttl"), 1)
        cf = conf["experimental"]["cache_file"]
        self.assertTrue(cf["enabled"] and cf["store_fakeip"])

    def test_mihomo_same_range(self):
        d = server.load()
        d["dns"] = dict(d["dns"], mode="fake-ip")
        cfg = server.build_config(d)
        self.assertEqual(cfg["dns"]["fake-ip-range"], "198.18.0.1/16")
        self.assertFalse(cfg["profile"]["store-fake-ip"])  # v10.3.2：关闭，热重载保留映射


if __name__ == "__main__":
    unittest.main()
