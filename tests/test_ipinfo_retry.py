import unittest
from unittest import mock
from tests.helper import server
import shunt.ipinfo as ipinfo
import shunt.sysopt as sysopt

assert server  # 先导入 server：注册内嵌 shunt 包

ok = {"direct": {"ip": "1.2.3.4", "loc": "中国"}, "proxy": {"ip": "5.6.7.8", "loc": "日本"}}
bad = {"direct": {"ip": "", "loc": ""}, "proxy": {"ip": "", "loc": ""}}


class IpInfoRetry(unittest.TestCase):
    """重启后 IP 信息一直「-」：失败结果不能缓存 10 分钟，要退避重查"""

    def setUp(self):
        self.mod = ipinfo
        self.mod._CACHE.update(t=0, v=None, fail=0, next=0)

    def _get(self, q, now):
        with mock.patch.object(self.mod.time, "time", return_value=now):
            return self.mod.get_ipinfo(q)

    def test_failure_not_cached_and_backoff(self):
        calls = []
        q_bad = lambda: calls.append(1) or bad
        r = self._get(q_bad, 1000)
        self.assertEqual(r["retry"], 5)
        self.assertEqual(len(calls), 1)
        r = self._get(q_bad, 1003)  # 退避期内不重复查
        self.assertEqual(len(calls), 1)
        self.assertEqual(r["retry"], 2)
        r = self._get(q_bad, 1006)  # 到点重查，间隔翻倍
        self.assertEqual(len(calls), 2)
        self.assertEqual(r["retry"], 10)
        r = self._get(lambda: ok, 1017)  # 核心就绪后查到：缓存，不再带 retry
        self.assertNotIn("retry", r)
        self.assertEqual(r["proxy"]["ip"], "5.6.7.8")
        r = self._get(q_bad, 1200)  # 10 分钟内用缓存
        self.assertEqual(r["direct"]["ip"], "1.2.3.4")

    def test_partial_is_retried(self):
        part = {"direct": {"ip": "1.2.3.4", "loc": ""}, "proxy": {"ip": "", "loc": ""}}
        r = self._get(lambda: part, 1000)
        self.assertEqual(r["retry"], 5)
        self.assertEqual(r["direct"]["ip"], "1.2.3.4")

    def test_backoff_caps_at_60(self):
        self.assertEqual([self.mod._backoff(n) for n in range(1, 8)], [5, 10, 20, 40, 60, 60, 60])

    def test_reset_on_core_restart(self):
        self._get(lambda: ok, 1000)
        with mock.patch.object(sysopt, "sh", return_value=(0, "")), mock.patch.object(sysopt, "wd_hold"):
            sysopt.svc_restart()
        self.assertIsNone(self.mod._CACHE["v"])

    def test_proxy_side_skipped_when_core_down(self):
        with mock.patch.object(self.mod, "core_ready", return_value=False), \
             mock.patch.object(self.mod, "_fetch", return_value="") as f, \
             mock.patch.object(self.mod, "_fetch_direct_ip", return_value="1.2.3.4"), \
             mock.patch.object(self.mod, "_geo", return_value=""), \
             mock.patch.object(self.mod, "_fetch_cn_ip") as cn:
            v = self.mod._query()
        self.assertEqual(v["proxy"]["ip"], "")
        self.assertEqual(v["direct"]["ip"], "1.2.3.4")  # 本地公网绕过核心直连
        cn.assert_not_called()
        self.assertFalse([c for c in f.call_args_list if c.args[1:2] == (True,)])  # 核心没起来不经代理白等


if __name__ == "__main__":
    unittest.main()
