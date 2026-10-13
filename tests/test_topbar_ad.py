import os, re, time, unittest
from unittest import mock
from tests.helper import server
from tests.test_p0opt import _handler

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TopbarAdChip(unittest.TestCase):
    """顶栏「广告拦截」卡片：今天的拦截数，与概览同一口径"""

    def _stats(self):
        st = server.AdStats.__new__(server.AdStats)
        st.lock = server.threading.Lock()
        st.data = {"days": {}, "hours": {}, "dns5": {}}
        st.dns_recent = server.deque(maxlen=60)
        st._req_batch = 0
        return st

    def test_today_matches_report(self):
        st = self._stats()
        st.data["days"]["2000-01-01"] = {"count": 99, "top": {}, "lists": {}}  # 昨天及更早不算
        self.assertEqual(st.today(), 0)
        for _ in range(3):
            st.hit("ads.example.com", "ad-abc")
        self.assertEqual(st.today(), 3)
        self.assertEqual(st.today(), st.report()["today"])

    def test_ping_carries_ad_today(self):
        st = self._stats()
        st.hit("ads.example.com", "ad-abc")
        with mock.patch.object(server.adblock, "AD_STATS", st):
            h, cap = _handler("/api/ping")
            h.route("GET")
        self.assertEqual(cap["code"], 200)
        self.assertEqual(cap["obj"]["ad_today"], 1)
        with mock.patch.object(server.adblock, "AD_STATS", None):  # 统计还没起来：0 而不是报错
            h, cap = _handler("/api/ping")
            h.route("GET")
        self.assertEqual(cap["obj"]["ad_today"], 0)

    def test_default_tz_beijing_when_unset(self):
        old = os.environ.get("TZ")
        try:
            os.environ.pop("TZ", None)
            with mock.patch.object(server.os.path, "exists", lambda p: False if p == "/etc/localtime" else os.path.exists(p)):
                self.assertTrue(server.default_tz())
            self.assertEqual(time.localtime(0).tm_hour, 8)  # UTC 0 点 = 北京 8 点
            os.environ["TZ"] = "UTC"
            self.assertFalse(server.default_tz())  # 设备 / 环境设了时区就不动
        finally:
            if old is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old
            time.tzset()

    def test_chip_sits_between_memory_and_versions(self):
        with open(os.path.join(ROOT, "web", "index.html"), encoding="utf-8") as f:
            html = f.read()
        hs = html[html.index('<div class="hstats">'):]
        i_mem, i_ad, i_ver = hs.index('id="h-mem"'), hs.index('id="h-ad"'), hs.index('class="vchips"')
        self.assertTrue(i_mem < i_ad < i_ver)
        self.assertIn("广告拦截", re.search(r'id="h-ad".*?</div>', hs, re.S).group(0))
        with open(os.path.join(ROOT, "web", "js", "03-header.js"), encoding="utf-8") as f:
            js = f.read()
        self.assertIn("ad_today", js)


if __name__ == "__main__":
    unittest.main()
