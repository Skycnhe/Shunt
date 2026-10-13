import json, unittest
from tests.helper import server


def _stats():
    st = server.AdStats.__new__(server.AdStats)
    st.lock = server.threading.Lock()
    st.data = {"days": {}, "hours": {}, "dns5": {}}
    st.dns_recent = server.deque(maxlen=60)
    st._req_batch = 0
    st.saved = 9e18  # 测试里不落盘
    return st


def _sb(st, cid, body):
    st.sink_sb(json.dumps({"type": "debug", "payload": f"[{cid} 0ms] {body}"}))


REJ = "router: match[3] rule_set=ad-abc => reject"


class AdFakeIP(unittest.TestCase):
    """广告拦截排行里不应出现 198.18.x.x：sing-box 按 Fake-IP 映射还原的域名才是被拦截的对象"""

    def test_singbox_fakeip_domain_recorded(self):
        st = _stats()
        _sb(st, 101, "inbound/tproxy[tproxy-in]: inbound connection to 198.18.0.11:443")
        _sb(st, 101, "router: found fakeip domain: ads.example.com")
        _sb(st, 101, REJ)
        rep = st.report()
        self.assertEqual(rep["today"], 1)
        self.assertEqual(rep["top"], [("ads.example.com", 1)])

    def test_sniff_still_wins_and_fakeip_does_not_override_domain(self):
        st = _stats()
        _sb(st, 7, "inbound/tproxy[tproxy-in]: inbound connection to 198.18.0.12:443")
        _sb(st, 7, "router: sniffed protocol: tls, domain: t.example.com")
        _sb(st, 7, "router: found fakeip domain: other.example.com")
        _sb(st, 7, REJ)
        self.assertEqual(st.report()["top"], [("t.example.com", 1)])

    def test_unresolved_fakeip_counted_but_not_ranked(self):
        st = _stats()
        _sb(st, 9, "inbound/tproxy[tproxy-in]: inbound packet connection to 198.18.0.11:443")
        _sb(st, 9, REJ)
        st.hit("[fc00::5]", "ad-abc")
        st.hit("?", "ad-abc")
        rep = st.report()
        self.assertEqual(rep["today"], 3)
        self.assertEqual(rep["top"], [])

    def test_old_stats_with_fakeip_hidden(self):
        st = _stats()
        day = server.time.strftime("%Y-%m-%d")
        st.data["days"][day] = {"count": 5, "top": {"198.18.0.11": 4, "ads.example.com": 1}, "lists": {}}
        self.assertEqual(st.report()["top"], [("ads.example.com", 1)])

    def test_mihomo_fakeip_host_not_ranked(self):
        st = _stats()
        line = json.dumps({"type": "info", "payload": "[TCP] 192.168.1.5:5000 --> 198.18.0.11:443 match RuleSet(ad-abc) using REJECT"})
        st.sink(line)
        self.assertEqual(st.report()["today"], 1)
        self.assertEqual(st.report()["top"], [])

    def test_is_fake_ip(self):
        for h in ("198.18.0.11", "198.19.255.1", "[fc00::1]"):
            self.assertTrue(server.is_fake_ip(h), h)
        for h in ("8.8.8.8", "ads.example.com", "?", "192.168.1.1"):
            self.assertFalse(server.is_fake_ip(h), h)


if __name__ == "__main__":
    unittest.main()
