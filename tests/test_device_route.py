"""v10.2.0 按设备分流：mihomo / sing-box 规则生成（顺序、IPv6、缺失策略组跳过、停用忽略、MAC 解析）、校验、接口保存与读取"""
import copy
import os
import sys
import unittest
from unittest import mock

from tests.helper import server
from tests.test_v1012 import ApiCase

DR = sys.modules["shunt.devroute"]
SCH = sys.modules["shunt.schedule"]
W = sys.modules["shunt.webapi"]
V = sys.modules["shunt.validate"]
DATA = sys.modules["shunt.data"]

MANUAL = "\U0001F590\uFE0F 手动选择"
NODE = {"proxy": {"name": "n1", "type": "ss", "server": "1.2.3.4", "port": 8388, "cipher": "aes-128-gcm", "password": "x"}}
MAC = "aa:bb:cc:dd:ee:01"
REAL_NEIGH6 = DR.neigh6


def entry(**kw):
    e = {"name": "dev", "ip": "", "mac": "", "target": "DIRECT", "enabled": True}
    e.update(kw)
    return e


class Base(unittest.TestCase):
    def setUp(self):
        DR.SEEN.clear()
        DR._LOGGED.clear()
        self.d = copy.deepcopy(server.load())
        self.d.update(nodes=[copy.deepcopy(NODE)], rules=["DOMAIN-SUFFIX,example.com,DIRECT"], device_routes=[])
        self.arp, self.n6 = {}, {}
        ps = [mock.patch.object(DR, "arp_table", lambda: dict(self.arp)),
              mock.patch.object(DR, "neigh6", lambda: dict(self.n6))]
        for p in ps:
            p.start()
            self.addCleanup(p.stop)

    def rules(self, **kw):
        self.d.update(kw)
        return server.build_config(self.d)["rules"]

    @staticmethod
    def dev_rules(rules):
        return [r for r in rules if r.startswith("SRC-IP-CIDR,")]


class MihomoTest(Base):
    def test_order_and_targets(self):
        self.d["dns"] = dict(self.d["dns"], block_bypass=True)
        rules = self.rules(device_routes=[entry(name="tv", ip="192.168.1.5", target=MANUAL),
                                          entry(name="kid", ip="192.168.1.6", target="REJECT")])
        self.assertEqual(self.dev_rules(rules), [f"SRC-IP-CIDR,192.168.1.5/32,{MANUAL}", "SRC-IP-CIDR,192.168.1.6/32,REJECT"])
        i = rules.index(f"SRC-IP-CIDR,192.168.1.5/32,{MANUAL}")
        guard = max(k for k, r in enumerate(rules) if "dns-bypass" in r or "DST-PORT,853" in r)
        self.assertLess(guard, i)  # DNS 防绕过排在前面
        self.assertLess(rules.index("GEOIP,private,DIRECT,no-resolve"), i)  # 局域网直连排在前面
        self.assertLess(i, rules.index("DOMAIN-SUFFIX,example.com,DIRECT"))  # 优先于自定义规则
        self.assertTrue(rules[-1].startswith("MATCH,"))

    def test_tun_bypass_stays_first(self):
        rules = self.rules(proxy_mode="tun", bypass=["192.168.1.5"], device_routes=[entry(ip="192.168.1.5", target="REJECT")])
        self.assertEqual(rules[0], "SRC-IP-CIDR,192.168.1.5/32,DIRECT")  # 绕过设备优先：仍然直连
        self.assertLess(0, rules.index("SRC-IP-CIDR,192.168.1.5/32,REJECT"))

    def test_ipv6_and_cidr(self):
        rules = self.rules(device_routes=[entry(ip="fd00::5"), entry(name="net", ip="192.168.2.0/28", target="REJECT"),
                                          entry(name="v6net", ip="2408:8000::/64")])
        self.assertEqual(self.dev_rules(rules), ["SRC-IP-CIDR,fd00::5/128,DIRECT", "SRC-IP-CIDR,192.168.2.0/28,REJECT",
                                                 "SRC-IP-CIDR,2408:8000::/64,DIRECT"])

    def test_missing_group_skipped(self):
        with mock.patch("builtins.print") as pr:
            rules = self.rules(device_routes=[entry(name="gone", ip="192.168.1.7", target="🇯🇵 日本已删除"),
                                              entry(name="ok", ip="192.168.1.8", target="DIRECT")])
        self.assertEqual(self.dev_rules(rules), ["SRC-IP-CIDR,192.168.1.8/32,DIRECT"])
        self.assertTrue(any("日本已删除" in str(c) for c in pr.call_args_list))
        cfg = server.build_config(self.d)
        names = {g["name"] for g in cfg["proxy-groups"]} | server.BUILTIN_POLICIES | {"n1"}
        for r in cfg["rules"]:
            self.assertIn(r.split(",")[server.rule_policy_index(r.split(","))], names, r)

    def test_only_missing_adds_nothing(self):
        base = self.rules(device_routes=[])
        rules = self.rules(device_routes=[entry(ip="192.168.1.7", target="不存在的组")])
        self.assertEqual(rules, base)  # 没有有效条目时不插入局域网直连等额外规则

    def test_disabled_ignored(self):
        rules = self.rules(device_routes=[entry(ip="192.168.1.5", enabled=False), entry(ip="192.168.1.6", target="REJECT")])
        self.assertEqual(self.dev_rules(rules), ["SRC-IP-CIDR,192.168.1.6/32,REJECT"])

    def test_duplicate_address_first_wins(self):
        self.arp.update({"192.168.1.5": MAC})
        rules = self.rules(device_routes=[entry(ip="192.168.1.5", target="REJECT"), entry(name="b", mac=MAC)])
        self.assertEqual(self.dev_rules(rules), ["SRC-IP-CIDR,192.168.1.5/32,REJECT"])

    def test_bad_stored_entries_do_not_break(self):
        rules = self.rules(device_routes=["x", {"ip": "not-ip", "target": "DIRECT"}, {"ip": "10.0.0.1"}, entry(ip="10.0.0.2")])
        self.assertEqual(self.dev_rules(rules), ["SRC-IP-CIDR,10.0.0.2/32,DIRECT"])


class MacResolveTest(Base):
    def test_arp_only(self):
        self.arp.update({"192.168.1.20": MAC, "192.168.1.21": "11:22:33:44:55:66"})
        rules = self.rules(device_routes=[entry(mac="AA-BB-CC-DD-EE-01", target="REJECT")])
        self.assertEqual(self.dev_rules(rules), ["SRC-IP-CIDR,192.168.1.20/32,REJECT"])

    def test_ipv6_neighbors_only_when_ipv6_on(self):
        self.arp.update({"192.168.1.20": MAC})
        self.n6.update({"2408:8000::20": MAC})
        e = [entry(mac=MAC)]
        self.assertEqual(self.dev_rules(self.rules(ipv6=False, device_routes=e)), ["SRC-IP-CIDR,192.168.1.20/32,DIRECT"])
        self.assertEqual(self.dev_rules(self.rules(ipv6=True, device_routes=e)),
                         ["SRC-IP-CIDR,192.168.1.20/32,DIRECT", "SRC-IP-CIDR,2408:8000::20/128,DIRECT"])

    def test_unknown_mac_skipped_then_cached(self):
        e = [entry(mac=MAC)]
        self.assertEqual(self.dev_rules(self.rules(device_routes=e)), [])
        self.arp.update({"192.168.1.20": MAC})
        self.assertEqual(self.dev_rules(self.rules()), ["SRC-IP-CIDR,192.168.1.20/32,DIRECT"])
        self.arp.clear()  # 设备休眠、ARP 条目过期：沿用上次的 IP
        self.assertEqual(self.dev_rules(self.rules()), ["SRC-IP-CIDR,192.168.1.20/32,DIRECT"])
        self.arp.update({"192.168.1.20": "11:22:33:44:55:66"})  # IP 已分给别的设备：不再沿用
        self.assertEqual(self.dev_rules(self.rules()), [])

    def test_neigh6_parse(self):
        out = "2408:8000::20 dev eth0 lladdr AA:BB:CC:DD:EE:01 REACHABLE\nfe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:02 STALE\n" \
              "2408:8000::30 dev eth0  FAILED\n"
        with mock.patch.object(DR.subprocess, "run", return_value=mock.Mock(stdout=out)):
            self.assertEqual(REAL_NEIGH6(), {"2408:8000::20": MAC})
        with mock.patch.object(DR.subprocess, "run", side_effect=OSError("no ip")):
            self.assertEqual(REAL_NEIGH6(), {})

    def test_mac_changed_triggers_reload_once(self):
        self.d["device_routes"] = [entry(mac=MAC)]
        path = os.path.join(os.path.dirname(DR.APPLIED_FILE), "devroute_applied.json")
        with mock.patch.object(DR, "APPLIED_FILE", path + ".t"):
            DR.STATE.update(applied=None, loaded=False, last=None)
            self.arp.update({"192.168.1.20": MAC})
            server.build_config(self.d)
            DR.mark_applied()  # 正式配置写入时的解析结果
            self.assertIsNone(DR.mac_changed(self.d))
            self.arp.clear()
            self.arp.update({"192.168.1.40": MAC})  # 设备换了 IP
            SCH._DEVROUTE["tried"] = None
            with mock.patch.object(SCH, "reload_core", return_value=(True, "ok")) as rc, \
                    mock.patch.object(SCH, "sched_event"), mock.patch.dict(SCH.WD, manual_stop=False):
                SCH.devroute_tick(self.d)
                SCH.devroute_tick(self.d)  # 同一结果不重复重载
            rc.assert_called_once()
            DR.STATE.update(applied=None, loaded=False, last=None)
            try:
                os.unlink(path + ".t")
            except OSError:
                pass

    def test_no_mac_entries_no_work(self):
        self.d["device_routes"] = [entry(ip="192.168.1.5")]
        with mock.patch.object(DR, "arp_table", side_effect=AssertionError("不应读 ARP")):
            self.assertIsNone(DR.mac_changed(self.d))
            server.build_config(self.d)


class SingBoxTest(Base):
    def route(self, **kw):
        self.d.update(kw)
        return server.build_singbox(self.d)[0]["route"]["rules"]

    def test_source_ip_rules(self):
        rr = self.route(device_routes=[entry(ip="192.168.1.5", target=MANUAL), entry(name="k", ip="fd00::6", target="REJECT"),
                                       entry(name="d", ip="192.168.1.7", target="DIRECT"),
                                       entry(name="x", ip="192.168.1.8", target="不存在"), entry(ip="192.168.1.9", enabled=False)])
        src = [r for r in rr if "source_ip_cidr" in r]
        self.assertEqual(src, [{"source_ip_cidr": ["192.168.1.5/32"], "action": "route", "outbound": MANUAL},
                               {"source_ip_cidr": ["fd00::6/128"], "action": "reject"},
                               {"source_ip_cidr": ["192.168.1.7/32"], "action": "route", "outbound": "DIRECT"}])
        i = rr.index(src[0])
        self.assertLess(max(k for k, r in enumerate(rr) if r.get("action") == "hijack-dns"), i)  # DNS 劫持在前
        self.assertLess(rr.index({"ip_is_private": True, "action": "route", "outbound": "DIRECT"}), i)  # 局域网直连在前
        custom = next(k for k, r in enumerate(rr) if r.get("domain_suffix") == ["example.com"])
        self.assertLess(i, custom)

    def test_mac_resolved(self):
        self.arp.update({"192.168.1.20": MAC})
        rr = self.route(device_routes=[entry(mac=MAC, target="REJECT")])
        self.assertIn({"source_ip_cidr": ["192.168.1.20/32"], "action": "reject"}, rr)


class ValidateTest(unittest.TestCase):
    def test_good(self):
        out = DR.clean_device_routes([{"name": " tv ", "ip": "192.168.1.5/32", "target": MANUAL},
                                      {"mac": "AA-BB-CC-DD-EE-01", "target": "REJECT", "enabled": False},
                                      {"ip": "192.168.1.9/24", "target": "DIRECT"}, {"ip": "FD00::1", "target": "DIRECT"}])
        self.assertEqual(out[0], {"name": "tv", "ip": "192.168.1.5", "mac": "", "target": MANUAL, "enabled": True})
        self.assertEqual(out[1], {"name": MAC, "ip": "", "mac": MAC, "target": "REJECT", "enabled": False})
        self.assertEqual(out[2]["ip"], "192.168.1.0/24")
        self.assertEqual(out[3]["ip"], "fd00::1")
        self.assertEqual(V.clean_fields({"device_routes": []}, {"device_routes"}), {"device_routes": []})

    def test_bad(self):
        bad = ["x", [1], [{"target": "DIRECT"}], [{"ip": "1.2.3.4", "mac": MAC, "target": "DIRECT"}],
               [{"ip": "999.1.1.1", "target": "DIRECT"}], [{"mac": "zz:bb:cc:dd:ee:ff", "target": "DIRECT"}],
               [{"ip": "1.2.3.4"}], [{"ip": "1.2.3.4", "target": "a,b"}], [{"ip": "1.2.3.4", "target": "DIRECT", "name": 5}],
               [{"ip": "1.2.3.4", "target": "DIRECT"}, {"ip": "1.2.3.4/32", "target": "REJECT"}],
               [{"ip": "1.2.3.4", "target": "DIRECT"}] * (DR.ROUTES_MAX + 1)]
        for v in bad:
            with self.assertRaises(ValueError, msg=str(v)[:80]):
                V.clean_fields({"device_routes": v}, {"device_routes"})

    def test_rename_follows(self):
        d = {"device_routes": [entry(ip="1.1.1.1", target="旧组")], "rules": []}
        self.assertEqual(DATA.map_refs(d, {"旧组": "新组"}), 1)
        self.assertEqual(d["device_routes"][0]["target"], "新组")


class ApiTest(ApiCase):
    def test_save_and_load(self):
        routes = [{"name": "电视", "ip": "192.168.1.5", "target": "REJECT"}, {"name": "手机", "mac": "AA:BB:CC:DD:EE:01", "target": "DIRECT"}]
        with mock.patch.object(W, "reload_core", return_value=(True, "配置已重载")) as rc, \
                mock.patch.object(W, "tp_apply", return_value=(0, "")) as tp:
            code, j = self.call("PUT", "/api/settings", {"device_routes": routes})
        self.assertEqual(code, 200, j)
        rc.assert_called_once()
        tp.assert_not_called()
        saved = server.load()["device_routes"]
        self.assertEqual(saved[1], {"name": "手机", "ip": "", "mac": MAC, "target": "DIRECT", "enabled": True})
        code, st = self.call("GET", "/api/state")
        self.assertEqual(code, 200)
        self.assertEqual(st["device_routes"], saved)
        code, bk = self.call("GET", "/api/backup")
        self.assertEqual(bk["device_routes"], saved)

    def test_bad_rejected(self):
        before = server.load()["device_routes"]
        with mock.patch.object(W, "reload_core", return_value=(True, "ok")) as rc:
            code, j = self.call("PUT", "/api/settings", {"device_routes": [{"ip": "nope", "target": "DIRECT"}]})
        self.assertEqual(code, 400, j)
        self.assertIn("IP", j["message"])
        rc.assert_not_called()
        self.assertEqual(server.load()["device_routes"], before)

    def test_missing_group_warned(self):
        with mock.patch.object(W, "reload_core", return_value=(True, "配置已重载")):
            code, j = self.call("PUT", "/api/settings", {"device_routes": [{"name": "盒子", "ip": "192.168.1.9", "target": "不存在的组"}]})
        self.assertEqual(code, 200, j)
        self.assertIn("盒子", j["message"])
        self.assertIn("不存在", j["message"])

    def test_restore(self):
        routes = [{"name": "a", "ip": "10.0.0.3", "target": "DIRECT", "enabled": False}]
        with mock.patch.object(W, "reload_core", return_value=(True, "配置已重载")), \
                mock.patch.object(W, "tp_apply", return_value=(0, "")), mock.patch.object(W, "ab_compose"):
            code, j = self.call("POST", "/api/restore", {"device_routes": routes, "mode": "rule"})
            self.assertEqual(code, 200, j)
            self.assertEqual(server.load()["device_routes"][0]["ip"], "10.0.0.3")
            code, j = self.call("POST", "/api/restore", {"device_routes": [{"ip": "x", "target": "DIRECT"}], "mode": "rule"})
            self.assertEqual(code, 400, j)


if __name__ == "__main__":
    unittest.main()
