"""v8.4.15（与 Hk002 v10.3.11 相同）：直连规则审查发现的问题。
- 自定义规则「静默不生效」的写法：DOMAIN-SUFFIX 值带前导 . / +. / *.（mihomo 永不命中）、DOMAIN 写成 +.a.com、
  IP-CIDR 只写单个 IP（mihomo 整份配置校验失败）→ 保存时和生成配置时规范化（两个内核都生效）
- sing-box：新引用的 GEOSITE / GEOIP 规则、规则集订阅保存后不下载 .srs，规则被当成「未下载」跳过 → 重载前补下缺失文件
- sing-box：逻辑规则里的 GEOSITE / GEOIP 不在下载需求表里，永远下载不到 → sb_rule_need 也扫描逻辑规则
- tproxy.sh：Fake-IP 的 IPv6 段落在 reserved6（fc00::/7）里被 return，AAAA 假地址的连接不进核心 → 先交给核心
设置 SHUNT_TEST_MIHOMO=<mihomo> / SHUNT_TEST_SINGBOX=<sing-box> 时用真实内核校验生成的配置"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tests.helper import server
from tests.test_v1012 import ApiCase
from tests.test_v840 import base

assert server

B = sys.modules["shunt.base"]
RU = sys.modules["shunt.ruleutil"]
MH = sys.modules["shunt.mihomo"]
SBC = sys.modules["shunt.sb_config"]
C = sys.modules["shunt.core"]
WA = sys.modules["shunt.webapi"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEL = B.G_SEL
VER = "8.4.15"


def read(*p):
    with open(os.path.join(ROOT, *p), encoding="utf-8") as f:
        return f.read()


class VersionTest(unittest.TestCase):
    def test_version(self):
        self.assertEqual(B.PANEL_VERSION, VER)

    def test_changelog_top(self):
        heads = [ln for ln in read("CHANGELOG.md").splitlines() if ln.startswith("## v")]
        self.assertTrue(heads[0].startswith("## v" + VER), heads[0])

    def test_built(self):
        self.assertIn(f'PANEL_VERSION = "{VER}"', read("server.py"))


class NormRuleTest(unittest.TestCase):
    def test_domain_suffix_prefix(self):
        n = RU.norm_rule
        self.assertEqual(n("DOMAIN-SUFFIX,.lead.com,DIRECT"), "DOMAIN-SUFFIX,lead.com,DIRECT")
        self.assertEqual(n("DOMAIN-SUFFIX,+.plus.net,DIRECT"), "DOMAIN-SUFFIX,plus.net,DIRECT")
        self.assertEqual(n("DOMAIN-SUFFIX,*.star.net,DIRECT"), "DOMAIN-SUFFIX,star.net,DIRECT")
        self.assertEqual(n("domain-suffix, .x.com ,DIRECT"), "domain-suffix,x.com,DIRECT")
        self.assertEqual(n("DOMAIN-SUFFIX,.nopol.com"), "DOMAIN-SUFFIX,nopol.com")
        self.assertEqual(n("DOMAIN,+.a.com,DIRECT"), "DOMAIN-SUFFIX,a.com,DIRECT")
        self.assertEqual(n("DOMAIN,.a.com,DIRECT"), "DOMAIN-SUFFIX,a.com,DIRECT")

    def test_bare_ip(self):
        n = RU.norm_rule
        self.assertEqual(n("IP-CIDR,5.6.7.9,DIRECT,no-resolve"), "IP-CIDR,5.6.7.9/32,DIRECT,no-resolve")
        self.assertEqual(n("IP-CIDR6,2400:cb00::1,DIRECT"), "IP-CIDR6,2400:cb00::1/128,DIRECT")
        self.assertEqual(n("IP-CIDR,[2400:cb00::1],DIRECT"), "IP-CIDR,2400:cb00::1/128,DIRECT")
        self.assertEqual(n("SRC-IP-CIDR,192.168.1.50,DIRECT"), "SRC-IP-CIDR,192.168.1.50/32,DIRECT")

    def test_untouched(self):
        n = RU.norm_rule
        for r in ("DOMAIN-SUFFIX,a.com,DIRECT", "DOMAIN,a.com,DIRECT", "DOMAIN-WILDCARD,*.a.com,DIRECT",
                  "IP-CIDR,1.2.3.0/24,DIRECT,no-resolve", "IP-CIDR,not-an-ip,DIRECT", "AND,((DOMAIN-SUFFIX,.a.com),(NETWORK,UDP)),DIRECT",
                  "# DOMAIN-SUFFIX,.a.com,DIRECT", "", "MATCH,DIRECT", "DOMAIN-SUFFIX,.,DIRECT", "GEOSITE,cn,DIRECT"):
            self.assertEqual(n(r), r)


RULES = ["DOMAIN-SUFFIX,.lead.com,DIRECT", "DOMAIN-SUFFIX,+.plus.net,DIRECT", "DOMAIN,+.d.org,DIRECT",
         "IP-CIDR,5.6.7.9,DIRECT,no-resolve", "IP-CIDR,2400:cb00::1,DIRECT,no-resolve", "DOMAIN-SUFFIX,.nopol.com"]


class ConfigTest(unittest.TestCase):
    def test_mihomo(self):
        d = base()
        d["rules"] = list(RULES)
        rules = MH.build_config(d)["rules"]
        for r in ("DOMAIN-SUFFIX,lead.com,DIRECT", "DOMAIN-SUFFIX,plus.net,DIRECT", "DOMAIN-SUFFIX,d.org,DIRECT",
                  "IP-CIDR,5.6.7.9/32,DIRECT,no-resolve", "IP-CIDR,2400:cb00::1/128,DIRECT,no-resolve", f"DOMAIN-SUFFIX,nopol.com,{SEL}"):
            self.assertIn(r, rules)

    def test_singbox(self):
        d = base(core="singbox")
        d["rules"] = list(RULES)
        rr = SBC.build_singbox(d)[0]["route"]["rules"]
        sufs = [x for r in rr if r.get("outbound") == "DIRECT" for x in r.get("domain_suffix") or []]
        for v in ("lead.com", "plus.net", "d.org"):
            self.assertIn(v, sufs)
        self.assertFalse([x for x in sufs if x.startswith(("+", "*", "."))], sufs)
        cidrs = [x for r in rr for x in r.get("ip_cidr") or []]
        self.assertIn("5.6.7.9/32", cidrs)
        self.assertIn("2400:cb00::1/128", cidrs)


class RulesApiTest(ApiCase):
    def test_put_saves_normalized(self):
        server.save(base())
        with mock.patch.object(WA, "reload_core", return_value=(True, "ok")):
            code, j = self.call("PUT", "/api/rules", {"rules": ["DOMAIN-SUFFIX,*.a.com,DIRECT", "IP-CIDR,1.2.3.4,DIRECT,no-resolve",
                                                                "DOMAIN-SUFFIX,.b.com"]})
        self.assertEqual(code, 200, j)
        self.assertEqual(server.load()["rules"], ["DOMAIN-SUFFIX,a.com,DIRECT", "IP-CIDR,1.2.3.4/32,DIRECT,no-resolve",
                                                  f"DOMAIN-SUFFIX,b.com,{SEL}"])


class RuleNeedTest(unittest.TestCase):
    def test_logical_geo_in_need(self):
        d = base(core="singbox")
        d["rules"] = ["AND,((GEOSITE,steam),(NETWORK,TCP)),DIRECT", "OR,((GEOIP,JP,no-resolve),(DOMAIN,a.com)),DIRECT",
                      "NOT,((GEOSITE,Category-Games)),DIRECT", "# GEOSITE,commented,DIRECT", "GEOSITE,apple,DIRECT"]
        need = SBC.sb_rule_need(d)
        for t in ("geosite-steam", "geoip-jp", "geosite-category-games", "geosite-apple"):
            self.assertIn(t, need)
        self.assertNotIn("geosite-commented", need)
        self.assertEqual(need["geosite-category-games"]["path"], "geosite-category-games.srs")
        # 与完整构建的需求表一致（下载 / GEO 更新按 sb_rule_need，生成配置按完整构建）
        self.assertEqual(set(need), set(SBC.build_singbox(d)[2]))


class FetchMissingTest(unittest.TestCase):
    """sing-box：保存规则后新引用、本地没有的规则集先下载，再生成配置"""

    def setUp(self):
        self.orig = server.load()
        self.dir = tempfile.mkdtemp(prefix="sbrules-")
        self.p = mock.patch.object(SBC, "SB_RULE_DIR", self.dir)
        self.p.start()
        SBC._MISSING_FAIL.clear()

    def tearDown(self):
        server.save(self.orig)  # 别把 sing-box 数据留给后面的用例
        self.p.stop()
        SBC._MISSING_FAIL.clear()
        shutil.rmtree(self.dir, ignore_errors=True)

    def have_all(self, d, skip=()):
        for tag, rsd in SBC.sb_rule_need(d).items():
            if tag not in skip and rsd["kind"] != "adblock":
                with open(os.path.join(self.dir, rsd["path"]), "wb") as f:
                    f.write(b"SRS1")

    def test_new_geosite_rule_downloaded_before_reload(self):
        d = base(core="singbox")
        d["rules"] = ["GEOSITE,apple,DIRECT"]
        self.have_all(d, skip=("geosite-apple",))
        server.save(d)
        calls = []

        def fake_sync(dd, force=False, need=None, wait=None):
            calls.append((sorted(need), force, wait))
            for rsd in need.values():
                with open(os.path.join(self.dir, rsd["path"]), "wb") as f:
                    f.write(b"SRS1")
            return []
        seen = {}

        def fake_reload(prev):
            conf = SBC.build_singbox(server.load())[0]
            seen["rules"] = conf["route"]["rules"]
            return True, "ok"
        with mock.patch.object(SBC, "sb_sync_assets", side_effect=fake_sync), mock.patch.object(C, "_reload_core", side_effect=fake_reload):
            self.assertEqual(C.reload_core(), (True, "ok"))
        self.assertEqual(calls, [(["geosite-apple"], False, SBC.MISSING_WAIT)])
        self.assertTrue(any(r.get("rule_set") == ["geosite-apple"] and r.get("outbound") == "DIRECT" for r in seen["rules"]), seen)

    def test_nothing_missing_no_download(self):
        d = base(core="singbox")
        d["rules"] = ["GEOSITE,apple,DIRECT"]
        self.have_all(d)
        server.save(d)
        with mock.patch.object(SBC, "sb_sync_assets") as sync, mock.patch.object(C, "_reload_core", return_value=(True, "ok")):
            C.reload_core()
        sync.assert_not_called()

    def test_failed_download_cooldown(self):
        d = base(core="singbox")
        d["rules"] = ["GEOSITE,apple,DIRECT"]
        self.have_all(d, skip=("geosite-apple",))
        server.save(d)
        with mock.patch.object(SBC, "sb_sync_assets", return_value=["geosite-apple：下载失败"]) as sync, \
                mock.patch.object(C, "_reload_core", return_value=(True, "ok")):
            self.assertEqual(C.reload_core(), (True, "ok"))  # 下载失败不影响保存，规则照旧跳过并提示
            C.reload_core()  # 10 分钟内不再重试
        self.assertEqual(sync.call_count, 1)

    def test_mihomo_untouched(self):
        d = base()
        d["rules"] = ["GEOSITE,apple,DIRECT"]
        server.save(d)
        with mock.patch.object(SBC, "sb_sync_assets") as sync, mock.patch.object(C, "_reload_core", return_value=(True, "ok")):
            C.reload_core()
        sync.assert_not_called()

    def test_wait_param(self):
        self.assertIn("wait=None", read("shunt", "sb_config.py").split("def sb_sync_assets", 1)[1].split("\n", 1)[0])


FAKE = "#!/bin/sh\n[ \"$1\" = -f ] && cat > \"$OUT\"\nexit 0\n"


class TproxyFakeV6Test(unittest.TestCase):
    def test_fake_v6_ranges_tproxied_before_reserved(self):
        d = tempfile.mkdtemp(prefix="tp6-")
        try:
            bind = os.path.join(d, "bin")
            os.makedirs(bind)
            for c, body in (("nft", FAKE), ("sysctl", "#!/bin/sh\nexit 0\n"), ("modprobe", "#!/bin/sh\nexit 0\n"), ("ip", "#!/bin/sh\nexit 0\n")):
                with open(os.path.join(bind, c), "w") as f:
                    f.write(body)
                os.chmod(os.path.join(bind, c), 0o755)
            env_f = os.path.join(d, "env")
            with open(env_f, "w") as f:
                f.write("B_IP=''\nB_MAC=''\nB_IP6=''\nLOCAL6='fe80::1'\nIPV6=1\nMODE=tproxy\nDNS_ALL=0\n")
            out = os.path.join(d, "rules.nft")
            env = dict(os.environ, PATH=bind + ":" + os.environ["PATH"], TPENV_FILE=env_f, OUT=out)
            r = subprocess.run(["sh", os.path.join(ROOT, "tproxy.sh"), "start"], env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(out) as f:
                lines = [ln.strip() for ln in f.read().splitlines()]
            fake = [i for i, ln in enumerate(lines) if "fc00::/18" in ln and "fdfe:dcba:9876::/64" in ln and "tproxy ip6" in ln]
            res = [i for i, ln in enumerate(lines) if "ip6 daddr @reserved6 return" in ln]
            self.assertTrue(fake and res and fake[0] < res[0], lines)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_ranges_match_generated_configs(self):
        d = base(core="singbox")
        d["ipv6"] = True
        d["dns"] = dict(d.get("dns") or {}, mode="fake-ip")
        fake = [s for s in SBC.build_singbox(d)[0]["dns"]["servers"] if s.get("type") == "fakeip"][0]
        self.assertEqual(fake["inet6_range"], "fc00::/18")
        d["core"] = "mihomo"
        self.assertTrue(MH.build_config(d)["dns"]["fake-ip-range6"].startswith("fdfe:dcba:9876::"))
        self.assertTrue(MH.build_config(d)["dns"]["fake-ip-range6"].endswith("/64"))


@unittest.skipUnless(os.environ.get("SHUNT_TEST_MIHOMO") and os.access(os.environ.get("SHUNT_TEST_MIHOMO", ""), os.X_OK),
                     "设置 SHUNT_TEST_MIHOMO=<mihomo 可执行文件> 时运行")
class RealMihomoTest(unittest.TestCase):
    def test_bare_ip_rule_passes(self):
        d = base()
        d["rules"] = list(RULES)
        wd = tempfile.mkdtemp(prefix="mh-")
        try:
            with open(os.path.join(wd, "config.yaml"), "w") as f:
                json.dump(MH.build_config(d), f, ensure_ascii=False)
            r = subprocess.run([os.environ["SHUNT_TEST_MIHOMO"], "-t", "-d", wd, "-f", os.path.join(wd, "config.yaml")],
                               capture_output=True, text=True, timeout=120)
            self.assertIn("test is successful", r.stdout + r.stderr, r.stdout + r.stderr)
        finally:
            shutil.rmtree(wd, ignore_errors=True)


@unittest.skipUnless(os.environ.get("SHUNT_TEST_SINGBOX") and os.access(os.environ.get("SHUNT_TEST_SINGBOX", ""), os.X_OK),
                     "设置 SHUNT_TEST_SINGBOX=<sing-box 可执行文件> 时运行")
class RealSingboxTest(unittest.TestCase):
    def test_check(self):
        d = base(core="singbox")
        d["rules"] = list(RULES)
        wd = tempfile.mkdtemp(prefix="sb-")
        try:
            p = os.path.join(wd, "config.json")
            with open(p, "w") as f:
                json.dump(SBC.build_singbox(d)[0], f, ensure_ascii=False)
            r = subprocess.run([os.environ["SHUNT_TEST_SINGBOX"], "check", "-c", p], capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        finally:
            shutil.rmtree(wd, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
