"""v10.3.8（与 Hk001 v8.4.12 相同）：设置 → 外观 →「界面布局」可选 经典（横向标签栏）/ 抽屉菜单（新，默认）。

经典布局还原 v10.3.4 的导航：顶栏下横向标签栏（含「概览」），手机（≤720px）上移到页面底部（概览 / 节点 / 连接 / 日志 +「更多」弹层）；
抽屉布局保持 v10.3.5 起的样子。两种布局共用 go() / #hash / 返回键 / 统计卡网格 / 顶栏按钮；布局按设备保存在 localStorage mp_layout，
<head> 内联脚本在首屏前设好 html[data-layout]，切换立即生效（关闭打开着的抽屉 / 弹层，焦点不留在隐藏的元素上）。
"""
import json
import os
import re
import shutil
import subprocess
import sys
import unittest

from tests.helper import server

assert server

B = sys.modules["shunt.base"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TABS = ["概览", "节点", "策略组", "订阅", "规则", "DNS", "广告拦截", "连接", "统计", "日志", "设置"]
NP = ["策略组", "订阅", "规则", "DNS", "广告拦截", "统计", "设置"]


def read(*p):
    with open(os.path.join(ROOT, *p), encoding="utf-8") as f:
        return f.read()


class VersionTest(unittest.TestCase):
    def test_version(self):
        self.assertEqual(B.PANEL_VERSION, "10.3.8")

    def test_changelog_top(self):
        heads = [ln for ln in read("CHANGELOG.md").splitlines() if ln.startswith("## v")]
        self.assertTrue(heads[0].startswith("## v10.3.8"), heads[0])


class MarkupTest(unittest.TestCase):
    def setUp(self):
        self.src = read("web", "index.html")
        self.html = read("index.html")
        self.css = read("web", "style.css")
        self.blk = self.css[self.css.index("/* v10.3.8 界面布局可选"):]

    def test_head_sets_layout_before_paint(self):
        head = self.src[:self.src.index("</head>")]
        self.assertIn("d.dataset.layout=localStorage.getItem('mp_layout')==='classic'?'classic':'drawer'", head)

    def test_settings_option(self):
        m = re.search(r'<div data-sg="look" class="card" id="ly-card"><h3>界面布局</h3>', self.src)
        self.assertIsNotNone(m, "设置 → 外观 里有「界面布局」卡片")
        self.assertLess(m.start(), self.src.index("<h3>主题</h3>"))
        card = self.src[m.start():self.src.index("<h3>主题</h3>")]
        self.assertIn('role="radiogroup"', card)
        self.assertIn('data-ly="classic" onclick="setLayout(\'classic\')"><b>经典（横向标签栏）</b>', card)
        self.assertIn('data-ly="drawer" onclick="setLayout(\'drawer\')"><b>抽屉菜单（新）</b>', card)
        self.assertIn("renderLayoutOpt()", read("web", "js", "01-theme.js"))

    def test_classic_markup(self):
        hdr = self.src[self.src.index("<header"):self.src.index("</header>")]
        self.assertIn('<nav id="tabbar" aria-label="页面"></nav>', hdr)
        self.assertIn('<div id="more-sheet" class="hide" onclick="if(event.target===this)closeMore()">', self.src)
        self.assertIn('id="more-list" role="dialog" aria-modal="true"', self.src)
        self.assertIn('id="menu-btn" onclick="brandClick()"', self.src)

    def test_css_by_layout(self):
        self.assertIn("html:not([data-layout=classic]) #tabbar,html:not([data-layout=classic]) #more-sheet{display:none!important}", self.blk)
        self.assertIn("html[data-layout=classic] .brand .bmenu,html[data-layout=classic] .brand .bpage{display:none}", self.blk)
        self.assertRegex(self.blk, r"#tabbar\.bottom\{position:fixed;[^}]*grid-template-columns:repeat\(5,minmax\(0,1fr\)\)")
        self.assertIn("#tabbar.bottom button.np{display:none}#tabbar.bottom .more{display:flex}", self.blk)
        self.assertIn("body.hasbn main{padding-bottom:calc(84px + env(safe-area-inset-bottom))}", self.blk)
        self.assertRegex(self.blk, r"#tabbar\.bottom button\{[^}]*min-height:52px")
        # 旧版的通用 nav{} / nav button{} 规则不能回来：抽屉里的 <nav class="dnav"> 也会被套上
        self.assertIsNone(re.search(r"(^|[}\s,])nav( button)?\{", self.css, re.M))

    def test_shared_improvements_kept(self):
        self.assertIn(".hrow>.hstats{order:9;flex:1 1 100%", self.css)            # 统计卡网格
        self.assertIn("go(tabFromHash(location.hash),1)", read("web", "js", "25-settings2.js"))
        lay = read("web", "js", "02-layout.js")
        self.assertEqual(lay.count("function go("), 1)
        self.assertIn("addEventListener('popstate'", lay)


class FrontendTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("node"):
            raise unittest.SkipTest("需要 node")
        r = subprocess.run(["node", os.path.join(ROOT, "tests", "v1038_frontend.js"), ROOT], capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
        cls.o = json.loads(r.stdout)

    def test_default_drawer_no_tabbar(self):
        for k in ("fresh", "bogus"):
            f = self.o[k]
            self.assertEqual((f["layout"], f["attr"]), ("drawer", "drawer"), k)
            self.assertEqual(f["tabs"], [], k)
            self.assertEqual(f["drawerItems"], TABS[1:], k)
            self.assertEqual(f["btn"]["exp"], "false")
            self.assertEqual(f["btn"]["ctl"], "drawer")
        self.assertIsNone(self.o["fresh"]["store"])        # 只看不选不写 localStorage
        self.assertEqual(self.o["freshNodes"]["page"], "节点")
        self.assertEqual(self.o["freshNodes"]["tabs"], [])

    def test_classic_tabbar_has_overview(self):
        c = self.o["classic"]
        self.assertEqual((c["layout"], c["attr"]), ("classic", "classic"))
        self.assertEqual(c["tabs"], TABS + ["更多"])
        self.assertEqual(c["tabCur"], ["概览"])
        self.assertEqual(c["np"], NP)
        self.assertTrue(c["pageHidden"])
        self.assertEqual(c["btn"], {"exp": None, "ctl": None, "pop": None, "label": "Shunt，回到概览", "title": "回到概览"})
        n = self.o["classicNodes"]
        self.assertEqual((n["tabCur"], n["hash"], n["loaded"], n["visible"]), (["节点"], "#nodes", "loadProxies", ["节点"]))
        b = self.o["classicBrand"]
        self.assertEqual((b["tab"], b["drawerOpen"], b["hash"]), ("概览", False, ""))   # 经典布局下 Shunt 图标回概览、不开抽屉
        p = self.o["pickTab"]
        self.assertEqual((p["tab"], p["tabCur"], p["focus"], p["hash"]), ("策略组", ["策略组"], "策略组", "#groups"))
        self.assertEqual(p["tabs"][-1], "策略组")           # 「更多」按钮显示当前的非主要页
        h = self.o["classicHash"]
        self.assertEqual((h["tab"], h["tabCur"], h["loaded"]), ("日志", ["日志"], "openLogs"))

    def test_switch(self):
        d = self.o["toDrawer"]
        self.assertEqual((d["layout"], d["attr"], d["tabs"], d["store"]), ("drawer", "drawer", [], "drawer"))
        self.assertEqual(self.o["toDrawerSets"], ["mp_layout=drawer"])
        self.assertEqual((d["btn"]["exp"], d["btn"]["ctl"], d["btn"]["pop"]), ("false", "drawer", "dialog"))
        self.assertEqual((d["page"], d["pageHidden"]), ("日志", False))
        self.assertEqual(d["focus"], "ly:drawer")          # 焦点留在设置页选中的那一项
        self.assertEqual(d["opts"], ["classic:false", "drawer:true"])
        self.assertEqual((d["tab"], d["visible"]), ("日志", ["日志"]))   # 切换布局不切页
        self.assertTrue(self.o["drawerOpened"])
        c = self.o["toClassicFromOpenDrawer"]
        self.assertFalse(c["drawerOpen"])                  # 打开着的抽屉先关掉
        self.assertEqual(c["focus"], "menu-btn")           # 焦点原在抽屉里 → 落到左上角按钮
        self.assertEqual((c["tabCur"], c["store"], c["opts"]), (["日志"], "classic", ["classic:true", "drawer:false"]))
        s = self.o["storageEvt"]
        self.assertEqual((s["layout"], s["tabs"]), ("drawer", []))
        self.assertEqual(self.o["storageEvtWrites"], 0)

    def test_mobile_bottom_bar_and_more(self):
        m = self.o["mobile"]
        self.assertEqual((m["bottom"], m["inBody"], m["hasbn"]), (True, True, True))
        self.assertEqual(m["np"], NP)                      # 底部栏只显示 概览 / 节点 / 连接 / 日志 + 更多（np 由 CSS 隐藏）
        mo = self.o["moreOpen"]
        self.assertEqual((mo["open"], mo["items"], mo["focus"], mo["exp"]), (True, NP, "策略组", "true"))
        self.assertEqual(self.o["moreEsc"], {"open": False, "focus": "more-btn"})
        p = self.o["morePick"]
        self.assertEqual((p["tab"], p["moreOpen"], p["hash"], p["loaded"], p["tabs"][-1]), ("设置", False, "#settings", "renderSettings", "设置"))
        d = self.o["mobileToDrawer"]
        self.assertEqual((d["moreOpen"], d["bottom"], d["inBody"], d["hasbn"], d["tabs"], d["focus"]), (False, False, False, False, [], "menu-btn"))
        b = self.o["mobileBack"]
        self.assertEqual((b["bottom"], b["inBody"], b["hasbn"], b["tabCur"]), (True, True, True, ["设置"]))
        self.assertEqual((self.o["mqDesktop"]["bottom"], self.o["mqDesktop"]["inBody"], self.o["mqDesktop"]["hasbn"]), (False, False, False))
        self.assertEqual((self.o["mqMobile"]["bottom"], self.o["mqMobile"]["inBody"]), (True, True))

    def test_persist(self):
        self.assertEqual((self.o["persistClassic"]["layout"], self.o["persistClassic"]["tabs"][0]), ("classic", "概览"))
        self.assertEqual((self.o["persistDrawer"]["layout"], self.o["persistDrawer"]["tabs"]), ("drawer", []))


if __name__ == "__main__":
    unittest.main()
