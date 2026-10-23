"""v8.4.9：面板导航改为左侧抽屉（所有宽度统一，去掉横向标签栏 / 手机底部导航），顶栏统计卡不截断，修两处把手机页面撑宽的元素。

用户截图（Android Chrome，v8.4.6）里手机按 ~900px 的电脑布局显示：index.html 的 viewport 一直是 width=device-width，
页面也没有能让媒体查询跑到 >720px 的元素，判断是 Chrome「桌面版网站」（该模式忽略 viewport，按 980px 排版）。
v8.4.9 在该模式（触屏 + 721–1100px）下顶栏、统计卡、抽屉放大，并在抽屉底部提示关闭方法。
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
TABS = ["节点", "策略组", "订阅", "规则", "DNS", "广告拦截", "连接", "统计", "日志", "设置"]


def read(*p):
    with open(os.path.join(ROOT, *p), encoding="utf-8") as f:
        return f.read()


class DrawerMarkupTest(unittest.TestCase):
    def setUp(self):
        self.src = read("web", "index.html")
        self.html = read("index.html")
        self.css = read("web", "style.css")

    def test_viewport(self):
        m = re.search(r'<meta name="viewport" content="([^"]+)">', self.html)
        self.assertIsNotNone(m)
        self.assertIn("width=device-width", m.group(1))
        self.assertIn("initial-scale=1", m.group(1))
        self.assertNotRegex(m.group(1), r"width=\d")

    def test_no_horizontal_tab_bar(self):
        hdr = self.src[self.src.index("<header"):self.src.index("</header>")]
        self.assertNotIn("<nav", hdr)                      # 顶栏里不再有标签栏
        self.assertNotIn("more-sheet", self.src)           # 手机底部导航的「更多」面板也去掉了
        self.assertNotIn("nav#nav.bottom", self.css)
        self.assertNotIn("placeNav", self.html)
        self.assertNotIn("openMore", self.html)
        self.assertEqual(self.src.count('id="nav"'), 1)
        self.assertIn('<nav class="dnav" id="nav"', self.src)

    def test_menu_button(self):
        m = re.search(r'<button type="button" class="brand" id="menu-btn"([^>]*)>', self.src)
        self.assertIsNotNone(m, "左上角 Shunt 图标 + 文字是一个按钮")
        a = m.group(1)
        for k in ('aria-controls="drawer"', 'aria-expanded="false"', 'onclick="toggleDrawer()"'):
            self.assertIn(k, a)
        btn = self.src[m.start():self.src.index("</button>", m.start())]
        self.assertIn('class="logo"', btn)
        self.assertIn("<b>Shunt</b>", btn)
        self.assertIn('id="h-page"', btn)                  # 非主页时显示当前页名

    def test_drawer(self):
        m = re.search(r'<aside id="drawer"([^>]*)>', self.src)
        self.assertIsNotNone(m)
        for k in ('role="dialog"', 'aria-modal="true"', 'aria-hidden="true"', "inert"):
            self.assertIn(k, m.group(1))
        self.assertIn('id="drawer-mask"', self.src)
        self.assertIn('onclick="closeDrawer()"', self.src)
        self.assertRegex(self.src, r'<button type="button" class="dhome" id="d-home" onclick="pickNav\(\'概览\'\)"')

    def test_drawer_css(self):
        blk = self.css[self.css.index("/* v8.4.9 抽屉导航"):]
        self.assertRegex(blk, r"\.dnav button\{[^}]*min-height:48px[^}]*font-size:17px")
        self.assertRegex(blk, r"\.dhome\{[^}]*min-height:56px")
        self.assertRegex(blk, r"\.brand\{[^}]*min-height:44px")
        self.assertIn("focus-visible", blk)
        self.assertIn("prefers-reduced-motion", blk)
        self.assertIn("color-mix(in srgb,var(--bg) 80%,transparent)", blk)   # 半透明底 + glass 毛玻璃，背景图上可读
        # 触屏宽屏（含「桌面版网站」）：按钮 ≥40px
        touch = blk[blk.index("(hover:none) and (pointer:coarse)"):]
        self.assertRegex(touch, r"\.corebox \.ib\{height:48px")
        self.assertRegex(touch, r"\.hrow>\.ib\.round\{width:48px;height:48px")


class HeaderStatsTest(unittest.TestCase):
    def setUp(self):
        self.css = read("web", "style.css")
        self.blk = self.css[self.css.index("/* v8.4.9 抽屉导航"):]

    def test_grid_not_scroll(self):
        self.assertRegex(self.blk, r"\.hrow>\.hstats\{[^}]*display:grid;grid-template-columns:repeat\(8,minmax\(0,1fr\)\)[^}]*overflow:visible")
        self.assertIn("@media (max-width:1100px){.hrow>.hstats{grid-template-columns:repeat(4,minmax(0,1fr))}}", self.blk)
        self.assertIn(".hstats .vchips{display:contents}", self.blk)

    def test_values_wrap_not_ellipsis(self):
        self.assertIn(".hstats .chip .k,.hstats .chip b{white-space:normal;overflow:visible;text-overflow:clip;overflow-wrap:anywhere}", self.blk)
        self.assertNotIn(".hstats .chip:nth-child(n+3){display:none}", self.css)  # 手机上 8 张卡都显示

    def test_page_not_widened(self):
        self.assertNotIn("minmax(300px,1fr)", read("web", "index.html"))
        self.assertIn(".dti .row>.sp{overflow-wrap:anywhere}", self.css)


class FrontendTest(unittest.TestCase):
    def test_core_hash_map(self):
        core = read("web", "js", "00-core.js")
        for t in TABS:
            self.assertRegex(core, re.escape(t) + r":'[a-z]+'")
        self.assertIn("const HOME='概览'", core)

    def test_start_uses_hash(self):
        js = read("web", "js", "25-settings2.js")
        self.assertIn("go(tabFromHash(location.hash),1)", js)
        self.assertNotIn("placeNav", js)
        self.assertIn("const MQ=", read("web", "js", "02-layout.js"))   # 设置页分栏还在用

    @unittest.skipUnless(shutil.which("node"), "需要 node")
    def test_drawer_logic(self):
        r = subprocess.run(["node", os.path.join(ROOT, "tests", "v849_frontend.js"), ROOT], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        o = json.loads(r.stdout)
        h = o["hash"]
        for k in ("", "#", "#overview", "#home", "#bogus", "#%E0%A4%A"):
            self.assertEqual(h[k], "概览", k)
        for k, t in (("#nodes", "节点"), ("#/nodes", "节点"), ("#proxies", "节点"), ("#NODES", "节点"), ("#groups", "策略组"), ("#subs", "订阅"),
                     ("#rules", "规则"), ("#dns", "DNS"), ("#adblock", "广告拦截"), ("#conns", "连接"), ("#connections", "连接"),
                     ("#stats", "统计"), ("#logs", "日志"), ("#settings", "设置"), ("#%E7%AD%96%E7%95%A5%E7%BB%84", "策略组")):
            self.assertEqual(h[k], t, k)
        self.assertEqual(o["home"]["items"], TABS)          # 菜单里没有「概览」
        self.assertTrue(o["home"]["pageHidden"])
        self.assertEqual(o["home"]["homeCur"], "page")
        self.assertEqual(o["home"]["visible"], ["概览"])
        self.assertEqual(o["home"]["pushes"], [])
        self.assertEqual(o["open"], {"open": True, "exp": "true", "hidden": "false", "inert": False, "mask": True, "focus": True, "bodyLock": True})
        self.assertEqual(o["esc"], {"open": False, "exp": "false", "hidden": "true", "inert": True, "mask": True, "focus": True})
        p = o["pick"]
        self.assertFalse(p["open"])
        self.assertEqual((p["tab"], p["hash"], p["pushes"], p["loaded"], p["page"]), ("节点", "#nodes", ["#nodes"], "loadProxies", "节点"))
        self.assertEqual(p["cur"], ["节点"])
        self.assertEqual(p["on"], ["节点"])
        self.assertIsNone(p["homeCur"])
        self.assertEqual(p["visible"], ["节点"])
        self.assertTrue(p["focus"])
        self.assertEqual(o["focusCurrent"], "节点")           # 打开抽屉时焦点落在当前页
        self.assertFalse(o["toggled"])
        self.assertEqual(o["hashchange"], {"tab": "日志", "loaded": "openLogs"})
        self.assertEqual(o["popHome"], {"tab": "概览", "loaded": "renderOverview"})
        self.assertEqual(o["dupPush"], ["#nodes"])
        self.assertEqual(o["unknown"]["tab"], "概览")
        self.assertFalse(o["DSK"])


if __name__ == "__main__":
    unittest.main()
