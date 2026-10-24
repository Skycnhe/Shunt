"""v10.3.9（与 Hk001 v8.4.13 相同）：经典布局还原成 v7.6.x（2026-10-12 前后）的样子。

- 顶部一行紧凑统计小块（小标签 + 粗数值，按内容宽度排开，放不下换行，不截断）；抽屉布局仍是 v10.3.5 起的统计卡网格
- 下面一条圆角半透明横向标签栏，当前页浅色胶囊高亮；手机上也在顶部，去掉底部栏和「更多」弹层
- 标签项与菜单一致（概览 + 节点 … 设置），旧版的「检测」页 v7.7.1 已并入 设置 → 网络，不加回
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
VER = "10.3.9"


def read(*p):
    with open(os.path.join(ROOT, *p), encoding="utf-8") as f:
        return f.read()


class VersionTest(unittest.TestCase):
    def test_version(self):
        self.assertEqual(B.PANEL_VERSION, VER)

    def test_changelog_top(self):
        heads = [ln for ln in read("CHANGELOG.md").splitlines() if ln.startswith("## v")]
        self.assertTrue(heads[0].startswith("## v" + VER), heads[0])


class ClassicCssTest(unittest.TestCase):
    def setUp(self):
        self.css = read("web", "style.css")
        self.blk = self.css[self.css.index("界面布局可选（设置 → 外观 → 界面布局"):self.css.index("/* 设置页「界面布局」单选 */")]

    def test_tabbar_top_wraps(self):
        m = re.search(r"#tabbar\{([^}]*)\}", self.blk)
        self.assertIn("flex-wrap:wrap", m.group(1))
        self.assertIn("background:var(--segbg)", m.group(1))
        self.assertNotIn("overflow-x:auto", m.group(1))           # 不靠横向滑动藏标签
        self.assertIn("#tabbar button.on{background:var(--segon)", self.blk)
        self.assertNotIn("position:fixed", self.blk)                # 没有固定在底部的栏
        self.assertNotIn("more-sheet", self.css)
        self.assertNotIn("#tabbar.bottom", self.css)
        # 「桌面版网站」/ 触屏宽屏不再把经典标签放大成两行
        self.assertNotIn("html.dsk #tabbar", self.css)

    def test_classic_stats_compact(self):
        self.assertIn("html[data-layout=classic] .hrow>.hstats{display:flex;flex-wrap:wrap;", self.blk)
        self.assertRegex(self.blk, r"html\[data-layout=classic\] \.hstats \.chip\{flex:0 0 auto;min-width:100px;")
        for k in (".k", "b"):
            m = re.search(r"html\[data-layout=classic\] \.hstats \.chip " + re.escape(k) + r"\{([^}]*)\}", self.blk)
            self.assertIn("white-space:nowrap", m.group(1))
            self.assertIn("overflow:visible", m.group(1))
            self.assertIn("text-overflow:clip", m.group(1))
        # 抽屉布局的统计卡网格不动
        self.assertIn(".hrow>.hstats{order:9;flex:1 1 100%;width:100%;margin-left:0;display:grid;grid-template-columns:repeat(8,minmax(0,1fr))", self.css)

    def test_markup(self):
        src = read("web", "index.html")
        self.assertNotIn("more-sheet", src)
        self.assertNotIn('data-tab="检测"', src)
        self.assertIn('id="unlock-btn"', src)                        # 解锁检测在 设置 → 网络
        self.assertIn('id="diag-btn"', src)
        self.assertIn("手机上也在顶部", src)
        self.assertIn(VER, read("server.py"))


class ClassicFrontendTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("node"):
            raise unittest.SkipTest("需要 node")
        r = subprocess.run(["node", os.path.join(ROOT, "tests", "v1039_frontend.js"), ROOT], capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
        cls.o = json.loads(r.stdout)

    def test_classic_tabbar_all_items(self):
        for k in ("classic", "mobile", "mobileBack", "mqDesktop", "mqMobile"):
            o = self.o[k]
            self.assertEqual(o["tabs"], TABS, k)
            self.assertNotIn("检测", o["tabs"])
            self.assertFalse(o["moreBtn"], k)
            self.assertFalse(o["icons"], k)                          # 旧版样式：纯文字标签

    def test_narrow_no_bottom_bar(self):
        for k in ("mobile", "mobilePick", "mobileBack", "mqDesktop", "mqMobile", "mobileEsc"):
            o = self.o[k]
            self.assertEqual((o["bottom"], o["inBody"], o["hasbn"]), (False, False, False), k)
        p = self.o["mobilePick"]
        self.assertEqual((p["tab"], p["tabCur"], p["focus"], p["hash"], p["loaded"]), ("日志", ["日志"], "日志", "#logs", "openLogs"))
        self.assertEqual(self.o["mobileToDrawer"]["tabs"], [])
        self.assertEqual(self.o["gone"], [])                          # 「更多」/ 底部栏相关函数已删除

    def test_has_probe_works(self):
        # 自检：gone 为空不是因为探测函数失效
        self.assertEqual(self.o["probe"], True)


if __name__ == "__main__":
    unittest.main()
