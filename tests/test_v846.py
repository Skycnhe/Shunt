"""v8.4.6：下载被截断（背景图只剩上半张、订阅 / 规则集节点变少）、背景图并发写坏、恢复设置 / 快照 / 版本备份改订阅不清缓存、
版本备份恢复与在线更新并发、改筛选后订阅只剩已删节点、非对象请求体 / 字段类型错误回 500、无 PyYAML 时锚点节点丢失、
背景大图显示前缩小"""
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock

from tests.helper import server
from tests.test_v1012 import ApiCase
from tests.test_v840 import base

assert server

B = sys.modules["shunt.base"]
BK = sys.modules["shunt.backup"]
LT = sys.modules["shunt.latency"]
SBS = sys.modules["shunt.sb_subs"]
YL = sys.modules["shunt.sb_yaml"]
WA = sys.modules["shunt.webapi"]
D = sys.modules["shunt.data"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class FakeResp:
    """模拟 http.client 的 read(n)：对方中途断开时只返回收到的部分，length 留下没收到的字节数"""

    def __init__(self, data, declared=None):
        self.data, self.length = data, (declared if declared is not None else len(data))
        self.headers = {}

    def read(self, n=-1):
        out = self.data[:n] if n >= 0 else self.data
        self.data = self.data[len(out):]
        if self.length is not None:
            self.length -= len(out)
        return out

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class ReadFullTest(unittest.TestCase):
    def test_complete(self):
        self.assertEqual(B.read_full(FakeResp(b"abc"), 10), b"abc")

    def test_no_length(self):
        r = FakeResp(b"abc")
        r.length = None  # 没有 Content-Length：无法判断，照常返回
        self.assertEqual(B.read_full(r, 10), b"abc")

    def test_truncated_raises(self):
        with self.assertRaises(IOError):
            B.read_full(FakeResp(b"abc", declared=100), 1000)

    def test_over_limit_not_truncation(self):
        self.assertEqual(B.read_full(FakeResp(b"x" * 20), 11), b"x" * 11)  # 超过上限由调用方按长度判断


JPEG = b"\xff\xd8\xff\xe0" + b"j" * 200 + b"\xff\xd9"


class BgTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bg846-")
        self.p = mock.patch.object(LT, "BG_FILE", os.path.join(self.tmp, "bg.img"))
        self.p.start()

    def tearDown(self):
        self.p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def opener(self, resp):
        o = mock.Mock()
        o.open.side_effect = lambda *a, **k: resp()
        return o

    def test_truncated_download_rejected(self):
        """以前只收到一半也当成功保存：浏览器只画出上半截"""
        with mock.patch.object(LT, "dl_check"), \
                mock.patch.object(LT, "proxy_opener", return_value=self.opener(lambda: FakeResp(JPEG[:100], declared=len(JPEG)))):
            ok, msg = LT.bg_fetch("https://img.example/a.jpg")
        self.assertFalse(ok)
        self.assertIn("不完整", msg)
        self.assertFalse(os.path.exists(LT.BG_FILE))

    def test_complete_download_saved(self):
        with mock.patch.object(LT, "dl_check"), mock.patch.object(LT, "proxy_opener", return_value=self.opener(lambda: FakeResp(JPEG))):
            ok, msg = LT.bg_fetch("https://img.example/a.jpg")
        self.assertTrue(ok, msg)
        with open(LT.BG_FILE, "rb") as f:
            self.assertEqual(f.read(), JPEG)
        self.assertEqual(os.listdir(self.tmp), ["bg.img"])  # 没有留下临时文件

    def test_concurrent_writes_not_mixed(self):
        """上传与每日刷新同时写：以前共用 bg.img.tmp，可能换上两张图拼起来的坏文件"""
        a, b = b"\xff\xd8\xff" + b"a" * 300000, b"\xff\xd8\xff" + b"b" * 100000

        def run(x):
            for _ in range(15):
                LT._bg_write(x)
        ts = [threading.Thread(target=run, args=(x,)) for x in (a, b)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        with open(LT.BG_FILE, "rb") as f:
            self.assertIn(f.read(), (a, b))
        self.assertEqual(os.listdir(self.tmp), ["bg.img"])


class SubDownloadTruncTest(unittest.TestCase):
    def test_sub_truncated_falls_back(self):
        """订阅只收到前半段：以前按半截内容解析，节点悄悄变少并写进缓存；现在当作下载失败"""
        full = "\n".join(f"ss://YWVzLTEyOC1nY206eA@1.2.3.{i}:8388#N{i}" for i in range(1, 9)).encode()
        o = mock.Mock()
        o.open.side_effect = lambda *a, **k: FakeResp(full[:len(full) // 2], declared=len(full))
        with mock.patch.object(SBS, "dl_check"), mock.patch.object(SBS, "core_alive", return_value=False), \
                mock.patch.object(SBS, "proxy_opener", return_value=o), mock.patch.object(SBS, "write_json") as wj:
            with self.assertRaises(IOError) as cm:
                SBS.sb_fetch_sub({"name": "T846", "url": "https://sub.example/x"})
        self.assertIn("不完整", str(cm.exception))
        wj.assert_not_called()


class YamlAnchorTest(unittest.TestCase):
    TEXT = """proxies:
  - &a {name: A, type: ss, server: 1.1.1.1, port: 1, cipher: aes-128-gcm, password: x}
  - <<: *a
    name: B
  - &c
    name: C
    type: ss
    server: 2.2.2.2
    port: 2
  - name: D
    type: vmess
    server: 3.3.3.3
    port: 3
    ws-opts: &w
      path: /p
  - name: E
    type: vmess
    server: 3.3.3.3
    port: 4
    ws-opts: *w
  - just-a-string
"""

    def test_lite_parser_anchors(self):
        with mock.patch.object(SBS, "_yaml_full", return_value=None):  # 模拟没装 PyYAML
            nodes, errs = SBS.parse_sub_text(self.TEXT)
        by = {n["name"]: n for n in nodes}
        self.assertEqual(sorted(by), ["A", "B", "C", "D", "E"])  # 以前只剩 D、E（A 成了字符串，C 整段丢失，B 缺 type）
        self.assertEqual(by["B"]["server"], "1.1.1.1")
        self.assertEqual(by["B"]["port"], 1)
        self.assertEqual(by["E"]["ws-opts"], {"path": "/p"})
        self.assertEqual(len(errs), 1)  # 读不出的条目有提示（以前静默丢弃）

    def test_own_keys_override_merge(self):
        y = YL.yaml_lite("base: &b {x: 1, y: 2}\nk:\n  y: 9\n  <<: *b\n")
        self.assertEqual(y["k"], {"x": 1, "y": 9})

    def test_plain_unchanged(self):
        y = YL.yaml_lite("a:\n  - {name: 'x&y', v: '*z'}\n  - name: q\n    t: 1\n")
        self.assertEqual(y, {"a": [{"name": "x&y", "v": "*z"}, {"name": "q", "t": 1}]})


class BodyTypeTest(ApiCase):
    def raw(self, method, path, raw):
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        try:
            c.request(method, path, body=raw, headers={"X-Shunt": "1", "Content-Type": "application/json"})
            r = c.getresponse()
            return r.status, json.loads(r.read() or b"{}")
        finally:
            c.close()

    def test_non_object_body(self):
        for raw in ("[1]", '"x"', "123", "null"):
            code, j = self.raw("POST", "/api/subs", raw)
            self.assertEqual(code, 400, (raw, j))
            self.assertIn("JSON 对象", j["message"])

    def test_latency_bad_type(self):
        code, j = self.call("PUT", "/api/schedule", {"latency": "abc"})
        self.assertEqual(code, 400, j)
        code, j = self.call("PUT", "/api/schedule", {"latency": [1]})
        self.assertEqual(code, 400, j)

    def test_adblock_bad_shapes(self):
        before = server.load()["adblock"]
        for b in ({"lists": [1]}, {"lists": "x"}, {"black": "ads.com"}, {"white": {"a": 1}}, {"interval": "abc"}):
            code, j = self.call("PUT", "/api/adblock", b)
            self.assertEqual(code, 400, (b, j))
        self.assertEqual(server.load()["adblock"], before)


class RestoreSubCacheTest(ApiCase):
    """恢复设置 / 快照 / 版本备份把订阅换了链接：删 mihomo 的 provider 缓存；sing-box 重新下载变化的订阅"""

    def setUp(self):
        super().setUp()
        server.save(base())
        self.pdir = os.path.join(B.CONF_DIR, "providers")
        os.makedirs(self.pdir, exist_ok=True)
        for n in ("A", "B", "C"):
            with open(os.path.join(self.pdir, n + ".yaml"), "w") as f:
                f.write("proxies: []\n")
        try:
            with open(D.HISTORY_FILE) as f:
                self.hist = f.read()
        except OSError:
            self.hist = None
        self.core = "mihomo"
        self.p = [mock.patch.object(WA, "reload_core", return_value=(True, "ok")),
                  mock.patch.object(WA, "active_core", side_effect=lambda *a: self.core),
                  mock.patch.object(WA, "tp_apply", return_value=(0, "")),
                  mock.patch.object(WA, "ab_compose"),
                  mock.patch.object(WA, "sb_update_subs", return_value=([], []))]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()
        for n in ("A", "B", "C"):
            try:
                os.remove(os.path.join(self.pdir, n + ".yaml"))
            except OSError:
                pass
        if self.hist is None:
            try:
                os.remove(D.HISTORY_FILE)
            except OSError:
                pass
        else:
            with open(D.HISTORY_FILE, "w") as f:
                f.write(self.hist)
        super().tearDown()

    def cached(self, n):
        return os.path.isfile(os.path.join(self.pdir, n + ".yaml"))

    def subs(self, a_url="https://a.example/s", b_filter=""):
        return [{"name": "A", "url": a_url, "filter": "", "exclude": ""},
                {"name": "B", "url": "https://b.example/s", "filter": b_filter, "exclude": ""}]

    def test_restore_changed_url_drops(self):
        code, j = self.call("POST", "/api/restore", {"subs": self.subs(a_url="https://new.example/s")})
        self.assertEqual(code, 200, j)
        self.assertFalse(self.cached("A"))  # 以前保留：mihomo 继续用旧链接的节点到下个更新间隔
        self.assertTrue(self.cached("B"))
        WA.sb_update_subs.assert_not_called()

    def test_restore_same_keeps(self):
        code, j = self.call("POST", "/api/restore", {"subs": self.subs()})
        self.assertEqual(code, 200, j)
        self.assertTrue(self.cached("A") and self.cached("B"))

    def test_restore_removed_and_new_sub(self):
        subs = [self.subs()[0], {"name": "C", "url": "https://c.example/s", "filter": "", "exclude": ""}]
        code, j = self.call("POST", "/api/restore", {"subs": subs})
        self.assertEqual(code, 200, j)
        self.assertTrue(self.cached("A"))
        self.assertFalse(self.cached("B"))  # 恢复后不再有的订阅
        self.assertFalse(self.cached("C"))  # 新出现的同名订阅：旧缓存不能用

    def test_restore_singbox_refetch(self):
        self.core = "singbox"
        code, j = self.call("POST", "/api/restore", {"subs": self.subs(b_filter="HK")})
        self.assertEqual(code, 200, j)
        WA.sb_update_subs.assert_called_once_with(["B"])  # 筛选变了：sing-box 缓存里是按旧筛选过滤的节点

    def test_history_snapshot(self):
        snap = dict(server.load(), subs=self.subs(a_url="https://snap.example/s"))
        with open(D.HISTORY_FILE, "w") as f:
            json.dump([{"id": "s846", "t": int(time.time()), "changed": ["subs"], "data": snap}], f)
        code, j = self.call("POST", "/api/history", {"id": "s846"})
        self.assertEqual(code, 200, j)
        self.assertEqual(server.load()["subs"][0]["url"], "https://snap.example/s")
        self.assertFalse(self.cached("A"))
        self.assertTrue(self.cached("B"))


class BackupRestoreLockTest(ApiCase):
    def setUp(self):
        super().setUp()
        server.save(base())
        self.dir = tempfile.mkdtemp(prefix="bk846-")
        self.base = tempfile.mkdtemp(prefix="base846-")
        with open(os.path.join(self.base, "server.py"), "w") as f:
            f.write("cur")
        self.pdir = os.path.join(B.CONF_DIR, "providers")
        os.makedirs(self.pdir, exist_ok=True)
        with open(os.path.join(self.pdir, "A.yaml"), "w") as f:
            f.write("proxies: []\n")
        self.p = [mock.patch.object(BK, "BACKUP_DIR", self.dir), mock.patch.object(BK, "BASE", self.base),
                  mock.patch.object(WA, "reload_core", return_value=(True, "ok")),
                  mock.patch.object(WA, "tp_apply", return_value=(0, "")),
                  mock.patch.object(WA, "restart_self"),
                  mock.patch.object(WA, "active_core", return_value="mihomo"),
                  mock.patch.object(WA, "ab_compose")]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()
        B.UPD_STATE["busy"] = False
        shutil.rmtree(self.dir, ignore_errors=True)
        shutil.rmtree(self.base, ignore_errors=True)
        try:
            os.remove(os.path.join(self.pdir, "A.yaml"))
        except OSError:
            pass
        super().tearDown()

    def _mk(self, data):
        name = "shunt-backup-v9.9.7-20260101-000001.tar.gz"
        src = os.path.join(self.base, "src")
        os.makedirs(src, exist_ok=True)
        with open(os.path.join(src, "data.json"), "w") as f:
            json.dump(data, f)
        with open(os.path.join(src, "server.py"), "w") as f:
            f.write("old")
        with tarfile.open(os.path.join(self.dir, name), "w:gz") as tf:
            tf.add(os.path.join(src, "data.json"), arcname="data.json")
            tf.add(os.path.join(src, "server.py"), arcname="server.py")
        return name

    def test_busy_rejected(self):
        name = self._mk(server.load())
        B.UPD_STATE["busy"] = True  # 面板在线更新进行中
        code, j = self.call("POST", "/api/backup/restore", {"name": name})
        self.assertEqual(code, 409, j)
        with open(os.path.join(self.base, "server.py")) as f:
            self.assertEqual(f.read(), "cur")
        WA.restart_self.assert_not_called()

    def test_ok_releases_and_drops_cache(self):
        d = server.load()
        d["subs"][0]["url"] = "https://changed.example/s"
        name = self._mk(d)
        code, j = self.call("POST", "/api/backup/restore", {"name": name})
        self.assertEqual(code, 200, j)
        for _ in range(50):  # 响应先发出，忙标志在 finally 里随后清除
            if not B.UPD_STATE["busy"]:
                break
            time.sleep(0.02)
        self.assertFalse(B.UPD_STATE["busy"])
        self.assertFalse(os.path.isfile(os.path.join(self.pdir, "A.yaml")))


class FilterRemovedOnlyTest(ApiCase):
    """mihomo：编辑订阅筛选后 provider 只剩已删节点 → 订阅为空、mihomo 加载失败；拒绝保存"""

    def setUp(self):
        super().setUp()
        server.save(base(removed_a=["HK 01", "HK 02"]))
        self.pdir = os.path.join(B.CONF_DIR, "providers")
        os.makedirs(self.pdir, exist_ok=True)
        with open(os.path.join(self.pdir, "A.yaml"), "w") as f:
            f.write("proxies:\n" + "".join(f"  - {{name: '{n}', type: ss, server: 1.1.1.1, port: 1}}\n" for n in ("HK 01", "HK 02", "US 01")))
        self.p = [mock.patch.object(WA, "reload_core", return_value=(True, "ok")),
                  mock.patch.object(WA, "active_core", return_value="mihomo"),
                  mock.patch.object(WA, "refresh_after_sub")]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()
        try:
            os.remove(os.path.join(self.pdir, "A.yaml"))
        except OSError:
            pass
        super().tearDown()

    def post(self, flt, exc=""):
        return self.call("POST", "/api/subs", {"name": "A", "url": WA.mask_url("https://a.example/s"), "filter": flt, "exclude": exc})

    def test_only_removed_rejected(self):
        code, j = self.post("HK")
        self.assertEqual(code, 400, j)
        self.assertIn("已从订阅删除", j["message"])
        self.assertEqual(server.load()["subs"][0]["filter"], "")

    def test_exclude_rejected(self):
        code, j = self.post("", "US")
        self.assertEqual(code, 400, j)

    def test_ok_when_something_left(self):
        code, j = self.post("HK|US")
        self.assertEqual(code, 200, j)
        self.assertEqual(server.load()["subs"][0]["filter"], "HK|US")

    def test_matches_nothing_not_our_business(self):
        """筛选本身一个都不匹配（与已删节点无关）：沿用以前的行为，不在这里拦"""
        code, j = self.post("JP")
        self.assertEqual(code, 200, j)


class BgFrontendTest(unittest.TestCase):
    """链接 / 每日壁纸大图显示前缩到 2560px；外链和小图原样使用"""

    def test_bgfit(self):
        js = r"""
const fs=require('fs');
let BLOBS=0;
global.URL={createObjectURL:()=>'blob:'+(++BLOBS),revokeObjectURL:()=>{}};
const SIZES={'/bg?v=1':[6000,4000],'/bg?v=2':[1920,1080]};
global.Image=class{set src(v){this._s=v;const z=SIZES[v];setTimeout(()=>{if(z){this.naturalWidth=z[0];this.naturalHeight=z[1];this.onload()}else this.onerror()},0)}get src(){return this._s}};
let CANVAS=null;
global.document={createElement:()=>(CANVAS={getContext:()=>({drawImage(){}}),toBlob(cb){cb({})}}),documentElement:{classList:{toggle(){}}}};
const src=fs.readFileSync(process.argv[1]+'/web/js/01-theme.js','utf8');
eval(src.slice(src.indexOf('const BG_MAXPX'),src.indexOf('function bgApply'))+';global.bgFit=bgFit;global.BGFIT_GET=()=>BGFIT;');
const out={};
bgFit('https://x.example/a.jpg',u=>{out.ext=u});
bgFit('/bg?v=1',u=>{out.big=u;out.size=[CANVAS.width,CANVAS.height];
  bgFit('/bg?v=1',u2=>{out.cached=u2;
    bgFit('/bg?v=2',u3=>{out.small=u3;process.stdout.write(JSON.stringify(out))})})});
"""
        r = subprocess.run(["node", "-e", js, ROOT], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out["ext"], "https://x.example/a.jpg")
        self.assertTrue(out["big"].startswith("blob:"))
        self.assertEqual(out["size"], [2560, 1707])
        self.assertEqual(out["cached"], out["big"])
        self.assertEqual(out["small"], "/bg?v=2")

    def test_css_large_viewport(self):
        with open(os.path.join(ROOT, "web", "style.css"), encoding="utf-8") as f:
            css = f.read()
        rule = css[css.index("#bgimg{"):css.index("}", css.index("#bgimg{"))]
        self.assertIn("100lvh", rule)
        self.assertNotIn("inset:-30px", rule)


if __name__ == "__main__":
    unittest.main()
