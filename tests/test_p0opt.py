"""P0 优化回归测试：webapi 鉴权冒烟、data.update 并发、yaml_lite 边界。

离线可跑（走 tests/helper.py 的临时数据目录），不依赖网络。
注意：跑的是生成的 server.py；本轮源码改动未重新生成前不影响这些测试。
"""
import threading
import unittest

from tests.helper import server


def _handler(path, headers=None, ip="127.0.0.1"):
    """构造一个不走 socket 的 H 实例：send 只记录返回码"""
    h = server.H.__new__(server.H)
    h.client_address = (ip, 12345)
    h.path = path
    hdrs = {"Host": "127.0.0.1:8080"}
    hdrs.update(headers or {})
    h.headers = hdrs
    captured = {}

    def fake_send(code, obj, ctype="application/json"):
        captured["code"] = code
        captured["obj"] = obj

    h.send = fake_send
    return h, captured


class WebapiAuthSmokeTest(unittest.TestCase):
    """机密 GET 接口必须带 X-Shunt 头；普通只读接口不受影响"""

    def test_state_with_header_passes_guard(self):
        h, _ = _handler("/api/state", {"X-Shunt": "1"})
        self.assertEqual(h.guard("GET", "/api/state"), "")

    def test_state_without_header_passes_guard(self):
        h, _ = _handler("/api/state")
        self.assertEqual(h.guard("GET", "/api/state"), "")

    def test_backup_without_header_denied(self):
        h, _ = _handler("/api/backup")
        why = h.guard("GET", "/api/backup")
        self.assertTrue(why and "X-Shunt" in why, why)

    def test_backup_with_header_passes_guard(self):
        h, _ = _handler("/api/backup", {"X-Shunt": "1"})
        self.assertEqual(h.guard("GET", "/api/backup"), "")

    def test_config_download_without_header_denied(self):
        h, _ = _handler("/api/config?download=1")
        self.assertTrue(h.guard("GET", "/api/config"))

    def test_history_without_header_denied(self):
        h, _ = _handler("/api/history")
        self.assertTrue(h.guard("GET", "/api/history"))

    def test_route_backup_without_header_403(self):
        h, cap = _handler("/api/backup")
        h.route("GET")
        self.assertEqual(cap.get("code"), 403)

    def test_route_state_with_header_200(self):
        h, cap = _handler("/api/state", {"X-Shunt": "1"})
        h.route("GET")
        self.assertEqual(cap.get("code"), 200)


class UpdateConcurrencyTest(unittest.TestCase):
    """多线程同时 update()：LOCK 保证读-改-写串行，不丢更新"""

    def test_no_lost_updates(self):
        data_mod = server.shunt.data
        data_mod.update(lambda d: d.update({"conc_list": []}))
        N_THREADS, N_ITERS = 8, 10

        def worker(tid):
            for i in range(N_ITERS):
                data_mod.update(lambda d, tid=tid, i=i: d["conc_list"].append((tid, i)))

        ths = [threading.Thread(target=worker, args=(t,)) for t in range(N_THREADS)]
        for t in ths:
            t.start()
        for t in ths:
            t.join(60)
        self.assertFalse(any(t.is_alive() for t in ths), "worker hung")
        got = data_mod.load()["conc_list"]
        want = {(t, i) for t in range(N_THREADS) for i in range(N_ITERS)}
        self.assertEqual(set(map(tuple, got)), want)


class YamlLiteEdgeTest(unittest.TestCase):
    """yaml_lite 手写解析器：边界输入不断言崩溃"""

    def test_no_crash_on_edge_cases(self):
        yl = server.shunt.sb_yaml.yaml_lite
        samples = [
            "key: |\n  line1\n  line2\n",      # 多行 literal
            "key: >\n  folded\n  text\n",      # 多行 folded
            "key: \"quoted: colon\"\n",        # 引号内冒号
            "key: 'it''s'\n",                  # 单引号转义
            "- item1\n- item2\n",               # 顶层列表
            "a:\n  b:\n    c: 1\n",            # 嵌套
            "key: value # comment\n",          # 行尾注释
            "key:\n",                          # 空值
            "",                               # 空串
            "   \n",                           # 纯空白
            "\tkey: tab\n",                   # 制表符缩进
            "key: !!str value\n",              # tag
            "{a: 1, b: 2}\n",                 # flow map
            "[1, 2, 3]\n",                     # flow list
            "key: value\r\n",                  # CRLF
            "dup: 1\ndup: 2\n",                # 重复键
            ":\n",                             # 只有冒号
        ]
        for s in samples:
            try:
                yl(s)
            except Exception as e:
                self.fail(f"yaml_lite crashed on {s!r}: {type(e).__name__}: {e}")

    def test_malformed_raises_valueerror(self):
        # 未闭合的方括号是故意抛 ValueError（调用方按行跳过），不是崩溃
        yl = server.shunt.sb_yaml.yaml_lite
        with self.assertRaises(ValueError):
            yl("key: [unclosed\n")


if __name__ == "__main__":
    unittest.main()
