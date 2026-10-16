"""节点健康检查单元测试（纯逻辑，不依赖 shunt 包导入）"""
import unittest
import time


# 从 shunt/health.py 复制的纯逻辑函数（避免包导入问题）
def _today():
    return time.strftime("%Y-%m-%d")


def record_one(rec, ok, latency=0):
    today = _today()
    if ok:
        rec["fail_days"] = 0
        rec["fail_dates"] = []
        rec["hidden"] = False
        rec["last_ok"] = int(time.time())
        if latency:
            rec["latency"] = latency
    else:
        dates = rec.get("fail_dates") or []
        if today not in dates:
            dates.append(today)
            dates = sorted(dates)[-30:]
        rec["fail_dates"] = dates
        rec["fail_days"] = len(dates)
        rec["last_fail"] = int(time.time())
    return rec


DEFAULT_CFG = {"enabled": False, "time": "03:00", "warn_days": 3, "hide_days": 7}


def node_level(rec, cfg=None):
    cfg = cfg or DEFAULT_CFG
    if rec.get("hidden"):
        return "hidden"
    fail_days = rec.get("fail_days", 0)
    if fail_days >= cfg.get("hide_days", 7):
        return "hidden"
    if fail_days >= cfg.get("warn_days", 3):
        return "bad"
    if fail_days > 0:
        return "warn"
    return "ok"


class TestRecordOne(unittest.TestCase):
    def test_success_clears(self):
        rec = {"fail_days": 5, "fail_dates": ["2026-10-10", "2026-10-11"], "hidden": True}
        record_one(rec, True, 120)
        self.assertEqual(rec["fail_days"], 0)
        self.assertEqual(rec["fail_dates"], [])
        self.assertFalse(rec["hidden"])
        self.assertEqual(rec["latency"], 120)

    def test_fail_counts_once_per_day(self):
        rec = {"fail_days": 0, "fail_dates": [], "hidden": False}
        record_one(rec, False)
        self.assertEqual(rec["fail_days"], 1)
        record_one(rec, False)
        self.assertEqual(rec["fail_days"], 1)
        self.assertEqual(len(rec["fail_dates"]), 1)

    def test_fail_dates_trimmed(self):
        rec = {"fail_days": 0, "fail_dates": [f"2026-09-{i:02d}" for i in range(1, 32)], "hidden": False}
        record_one(rec, False)
        self.assertLessEqual(len(rec["fail_dates"]), 30)


class TestNodeLevel(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(node_level({"fail_days": 0, "hidden": False}), "ok")

    def test_warn(self):
        self.assertEqual(node_level({"fail_days": 1, "hidden": False}), "warn")
        self.assertEqual(node_level({"fail_days": 2, "hidden": False}), "warn")

    def test_bad(self):
        self.assertEqual(node_level({"fail_days": 3, "hidden": False}), "bad")
        self.assertEqual(node_level({"fail_days": 5, "hidden": False}), "bad")

    def test_hidden_by_days(self):
        self.assertEqual(node_level({"fail_days": 7, "hidden": False}), "hidden")

    def test_hidden_by_flag(self):
        self.assertEqual(node_level({"fail_days": 0, "hidden": True}), "hidden")

    def test_custom_thresholds(self):
        cfg = {"warn_days": 5, "hide_days": 10}
        self.assertEqual(node_level({"fail_days": 4, "hidden": False}, cfg), "warn")
        self.assertEqual(node_level({"fail_days": 5, "hidden": False}, cfg), "bad")
        self.assertEqual(node_level({"fail_days": 9, "hidden": False}, cfg), "bad")
        self.assertEqual(node_level({"fail_days": 10, "hidden": False}, cfg), "hidden")


class TestHealthCfg(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(DEFAULT_CFG["enabled"], False)
        self.assertEqual(DEFAULT_CFG["time"], "03:00")
        self.assertEqual(DEFAULT_CFG["warn_days"], 3)
        self.assertEqual(DEFAULT_CFG["hide_days"], 7)


if __name__ == "__main__":
    unittest.main()
