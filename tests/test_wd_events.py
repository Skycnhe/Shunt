"""看门狗事件记录：落盘、最多 20 条（满了删最旧）、按类型计数"""
import os
import tempfile
import unittest
from unittest import mock

from tests.helper import server  # 确保离线导入
from shunt import notify as N

__all__ = ["server"]


class TestWdEvents(unittest.TestCase):
    def setUp(self):
        self.f = os.path.join(tempfile.mkdtemp(), "wd_events.json")
        self.p = [mock.patch.object(N, "WD_EVENTS_FILE", self.f), mock.patch.object(N, "notify")]
        for p in self.p:
            p.start()
        self.saved = N.WD["events"]
        N.WD["events"] = N.deque(maxlen=N.WD_EVENTS_MAX)

    def tearDown(self):
        for p in self.p:
            p.stop()
        N.WD["events"] = self.saved

    def test_cap_20_drops_oldest_and_persists(self):
        for i in range(25):
            N.wd_event(f"ev{i}", kind="restart" if i % 2 else "recover")
        self.assertEqual(len(N.WD["events"]), 20)
        self.assertEqual(N.WD["events"][0]["msg"], "ev24")
        self.assertEqual(N.WD["events"][-1]["msg"], "ev5")  # ev0~ev4 自动删除
        with mock.patch.object(N, "WD_EVENTS_FILE", self.f):
            again = N._load_wd_events()
        self.assertEqual([e["msg"] for e in again], [e["msg"] for e in N.WD["events"]])
        self.assertEqual(N.wd_counts(), {"restart": 10, "direct": 0, "recover": 10})

    def test_bad_file_ignored(self):
        with open(self.f, "w") as f:
            f.write("{not json")
        self.assertEqual(len(N._load_wd_events()), 0)
        with open(self.f, "w") as f:
            f.write('[{"t": 1, "msg": "ok", "kind": "direct"}, {"t": "x"}, 3]')
        ev = N._load_wd_events()
        self.assertEqual(len(ev), 1)
        self.assertEqual(N.wd_counts(ev)["direct"], 1)


if __name__ == "__main__":
    unittest.main()
