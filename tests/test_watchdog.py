"""看门狗：一次 /version 超时不重启，连续失败才重启"""
import sys
import unittest
from unittest import mock

from tests.helper import server

assert server  # 导入后 shunt.* 模块才在 sys.modules 里

N = sys.modules["shunt.notify"]


def seq_core(codes):
    codes = list(codes)

    def fake(method, path, body=None, timeout=10):
        return (codes.pop(0) if codes else 502), b"{}"
    return fake


class Watchdog(unittest.TestCase):
    def setUp(self):
        N.WD.update(status="ok", fails=0, tp_off=False, manual_stop=False)

    def test_transient_timeout_is_not_failure(self):
        with mock.patch.object(N, "core", seq_core([502, 200])), mock.patch.object(N.time, "sleep"):
            self.assertTrue(N.core_alive_confirmed())

    def test_all_fail(self):
        with mock.patch.object(N, "core", seq_core([502, 502, 502])), mock.patch.object(N.time, "sleep"):
            self.assertFalse(N.core_alive_confirmed())

    def test_tick_no_restart_on_single_timeout(self):
        with mock.patch.object(N, "core", seq_core([502, 200])), mock.patch.object(N.time, "sleep"), \
                mock.patch.object(N, "sh", return_value=(0, "")) as sh:
            N.watchdog_tick()
        sh.assert_not_called()
        self.assertEqual(N.WD["fails"], 0)

    def test_tick_restarts_when_really_dead(self):
        with mock.patch.object(N, "core", seq_core([])), mock.patch.object(N.time, "sleep"), \
                mock.patch.object(N, "sh", return_value=(0, "")) as sh, mock.patch.object(N, "wd_event"):
            N.watchdog_tick()
        self.assertTrue(any("restart" in c.args[0] for c in sh.call_args_list))
        self.assertEqual(N.WD["fails"], 1)


class InitScript(unittest.TestCase):
    def test_graceful_stop(self):
        import os
        txt = open(os.path.join(os.path.dirname(os.path.dirname(__file__)), "init.d", "mihomo")).read()
        self.assertIn('retry="TERM/15/KILL/5"', txt)


if __name__ == "__main__":
    unittest.main()
