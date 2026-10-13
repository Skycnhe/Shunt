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
        N.WD_HOLD.update(until=0.0, why="")

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
                mock.patch.object(N, "svc_restart", return_value=(0, "")) as rs, mock.patch.object(N, "wd_event") as ev:
            N.watchdog_tick()
        rs.assert_called_once()
        self.assertEqual(N.WD["fails"], 1)
        self.assertIn("第 1 次自动重启", ev.call_args.args[0])

    def test_hold_skips_check(self):
        """面板自己在重启 / 重载核心时（WD_HOLD），看门狗不判定、不重启"""
        N.WD_HOLD["until"] = N.time.time() + 30
        with mock.patch.object(N, "core", seq_core([])) as _c, mock.patch.object(N.time, "sleep"), \
                mock.patch.object(N, "svc_restart") as rs:
            N.watchdog_tick()
        rs.assert_not_called()
        self.assertEqual(N.WD["fails"], 0)

    def test_svc_restart_sets_hold(self):
        S = sys.modules["shunt.sysopt"]
        with mock.patch.object(S, "sh", return_value=(0, "")):
            S.svc_restart(timeout=10)
        self.assertGreater(N.WD_HOLD["until"], N.time.time() + 30)


class InitScript(unittest.TestCase):
    def test_graceful_stop(self):
        import os
        txt = open(os.path.join(os.path.dirname(os.path.dirname(__file__)), "init.d", "mihomo")).read()
        self.assertIn('retry="TERM/15/KILL/5"', txt)


if __name__ == "__main__":
    unittest.main()
