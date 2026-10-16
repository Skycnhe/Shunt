"""服务控制异步化（v8.3）：_do_service / _service_job / SERVICE_STATE / svc_restart 超时"""
import inspect
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.helper import server

assert server  # 导入后 shunt.* 模块才在 sys.modules 里

W = sys.modules["shunt.webapi"]


class TestDoService(unittest.TestCase):
    def test_stop_timeout_message(self):
        with mock.patch.object(W, "rc_run", return_value=(124, "（命令超时）")), \
             mock.patch("time.sleep"):
            ok, msg = W._do_service("stop")
        self.assertFalse(ok)
        self.assertIn("30 秒", msg)
        self.assertIn("rc-service shunt-core status", msg)

    def test_stop_success_proc_gone(self):
        with mock.patch.object(W, "rc_run", return_value=(0, "ok")), \
             mock.patch.object(W, "core_proc_alive", return_value=False), \
             mock.patch("time.sleep"):
            ok, msg = W._do_service("stop")
        self.assertTrue(ok)
        self.assertEqual(msg, "ok")

    def test_stop_fail_proc_alive(self):
        # v7.9.5 的 pid 二次确认：rc-service 返回 0 但进程仍在 → 真实失败
        with mock.patch.object(W, "rc_run", return_value=(0, "ok")), \
             mock.patch.object(W, "core_proc_alive", return_value=True), \
             mock.patch("time.sleep"), \
             mock.patch.object(W, "log_err"):
            ok, msg = W._do_service("stop")
        self.assertFalse(ok)
        self.assertIn("仍在运行", msg)

    def test_stop_rc_failure(self):
        with mock.patch.object(W, "rc_run", return_value=(1, "service not found")), \
             mock.patch.object(W, "log_err"):
            ok, msg = W._do_service("stop")
        self.assertFalse(ok)
        self.assertEqual(msg, "service not found")

    def test_restart_timeout_message(self):
        with mock.patch.object(W, "svc_restart", return_value=(124, "（命令超时）")), \
             mock.patch.object(W, "retest_soon"):
            ok, msg = W._do_service("restart")
        self.assertFalse(ok)
        self.assertIn("重启", msg)
        self.assertIn("30 秒", msg)

    def test_restart_success_calls_retest(self):
        # v8.3.1：restart 改走 svc_restart()（含看门狗暂停 + IP 重查），成功后 pid 确认进程还在
        with mock.patch.object(W, "svc_restart", return_value=(0, "ok")), \
             mock.patch.object(W, "core_proc_alive", return_value=True), \
             mock.patch("time.sleep"), \
             mock.patch.object(W, "retest_soon") as rs:
            ok, msg = W._do_service("restart")
        self.assertTrue(ok)
        self.assertEqual(msg, "ok")
        rs.assert_called_once_with()

    def test_restart_immediate_exit(self):
        # v8.3.1：重启后 pid 确认进程秒退 → 返回真实失败
        with mock.patch.object(W, "svc_restart", return_value=(0, "ok")), \
             mock.patch.object(W, "core_proc_alive", return_value=False), \
             mock.patch("time.sleep"), \
             mock.patch.object(W, "retest_soon"):
            ok, msg = W._do_service("restart")
        self.assertFalse(ok)
        self.assertIn("立即退出", msg)

    def test_start_immediate_exit(self):
        # v8.3.1：启动后 pid 确认进程秒退 → 返回真实失败
        with mock.patch.object(W, "rc_run", return_value=(0, "ok")), \
             mock.patch.object(W, "wd_hold"), \
             mock.patch.object(W, "core_proc_alive", return_value=False), \
             mock.patch("time.sleep"), \
             mock.patch.object(W, "retest_soon"):
            ok, msg = W._do_service("start")
        self.assertFalse(ok)
        self.assertIn("立即退出", msg)

    def test_stop_failure_restores_watchdog(self):
        # v8.3.1：停止失败时恢复看门狗标志，避免永久失效
        with mock.patch.object(W, "rc_run", return_value=(1, "rc failed")), \
             mock.patch.object(W, "core_proc_alive", return_value=True), \
             mock.patch.object(W, "log_err"):
            W.WD["manual_stop"] = True  # 模拟请求线程已置位
            ok, msg = W._do_service("stop")
        self.assertFalse(ok)
        self.assertFalse(W.WD["manual_stop"])  # 失败后交还给看门狗

    def test_start_uses_start_label(self):
        with mock.patch.object(W, "rc_run", return_value=(124, "（命令超时）")), \
             mock.patch.object(W, "wd_hold"), \
             mock.patch.object(W, "retest_soon"):
            ok, msg = W._do_service("start")
        self.assertFalse(ok)
        self.assertIn("启动", msg)


class TestServiceJob(unittest.TestCase):
    def test_job_updates_state(self):
        W.SERVICE_STATE.update({"running": True, "action": "restart", "ok": None, "message": "", "t": 0})
        with mock.patch.object(W, "_do_service", return_value=(True, "done")):
            W._service_job("restart")
        self.assertFalse(W.SERVICE_STATE["running"])
        self.assertTrue(W.SERVICE_STATE["ok"])
        self.assertEqual(W.SERVICE_STATE["message"], "done")

    def test_job_exception(self):
        with mock.patch.object(W, "_do_service", side_effect=RuntimeError("boom")), \
             mock.patch.object(W, "log_err"):
            W._service_job("restart")
        self.assertFalse(W.SERVICE_STATE["running"])
        self.assertFalse(W.SERVICE_STATE["ok"])
        self.assertIn("boom", W.SERVICE_STATE["message"])


class TestSvcRestartTimeout(unittest.TestCase):
    def test_default_timeout_30(self):
        S = sys.modules["shunt.sysopt"]
        sig = inspect.signature(S.svc_restart)
        self.assertEqual(sig.parameters["timeout"].default, 30)


if __name__ == "__main__":
    unittest.main()
