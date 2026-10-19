"""v10.2.9 回归测试（同步 Hk001 v8.3.11 第 9 / 12 / 14 条）：看门狗探测期间开始热重载 / 内核更新 / 手动停止时不误杀、
服务锁被占时跳过且不计失败、关闭文件句柄后不被旧 conf.d/mihomo 迁移改回、看门狗计数遍历期间并发写入不报错"""
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from tests.helper import server

assert server

N = sys.modules["shunt.notify"]
SO = sys.modules["shunt.sysopt"]


class WatchdogYieldTest(unittest.TestCase):
    """第 9 条：core_alive_confirmed 要二十多秒，期间开始热重载 / 内核更新 / 被手动停止时不能 SIGQUIT + 重启"""
    def setUp(self):
        N.WD.update(status="ok", fails=0, tp_off=False, manual_stop=False)
        N.WD_HOLD.update(until=0.0, why="")
        N.CORE_UPD["busy"] = False

    def tearDown(self):
        N.WD.update(status="ok", fails=0, tp_off=False, manual_stop=False)
        N.WD_HOLD.update(until=0.0, why="")
        N.CORE_UPD["busy"] = False

    def _tick(self, during):
        def confirm():
            during()
            return False
        with mock.patch.object(N, "core_alive_confirmed", confirm), mock.patch.object(N, "load", return_value=server.load()), \
                mock.patch.object(N, "mass_testing", return_value=False), mock.patch.object(N, "core_proc_alive", return_value=True), \
                mock.patch.object(N, "core_fd_usage", return_value="10/1024"), mock.patch.object(N, "core_last_error", return_value=""), \
                mock.patch.object(N, "core_hang_dump", return_value=True) as dump, \
                mock.patch.object(N, "svc_restart", return_value=(0, "")) as rs, mock.patch.object(N, "wd_event") as ev, \
                mock.patch.object(N, "sh", return_value=(0, "")):
            N.watchdog_tick()
        return dump, rs, ev

    def test_reload_started_during_probe(self):
        dump, rs, ev = self._tick(lambda: N.WD_HOLD.update(until=time.time() + 60, why="热重载"))
        dump.assert_not_called()
        rs.assert_not_called()
        ev.assert_not_called()
        self.assertEqual(N.WD["fails"], 0)

    def test_core_update_started_during_probe(self):
        dump, rs, _ = self._tick(lambda: N.CORE_UPD.update(busy=True))
        dump.assert_not_called()
        rs.assert_not_called()

    def test_manual_stop_during_probe(self):
        dump, rs, _ = self._tick(lambda: N.WD.update(manual_stop=True))
        dump.assert_not_called()
        rs.assert_not_called()
        self.assertEqual(N.WD["status"], "stopped")

    def test_service_lock_busy_skips(self):
        got, release = threading.Event(), threading.Event()

        def holder():
            with N.SVC_OP:
                got.set()
                release.wait(10)
        t = threading.Thread(target=holder, daemon=True)
        t.start()
        got.wait(5)
        try:
            dump, rs, _ = self._tick(lambda: None)
        finally:
            release.set()
            t.join(5)
        dump.assert_not_called()
        rs.assert_not_called()
        self.assertEqual(N.WD["fails"], 0)

    def test_really_dead_still_restarts(self):
        dump, rs, ev = self._tick(lambda: None)
        dump.assert_called_once()
        rs.assert_called_once()
        self.assertEqual(N.WD["fails"], 1)
        self.assertIn("第 1 次自动重启", ev.call_args.args[0])


class WdCountsConcurrentTest(unittest.TestCase):
    """第 14 条：遍历事件记录期间看门狗线程 appendleft，不再抛 deque mutated during iteration"""
    def test_mutation_during_iteration(self):
        import collections
        dq = collections.deque(maxlen=20)

        class E(dict):
            def get(self, k, default=None):
                dq.appendleft({"kind": "direct"})  # 模拟另一个线程在遍历途中写入
                return super().get(k, default)
        dq.extend([E(kind="restart"), E(kind="recover")])
        with mock.patch.dict(N.WD, {"events": dq}):
            c = N.wd_counts()
        self.assertEqual(c, {"restart": 1, "direct": 0, "recover": 1})


class FdConfdSwitchTest(unittest.TestCase):
    """第 12 条：关掉「文件句柄」后，面板重启不再从旧 conf.d/mihomo 搬回 rc_ulimit"""
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.old = os.path.join(self.tmp, "mihomo")
        self.new = os.path.join(self.tmp, "shunt-core")
        with open(self.old, "w") as f:
            f.write('# keep\nrc_ulimit="-n 65536"\n')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def mig(self, on):
        with mock.patch.object(SO, "OPT_CONFD", self.new), mock.patch.object(SO, "OPT_CONFD_OLD", self.old):
            return SO.opt_migrate_confd(on=set(on))

    def test_off_not_migrated_and_old_cleared(self):
        self.assertFalse(self.mig([]))
        self.assertFalse(os.path.exists(self.new))
        with open(self.old) as f:
            self.assertEqual(f.read(), "# keep\n")  # 旧文件其它内容保留，只删 rc_ulimit

    def test_on_migrated_once_then_toggle_off_sticks(self):
        self.assertTrue(self.mig(["fd"]))
        with open(self.new) as f:
            self.assertIn('rc_ulimit="-n 65536"', f.read())
        with open(self.new, "w") as f:  # 用户在「系统优化」关掉文件句柄：opt_apply 删掉这一行
            f.write("")
        self.assertFalse(self.mig([]))  # 以前面板重启又从旧文件搬回来
        self.assertFalse(self.mig(["fd"]))
        with open(self.new) as f:
            self.assertNotIn("rc_ulimit", f.read())

    def test_reads_switch_from_data(self):
        with mock.patch.object(SO, "OPT_CONFD", self.new), mock.patch.object(SO, "OPT_CONFD_OLD", self.old), \
                mock.patch.object(SO, "load", return_value={"sysopt": ["bbr"]}):
            self.assertFalse(SO.opt_migrate_confd())
        self.assertFalse(os.path.exists(self.new))


if __name__ == "__main__":
    unittest.main()
