"""核心文件句柄：服务改名后 conf.d 迁移、看门狗句柄诊断；重载等待与卡死现场保存"""
import os
import subprocess
import tempfile
import unittest
from unittest import mock

from tests.helper import server  # 确保离线导入
from shunt import notify, sb_config, sysopt

__all__ = ["server"]


class TestConfdMigrate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.old = os.path.join(self.tmp, "mihomo")
        self.new = os.path.join(self.tmp, "shunt-core")

    def run_mig(self, on=("fd",)):
        with mock.patch.object(sysopt, "OPT_CONFD", self.new), mock.patch.object(sysopt, "OPT_CONFD_OLD", self.old):
            return sysopt.opt_migrate_confd(on=set(on))

    def test_copy_ulimit(self):
        with open(self.old, "w") as f:
            f.write('# x\nrc_ulimit="-n 1048576"\n')
        self.assertTrue(self.run_mig())
        self.assertIn('rc_ulimit="-n 1048576"', open(self.new).read())
        self.assertFalse(self.run_mig())  # 第二次不重复写

    def test_keep_existing(self):
        with open(self.old, "w") as f:
            f.write('rc_ulimit="-n 1048576"\n')
        with open(self.new, "w") as f:
            f.write('rc_ulimit="-n 65536"\n')
        self.assertFalse(self.run_mig())
        self.assertEqual(open(self.new).read(), 'rc_ulimit="-n 65536"\n')

    def test_no_old(self):
        self.assertFalse(self.run_mig())
        self.assertFalse(os.path.exists(self.new))

    def test_same_path_noop(self):
        with mock.patch.object(sysopt, "OPT_CONFD", self.old), mock.patch.object(sysopt, "OPT_CONFD_OLD", self.old):
            self.assertFalse(sysopt.opt_migrate_confd())


class TestFdUsage(unittest.TestCase):
    def test_self(self):
        tmp = tempfile.mkdtemp()
        pidf = os.path.join(tmp, "core.pid")
        with open(pidf, "w") as f:
            f.write(str(os.getpid()))
        with mock.patch.object(notify, "CORE_PID", pidf):
            u = notify.core_fd_usage()
        self.assertRegex(u, r"^\d+/(\d+|unlimited)$")

    def test_missing(self):
        with mock.patch.object(notify, "CORE_PID", "/nonexistent/pid"):
            self.assertEqual(notify.core_fd_usage(), "")



class TestReloadWait(unittest.TestCase):
    def test_nomark_fallback_not_short(self):
        # SIGHUP 后 sing-box 先 check 新配置，这期间应答的是旧实例；不能几秒就当重载成功
        self.assertGreaterEqual(sb_config.SB_RELOAD_NOMARK, 30)
        self.assertGreater(sb_config.SB_RELOAD_WAIT, sb_config.SB_RELOAD_NOMARK)


class TestHangDump(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.log = os.path.join(self.tmp, "core.log")
        self.hang = os.path.join(self.tmp, "hang.log")
        self.pidf = os.path.join(self.tmp, "core.pid")
        with open(self.log, "w") as f:
            f.write("INFO line before hang\n")

    def test_dump_saves_tail_and_stops_process(self):
        p = subprocess.Popen(["sleep", "30"])
        try:
            with open(self.pidf, "w") as f:
                f.write(str(p.pid))
            with mock.patch.object(notify, "CORE_PID", self.pidf), mock.patch.object(notify, "MIHOMO_LOG", self.log), \
                    mock.patch.object(notify, "HANG_LOG", self.hang):
                self.assertTrue(notify.core_hang_dump("控制接口无响应"))
            p.wait(timeout=5)  # SIGQUIT 已结束进程
            s = open(self.hang, encoding="utf-8").read()
            self.assertIn("line before hang", s)
            self.assertIn("控制接口无响应", s)
        finally:
            if p.poll() is None:
                p.kill()

    def test_no_process(self):
        with mock.patch.object(notify, "CORE_PID", self.pidf), mock.patch.object(notify, "HANG_LOG", self.hang):
            self.assertFalse(notify.core_hang_dump("x"))
        self.assertFalse(os.path.exists(self.hang))


if __name__ == "__main__":
    unittest.main()
