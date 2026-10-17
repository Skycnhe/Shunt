"""核心文件句柄：服务改名后 conf.d 迁移、看门狗句柄诊断"""
import os
import tempfile
import unittest
from unittest import mock

from tests.helper import server  # 确保离线导入
from shunt import notify, sysopt

__all__ = ["server"]


class TestConfdMigrate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.old = os.path.join(self.tmp, "mihomo")
        self.new = os.path.join(self.tmp, "shunt-core")

    def run_mig(self):
        with mock.patch.object(sysopt, "OPT_CONFD", self.new), mock.patch.object(sysopt, "OPT_CONFD_OLD", self.old):
            return sysopt.opt_migrate_confd()

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


if __name__ == "__main__":
    unittest.main()
