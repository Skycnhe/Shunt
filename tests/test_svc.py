"""核心启停：用 shell 脚本模拟 OpenRC 的 rc-service，验证管道继承不卡、超时整组结束、服务锁、手动停止标志落盘"""
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from tests.helper import server

assert server
S = sys.modules["shunt.sysopt"]
N = sys.modules["shunt.notify"]
W = sys.modules["shunt.webapi"]
SC = sys.modules["shunt.schedule"]

# 模拟 rc-service shunt-core：MODE 文件控制行为
#   (空)  start 时像 tproxy.sh 那样留一个继承 stdout 的后台子进程（sleep 20）
#   hang  stop 卡住 300 秒（模拟 OpenRC 卡在 stopping）
#   busy  第一次 start 报 already starting，zap 后恢复
RC = r'''#!/bin/sh
D=$(dirname "$0"); MODE=$(cat "$D/mode" 2>/dev/null)
echo "$1" >> "$D/calls"
case "$1" in
  start)
    if [ "$MODE" = busy ] && [ ! -f "$D/zapped" ]; then echo " * ERROR: shunt-core is already starting"; exit 1; fi
    sleep 1000 >/dev/null 2>&1 & echo $! > "$D/core.pid"
    (sleep 20) &
    echo " * Starting shunt-core ... [ ok ]";;
  stop)
    echo $$ > "$D/stop.pid"
    [ "$MODE" = hang ] && sleep 300
    [ -f "$D/core.pid" ] && kill "$(cat "$D/core.pid")" 2>/dev/null; rm -f "$D/core.pid";;
  restart) "$0" stop; "$0" start;;
  zap) touch "$D/zapped";;
esac
'''


class Svc(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="shunt-rc-")
        self.rc = os.path.join(self.d, "rc")
        with open(self.rc, "w") as f:
            f.write(RC)
        os.chmod(self.rc, os.stat(self.rc).st_mode | stat.S_IEXEC)
        self.pid = os.path.join(self.d, "core.pid")
        self.patches = [mock.patch.object(S, "SVC", self.rc), mock.patch.object(N, "CORE_PID", self.pid),
                        mock.patch.object(N, "STOP_FLAG", os.path.join(self.d, "core_stopped"))]
        for p in self.patches:
            p.start()
        N.WD.update(status="ok", fails=0, tp_off=False, manual_stop=False)
        N.WD_HOLD.update(until=0.0, why="")

    def tearDown(self):
        S._rc_once(self.rc + " stop", 5)
        for p in self.patches:
            p.stop()

    def mode(self, m):
        with open(os.path.join(self.d, "mode"), "w") as f:
            f.write(m)

    def calls(self):
        try:
            with open(os.path.join(self.d, "calls")) as f:
                return f.read().split()
        except OSError:
            return []

    def test_pipe_inherit_does_not_block(self):
        """start_post 留下的后台子进程继承输出：rc_run 不能等它（以前 capture_output 会卡到超时）"""
        t = time.time()
        code, out = S.rc_run("start", timeout=15)
        self.assertEqual(code, 0)
        self.assertLess(time.time() - t, 5)
        self.assertIn("Starting", out)

    def test_timeout_kills_whole_group(self):
        """超时：rc-service 本身也要被结束，不能留下一个还卡在 stopping 的进程"""
        self.mode("hang")
        t = time.time()
        code, out = S.rc_run("stop", timeout=1)
        self.assertEqual(code, 124)
        self.assertLess(time.time() - t, 10)
        self.assertIn("超时", out)
        with open(os.path.join(self.d, "stop.pid")) as f:
            p = int(f.read())
        time.sleep(0.2)
        with self.assertRaises(OSError):
            os.kill(p, 0)
        self.assertIn("zap", self.calls())  # 超时后 zap 复位 OpenRC 状态
        self.mode("")

    def test_busy_zap_retry(self):
        self.mode("busy")
        code, out = S.rc_run("start", timeout=10)
        self.assertEqual(code, 0)
        self.assertEqual(self.calls(), ["start", "zap", "start"])
        self.assertIn("zap", out)

    def test_manual_stop_persisted(self):
        N.set_manual_stop(True)
        self.assertTrue(os.path.isfile(N.STOP_FLAG))
        N.set_manual_stop(False)
        self.assertFalse(os.path.exists(N.STOP_FLAG))

    def test_api_stop_then_watchdog_does_not_restart(self):
        S.rc_run("start", timeout=10)
        self.assertTrue(N.core_proc_alive())
        ok, msg = W._svc_do("stop")
        self.assertTrue(ok, msg)
        self.assertTrue(N.WD["manual_stop"])
        self.assertTrue(os.path.isfile(N.STOP_FLAG))
        self.assertLessEqual(N.WD_HOLD["until"], time.time())  # 停止完不留看门狗暂停期
        with mock.patch.object(N, "core", return_value=(502, b"")), mock.patch.object(N.time, "sleep"), \
                mock.patch.object(N, "svc_restart") as rs:
            N.watchdog_tick()
        rs.assert_not_called()
        self.assertEqual(N.WD["status"], "stopped")

    def test_watchdog_waiting_for_lock_respects_stop(self):
        """看门狗决定重启时用户正好点了停止：看门狗等到锁后应放弃，不能把核心又拉起来"""
        S.rc_run("start", timeout=10)
        started = threading.Event()
        real = S.rc_run

        def slow_rc(act, timeout=90):
            started.set()
            time.sleep(0.5)
            return real(act, timeout)
        with mock.patch.object(S, "rc_run", slow_rc), mock.patch.object(W, "rc_run", slow_rc):
            t = threading.Thread(target=W._svc_do, args=("stop",))
            t.start()
            started.wait(5)
            code, msg = S.svc_restart(timeout=10, why="看门狗重启核心", cancel=lambda: N.WD["manual_stop"])
            t.join(15)
        self.assertEqual(code, 1)
        self.assertIn("取消", msg)
        self.assertFalse(N.core_proc_alive())
        self.assertNotIn("restart", self.calls())

    def test_watchdog_clears_stale_flag(self):
        """开机自启 / SSH 手动启动后核心在跑：过时的手动停止标志自动清除"""
        S.rc_run("start", timeout=10)
        N.set_manual_stop(True)
        with mock.patch.object(N, "core", return_value=(200, b"{}")):
            N.watchdog_tick()
        self.assertFalse(N.WD["manual_stop"])
        self.assertFalse(os.path.exists(N.STOP_FLAG))

    def test_api_restart_and_start(self):
        with mock.patch.object(W, "core_alive", return_value=True), mock.patch.object(W, "retest_soon"):
            ok, msg = W._svc_do("start")
            self.assertTrue(ok, msg)
            ok, msg = W._svc_do("restart")
            self.assertTrue(ok, msg)
        self.assertTrue(N.core_proc_alive())

    def test_schedule_restart_skips_when_stopped(self):
        N.set_manual_stop(True)
        with mock.patch.object(SC, "svc_restart") as rs:
            ok, msg = SC.run_task("core_restart")
        rs.assert_not_called()
        self.assertTrue(ok)
        self.assertIn("跳过", msg)


class Strays(unittest.TestCase):
    """不在 pid 文件里的核心进程（OpenRC 被 zap 过 / SSH 手动运行）：停止要能结束它们"""
    def setUp(self):
        import shutil, subprocess
        self.d = tempfile.mkdtemp(prefix="shunt-stray-")
        self.bin = os.path.join(self.d, "mihomo")
        shutil.copy(shutil.which("sh"), self.bin)  # 拷一份 sh 冒充核心二进制（按可执行文件识别）
        self.rc = os.path.join(self.d, "rc")
        with open(self.rc, "w") as f:
            f.write(RC)
        os.chmod(self.rc, 0o755)
        self.pid = os.path.join(self.d, "core.pid")
        self.patches = [mock.patch.object(S, "SVC", self.rc), mock.patch.object(N, "CORE_PID", self.pid),
                        mock.patch.object(S, "CORE_BINS", (self.bin,)),
                        mock.patch.object(N, "STOP_FLAG", os.path.join(self.d, "core_stopped"))]
        for p in self.patches:
            p.start()
        N.WD.update(status="ok", fails=0, tp_off=False, manual_stop=False)
        self.orphan = subprocess.Popen([self.bin, "-c", "sleep 1000; :"])
        self.check = subprocess.Popen([self.bin, "-c", "sleep 1000; :", "-t"])  # 像 selftest 的 mihomo -t：不是常驻核心，不能误杀

    def tearDown(self):
        for p in (self.orphan, self.check):
            p.kill()
            p.wait()
        for p in self.patches:
            p.stop()

    def test_detect(self):
        self.assertEqual(S.core_procs(), [self.orphan.pid])

    def test_stop_kills_orphan(self):
        ok, msg = W._svc_do("stop")
        self.orphan.wait(5)
        self.assertTrue(ok, msg)
        self.assertIn("残留", msg)
        self.assertEqual(S.core_procs(), [])
        self.assertIsNone(self.check.poll())

    def test_start_clears_orphan_first(self):
        with mock.patch.object(W, "core_alive", return_value=True), mock.patch.object(W, "retest_soon"):
            ok, msg = W._svc_do("start")
        self.orphan.wait(5)
        self.assertTrue(ok, msg)
        self.assertTrue(N.core_proc_alive())
        S._rc_once(self.rc + " stop", 5)


if __name__ == "__main__":
    unittest.main()
