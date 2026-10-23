"""v8.4.11（与 Hk002 v10.3.7 相同）：顶栏「重启 / 停止 / 启动」提速。
- init.d：面板已在自己进程里生成配置（CORE_PREP 文件 2 分钟内）时 start_pre 跳过 --gen；start_post 不再固定 sleep 1，
  tproxy.sh 等核心监听好端口再挂规则（核心退出则不挂），参数直接读 CORE_PREP，不再起 Python 跑 --tpenv；
  stop_pre 先删 nftables 表（停核心期间不再把流量导向正在退出的核心）；stop_post 顺带清核心被 KILL 后残留的 TUN 规则
- rc_run 启动 / 重启前调用 cli.core_prep，用完删掉 CORE_PREP；--gen 也写 CORE_PREP
- 前端按钮立即显示「重启中…」等、0.2 秒查一次结果、完成后立刻按结果刷新顶栏
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from tests.helper import server, TMP

assert server

B = sys.modules["shunt.base"]
S = sys.modules["shunt.sysopt"]
CLI = sys.modules["shunt.cli"]
N = sys.modules["shunt.notify"]
W = sys.modules["shunt.webapi"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*p):
    with open(os.path.join(ROOT, *p), encoding="utf-8") as f:
        return f.read()


class VersionTest(unittest.TestCase):
    def test_version(self):
        self.assertEqual(B.PANEL_VERSION, "8.4.11")

    def test_changelog_top(self):
        heads = [ln for ln in read("CHANGELOG.md").splitlines() if ln.startswith("## v")]
        self.assertTrue(heads[0].startswith("## v8.4.11"), heads[0])


# 假命令：调用记到 $FAKE/log；nft list tables / ip -N rule show 的输出、pidof 的返回值从 $FAKE 下的文件读
FAKE_CMD = r'''#!/bin/sh
n=$(basename "$0"); echo "$n $*" >> "$FAKE/log"
case "$n $*" in
  "nft list tables") cat "$FAKE/tables" 2>/dev/null; exit 0;;
  "nft list "*) exit 1;;
  "nft -f -") cat > /dev/null; exit 0;;
  "ip -4 rule show") cat "$FAKE/rule4" 2>/dev/null; exit 0;;
  "ip -6 rule show") cat "$FAKE/rule6" 2>/dev/null; exit 0;;
  "ip "*"rule del fwmark"*) exit 1;;
  "pidof "*) exit $(cat "$FAKE/pidof_rc" 2>/dev/null || echo 1);;
  "python3 "*) exit 1;;
esac
exit 0
'''


class ShellCase(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="shunt-8411-")
        self.bin = os.path.join(self.d, "bin")
        os.makedirs(self.bin)
        for c in ("nft", "ip", "pidof", "python3", "sysctl", "modprobe"):
            p = os.path.join(self.bin, c)
            with open(p, "w") as f:
                f.write(FAKE_CMD)
            os.chmod(p, 0o755)
        self.net = os.path.join(self.d, "net")
        os.makedirs(self.net)
        self.env = dict(os.environ, FAKE=self.d, PATH=self.bin + ":" + os.environ["PATH"], PROC_NET=self.net)
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            p.kill()
            p.wait()
        shutil.rmtree(self.d, ignore_errors=True)

    def put(self, name, text):
        with open(os.path.join(self.d, name), "w") as f:
            f.write(text)

    def log(self):
        try:
            with open(os.path.join(self.d, "log")) as f:
                return f.read().splitlines()
        except OSError:
            return []

    def sh(self, args, env=None, timeout=30):
        e = dict(self.env, **(env or {}))
        return subprocess.run(["sh", os.path.join(ROOT, "tproxy.sh")] + args, env=e, capture_output=True, text=True, timeout=timeout)

    def tpenv(self, mode="tproxy"):
        p = os.path.join(self.d, "prep")
        self.put("prep", f"B_IP=''\nB_MAC=''\nB_IP6=''\nLOCAL6=''\nIPV6=0\nMODE={mode}\nDNS_ALL=0\n")
        return p

    def ports(self, udp=True, tcp=True, tcp_state="0A"):
        hdr = "  sl  local_address rem_address   st tx_queue rx_queue\n"
        with open(os.path.join(self.net, "udp"), "w") as f:
            f.write(hdr + ("   1: 00000000:041D 00000000:0000 07 00000000:00000000\n" if udp else ""))
        with open(os.path.join(self.net, "tcp"), "w") as f:
            # 第一行：远端端口恰好是 1ED5 的连接，不能当成本机监听
            f.write(hdr + "   0: 0100007F:9C40 0100007F:1ED5 01 00000000:00000000\n"
                    + (f"   1: 00000000:1ED5 00000000:0000 {tcp_state} 00000000:00000000\n" if tcp else ""))

    def live_pid(self):
        p = subprocess.Popen(["sleep", "60"])
        self.procs.append(p)
        f = os.path.join(self.d, "core.pid")
        with open(f, "w") as fh:
            fh.write(str(p.pid))
        return f


class TproxyApply(ShellCase):
    def test_tpenv_file_skips_python(self):
        """TPENV_FILE 有效：直接读参数，不起 Python；按 MODE 挂 TProxy 规则"""
        r = self.sh(["apply"], {"TPENV_FILE": self.tpenv("tproxy")})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("TProxy 已开启", r.stdout)
        self.assertFalse([x for x in self.log() if x.startswith("python3")], self.log())
        self.assertIn("nft -f -", self.log())

    def test_without_tpenv_file_falls_back_to_python(self):
        r = self.sh(["apply"], {"TPENV_FILE": os.path.join(self.d, "nope")})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue([x for x in self.log() if x.startswith("python3") and "--tpenv" in x], self.log())

    def test_wait_ready_ports_up(self):
        """核心已监听 1053/UDP 与 7893/TCP：立刻挂规则"""
        self.ports()
        t = time.time()
        r = self.sh(["apply"], {"TPENV_FILE": self.tpenv("tproxy"), "WAIT_PID": self.live_pid()})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertLess(time.time() - t, 3)
        self.assertIn("nft -f -", self.log())

    def test_wait_ready_waits_for_listen(self):
        """端口晚 0.5 秒才监听：等到再挂（以前固定 sleep 1，不管核心好没好）；TCP 非 LISTEN、只有远端端口相同都不算"""
        self.ports(udp=True, tcp=True, tcp_state="01")
        pidf = self.live_pid()

        def later():
            time.sleep(0.5)
            self.ports()
        import threading
        th = threading.Thread(target=later)
        th.start()
        t = time.time()
        r = self.sh(["apply"], {"TPENV_FILE": self.tpenv("tproxy"), "WAIT_PID": pidf})
        dt = time.time() - t
        th.join()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertGreaterEqual(dt, 0.45)
        self.assertLess(dt, 3)
        self.assertIn("nft -f -", self.log())

    def test_tun_mode_waits_only_dns(self):
        self.ports(udp=True, tcp=False)
        r = self.sh(["apply"], {"TPENV_FILE": self.tpenv("tun"), "WAIT_PID": self.live_pid()})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("TUN 模式", r.stdout)

    def test_core_exited_no_rules(self):
        """核心进程已退出：不挂规则（局域网保持直连），返回非 0 让 init.d 提示"""
        p = subprocess.Popen(["true"])
        p.wait()
        f = os.path.join(self.d, "dead.pid")
        with open(f, "w") as fh:
            fh.write(str(p.pid))
        r = self.sh(["apply"], {"TPENV_FILE": self.tpenv("tproxy"), "WAIT_PID": f})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("核心进程已退出", r.stdout)
        self.assertNotIn("nft -f -", self.log())

    def test_off_mode_does_not_wait(self):
        t = time.time()
        r = self.sh(["apply"], {"TPENV_FILE": self.tpenv("off"), "WAIT_PID": self.live_pid()})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertLess(time.time() - t, 3)
        self.assertIn("透明代理规则已关闭", r.stdout)

    def test_no_wait_pid_no_wait(self):
        """面板 tp_apply 等其他调用不带 WAIT_PID：行为与以前一致，不等端口"""
        t = time.time()
        r = self.sh(["apply"], {"TPENV_FILE": self.tpenv("tproxy")})
        self.assertEqual(r.returncode, 0)
        self.assertLess(time.time() - t, 3)


class Leftovers(ShellCase):
    RULES4 = ("0:\tfrom all lookup local\n100:\tfrom all fwmark 0x162 lookup 162\n9000:\tfrom all to 172.18.0.0/30 lookup 2022\n"
              "9001:\tfrom all ipproto icmp goto 9010\n9003:\tnot from all iif lo lookup 2022\n9010:\tfrom all unreachable\n"
              "32766:\tfrom all lookup main\n")

    def test_nothing_left_is_cheap(self):
        """核心正常退出（没有残留）：只查 3 条命令，不调 pidof、不删任何东西"""
        r = self.sh(["leftovers"])
        self.assertEqual(r.returncode, 0)
        self.assertEqual(self.log(), ["nft list tables", "ip -4 rule show", "ip -6 rule show"])

    def test_killed_core_leftovers_removed(self):
        self.put("tables", "table inet mihomo_panel\ntable inet sing-box\ntable inet mihomo\n")
        self.put("rule4", self.RULES4)
        self.put("pidof_rc", "1")
        r = self.sh(["stop", "leftovers"])
        self.assertEqual(r.returncode, 0)
        lg = self.log()
        self.assertIn("nft delete table inet mihomo_panel", lg)  # stop 本身
        self.assertIn("nft delete table inet sing-box", lg)
        self.assertIn("nft delete table inet mihomo", lg)
        dels = [x for x in lg if x.startswith("ip -4 rule del pref")]
        self.assertEqual(dels, [f"ip -4 rule del pref {p}" for p in (9000, 9001, 9003, 9010)])
        self.assertFalse([x for x in lg if x.startswith("ip -6 rule del pref")])  # IPv6 没有 2022 规则：不动

    def test_core_running_untouched(self):
        """还有核心进程（含不受服务管理的）：一律不动"""
        self.put("tables", "table inet sing-box\n")
        self.put("rule4", self.RULES4)
        self.put("pidof_rc", "0")
        self.sh(["leftovers"])
        self.assertFalse([x for x in self.log() if " delete " in x or " del " in x], self.log())

    def test_rules_without_2022_untouched(self):
        """9000 段里没有指向 2022 的规则（不是核心留下的）：不删"""
        self.put("rule4", "0:\tfrom all lookup local\n9000:\tfrom 10.0.0.0/8 lookup 100\n32766:\tfrom all lookup main\n")
        self.put("pidof_rc", "1")
        self.sh(["leftovers"])
        self.assertFalse([x for x in self.log() if " del " in x], self.log())

    def test_legacy_panel_table_not_deleted_here(self):
        """含 bypass_mac 的 inet mihomo 是本脚本旧版的表，由 drop_legacy 处理；leftovers 只删核心的 auto-redirect 表"""
        self.put("tables", "table inet mihomo\n")
        self.put("pidof_rc", "1")
        fake = os.path.join(self.bin, "nft")
        with open(fake, "w") as f:
            f.write(FAKE_CMD.replace('"nft list "*) exit 1;;', '"nft list set inet mihomo bypass_mac") exit 0;;\n  "nft list "*) exit 1;;'))
        self.sh(["leftovers"])
        self.assertNotIn("nft delete table inet mihomo", self.log())

    def test_old_stop_usage_unchanged(self):
        r = self.sh(["stop"])
        self.assertIn("透明代理规则已关闭", r.stdout)
        self.assertNotIn("nft list tables", self.log())


class InitScript(ShellCase):
    """把 init.d 的路径换到临时目录，source 后直接调用 start_pre / start_post / stop_pre / stop_post"""

    def run_fn(self, fn, name="shunt-core", pre=""):
        s = read("init.d", name)
        s = (s.replace("/opt/mihomo-panel/server.py", os.path.join(self.d, "server.py"))
             .replace("/opt/mihomo-panel/tproxy.sh", os.path.join(self.d, "tp.sh"))
             .replace("/run/shunt-core.prep", os.path.join(self.d, "prep"))
             .replace("/var/log/mihomo.log", os.path.join(self.d, "core.log"))
             .replace("/etc/sing-box", os.path.join(self.d, "sb")))
        with open(os.path.join(self.d, "init.sh"), "w") as f:
            f.write(s)
        with open(os.path.join(self.d, "tp.sh"), "w") as f:
            f.write('#!/bin/sh\necho "tproxy $* TPENV_FILE=$TPENV_FILE WAIT_PID=$WAIT_PID" >> "$FAKE/log"\n')
        os.chmod(os.path.join(self.d, "tp.sh"), 0o755)
        script = f'ewarn() {{ echo "WARN $*"; }}; RC_SVCNAME={name}; . "{self.d}/init.sh"; {pre} {fn}; echo "rc=$?"'
        return subprocess.run(["sh", "-c", script], env=self.env, capture_output=True, text=True, timeout=30)

    def test_start_pre_fresh_prep_skips_gen(self):
        for name in ("shunt-core", "mihomo"):
            self.tpenv()
            r = self.run_fn("start_pre", name)
            self.assertIn("rc=0", r.stdout)
            self.assertFalse([x for x in self.log() if "--gen" in x], (name, self.log()))
            self.assertTrue(os.path.exists(os.path.join(self.d, "prep")))  # 留给 start_post

    def test_start_pre_stale_prep_runs_gen(self):
        p = self.tpenv()
        old = time.time() - 600
        os.utime(p, (old, old))
        r = self.run_fn("start_pre")
        self.assertIn("rc=0", r.stdout)
        self.assertTrue([x for x in self.log() if "--gen" in x], self.log())
        self.assertFalse(os.path.exists(p))  # 过期的删掉，不让 start_post 用
        self.assertIn("WARN 生成配置失败", r.stdout)  # 假 python3 返回 1：照旧提示并继续启动

    def test_start_pre_no_prep_runs_gen(self):
        r = self.run_fn("start_pre")
        self.assertIn("rc=0", r.stdout)
        self.assertTrue([x for x in self.log() if "--gen" in x], self.log())

    def test_start_post_passes_prep_and_pidfile(self):
        p = self.tpenv()
        r = self.run_fn("start_post", pre='pidfile=/run/x.pid;')
        self.assertIn("rc=0", r.stdout)
        self.assertEqual(self.log(), [f"tproxy apply TPENV_FILE={p} WAIT_PID=/run/x.pid"])
        self.assertFalse(os.path.exists(p))  # 用完即删
        self.assertNotIn("sleep 1", read("init.d", "shunt-core").split("start_post()")[1].split("\n}")[0])

    def test_start_post_without_prep(self):
        r = self.run_fn("start_post", pre='pidfile=/run/x.pid;')
        self.assertIn("rc=0", r.stdout)
        self.assertEqual(self.log(), ["tproxy apply TPENV_FILE= WAIT_PID=/run/x.pid"])

    def test_stop_pre_and_post(self):
        r = self.run_fn("stop_pre")
        self.assertIn("rc=0", r.stdout)
        self.assertEqual(self.log(), ["nft delete table inet mihomo_panel"])
        r = self.run_fn("stop_post")
        self.assertIn("rc=0", r.stdout)
        self.assertEqual(self.log()[-1], "tproxy stop leftovers TPENV_FILE= WAIT_PID=")

    def test_table_name_matches(self):
        self.assertIn("TABLE=mihomo_panel", read("tproxy.sh"))
        self.assertIn('retry="TERM/15/KILL/5"', read("init.d", "shunt-core"))  # 正常退出时间不缩短（sing-box Fake-IP 缓存）


class CorePrep(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="shunt-prep-")
        self.prep = os.path.join(self.d, "shunt-core.prep")
        self.rc = os.path.join(self.d, "rc")
        # 模拟 rc-service：记下调用时 CORE_PREP 是否存在
        with open(self.rc, "w") as f:
            f.write(f'#!/bin/sh\necho "$1 $( [ -f {self.prep} ] && echo prep || echo noprep)" >> {self.d}/calls\n')
        os.chmod(self.rc, os.stat(self.rc).st_mode | stat.S_IEXEC)
        self.patches = [mock.patch.object(S, "CORE_PREP", self.prep), mock.patch.object(B, "CORE_PREP", self.prep),
                        mock.patch.object(S, "SVC", self.rc)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.d, ignore_errors=True)

    def calls(self):
        with open(os.path.join(self.d, "calls")) as f:
            return f.read().split("\n")[:-1]

    def test_rc_start_restart_prepares_and_cleans(self):
        cfg = os.path.join(TMP, "config.yaml")
        if os.path.exists(cfg):
            os.remove(cfg)
        for act in ("start", "restart"):
            code, _ = S.rc_run(act, timeout=10)
            self.assertEqual(code, 0)
            self.assertFalse(os.path.exists(self.prep))  # 用完删掉，不留给以后 SSH 里的 rc-service
        self.assertEqual(self.calls(), ["start prep", "restart prep"])
        self.assertTrue(os.path.exists(cfg))  # 配置由面板进程生成

    def test_rc_stop_no_prep(self):
        S.rc_run("stop", timeout=10)
        self.assertEqual(self.calls(), ["stop noprep"])

    def test_prep_failure_falls_back(self):
        """生成失败：记日志、不写 CORE_PREP（init.d 照旧 --gen），照常启动；上一次残留的也删掉"""
        with open(self.prep, "w") as f:
            f.write("MODE=tproxy\n")
        with mock.patch.object(CLI, "write_active_config", side_effect=ValueError("坏数据")), \
                mock.patch("shunt.errlog.log_err") as le:
            code, _ = S.rc_run("start", timeout=10)
        self.assertEqual(code, 0)
        self.assertEqual(self.calls(), ["start noprep"])
        self.assertTrue(le.called)

    def test_prep_disabled_when_no_path(self):
        with mock.patch.object(S, "CORE_PREP", ""), mock.patch.object(B, "CORE_PREP", ""), \
                mock.patch.object(CLI, "write_active_config") as w:
            S.rc_run("start", timeout=10)
        self.assertFalse(w.called)
        self.assertEqual(self.calls(), ["start noprep"])

    def test_write_prep_content_and_mode(self):
        self.assertTrue(CLI.write_prep(self.prep))
        self.assertEqual(stat.S_IMODE(os.stat(self.prep).st_mode), 0o600)
        with open(self.prep) as f:
            txt = f.read()
        self.assertEqual(txt, CLI.tp_env() + "\n")
        self.assertIn("MODE=", txt)

    def test_gen_writes_prep(self):
        """开机 / SSH 启动：--gen 顺带写 CORE_PREP，start_post 的 tproxy.sh 不必再起 Python"""
        d = tempfile.mkdtemp(prefix="shunt-gen-")
        with open(os.path.join(d, "data.json"), "w") as f:
            json.dump({"proxy_mode": "tun"}, f)
        env = dict(os.environ, PANEL_OFFLINE="1", PANEL_DATA=os.path.join(d, "data.json"), MIHOMO_DIR=d,
                   SB_DIR=os.path.join(d, "sb"), PANEL_CORE_PREP=os.path.join(d, "prep"))
        r = subprocess.run([sys.executable, os.path.join(ROOT, "server.py"), "--gen"], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(d, "prep")) as f:
            self.assertIn("MODE=tun", f.read())
        shutil.rmtree(d, ignore_errors=True)


class PrepPath(unittest.TestCase):
    def test_default_path_only_when_deployed(self):
        if B.BASE != "/opt/mihomo-panel":  # 开发 / 测试目录不写 /run
            self.assertEqual(B.CORE_PREP, os.environ.get("PANEL_CORE_PREP", ""))
        self.assertIn("/run/shunt-core.prep", read("init.d", "shunt-core"))
        self.assertIn('"/run/shunt-core.prep"', read("shunt", "base.py"))


class SvcConfirm(unittest.TestCase):
    def test_start_confirm_fast(self):
        """rc 返回后控制接口一应答就算成功：核心进程在、第二次查到 /version 就返回（0.1 秒间隔）"""
        seq = iter([False, True])
        with mock.patch.object(W, "rc_run", return_value=(0, "")), mock.patch.object(W, "core_proc_alive", return_value=True), \
                mock.patch.object(W, "core_procs", return_value=[]), mock.patch.object(W, "core_alive", side_effect=lambda **k: next(seq)) as ca, \
                mock.patch.object(W, "retest_soon"), mock.patch.object(W, "set_manual_stop"):
            t = time.time()
            ok, msg = W._svc_do("start")
        self.assertTrue(ok, msg)
        self.assertLess(time.time() - t, 0.6)
        self.assertEqual(ca.call_args.kwargs.get("timeout"), 2)

    def test_start_fails_when_process_gone(self):
        with mock.patch.object(W, "rc_run", return_value=(0, "boom")), mock.patch.object(W, "core_proc_alive", return_value=False), \
                mock.patch.object(W, "core_procs", return_value=[]), mock.patch.object(W, "core_alive", return_value=False), \
                mock.patch.object(W, "set_manual_stop"):
            ok, msg = W._svc_do("start")
        self.assertFalse(ok)
        self.assertIn("没有运行起来", msg)


@unittest.skipUnless(shutil.which("node"), "需要 node")
class Frontend(unittest.TestCase):
    def test_buttons(self):
        r = subprocess.run(["node", os.path.join(ROOT, "tests", "v8411_frontend.js"), ROOT], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        o = json.loads(r.stdout)
        # 点「重启」：立刻显示「重启中…」，三个按钮都禁用；后台中途报核心不在也不切换按钮
        self.assertEqual(o["busy"]["label"], "重启中…")
        self.assertEqual(o["busy"]["run"], "重启中…")
        self.assertEqual(o["busy"]["disabled"], [True, True, True])
        self.assertEqual(o["busy"]["hidden"], [False, False, True])
        # 完成：按钮文字恢复、按结果立即刷新顶栏（不等下一轮轮询），轮询间隔 0.2 秒
        self.assertEqual(o["done"]["labels"], ["重启", "停止", "启动"])
        self.assertEqual(o["done"]["disabled"], [False, False, False])
        self.assertEqual(o["done"]["run"], "运行中")
        self.assertEqual(o["done"]["toast"], "核心已重启")
        self.assertEqual(o["intervals"], [200])
        # 停止完成：立即切到「启动」按钮
        self.assertEqual(o["stop"]["hidden"], [True, True, False])
        self.assertEqual(o["stop"]["run"], "已停止")


if __name__ == "__main__":
    unittest.main()
