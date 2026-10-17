"""Telegram 通知"""
import json, os, signal, socket, threading, time, urllib.request, urllib.error
from collections import deque
from urllib.parse import quote

from .base import CORE_UPD, G_MANUAL, HC, MIHOMO_LOG, NOTIFY_FILE, PANEL_DIR, TPROXY_SH, WD_HOLD, mass_testing
from .errlog import log_tail
from .data import load, read_json, write_json
from .corehttp import core, core_json
from .sb_common import CORE_PID, CORES, active_core
from .sysopt import SVC_OP, proxy_opener, sh, svc_restart
def tg_send(text, d=None):
    d = d or load()
    if not d.get("tg_token") or not d.get("tg_chat"):
        return False, "未配置 Telegram"
    body = json.dumps({"chat_id": d["tg_chat"], "text": f"[Shunt@{socket.gethostname()}]\n{text}"}).encode()
    url = f"https://api.telegram.org/bot{d['tg_token']}/sendMessage"
    err = ""
    for use_proxy in (True, False):  # 先走代理，核心挂了再直连
        try:
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
            with proxy_opener(use_proxy).open(req, timeout=10) as r:
                if json.loads(r.read()).get("ok"):
                    return True, "已发送"
        except urllib.error.HTTPError as e:
            try:
                return False, json.loads(e.read()).get("description", str(e))
            except Exception:
                return False, str(e)
        except Exception as e:
            err = str(e)
    return False, "发送失败：" + err


def notify(text):
    threading.Thread(target=tg_send, args=(text,), daemon=True).start()


# ---------------------------------------------------------------- 故障自动直连 (watchdog) + 定期告警
# 「手动停止」标志落盘：以前只在内存里，面板一重启（在线更新、切 HTTPS、rc-service shunt restart）标志就丢了，
# 看门狗随即把用户手动停掉的核心又拉起来
STOP_FLAG = os.path.join(PANEL_DIR, "core_stopped")
WD = {"status": "ok", "fails": 0, "events": deque(maxlen=50), "last_check": 0, "manual_stop": os.path.isfile(STOP_FLAG),
      "tp_off": False}


def set_manual_stop(on):
    """置位 / 清除「用户手动停止了核心」：内存 + 标志文件"""
    WD["manual_stop"] = bool(on)
    try:
        if on:
            with open(STOP_FLAG, "w") as f:
                f.write(str(int(time.time())))
        elif os.path.exists(STOP_FLAG):
            os.remove(STOP_FLAG)
    except OSError:
        pass


def wd_event(msg, push=True):
    WD["events"].appendleft({"t": int(time.time()), "msg": msg})
    print(time.strftime("%F %T"), "[watchdog]", msg, flush=True)
    if push:
        notify(msg)


def core_alive():
    code, _ = core("GET", "/version", timeout=5)
    return code == 200


def core_alive_confirmed(retries=2, gap=3):
    """看门狗用：一次 /version 超时不算无响应，再隔几秒复查，连续都失败才判定故障。
    小路由上 sing-box 加载大规则集、重载配置或 GC 时会短暂卡几秒；以前一次超时就重启，
    重启若被强制结束（kill），sing-box 的 Fake-IP 映射全部丢失，客户端随后大量「missing fakeip record」"""
    if core_alive():
        return True
    for _ in range(retries):
        time.sleep(gap)
        code, _ = core("GET", "/version", timeout=8)
        if code == 200:
            return True
    return False


def core_proc_alive():
    """核心进程是否还在（pid 文件 + kill 0）。用来区分「进程退出」和「进程在但控制接口卡住」"""
    try:
        with open(CORE_PID) as f:
            os.kill(int(f.read().strip()), 0)
        return True
    except Exception:
        return False


def core_fd_usage():
    """核心进程已用 / 上限文件句柄，如「1021/1024」；读不到返回空串。句柄用尽是控制接口无响应最常见的原因"""
    try:
        with open(CORE_PID) as f:
            pid = int(f.read().strip())
        used = len(os.listdir(f"/proc/{pid}/fd"))
        lim = ""
        with open(f"/proc/{pid}/limits") as f:
            for line in f:
                if line.startswith("Max open files"):
                    lim = line.split()[3]
        return f"{used}/{lim}" if lim else str(used)
    except Exception:
        return ""


HANG_LOG = os.environ.get("PANEL_HANG_LOG", "/var/log/shunt-core-hang.log")


def core_hang_dump(why):
    """控制接口无响应、进程仍在：重启前把核心日志末尾和 Go 协程栈（SIGQUIT）存进 HANG_LOG。
    start_pre 会清空核心日志，不存下来就无从知道核心当时卡在哪。只保留最近一次（最多约 512KB）"""
    try:
        with open(CORE_PID) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
    except Exception:
        return False
    def tail(n):
        try:
            with open(MIHOMO_LOG, "rb") as f:
                f.seek(0, 2)
                end = f.tell()
                f.seek(max(0, end - n))
                return end, f.read()
        except OSError:
            return 0, b""
    off, before = tail(64 * 1024)
    try:
        os.kill(pid, signal.SIGQUIT)  # Go 运行时收到 SIGQUIT 把所有协程栈打到 stderr（即核心日志）后退出
    except OSError:
        pass
    for _ in range(20):
        time.sleep(0.25)
        try:
            os.kill(pid, 0)
        except OSError:
            break
    time.sleep(0.3)
    end, _ = tail(0)
    dump = b""
    if end > off:
        try:
            with open(MIHOMO_LOG, "rb") as f:
                f.seek(off)
                dump = f.read(448 * 1024)
        except OSError:
            pass
    try:
        with open(HANG_LOG, "wb") as f:
            f.write(("===== %s %s =====\n----- 核心日志末尾 -----\n" % (time.strftime("%F %T"), why)).encode())
            f.write(before)
            f.write("\n----- SIGQUIT 协程栈 -----\n".encode())
            f.write(dump)
        return True
    except OSError:
        return False


def core_last_error():
    """核心日志末尾 16KB 里最后一条 FATAL / ERROR / panic，写进看门狗事件，便于事后查原因"""
    for line in reversed(log_tail(MIHOMO_LOG) or []):
        if ("FATAL" in line or " ERROR " in line or "panic:" in line or "level=error" in line or "level=fatal" in line) \
                and "missing fakeip record" not in line:
            return line.strip()[-160:]
    return ""


def watchdog_tick():
    if CORE_UPD["busy"]:  # 内核更新过程中核心会重启，不算故障
        return
    if time.time() < WD_HOLD["until"]:  # 面板自己正在重启 / 重载核心（含启动后的加载期）
        return
    d = load()
    WD["last_check"] = int(time.time())
    if not d.get("watchdog", True):
        WD["status"] = "off"
        return
    if mass_testing():  # 全节点测速进行中：核心高负载，/version 可能超时，暂停故障判定
        return
    redirecting = d["proxy_mode"] != "off"  # TProxy 或 TUN（TUN 模式下 tproxy.sh 仍负责 DNS 重定向）
    cname = CORES.get(active_core(d), "mihomo")
    if core_alive_confirmed():
        # 核心在跑（开机自启、SSH 手动 start）：「手动停止」已过时，恢复看门狗。
        # 只在没人控制服务时清（拿不到锁说明正在停止 / 启动，不能清）
        if WD["manual_stop"] and SVC_OP.acquire(blocking=False):
            try:
                if core_proc_alive():
                    set_manual_stop(False)
            finally:
                SVC_OP.release()
        if WD["status"] in ("restarting", "direct"):
            msg = f"{cname} 核心已恢复"
            if WD["tp_off"] and redirecting:
                code, out = sh(TPROXY_SH + " apply")
                msg += "，透明代理已重新开启" if code == 0 else "，但重新开启透明代理失败：" + out[-120:]
            WD["tp_off"] = False
            wd_event(msg)
        WD["status"], WD["fails"] = "ok", 0
        return
    if WD["manual_stop"]:
        WD["status"] = "stopped"
        return
    WD["fails"] += 1
    if WD["fails"] <= 2:
        WD["status"] = "restarting"
        why = "控制接口无响应（进程仍在）" if core_proc_alive() else "进程已退出"
        err = core_last_error()
        fd = core_fd_usage() if core_proc_alive() else ""
        if fd:
            why += f"，文件句柄 {fd}"
        if fd and core_hang_dump(why):
            why += f"，现场已存到 {HANG_LOG}"
        wd_event(f"{cname} 核心{why}，第 {WD['fails']} 次自动重启" + (f"；日志最后一条错误：{err}" if err else ""),
                 push=WD["fails"] == 1)
        svc_restart(timeout=60, why="看门狗重启核心", cancel=lambda: WD["manual_stop"])
        return
    if WD["status"] != "direct":
        WD["status"] = "direct"
        if redirecting:
            sh(TPROXY_SH + " stop")  # TUN 模式下核心退出时 TUN 设备与路由随之消失，这里再撤掉 DNS 重定向
            WD["tp_off"] = True
        wd_event(f"{cname} 核心重启 2 次仍无响应，已关闭透明代理，局域网暂时直连上网")
    elif WD["fails"] % 10 == 0:  # 直连状态下每 5 分钟再尝试拉起一次
        svc_restart(timeout=60, why="看门狗重启核心", cancel=lambda: WD["manual_stop"])
        if redirecting:
            # rc 的 start_post 不管核心是否真的起来都会重新挂上规则（command_background 下启动总算成功）：
            # 一律撤掉，局域网保持直连；核心若已恢复，下一轮确认后再重新开启
            # TUN 模式下核心一启动就接管路由，无法“暂不接管”，下一轮检查会正常恢复
            sh(TPROXY_SH + " stop")
            WD["tp_off"] = True


def load_notified():
    return read_json(NOTIFY_FILE, {})


def check_nodes():
    """节点选择里所有节点都超时 → 通知（只在状态变化时发）"""
    d = load()
    if d.get("mode") == "direct" or not (d.get("tg_token") and d.get("tg_chat")):
        return  # 没配置 Telegram 时不必每 10 分钟测一遍全部节点
    # 用「🖐️ 手动选择」（select，含全部节点）测速：对 url-test 组调用 /group/…/delay 会被 mihomo 清除用户的📌固定选择
    pg = core_json("/proxies/" + quote(G_MANUAL))
    if not pg:
        return
    code, raw = core("GET", f"/group/{quote(G_MANUAL)}/delay?url={quote(HC)}&timeout=5000", timeout=30)
    try:
        res = json.loads(raw) if code == 200 else {}
    except Exception:
        res = {}
    all_down = not any(v for v in res.values() if isinstance(v, int) and v > 0)
    st = load_notified()
    if all_down != bool(st.get("allnodes")):
        st["allnodes"] = all_down
        write_json(NOTIFY_FILE, st)
        notify("⚠️ 节点选择中的所有节点均测速超时，请检查订阅或网络" if all_down else "✅ 节点已恢复可用")
