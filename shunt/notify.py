"""Telegram 通知"""
import json, os, socket, threading, time, urllib.request, urllib.error
from collections import deque
from urllib.parse import quote

from .base import CORE_UPD, G_MANUAL, HC, MASS_TEST, MIHOMO_LOG, NOTIFY_FILE, TPROXY_SH, WD_HOLD
from .data import load, read_json, write_json
from .corehttp import core, core_json
from .sb_common import CORE_PID, CORES, active_core
from .sysopt import proxy_opener, sh, svc_restart
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
WD = {"status": "ok", "fails": 0, "events": deque(maxlen=50), "last_check": 0, "manual_stop": False, "tp_off": False}


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
        os.kill(int(open(CORE_PID).read().strip()), 0)
        return True
    except Exception:
        return False


def core_last_error():
    """核心日志末尾 16KB 里最后一条 FATAL / ERROR / panic，写进看门狗事件，便于事后查原因"""
    try:
        with open(MIHOMO_LOG, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 16 * 1024))
            lines = f.read().decode("utf-8", "ignore").splitlines()
    except OSError:
        return ""
    for line in reversed(lines):
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
    if MASS_TEST["n"] > 0:  # 全节点测速进行中：核心高负载，/version 可能超时，暂停故障判定
        return
    redirecting = d["proxy_mode"] != "off"  # TProxy 或 TUN（TUN 模式下 tproxy.sh 仍负责 DNS 重定向）
    cname = CORES.get(active_core(d), "mihomo")
    if core_alive_confirmed():
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
        wd_event(f"{cname} 核心{why}，第 {WD['fails']} 次自动重启" + (f"；日志最后一条错误：{err}" if err else ""),
                 push=WD["fails"] == 1)
        svc_restart(timeout=60, why="看门狗重启核心")
        return
    if WD["status"] != "direct":
        WD["status"] = "direct"
        if redirecting:
            sh(TPROXY_SH + " stop")  # TUN 模式下核心退出时 TUN 设备与路由随之消失，这里再撤掉 DNS 重定向
            WD["tp_off"] = True
        wd_event(f"{cname} 核心重启 2 次仍无响应，已关闭透明代理，局域网暂时直连上网")
    elif WD["fails"] % 10 == 0:  # 直连状态下每 5 分钟再尝试拉起一次
        svc_restart(timeout=60)
        if redirecting and core_alive():
            sh(TPROXY_SH + " stop")  # rc 的 start_post 会重新挂上规则，等下一轮确认恢复后再开
            # TUN 模式下核心一启动就接管路由，无法“暂不接管”，下一轮检查会正常恢复


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
