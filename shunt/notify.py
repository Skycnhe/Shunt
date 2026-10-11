"""Telegram 通知"""
import json, socket, threading, time, urllib.request, urllib.error
from collections import deque
from urllib.parse import quote

from .base import CORE_UPD, G_MANUAL, HC, NOTIFY_FILE, SVC, TPROXY_SH
from .data import load, read_json, write_json
from .corehttp import core, core_json
from .sysopt import proxy_opener, sh
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


def watchdog_tick():
    if CORE_UPD["busy"]:  # 内核更新过程中核心会重启，不算故障
        return
    d = load()
    WD["last_check"] = int(time.time())
    if not d.get("watchdog", True):
        WD["status"] = "off"
        return
    redirecting = d["proxy_mode"] != "off"  # TProxy 或 TUN（TUN 模式下 tproxy.sh 仍负责 DNS 重定向）
    if core_alive():
        if WD["status"] in ("restarting", "direct"):
            msg = "mihomo 核心已恢复"
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
        wd_event(f"mihomo 核心无响应，第 {WD['fails']} 次自动重启", push=WD["fails"] == 1)
        sh(SVC + " restart", timeout=60)
        return
    if WD["status"] != "direct":
        WD["status"] = "direct"
        if redirecting:
            sh(TPROXY_SH + " stop")  # TUN 模式下核心退出时 TUN 设备与路由随之消失，这里再撤掉 DNS 重定向
            WD["tp_off"] = True
        wd_event("mihomo 核心重启 2 次仍无响应，已关闭透明代理，局域网暂时直连上网")
    elif WD["fails"] % 10 == 0:  # 直连状态下每 5 分钟再尝试拉起一次
        sh(SVC + " restart", timeout=60)
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
