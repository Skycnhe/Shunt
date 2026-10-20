"""定时任务"""
import json, os, re, threading, time
from collections import deque
from urllib.parse import quote

from .errlog import log_err
from .base import G_MANUAL, HC, PANEL_DIR
from .data import load, read_json, write_json
from .core import refresh_regions, reload_core
from .corehttp import core, core_json
from .sb_common import active_core
from .groups import sb_sub_cache
from .sb_subs import sb_update_subs
from .sb_config import sb_sync_assets
from .sysopt import svc_restart
from .notify import WD
from .latency import bg_fetch, bg_meta, bg_meta_save
from .adblock import AB_STATE, ab_meta, adblock_update
from .health import health_cfg, run_check as health_run_check
SCHED = {"events": deque(maxlen=30), "done": {}}
# 每天定点任务的最近执行记录 {任务: {"date": 日期, "at": 当时的设定时刻}}，落盘到 sched_done.json：
# 面板重启后不会把今天已跑过的任务再跑一遍
DAILY_FILE = os.path.join(PANEL_DIR, "sched_done.json")
DAILY = {"data": None}
_DAILY_LOCK = threading.Lock()
HHMM = re.compile(r"([01]\d|2[0-3]):[0-5]\d")


def _daily():
    if DAILY["data"] is None:
        d = read_json(DAILY_FILE, {})
        DAILY["data"] = d if isinstance(d, dict) else {}
    return DAILY["data"]


def _daily_mark(k, today, at):
    _daily()[k] = {"date": today, "at": at}
    try:
        write_json(DAILY_FILE, DAILY["data"])
    except OSError as e:
        log_err("保存定时任务记录", e)


def daily_due(k, at, now_hm, today):
    """每天定点任务是否该执行：到点或已过点（当天补跑）且今天还没跑过；返回 True 时已记为今天执行过（不会重复触发）。

    - 原来要求当前 HH:MM 正好等于设定值：循环被长任务卡住跨过那一分钟，当天就漏跑了
    - 第一次见到这个任务、或设定时刻刚被改过，而今天的时刻已经过了：记为今天已执行，从下一次开始
      （刚升级 / 开机 / 改时间时不会立刻把今天错过的任务全跑一遍，比如定时重启）
    - 设定时刻无效（如 25:00）或为空：永不触发"""
    if not at or not HHMM.fullmatch(at):
        return False
    with _DAILY_LOCK:
        rec = _daily().get(k)
        if not isinstance(rec, dict):
            rec = None
        if rec is not None and rec.get("date") == today:
            if rec.get("at") != at:  # 今天已经跑过、之后改了时刻：只更新记录，明天按新时刻
                _daily_mark(k, today, at)
            return False
        if now_hm < at:  # 还没到点：记下设定时刻，到点时才认得出「这是没改过的时刻」
            if rec is None or rec.get("at") != at:
                _daily_mark(k, (rec or {}).get("date") or "", at)
            return False
        if rec is None or rec.get("at") != at:
            _daily_mark(k, today, at)
            return False
        _daily_mark(k, today, at)
        return True


def sched_event(msg):
    SCHED["events"].appendleft({"t": int(time.time()), "msg": msg})
    print(time.strftime("%F %T"), "[schedule]", msg, flush=True)


def run_task(name):
    d = load()
    if name == "sub_update" and active_core(d) == "singbox":
        ok, bad = sb_update_subs(d=d)
        try:
            refresh_regions()
        except Exception as e:
            log_err("定时任务：刷新地区分组", e)
        return not bad, "订阅已更新" if not bad else "以下订阅更新失败：" + "；".join(bad)
    if name == "geo_update" and active_core(d) == "singbox":
        bad = sb_sync_assets(d, force=True)
        ok, msg = reload_core()
        return not bad and ok, "GEO / 规则集已更新" if not bad else "部分规则集更新失败：" + "；".join(bad)[:200]
    if name == "sub_update":
        bad = []
        for s in d["subs"]:
            code, _ = core("PUT", "/providers/proxies/" + quote(s["name"], safe=""), timeout=120)
            if code >= 300:
                bad.append(s["name"])
        try:
            refresh_regions()
        except Exception as e:
            log_err("定时任务：刷新地区分组", e)
        return not bad, "订阅已更新" if not bad else "以下订阅更新失败：" + "、".join(bad)
    if name == "core_restart":
        if WD["manual_stop"]:  # 用户手动停止了核心：定时重启不能替用户把它拉起来
            return True, "核心已手动停止，跳过定时重启"
        code, out = svc_restart(timeout=90, why="定时重启核心", cancel=lambda: WD["manual_stop"])
        return code == 0, "核心已重启" if code == 0 else out[-200:]
    if name == "geo_update":
        code, raw = core("POST", "/configs/geo", {}, timeout=180)
        return code < 300, "GEO 数据库已更新" if code < 300 else raw.decode(errors="ignore")[:200]
    if name == "latency":
        # GLOBAL 只含 config 里的节点和策略组，订阅节点要经「🖐️ 手动选择」（含全部节点）测速
        code, raw = core("GET", f"/group/GLOBAL/delay?url={quote(HC)}&timeout=5000", timeout=120)
        n = 0
        if core_json("/proxies/" + quote(G_MANUAL)):
            c2, r2 = core("GET", f"/group/{quote(G_MANUAL)}/delay?url={quote(HC)}&timeout=5000", timeout=120)
            try:
                n = sum(1 for v in json.loads(r2).values() if isinstance(v, int) and v > 0) if c2 == 200 else 0
            except Exception:
                n = 0
            code = 200 if (code == 200 or c2 in (200, 504)) else code
        return code == 200, f"节点测速完成，{n} 个节点可达"
    if name == "adblock":
        return adblock_update()
    if name == "health":
        return health_run_check()
    return False, "未知任务"


TASK_NAMES = {"sub_update": "定时更新订阅", "core_restart": "定时重启核心", "geo_update": "定时更新 GEO",
              "latency": "自动测速", "adblock": "更新广告规则", "health": "节点健康检查"}


def sched_loop():
    n = 0
    while True:
        time.sleep(20)
        n += 1
        try:
            d = load()
            sc = d.get("schedule") or {}
            now = time.strftime("%H:%M")
            today = time.strftime("%Y-%m-%d")
            due = [k for k in ("sub_update", "core_restart", "geo_update") if daily_due(k, str(sc.get(k) or ""), now, today)]
            # 节点健康检查：每天到点且启用时执行（已过点、今天还没跑也补跑）
            hcfg = health_cfg(d)
            if hcfg.get("enabled") and daily_due("health", str(hcfg.get("time") or ""), now, today):
                due.append("health")
            mins = int(sc.get("latency") or 0)
            if mins and time.time() - SCHED["done"].get("latency", 0) >= mins * 60:
                due.append("latency")
            if active_core(d) == "singbox" and d["subs"]:  # mihomo 的订阅由核心按间隔自动更新；sing-box 由面板代劳
                iv = max(int(d.get("sub_interval") or 86400), 600)
                last = min([sb_sub_cache(s["name"]).get("updated", 0) for s in d["subs"]] or [0])
                if time.time() - max(last, SCHED["done"].get("sb_subs", 0)) >= iv:
                    SCHED["done"]["sb_subs"] = time.time()
                    ok_, bad_ = sb_update_subs(d=d)
                    refresh_regions()
                    if bad_:
                        sched_event("订阅自动更新：✗ " + "；".join(bad_)[:200])
            bm = bg_meta()
            if bm.get("daily") and bm.get("url") and time.time() - max(int(bm.get("t") or 0), SCHED["done"].get("bg", 0)) >= 86400:
                SCHED["done"]["bg"] = time.time()  # 失败也等一天，避免反复重试
                if bg_fetch(bm["url"])[0]:
                    bm["t"] = int(time.time())
                    bg_meta_save(bm)
            ab = d["adblock"]
            if ab.get("enabled") and ab.get("lists") and int(ab.get("interval") or 0):
                if time.time() - max(AB_STATE["last"], ab_last_update()) >= int(ab["interval"]):
                    due.append("adblock")
            for k in due:
                if k == "latency":
                    SCHED["done"][k] = time.time()
                if k == "adblock":
                    AB_STATE["last"] = int(time.time())  # 失败也等下一个周期，避免频繁重试
                ok, msg = run_task(k)
                if k != "latency" or not ok:
                    sched_event(f"{TASK_NAMES[k]}：{'✓' if ok else '✗'} {msg}")
        except Exception as e:
            print("schedule error", e, flush=True)


def ab_last_update():
    m = ab_meta()
    return max([v.get("updated", 0) for v in m.values()] or [0])
