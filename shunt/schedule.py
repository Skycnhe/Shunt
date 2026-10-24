"""定时任务"""
import json, os, re, threading, time
from collections import deque
from urllib.parse import quote

from .errlog import log_err
from .base import BUILTIN_POLICIES, G_MANUAL, HC, PANEL_DIR
from .data import load, read_json, write_json
from .core import refresh_regions, reload_core
from .corehttp import core, core_json
from .nodeprobe import fill_absent
from .sb_common import active_core
from .groups import sb_sub_cache
from .sb_subs import sb_update_subs
from .sb_config import sb_sync_assets
from .sysopt import svc_restart
from .notify import WD
from .latency import bg_fetch, bg_meta, bg_meta_save
from .adblock import AB_STATE, ab_meta, adblock_update
from .health import health_cfg, run_check as health_run_check
from .devroute import mac_changed
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


MH_SAME_NOTE = "（节点与更新前完全相同：mihomo 拿到的订阅内容没有变化，或机场回复了 304 未修改）"


def mh_provider_names(name):
    """mihomo 里某个订阅（proxy-provider）当前的节点名列表；核心没应答 / 没有这个订阅时返回 None"""
    j = core_json("/providers/proxies/" + quote(name, safe=""), timeout=5)
    if not isinstance(j, dict) or not isinstance(j.get("proxies"), list):
        return None
    return [x.get("name") for x in j["proxies"] if isinstance(x, dict)]


def mh_unchanged_note(before, after):
    """mihomo 更新订阅前后节点名单完全一样时给出提示。mihomo 默认开启 ETag：机场 / CDN 回复 304，
    或返回的内容与本地缓存逐字节相同，mihomo 只刷新「更新时间」、继续用本地 ./providers/<名>.yaml，
    更新接口照样回 204。以前面板只报「已更新」，看不出节点其实没换"""
    if before and after is not None and before == after:
        return f"：{len(after)} 个节点" + MH_SAME_NOTE
    return f"：{len(after)} 个节点" if after is not None else ""


def subs_update(names=None, d=None, where=None):
    """更新订阅（names 为空 = 全部）并刷新地区组：sing-box 由面板下载，mihomo 让核心重新拉取。
    返回 (成功列表, 失败列表「名称：原因」, 刷新地区组的提示)；给了 where 时刷新地区组出错只记日志不抛出"""
    d = d or load()
    if active_core(d) == "singbox":
        okl, bad = sb_update_subs(names, d)
    else:
        okl, bad = [], []
        for nm in names or [s["name"] for s in d["subs"]]:
            before = mh_provider_names(nm)
            code, raw = core("PUT", "/providers/proxies/" + quote(nm, safe=""), timeout=120)
            if code >= 300:
                bad.append(nm + "：" + raw.decode(errors="ignore")[:100])
            else:
                okl.append(nm + mh_unchanged_note(before, mh_provider_names(nm)))
    try:
        _, msg = refresh_regions()
    except Exception as e:
        if where is None:
            raise
        log_err(where, e)
        msg = ""
    return okl, bad, msg


LATENCY_PROBE_BUDGET = 60  # sing-box 定时测速逐个补测的时间上限（定时任务在 sched_loop 里同步执行，不能拖太久）


def run_task(name):
    d = load()
    if name == "sub_update":
        _, bad, _ = subs_update(d=d, where="定时任务：刷新地区分组")
        return not bad, "订阅已更新" if not bad else "以下订阅更新失败：" + "；".join(bad)
    if name == "geo_update" and active_core(d) == "singbox":
        bad = sb_sync_assets(d, force=True)
        ok, msg = reload_core()
        if bad:
            return False, "部分规则集更新失败：" + "；".join(bad)[:200]
        # 重载失败时以前仍报「GEO / 规则集已更新」（事件里显示「✗ GEO / 规则集已更新」），看不出是重载出了问题
        return ok, "GEO / 规则集已更新" if ok else "规则集已下载，但重载核心失败：" + str(msg)[:200]
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
        pg = core_json("/proxies/" + quote(G_MANUAL))
        if pg:
            c2, r2 = core("GET", f"/group/{quote(G_MANUAL)}/delay?url={quote(HC)}&timeout=5000", timeout=120)
            try:
                res = json.loads(r2) if c2 == 200 else {}
            except Exception:
                res = {}
            res = {k: v for k, v in res.items() if isinstance(v, int) and not isinstance(v, bool) and v > 0} if isinstance(res, dict) else {}
            if c2 == 200 and active_core() == "singbox":
                # sing-box 整组测速同时只测 10 个、共用超时：没轮到测的节点不在结果里，也没有刷新延迟，逐个补测
                members = [m for m in ((pg.get("all") if isinstance(pg, dict) else None) or []) if isinstance(m, str) and m not in BUILTIN_POLICIES]
                res = fill_absent({m: res.get(m, 0) for m in members}, LATENCY_PROBE_BUDGET)
            n = sum(1 for v in res.values() if v > 0)
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
                    # 给 where：刷新地区组出错只记日志。以前异常抛出到循环外，本轮已记为「今天已执行」的定点任务
                    # （定时重启核心 / 更新 GEO / 健康检查等）随之被跳过，当天不再执行
                    _, bad_, _ = subs_update(d=d, where="订阅自动更新：刷新地区分组")
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
            if n % 3 == 0:  # 每分钟：按设备分流里 MAC 对应的 IP 变了就重新生成配置
                devroute_tick(d)
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


_DEVROUTE = {"tried": None}  # 上次因 MAC 解析变化而重载时的解析结果：重载失败也不对同一结果反复重试


def devroute_tick(d):
    """按设备分流的 MAC 条目：ARP / DHCP / IPv6 邻居表解析出的 IP 与当前配置不同时重载核心。
    只读 /proc/net/arp 和租约文件（开 IPv6 时多跑一次 ip -6 neigh），没有 MAC 条目时什么都不做"""
    if WD["manual_stop"]:
        return
    cur = mac_changed(d)
    if cur is None or cur == _DEVROUTE["tried"]:
        return
    _DEVROUTE["tried"] = cur
    ok, msg = reload_core()
    sched_event(f"按设备分流：设备 IP 有变化，{'已更新配置' if ok else '更新配置失败 ' + str(msg)[:120]}")


def ab_last_update():
    m = ab_meta()
    return max([v.get("updated", 0) for v in m.values()] or [0])
