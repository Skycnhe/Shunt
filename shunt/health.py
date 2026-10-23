"""节点健康检查：定时测速，连续失败的节点标红/自动隐藏。"""
import json
import threading
import time
from urllib.parse import quote

from .base import BUILTIN_POLICIES, G_MANUAL, HC
from .corehttp import core, core_json
from .data import load, update
from .nodeprobe import fill_absent
from .sb_common import active_core

HEALTH_STATE = {"running": False, "last_run": 0, "total": 0, "checked": 0}

DEFAULT_CFG = {"enabled": False, "time": "03:00", "warn_days": 3, "hide_days": 7}


def health_cfg(d=None):
    """读取健康检查配置（data.json 的 health_cfg 字段）"""
    d = d or load()
    cfg = dict(DEFAULT_CFG)
    cfg.update(d.get("health_cfg") or {})
    return cfg


def save_health_cfg(cfg):
    """与其他写入共用 data.update()（全局锁内读-改-写、原子落盘），不会和同时保存的设置互相覆盖"""
    update(lambda d: d.update(health_cfg=dict(cfg)))


def _today():
    return time.strftime("%Y-%m-%d")


def record_one(rec, ok, latency=0):
    """更新单个节点的健康记录。成功：清零并取消隐藏；失败：按天去重计数。"""
    today = _today()
    if ok:
        rec["fail_days"] = 0
        rec["fail_dates"] = []
        rec["hidden"] = False
        rec["last_ok"] = int(time.time())
        if latency:
            rec["latency"] = latency
    else:
        dates = rec.get("fail_dates") or []
        if today not in dates:
            dates.append(today)
            # 只保留最近 30 天的记录
            dates = sorted(dates)[-30:]
        rec["fail_dates"] = dates
        rec["fail_days"] = len(dates)
        rec["last_fail"] = int(time.time())
    return rec


def apply_results(results, d=None, universe=None):
    """合并一次全量测速结果：{node_name: latency_ms(0=失败)}。
    universe：当前全部节点名；给出时只删除不在其中的节点记录（失败节点保留并计数），
    不给时按 results 的键清理（兼容旧调用）。
    d 给出时只在这份数据上合并（不落盘）；否则在 data.update() 的锁内读-改-写 data.json"""
    out = {}

    def merge(dd):
        cfg = health_cfg(dd)
        health = dd.get("health") or {}
        for name, latency in results.items():
            rec = health.get(name) or {"fail_days": 0, "fail_dates": [], "hidden": False}
            record_one(rec, latency > 0, latency)
            # 自动隐藏达到阈值的节点
            if rec["fail_days"] >= cfg.get("hide_days", 7):
                rec["hidden"] = True
            health[name] = rec
        # 清理已删除节点的记录
        all_nodes = set(results.keys()) if universe is None else set(universe) | set(results.keys())
        for name in list(health.keys()):
            if name not in all_nodes:
                del health[name]
        dd["health"] = health
        out["health"] = health

    if d is not None:
        merge(d)
    else:
        update(merge)
    return out["health"]


def merge_delay(members, code, data):
    """把 /group/…/delay 的应答整理成 {节点: 延迟(0=失败或缺席)}。
    mihomo 与 sing-box 的 clash API 都只返回测速成功的节点，失败的直接缺席；
    mihomo 全部失败时返回 504，sing-box 返回空对象。全集取自组的 all 成员。
    mihomo 测完整组，缺席即失败；sing-box 同时只测 10 个、共用超时，缺席可能只是没轮到测，调用方要用 nodeprobe.fill_absent 补测"""
    ok = data if code == 200 and isinstance(data, dict) else {}
    nodes = [n for n in (members or list(ok)) if isinstance(n, str) and n not in BUILTIN_POLICIES]
    results = {}
    for n in nodes:
        v = ok.get(n)
        results[n] = v if isinstance(v, int) and not isinstance(v, bool) and v > 0 else 0
    return results


def unhide(name):
    """手动取消隐藏节点，清零计数重新评估"""
    found = []

    def fn(d):
        health = d.get("health") or {}
        rec = health.get(name)
        if rec:
            rec["hidden"] = False
            rec["fail_days"] = 0
            rec["fail_dates"] = []
            d["health"] = health
            found.append(True)
    if name not in (load().get("health") or {}):
        return False
    update(fn)
    return bool(found)


def get_records(d=None):
    """返回所有节点的健康记录"""
    d = d or load()
    return d.get("health") or {}


HEALTH_PROBE_BUDGET = 240  # sing-box 逐个补测的时间上限（每天一次的后台检查，比告警复核宽松；需小于 base.MASS_MAX_AGE）


def run_check():
    """执行一次全量健康检查：经核心 delay 接口批量测速"""
    HEALTH_STATE["running"] = True
    HEALTH_STATE["checked"] = 0
    try:
        # 用「🖐️ 手动选择」组测速（含全部节点），不影响 url-test 组的固定选择
        pg = core_json("/proxies/" + quote(G_MANUAL))
        if not pg:
            return False, "手动选择组不存在"
        members = pg.get("all") or []
        code, raw = core("GET", f"/group/{quote(G_MANUAL)}/delay?url={quote(HC)}&timeout=5000", timeout=180)
        if code not in (200, 504):  # 504：mihomo 全部节点超时，按全部失败记录
            return False, f"测速接口返回 {code}"
        data = {}
        if code == 200:
            try:
                data = json.loads(raw)
            except Exception:
                return False, "测速结果解析失败"
        results = merge_delay(members, code, data)
        if not results:
            return False, "手动选择组里没有节点"
        universe = list(results)
        HEALTH_STATE["total"] = len(results)
        undecided = 0
        if code == 200 and active_core() == "singbox":
            # sing-box 整组测速同时只测 10 个、共用超时，没轮到测的节点也不在结果里：缺席不等于失败，逐个补测；
            # 补测也没有结论的节点（核心重载中、预算内没测完）本轮不记录，免得把可用节点记一天失败
            fails = sum(1 for v in results.values() if not v)
            HEALTH_STATE["checked"] = len(results) - fails
            base_n = HEALTH_STATE["checked"]
            results = fill_absent(results, HEALTH_PROBE_BUDGET, progress=lambda k: HEALTH_STATE.update(checked=base_n + k))
            undecided = len(universe) - len(results)
            if not results:
                return False, "核心没有返回测速结果，本次未记录"
        HEALTH_STATE["checked"] = len(universe)
        apply_results(results, universe=universe)
        HEALTH_STATE["last_run"] = int(time.time())
        ok_count = sum(1 for v in results.values() if v > 0)
        if undecided:
            return True, f"检查完成：{ok_count}/{len(universe)} 个节点正常，{undecided} 个未测出结果（本次不记录）"
        return True, f"检查完成：{ok_count}/{len(results)} 个节点正常"
    finally:
        HEALTH_STATE["running"] = False


def run_check_bg():
    """后台线程执行检查，API 立即返回"""
    if HEALTH_STATE["running"]:
        return False
    t = threading.Thread(target=run_check, daemon=True)
    t.start()
    return True
