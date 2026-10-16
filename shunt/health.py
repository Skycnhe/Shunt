"""节点健康检查：定时测速，连续失败的节点标红/自动隐藏。"""
import json
import threading
import time
from urllib.parse import quote

from .base import G_MANUAL, HC
from .corehttp import core, core_json
from .data import load, save

HEALTH_STATE = {"running": False, "last_run": 0, "total": 0, "checked": 0}

DEFAULT_CFG = {"enabled": False, "time": "03:00", "warn_days": 3, "hide_days": 7}


def health_cfg(d=None):
    """读取健康检查配置（data.json 的 health_cfg 字段）"""
    d = d or load()
    cfg = dict(DEFAULT_CFG)
    cfg.update(d.get("health_cfg") or {})
    return cfg


def save_health_cfg(cfg):
    d = load()
    d["health_cfg"] = cfg
    save(d)


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


def node_level(rec, cfg=None):
    """节点健康等级：ok / warn / bad / hidden"""
    cfg = cfg or DEFAULT_CFG
    if rec.get("hidden"):
        return "hidden"
    fail_days = rec.get("fail_days", 0)
    if fail_days >= cfg.get("hide_days", 7):
        return "hidden"
    if fail_days >= cfg.get("warn_days", 3):
        return "bad"
    if fail_days > 0:
        return "warn"
    return "ok"


def apply_results(results, d=None):
    """合并一次全量测速结果：{node_name: latency_ms(0=失败)}"""
    d = d or load()
    cfg = health_cfg(d)
    health = d.get("health") or {}
    for name, latency in results.items():
        rec = health.get(name) or {"fail_days": 0, "fail_dates": [], "hidden": False}
        record_one(rec, latency > 0, latency)
        # 自动隐藏达到阈值的节点
        if rec["fail_days"] >= cfg.get("hide_days", 7):
            rec["hidden"] = True
        health[name] = rec
    # 清理已删除节点的记录
    all_nodes = set(results.keys())
    for name in list(health.keys()):
        if name not in all_nodes:
            del health[name]
    d["health"] = health
    save(d)
    return health


def unhide(name):
    """手动取消隐藏节点，清零计数重新评估"""
    d = load()
    health = d.get("health") or {}
    rec = health.get(name)
    if rec:
        rec["hidden"] = False
        rec["fail_days"] = 0
        rec["fail_dates"] = []
        d["health"] = health
        save(d)
        return True
    return False


def get_records(d=None):
    """返回所有节点的健康记录"""
    d = d or load()
    return d.get("health") or {}


def run_check():
    """执行一次全量健康检查：经核心 delay 接口批量测速"""
    HEALTH_STATE["running"] = True
    HEALTH_STATE["checked"] = 0
    try:
        # 用「🖐️ 手动选择」组测速（含全部节点），不影响 url-test 组的固定选择
        if not core_json("/proxies/" + quote(G_MANUAL)):
            return False, "手动选择组不存在"
        code, raw = core("GET", f"/group/{quote(G_MANUAL)}/delay?url={quote(HC)}&timeout=5000", timeout=180)
        if code != 200:
            return False, f"测速接口返回 {code}"
        try:
            data = json.loads(raw)
        except Exception:
            return False, "测速结果解析失败"
        results = {}
        for name, v in data.items():
            # 只统计实际节点，跳过策略组
            if isinstance(v, int):
                results[name] = v
        HEALTH_STATE["total"] = len(results)
        HEALTH_STATE["checked"] = len(results)
        apply_results(results)
        HEALTH_STATE["last_run"] = int(time.time())
        ok_count = sum(1 for v in results.values() if v > 0)
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
