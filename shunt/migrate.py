"""v5 → v6 升级：保留节点选择"""
import os, time
from urllib.parse import quote

from .base import CONF_DIR, PANEL_DIR
from .data import legacy_map, load, read_json, write_json
from .core import core, core_json, reload_core
from .sb_common import active_core
from .notify import core_alive
SEL_FILE = os.path.join(PANEL_DIR, "selected.json")


def snapshot_selections(force=False):
    """记录各手动选择组当前选中的节点 / 分组（升级改名前调用）"""
    if os.path.isfile(SEL_FILE) and not force:
        return None
    j = core_json("/proxies", timeout=5)
    if not j:
        return None
    sel = {n: p["now"] for n, p in (j.get("proxies") or {}).items() if p.get("type") == "Selector" and p.get("now") and n != "GLOBAL"}
    write_json(SEL_FILE, sel)
    return sel


def restore_selections():
    """按新名称恢复升级前的选择；返回恢复的组数"""
    sel = read_json(SEL_FILE, None)
    if not sel:
        return 0
    mp = legacy_map(load()["groups_cfg"].get("strategy"))
    proxies = (core_json("/proxies", timeout=5) or {}).get("proxies") or {}
    n = 0
    for g, now in sel.items():
        g2, now2 = mp.get(g, g), mp.get(now, now)
        p = proxies.get(g2) or {}
        if p.get("type") == "Selector" and now2 in (p.get("all") or []) and p.get("now") != now2:
            code, _ = core("PUT", "/proxies/" + quote(g2), {"name": now2})
            n += code < 300
    try:
        os.remove(SEL_FILE)
    except OSError:
        pass
    print(time.strftime("%F %T"), f"[upgrade] 已按新名称恢复 {n} 个策略组的选择", flush=True)
    return n


def startup_migrate():
    """面板升级后首次启动：核心还在跑旧配置（旧组名）时，先记下选择，再生成新配置并恢复选择"""
    for _ in range(30):
        if core_alive():
            break
        time.sleep(2)
    else:
        return
    cur = {} if active_core() == "singbox" else read_json(os.path.join(CONF_DIR, "config.yaml"), None) or {}
    old = set(legacy_map())
    if any(g.get("name") in old for g in cur.get("proxy-groups") or []):
        snapshot_selections()
        ok, msg = reload_core()
        print(time.strftime("%F %T"), "[upgrade] 已按新版策略组重新生成配置：", ok, msg[:120], flush=True)
        time.sleep(1)
    if os.path.isfile(SEL_FILE):
        restore_selections()
