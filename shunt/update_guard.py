"""面板更新失败自动回滚"""
import os

from .errlog import log_err
from .base import AUTO_TAIL, BASE, G_AUTO, G_DIRECT, G_MANUAL, G_SEL, LB_PREFIX, LB_TAIL, PANEL_VERSION, PORT, SIDE_GROUPS, local_file
from .data import LB_ALL, map_refs
from .sysopt import sh
GUARD = os.path.join(BASE, ".update-guard.sh")
ROLLBACK_NOTE = os.path.join(BASE, ".rollback-note")


def update_guard_script(files):
    """更新后由独立的 shell 脚本检查新面板：90 秒内一直打不开就把 .backup 里的旧版本放回去并重启"""
    bak = os.path.join(BASE, ".backup")
    cps = "\n".join(f"  [ -f '{bak}/{f}' ] && cp '{bak}/{f}' '{local_file(f)}'" for f in files)
    restart = os.environ.get("PANEL_RESTART", "rc-service shunt restart 2>/dev/null || rc-service mihomo-panel restart")  # 回滚时服务可能已改名
    return f"""#!/bin/sh
# 由 Shunt 面板生成：在线更新后自动检查，新版启动失败时回滚
sleep 30
i=0
while [ $i -lt 6 ]; do
  python3 - <<'PY' && {{ rm -f "$0"; exit 0; }}
import ssl, sys, urllib.request
ctx = ssl._create_unverified_context()
op = urllib.request.build_opener(urllib.request.ProxyHandler({{}}), urllib.request.HTTPSHandler(context=ctx))
for u in ("http://127.0.0.1:{PORT}/manifest.webmanifest", "https://127.0.0.1:{PORT}/manifest.webmanifest"):
    try:
        op.open(u, timeout=5)
        sys.exit(0)
    except Exception:
        pass
sys.exit(1)
PY
  i=$((i+1)); sleep 10
done
{cps}
echo "新版面板 90 秒内没有启动成功，已自动恢复为 v{PANEL_VERSION}" > '{ROLLBACK_NOTE}'
echo "[update-guard] 新版面板启动失败，已回滚到 v{PANEL_VERSION}" >> /var/log/mihomo-panel.log
{restart} >/dev/null 2>&1
rm -f "$0"
"""


def start_update_guard(files):
    try:
        with open(GUARD, "w") as f:
            f.write(update_guard_script(files))
        os.chmod(GUARD, 0o755)
        sh(f"(command -v setsid >/dev/null && setsid sh '{GUARD}' || sh '{GUARD}') >/dev/null 2>&1 &")
    except OSError as e:
        log_err("更新回滚守护", e)


def group_kind(n, custom=()):
    if n in custom:
        return "custom"
    if n == G_SEL:
        return "select"
    if n == G_MANUAL:
        return "manual"
    if n == G_AUTO:
        return "auto"
    if n == G_DIRECT:
        return "direct"
    if n in SIDE_GROUPS:
        return "service"
    if n.startswith(LB_PREFIX) and n.endswith((LB_TAIL,) + tuple(LB_ALL.values())):
        return "lb"
    if n.endswith(AUTO_TAIL):
        return "region"
    return "other"


def group_meta(d, cfg):
    cn = {g["name"] for g in d.get("custom_groups") or []}
    meta = {}
    for g in cfg["proxy-groups"]:
        n = g["name"]
        meta[n] = {"kind": group_kind(n, cn), "type": g["type"], "strategy": g.get("strategy", ""), "filter": g.get("filter", ""),
                   "subs": bool(g.get("use")), "icon": g.get("icon", "")}
    return meta


def rename_policy(d, old, new):
    """策略组改名 / 删除（new 为节点选择）时同步更新自定义规则、规则集、其他自定义组、DNS 的引用；返回受影响条目数"""
    return map_refs(d, {old: new}, drop={old} if new == G_SEL else ())
