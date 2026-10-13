"""v7.7.6 服务改名：mihomo-panel → shunt（面板），mihomo → shunt-core（核心）。
旧设备在线更新后由新面板在后台执行一次：装好新 init 脚本、换开机启动项、停旧服务起新服务，成功后删掉旧脚本；
新服务起不来就恢复旧服务。核心原本是手动停止的，迁移后保持停止。"""
import os, threading, time

from .base import BASE, wd_hold
from .errlog import log_err
from .sysopt import sh

MIGRATE_SH = os.path.join(BASE, ".svc-migrate.sh")
SCRIPT = """#!/bin/sh
# 由 Shunt 面板生成：服务改名迁移（mihomo-panel → shunt，mihomo → shunt-core），执行一次后自删
exec >>/var/log/mihomo-panel.log 2>&1
echo "[svc-migrate] $(date '+%F %T') 服务改名：mihomo-panel → shunt，mihomo → shunt-core"
B={base}
for s in shunt shunt-core; do cp "$B/init.d/$s" "/etc/init.d/$s" && chmod +x "/etc/init.d/$s" || {{ echo "[svc-migrate] 复制 $s 失败"; rm -f "$0"; exit 1; }}; done
core_on=0; rc-service mihomo status >/dev/null 2>&1 && core_on=1
rc-update del mihomo default >/dev/null 2>&1; rc-update del mihomo-panel default >/dev/null 2>&1
rc-update add shunt-core default >/dev/null 2>&1; rc-update add shunt default >/dev/null 2>&1
if [ $core_on = 1 ]; then
  rc-service mihomo stop
  if ! rc-service shunt-core start; then
    echo "[svc-migrate] shunt-core 启动失败，恢复旧服务"
    rc-service shunt-core zap >/dev/null 2>&1
    rc-update del shunt-core default; rc-update del shunt default; rc-update add mihomo default; rc-update add mihomo-panel default
    rm -f /etc/init.d/shunt /etc/init.d/shunt-core
    rc-service mihomo start; rm -f "$0"; exit 1
  fi
fi
rc-service mihomo-panel stop   # 结束当前（旧服务名下的）面板进程
sleep 1
if rc-service shunt start; then
  rc-service mihomo zap >/dev/null 2>&1; rc-service mihomo-panel zap >/dev/null 2>&1
  rm -f /etc/init.d/mihomo /etc/init.d/mihomo-panel
  echo "[svc-migrate] 完成：rc-service shunt / shunt-core"
else
  echo "[svc-migrate] shunt 启动失败，恢复旧面板服务"
  rc-update del shunt default; rc-update add mihomo-panel default
  rc-service mihomo-panel start
fi
rm -f "$0"
"""


def need_migrate():
    return (BASE == "/opt/mihomo-panel" and os.path.isfile("/etc/init.d/mihomo-panel")
            and not os.path.isfile("/etc/init.d/shunt")
            and os.path.isfile(os.path.join(BASE, "init.d", "shunt")) and os.path.isfile(os.path.join(BASE, "init.d", "shunt-core"))
            and hasattr(os, "geteuid") and os.geteuid() == 0)


def svc_migrate(delay=20):
    """面板启动 delay 秒后（让在线更新的回滚守护先确认新版能打开）在后台跑迁移脚本"""
    if not need_migrate():
        return False

    def run():
        time.sleep(delay)
        try:
            with open(MIGRATE_SH, "w") as f:
                f.write(SCRIPT.format(base=BASE))
            os.chmod(MIGRATE_SH, 0o755)
            wd_hold(180, "服务改名迁移")
            sh(f"(command -v setsid >/dev/null && setsid sh '{MIGRATE_SH}' || sh '{MIGRATE_SH}') >/dev/null 2>&1 &")
        except OSError as e:
            log_err("服务改名迁移", e)
    threading.Thread(target=run, daemon=True).start()
    return True
