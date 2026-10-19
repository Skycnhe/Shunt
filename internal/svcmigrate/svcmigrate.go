// Package svcmigrate 对应 Python shunt/svcmigrate.py：v7.7.6 服务改名
// （mihomo-panel → shunt（面板），mihomo → shunt-core（核心））。
// 旧设备在线更新后由新面板在后台执行一次：装好新 init 脚本、换开机启动项、
// 停旧服务起新服务，成功后删掉旧脚本；新服务起不来就恢复旧服务。
package svcmigrate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"shunt/internal/base"
	"shunt/internal/errlog"
	"shunt/internal/sysopt"
)

// MigrateSh 对应 MIGRATE_SH
var MigrateSh = filepath.Join(base.Base, ".svc-migrate.sh")

// migrateScript 对应 SCRIPT：__BASE__ 在写入时替换为 base.Base。
const migrateScript = `#!/bin/sh
# 由 Shunt 面板生成：服务改名迁移（mihomo-panel → shunt，mihomo → shunt-core），执行一次后自删
exec >>/var/log/mihomo-panel.log 2>&1
echo "[svc-migrate] $(date '+%F %T') 服务改名：mihomo-panel → shunt，mihomo → shunt-core"
B=__BASE__
for s in shunt shunt-core; do cp "$B/init.d/$s" "/etc/init.d/$s" && chmod +x "/etc/init.d/$s" || { echo "[svc-migrate] 复制 $s 失败"; rm -f "$0"; exit 1; }; done
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
`

// NeedMigrate 对应 need_migrate()。
func NeedMigrate() bool {
	return base.Base == "/opt/mihomo-panel" &&
		fileExists("/etc/init.d/mihomo-panel") &&
		!fileExists("/etc/init.d/shunt") &&
		fileExists(filepath.Join(base.Base, "init.d", "shunt")) &&
		fileExists(filepath.Join(base.Base, "init.d", "shunt-core")) &&
		os.Geteuid() == 0
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// SvcMigrate 对应 svc_migrate(delay)：面板启动 delay 秒后（让在线更新的回滚守护先确认新版能打开）
// 在后台跑迁移脚本。不需要迁移返回 false。
func SvcMigrate(delaySec int) bool {
	if !NeedMigrate() {
		return false
	}
	go func() {
		time.Sleep(time.Duration(delaySec) * time.Second)
		script := strings.ReplaceAll(migrateScript, "__BASE__", base.Base)
		if err := os.WriteFile(MigrateSh, []byte(script), 0o755); err != nil {
			errlog.LogErr("服务改名迁移", err, false)
			return
		}
		base.WdHold(180, "服务改名迁移", false)
		sysopt.Sh(fmt.Sprintf("(command -v setsid >/dev/null && setsid sh '%s' || sh '%s') >/dev/null 2>&1 &", MigrateSh, MigrateSh))
	}()
	return true
}
