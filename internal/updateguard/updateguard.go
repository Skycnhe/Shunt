// Package updateguard 对应 Python shunt/update_guard.py：面板更新失败自动回滚，
// 以及策略组改名时的引用同步（group_kind / group_meta / rename_policy）。
package updateguard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"shunt/internal/base"
	"shunt/internal/data"
	"shunt/internal/errlog"
	"shunt/internal/sysopt"
)

// Guard 对应 GUARD
var Guard = filepath.Join(base.Base, ".update-guard.sh")

// RollbackNote 对应 ROLLBACK_NOTE
var RollbackNote = filepath.Join(base.Base, ".rollback-note")

// UpdateGuardScript 对应 update_guard_script(files)：
// 更新后由独立的 shell 脚本检查新面板：90 秒内一直打不开就把 .backup 里的旧版本放回去并重启。
func UpdateGuardScript(files []string) string {
	bak := filepath.Join(base.Base, ".backup")
	var cps strings.Builder
	for _, f := range files {
		fmt.Fprintf(&cps, "  [ -f '%s/%s' ] && cp '%s/%s' '%s'\n", bak, f, bak, f, base.LocalFile(f))
	}
	restart := os.Getenv("PANEL_RESTART")
	if restart == "" {
		restart = "rc-service shunt restart 2>/dev/null || rc-service mihomo-panel restart" // 回滚时服务可能已改名
	}
	var sb strings.Builder
	sb.WriteString("#!/bin/sh\n# 由 Shunt 面板生成：在线更新后自动检查，新版启动失败时回滚\nsleep 30\ni=0\n")
	sb.WriteString("while [ $i -lt 6 ]; do\n")
	sb.WriteString("  python3 - <<'PY' && { rm -f \"$0\"; exit 0; }\n")
	sb.WriteString("import ssl, sys, urllib.request\n")
	sb.WriteString("ctx = ssl._create_unverified_context()\n")
	sb.WriteString("op = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))\n")
	fmt.Fprintf(&sb, "for u in (\"http://127.0.0.1:%d/manifest.webmanifest\", \"https://127.0.0.1:%d/manifest.webmanifest\"):\n",
		base.Port, base.Port)
	sb.WriteString("    try:\n        op.open(u, timeout=5)\n        sys.exit(0)\n    except Exception:\n        pass\n")
	sb.WriteString("sys.exit(1)\nPY\n")
	sb.WriteString("  i=$((i+1)); sleep 10\ndone\n")
	sb.WriteString(cps.String())
	fmt.Fprintf(&sb, "echo \"新版面板 90 秒内没有启动成功，已自动恢复为 v%s\" > '%s'\n", base.PanelVersion, RollbackNote)
	fmt.Fprintf(&sb, "echo \"[update-guard] 新版面板启动失败，已回滚到 v%s\" >> /var/log/mihomo-panel.log\n", base.PanelVersion)
	sb.WriteString(restart + " >/dev/null 2>&1\n")
	sb.WriteString("rm -f \"$0\"\n")
	return sb.String()
}

// StartUpdateGuard 对应 start_update_guard(files)。
func StartUpdateGuard(files []string) {
	if err := os.WriteFile(Guard, []byte(UpdateGuardScript(files)), 0o755); err != nil {
		errlog.LogErr("更新回滚守护", err, false)
		return
	}
	sysopt.Sh(fmt.Sprintf("(command -v setsid >/dev/null && setsid sh '%s' || sh '%s') >/dev/null 2>&1 &", Guard, Guard))
}

// lbSuffixes 对应 (LB_TAIL,) + tuple(LB_ALL.values())：负载均衡组名的合法后缀
func lbSuffixes() []string {
	out := []string{base.LbTail}
	for _, k := range data.LbKinds {
		out = append(out, k[1])
	}
	for _, k := range data.LbDropped {
		out = append(out, k[1])
	}
	return out
}

// GroupKind 对应 group_kind(n, custom)：策略组分类。
func GroupKind(n string, custom ...string) string {
	for _, c := range custom {
		if n == c {
			return "custom"
		}
	}
	switch n {
	case base.GSel:
		return "select"
	case base.GManual:
		return "manual"
	case base.GAuto:
		return "auto"
	case base.GDirect:
		return "direct"
	}
	for _, s := range base.SideGroups {
		if n == s {
			return "service"
		}
	}
	if strings.HasPrefix(n, base.LbPrefix) {
		for _, s := range lbSuffixes() {
			if strings.HasSuffix(n, s) {
				return "lb"
			}
		}
	}
	if strings.HasSuffix(n, base.AutoTail) {
		return "region"
	}
	return "other"
}

// GroupMeta 对应 group_meta(d, cfg)：各策略组的元信息（kind/type/strategy/filter/subs/icon）。
func GroupMeta(d map[string]any, cfg map[string]any) map[string]map[string]any {
	cn := map[string]bool{}
	for _, g := range data.List(d, "custom_groups") {
		if gm, ok := g.(map[string]any); ok {
			cn[data.Str(gm, "name")] = true
		}
	}
	customs := make([]string, 0, len(cn))
	for c := range cn {
		customs = append(customs, c)
	}
	meta := map[string]map[string]any{}
	for _, g := range data.List(cfg, "proxy-groups") {
		gm, _ := g.(map[string]any)
		if gm == nil {
			continue
		}
		n := data.Str(gm, "name")
		meta[n] = map[string]any{
			"kind":     GroupKind(n, customs...),
			"type":     data.Str(gm, "type"),
			"strategy": data.Str(gm, "strategy"),
			"filter":   data.Str(gm, "filter"),
			"subs":     truthy(gm["use"]),
			"icon":     data.Str(gm, "icon"),
		}
	}
	return meta
}

// truthy 对应 Python bool() 的真值判定。
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0
	case int:
		return t != 0
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	default:
		return true
	}
}

// RenamePolicy 对应 rename_policy(d, old, new)：策略组改名 / 删除（new 为节点选择）时同步更新
// 自定义规则、规则集、其他自定义组、DNS 的引用；返回受影响条目数。
func RenamePolicy(d map[string]any, old, newName string) int {
	if newName == base.GSel {
		return data.MapRefs(d, map[string]string{old: newName}, old)
	}
	return data.MapRefs(d, map[string]string{old: newName})
}
