// Package migrate 对应 Python shunt/migrate.py：v5 → v6 升级，保留节点选择。
package migrate

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"shunt/internal/base"
	"shunt/internal/core"
	"shunt/internal/corehttp"
	"shunt/internal/data"
	"shunt/internal/notify"
	"shunt/internal/singbox"
)

// 把本包实现注入 core（core 不能反向导入 migrate，会循环引用；
// 模式与 latency.go 的 core.SetRetestSoon(RetestSoon) 一致）。
func init() {
	core.SetSnapshotSelections(SnapshotSelections)
	core.SetRestoreSelections(RestoreSelections)
}

// STUB:core.ReloadCore —— 接线到 core.ReloadCore（prev=nil：迁移场景无回滚基线）
func reloadCore() (bool, string) { return core.ReloadCore(nil) }

// STUB:sb_common.ActiveCore —— 接线到 singbox.ActiveCore
func activeCore(d map[string]any) string { return singbox.ActiveCore(d) }

// SelFile 对应 SEL_FILE
var SelFile = filepath.Join(base.PanelDir, "selected.json")

// SnapshotSelections 对应 snapshot_selections(force)：记录各手动选择组当前选中的节点 / 分组。
// 文件已存在且非 force 时返回 nil（调用方可据此打印 skip）。
func SnapshotSelections(force bool) map[string]any {
	if !force {
		if _, err := os.Stat(SelFile); err == nil {
			return nil
		}
	}
	j := corehttp.CoreJSON("/proxies", 5)
	if j == nil {
		return nil
	}
	proxies, _ := j["proxies"].(map[string]any)
	sel := map[string]any{}
	for n, p := range proxies {
		pm, _ := p.(map[string]any)
		if pm == nil {
			continue
		}
		if data.Str(pm, "type") == "Selector" && data.Str(pm, "now") != "" && n != "GLOBAL" {
			sel[n] = pm["now"]
		}
	}
	_ = data.WriteJSON(SelFile, sel)
	return sel
}

// RestoreSelections 对应 restore_selections()：按新名称恢复升级前的选择；返回恢复的组数。
func RestoreSelections() int {
	sel := data.ReadJSON(SelFile, map[string]any(nil))
	if len(sel) == 0 {
		return 0
	}
	mp := data.LegacyMap()
	proxies := map[string]any{}
	if j := corehttp.CoreJSON("/proxies", 5); j != nil {
		proxies, _ = j["proxies"].(map[string]any)
		if proxies == nil {
			proxies = map[string]any{}
		}
	}
	n := 0
	for g, now := range sel {
		nowStr, _ := now.(string)
		g2 := mapName(mp, g)
		now2 := mapName(mp, nowStr)
		p, _ := proxies[g2].(map[string]any)
		if p == nil || data.Str(p, "type") != "Selector" {
			continue
		}
		inAll := false
		for _, a := range data.List(p, "all") {
			if s, ok := a.(string); ok && s == now2 {
				inAll = true
				break
			}
		}
		if inAll && data.Str(p, "now") != now2 {
			if code, _ := corehttp.Core("PUT", "/proxies/"+url.PathEscape(g2), map[string]any{"name": now2}, 10); code < 300 {
				n++
			}
		}
	}
	_ = os.Remove(SelFile)
	fmt.Printf("%s [upgrade] 已按新名称恢复 %d 个策略组的选择\n", time.Now().Format("2006-01-02 15:04:05"), n)
	return n
}

func mapName(mp map[string]string, name string) string {
	if v, ok := mp[name]; ok && v != "" {
		return v
	}
	return name
}

// StartupMigrate 对应 startup_migrate()：面板升级后首次启动，核心还在跑旧配置（旧组名）时，
// 先记下选择，再生成新配置并恢复选择。
func StartupMigrate() {
	alive := false
	for i := 0; i < 30; i++ {
		if notify.CoreAlive() {
			alive = true
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !alive {
		return
	}
	var cur map[string]any
	if activeCore(nil) == "singbox" {
		cur = map[string]any{}
	} else {
		cur = data.ReadJSON(filepath.Join(base.ConfDir, "config.yaml"), map[string]any(nil))
		if cur == nil {
			cur = map[string]any{}
		}
	}
	old := map[string]bool{}
	for k := range data.LegacyMap() {
		old[k] = true
	}
	need := false
	for _, g := range data.List(cur, "proxy-groups") {
		if gm, ok := g.(map[string]any); ok && old[data.Str(gm, "name")] {
			need = true
			break
		}
	}
	if need {
		SnapshotSelections(false)
		ok, msg := reloadCore()
		fmt.Printf("%s [upgrade] 已按新版策略组重新生成配置： %v %s\n",
			time.Now().Format("2006-01-02 15:04:05"), ok, tailRunes(msg, 120))
		time.Sleep(time.Second)
	}
	if _, err := os.Stat(SelFile); err == nil {
		RestoreSelections()
	}
}

func tailRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[len(r)-n:]
	}
	return string(r)
}
