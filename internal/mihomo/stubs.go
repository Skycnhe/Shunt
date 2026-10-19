package mihomo

import (
	"shunt/internal/coreupdate"
	"shunt/internal/devroute"
	"shunt/internal/groups"
	"shunt/internal/sysopt"
)

// 本文件收拢跨包调用接线：被调用的函数属于其他包（sysopt/devroute/groups）。
// 为可测试性保留包级 func 变量形式：默认实现直接转调真实函数，测试中可临时替换（defer 恢复）。
//
// 反向依赖（sb_common.active_core）经 ActiveCoreHook 注入：mihomo 不能 import
// singbox（singbox 反向依赖 mihomo.BuildConfig 等），由 singbox 包在 init 中赋值。

// regionPlanItem 对应 groups.region_plan(d, names, use) 返回的元组：
// (地区名, 过滤正则或 "", exclude 正则或 "", 手动匹配节点, 节点总数, 是否有未知订阅节点)
type regionPlanItem struct {
	Rname   string
	Flt     string
	Exc     string
	Matched []string
	Total   int
	Unknown bool
}

// ActiveCoreHook 当前内核判定（对应 sb_common.active_core）；由 singbox 包在 init 中注入，
// 未注入时默认 "mihomo"。
var ActiveCoreHook = func(d map[string]any) string { return "mihomo" }

// activeCore 对应 sb_common.active_core（经 ActiveCoreHook 接线）
var activeCore = func(d map[string]any) string { return ActiveCoreHook(d) }

// shRun 对应 sysopt.sh
var shRun = func(cmd string, timeoutSec int) (int, string) { return sysopt.Sh(cmd, timeoutSec) }

// deviceRouteRules 对应 devroute.device_route_rules
var deviceRouteRules = func(d map[string]any, policies map[string]bool) []string {
	list := make([]string, 0, len(policies))
	for p := range policies {
		list = append(list, p)
	}
	return devroute.DeviceRouteRules(d, list)
}

// markApplied 对应 devroute.mark_applied
var markApplied = devroute.MarkApplied

// cleanCustomGroup 对应 groups.clean_custom_group
var cleanCustomGroup = groups.CleanCustomGroup

// gcfg 对应 groups.gcfg
var gcfg = groups.Gcfg

// groupOpts 对应 groups.group_opts
var groupOpts = func(typ string, gc map[string]any, extra map[string]any) map[string]any {
	return groups.GroupOpts(typ, gc, extra)
}

// regionPlan 对应 groups.region_plan
var regionPlan = func(d map[string]any, names []string, use []string) []regionPlanItem {
	out := []regionPlanItem{}
	for _, e := range groups.RegionPlan(d, names, len(use) > 0) {
		out = append(out, regionPlanItem{
			Rname:   e.Name,
			Flt:     e.Filter,
			Exc:     e.Exclude,
			Matched: e.Manual,
			Total:   e.Total,
			Unknown: e.Unknown,
		})
	}
	return out
}

// rxCompile 对应 groups.rx — 编译正则（缓存）；无效时返回 nil
var rxCompile = groups.Rx

// 注：core 曾通过本文件的 init 经 core.SetMihomoHooks 反向注入，
// 但 core→notify→singbox→mihomo 已形成环路，该 init 会导致 import cycle。
// 现改由 core/stubs.go 直接 import mihomo 接线（与 Python 的 from .mihomo import 一致），
// 此处不再注入。

// coreupdate 需要 mihomo 的 mh_bin / write_config，但不能反向导入 mihomo
// （coreupdate→mihomo→devroute→stats→core→coreupdate 成环），
// 故由本文件的 init 经 coreupdate.SetMihomoHooks 注入（mihomo→coreupdate 无环）。
func init() {
	coreupdate.SetMihomoHooks(coreupdate.MihomoHooks{
		MhBin: func(kind string) string { return MhBin(kind) },
		WriteConfig: func(d map[string]any, path string) (string, error) {
			return WriteConfig(d, path)
		},
	})
}
