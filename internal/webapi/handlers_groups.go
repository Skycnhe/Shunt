package webapi

// 对应 Python shunt/webapi.py：/api/groups 系列（查询、配置、自定义组增删、预览、刷新地区组）。

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"shunt/internal/base"
	"shunt/internal/core"
	"shunt/internal/coreupdate"
	"shunt/internal/data"
	"shunt/internal/groups"
	"shunt/internal/links"
	"shunt/internal/mihomo"
	"shunt/internal/singbox"
	"shunt/internal/updateguard"
)

func registerGroupRoutes() {
	Route("GET", "/api/groups", apiGroupsGet)
	Route("PUT", "/api/groups/cfg", apiGroupsCfgPut)
	Route("POST", "/api/groups", apiGroupsPost)
	Route("DELETE", "/api/groups", apiGroupsDelete)
	Route("POST", "/api/groups/preview", apiGroupsPreviewPost)
	Route("POST", "/api/groups/refresh", apiGroupsRefreshPost)
}

var httpURLRe = regexp.MustCompile(`^https?://\S+$`)

// ---------- validate_groups（对应 webapi.py 的 validate_groups + find_cycle） ----------

// findCycle 策略组之间的循环引用，返回环路径或 nil。
func findCycle(gs []any) []string {
	gmap := map[string][]string{}
	order := []string{}
	for _, x := range gs {
		gm, _ := x.(map[string]any)
		if gm == nil {
			continue
		}
		n := data.Str(gm, "name")
		order = append(order, n)
		gmap[n] = data.Strs(gm, "proxies")
	}
	state := map[string]int{}
	var stack []string
	var dfs func(n string) []string
	dfs = func(n string) []string {
		state[n] = 1
		stack = append(stack, n)
		for _, m := range gmap[n] {
			if _, ok := gmap[m]; !ok {
				continue
			}
			if state[m] == 1 {
				idx := 0
				for i, s := range stack {
					if s == m {
						idx = i
						break
					}
				}
				return append(append([]string{}, stack[idx:]...), m)
			}
			if state[m] == 0 {
				if c := dfs(m); c != nil {
					return c
				}
			}
		}
		state[n] = 2
		stack = stack[:len(stack)-1]
		return nil
	}
	for _, n := range order {
		if state[n] == 0 {
			if c := dfs(n); c != nil {
				return c
			}
		}
	}
	return nil
}

// validateGroups 生成配置后检查自定义组：重名、成员不存在、循环引用。
func validateGroups(d map[string]any) []string {
	var errs []string
	nodes := map[string]bool{}
	for _, n := range groups.AllNodeNames(d) {
		nodes[n] = true
	}
	fixed := links.ReservedNames(nil)
	seen := map[string]bool{}
	for _, x := range data.List(d, "custom_groups") {
		xm, _ := x.(map[string]any)
		if xm == nil {
			continue
		}
		n := data.Str(xm, "name")
		if seen[n] {
			errs = append(errs, "策略组重名："+n)
		}
		if fixed[n] {
			errs = append(errs, "「"+n+"」与内置策略组或策略同名")
		}
		if nodes[n] {
			errs = append(errs, "「"+n+"」与节点同名")
		}
		seen[n] = true
	}
	cfg := mihomo.BuildConfig(d, true)
	names := map[string]bool{}
	for _, g := range data.List(cfg, "proxy-groups") {
		if gm, ok := g.(map[string]any); ok {
			names[data.Str(gm, "name")] = true
		}
	}
	for p := range base.BuiltinPolicies {
		names[p] = true
	}
	for _, p := range data.List(cfg, "proxies") {
		if pm, ok := p.(map[string]any); ok {
			names[data.Str(pm, "name")] = true
		}
	}
	for _, x := range data.List(d, "custom_groups") {
		xm, _ := x.(map[string]any)
		if xm == nil {
			continue
		}
		cn := data.Str(xm, "name")
		members := data.Strs(xm, "proxies")
		var miss []string
		for _, m := range members {
			if !names[m] {
				miss = append(miss, m)
			}
		}
		if len(miss) > 0 {
			if len(miss) > 5 {
				miss = miss[:5]
			}
			errs = append(errs, "「"+cn+"」的成员不存在："+strings.Join(miss, "、"))
		}
		for _, m := range members {
			if m == cn {
				errs = append(errs, "「"+cn+"」不能包含自己")
				break
			}
		}
	}
	if cyc := findCycle(data.List(cfg, "proxy-groups")); len(cyc) > 0 {
		errs = append(errs, "策略组循环引用："+strings.Join(cyc, " → ")+
			"（加入分流组候选的自定义组不能再引用 YouTube / Google 等分流组，可关闭“加入分流组候选”）")
	}
	return errs
}

// ---------- GET /api/groups ----------

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func apiGroupsGet(c *Ctx) (int, any) {
	d := data.Load()
	cfg := mihomo.BuildConfig(d)
	names := []string{}
	for _, p := range data.List(cfg, "proxies") {
		if pm, ok := p.(map[string]any); ok {
			names = append(names, data.Str(pm, "name"))
		}
	}
	plan := groups.RegionPlan(d, names, len(data.Map(cfg, "proxy-providers")) > 0)
	gnames := []string{}
	for _, g := range data.List(cfg, "proxy-groups") {
		if gm, ok := g.(map[string]any); ok {
			gnames = append(gnames, data.Str(gm, "name"))
		}
	}
	meta := updateguard.GroupMeta(d, cfg)
	sb := singbox.ActiveCore(d) == "singbox"
	if sb {
		gnames = sbGroupView(gnames, meta)
	}
	regions := make([]map[string]any, 0, len(plan))
	for _, r := range plan {
		gs := []string{}
		auto := data.AutoName(r.Name)
		lbs := data.LbNames(r.Name)
		for _, g := range gnames {
			if g == auto || containsStr(lbs, g) {
				gs = append(gs, g)
			}
		}
		regions = append(regions, map[string]any{
			"name": r.Name, "total": r.Total, "manual": len(r.Manual), "unknown": r.Unknown, "groups": gs,
		})
	}
	sel := []string{}
	for _, g := range data.List(cfg, "proxy-groups") {
		gm, ok := g.(map[string]any)
		if !ok || data.Str(gm, "name") != base.GSel {
			continue
		}
		for _, p := range data.List(gm, "proxies") {
			if s, ok := p.(string); ok {
				sel = append(sel, s)
			}
		}
		break
	}
	if sb {
		gset := map[string]bool{}
		for _, g := range gnames {
			gset[g] = true
		}
		keep := []string{}
		for _, x := range sel {
			if gset[x] || base.BuiltinPolicies[x] {
				keep = append(keep, x)
			}
		}
		sel = keep
	}
	rnames := make([]string, 0, len(base.Regions))
	for _, r := range base.Regions {
		rnames = append(rnames, r.Name)
	}
	return c.Send(200, map[string]any{
		"cfg": groups.Gcfg(d), "region_groups": d["region_groups"], "custom": d["custom_groups"],
		"regions": regions, "groups": gnames, "manual": names, "nodes": groups.AllNodeNames(d),
		"meta": meta, "core": singbox.ActiveCore(d), "types": base.GroupTypes, "strategies": base.LbStrategies,
		"region_names": rnames, "primary": base.PrimaryRegions, "selector": sel,
	})
}

// ---------- PUT /api/groups/cfg ----------

// parseCfgInt 对应 Python int(b["interval"])：JSON 数字截断取整，字符串去空白后解析。
func parseCfgInt(v any) (int, bool) {
	switch t := v.(type) {
	case float64:
		return int(t), true
	case float32:
		return int(t), true
	case int:
		return t, true
	case int64:
		return int(t), true
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

func apiGroupsCfgPut(c *Ctx) (int, any) {
	gc := groups.Gcfg(data.Load())
	for _, k := range []string{"lb", "extra", "other", "lazy", "lgbm"} {
		if v, ok := c.Body[k]; ok {
			gc[k] = toBool(v)
		}
	}
	for _, k := range []string{"interval", "tolerance"} {
		if v, ok := c.Body[k]; ok {
			n, good := parseCfgInt(v)
			if !good {
				return c.Send(400, map[string]any{"message": "测速间隔 / 容差必须是数字"})
			}
			gc[k] = n
		}
	}
	interval, _ := parseCfgInt(gc["interval"])
	tolerance, _ := parseCfgInt(gc["tolerance"])
	if interval < 30 || interval > 86400 {
		return c.Send(400, map[string]any{"message": "测速间隔应在 30–86400 秒之间"})
	}
	if tolerance < 0 || tolerance > 1000 {
		return c.Send(400, map[string]any{"message": "容差应在 0–1000 ms 之间"})
	}
	if _, ok := c.Body["url"]; ok {
		u := strings.TrimSpace(c.BodyStr("url"))
		if !httpURLRe.MatchString(u) {
			return c.Send(400, map[string]any{"message": "测速地址必须是 http(s) 链接"})
		}
		gc["url"] = u
	}

	fn := func(d map[string]any) {
		d["groups_cfg"] = gc
		if v, ok := c.Body["region_groups"]; ok {
			d["region_groups"] = toBool(v)
		}
	}
	test := data.Load()
	fn(test)
	if errs := validateGroups(test); len(errs) > 0 {
		if len(errs) > 3 {
			errs = errs[:3]
		}
		return c.Send(400, map[string]any{"message": strings.Join(errs, "；")})
	}
	prev := data.Update(fn)
	ok, msg := core.ReloadCore(prev)
	if ok && toBool(gc["lgbm"]) && singbox.ActiveCore(data.Load()) == "smart" {
		if _, err := os.Stat(coreupdate.LgbmFile); err != nil {
			go coreupdate.LgbmFetchReload()
			msg = "策略组设置已生效，LightGBM 模型正在后台下载，下载完会自动重载"
		}
	}
	if ok {
		return c.Reply(true, "策略组设置已生效")
	}
	return c.Reply(false, msg)
}

// ---------- POST /api/groups（新建 / 编辑自定义组） ----------

func customGroupByName(d map[string]any, name string) bool {
	for _, x := range data.List(d, "custom_groups") {
		if xm, ok := x.(map[string]any); ok && data.Str(xm, "name") == name {
			return true
		}
	}
	return false
}

func apiGroupsPost(c *Ctx) (int, any) {
	g, err := groups.CleanCustomGroup(c.Body)
	if err != nil {
		return c.Send(400, map[string]any{"message": err.Error()})
	}
	orig := strings.TrimSpace(c.BodyStr("orig"))
	gname := data.Str(g, "name")
	cur := data.Load()
	if orig != "" && !customGroupByName(cur, orig) {
		return c.Send(404, map[string]any{"message": "策略组不存在：" + orig})
	}
	if gname != orig && customGroupByName(cur, gname) {
		return c.Send(400, map[string]any{"message": "已存在同名策略组：" + gname})
	}
	refs := 0
	fn := func(d map[string]any) {
		if orig != "" {
			lst := data.List(d, "custom_groups")
			for i, x := range lst {
				if xm, ok := x.(map[string]any); ok && data.Str(xm, "name") == orig {
					lst[i] = g
				}
			}
			d["custom_groups"] = lst
			if gname != orig {
				refs = updateguard.RenamePolicy(d, orig, gname)
			}
		} else {
			d["custom_groups"] = append(data.List(d, "custom_groups"), g)
		}
	}
	test := data.Load()
	fn(test)
	if errs := validateGroups(test); len(errs) > 0 {
		if len(errs) > 3 {
			errs = errs[:3]
		}
		return c.Send(400, map[string]any{"message": strings.Join(errs, "；")})
	}
	prev := data.Update(fn)
	ok, msg := core.ReloadCore(prev)
	if !ok {
		return c.Send(500, map[string]any{"message": msg})
	}
	extra := ""
	if refs > 0 {
		extra = fmt.Sprintf("，已同步更新 %d 处引用", refs)
	}
	verb := "已创建策略组 "
	if orig != "" {
		verb = "已保存策略组 "
	}
	return c.Send(200, map[string]any{"message": verb + gname + extra})
}

// ---------- DELETE /api/groups ----------

func apiGroupsDelete(c *Ctx) (int, any) {
	name := c.BodyStr("name")
	cur := data.Load()
	if !customGroupByName(cur, name) {
		return c.Send(404, map[string]any{"message": "策略组不存在：" + name})
	}
	users := []string{}
	for _, x := range data.List(cur, "custom_groups") {
		xm, ok := x.(map[string]any)
		if !ok {
			continue
		}
		if containsStr(data.Strs(xm, "proxies"), name) {
			users = append(users, data.Str(xm, "name"))
		}
	}
	if len(users) > 0 && !toBool(c.Body["force"]) {
		return c.Send(409, map[string]any{
			"message": fmt.Sprintf("「%s」被其他策略组引用：%s。确认删除会同时从这些组中移除它", name, strings.Join(users, "、")),
			"users":   users,
		})
	}
	refs := 0
	fn := func(d map[string]any) {
		kept := []any{}
		for _, x := range data.List(d, "custom_groups") {
			if xm, ok := x.(map[string]any); ok && data.Str(xm, "name") == name {
				continue
			}
			kept = append(kept, x)
		}
		d["custom_groups"] = kept
		refs = updateguard.RenamePolicy(d, name, base.GSel)
	}
	prev := data.Update(fn)
	ok, msg := core.ReloadCore(prev)
	if !ok {
		return c.Send(500, map[string]any{"message": msg})
	}
	extra := ""
	if refs > 0 {
		extra = fmt.Sprintf("，%d 处引用已改为「%s」", refs, base.GSel)
	}
	return c.Send(200, map[string]any{"message": "已删除 " + name + extra})
}

// ---------- POST /api/groups/preview ----------

func apiGroupsPreviewPost(c *Ctx) (int, any) {
	flt := strings.TrimSpace(c.BodyStr("filter"))
	if flt == "" {
		return c.Send(200, map[string]any{"matched": []any{}, "total": 0})
	}
	r := groups.Rx(flt)
	if r == nil {
		return c.Send(400, map[string]any{"message": "正则无效"})
	}
	d := data.Load()
	manual := []string{}
	for _, n := range data.List(d, "nodes") {
		if nm, ok := n.(map[string]any); ok {
			if px, ok := nm["proxy"].(map[string]any); ok {
				manual = append(manual, data.Str(px, "name"))
			}
		}
	}
	allnodes := manual
	useSubs := true
	if v, ok := c.Body["subs"]; ok {
		useSubs = toBool(v)
	}
	if useSubs {
		allnodes = groups.AllNodeNames(d)
	}
	hit := []string{}
	for _, n := range allnodes {
		if r.MatchString(n) {
			hit = append(hit, n)
		}
	}
	matched := hit
	if len(matched) > 200 {
		matched = matched[:200]
	}
	return c.Send(200, map[string]any{"matched": matched, "total": len(hit), "of": len(allnodes)})
}

// ---------- POST /api/groups/refresh ----------

func apiGroupsRefreshPost(c *Ctx) (int, any) {
	return c.Reply(core.RefreshRegions())
}
