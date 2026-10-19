// Package groups 对应 Python shunt/groups.py：策略组配置。
// 订阅节点名单缓存（provider_nodes / rev）、sing-box 订阅 outbound 去重、
// 地区分组规划（region_plan）与自定义策略组校验。
package groups

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"shunt/internal/base"
	"shunt/internal/corehttp"
	"shunt/internal/data"
	"shunt/internal/errlog"
	"shunt/internal/links"
)

// errlog.LogErr 接线
func logErr(where string, err error) { errlog.LogErr(where, err, false) }

// corehttp.CoreJSON 接线
func coreJSON(path string, timeoutSec int) map[string]any { return corehttp.CoreJSON(path, timeoutSec) }

// links.ReservedNames 接线
func reservedNames(d map[string]any) map[string]bool { return links.ReservedNames(d) }

// ActiveCoreHook 当前内核判定（对应 sb_common.active_core）。
// groups 不能 import singbox（singbox 反向依赖 groups.Gcfg 等，会循环），
// 由 singbox 包在 init 中注入；未注入时默认 "mihomo"。
var ActiveCoreHook = func() string { return "mihomo" }

// singbox.ActiveCore 接线（经 ActiveCoreHook，避免 import cycle）
func activeCore() string { return ActiveCoreHook() }

// NameBad 策略组 / 目标名禁用字符：逗号、#、换行、制表符、引号
var NameBad = regexp.MustCompile(`[,#\n\r\t"]`)

var iconRx = regexp.MustCompile(`^https?://\S{4,500}$`)

// ---------- 正则缓存 ----------

// Go RE2 不支持 Python 正则的前后断言 (?<![A-Za-z]) / (?![A-Za-z])（base.Regions 在用）。
// 只用于 search 布尔判断时可做等价改写：
// (?<![A-Za-z])X → (?:^|[^A-Za-z])X ， X(?![A-Za-z]) → X(?:$|[^A-Za-z])。
var (
	lookbehindRx = regexp.MustCompile(`\(\?<!\[A-Za-z\]\)`)
	lookaheadRx  = regexp.MustCompile(`\(\?!\[A-Za-z\]\)`)
)

func goPattern(p string) string {
	p = lookbehindRx.ReplaceAllString(p, `(?:^|[^A-Za-z])`)
	p = lookaheadRx.ReplaceAllString(p, `(?:$|[^A-Za-z])`)
	return p
}

var rxCache = struct {
	sync.Mutex
	m map[string]*regexp.Regexp
	// 编译失败记 nil：用 ok 区分"没查过"与"无效"
	ok map[string]bool
}{m: map[string]*regexp.Regexp{}, ok: map[string]bool{}}

// Rx 编译正则（缓存）；无效时返回 nil
func Rx(pattern string) *regexp.Regexp {
	rxCache.Lock()
	defer rxCache.Unlock()
	if r, found := rxCache.m[pattern]; found {
		if rxCache.ok[pattern] {
			return r
		}
		return nil
	}
	r, err := regexp.Compile(goPattern(pattern))
	if err != nil {
		rxCache.m[pattern] = nil
		rxCache.ok[pattern] = false
		return nil
	}
	rxCache.m[pattern] = r
	rxCache.ok[pattern] = true
	return r
}

// ---------- 订阅节点缓存 ----------

// NamedNode 去重后的订阅节点（名, 原始节点）
type NamedNode struct {
	Name string
	Node map[string]any
}

// SubCachePath sing-box 订阅缓存文件路径（对应 Python 的 sub_cache_path）
func SubCachePath(name string) string {
	return filepath.Join(base.PanelDir, "sb_subs", data.Safe(name)+".json")
}

// SbSubCache 读 sing-box 订阅节点缓存文件
func SbSubCache(name string) map[string]any {
	return data.ReadJSON(SubCachePath(name), map[string]any{})
}

// SbSubOutbounds {订阅名: [去重后节点]}：名称与手动节点、保留名全局去重，与生成的 sing-box 配置一致
func SbSubOutbounds(d map[string]any) map[string][]NamedNode {
	taken := map[string]bool{}
	for _, n := range data.List(d, "nodes") {
		if pm, ok := n.(map[string]any); ok {
			if pr, ok := pm["proxy"].(map[string]any); ok {
				taken[data.Str(pr, "name")] = true
			}
		}
	}
	for n := range reservedNames(d) {
		taken[n] = true
	}
	out := map[string][]NamedNode{}
	for _, s := range data.List(d, "subs") {
		sm, ok := s.(map[string]any)
		if !ok {
			continue
		}
		sname := data.Str(sm, "name")
		var lst []NamedNode
		for _, p := range data.List(SbSubCache(sname), "nodes") {
			pm, ok := p.(map[string]any)
			if !ok {
				continue
			}
			b := strings.TrimSpace(data.Str(pm, "name"))
			if b == "" {
				b = "node"
			}
			name, k := b, 2
			for taken[name] {
				name, k = fmt.Sprintf("%s (%d)", b, k), k+1
			}
			taken[name] = true
			lst = append(lst, NamedNode{Name: name, Node: pm})
		}
		out[sname] = lst
	}
	return out
}

// SbProviderNodes {订阅名: [节点名]}，名称已按全局去重（与生成的 sing-box 配置一致）
func SbProviderNodes(d map[string]any) map[string][]string {
	out := map[string][]string{}
	for k, v := range SbSubOutbounds(d) {
		names := make([]string, 0, len(v))
		for _, nn := range v {
			names = append(names, nn.Name)
		}
		out[k] = names
	}
	return out
}

var provState = struct {
	sync.Mutex
	t    float64
	data map[string][]string
	rev  int
}{}

func provFile() string { return filepath.Join(base.PanelDir, "provider_nodes.json") }

// ProviderNodes 订阅（proxy-provider）里的节点名 {订阅名: [节点名]}：
// 优先读运行中的核心，缓存到文件供核心未运行时生成配置
func ProviderNodes(fresh ...bool) map[string][]string {
	now := float64(time.Now().UnixNano()) / 1e9
	f := len(fresh) > 0 && fresh[0]
	provState.Lock()
	if !f && provState.data != nil && now-provState.t < 60 {
		d := provState.data
		provState.Unlock()
		return d
	}
	provState.Unlock()

	var pdata map[string][]string
	if activeCore() == "singbox" { // sing-box 的订阅由面板下载解析，节点名直接取缓存
		pdata = SbProviderNodes(data.Load())
		provSet(now, pdata)
		return pdata
	}
	var j map[string]any
	if os.Getenv("PANEL_OFFLINE") == "" {
		j = coreJSON("/providers/proxies", 3)
	}
	if j != nil {
		pdata = map[string][]string{}
		if provs, ok := j["providers"].(map[string]any); ok {
			for name, p := range provs {
				pm, ok := p.(map[string]any)
				if !ok {
					continue
				}
				vt, _ := pm["vehicleType"].(string)
				pl, hasPl := pm["proxies"]
				if (vt == "HTTP" || vt == "File" || vt == "Inline") && hasPl && pl != nil {
					var lst []string
					if arr, ok := pl.([]any); ok {
						for _, x := range arr {
							if xm, ok := x.(map[string]any); ok {
								if n, _ := xm["name"].(string); n != "" {
									lst = append(lst, n)
								}
							}
						}
					}
					pdata[name] = lst
				}
			}
		}
		if old := data.ReadJSON(provFile(), map[string][]string(nil)); !strMapEqual(pdata, old) {
			if err := data.WriteJSON(provFile(), pdata); err != nil {
				logErr("保存订阅节点列表", err)
			}
		}
	}
	if pdata == nil {
		pdata = data.ReadJSON(provFile(), map[string][]string{})
	}
	provSet(now, pdata)
	return pdata
}

func provSet(now float64, d map[string][]string) {
	provState.Lock()
	defer provState.Unlock()
	if provState.data != nil && !strMapEqual(d, provState.data) {
		provState.rev++
	}
	provState.t = now
	provState.data = d
}

// ProvUpdate 对应 PROV.update(...)：build_singbox 传 {订阅名: [节点名]} 刷新缓存；
// 传 nil（对应 Python 的 t=0, data=None）使缓存失效，下次读取时重新抓取。
func ProvUpdate(data map[string][]string) {
	if data == nil {
		provState.Lock()
		provState.t = 0
		provState.data = nil
		provState.Unlock()
		return
	}
	provSet(float64(time.Now().UnixNano())/1e9, data)
}

// ProviderRev 订阅节点名单的版本：节点增删 / 改名后变化
func ProviderRev() int {
	provState.Lock()
	defer provState.Unlock()
	return provState.rev
}

// ---------- 分组配置 ----------

// Gcfg 地区分组配置：GROUPS_DEFAULT 叠加 data.json 的 groups_cfg；
// v6 起地区「自动优选」组固定 url-test、负载均衡只支持一致性哈希
func Gcfg(d map[string]any) map[string]any {
	gc := map[string]any{}
	for k, v := range base.GroupsDefault {
		gc[k] = v
	}
	for k, v := range data.Map(d, "groups_cfg") {
		if _, ok := base.GroupsDefault[k]; ok {
			gc[k] = v
		}
	}
	gc["type"] = "url-test"
	gc["strategy"] = "consistent-hashing"
	return gc
}

// GroupOpts 各类型策略组的公共参数
func GroupOpts(t string, gc map[string]any, extra ...map[string]any) map[string]any {
	var e map[string]any
	if len(extra) > 0 && extra[0] != nil {
		e = extra[0]
	}
	g := map[string]any{"type": t}
	if t != "select" {
		u := strOf(e["url"])
		if u == "" {
			u = data.Str(gc, "url")
		}
		iv := data.Int(e, "interval")
		if iv == 0 {
			iv = data.Int(gc, "interval")
		}
		g["url"] = u
		g["interval"] = iv
		g["lazy"] = data.Bool(gc, "lazy")
		if t == "url-test" || t == "smart" {
			tol := data.Int(gc, "tolerance")
			if tv, ok := e["tolerance"]; ok && tv != nil && tv != "" {
				tol = toInt(tv)
			}
			g["tolerance"] = tol
		}
		if t == "load-balance" {
			g["strategy"] = "consistent-hashing"
		}
		if t == "smart" { // Smart 内核：按延迟 / 丢包 / 速度综合打分，可用 LightGBM 模型预测权重
			g["uselightgbm"] = data.Bool(gc, "lgbm")
			g["collectdata"] = false
		}
	}
	return g
}

// RegionEntry region_plan 的一行：(地区名, 正则, exclude 正则, 手动节点, 节点总数, 是否未知)
type RegionEntry struct {
	Name    string   `json:"name"`
	Filter  string   `json:"filter"`
	Exclude string   `json:"exclude"`
	Manual  []string `json:"manual"`
	Total   int      `json:"total"`
	Unknown bool     `json:"unknown"`
}

// RegionPlan 返回确实有节点的地区规划；只保留有节点的地区
func RegionPlan(d map[string]any, names []string, use bool) []RegionEntry {
	regionGroups := true
	if v, ok := d["region_groups"]; ok {
		regionGroups, _ = v.(bool)
	}
	if !(use || len(names) > 0) || !regionGroups {
		return []RegionEntry{}
	}
	gc := Gcfg(d)
	pn := map[string][]string{}
	if use {
		pn = ProviderNodes()
	}
	var subs []string
	for _, s := range data.List(d, "subs") {
		if sm, ok := s.(map[string]any); ok {
			subs = append(subs, data.Str(sm, "name"))
		}
	}
	unknown := false
	for _, s := range subs {
		if _, ok := pn[s]; !ok {
			unknown = true
			break
		}
	}
	var pnames []string
	for _, s := range subs {
		pnames = append(pnames, pn[s]...)
	}
	regs := base.Regions
	if !data.Bool(gc, "extra") {
		regs = base.Regions[:base.PrimaryRegions]
	}
	out := []RegionEntry{}
	for i, r := range regs {
		rx := Rx(r.Pattern)
		var matched []string
		total := 0
		if rx != nil {
			for _, n := range names {
				if rx.MatchString(n) {
					matched = append(matched, n)
					total++
				}
			}
			for _, n := range pnames {
				if rx.MatchString(n) {
					total++
				}
			}
		}
		if total > 0 || (unknown && i < base.PrimaryRegions) { // 订阅还没加载过：沿用旧行为，先生成 5 个常用地区
			out = append(out, RegionEntry{Name: r.Name, Filter: r.Pattern, Manual: matched, Total: total, Unknown: unknown})
		}
	}
	if data.Bool(gc, "other") {
		alls := make([]*regexp.Regexp, 0, len(regs))
		for _, r := range regs {
			alls = append(alls, Rx(r.Pattern))
		}
		hitAny := func(n string) bool {
			for _, r := range alls {
				if r != nil && r.MatchString(n) {
					return true
				}
			}
			return false
		}
		var matched []string
		total := 0
		for _, n := range names {
			if !hitAny(n) {
				matched = append(matched, n)
				total++
			}
		}
		for _, n := range pnames {
			if !hitAny(n) {
				total++
			}
		}
		if total > 0 {
			pats := make([]string, 0, len(regs))
			for _, r := range regs {
				pats = append(pats, r.Pattern)
			}
			out = append(out, RegionEntry{Name: base.GOther, Exclude: strings.Join(pats, "|"), Manual: matched, Total: total, Unknown: unknown})
		}
	}
	return out
}

// AllNodeNames 手动节点 + 已知订阅节点
func AllNodeNames(d map[string]any) []string {
	pn := map[string][]string{}
	if len(data.List(d, "subs")) > 0 {
		pn = ProviderNodes()
	}
	var out []string
	for _, n := range data.List(d, "nodes") {
		if pm, ok := n.(map[string]any); ok {
			if pr, ok := pm["proxy"].(map[string]any); ok {
				out = append(out, data.Str(pr, "name"))
			}
		}
	}
	for _, s := range data.List(d, "subs") {
		if sm, ok := s.(map[string]any); ok {
			out = append(out, pn[data.Str(sm, "name")]...)
		}
	}
	return out
}

// CleanCustomGroup 校验并规范化一个自定义策略组（不含引用检查）
func CleanCustomGroup(b map[string]any) (map[string]any, error) {
	fail := func(msg string) (map[string]any, error) { return nil, errors.New(msg) }
	name := strings.TrimSpace(data.Str(b, "name"))
	if name == "" || len([]rune(name)) > 40 || NameBad.MatchString(name) {
		return fail("名称不能为空、不超过 40 字，且不能包含逗号、# 或引号")
	}
	t := data.Str(b, "type")
	if t == "" {
		t = "select"
	}
	valid := false
	for _, gt := range base.GroupTypes {
		if t == gt {
			valid = true
			break
		}
	}
	if !valid {
		return fail("类型只能是 select / url-test / fallback / load-balance")
	}
	members := []string{}
	for _, m := range data.List(b, "proxies") {
		s := strings.TrimSpace(strOf(m))
		if s == "" || containsStr(members, s) {
			continue
		}
		members = append(members, s)
	}
	flt := strings.TrimSpace(data.Str(b, "filter"))
	if flt != "" && Rx(flt) == nil {
		return fail("筛选正则无效：" + flt)
	}
	if len(members) == 0 && flt == "" {
		return fail("请至少选择一个成员，或填写筛选正则")
	}
	icon := strings.TrimSpace(data.Str(b, "icon"))
	if icon != "" && !iconRx.MatchString(icon) {
		return fail("图标必须是 http(s) 图片地址")
	}
	subs := true
	if v, ok := b["subs"]; ok {
		subs, _ = v.(bool)
	}
	expose := true
	if v, ok := b["expose"]; ok {
		expose, _ = v.(bool)
	}
	g := map[string]any{
		"name": name, "type": t, "proxies": members, "filter": flt,
		"subs": subs, "expose": expose, "icon": icon,
	}
	if t != "select" {
		iv, ok1 := toIntOk(b["interval"])
		tol, ok2 := toIntOk(b["tolerance"])
		if !ok1 || !ok2 {
			return fail("测速间隔 / 容差必须是数字")
		}
		if iv != 0 && (iv < 30 || iv > 86400) {
			return fail("测速间隔应在 30–86400 秒之间")
		}
		if tol < 0 || tol > 1000 {
			return fail("容差应在 0–1000 ms 之间")
		}
		g["interval"] = iv
		g["tolerance"] = tol
		if t == "load-balance" {
			g["strategy"] = "consistent-hashing" // 只支持一致性哈希
		}
	}
	return g, nil
}

// ---------- 小助手 ----------

func strOf(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func strMapEqual(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok || len(va) != len(vb) {
			return false
		}
		for i := range va {
			if va[i] != vb[i] {
				return false
			}
		}
	}
	return true
}

// toIntOk Python int(v or 0) 语义：nil/"" /0 → (0, true)；不可转 → (0, false)
func toIntOk(v any) (int, bool) {
	if v == nil {
		return 0, true
	}
	switch x := v.(type) {
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case int:
		return x, true
	case int64:
		return int(x), true
	case float64:
		return int(x), true
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return 0, true
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

func toInt(v any) int {
	n, _ := toIntOk(v)
	return n
}
