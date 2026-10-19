package singbox

// sb_config.py：生成 sing-box 配置。build_singbox 把 mihomo 结构翻译成 sing-box 配置。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"shunt/internal/base"
	"shunt/internal/data"
	"shunt/internal/ruleutil"
)

// BuildSingbox 把 build_config 生成的 mihomo 结构翻译成 sing-box 配置；
// 返回 (配置, 警告列表, 需要的规则集文件)
func BuildSingbox(d map[string]any) (map[string]any, []string, map[string]any) {
	subOut := stubSbSubOutbounds(d)
	provData := map[string][]string{}
	for k, v := range subOut {
		names := []string{}
		for _, sn := range v {
			names = append(names, sn.Name)
		}
		provData[k] = names
	}
	stubProvUpdate(provData)
	cfg := stubBuildConfig(d)
	v6 := data.Bool(d, "ipv6")
	gc := stubGcfg(d)
	warn := []string{}
	outbounds, nodeNames, provNames := SbNodeOutbounds(d, cfg, subOut, &warn)
	alias, groupOuts := SbGroupOutbounds(cfg, gc, nodeNames, provNames, &warn)
	outbounds = append(outbounds, groupOuts...)
	var groupOut, rest []map[string]any
	for _, o := range outbounds {
		if t := data.Str(o, "type"); t == "selector" || t == "urltest" {
			groupOut = append(groupOut, o)
		} else {
			rest = append(rest, o)
		}
	}
	outbounds = append(append(groupOut, rest...), map[string]any{"type": "direct", "tag": "DIRECT"})
	policies := map[string]bool{}
	for _, o := range outbounds {
		policies[data.Str(o, "tag")] = true
	}
	for k := range base.BuiltinPolicies {
		policies[k] = true
	}
	inbounds := SbInbounds(d, v6)
	inTags := map[string]bool{}
	for _, ib := range inbounds {
		inTags[data.Str(ib, "tag")] = true
	}
	ruleSets := SbRuleSets(cfg, &warn)
	tr := NewSBRules(cfg, inTags, alias, ruleSets, &warn)
	// 路由规则
	var routeRules []any
	sniffer := true
	if _, ok := d["sniffer"]; ok {
		sniffer = data.Bool(d, "sniffer")
	}
	dcMode := data.Str(stubDnsCfg(d), "mode")
	if sniffer || dcMode == "fake-ip" {
		routeRules = append(routeRules, map[string]any{"action": "sniff"})
	}
	globalOut := "DIRECT"
	if policies[base.GSel] {
		globalOut = base.GSel
	}
	routeRules = append(routeRules,
		map[string]any{"inbound": []any{"dns-in"}, "action": "hijack-dns"},
		map[string]any{"protocol": []any{"dns"}, "action": "hijack-dns"},
		map[string]any{"clash_mode": "Direct", "action": "route", "outbound": "DIRECT"},
		map[string]any{"clash_mode": "Global", "action": "route", "outbound": globalOut},
	)
	resolved := false
	final := "DIRECT"
	for _, lineAny := range data.List(cfg, "rules") {
		line, _ := lineAny.(string)
		if strings.HasPrefix(strings.ToUpper(line), "MATCH,") {
			act := tr.Action(line[strings.Index(line, ",")+1:])
			if act != nil {
				if ob, ok := act["outbound"].(string); ok && ob != "" {
					final = ob
				} else {
					final = "DIRECT"
				}
			} else {
				final = "DIRECT"
			}
			continue
		}
		r, needs := tr.Rule(line)
		if r == nil {
			continue
		}
		if data.Str(r, "action") == "route" && !policies[data.Str(r, "outbound")] {
			if policies[base.GSel] {
				r["outbound"] = base.GSel
			} else {
				r["outbound"] = "DIRECT"
			}
		}
		if needs && !resolved { // 与 mihomo 一致：没有 no-resolve 的 IP 规则先解析域名再匹配
			routeRules = append(routeRules, map[string]any{"action": "resolve"})
			resolved = true
		}
		routeRules = append(routeRules, r)
	}
	dns, tNode, tDirect, tProxy := SbDNS(d, cfg, policies, tr, alias, v6)
	if resolved {
		for _, rAny := range routeRules {
			r, _ := rAny.(map[string]any)
			if r == nil || data.Str(r, "action") != "resolve" {
				continue
			}
			if tProxy != "" {
				if dcMode == "fake-ip" {
					r["server"] = tProxy
				} else {
					r["server"] = dns["final"]
				}
				r["client_subnet"] = base.CnEcs // 经代理 DNS 解析时按国内网段返回，国内 CDN 域名才能命中 GEOIP,CN 直连
			} else {
				r["server"] = tDirect
			}
		}
	}
	defs, missing := SbRuleSetDefs(ruleSets, &warn)
	routeRules = SbPruneRules(routeRules, missing)
	if dr, ok := dns["rules"].([]any); ok {
		dns["rules"] = SbPruneRules(dr, missing)
	}
	mode := map[string]string{"global": "Global", "direct": "Direct"}[data.Str(d, "mode")]
	if mode == "" {
		mode = "Rule"
	}
	routeFinal := "DIRECT"
	if policies[final] {
		routeFinal = final
	}
	conf := map[string]any{
		"log":       map[string]any{"level": "info", "timestamp": true},
		"dns":       dns,
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route": map[string]any{
			"rules": routeRules, "rule_set": defs, "final": routeFinal,
			"auto_detect_interface": true, "default_domain_resolver": tNode,
		},
		"experimental": map[string]any{
			"clash_api": map[string]any{
				"external_controller": fmt.Sprintf("%s:%d", base.CtrlHost, base.CtrlPort),
				"secret":              d["secret"],
				"default_mode":        mode,
			},
			"cache_file": map[string]any{"enabled": true, "path": filepath.Join(SBDir, "cache.db"), "store_fakeip": true},
		},
	}
	need := map[string]any{}
	for tag, rsdAny := range ruleSets {
		if rsd, ok := rsdAny.(map[string]any); ok && data.Str(rsd, "kind") == "inline" {
			continue
		}
		need[tag] = rsdAny
	}
	return conf, dedupStr(warn), need
}

// SbNodeOutbounds 手动节点与订阅节点 → (outbounds, 手动节点名, {订阅名: 节点名列表})
func SbNodeOutbounds(d, cfg map[string]any, subOut map[string][]SubNode, warn *[]string) ([]map[string]any, []string, map[string][]string) {
	var outbounds []map[string]any
	var nodeNames []string
	provNames := map[string][]string{}
	for _, pAny := range data.List(cfg, "proxies") {
		p, ok := pAny.(map[string]any)
		if !ok {
			continue
		}
		o, err := SbOutbound(p, data.Str(p, "name"))
		if err != nil {
			*warn = append(*warn, fmt.Sprintf("节点「%s」：%s，已跳过", data.Str(p, "name"), err))
			continue
		}
		outbounds = append(outbounds, o)
		nodeNames = append(nodeNames, data.Str(p, "name"))
	}
	skipped := 0
	for sname, lst := range subOut {
		var names []string
		for _, sn := range lst {
			o, err := SbOutbound(sn.Proxy, sn.Name)
			if err != nil {
				skipped++
				continue
			}
			outbounds = append(outbounds, o)
			names = append(names, sn.Name)
		}
		provNames[sname] = names
	}
	if skipped > 0 {
		*warn = append(*warn, fmt.Sprintf("订阅中有 %d 个节点的协议 sing-box 不支持（如 ssr、snell、wireguard），已跳过", skipped))
	}
	for _, sAny := range data.List(d, "subs") {
		s, _ := sAny.(map[string]any)
		if s == nil {
			continue
		}
		if data.Int(stubSbSubCache(data.Str(s, "name")), "updated") == 0 {
			*warn = append(*warn, fmt.Sprintf("订阅「%s」还没有下载过节点", data.Str(s, "name")))
		}
	}
	return outbounds, nodeNames, provNames
}

// SbGroupOutbounds 策略组：地区负载均衡与自动优选相同 → 去掉并重定向引用；其余 load-balance / fallback 改为 urltest。
// 返回 (别名表, 组 outbounds)
func SbGroupOutbounds(cfg, gc map[string]any, nodeNames []string, provNames map[string][]string, warn *[]string) (map[string]string, []map[string]any) {
	alias := map[string]string{}
	regionLb := map[string]bool{}
	regions := make([]base.Region, 0, len(base.Regions)+1)
	regions = append(regions, base.Regions...)
	regions = append(regions, base.Region{Name: base.GOther})
	for _, r := range regions {
		names := append(append(data.LbNames(r.Name), data.LbDroppedNames(r.Name)...), data.LbOldName(r.Name))
		for _, n := range names {
			alias[n] = data.AutoName(r.Name)
			regionLb[n] = true
		}
	}
	var groups []map[string]any
	for _, gAny := range data.List(cfg, "proxy-groups") {
		g, ok := gAny.(map[string]any)
		if !ok {
			continue
		}
		if regionLb[data.Str(g, "name")] {
			continue
		}
		groups = append(groups, g)
	}
	gnames := map[string]bool{}
	for _, g := range groups {
		gnames[data.Str(g, "name")] = true
	}
	for k, v := range alias {
		if !gnames[v] {
			delete(alias, k)
		}
	}
	var lbCustom []string
	for _, g := range groups {
		if t := data.Str(g, "type"); t == "load-balance" || t == "fallback" {
			lbCustom = append(lbCustom, data.Str(g, "name"))
		}
	}
	if len(lbCustom) > 0 {
		show, suffix := lbCustom, ""
		if len(show) > 6 {
			show, suffix = show[:6], "…"
		}
		*warn = append(*warn, "sing-box 没有负载均衡 / 故障转移组，已按自动测速运行："+strings.Join(show, "、")+suffix)
	}
	known := map[string]bool{}
	for _, n := range nodeNames {
		known[n] = true
	}
	for _, v := range provNames {
		for _, n := range v {
			known[n] = true
		}
	}
	for n := range gnames {
		known[n] = true
	}
	var outbounds []map[string]any
	for _, g := range groups {
		gname := data.Str(g, "name")
		var members []string
		inMembers := map[string]bool{}
		for _, mAny := range data.List(g, "proxies") {
			m, _ := mAny.(string)
			if a, ok := alias[m]; ok {
				m = a
			}
			if m == "REJECT" || m == "REJECT-DROP" || m == "PASS" {
				continue
			}
			if m == "COMPATIBLE" {
				m = "DIRECT"
			}
			if (known[m] || m == "DIRECT") && m != gname && !inMembers[m] {
				members = append(members, m)
				inMembers[m] = true
			}
		}
		if use := data.List(g, "use"); len(use) > 0 {
			var pool []string
			for _, uAny := range use {
				if u, ok := uAny.(string); ok {
					pool = append(pool, provNames[u]...)
				}
			}
			var rf, rex *regexp.Regexp
			if f := data.Str(g, "filter"); f != "" {
				rf = stubRx(f)
			}
			if ex := data.Str(g, "exclude-filter"); ex != "" {
				rex = stubRx(ex)
			}
			for _, n := range pool {
				if rf != nil && !rf.MatchString(n) {
					continue
				}
				if rex != nil && rex.MatchString(n) {
					continue
				}
				if !inMembers[n] {
					members = append(members, n)
					inMembers[n] = true
				}
			}
		}
		if len(members) == 0 {
			members = []string{"DIRECT"}
		}
		if data.Str(g, "type") == "select" {
			outbounds = append(outbounds, map[string]any{
				"type": "selector", "tag": gname, "outbounds": members,
				"interrupt_exist_connections": false,
			})
		} else {
			iv := data.Int(g, "interval")
			if iv == 0 {
				iv = data.Int(gc, "interval")
			}
			if iv < 30 {
				iv = 30
			}
			tol := data.Int(gc, "tolerance")
			if v, ok := g["tolerance"]; ok && v != nil {
				tol = toInt(v)
			}
			u := data.Str(g, "url")
			if u == "" {
				u = data.Str(gc, "url")
			}
			o := map[string]any{
				"type": "urltest", "tag": gname, "outbounds": members,
				"url": u, "interval": fmt.Sprintf("%ds", iv), "tolerance": tol,
				"interrupt_exist_connections": false,
			}
			lazy := true
			if _, ok := g["lazy"]; ok {
				lazy = data.Bool(g, "lazy")
			}
			if data.Str(g, "type") == "url-test" && !lazy {
				o["idle_timeout"] = "720h"
			}
			outbounds = append(outbounds, o)
		}
	}
	return alias, outbounds
}

// SbInbounds 生成 sing-box 入站
func SbInbounds(d map[string]any, v6 bool) []map[string]any {
	lis := "0.0.0.0"
	if v6 {
		lis = "::"
	}
	inbounds := []map[string]any{
		{"type": "mixed", "tag": "mixed-in", "listen": lis, "listen_port": base.Mixed},
		{"type": "direct", "tag": "dns-in", "listen": lis, "listen_port": 1053},
	}
	if data.Str(d, "proxy_mode") == "tproxy" { // 透明代理（tproxy.sh 把流量转到 7893）
		inbounds = []map[string]any{
			inbounds[0],
			{"type": "tproxy", "tag": "tproxy-in", "listen": lis, "listen_port": 7893},
			inbounds[1],
		}
	}
	tp := stubTunParams(d) // TUN 决策与 mihomo_tun 共用；auto_redirect 另需 nftables 可用
	if data.Bool(tp, "enable") {
		address := []string{"172.19.0.1/30"}
		if v6 {
			address = append(address, "fdfe:dcba:9876::1/126")
		}
		inbounds = append(inbounds, map[string]any{
			"type": "tun", "tag": "tun-in",
			"interface_name": data.Str(tp, "device"),
			"address":        address,
			"auto_route":     true,
			"auto_redirect":  data.Bool(tp, "auto_redirect") && stubNftOk(),
			"strict_route":   data.Bool(tp, "strict_route"),
			"stack":          data.Str(tp, "stack"),
		})
	}
	return inbounds
}

// SbGeoRuleSets 显式计算 sing-box 需要的 GEO 规则集条目（{tag: {kind,url,path}}）。
//
// 之前这些条目靠完整 build_singbox 的副作用产生：SBRules.UseGeo 在翻译 GEOSITE/GEOIP 规则、
// sb_dns 在生成 DNS 策略时把它们塞进共用的 rule_sets 字典。这里逐条复刻那两个地方的逻辑，
// 供轻量路径（SbRuleNeed）使用，避免为取 need 而重跑整个构建。
func SbGeoRuleSets(d map[string]any, dc ...map[string]any) map[string]any {
	var dcc map[string]any
	if len(dc) > 0 {
		dcc = dc[0]
	} else {
		dcc = stubDnsCfg(d)
	}
	geos := map[string]any{}
	add := func(kind, name string) {
		if kind == "geoip" {
			if low := strings.ToLower(name); low == "private" || low == "lan" {
				return // 翻译成 ip_is_private，不产生规则集条目
			}
		}
		tag, entry := GeoSrsEntry(kind, name)
		if _, ok := geos[tag]; !ok {
			geos[tag] = entry
		}
	}
	for _, kn := range builtinGeo { // mihomo_rules 末尾硬编码分流规则
		add(kn[0], kn[1])
	}
	for _, lineAny := range data.List(d, "rules") { // 用户自定义规则里的 GEOSITE/GEOIP
		line, _ := lineAny.(string)
		parts := strings.Split(line, ",")
		if len(parts) >= 2 {
			if t := strings.ToUpper(strings.TrimSpace(parts[0])); t == "GEOSITE" || t == "GEOIP" {
				add(strings.ToLower(strings.TrimSpace(parts[0])), strings.TrimSpace(parts[1]))
			}
		}
	}
	for _, peAny := range data.List(dcc, "policies") { // sb_dns.policy_cond：DNS 策略里的 geosite 匹配
		pe, _ := peAny.(map[string]any)
		if pe == nil {
			continue
		}
		if kind, names := stubPolicyParts(data.Str(pe, "match")); kind == "geosite" {
			for _, n := range names {
				add("geosite", n)
			}
		}
	}
	add("geosite", "cn") // sb_dns.cn_cond：固定加入
	add("geosite", "private")
	for _, x := range data.Strs(dcc, "fake_filter") { // sb_dns：fake-ip 过滤里的 geosite:
		if strings.HasPrefix(strings.ToLower(x), "geosite:") {
			add("geosite", x[8:])
		}
	}
	return geos
}

// SbRuleNeed 轻量计算 sing-box 规则集需求表（等价于 BuildSingbox(d) 的第 3 个返回值）：只依赖 d，不跑完整构建。
func SbRuleNeed(d map[string]any) map[string]any {
	dc := stubDnsCfg(d)
	var w []string
	need := SbRuleSets(map[string]any{"rule-providers": stubBuildRuleProviders(d, dc)}, &w)
	for tag, e := range SbGeoRuleSets(d, dc) {
		need[tag] = e
	}
	out := map[string]any{}
	for tag, rsdAny := range need {
		if rsd, ok := rsdAny.(map[string]any); ok && data.Str(rsd, "kind") == "inline" {
			continue // 内嵌规则集无需下载
		}
		out[tag] = rsdAny
	}
	return out
}

var (
	srsRe = regexp.MustCompile(`\.srs(?:\?|$)`)
	mrsRe = regexp.MustCompile(`\.mrs(\?|$)`)
)

// SbRuleSets mihomo rule-providers → sing-box 规则集描述（inline / 广告拦截 / srs / 需要转换）
func SbRuleSets(cfg map[string]any, warn *[]string) map[string]any {
	ruleSets := map[string]any{}
	for name, provAny := range data.Map(cfg, "rule-providers") {
		prov, _ := provAny.(map[string]any)
		if prov == nil {
			continue
		}
		switch {
		case data.Str(prov, "type") == "inline":
			r := map[string]any{}
			for _, xAny := range data.List(prov, "payload") {
				x := toStr(xAny)
				if data.Str(prov, "behavior") == "ipcidr" {
					r["ip_cidr"] = appendAnyList(r["ip_cidr"], x)
				} else {
					k, v := ruleutil.MhDomain(x)
					r[k] = appendAnyList(r[k], v)
				}
			}
			rules := []any{}
			if len(r) > 0 {
				rules = []any{r}
			}
			ruleSets[name] = map[string]any{"kind": "inline", "rules": rules}
		case strings.HasPrefix(name, "ad-"):
			ruleSets[name] = map[string]any{
				"kind": "adblock",
				"src":  filepath.Join(base.AbDir, filepath.Base(data.Str(prov, "path"))),
				"path": name + ".json",
			}
		default:
			url := data.Str(prov, "url")
			switch {
			case srsRe.MatchString(url):
				ruleSets[name] = map[string]any{"kind": "srs", "url": url, "path": fmt.Sprintf("rs-%s.srs", data.Safe(name))}
			case data.Str(prov, "format") == "mrs" && strings.Contains(url, "meta-rules-dat") && strings.Contains(url, "/meta/"):
				ruleSets[name] = map[string]any{
					"kind": "srs",
					"url":  mrsRe.ReplaceAllString(strings.Replace(url, "/meta/", "/sing/", 1), ".srs$1"),
					"path": fmt.Sprintf("rs-%s.srs", data.Safe(name)),
				}
			case data.Str(prov, "format") == "mrs":
				*warn = append(*warn, fmt.Sprintf("规则集「%s」是 mihomo 专用的 .mrs 格式，sing-box 无法使用，已跳过（可改用 .srs 地址）", name))
			default:
				behavior := data.Str(prov, "behavior")
				if behavior == "" {
					behavior = "domain"
				}
				format := data.Str(prov, "format")
				if format == "" {
					format = "yaml"
				}
				ruleSets[name] = map[string]any{
					"kind": "convert", "url": url, "behavior": behavior,
					"format": format, "path": fmt.Sprintf("rs-%s.json", data.Safe(name)),
				}
			}
		}
	}
	return ruleSets
}

// SbRuleSetDefs 规则集定义：只保留本地已有文件的（缺失的规则及引用跳过，避免启动失败）
func SbRuleSetDefs(ruleSets map[string]any, warn *[]string) ([]any, map[string]bool) {
	defs := []any{}
	missing := map[string]bool{}
	for tag, rsdAny := range ruleSets {
		rsd, _ := rsdAny.(map[string]any)
		if rsd == nil {
			continue
		}
		if data.Str(rsd, "kind") == "inline" {
			rules, _ := rsd["rules"].([]any)
			if len(rules) == 0 {
				rules = []any{map[string]any{"domain": []any{"invalid.invalid"}}}
			}
			defs = append(defs, map[string]any{"type": "inline", "tag": tag, "rules": rules})
			continue
		}
		path := filepath.Join(SBRuleDir, data.Str(rsd, "path"))
		if st, err := os.Stat(path); err == nil && st.Size() > 0 {
			format := "source"
			if strings.HasSuffix(path, ".srs") {
				format = "binary"
			}
			defs = append(defs, map[string]any{"type": "local", "tag": tag, "format": format, "path": path})
		} else {
			missing[tag] = true
		}
	}
	if len(missing) > 0 {
		tags := make([]string, 0, len(missing))
		for t := range missing {
			tags = append(tags, t)
		}
		sort.Strings(tags)
		show, suffix := tags, ""
		if len(show) > 8 {
			show, suffix = show[:8], "…"
		}
		*warn = append(*warn, "以下规则集文件尚未下载，相关规则暂时跳过："+strings.Join(show, "、")+suffix)
	}
	return defs, missing
}

// SbPruneRules 去掉引用了缺失规则集的规则（逻辑规则里有一条缺失就整条去掉）
func SbPruneRules(lst []any, missing map[string]bool) []any {
	out := []any{}
	for _, rAny := range lst {
		r, _ := rAny.(map[string]any)
		if r == nil {
			continue
		}
		r = copyMap(r)
		if data.Str(r, "type") == "logical" {
			subs, _ := r["rules"].([]any)
			pruned := SbPruneRules(subs, missing)
			if len(pruned) != len(subs) {
				continue
			}
			r["rules"] = pruned
		} else if rs, ok := r["rule_set"]; ok {
			var keep []any
			if l, isList := rs.([]any); isList {
				for _, x := range l {
					if s, ok := x.(string); ok && !missing[s] {
						keep = append(keep, x)
					}
				}
			}
			if len(keep) == 0 {
				continue
			}
			r["rule_set"] = keep
		}
		out = append(out, r)
	}
	return out
}

var payloadLineRe = regexp.MustCompile(`(?m)^payload\s*:`)

// ruleLinesToSource mihomo 规则集文本（yaml payload / text）→ sing-box source 规则集
func ruleLinesToSource(text, behavior, format string) map[string]any {
	t := strings.TrimSpace(text)
	var items []string
	if format == "yaml" || payloadLineRe.MatchString(t) {
		if y, err := YamlLite(t); err == nil {
			if m, ok := y.(map[string]any); ok {
				for _, x := range data.List(m, "payload") {
					items = append(items, toStr(x))
				}
			}
		}
	} else {
		for _, l := range strings.Split(t, "\n") {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "//") {
				continue
			}
			items = append(items, l)
		}
	}
	r := map[string]any{}
	var w []string
	tr := NewSBRules(map[string]any{}, map[string]bool{}, map[string]string{}, map[string]any{}, &w)
	for _, x := range items {
		x = strings.Trim(strings.TrimSpace(x), "'\"")
		switch behavior {
		case "ipcidr":
			if n, ok := normalizeIPNet(x); ok {
				r["ip_cidr"] = appendAnyList(r["ip_cidr"], n)
			}
		case "domain":
			k, v := ruleutil.MhDomain(x)
			r[k] = appendAnyList(r[k], v)
		default:
			typ, val, _ := strings.Cut(x, ",")
			c := condResult{kind: condUnsupported}
			if val != "" {
				vv, _, _ := strings.Cut(val, ",")
				c = tr.Cond(typ, vv)
			}
			if c.kind == condOK && len(c.rule) > 0 {
				for k, v := range c.rule {
					if l, ok := v.([]any); ok {
						cur, _ := r[k].([]any)
						r[k] = append(cur, l...)
					}
				}
			}
		}
	}
	rules := []any{}
	if len(r) > 0 {
		rules = []any{r}
	}
	return map[string]any{"version": 3, "rules": rules}
}

// normalizeIPNet "1.2.3.4" → "1.2.3.4/32"（对应 Python ipaddress.ip_network(x, strict=False) 的字符串形式）
func normalizeIPNet(x string) (string, bool) {
	if strings.Contains(x, "/") {
		_, n, err := net.ParseCIDR(x)
		if err != nil {
			return "", false
		}
		return n.String(), true
	}
	ip := net.ParseIP(x)
	if ip == nil {
		return "", false
	}
	if ip.To4() != nil {
		return ip.String() + "/32", true
	}
	return ip.String() + "/128", true
}

// SbAdblockSource 面板广告列表（每行 +.a.com 或 a.com）→ sing-box source 规则集
func SbAdblockSource(src string) (map[string]any, error) {
	b, err := os.ReadFile(src)
	if err != nil {
		return nil, err
	}
	var suf, exact []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "+."):
			suf = append(suf, line[2:])
		case line != "":
			exact = append(exact, line)
		}
	}
	r := map[string]any{}
	if len(suf) > 0 {
		r["domain_suffix"] = suf
	}
	if len(exact) > 0 {
		r["domain"] = exact
	}
	rules := []any{}
	if len(r) > 0 {
		rules = []any{r}
	}
	return map[string]any{"version": 3, "rules": rules}, nil
}

// SbRuleCount sing-box source 规则集里的条目数（广告拦截页显示「已加载」用；
// sing-box 的 clash_api 不提供规则集信息）。读不到返回 ok=false。
func SbRuleCount(path string) (int, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	var j map[string]any
	if err := json.Unmarshal(b, &j); err != nil {
		return 0, false
	}
	n := 0
	for _, rAny := range data.List(j, "rules") {
		r, _ := rAny.(map[string]any)
		if r == nil {
			continue
		}
		for _, v := range r {
			if l, ok := v.([]any); ok {
				n += len(l)
			}
		}
	}
	return n, true
}

// SbAbLoaded {"ad-xxx": 条目数}：只统计配置里实际引用、且已转换好的广告拦截规则集
func SbAbLoaded(d map[string]any) map[string]any {
	out := map[string]any{}
	for tag, rsdAny := range SbRuleNeed(d) {
		rsd, _ := rsdAny.(map[string]any)
		if rsd == nil || data.Str(rsd, "kind") != "adblock" {
			continue
		}
		path := filepath.Join(SBRuleDir, data.Str(rsd, "path"))
		if st, err := os.Stat(path); err == nil && st.Size() > 0 {
			if n, ok := SbRuleCount(path); ok {
				out[tag] = n
			} else {
				out[tag] = nil
			}
		}
	}
	return out
}

// SbSyncAssets 下载 / 转换 sing-box 需要的规则集文件；返回失败列表
func SbSyncAssets(d map[string]any, force bool, need map[string]any) []string {
	if need == nil {
		need = SbRuleNeed(d)
	}
	gh := strings.TrimRight(data.Str(d, "gh_proxy"), "/")
	_ = os.MkdirAll(SBRuleDir, 0o755)
	bad := []string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for tag, rsdAny := range need {
		rsd, _ := rsdAny.(map[string]any)
		if rsd == nil {
			continue
		}
		wg.Add(1)
		go func(tag string, rsd map[string]any) {
			defer wg.Done()
			if err := syncOneAsset(tag, rsd, gh, force); err != nil {
				mu.Lock()
				bad = append(bad, fmt.Sprintf("%s：%s", tag, err))
				mu.Unlock()
			}
		}(tag, rsd)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(150 * time.Second):
	}
	return bad
}

// syncOneAsset 单个规则集：下载 / 转换 / 写文件（每个规则集独立文件，goroutine 间无冲突）
func syncOneAsset(tag string, rsd map[string]any, gh string, force bool) error {
	path := filepath.Join(SBRuleDir, data.Str(rsd, "path"))
	if data.Str(rsd, "kind") == "adblock" {
		if st, err := os.Stat(data.Str(rsd, "src")); err == nil {
			needWrite := force
			if !needWrite {
				if dst, err := os.Stat(path); err != nil || st.ModTime().After(dst.ModTime()) {
					needWrite = true
				}
			}
			if needWrite {
				srcObj, err := SbAdblockSource(data.Str(rsd, "src"))
				if err != nil {
					return err
				}
				return data.WriteJSON(path, srcObj)
			}
		}
		return nil
	}
	if st, err := os.Stat(path); err == nil && st.Size() > 0 && !force {
		return nil
	}
	url := data.Str(rsd, "url")
	urls := []string{url}
	if gh != "" && strings.Contains(url, "github") {
		urls = []string{gh + "/" + url, url}
	}
	var body []byte
	errMsg := ""
	for _, u := range urls {
		for _, useProxy := range proxyOrder() {
			// SSRF 防护：直连时校验 DNS，走代理时由代理解析（字面内网 IP 永远拦截）
			if err := base.DlCheck(u, useProxy); err != nil {
				errMsg = firstN(err.Error(), 120)
				continue
			}
			b, _, err := stubHTTPGet(u, base.Ua, useProxy, 40<<20, 30)
			if err != nil {
				errMsg = firstN(err.Error(), 120)
				continue
			}
			body = b
			break
		}
		if body != nil {
			break
		}
	}
	if body == nil {
		if errMsg == "" {
			errMsg = "下载失败"
		}
		return fmt.Errorf("%s", errMsg)
	}
	switch data.Str(rsd, "kind") {
	case "geo", "srs":
		if !bytes.HasPrefix(body, []byte("SRS")) {
			return fmt.Errorf("不是有效的 .srs 文件")
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, body, 0o644); err != nil {
			return err
		}
		return os.Rename(tmp, path)
	default:
		src := ruleLinesToSource(string(body), data.Str(rsd, "behavior"), data.Str(rsd, "format"))
		if rules, _ := src["rules"].([]any); len(rules) == 0 {
			return fmt.Errorf("没有解析出任何规则")
		}
		return data.WriteJSON(path, src)
	}
}

// WriteSbConfig 生成并写入 sing-box 配置，返回写入路径
func WriteSbConfig(d map[string]any, path ...string) string {
	_ = os.MkdirAll(SBDir, 0o755)
	conf, warn, _ := BuildSingbox(d)
	SBState["warn"] = warn
	p := SBConf
	if len(path) > 0 && path[0] != "" {
		p = path[0]
	}
	stubWriteAtomic(p, conf)
	stubMarkApplied()
	return p
}

// CheckSbConfig 用 sing-box 二进制校验配置文件；二进制不存在时视为通过
func CheckSbConfig(path string, bin ...string) (bool, string) {
	b := SBBin
	if len(bin) > 0 && bin[0] != "" {
		b = bin[0]
	}
	if _, err := os.Stat(b); err != nil {
		return true, ""
	}
	code, out := stubSh(fmt.Sprintf("'%s' check -c '%s' -D '%s'", b, path, SBDir), 90)
	if code == 0 {
		return true, ""
	}
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "FATAL") || strings.Contains(l, "ERROR") || strings.Contains(strings.ToLower(l), "error") {
			lines = append(lines, l)
		}
	}
	tail := lines
	if len(tail) > 3 {
		tail = tail[len(tail)-3:]
	}
	msg := strings.Join(tail, "\n")
	if msg == "" {
		r := []rune(out)
		if len(r) > 400 {
			r = r[len(r)-400:]
		}
		msg = string(r)
	}
	return false, msg
}

// WriteActiveConfig 按当前内核写入对应的正式配置，返回写入路径
func WriteActiveConfig(d ...map[string]any) string {
	var dd map[string]any
	if len(d) > 0 {
		dd = d[0]
	} else {
		dd = data.Load()
	}
	if ActiveCore(dd) == "singbox" {
		return WriteSbConfig(dd)
	}
	return stubWriteConfig(dd)
}

// CorePid 核心进程 pid；读不到或进程不在返回 0
func CorePid() int {
	b, err := os.ReadFile(CorePidPath)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0
	}
	if syscall.Kill(pid, 0) != nil {
		return 0
	}
	return pid
}

var logErrRe = regexp.MustCompile(`^(\S+\s+){0,3}(FATAL|ERROR)(\[\d+\])?\s*`)

// SbLogError sing-box 日志里最后一条 FATAL / ERROR（去时间戳前缀，最多 200 字）
func SbLogError() string {
	lines := stubLogTail(base.MihomoLog)
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if strings.Contains(line, "FATAL") || strings.Contains(line, " ERROR ") {
			s := strings.TrimSpace(logErrRe.ReplaceAllString(line, ""))
			r := []rune(s)
			if len(r) > 200 {
				r = r[len(r)-200:]
			}
			return string(r)
		}
	}
	return ""
}

func logSize() int64 {
	if st, err := os.Stat(base.MihomoLog); err == nil {
		return st.Size()
	}
	return 0
}

// logSince 日志从 off 起新增的内容（文件被截断 / 清理过则从头读），最多读 64KB
func logSince(off int64) string {
	f, err := os.Open(base.MihomoLog)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return ""
	}
	end := st.Size()
	if end < off {
		off = 0
	}
	start := off
	if end-64*1024 > start {
		start = end - 64*1024
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return ""
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		return ""
	}
	return strings.ToValidUTF8(string(buf), "")
}

func pidAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

const (
	// SBReloadWait 最多等 60 秒：小路由上 SIGHUP 后先 check 新配置（大订阅 / 规则集要好几秒），再关旧实例、启动新实例
	SBReloadWait = 60.0
	// SBReloadNomark 日志里一直没有「sing-box started」（日志被清）时，控制端口应答且进程在，等满 40 秒才算成功
	SBReloadNomark = 40.0
)

var reloadErrRe = regexp.MustCompile(`(?:ERROR|FATAL)[^\n]*reload service[^\n]*`)

// SbHotReload sing-box 热重载：SIGHUP 后以日志为准确认新配置生效；进程不在时重启服务
func SbHotReload() (bool, string) {
	pid := CorePid()
	if pid != 0 {
		base.WdHold(SBReloadWait+30, "sing-box 重载配置", false) // 重载期间控制端口短暂不可用，看门狗不要当成故障
		off := logSize()
		if syscall.Kill(pid, syscall.SIGHUP) == nil {
			t0 := time.Now()
			for time.Since(t0).Seconds() < SBReloadWait {
				time.Sleep(500 * time.Millisecond)
				if !pidAlive(pid) {
					return false, "sing-box 重载后进程已退出，请查看日志"
				}
				nw := logSince(off)
				if m := reloadErrRe.FindString(nw); m != "" {
					return false, "sing-box 拒绝了新配置：" + lastN(m, 200)
				}
				started := strings.Contains(nw, "sing-box started")
				if (started || time.Since(t0).Seconds() >= SBReloadNomark) && stubCoreAlive() {
					base.WdHold(5, "sing-box 重载配置", true) // 已确认恢复：缩短看门狗暂停期
					return true, "配置已重载"
				}
			}
			return false, "sing-box 重载后未响应，请查看日志"
		}
	}
	stubSvcRestart(90)
	return true, "已写入配置并重启 sing-box"
}

var sbVersionRe = regexp.MustCompile(`sing-box version (\S+)`)

// SbVersion sing-box 二进制版本号；二进制不存在返回 ""
func SbVersion(path ...string) string {
	p := SBBin
	if len(path) > 0 && path[0] != "" {
		p = path[0]
	}
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	code, out := stubSh(shlexQuote(p)+" version", 15)
	if code != 0 {
		return ""
	}
	if m := sbVersionRe.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

// shlexQuote shell 单词引用（对应 Python shlex.quote）
func shlexQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			strings.ContainsRune("@%_+=:,./-", r)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// IsoUTC Unix 时间戳 → "2006-01-02T15:04:05Z"
func IsoUTC(t float64) string {
	return time.Unix(int64(t), 0).UTC().Format("2006-01-02T15:04:05Z")
}

// SbFakeProviders sing-box 没有 proxy-provider：按 mihomo /providers/proxies 的格式拼出订阅节点及其延迟，前端无需区分内核
func SbFakeProviders(d map[string]any) map[string]any {
	px := map[string]any{}
	if j := stubCoreJSON("/proxies", 5); j != nil {
		if m, ok := j["proxies"].(map[string]any); ok {
			px = m
		}
	}
	out := map[string]any{}
	pn := stubSbProviderNodes(d)
	for _, sAny := range data.List(d, "subs") {
		s, _ := sAny.(map[string]any)
		if s == nil {
			continue
		}
		name := data.Str(s, "name")
		c := stubSbSubCache(name)
		proxies := []any{}
		for _, n := range pn[name] {
			entry, _ := px[n].(map[string]any)
			if entry == nil {
				entry = map[string]any{}
			}
			p := map[string]any{"name": n, "type": data.Str(entry, "type"), "history": []any{}}
			for k, v := range entry {
				p[k] = v
			}
			proxies = append(proxies, p)
		}
		upd := data.Int(c, "updated")
		updatedAt := ""
		if upd != 0 {
			updatedAt = IsoUTC(float64(upd))
		}
		info := data.Map(c, "info")
		if info == nil {
			info = map[string]any{}
		}
		out[name] = map[string]any{
			"name": name, "type": "Proxy", "vehicleType": "HTTP",
			"updatedAt": updatedAt, "subscriptionInfo": info, "proxies": proxies,
		}
	}
	return map[string]any{"providers": out}
}

// SbFakeRuleProviders 规则集 providers 信息（前端规则集页用）
func SbFakeRuleProviders(d map[string]any) map[string]any {
	out := map[string]any{}
	need := SbRuleNeed(d)
	for _, rAny := range data.List(d, "rulesets") {
		r, _ := rAny.(map[string]any)
		if r == nil {
			continue
		}
		name := data.Str(r, "name")
		path := ""
		if rsdAny, ok := need[name]; ok {
			if rsd, ok := rsdAny.(map[string]any); ok {
				path = filepath.Join(SBRuleDir, data.Str(rsd, "path"))
			}
		}
		var mt int64
		if path != "" {
			if st, err := os.Stat(path); err == nil {
				mt = st.ModTime().Unix()
			}
		}
		updatedAt := ""
		if mt != 0 {
			updatedAt = IsoUTC(float64(mt))
		}
		behavior := data.Str(r, "behavior")
		if behavior == "" {
			behavior = "domain"
		}
		out[name] = map[string]any{
			"name": name, "type": "Rule", "vehicleType": "HTTP",
			"behavior": capitalize(behavior), "ruleCount": 0, "updatedAt": updatedAt,
		}
	}
	return map[string]any{"providers": out}
}

func capitalize(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	return strings.ToUpper(string(r[0])) + strings.ToLower(string(r[1:]))
}

func lastN(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[len(r)-n:]
	}
	return string(r)
}

func dedupStr(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func appendAnyList(v any, s string) []any {
	var l []any
	if v != nil {
		l, _ = v.([]any)
	}
	return append(l, s)
}
