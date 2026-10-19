package singbox

// sb_dns.py：sing-box DNS 配置（含 Fake-IP inet4_range、rewrite_ttl）。

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"shunt/internal/data"
	"shunt/internal/ruleutil"
)

var dnsSchemeRe = regexp.MustCompile(`^(https|tls|quic|h3|udp|tcp)://(.+)$`)

// sbDNSServer mihomo DNS 地址（含 #策略组）→ sing-box DNS server
func sbDNSServer(addr, tag, boot string) map[string]any {
	addr = strings.TrimSpace(addr)
	pol := ruleutil.DnsPolicyOf(addr)
	base := addr
	if i := strings.Index(addr, "#"); i >= 0 {
		base = addr[:i]
	}
	s := map[string]any{"tag": tag}
	switch {
	case strings.HasPrefix(base, "system"):
		s["type"] = "local"
	case strings.HasPrefix(base, "dhcp://"):
		s["type"] = "dhcp"
		ifc := base[7:]
		if ifc != "" && ifc != "system" {
			s["interface"] = ifc
		}
	default:
		scheme, rest := "udp", base
		if m := dnsSchemeRe.FindStringSubmatch(base); m != nil {
			scheme, rest = m[1], m[2]
		}
		u, err := url.Parse("x://" + rest)
		host := rest
		var port, path string
		if err == nil {
			if h := u.Hostname(); h != "" {
				host = h
			}
			port = u.Port()
			path = u.Path
		}
		s["type"] = scheme
		s["server"] = host
		if port != "" {
			s["server_port"] = toInt(port)
		}
		if (scheme == "https" || scheme == "h3") && path != "" && path != "/dns-query" {
			s["path"] = path
		}
		if !stubIsIPAddr(host) && boot != "" {
			s["domain_resolver"] = boot
		}
	}
	if pol != "" {
		s["detour"] = pol
	}
	return s
}

var rcodeMap = map[string]string{
	"success": "NOERROR", "format_error": "FORMERR", "server_failure": "SERVFAIL",
	"name_error": "NXDOMAIN", "not_implemented": "NOTIMP", "refused": "REFUSED",
}

// SbDNS 生成 sing-box dns 段；返回 (dns, 节点测速用 server tag, 直连 server tag, 代理 server tag)
func SbDNS(d, cfg map[string]any, policies map[string]bool, rs *SBRules, alias map[string]string, v6 bool) (map[string]any, string, string, string) {
	dc := stubDnsCfg(d)
	warn := rs.Warn

	fixd := func(x string) string {
		if pol := ruleutil.DnsPolicyOf(x); pol != "" {
			if a, ok := alias[pol]; ok {
				head, _, _ := strings.Cut(x, "#")
				return head + "#" + a
			}
		}
		return x
	}
	fx := func(xs []string) []string {
		out := make([]string, len(xs))
		for i, x := range xs {
			out[i] = stubFixDNSPolicy(fixd(x), policies)
		}
		return out
	}

	var servers []any
	tags := map[string]string{}
	server := func(addr, boot string) string {
		if t, ok := tags[addr]; ok {
			return t
		}
		if strings.HasPrefix(addr, "rcode://") {
			return addr
		}
		tag := fmt.Sprintf("dns-%d", len(tags)+1)
		servers = append(servers, sbDNSServer(addr, tag, boot))
		tags[addr] = tag
		return tag
	}

	bootList := data.Strs(dc, "default")
	servers = append(servers, sbDNSServer(bootList[0], "dns-boot", ""))
	direct := fx(data.Strs(dc, "direct"))
	proxy := fx(data.Strs(dc, "proxy"))
	tDirect := server(direct[0], "dns-boot")
	tProxy := ""
	if len(proxy) > 0 {
		tProxy = server(proxy[0], "dns-boot")
	}
	var tNode string
	if ps := data.Strs(dc, "pserver"); len(ps) > 0 {
		head, _, _ := strings.Cut(ps[0], "#")
		tNode = server(head, "dns-boot")
	} else {
		head, _, _ := strings.Cut(direct[0], "#")
		tNode = server(head, "dns-boot")
	}
	final := tDirect
	if tProxy != "" {
		final = tProxy
	}

	var rules []any
	ab := data.Map(d, "adblock")
	abSets := []string{}
	for k := range rs.RuleSets {
		if strings.HasPrefix(k, "ad-") {
			abSets = append(abSets, k)
		}
	}
	sort.Strings(abSets)
	if data.Bool(ab, "enabled") && data.Bool(ab, "dns") && len(abSets) > 0 {
		for _, k := range abSets {
			if k == "ad-allow" {
				rules = append(rules, map[string]any{"rule_set": []any{"ad-allow"}, "action": "route", "server": tDirect})
				break
			}
		}
		var bl []any
		for _, k := range abSets {
			if k != "ad-allow" {
				bl = append(bl, k)
			}
		}
		if len(bl) > 0 {
			rules = append(rules, map[string]any{"rule_set": bl, "action": "predefined", "rcode": "NXDOMAIN"})
		}
	}

	policyCond := func(match string) map[string]any {
		kind, names := stubPolicyParts(match)
		switch kind {
		case "geosite":
			var rsets []any
			for _, n := range names {
				rsets = append(rsets, rs.UseGeo("geosite", n))
			}
			return map[string]any{"rule_set": rsets}
		case "rule-set":
			var have []any
			for _, n := range names {
				if _, ok := rs.RuleSets[n]; ok {
					have = append(have, n)
				}
			}
			if len(have) == 0 {
				return nil
			}
			return map[string]any{"rule_set": have}
		}
		c := map[string]any{}
		for _, n := range names {
			k, v := ruleutil.MhDomain(n)
			var cur []any
			if ex, ok := c[k]; ok {
				cur, _ = ex.([]any)
			}
			c[k] = append(cur, v)
		}
		return c
	}

	target := func(servers_ []string) map[string]any {
		s0 := servers_[0]
		if strings.HasPrefix(s0, "rcode://") {
			rc, ok := rcodeMap[s0[8:]]
			if !ok {
				rc = "NXDOMAIN"
			}
			return map[string]any{"action": "predefined", "rcode": rc}
		}
		return map[string]any{"action": "route", "server": server(s0, "dns-boot")}
	}

	for _, peAny := range data.List(dc, "policies") {
		pe, _ := peAny.(map[string]any)
		if pe == nil {
			continue
		}
		c := policyCond(data.Str(pe, "match"))
		if len(c) > 0 {
			r := copyMap(c)
			for k, v := range target(data.Strs(pe, "servers")) {
				r[k] = v
			}
			rules = append(rules, r)
		} else {
			*warn = append(*warn, fmt.Sprintf("DNS 策略「%s」引用的规则集 sing-box 中不存在，已跳过", data.Str(pe, "match")))
		}
	}

	exact := map[string][]any{}
	for _, hAny := range data.List(dc, "hosts") {
		h, _ := hAny.(map[string]any)
		if h == nil {
			continue
		}
		domain := data.Str(h, "domain")
		var ips []any
		for _, v := range data.List(h, "value") {
			if s, ok := v.(string); ok && stubIsIPAddr(s) {
				ips = append(ips, s)
			}
		}
		if strings.HasPrefix(domain, "+.") || strings.HasPrefix(domain, "*.") || len(ips) == 0 {
			*warn = append(*warn, fmt.Sprintf("hosts「%s」sing-box 只支持精确域名 → IP，已跳过", domain))
			continue
		}
		exact[domain] = ips
	}
	if len(exact) > 0 {
		pre := map[string]any{}
		for k, v := range exact {
			pre[k] = v
		}
		servers = append(servers, map[string]any{"type": "hosts", "tag": "dns-hosts", "predefined": pre})
		domains := make([]any, 0, len(exact))
		for k := range exact {
			domains = append(domains, k)
		}
		sortAny(domains)
		rules = append(rules, map[string]any{"domain": domains, "action": "route", "server": "dns-hosts"})
	}

	cnRuleSet := []any{rs.UseGeo("geosite", "cn"), rs.UseGeo("geosite", "private")}
	if _, ok := rs.RuleSets["cn-apps"]; ok { // 内置国内 App 名单与 geosite:cn 一样走直连 DNS
		cnRuleSet = append([]any{"cn-apps"}, cnRuleSet...)
	}
	cnCond := map[string]any{"rule_set": cnRuleSet}

	if data.Str(dc, "mode") == "fake-ip" {
		// v7.5.9 曾把范围从 198.18.0.0/15 缩小到 /16，导致老版本分配的 198.19.x.x 映射变孤儿
		// （sing-box 不认识 → missing fakeip record）。/15 是 /16 的超集，含 198.18.x 和 198.19.x
		fake := map[string]any{"type": "fakeip", "tag": "dns-fake", "inet4_range": "198.18.0.0/15"}
		if v6 {
			fake["inet6_range"] = "fc00::/18"
		}
		servers = append(servers, fake)

		var ruleSetVals []any
		dom := map[string][]any{}
		var domKeys []string
		for _, x := range data.Strs(dc, "fake_filter") {
			low := strings.ToLower(x)
			switch {
			case strings.HasPrefix(low, "geosite:"):
				ruleSetVals = append(ruleSetVals, rs.UseGeo("geosite", x[8:]))
			case strings.HasPrefix(low, "rule-set:"):
				if _, ok := rs.RuleSets[x[9:]]; ok {
					ruleSetVals = append(ruleSetVals, x[9:])
				}
			default:
				k, v := ruleutil.MhDomain(x)
				if _, ok := dom[k]; !ok {
					domKeys = append(domKeys, k)
				}
				dom[k] = append(dom[k], v)
			}
		}
		if len(ruleSetVals) > 0 || len(domKeys) > 0 { // Fake-IP 过滤名单：按国内 / 国外分流到真实 DNS
			var parts []any
			if len(domKeys) > 0 {
				dm := map[string]any{}
				for _, k := range domKeys {
					var vals []any
					for _, v := range dom[k] {
						vals = append(vals, v)
					}
					dm[k] = vals
				}
				parts = append(parts, dm)
			}
			if len(ruleSetVals) > 0 {
				parts = append(parts, map[string]any{"rule_set": ruleSetVals})
			}
			var fc map[string]any
			if len(parts) == 1 {
				fc = parts[0].(map[string]any)
			} else {
				fc = map[string]any{"type": "logical", "mode": "or", "rules": parts}
			}
			if data.Bool(dc, "policy") && tProxy != "" {
				rules = append(rules, map[string]any{
					"type": "logical", "mode": "and", "rules": []any{fc, cnCond},
					"action": "route", "server": tDirect,
				})
			}
			r := copyMap(fc)
			r["action"] = "route"
			r["server"] = final
			rules = append(rules, r)
		}
		// TTL 改成 1（与 mihomo 的 fake-ip 一致）：sing-box 默认 600 秒，内核被强制结束或切换内核后映射丢失时，
		// 客户端还会拿缓存的 198.18.x 连 10 分钟，日志刷「missing fakeip record」，期间这些网站都打不开
		rules = append(rules, map[string]any{
			"query_type": []any{"A", "AAAA"}, "action": "route", "server": "dns-fake", "rewrite_ttl": 1,
		})
	}
	if data.Bool(dc, "policy") && tProxy != "" {
		r := copyMap(cnCond)
		r["action"] = "route"
		r["server"] = tDirect
		rules = append(rules, r)
	}

	out := map[string]any{
		"servers": servers, "rules": rules, "final": final,
		"strategy":       map[bool]string{true: "prefer_ipv4", false: "ipv4_only"}[v6],
		"cache_capacity": 4096,
	}
	return out, tNode, tDirect, tProxy
}
