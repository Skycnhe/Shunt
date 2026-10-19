package mihomo

// mihomo YAML 配置生成：shunt/mihomo.py 的 Go 移植。
//
// 约定：
//   - Python 函数 foo_bar → Go 导出 FooBar；_private → 不导出。
//   - 配置用 map[string]any 构建（对应 Python dict），输出时经本包 Marshal 序列化为 YAML。
//   - 取值一律用 data.Str/Int/Bool/List/Map。
//   - 属于其他 agent 模块的函数（groups/sb_common/devroute/sysopt）经 stubs.go 的 stub 接入，
//     本文件不 import 他们的包。

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"shunt/internal/base"
	"shunt/internal/data"
	"shunt/internal/ruleutil"
)

// BUILTIN_GEO 内置规则里的 GEOSITE/GEOIP（kind, 值）：
// 与 MihomoRules 末尾硬编码列表保持一致；sing-box 翻译时为它们下载 .srs。
// 注意 GEOIP,private 不会产生条目（翻译成 ip_is_private），这里保留仅作对照。
var BuiltinGeo = [][2]string{
	{"geosite", "private"}, {"geoip", "private"},
	{"geosite", "category-ai-!cn"},
	{"geosite", "netflix"}, {"geoip", "netflix"},
	{"geosite", "youtube"}, {"geosite", "google"}, {"geoip", "google"},
	{"geosite", "telegram"}, {"geoip", "telegram"},
	{"geosite", "geolocation-!cn"}, {"geosite", "cn"}, {"geoip", "CN"},
}

// ---------- 小助手 ----------

func toStr(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// toBool 贴近 Python bool() 的真值判断（JSON 数据里一般是原生 bool）。
func toBool(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case int:
		return t != 0
	case int64:
		return t != 0
	case float64:
		return t != 0
	case []any:
		return len(t) != 0
	case []string:
		return len(t) != 0
	case map[string]any:
		return len(t) != 0
	default:
		return true
	}
}

// boolOr 取 m[key] 的布尔值；键缺失或值为 nil 时返回默认值 def。
// 对应 Python 的 bool(m.get(key, def))。
func boolOr(m map[string]any, key string, def bool) bool {
	if m == nil {
		return def
	}
	v, ok := m[key]
	if !ok || v == nil {
		return def
	}
	return toBool(v)
}

func isEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case []any:
		return len(t) == 0
	case []string:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	default:
		return false
	}
}

// strListOf 把 []any / []string 转成 []string。
func strListOf(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			out = append(out, toStr(x))
		}
		return out
	default:
		return nil
	}
}

// asAnyList 把各种列表转成 []any。
func asAnyList(v any) []any {
	switch t := v.(type) {
	case nil:
		return nil
	case []any:
		return t
	case []string:
		out := make([]any, 0, len(t))
		for _, x := range t {
			out = append(out, x)
		}
		return out
	default:
		return nil
	}
}

func anyList(ss []string) []any {
	out := make([]any, 0, len(ss))
	for _, s := range ss {
		out = append(out, s)
	}
	return out
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func concatStr(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// mergeMaps 把 src 的键并入 dst（src 覆盖），返回 dst。
func mergeMaps(dst, src map[string]any) map[string]any {
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// strListOr 空列表时取 fallback（对应 Python 的 xs or default）。
func strListOr(xs, fallback []string) []string {
	if len(xs) == 0 {
		return fallback
	}
	return xs
}

// ---------- 配置生成 ----------

// BuildConfig 主入口：生成完整 mihomo 配置 dict（对应 Python build_config）。
func BuildConfig(d map[string]any, strict ...bool) map[string]any {
	strictFlag := len(strict) > 0 && strict[0]

	providers := map[string]any{}
	var use []string
	subInterval := data.Int(d, "sub_interval")
	if subInterval == 0 {
		subInterval = 86400
	}
	for _, sv := range data.List(d, "subs") {
		s, _ := sv.(map[string]any)
		if s == nil {
			continue
		}
		name := data.Str(s, "name")
		pv := map[string]any{
			"type":     "http",
			"url":      data.Str(s, "url"),
			"path":     "./providers/" + data.Safe(name) + ".yaml",
			"interval": subInterval,
			"health-check": map[string]any{
				"enable": true, "url": base.Hc, "interval": 300,
			},
		}
		if f := data.Str(s, "filter"); f != "" {
			pv["filter"] = f
		}
		exc := base.DefaultExclude
		if v, ok := s["exclude"]; ok {
			exc = toStr(v)
		}
		if exc != "" {
			pv["exclude-filter"] = exc
		}
		providers[name] = pv
		if !containsStr(use, name) {
			use = append(use, name)
		}
	}

	proxies := []any{}
	var names []string
	for _, nv := range data.List(d, "nodes") {
		n, _ := nv.(map[string]any)
		if n == nil {
			continue
		}
		p := data.Map(n, "proxy")
		proxies = append(proxies, p)
		names = append(names, data.Str(p, "name"))
	}

	gc := gcfg(d)
	race := "url-test" // 竞技组：mihomo 用 url-test，Smart 内核用 smart
	if activeCore(d) == "smart" {
		race = "smart"
	}

	withSrc := func(g map[string]any, members []string, src bool) map[string]any {
		if len(members) > 0 {
			g["proxies"] = anyList(members)
		}
		if len(use) > 0 && src {
			g["use"] = anyList(use)
		}
		_, hasP := g["proxies"]
		_, hasU := g["use"]
		if !hasP && !hasU {
			g["proxies"] = anyList([]string{"COMPATIBLE"})
		}
		return g
	}

	// 地区分组：「<旗> <地区>竞技」(url-test，选延迟最低) + 「⚖️ <地区>哈希」(load-balance，一致性哈希)
	var autos, lbs [][2]any // (label, group)
	for _, item := range regionPlan(d, names, use) {
		_, label := data.RegionLabel(item.Rname)
		type variant struct {
			name   string
			typ    string
			bucket *[][2]any
			extra  map[string]any
		}
		variants := []variant{{data.AutoName(item.Rname), race, &autos, nil}}
		if data.Bool(gc, "lb") && (item.Total >= 2 || item.Unknown) { // 地区有 ≥2 个节点时生成负载均衡组（一致性哈希）
			for _, st := range data.LbKinds {
				variants = append(variants, variant{
					data.LbName(item.Rname, st[0]), "load-balance", &lbs,
					map[string]any{"strategy": st[0]},
				})
			}
		}
		for _, v := range variants {
			g := withSrc(mergeMaps(map[string]any{"name": v.name}, groupOpts(v.typ, gc, v.extra)), item.Matched, true)
			if len(use) > 0 {
				if item.Flt != "" {
					g["filter"] = item.Flt
				}
				if item.Exc != "" {
					g["exclude-filter"] = item.Exc
				}
			}
			*v.bucket = append(*v.bucket, [2]any{label, g})
		}
	}

	ordered := func(items [][2]any, order []string) []any {
		rank := map[string]int{}
		for i, n := range order {
			rank[n] = i
		}
		cp := append([][2]any{}, items...)
		sort.SliceStable(cp, func(a, b int) bool {
			ra, ok := rank[cp[a][0].(string)]
			if !ok {
				ra = len(order)
			}
			rb, ok := rank[cp[b][0].(string)]
			if !ok {
				rb = len(order)
			}
			return ra < rb
		})
		out := make([]any, 0, len(cp))
		for _, it := range cp {
			out = append(out, it[1])
		}
		return out
	}
	regionGroups := append(ordered(autos, base.AutoOrder), ordered(lbs, base.LbOrder)...)
	var rnames []string
	regionSet := map[string]bool{}
	for _, gv := range regionGroups {
		nm := data.Str(gv.(map[string]any), "name")
		rnames = append(rnames, nm)
		regionSet[nm] = true
	}

	// 自定义策略组
	var customGroups []map[string]any
	var cnames, exposed []string
	for _, cv := range data.List(d, "custom_groups") {
		cgm, _ := cv.(map[string]any)
		if cgm == nil {
			continue
		}
		cg, err := cleanCustomGroup(cgm)
		if err != nil {
			continue
		}
		members := strListOf(cg["proxies"])
		if f := data.Str(cg, "filter"); f != "" {
			r := rxCompile(f)
			if r != nil {
				for _, n := range names {
					if r.MatchString(n) && !containsStr(members, n) {
						members = append(members, n)
					}
				}
			}
		}
		g := mergeMaps(map[string]any{"name": data.Str(cg, "name")}, groupOpts(data.Str(cg, "type"), gc, cg))
		g["_members"] = members
		if ic := data.Str(cg, "icon"); ic != "" {
			g["icon"] = ic
		}
		if data.Str(cg, "filter") != "" && len(data.List(cg, "subs")) > 0 && len(use) > 0 {
			g["use"] = anyList(use)
			g["filter"] = data.Str(cg, "filter")
		}
		customGroups = append(customGroups, g)
		cnames = append(cnames, data.Str(cg, "name"))
		if data.Bool(cg, "expose") {
			exposed = append(exposed, data.Str(cg, "name"))
		}
	}

	// 🚀 节点选择 只包含：各地区竞技 → 各地区负载均衡 → 🖐️ 手动选择 → ⚡ 全局自动选择 → 🏠 直连
	have := len(use) > 0 || len(names) > 0
	directG := map[string]any{"name": base.GDirect, "type": "select", "proxies": anyList([]string{"DIRECT"})}
	var groups []any
	var side []string
	if have {
		groups = append(groups, map[string]any{
			"name": base.GSel, "type": "select",
			"proxies": anyList(concatStr(rnames, []string{base.GManual, base.GAuto, base.GDirect})),
		})
		groups = append(groups, regionGroups...)
		groups = append(groups, withSrc(map[string]any{"name": base.GManual, "type": "select"}, names, true))
		groups = append(groups, withSrc(mergeMaps(map[string]any{"name": base.GAuto}, groupOpts(race, gc, nil)), names, true))
		groups = append(groups, directG)
		side = concatStr([]string{base.GSel}, rnames, []string{base.GManual, base.GAuto}, exposed, []string{"DIRECT"}, names)
	} else {
		groups = []any{
			map[string]any{"name": base.GSel, "type": "select", "proxies": anyList([]string{base.GDirect})},
			directG,
		}
		side = concatStr([]string{base.GSel}, exposed, []string{"DIRECT"})
	}
	for _, sg := range base.SideGroups {
		groups = append(groups, withSrc(map[string]any{"name": sg, "type": "select"}, side, true))
	}
	known := map[string]bool{}
	for _, gv := range groups {
		known[data.Str(gv.(map[string]any), "name")] = true
	}
	for r := range regionSet {
		known[r] = true
	}
	for _, c := range cnames {
		known[c] = true
	}
	for p := range base.BuiltinPolicies {
		known[p] = true
	}
	for _, n := range names {
		known[n] = true
	}
	for _, g := range customGroups {
		members, _ := g["_members"].([]string)
		delete(g, "_members")
		if !strictFlag { // 成员已不存在（地区组消失、节点被删）时跳过，避免整份配置无法加载
			kept := members[:0]
			for _, m := range members {
				if known[m] {
					kept = append(kept, m)
				}
			}
			members = kept
		}
		if len(members) > 0 {
			g["proxies"] = anyList(members)
		}
		_, hasP := g["proxies"]
		_, hasU := g["use"]
		if !hasP && !hasU {
			g["proxies"] = anyList([]string{"COMPATIBLE"})
		}
		groups = append(groups, g)
	}
	policies := map[string]bool{}
	for _, gv := range groups {
		policies[data.Str(gv.(map[string]any), "name")] = true
	}
	for p := range base.BuiltinPolicies {
		policies[p] = true
	}
	for _, n := range names {
		policies[n] = true
	}

	dc := DnsCfg(d)
	ruleProviders, rules, abProv := MihomoRules(d, policies, dc)
	v6 := data.Bool(d, "ipv6")
	dns := MihomoDns(d, dc, policies, abProv)
	hosts := MihomoHosts(dc)
	tun := MihomoTun(d)
	extra := map[string]any{}
	if activeCore(d) == "smart" && data.Bool(gcfg(d), "lgbm") { // 模型放在 -d 目录（/etc/mihomo/Model.bin），内核每 72 小时自动更新
		gh := strings.TrimRight(data.Str(d, "gh_proxy"), "/")
		if gh != "" {
			gh += "/"
		}
		extra = map[string]any{
			"lgbm-auto-update":     true,
			"lgbm-update-interval": 72,
			"lgbm-url":             gh + base.LgbmURL,
		}
	}
	cfg := map[string]any{}
	for k, v := range extra { // dict(extra, **{...})：字面量键覆盖 extra
		cfg[k] = v
	}
	mode := data.Str(d, "mode")
	if mode == "" {
		mode = "rule"
	}
	cfg["mixed-port"] = base.Mixed
	cfg["tproxy-port"] = 7893
	cfg["allow-lan"] = true
	cfg["bind-address"] = "*"
	cfg["mode"] = mode
	cfg["log-level"] = "info"
	cfg["ipv6"] = v6
	cfg["external-controller"] = fmt.Sprintf("%s:%d", base.CtrlHost, base.CtrlPort)
	cfg["secret"] = data.Str(d, "secret")
	cfg["unified-delay"] = true
	cfg["tcp-concurrent"] = true
	cfg["global-ua"] = "clash.meta"
	cfg["geodata-mode"] = true
	cfg["geo-auto-update"] = true
	cfg["geo-update-interval"] = 24
	cfg["geox-url"] = map[string]any{
		"geoip":   "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat",
		"geosite": "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
		"mmdb":    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb",
	}
	cfg["profile"] = map[string]any{"store-selected": true, "store-fake-ip": true}
	cfg["sniffer"] = map[string]any{
		"enable": boolOr(d, "sniffer", true),
		"sniff": map[string]any{
			"HTTP": map[string]any{"ports": []any{80, "8080-8880"}, "override-destination": true},
			"TLS":  map[string]any{"ports": []any{443, 8443}},
			"QUIC": map[string]any{"ports": []any{443, 8443}},
		},
	}
	cfg["dns"] = dns
	cfg["tun"] = tun
	cfg["hosts"] = hosts
	cfg["proxies"] = proxies
	cfg["proxy-providers"] = providers
	cfg["rule-providers"] = ruleProviders
	cfg["proxy-groups"] = groups
	cfg["rules"] = anyList(rules)
	return cfg
}

// BuildRuleProviders rule-providers 段：规则集 + 广告拦截 + DNS 防绕过
// → (rule-providers, 广告拦截 providers, 广告拦截 rules)。
// MihomoRules 与 sing-box 轻量路径共用，后者不再为取规则集需求表而跑完整 BuildConfig。
func BuildRuleProviders(d map[string]any, dc map[string]any) (map[string]any, map[string]any, []string) {
	ruleProviders := map[string]any{}
	for _, rv := range data.List(d, "rulesets") {
		r, _ := rv.(map[string]any)
		if r == nil {
			continue
		}
		ext, ok := map[string]string{"mrs": "mrs", "text": "list"}[data.Str(r, "format")]
		if !ok {
			ext = "yaml"
		}
		behavior := data.Str(r, "behavior")
		if behavior == "" {
			behavior = "domain"
		}
		format := data.Str(r, "format")
		if format == "" {
			format = "yaml"
		}
		name := data.Str(r, "name")
		ruleProviders[name] = map[string]any{
			"type": "http", "behavior": behavior, "format": format,
			"url": data.Str(r, "url"), "path": "./rules/" + data.Safe(name) + "." + ext,
			"interval": 86400,
		}
	}
	abProv, abRules := ruleutil.AdblockProviders(d)
	for k, v := range abProv {
		ruleProviders[k] = v
	}
	// 注意：base.CnAppDomains 由 base 包 init 时对 map 做 range 构造，顺序随机（base 侧待修复）；
	// 这里排序一份拷贝，保证每次生成的配置字节一致（面板会对配置文件做字节级比对）。
	cnPayload := append([]string{}, base.CnAppDomains...)
	sort.Strings(cnPayload)
	ruleProviders["cn-apps"] = map[string]any{
		"type": "inline", "behavior": "domain", "payload": anyList(cnPayload),
	}
	if toBool(dc["block_bypass"]) { // 阻止局域网设备绕过 mihomo DNS：拒绝 DoT/DoQ(853) 与已知公共 DoH 服务器
		ruleProviders["dns-bypass-ip"] = map[string]any{
			"type": "inline", "behavior": "ipcidr", "payload": anyList(base.DohIPs),
		}
		ruleProviders["dns-bypass-domain"] = map[string]any{
			"type": "inline", "behavior": "domain", "payload": anyList(base.DohDomains),
		}
	}
	return ruleProviders, abProv, abRules
}

// MihomoRules 规则集、TUN 绕过、广告拦截、防绕过 DNS、自定义规则与内置分流规则
// → (rule-providers, rules, 广告拦截 providers)。
func MihomoRules(d map[string]any, policies map[string]bool, dc map[string]any) (map[string]any, []string, map[string]any) {
	ruleProviders, abProv, abRules := BuildRuleProviders(d, dc)
	var rsRules []string
	for _, rv := range data.List(d, "rulesets") {
		r, _ := rv.(map[string]any)
		if r == nil {
			continue
		}
		tgt := data.Str(r, "target")
		if !policies[tgt] {
			tgt = base.GSel
		}
		s := "RULE-SET," + data.Str(r, "name") + "," + tgt
		if data.Str(r, "behavior") == "ipcidr" {
			s += ",no-resolve"
		}
		rsRules = append(rsRules, s)
	}
	var custom []string
	for _, xv := range data.List(d, "rules") {
		if x := FixRulePolicy(toStr(xv), policies); x != "" {
			custom = append(custom, x)
		}
	}
	var pre []string
	if data.Str(d, "proxy_mode") == "tun" { // TUN 模式下无法在 nftables 里按来源绕过，改用规则让这些设备直连
		for _, xv := range data.List(d, "bypass") {
			if n, ok := parseIPNet(toStr(xv)); ok {
				pre = append(pre, "SRC-IP-CIDR,"+n+",DIRECT")
			}
		}
	}
	var guard []string
	if toBool(dc["block_bypass"]) {
		guard = []string{
			"AND,((" + base.LanIn + "),(DST-PORT,853)),REJECT",
			"AND,((" + base.LanIn + "),(DST-PORT,443),(RULE-SET,dns-bypass-ip,no-resolve)),REJECT",
			"AND,((" + base.LanIn + "),(RULE-SET,dns-bypass-domain)),REJECT",
		}
	}
	// 按设备分流：排在 TUN 绕过、DNS 防绕过、广告拦截之后，其余规则之前；前面先放局域网直连，
	// 被分流到代理 / 拦截的设备仍能访问局域网（TUN 模式下局域网流量也会进核心）
	dev := deviceRouteRules(d, policies)
	var lan []string
	if len(dev) > 0 {
		lan = []string{"GEOSITE,private,DIRECT", "GEOIP,private,DIRECT,no-resolve"}
	}
	rules := concatStr(pre, guard, lan, abRules, dev, custom, rsRules, []string{
		"GEOSITE,private,DIRECT", "GEOIP,private,DIRECT,no-resolve", "RULE-SET,cn-apps,DIRECT",
		"GEOSITE,category-ai-!cn," + base.GAi,
		"GEOSITE,netflix," + base.GNf, "GEOIP,netflix," + base.GNf + ",no-resolve",
		"GEOSITE,youtube," + base.GYt,
		"GEOSITE,google," + base.GGg, "GEOIP,google," + base.GGg + ",no-resolve",
		"GEOSITE,telegram," + base.GTg, "GEOIP,telegram," + base.GTg + ",no-resolve",
		"GEOSITE,geolocation-!cn," + base.GSel,
		"DOMAIN-SUFFIX,dangbei.com,DIRECT",
		"GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT",
		"MATCH," + base.GFinal,
	})
	return ruleProviders, rules, abProv
}

// parseIPNet 解析 "网段" 或裸 IP（对应 Python ipaddress.ip_network(x, strict=False)）。
func parseIPNet(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return "", false
		}
		return n.String(), true
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", false
	}
	if ip.To4() != nil {
		return ip.String() + "/32", true
	}
	return ip.String() + "/128", true
}

// MihomoDns dns 段：防泄露布局 + nameserver-policy。
func MihomoDns(d map[string]any, dc map[string]any, policies map[string]bool, abProv map[string]any) map[string]any {
	v6 := data.Bool(d, "ipv6")
	fx := func(xs []string) []string {
		out := make([]string, 0, len(xs))
		for _, x := range xs {
			out = append(out, FixDnsPolicy(x, policies))
		}
		return out
	}
	direct := strListOf(dc["direct"])
	if len(direct) == 0 {
		direct = strListOf(base.DNSDefault["direct"])
	}
	direct = fx(direct)
	proxyDns := fx(strListOf(dc["proxy"]))
	plainDirect := make([]string, 0, len(direct))
	for _, x := range direct {
		plainDirect = append(plainDirect, strings.SplitN(x, "#", 2)[0])
	}
	mode := toStr(dc["mode"])
	// 防泄露布局：默认 nameserver = 代理 DNS（经节点发出），只有 geosite:cn / private 用直连 DNS；
	// 节点域名由 proxy-server-nameserver 解析，DIRECT 连接由 direct-nameserver 解析；不使用 fallback
	dns := map[string]any{
		"enable": true, "listen": "0.0.0.0:1053", "ipv6": v6, "enhanced-mode": mode,
		"cache-algorithm": toStr(dc["cache"]), "prefer-h3": false,
		"use-hosts": true, "use-system-hosts": false,
		"respect-rules":                   toBool(dc["respect_rules"]),
		"default-nameserver":              anyList(strListOr(strListOf(dc["default"]), strListOf(base.DNSDefault["default"]))),
		"direct-nameserver":               anyList(plainDirect),
		"direct-nameserver-follow-policy": false,
	}
	if v6 {
		dns["listen"] = "[::]:1053"
	}
	ns := proxyDns
	if len(ns) == 0 {
		ns = direct
	}
	dns["nameserver"] = anyList(ns)
	psn := make([]string, 0, len(strListOf(dc["pserver"])))
	for _, x := range strListOf(dc["pserver"]) {
		psn = append(psn, strings.SplitN(x, "#", 2)[0])
	}
	dns["proxy-server-nameserver"] = anyList(strListOr(psn, plainDirect))
	if mode == "fake-ip" {
		dns["fake-ip-range"] = "198.18.0.1/16"
		var ff []string
		for _, x := range strListOf(dc["fake_filter"]) {
			if strings.TrimSpace(x) != "" {
				ff = append(ff, x)
			}
		}
		dns["fake-ip-filter"] = anyList(ff)
		if v6 {
			dns["fake-ip-range6"] = "fdfe:dcba:9876::1/64"
		}
	}
	pol := map[string]any{}
	ab := data.Map(d, "adblock")
	if data.Bool(ab, "enabled") && data.Bool(ab, "dns") { // DNS 层拦截：白名单先走直连 DNS，其余命中拦截列表直接返回 NXDOMAIN
		if _, ok := abProv["ad-allow"]; ok {
			pol["rule-set:ad-allow"] = anyList(direct)
		}
		for k := range abProv {
			if k != "ad-allow" {
				pol["rule-set:"+k] = "rcode://name_error"
			}
		}
	}
	for _, pev := range asAnyList(dc["policies"]) { // 用户自定义的 nameserver-policy（排在内置分流之前）
		pe, _ := pev.(map[string]any)
		if pe == nil {
			continue
		}
		m := toStr(pe["match"])
		if _, exists := pol[m]; !exists {
			pol[m] = anyList(fx(strListOf(pe["servers"])))
		}
	}
	if toBool(dc["policy"]) && len(proxyDns) > 0 { // 国内域名走直连 DNS，其余（含未知域名）走代理 DNS
		if _, ok := pol["rule-set:cn-apps"]; !ok {
			pol["rule-set:cn-apps"] = anyList(direct)
		}
		if _, ok := pol["geosite:cn,private"]; !ok {
			pol["geosite:cn,private"] = anyList(direct)
		}
	}
	if len(pol) > 0 {
		dns["nameserver-policy"] = pol
	}
	return dns
}

// MihomoHosts hosts 段：同域名多值去重合并，单值用标量、多值用列表。
func MihomoHosts(dc map[string]any) map[string]any {
	hosts := map[string][]string{}
	for _, hv := range asAnyList(dc["hosts"]) {
		h, _ := hv.(map[string]any)
		if h == nil {
			continue
		}
		dom := toStr(h["domain"])
		vals := hosts[dom]
		for _, v := range strListOf(h["value"]) {
			if !containsStr(vals, v) {
				vals = append(vals, v)
			}
		}
		hosts[dom] = vals
	}
	out := map[string]any{}
	for k, v := range hosts {
		if len(v) == 1 {
			out[k] = v[0]
		} else {
			out[k] = anyList(v)
		}
	}
	return out
}

// TunParams TUN 参数归一化：MihomoTun 与 sing-box 共用同一决策
// （是否启用、协议栈回退、设备名、开关量）。
func TunParams(d map[string]any) map[string]any {
	tc := data.Map(d, "tun")
	if len(tc) == 0 {
		tc = base.TunDefault
	}
	stack := data.Str(tc, "stack")
	if !containsStr(base.TunStacks, stack) {
		stack = "mixed"
	}
	return map[string]any{
		"enable":        data.Str(d, "proxy_mode") == "tun",
		"stack":         stack,
		"device":        SafeDev(data.Str(tc, "device")),
		"auto_redirect": boolOr(tc, "auto_redirect", true),
		"strict_route":  data.Bool(tc, "strict_route"),
	}
}

// MihomoTun tun 段。
func MihomoTun(d map[string]any) map[string]any {
	p := TunParams(d)
	if !toBool(p["enable"]) {
		return map[string]any{"enable": false}
	}
	return map[string]any{
		"enable": true, "stack": p["stack"], "device": p["device"], "auto-route": true,
		"auto-redirect": p["auto_redirect"], "auto-detect-interface": true,
		"dns-hijack":   []any{"any:53", "tcp://any:53"},
		"strict-route": p["strict_route"],
	}
}

// FixRulePolicy 自定义规则引用了不存在的策略组时改用节点选择，避免整份配置无法加载。
// 空规则 / 注释行返回 ""，调用方过滤。
func FixRulePolicy(rule string, policies map[string]bool) string {
	rule = strings.TrimSpace(rule)
	if rule == "" || strings.HasPrefix(rule, "#") {
		return ""
	}
	parts := strings.Split(rule, ",")
	i := ruleutil.RulePolicyIndex(parts)
	if i > 0 && !policies[strings.TrimSpace(parts[i])] && !strings.HasSuffix(strings.TrimSpace(parts[i]), ")") {
		parts[i] = base.GSel
	}
	return strings.Join(parts, ",")
}

// SafeDev 设备名清洗：只保留字母数字 _ -，最多 15 字符，空则用 "Meta"。
func SafeDev(name string) string {
	s := safeDevRx.ReplaceAllString(name, "")
	r := []rune(s)
	if len(r) > 15 {
		r = r[:15]
	}
	if len(r) == 0 {
		return "Meta"
	}
	return string(r)
}

var (
	// DnsRx DNS 服务器格式校验（对应 Python DNS_RX）。
	DnsRx = regexp.MustCompile(`^(?:(?:https|tls|quic|udp|tcp|h3)://[^\s#]+|dhcp://[\w.\-]+|system(?:://)?|rcode://\w+|\[?[0-9a-fA-F:.]+\]?(?::\d+)?)(?:#\S.*)?$`)
	// HostKeyRx hosts 域名键格式（对应 Python HOST_KEY_RX）。
	HostKeyRx = regexp.MustCompile(`^(?:\+\.|\*\.)?(?:[a-z0-9_*](?:[a-z0-9_\-*]{0,61}[a-z0-9_*])?\.)*[a-z0-9_\-]{1,63}$`)
	// PolicyDomainRx nameserver-policy 域名匹配项（对应 Python POLICY_DOMAIN_RX）。
	PolicyDomainRx = regexp.MustCompile(`(?i)^(?:\+\.|\*\.|\.)?(?:[a-z0-9_*\-]+\.)*[a-z0-9_*\-]+$`)
	// PolicyNameRx nameserver-policy 非域名匹配项（对应 Python POLICY_NAME_RX）。
	PolicyNameRx   = regexp.MustCompile(`^[\w@!\-.]+$`)
	defaultDNSIPRx = regexp.MustCompile(`^(?:(?:udp|tcp|tls|https)://)?\[?[0-9a-fA-F:.]+\]?(?::\d+)?(?:/|$)`)
	fakeFilterRx   = regexp.MustCompile(`^(?:geosite:|rule-set:)?[\w*+.\-!@:]+$`)
	safeDevRx      = regexp.MustCompile(`[^A-Za-z0-9_\-]`)
)

// NormPolicyMatch nameserver-policy 的键：geosite:a,b / rule-set:x,y / 域名1,域名2
// （mihomo 不支持在一个键里混用）。
func NormPolicyMatch(m string) string {
	var parts []string
	for _, x := range strings.Split(m, ",") {
		if s := strings.TrimSpace(x); s != "" {
			parts = append(parts, s)
		}
	}
	for _, pre := range []string{"geosite:", "rule-set:"} {
		if len(parts) > 0 && strings.HasPrefix(strings.ToLower(parts[0]), pre) {
			out := make([]string, 0, len(parts))
			for _, x := range parts {
				if strings.HasPrefix(strings.ToLower(x), pre) {
					out = append(out, x[len(pre):])
				} else {
					out = append(out, x)
				}
			}
			return pre + strings.Join(out, ",")
		}
	}
	return strings.Join(parts, ",")
}

// PolicyParts 返回 (类型, [名称])：类型为 geosite / rule-set / domain。
func PolicyParts(m string) (string, []string) {
	for _, pre := range []string{"geosite:", "rule-set:"} {
		if strings.HasPrefix(strings.ToLower(m), pre) {
			return pre[:len(pre)-1], strings.Split(m[len(pre):], ",")
		}
	}
	return "domain", strings.Split(m, ",")
}

// IsIPAddr 是否为合法 IP 地址。
func IsIPAddr(v string) bool {
	return net.ParseIP(v) != nil
}

// DnsCfg data.json 里的 dns 设置补齐默认值并规范化（旧版数据没有的键用默认值）。
func DnsCfg(d map[string]any) map[string]any {
	dc := map[string]any{}
	for k, v := range base.DNSDefault {
		dc[k] = v
	}
	if dm := data.Map(d, "dns"); dm != nil {
		for k, v := range dm {
			dc[k] = v
		}
	}
	for _, k := range base.DNSLists {
		var src []any
		if l, ok := dc[k].([]any); ok {
			src = l
		} else {
			src = asAnyList(base.DNSDefault[k])
		}
		out := []string{}
		for _, x := range src {
			if s := strings.TrimSpace(toStr(x)); s != "" {
				out = append(out, s)
			}
		}
		dc[k] = out
	}
	if m := toStr(dc["mode"]); m != "fake-ip" && m != "redir-host" {
		dc["mode"] = "fake-ip"
	}
	if c := toStr(dc["cache"]); c != "arc" && c != "lru" {
		dc["cache"] = "arc"
	}
	for _, k := range []string{"policy", "respect_rules", "block_bypass"} {
		dc[k] = toBool(dc[k])
	}
	hosts := []any{}
	for _, hv := range asAnyList(dc["hosts"]) {
		h, _ := hv.(map[string]any)
		if h == nil || toStr(h["domain"]) == "" || isEmpty(h["value"]) {
			continue
		}
		var raw []any
		switch vv := h["value"].(type) {
		case []any:
			raw = vv
		case []string:
			raw = asAnyList(vv)
		default:
			raw = asAnyList(strings.Fields(strings.ReplaceAll(toStr(vv), ",", " ")))
		}
		vals := []string{}
		for _, x := range raw {
			if s := strings.TrimSpace(toStr(x)); s != "" {
				vals = append(vals, s)
			}
		}
		hosts = append(hosts, map[string]any{
			"domain": strings.ToLower(strings.TrimSpace(toStr(h["domain"]))),
			"value":  vals,
		})
	}
	dc["hosts"] = hosts
	pols := []any{}
	for _, pev := range asAnyList(dc["policies"]) {
		pe, _ := pev.(map[string]any)
		if pe == nil || toStr(pe["match"]) == "" || isEmpty(pe["servers"]) {
			continue
		}
		var sv []string
		switch vv := pe["servers"].(type) {
		case []any:
			for _, x := range vv {
				sv = append(sv, toStr(x))
			}
		case []string:
			sv = vv
		default:
			sv = strings.Split(toStr(vv), ",")
		}
		servers := []string{}
		for _, x := range sv {
			if s := strings.TrimSpace(x); s != "" {
				servers = append(servers, s)
			}
		}
		pols = append(pols, map[string]any{
			"match":   NormPolicyMatch(toStr(pe["match"])),
			"servers": servers,
		})
	}
	dc["policies"] = pols
	return dc
}

// FixDnsPolicy DNS 服务器后缀 #策略组 引用了不存在的组时改用节点选择。
func FixDnsPolicy(server string, policies map[string]bool) string {
	server = strings.TrimSpace(server)
	if pol := ruleutil.DnsPolicyOf(server); pol != "" && !policies[pol] {
		server = strings.SplitN(server, "#", 2)[0] + "#" + base.GSel
	}
	return server
}

// CheckHostEntry 校验一条 hosts 记录，合法返回 ""，否则返回错误描述。
func CheckHostEntry(h map[string]any) string {
	dom := toStr(h["domain"])
	vals := strListOf(h["value"])
	if !HostKeyRx.MatchString(dom) {
		d := dom
		if d == "" {
			d = "(空)"
		}
		return "hosts 域名格式无效：" + d + "（可用 example.com、+.example.com、*.example.com）"
	}
	if len(vals) == 0 {
		return "hosts「" + dom + "」没有填写 IP"
	}
	for _, v := range vals {
		if !IsIPAddr(v) && !(ruleutil.DomainValid(v) && !IsIPAddr(dom)) {
			return "hosts「" + dom + "」的值无效：" + v + "（应为 IP，或单个域名作为别名）"
		}
	}
	allIP := true
	for _, v := range vals {
		if !IsIPAddr(v) {
			allIP = false
			break
		}
	}
	if len(vals) > 1 && !allIP {
		return "hosts「" + dom + "」：别名域名只能填一个"
	}
	return ""
}

// ValidateDns 校验 DNS 配置，返回错误列表（空表示合法）。
func ValidateDns(dc map[string]any, d map[string]any) []string {
	pol := policiesOf(d)
	var errs []string
	labels := [][2]string{
		{"direct", "直连 DNS"}, {"proxy", "代理 DNS"},
		{"default", "默认 DNS"}, {"pserver", "节点域名解析 DNS"},
	}
	for _, kl := range labels {
		key, label := kl[0], kl[1]
		for _, s := range strListOf(dc[key]) {
			switch {
			case !DnsRx.MatchString(s) || strings.HasPrefix(s, "rcode://"):
				errs = append(errs, label+" 格式无效："+s)
			case key == "default" && !defaultDNSIPRx.MatchString(s):
				errs = append(errs, "默认 DNS 必须是 IP（用于解析 DoH 域名）："+s)
			case (key == "default" || key == "pserver") && ruleutil.DnsPolicyOf(s) != "":
				errs = append(errs, label+" 不能指定 #策略组（解析节点域名本身不能经过节点）："+s)
			case ruleutil.DnsPolicyOf(s) != "" && !pol[ruleutil.DnsPolicyOf(s)]:
				errs = append(errs, label+" 引用的策略组不存在："+s)
			}
		}
	}
	for _, s := range strListOf(dc["fake_filter"]) {
		if !fakeFilterRx.MatchString(s) {
			errs = append(errs, "Fake-IP 过滤格式无效："+s)
		}
	}
	for _, hv := range asAnyList(dc["hosts"]) {
		if hm, ok := hv.(map[string]any); ok {
			if e := CheckHostEntry(hm); e != "" {
				errs = append(errs, e)
			}
		}
	}
	seen := map[string]bool{}
	for _, pev := range asAnyList(dc["policies"]) {
		pe, _ := pev.(map[string]any)
		if pe == nil {
			continue
		}
		m := toStr(pe["match"])
		kind, parts := PolicyParts(m)
		for _, part := range parts {
			var ok bool
			if kind != "domain" {
				ok = PolicyNameRx.MatchString(part) && !strings.Contains(part, ":")
			} else {
				ok = PolicyDomainRx.MatchString(part) && !strings.Contains(part, ":")
			}
			if !ok {
				errs = append(errs, "nameserver-policy 匹配项无效："+part+
					"（一条只能是 geosite:a,b、rule-set:x 或 域名列表 +.example.com,example.com，不能混用）")
			}
		}
		if seen[m] {
			errs = append(errs, "nameserver-policy 重复："+m)
		}
		seen[m] = true
		servers := strListOf(pe["servers"])
		if len(servers) == 0 {
			errs = append(errs, "nameserver-policy「"+m+"」没有填写 DNS 服务器")
		}
		for _, s := range servers {
			switch {
			case !DnsRx.MatchString(s):
				errs = append(errs, "nameserver-policy「"+m+"」的 DNS 格式无效："+s)
			case ruleutil.DnsPolicyOf(s) != "" && !pol[ruleutil.DnsPolicyOf(s)]:
				errs = append(errs, "nameserver-policy「"+m+"」引用的策略组不存在："+s)
			}
		}
	}
	if len(strListOf(dc["direct"])) == 0 {
		errs = append(errs, "直连 DNS 不能为空")
	}
	if len(strListOf(dc["default"])) == 0 {
		errs = append(errs, "默认 DNS 不能为空")
	}
	return errs
}

// BadRulePolicies 找出引用了不存在策略组的自定义规则。
func BadRulePolicies(rules []string, d map[string]any) []string {
	pol := policiesOf(d)
	var bad []string
	for _, r := range rules {
		parts := strings.Split(r, ",")
		i := ruleutil.RulePolicyIndex(parts)
		if i <= 0 || !pol[strings.TrimSpace(parts[i])] {
			bad = append(bad, r)
		}
	}
	return bad
}

// policiesOf 构造策略名集合：BuildConfig 生成的 proxy-groups（rules 置空）
// + 内置策略 + 手动节点名。对应 Python validate_dns / bad_rule_policies 开头的 pol 构造。
func policiesOf(d map[string]any) map[string]bool {
	d2 := map[string]any{}
	for k, v := range d {
		d2[k] = v
	}
	d2["rules"] = []any{}
	pol := map[string]bool{}
	if pg, ok := BuildConfig(d2)["proxy-groups"].([]any); ok {
		for _, gv := range pg {
			if gm, ok := gv.(map[string]any); ok {
				pol[data.Str(gm, "name")] = true
			}
		}
	}
	for p := range base.BuiltinPolicies {
		pol[p] = true
	}
	for _, nv := range data.List(d, "nodes") {
		if nm, ok := nv.(map[string]any); ok {
			pol[data.Str(data.Map(nm, "proxy"), "name")] = true
		}
	}
	return pol
}

// WriteConfig 生成配置并原子写入 path（默认 CONF_DIR/config.yaml），返回实际路径。
func WriteConfig(d map[string]any, paths ...string) (string, error) {
	if err := os.MkdirAll(filepath.Join(base.ConfDir, "providers"), 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(base.ConfDir, "config.yaml")
	if len(paths) > 0 && paths[0] != "" {
		path = paths[0]
	}
	if err := WriteAtomic(path, BuildConfig(d)); err != nil {
		return "", err
	}
	markApplied()
	return path, nil
}

var atomicCounter uint64

// WriteAtomic 先生成内容、写临时文件再改名：生成配置抛异常或写到一半断电时，
// 原来的配置文件保持完整。沿用原文件权限。
func WriteAtomic(path string, obj map[string]any) error {
	text, err := Marshal(obj)
	if err != nil {
		return err
	}
	n := atomic.AddUint64(&atomicCounter, 1)
	tmp := fmt.Sprintf("%s.tmp%d-%d", path, os.Getpid(), n)
	if err := os.WriteFile(tmp, []byte(text), 0o644); err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	if fi, err := os.Stat(path); err == nil { // 沿用原文件权限（以前是原地覆盖，权限不变）
		_ = os.Chmod(tmp, fi.Mode().Perm())
	}
	return os.Rename(tmp, path)
}

// MhBin mihomo 系内核的程序路径：smart → mihomo-smart，其余 → mihomo。
func MhBin(kinds ...string) string {
	kind := ""
	if len(kinds) > 0 {
		kind = kinds[0]
	}
	if kind == "" {
		kind = activeCore(nil)
	}
	if kind == "smart" {
		return base.SmartBin
	}
	return base.MihomoBin
}

// CheckConfig 用 mihomo -t 校验配置；没有核心程序时跳过。
// 返回 (是否通过, 错误摘要)。
func CheckConfig(path string, kinds ...string) (bool, string) {
	var kind string
	if len(kinds) > 0 {
		kind = kinds[0]
	}
	b := MhBin(kind)
	if st, err := os.Stat(b); err != nil || st.IsDir() {
		return true, ""
	}
	code, out := shRun(fmt.Sprintf("'%s' -t -d '%s' -f '%s'", b, base.ConfDir, path), 90)
	if code == 0 {
		return true, ""
	}
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		ll := strings.ToLower(l)
		if strings.Contains(l, "level=error") || strings.Contains(l, "level=fatal") ||
			strings.Contains(ll, "test failed") || strings.HasPrefix(l, "panic:") {
			lines = append(lines, l)
		}
	}
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	if tail := strings.Join(lines, "\n"); tail != "" {
		return false, tail
	}
	r := []rune(out)
	if len(r) > 400 {
		r = r[len(r)-400:]
	}
	return false, string(r)
}
