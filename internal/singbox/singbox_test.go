package singbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"shunt/internal/data"
)

// wireTestStubs 给测试接线最小可用的 stub；返回恢复函数
func wireTestStubs(t *testing.T) func() {
	t.Helper()
	saves := []func(){}
	save := func(set func(), restore func()) { set(); saves = append(saves, restore) }

	ob := stubBuildConfig
	save(func() {
		stubBuildConfig = func(d map[string]any) map[string]any {
			return map[string]any{
				"proxies": []any{
					map[string]any{"name": "ss-1", "type": "ss", "server": "1.2.3.4", "port": 8388, "cipher": "aes-256-gcm", "password": "pw"},
				},
				"proxy-groups": []any{
					map[string]any{"name": "🚀 节点选择", "type": "select", "proxies": []any{"ss-1"}},
					map[string]any{"name": "🐟 漏网之鱼", "type": "select", "proxies": []any{"ss-1"}},
				},
				"rules": []any{
					"DOMAIN-SUFFIX,google.com,🚀 节点选择",
					"GEOSITE,cn,DIRECT",
					"GEOIP,private,DIRECT",
					"MATCH,🐟 漏网之鱼",
				},
				"rule-providers": map[string]any{},
			}
		}
	}, func() { stubBuildConfig = ob })

	og := stubGcfg
	save(func() {
		stubGcfg = func(d map[string]any) map[string]any {
			return map[string]any{"url": "https://www.gstatic.com/generate_204", "interval": 60, "tolerance": 50}
		}
	}, func() { stubGcfg = og })

	osb := stubSbSubOutbounds
	save(func() {
		stubSbSubOutbounds = func(d map[string]any) map[string][]SubNode { return map[string][]SubNode{} }
	}, func() { stubSbSubOutbounds = osb })

	od := stubDnsCfg
	save(func() {
		stubDnsCfg = func(d map[string]any) map[string]any {
			return map[string]any{
				"default":     []any{"223.5.5.5"},
				"direct":      []any{"https://doh.pub/dns-query"},
				"proxy":       []any{"https://1.1.1.1/dns-query#🚀 节点选择"},
				"pserver":     []any{},
				"mode":        "fake-ip",
				"fake_filter": []any{"geosite:cn", "+.lan"},
				"policy":      true,
				"hosts":       []any{},
				"policies":    []any{},
			}
		}
	}, func() { stubDnsCfg = od })

	otp := stubTunParams
	save(func() {
		stubTunParams = func(d map[string]any) map[string]any {
			return map[string]any{"enable": false, "stack": "mixed", "device": "Meta", "auto_redirect": true, "strict_route": false}
		}
	}, func() { stubTunParams = otp })

	orp := stubBuildRuleProviders
	save(func() {
		stubBuildRuleProviders = func(d, dc map[string]any) map[string]any { return map[string]any{} }
	}, func() { stubBuildRuleProviders = orp })

	opu := stubProvUpdate
	save(func() {
		stubProvUpdate = func(data map[string][]string) {}
	}, func() { stubProvUpdate = opu })

	orx := stubRx
	save(func() {
		stubRx = func(pattern string) *regexp.Regexp {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil
			}
			return re
		}
	}, func() { stubRx = orx })

	opp := stubPolicyParts
	save(func() {
		stubPolicyParts = func(m string) (string, []string) {
			low := strings.ToLower(m)
			for _, pre := range []string{"geosite:", "rule-set:"} {
				if strings.HasPrefix(low, pre) {
					return pre[:len(pre)-1], strings.Split(m[len(pre):], ",")
				}
			}
			return "domain", strings.Split(m, ",")
		}
	}, func() { stubPolicyParts = opp })

	oip := stubIsIPAddr
	save(func() {
		stubIsIPAddr = func(v string) bool {
			if v == "" {
				return false
			}
			dots, colons := 0, 0
			for _, ch := range v {
				switch {
				case ch >= '0' && ch <= '9':
				case ch == '.':
					dots++
				case ch == ':' || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'):
					colons++
				default:
					return false
				}
			}
			return dots == 3 || colons >= 2
		}
	}, func() { stubIsIPAddr = oip })

	ofp := stubFixDNSPolicy
	save(func() {
		stubFixDNSPolicy = func(server string, policies map[string]bool) string { return server }
	}, func() { stubFixDNSPolicy = ofp })

	// 规则集文件目录指向临时目录，并预置 geosite-cn.srs（否则缺失文件的规则会被正确裁剪）
	oldRuleDir := SBRuleDir
	tmpDir := t.TempDir()
	save(func() { SBRuleDir = tmpDir }, func() { SBRuleDir = oldRuleDir })
	SBRuleDir = tmpDir
	if err := os.WriteFile(filepath.Join(tmpDir, "geosite-cn.srs"), []byte("dummy"), 0o644); err != nil {
		t.Fatalf("写假规则集文件: %v", err)
	}

	return func() {
		for i := len(saves) - 1; i >= 0; i-- {
			saves[i]()
		}
	}
}

func TestBuildSingboxTopLevel(t *testing.T) {
	defer wireTestStubs(t)()
	d := map[string]any{"secret": "s3cr3t", "mode": "rule", "subs": []any{}}
	conf, warn, need := BuildSingbox(d)

	for _, k := range []string{"dns", "outbounds", "route", "inbounds", "log", "experimental"} {
		if _, ok := conf[k]; !ok {
			t.Fatalf("配置缺少顶级字段 %q", k)
		}
	}
	// JSON 可序列化，且字段齐全
	raw, err := json.Marshal(conf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	dns := back["dns"].(map[string]any)
	if _, ok := dns["servers"]; !ok {
		t.Fatal("dns 缺少 servers")
	}
	if _, ok := dns["rules"]; !ok {
		t.Fatal("dns 缺少 rules")
	}
	route := back["route"].(map[string]any)
	rules := route["rules"].([]any)
	if len(rules) == 0 {
		t.Fatal("route.rules 为空")
	}
	if route["final"] != "🐟 漏网之鱼" {
		t.Fatalf("route.final = %v，应为 🐟 漏网之鱼（MATCH 行策略）", route["final"])
	}
	// Fake-IP 细节：inet4_range 必须是 /15，rewrite_ttl 必须为 1
	foundRange, foundTTL := false, false
	for _, s := range dns["servers"].([]any) {
		sm := s.(map[string]any)
		if sm["type"] == "fakeip" {
			if sm["inet4_range"] != "198.18.0.0/15" {
				t.Fatalf("inet4_range = %v，应为 198.18.0.0/15", sm["inet4_range"])
			}
			foundRange = true
		}
	}
	for _, r := range dns["rules"].([]any) {
		rm := r.(map[string]any)
		if rm["server"] == "dns-fake" {
			if ttl, _ := rm["rewrite_ttl"].(float64); ttl != 1 {
				t.Fatalf("rewrite_ttl = %v，应为 1", rm["rewrite_ttl"])
			}
			foundTTL = true
		}
	}
	if !foundRange {
		t.Fatal("dns.servers 里没有 fakeip")
	}
	if !foundTTL {
		t.Fatal("dns.rules 里没有带 rewrite_ttl 的 dns-fake 规则")
	}
	// GEOSITE,cn 翻译成了 rule_set（tag 经 ruleutil.RsTag）
	seenRuleSet := false
	for _, r := range rules {
		rm := r.(map[string]any)
		if rs, ok := rm["rule_set"].([]any); ok {
			for _, x := range rs {
				if x == "geosite-cn" {
					seenRuleSet = true
				}
			}
		}
	}
	if !seenRuleSet {
		t.Fatal("GEOSITE,cn 没有翻译成 rule_set geosite-cn")
	}
	// GEOIP,private 翻译成 ip_is_private
	seenPriv := false
	for _, r := range rules {
		rm := r.(map[string]any)
		if v, ok := rm["ip_is_private"].(bool); ok && v {
			seenPriv = true
		}
	}
	if !seenPriv {
		t.Fatal("GEOIP,private 没有翻译成 ip_is_private")
	}
	// need 含 sb_dns 固定加入的 geosite-cn / geosite-private（kind=geo，非 inline 不过滤）
	if len(need) != 2 {
		t.Fatalf("need 应为 2 个 geo 条目，实际 %v", need)
	}
	if data.Str(need["geosite-cn"].(map[string]any), "kind") != "geo" {
		t.Fatalf("geosite-cn kind 错误: %v", need["geosite-cn"])
	}
	_ = warn
}

func TestBuildSingboxOutboundsOrder(t *testing.T) {
	defer wireTestStubs(t)()
	conf, _, _ := BuildSingbox(map[string]any{})
	obs := conf["outbounds"].([]map[string]any)
	if len(obs) == 0 {
		t.Fatal("outbounds 为空")
	}
	// 组（selector）排在节点前面，最后是 DIRECT
	if obs[0]["type"] != "selector" {
		t.Fatalf("第一个 outbound 应为 selector，实际 %v", obs[0]["type"])
	}
	last := obs[len(obs)-1]
	if last["type"] != "direct" || last["tag"] != "DIRECT" {
		t.Fatalf("最后一个应为 DIRECT，实际 %v", last)
	}
}

func TestSBRulesCond(t *testing.T) {
	defer wireTestStubs(t)()
	var w []string
	tr := NewSBRules(map[string]any{}, map[string]bool{"mixed-in": true}, map[string]string{}, map[string]any{}, &w)

	c := tr.Cond("DOMAIN-SUFFIX", "Example.COM")
	if c.kind != condOK || c.rule["domain_suffix"].([]any)[0] != "example.com" {
		t.Fatalf("DOMAIN-SUFFIX 翻译错误: %+v", c)
	}
	c = tr.Cond("GEOSITE", "CN")
	if c.kind != condOK || c.rule["rule_set"].([]any)[0] != "geosite-cn" {
		t.Fatalf("GEOSITE 翻译错误: %+v", c)
	}
	c = tr.Cond("GEOIP", "LAN")
	if c.kind != condOK || c.rule["ip_is_private"] != true {
		t.Fatalf("GEOIP,lan 应为 ip_is_private: %+v", c)
	}
	c = tr.Cond("DST-PORT", "80,443,8000-8010")
	if c.kind != condOK {
		t.Fatalf("DST-PORT 不支持: %+v", c)
	}
	if ports := c.rule["port"].([]any); len(ports) != 2 || ports[0] != 80 {
		t.Fatalf("DST-PORT ports 错误: %v", c.rule)
	}
	if pr := c.rule["port_range"].([]any); len(pr) != 1 || pr[0] != "8000:8010" {
		t.Fatalf("DST-PORT range 错误: %v", c.rule)
	}
	c = tr.Cond("IN-TYPE", "TPROXY/TUN")
	if c.kind != condNever {
		t.Fatalf("IN-TYPE 无匹配入站应为永不命中: %+v", c)
	}
	c = tr.Cond("DOMAIN-WILDCARD", "+.example.com")
	if c.kind != condOK || c.rule["domain_suffix"].([]any)[0] != "example.com" {
		t.Fatalf("DOMAIN-WILDCARD 翻译错误: %+v", c)
	}
	// 逻辑规则（mihomo AND 语法：AND,((规则1),(规则2)),策略）
	r, _ := tr.Rule("AND,((DOMAIN-SUFFIX,a.com),(DOMAIN-KEYWORD,b)),🚀 节点选择")
	if r == nil || r["type"] != "logical" || r["outbound"] != "🚀 节点选择" {
		t.Fatalf("AND 规则翻译错误: %v", r)
	}
	// 不支持的规则记 warn
	n0 := len(w)
	if r, _ := tr.Rule("SCRIPT,test,🚀 节点选择"); r != nil {
		t.Fatalf("不支持的规则应返回 nil: %v", r)
	}
	if len(w) != n0+1 {
		t.Fatalf("不支持的规则应记一条 warn，实际 %d 条", len(w)-n0)
	}
	// MATCH 跳过
	if r, _ := tr.Rule("MATCH,DIRECT"); r != nil {
		t.Fatalf("MATCH 应返回 nil: %v", r)
	}
}

func TestSbOutbound(t *testing.T) {
	// ss
	o, err := SbOutbound(map[string]any{
		"name": "ss1", "type": "ss", "server": "1.2.3.4", "port": "8388",
		"cipher": "aes-256-gcm", "password": "pw",
	}, "ss1")
	if err != nil {
		t.Fatalf("ss: %v", err)
	}
	if o["type"] != "shadowsocks" || o["method"] != "aes-256-gcm" || o["server_port"] != 8388 {
		t.Fatalf("ss 字段错误: %v", o)
	}
	// vless + reality
	o, err = SbOutbound(map[string]any{
		"name": "v1", "type": "vless", "server": "x.com", "port": 443, "uuid": "u1",
		"tls": true, "servername": "x.com",
		"reality-opts": map[string]any{"public-key": "pk", "short-id": "sid"},
	}, "v1")
	if err != nil {
		t.Fatalf("vless: %v", err)
	}
	tls := o["tls"].(map[string]any)
	if tls["server_name"] != "x.com" {
		t.Fatalf("tls server_name 错误: %v", tls)
	}
	rl := tls["reality"].(map[string]any)
	if rl["public_key"] != "pk" || rl["enabled"] != true {
		t.Fatalf("reality 错误: %v", rl)
	}
	ut := tls["utls"].(map[string]any)
	if ut["fingerprint"] != "chrome" {
		t.Fatalf("reality 默认 utls 应为 chrome: %v", ut)
	}
	// 不支持的协议
	if _, err := SbOutbound(map[string]any{"name": "x", "type": "snell", "server": "h", "port": 1}, "x"); err == nil {
		t.Fatal("snell 应返回错误")
	}
	// _sb 透传
	o, err = SbOutbound(map[string]any{
		"_sb": map[string]any{"type": "wireguard", "server": "h", "server_port": 5},
	}, "wg1")
	if err != nil || o["type"] != "wireguard" || o["tag"] != "wg1" {
		t.Fatalf("_sb 透传错误: %v %v", o, err)
	}
	// ws transport early-data
	o, err = SbOutbound(map[string]any{
		"name": "w1", "type": "vmess", "server": "h", "port": 443, "uuid": "u",
		"network": "ws", "ws-opts": map[string]any{"path": "/p?ed=2048"},
	}, "w1")
	if err != nil {
		t.Fatalf("ws: %v", err)
	}
	tr := o["transport"].(map[string]any)
	if tr["path"] != "/p" || tr["max_early_data"] != 2048 || tr["early_data_header_name"] != "Sec-WebSocket-Protocol" {
		t.Fatalf("ws early-data 错误: %v", tr)
	}
}

func TestYamlLite(t *testing.T) {
	text := `
proxies:
  - name: "节点 [HK]"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: "p@ss"
    udp: true
  - {name: vmess1, type: vmess, server: 5.6.7.8, port: 443}
# 注释行
`
	v, err := YamlLite(text)
	if err != nil {
		t.Fatalf("YamlLite: %v", err)
	}
	m := v.(map[string]any)
	ps := m["proxies"].([]any)
	if len(ps) != 2 {
		t.Fatalf("proxies 应为 2 条，实际 %d", len(ps))
	}
	p0 := ps[0].(map[string]any)
	if p0["name"] != "节点 [HK]" || p0["port"] != 8388 || p0["udp"] != true {
		t.Fatalf("第一条解析错误: %v", p0)
	}
	p1 := ps[1].(map[string]any)
	if p1["name"] != "vmess1" || p1["type"] != "vmess" {
		t.Fatalf("流式行解析错误: %v", p1)
	}
	// 订阅解析入口
	y := SubYaml(text)
	if pl, ok := y["proxies"].([]any); !ok || len(pl) != 2 {
		t.Fatalf("SubYaml proxies 错误: %v", y["proxies"])
	}
}

func TestParseSubTextLinks(t *testing.T) {
	defer wireTestStubs(t)()
	// links stub 在 wireTestStubs 里没有接线，这里单独处理：只测 base64 分支的过滤逻辑需要 parse_link，
	// 因此用 YAML 分支代替
	text := "proxies:\n  - {name: n1, type: ss, server: 1.1.1.1, port: 1}\n"
	nodes, errs := ParseSubText(text, nil, 0)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	if len(nodes) != 1 || nodes[0]["name"] != "n1" {
		t.Fatalf("nodes: %v", nodes)
	}
}

func TestSbRuleSetsKinds(t *testing.T) {
	var w []string
	rs := SbRuleSets(map[string]any{"rule-providers": map[string]any{
		"inline1":  map[string]any{"type": "inline", "behavior": "domain", "payload": []any{"+.a.com", "b.com"}},
		"ad-test":  map[string]any{"type": "http", "path": "./rules/ad.txt"},
		"srs1":     map[string]any{"type": "http", "url": "https://example.com/x.srs"},
		"mrs-meta": map[string]any{"type": "http", "format": "mrs", "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geosite-cn.mrs"},
		"conv":     map[string]any{"type": "http", "behavior": "ipcidr", "url": "https://example.com/list.txt"},
	}}, &w)
	if rs["inline1"].(map[string]any)["kind"] != "inline" {
		t.Fatalf("inline kind 错误: %v", rs["inline1"])
	}
	rules := rs["inline1"].(map[string]any)["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("inline rules 错误: %v", rules)
	}
	if rs["ad-test"].(map[string]any)["kind"] != "adblock" {
		t.Fatalf("adblock kind 错误")
	}
	if rs["srs1"].(map[string]any)["kind"] != "srs" {
		t.Fatalf("srs kind 错误")
	}
	mrs := rs["mrs-meta"].(map[string]any)
	if mrs["kind"] != "srs" || !strings.Contains(mrs["url"].(string), "/sing/") || !strings.HasSuffix(mrs["url"].(string), ".srs") {
		t.Fatalf("mrs→srs 转换错误: %v", mrs)
	}
	if rs["conv"].(map[string]any)["kind"] != "convert" {
		t.Fatalf("convert kind 错误")
	}
}

func TestSbPruneRules(t *testing.T) {
	rules := []any{
		map[string]any{"rule_set": []any{"a", "missing-x"}, "action": "route", "outbound": "DIRECT"},
		map[string]any{"rule_set": []any{"missing-x"}, "action": "route", "outbound": "DIRECT"},
		map[string]any{"type": "logical", "mode": "or", "rules": []any{
			map[string]any{"domain": []any{"a.com"}},
			map[string]any{"rule_set": []any{"missing-x"}},
		}},
		map[string]any{"domain": []any{"b.com"}, "action": "route", "outbound": "DIRECT"},
	}
	out := SbPruneRules(rules, map[string]bool{"missing-x": true})
	if len(out) != 2 {
		t.Fatalf("应保留 2 条，实际 %d: %v", len(out), out)
	}
	if rs := out[0].(map[string]any)["rule_set"].([]any); len(rs) != 1 || rs[0] != "a" {
		t.Fatalf("rule_set 裁剪错误: %v", rs)
	}
}

func TestActiveCoreAndConfPath(t *testing.T) {
	if ActiveCore(map[string]any{"core": "singbox"}) != "singbox" {
		t.Fatal("ActiveCore singbox 错误")
	}
	if ActiveCore(map[string]any{"core": "nope"}) != "mihomo" {
		t.Fatal("未知内核应回退 mihomo")
	}
	if !strings.HasSuffix(CoreConfPath("singbox"), "config.json") {
		t.Fatalf("singbox 配置路径错误: %s", CoreConfPath("singbox"))
	}
	if !strings.HasSuffix(CoreConfPath("mihomo"), "config.yaml") {
		t.Fatalf("mihomo 配置路径错误: %s", CoreConfPath("mihomo"))
	}
}

func TestRuleLinesToSource(t *testing.T) {
	src := ruleLinesToSource("payload:\n  - +.a.com\n  - b.com\n", "domain", "yaml")
	rules := src["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("rules: %v", src)
	}
	r := rules[0].(map[string]any)
	if len(r["domain_suffix"].([]any)) != 1 || len(r["domain"].([]any)) != 1 {
		t.Fatalf("domain 翻译错误: %v", r)
	}
	src = ruleLinesToSource("1.2.3.0/24\n5.6.7.8\n", "ipcidr", "text")
	r = src["rules"].([]any)[0].(map[string]any)
	cidrs := r["ip_cidr"].([]any)
	if len(cidrs) != 2 || cidrs[0] != "1.2.3.0/24" || cidrs[1] != "5.6.7.8/32" {
		t.Fatalf("ipcidr 错误: %v", cidrs)
	}
}
