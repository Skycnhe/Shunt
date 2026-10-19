package mihomo

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"shunt/internal/base"
	"shunt/internal/data"
)

// withTestStubs 把跨包 stub 换成确定性测试实现（defer 恢复），
// 语义与 Python 原实现对齐（group_opts / clean_custom_group 为简化移植）。
func withTestStubs(t *testing.T) {
	t.Helper()
	savedActive, savedGcfg, savedGOpts, savedRP, savedRx, savedCCG, savedDRR, savedMA, savedSh :=
		activeCore, gcfg, groupOpts, regionPlan, rxCompile, cleanCustomGroup, deviceRouteRules, markApplied, shRun

	activeCore = func(d map[string]any) string { return "mihomo" }
	gcfg = func(d map[string]any) map[string]any {
		return map[string]any{
			"type": "url-test", "lb": true, "auto": true, "strategy": "consistent-hashing",
			"interval": 60, "tolerance": 0, "url": "https://www.gstatic.com/generate_204",
			"extra": true, "other": true, "lazy": true, "lgbm": false,
		}
	}
	groupOpts = func(typ string, gc map[string]any, extra map[string]any) map[string]any {
		g := map[string]any{"type": typ}
		if typ != "select" {
			url := data.Str(gc, "url")
			if extra != nil {
				if u := data.Str(extra, "url"); u != "" {
					url = u
				}
			}
			iv := data.Int(gc, "interval")
			if extra != nil {
				if e := data.Int(extra, "interval"); e != 0 {
					iv = e
				}
			}
			g["url"] = url
			g["interval"] = iv
			g["lazy"] = data.Bool(gc, "lazy")
			if typ == "url-test" || typ == "smart" {
				tol := data.Int(gc, "tolerance")
				if extra != nil {
					if v, ok := extra["tolerance"]; ok && v != nil && toStr(v) != "" {
						tol = data.Int(extra, "tolerance")
					}
				}
				g["tolerance"] = tol
			}
			if typ == "load-balance" {
				st := "consistent-hashing"
				if extra != nil {
					if s := data.Str(extra, "strategy"); s != "" {
						st = s
					}
				}
				g["strategy"] = st
			}
		}
		return g
	}
	regionPlan = func(d map[string]any, names []string, use []string) []regionPlanItem {
		return []regionPlanItem{
			{Rname: "🇭🇰 香港", Flt: "香港|HK", Matched: []string{"HK-01"}, Total: 3},
			{Rname: "🇯🇵 日本", Flt: "日本|JP", Matched: []string{"JP-01"}, Total: 1},
		}
	}
	rxCompile = func(pattern string) *regexp.Regexp {
		r, err := regexp.Compile(pattern)
		if err != nil {
			return nil
		}
		return r
	}
	cleanCustomGroup = func(cg map[string]any) (map[string]any, error) {
		name := strings.TrimSpace(data.Str(cg, "name"))
		if name == "" {
			return nil, errors.New("名称不能为空")
		}
		typ := data.Str(cg, "type")
		if typ == "" {
			typ = "select"
		}
		var members []string
		for _, m := range data.List(cg, "proxies") {
			if s := strings.TrimSpace(toStr(m)); s != "" && !containsStr(members, s) {
				members = append(members, s)
			}
		}
		subs := true
		if v, ok := cg["subs"]; ok {
			subs = toBool(v)
		}
		expose := true
		if v, ok := cg["expose"]; ok {
			expose = toBool(v)
		}
		return map[string]any{
			"name": name, "type": typ, "proxies": members,
			"filter": strings.TrimSpace(data.Str(cg, "filter")),
			"subs":   subs, "expose": expose,
			"icon": strings.TrimSpace(data.Str(cg, "icon")),
		}, nil
	}
	deviceRouteRules = func(d map[string]any, policies map[string]bool) []string { return nil }
	markApplied = func() {}
	shRun = func(cmd string, timeoutSec int) (int, string) { return 0, "" }

	t.Cleanup(func() {
		activeCore, gcfg, groupOpts, regionPlan, rxCompile = savedActive, savedGcfg, savedGOpts, savedRP, savedRx
		cleanCustomGroup, deviceRouteRules, markApplied, shRun = savedCCG, savedDRR, savedMA, savedSh
	})
}

func testData() map[string]any {
	d := base.DeepCopyDefault()
	d["secret"] = "testsecret"
	d["mode"] = "rule"
	d["subs"] = []any{
		map[string]any{"name": "sub1", "url": "https://example.com/sub"},
	}
	d["nodes"] = []any{
		map[string]any{"proxy": map[string]any{"name": "HK-01", "type": "ss", "server": "1.2.3.4", "port": 8388}},
		map[string]any{"proxy": map[string]any{"name": "JP-01", "type": "ss", "server": "5.6.7.8", "port": 8388}},
		map[string]any{"proxy": map[string]any{"name": "US-01", "type": "ss", "server": "9.10.11.12", "port": 8388}},
	}
	d["custom_groups"] = []any{
		map[string]any{
			"name": "我的组", "type": "select",
			"proxies": []any{"HK-01", "不存在的节点"},
			"filter":  "", "expose": true,
		},
	}
	d["rules"] = []any{
		"DOMAIN-SUFFIX,example.com,🚀 节点选择",
		"# 这是注释",
		"",
		"DOMAIN-SUFFIX,bad.com,不存在的组",
	}
	return d
}

func groupByName(groups []any, name string) map[string]any {
	for _, gv := range groups {
		if gm, ok := gv.(map[string]any); ok && data.Str(gm, "name") == name {
			return gm
		}
	}
	return nil
}

func TestBuildConfig(t *testing.T) {
	withTestStubs(t)
	d := testData()
	cfg := BuildConfig(d)

	// 顶层关键字段（与 Python 版字段名一致）
	if cfg["mixed-port"] != base.Mixed {
		t.Errorf("mixed-port = %v, want %v", cfg["mixed-port"], base.Mixed)
	}
	if cfg["tproxy-port"] != 7893 {
		t.Errorf("tproxy-port = %v", cfg["tproxy-port"])
	}
	if cfg["mode"] != "rule" {
		t.Errorf("mode = %v", cfg["mode"])
	}
	if cfg["secret"] != "testsecret" {
		t.Errorf("secret = %v", cfg["secret"])
	}
	if cfg["external-controller"] != "127.0.0.1:9090" {
		t.Errorf("external-controller = %v", cfg["external-controller"])
	}
	for _, k := range []string{"proxy-groups", "dns", "rules", "proxies", "proxy-providers", "rule-providers", "tun", "hosts", "sniffer"} {
		if _, ok := cfg[k]; !ok {
			t.Errorf("缺少顶层字段 %q", k)
		}
	}

	// proxies
	proxies, _ := cfg["proxies"].([]any)
	if len(proxies) != 3 {
		t.Fatalf("proxies 数量 = %d, want 3", len(proxies))
	}
	if data.Str(proxies[0].(map[string]any), "name") != "HK-01" {
		t.Errorf("proxies[0].name = %v", proxies[0])
	}

	// proxy-providers
	pp, _ := cfg["proxy-providers"].(map[string]any)
	pv, ok := pp["sub1"].(map[string]any)
	if !ok {
		t.Fatalf("proxy-providers 缺少 sub1: %v", pp)
	}
	if pv["type"] != "http" || pv["path"] != "./providers/sub1.yaml" || pv["interval"] != 86400 {
		t.Errorf("provider sub1 字段异常: %v", pv)
	}
	hc, _ := pv["health-check"].(map[string]any)
	if hc["url"] != base.Hc || hc["enable"] != true {
		t.Errorf("health-check 异常: %v", hc)
	}

	// proxy-groups：🚀 节点选择 / 地区组 / 手动 / 自动 / 直连 / side groups / 自定义组
	groups, _ := cfg["proxy-groups"].([]any)
	if len(groups) == 0 {
		t.Fatal("proxy-groups 为空")
	}
	sel := groupByName(groups, base.GSel)
	if sel == nil {
		t.Fatalf("缺少 %q 组", base.GSel)
	}
	wantSelProxies := []string{
		data.AutoName("🇯🇵 日本"), data.AutoName("🇭🇰 香港"), data.LbName("🇭🇰 香港", "consistent-hashing"),
		base.GManual, base.GAuto, base.GDirect,
	}
	gotSel := strListOf(sel["proxies"])
	if len(gotSel) != len(wantSelProxies) {
		t.Fatalf("节点选择 proxies = %v, want %v", gotSel, wantSelProxies)
	}
	for i := range wantSelProxies {
		if gotSel[i] != wantSelProxies[i] {
			t.Fatalf("节点选择 proxies = %v, want %v", gotSel, wantSelProxies)
		}
	}
	// 地区组按 AutoOrder/LbOrder 排序：日本(0) 在 香港(2) 前；负载均衡在最后
	autoHK := groupByName(groups, data.AutoName("🇭🇰 香港"))
	if autoHK == nil || autoHK["type"] != "url-test" {
		t.Errorf("香港竞技组异常: %v", autoHK)
	} else {
		if got := strListOf(autoHK["proxies"]); len(got) != 1 || got[0] != "HK-01" {
			t.Errorf("香港竞技组 proxies = %v", got)
		}
		if autoHK["filter"] != "香港|HK" {
			t.Errorf("香港竞技组 filter = %v", autoHK["filter"])
		}
		if _, ok := autoHK["use"].([]any); !ok {
			t.Errorf("香港竞技组缺少 use: %v", autoHK)
		}
	}
	lbHK := groupByName(groups, data.LbName("🇭🇰 香港", "consistent-hashing"))
	if lbHK == nil || lbHK["type"] != "load-balance" || lbHK["strategy"] != "consistent-hashing" {
		t.Errorf("香港负载均衡组异常: %v", lbHK)
	}
	if groupByName(groups, data.AutoName("🇯🇵 日本")) == nil {
		t.Errorf("缺少日本竞技组")
	}
	manual := groupByName(groups, base.GManual)
	if manual == nil {
		t.Fatalf("缺少手动选择组")
	}
	if got := strListOf(manual["proxies"]); len(got) != 3 || got[0] != "HK-01" {
		t.Errorf("手动选择 proxies = %v", got)
	}
	if groupByName(groups, base.GDirect) == nil {
		t.Errorf("缺少直连组")
	}
	for _, sg := range base.SideGroups {
		if groupByName(groups, sg) == nil {
			t.Errorf("缺少 side group %q", sg)
		}
	}
	// 自定义组：非 strict 下过滤掉不存在的成员
	cg := groupByName(groups, "我的组")
	if cg == nil {
		t.Fatalf("缺少自定义组")
	}
	if got := strListOf(cg["proxies"]); len(got) != 1 || got[0] != "HK-01" {
		t.Errorf("自定义组 proxies = %v, want [HK-01]", got)
	}

	// dns 段
	dns, _ := cfg["dns"].(map[string]any)
	if dns["listen"] != "0.0.0.0:1053" || dns["enhanced-mode"] != "fake-ip" {
		t.Errorf("dns 段异常: %v", dns)
	}
	if dns["fake-ip-range"] != "198.18.0.1/16" {
		t.Errorf("fake-ip-range = %v", dns["fake-ip-range"])
	}
	nsp, ok := dns["nameserver-policy"].(map[string]any)
	if !ok {
		t.Fatalf("缺少 nameserver-policy")
	}
	if _, ok := nsp["rule-set:cn-apps"]; !ok {
		t.Errorf("nameserver-policy 缺少 rule-set:cn-apps: %v", nsp)
	}
	if _, ok := nsp["geosite:cn,private"]; !ok {
		t.Errorf("nameserver-policy 缺少 geosite:cn,private")
	}
	ns := strListOf(dns["nameserver"])
	if len(ns) != 2 || !strings.Contains(ns[0], "1.1.1.1") {
		t.Errorf("nameserver = %v", ns)
	}

	// rule-providers 含 cn-apps
	rp, _ := cfg["rule-providers"].(map[string]any)
	cnapps, ok := rp["cn-apps"].(map[string]any)
	if !ok || cnapps["type"] != "inline" {
		t.Errorf("rule-providers 缺少 cn-apps: %v", rp)
	}

	// rules：自定义规则（注释/空行过滤、坏策略修正）+ 内置收尾
	rules := strListOf(cfg["rules"])
	if len(rules) == 0 {
		t.Fatal("rules 为空")
	}
	if rules[0] != "DOMAIN-SUFFIX,example.com,🚀 节点选择" {
		t.Errorf("rules[0] = %q", rules[0])
	}
	if rules[1] != "DOMAIN-SUFFIX,bad.com,🚀 节点选择" {
		t.Errorf("坏策略未修正为节点选择: rules[1] = %q", rules[1])
	}
	if rules[len(rules)-1] != "MATCH,"+base.GFinal {
		t.Errorf("rules 收尾 = %q", rules[len(rules)-1])
	}
	found := false
	for _, r := range rules {
		if r == "DOMAIN-SUFFIX,dangbei.com,DIRECT" {
			found = true
		}
	}
	if !found {
		t.Errorf("rules 缺少 dangbei.com 直连规则")
	}

	// tun 默认关闭
	tun, _ := cfg["tun"].(map[string]any)
	if tun["enable"] != false {
		t.Errorf("tun = %v, want {enable:false}", tun)
	}

	// sniffer
	sniffer, _ := cfg["sniffer"].(map[string]any)
	if sniffer["enable"] != true {
		t.Errorf("sniffer.enable = %v", sniffer["enable"])
	}
	sniff, _ := sniffer["sniff"].(map[string]any)
	httpSniff, _ := sniff["HTTP"].(map[string]any)
	ports, _ := httpSniff["ports"].([]any)
	if len(ports) != 2 || ports[0] != 80 || ports[1] != "8080-8880" {
		t.Errorf("sniffer HTTP ports = %v", ports)
	}

	// YAML 序列化：含关键段、键引号正确
	yml, err := Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, want := range []string{
		"proxy-groups:", "mixed-port: 7890", `"rule-set:cn-apps":`,
		"external-controller: 127.0.0.1:9090",
	} {
		if !strings.Contains(yml, want) {
			t.Errorf("YAML 缺少 %q", want)
		}
	}
}

func TestDnsCfg(t *testing.T) {
	dc := DnsCfg(map[string]any{})
	if toStr(dc["mode"]) != "fake-ip" {
		t.Errorf("mode = %v", dc["mode"])
	}
	if len(strListOf(dc["direct"])) == 0 || len(strListOf(dc["default"])) == 0 {
		t.Errorf("direct/default 为空: %v", dc)
	}
	if toBool(dc["policy"]) != true {
		t.Errorf("policy 默认应为 true")
	}
	// 非法 mode 回退
	dc2 := DnsCfg(map[string]any{"dns": map[string]any{"mode": "bogus", "cache": "bogus"}})
	if toStr(dc2["mode"]) != "fake-ip" || toStr(dc2["cache"]) != "arc" {
		t.Errorf("非法 mode/cache 未回退: %v %v", dc2["mode"], dc2["cache"])
	}
	// hosts 规范化
	dc3 := DnsCfg(map[string]any{"dns": map[string]any{
		"hosts": []any{map[string]any{"domain": "Example.COM", "value": "1.2.3.4, 5.6.7.8"}},
	}})
	hosts := asAnyList(dc3["hosts"])
	if len(hosts) != 1 {
		t.Fatalf("hosts = %v", dc3["hosts"])
	}
	hm := hosts[0].(map[string]any)
	if hm["domain"] != "example.com" {
		t.Errorf("domain 未小写: %v", hm["domain"])
	}
	if got := strListOf(hm["value"]); len(got) != 2 || got[0] != "1.2.3.4" {
		t.Errorf("value = %v", hm["value"])
	}
	// policies 键规范化
	dc4 := DnsCfg(map[string]any{"dns": map[string]any{
		"policies": []any{map[string]any{"match": "geosite:cn, geolocation-!cn", "servers": []any{"223.5.5.5"}}},
	}})
	pols := asAnyList(dc4["policies"])
	if len(pols) != 1 || toStr(pols[0].(map[string]any)["match"]) != "geosite:cn,geolocation-!cn" {
		t.Errorf("policies 规范化异常: %v", dc4["policies"])
	}
}

func TestFixRulePolicy(t *testing.T) {
	pol := map[string]bool{base.GSel: true, "HK-01": true}
	if got := FixRulePolicy("DOMAIN-SUFFIX,example.com,🚀 节点选择", pol); got != "DOMAIN-SUFFIX,example.com,🚀 节点选择" {
		t.Errorf("合法规则被改动: %q", got)
	}
	if got := FixRulePolicy("DOMAIN-SUFFIX,example.com,不存在的组", pol); got != "DOMAIN-SUFFIX,example.com,"+base.GSel {
		t.Errorf("坏策略未修正: %q", got)
	}
	if got := FixRulePolicy("# 注释", pol); got != "" {
		t.Errorf("注释行应返回空: %q", got)
	}
	if got := FixRulePolicy("  ", pol); got != "" {
		t.Errorf("空行应返回空: %q", got)
	}
	// 以 ) 结尾的（如 AND(...) 嵌套策略）不修正
	if got := FixRulePolicy("AND,((RULE-SET,x)),REJECT)", pol); got != "AND,((RULE-SET,x)),REJECT)" {
		t.Errorf(") 结尾不应修正: %q", got)
	}
}

func TestSafeDev(t *testing.T) {
	if SafeDev("Meta") != "Meta" {
		t.Errorf("SafeDev(Meta) = %q", SafeDev("Meta"))
	}
	if SafeDev("a/b\\c:d") != "abcd" {
		t.Errorf("SafeDev 清洗异常: %q", SafeDev("a/b\\c:d"))
	}
	if SafeDev("") != "Meta" {
		t.Errorf("空设备名应回退 Meta: %q", SafeDev(""))
	}
	if got := SafeDev("12345678901234567890"); got != "123456789012345" {
		t.Errorf("超长未截断: %q", got)
	}
}

func TestNormPolicyMatchAndParts(t *testing.T) {
	if got := NormPolicyMatch("geosite:cn, geolocation-!cn"); got != "geosite:cn,geolocation-!cn" {
		t.Errorf("NormPolicyMatch = %q", got)
	}
	if got := NormPolicyMatch("+.example.com, example.org"); got != "+.example.com,example.org" {
		t.Errorf("NormPolicyMatch = %q", got)
	}
	kind, parts := PolicyParts("rule-set:ad-allow,ad-custom")
	if kind != "rule-set" || len(parts) != 2 || parts[0] != "ad-allow" {
		t.Errorf("PolicyParts = %q %v", kind, parts)
	}
	kind, parts = PolicyParts("+.example.com")
	if kind != "domain" || len(parts) != 1 {
		t.Errorf("PolicyParts = %q %v", kind, parts)
	}
}

func TestTunParams(t *testing.T) {
	p := TunParams(map[string]any{})
	if toBool(p["enable"]) || toStr(p["stack"]) != "mixed" || toStr(p["device"]) != "Meta" {
		t.Errorf("TunParams 默认异常: %v", p)
	}
	if toBool(p["auto_redirect"]) != true {
		t.Errorf("auto_redirect 默认应为 true: %v", p)
	}
	p2 := TunParams(map[string]any{
		"proxy_mode": "tun",
		"tun":        map[string]any{"stack": "gvisor", "device": "eth0!@#", "auto_redirect": false, "strict_route": true},
	})
	if !toBool(p2["enable"]) || toStr(p2["stack"]) != "gvisor" || toStr(p2["device"]) != "eth0" {
		t.Errorf("TunParams = %v", p2)
	}
	if toBool(p2["auto_redirect"]) || !toBool(p2["strict_route"]) {
		t.Errorf("TunParams 开关异常: %v", p2)
	}
	// 非法 stack 回退 mixed
	p3 := TunParams(map[string]any{"tun": map[string]any{"stack": "bogus"}})
	if toStr(p3["stack"]) != "mixed" {
		t.Errorf("非法 stack 未回退: %v", p3["stack"])
	}
	if got := MihomoTun(map[string]any{})["enable"]; got != false {
		t.Errorf("MihomoTun 默认应关闭: %v", got)
	}
}

func TestValidateDns(t *testing.T) {
	withTestStubs(t)
	d := testData()
	dc := DnsCfg(d)
	if errs := ValidateDns(dc, d); len(errs) != 0 {
		t.Errorf("默认 DNS 配置应合法，errs = %v", errs)
	}
	bad := DnsCfg(map[string]any{"dns": map[string]any{
		"direct":  []any{"not a dns"},
		"default": []any{"https://doh.pub/dns-query"},
		"proxy":   []any{"https://1.1.1.1/dns-query#不存在的组"},
		"hosts":   []any{map[string]any{"domain": "bad domain!", "value": []any{"1.2.3.4"}}},
		"policies": []any{
			// 空 servers 的条目会被 DnsCfg 丢弃（与 Python 一致），直测部分见下
			map[string]any{"match": "geosite:cn", "servers": []any{"223.5.5.5"}},
		},
		"fake_filter": []any{"ok", "bad filter!!"},
	}})
	errs := ValidateDns(bad, d)
	joined := strings.Join(errs, "\n")
	for _, want := range []string{"直连 DNS 格式无效", "默认 DNS 必须是 IP", "引用的策略组不存在", "hosts 域名格式无效", "Fake-IP 过滤格式无效"} {
		if !strings.Contains(joined, want) {
			t.Errorf("缺少错误 %q，errs = %v", want, errs)
		}
	}
	// 直测 ValidateDns 的 policies 分支（绕过 DnsCfg 的丢弃逻辑）
	dc2 := DnsCfg(d)
	dc2["policies"] = []any{
		map[string]any{"match": "geosite:cn", "servers": []string{}},
		map[string]any{"match": "geosite:cn", "servers": []string{"223.5.5.5"}},
		map[string]any{"match": "bad mix:xx", "servers": []string{"223.5.5.5"}},
	}
	errs2 := ValidateDns(dc2, d)
	joined2 := strings.Join(errs2, "\n")
	for _, want := range []string{"没有填写 DNS 服务器", "nameserver-policy 重复", "nameserver-policy 匹配项无效"} {
		if !strings.Contains(joined2, want) {
			t.Errorf("缺少错误 %q，errs = %v", want, errs2)
		}
	}
}

func TestBadRulePolicies(t *testing.T) {
	withTestStubs(t)
	d := testData()
	bad := BadRulePolicies([]string{
		"DOMAIN-SUFFIX,a.com,🚀 节点选择",
		"DOMAIN-SUFFIX,b.com,不存在的组",
		"GEOIP,CN,DIRECT",
	}, d)
	if len(bad) != 1 || bad[0] != "DOMAIN-SUFFIX,b.com,不存在的组" {
		t.Errorf("BadRulePolicies = %v", bad)
	}
}

func TestCheckHostEntry(t *testing.T) {
	if e := CheckHostEntry(map[string]any{"domain": "example.com", "value": []string{"1.2.3.4"}}); e != "" {
		t.Errorf("合法 hosts 报错: %s", e)
	}
	if e := CheckHostEntry(map[string]any{"domain": "bad domain", "value": []string{"1.2.3.4"}}); e == "" {
		t.Errorf("非法域名未报错")
	}
	if e := CheckHostEntry(map[string]any{"domain": "example.com", "value": []string{}}); !strings.Contains(e, "没有填写 IP") {
		t.Errorf("空值未报错: %s", e)
	}
	if e := CheckHostEntry(map[string]any{"domain": "example.com", "value": []string{"1.2.3.4", "alias.example.com"}}); !strings.Contains(e, "只能填一个") {
		t.Errorf("多别名未报错: %s", e)
	}
}

func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	obj := map[string]any{"mixed-port": 7890, "rules": []any{"MATCH,DIRECT"}}
	if err := WriteAtomic(path, obj); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(raw), "mixed-port: 7890") {
		t.Errorf("写入内容异常:\n%s", raw)
	}
	// 覆盖写：临时文件不应残留
	if err := WriteAtomic(path, obj); err != nil {
		t.Fatalf("WriteAtomic 覆盖: %v", err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("残留临时文件: %v", ents)
	}
}

func TestYamlQuoting(t *testing.T) {
	yml, err := Marshal(map[string]any{
		"plain":    "hello",
		"colon":    "a: b",
		"numlike":  "8080",
		"boollike": "yes",
		"special":  "*.lan",
		"unicode":  "🚀 节点选择",
		"ports":    []any{80, "8080-8880"},
		"nested":   map[string]any{"rule-set:cn-apps": []any{"x"}},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, want := range []string{
		"plain: hello",
		`colon: "a: b"`,
		`numlike: "8080"`,
		`boollike: "yes"`,
		`special: "*.lan"`,
		"unicode: 🚀 节点选择",
		"- 80",
		"- 8080-8880",
		`"rule-set:cn-apps":`,
	} {
		if !strings.Contains(yml, want) {
			t.Errorf("YAML 缺少 %q\n%s", want, yml)
		}
	}
}

func TestMhBin(t *testing.T) {
	withTestStubs(t)
	if MhBin() != base.MihomoBin {
		t.Errorf("MhBin() = %q", MhBin())
	}
	if MhBin("smart") != base.SmartBin {
		t.Errorf("MhBin(smart) = %q", MhBin("smart"))
	}
	// 没有核心程序时跳过校验
	ok, msg := CheckConfig("/nonexistent/path.yaml")
	if !ok || msg != "" {
		t.Errorf("CheckConfig 无程序时应跳过: %v %q", ok, msg)
	}
}
