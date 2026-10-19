package validate

import (
	"strings"
	"testing"

	"shunt/internal/devroute"
)

func mustClean(t *testing.T, key string, v any) any {
	t.Helper()
	out, err := CleanFields(map[string]any{key: v}, []string{key})
	if err != nil {
		t.Fatalf("CleanFields(%s) 报错：%v", key, err)
	}
	return out[key]
}

func mustFail(t *testing.T, key string, v any) {
	t.Helper()
	if _, err := CleanFields(map[string]any{key: v}, []string{key}); err == nil {
		t.Errorf("CleanFields(%s, %v) 应报错", key, v)
	}
}

func TestCleanRulesets(t *testing.T) {
	out := mustClean(t, "rulesets", []any{
		map[string]any{"name": "ads", "url": "https://example.com/a.list"},
	}).([]map[string]any)
	if out[0]["behavior"] != "domain" || out[0]["format"] != "yaml" {
		t.Errorf("默认值不对：%v", out[0])
	}
	if out[0]["target"] != "🚀 节点选择" {
		t.Errorf("target 默认应为 GSel：%v", out[0]["target"])
	}
	mustFail(t, "rulesets", []any{map[string]any{"name": "a,b", "url": "https://x"}})
	mustFail(t, "rulesets", []any{map[string]any{"name": "a", "url": "notaurl"}})
	mustFail(t, "rulesets", []any{map[string]any{"name": "a", "url": "https://x", "behavior": "bad"}})
	mustFail(t, "rulesets", []any{
		map[string]any{"name": "a", "url": "https://x"},
		map[string]any{"name": "a", "url": "https://y"},
	})
	mustFail(t, "rulesets", "notalist")
}

func TestCleanBypass(t *testing.T) {
	out := mustClean(t, "bypass", []any{"192.168.1.1", "10.0.0.0/8", "aa:bb:cc:dd:ee:ff", "", "  "}).([]string)
	if len(out) != 3 {
		t.Errorf("空串应被丢弃，实际 %v", out)
	}
	mustFail(t, "bypass", []any{"not-an-ip"})
	mustFail(t, "bypass", []any{123})
}

func TestBypassOK(t *testing.T) {
	for _, s := range []string{"1.2.3.4", "10.0.0.0/8", "aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "::1", "fd00::/64"} {
		if !BypassOK(s) {
			t.Errorf("BypassOK(%q) 应为 true", s)
		}
	}
	for _, s := range []string{"example.com", "1.2.3.999", "aa:bb:cc"} {
		if BypassOK(s) {
			t.Errorf("BypassOK(%q) 应为 false", s)
		}
	}
}

func TestCleanTests(t *testing.T) {
	out := mustClean(t, "tests", []any{
		map[string]any{"name": "Google", "url": "https://www.google.com/generate_204"},
	}).([]map[string]any)
	if out[0]["name"] != "Google" {
		t.Errorf("tests 不对：%v", out)
	}
	mustFail(t, "tests", []any{})
	mustFail(t, "tests", []any{map[string]any{"name": "x", "url": "bad"}})
}

func TestCleanRules(t *testing.T) {
	out := mustClean(t, "rules", []any{"DOMAIN,example.com,DIRECT", ""}).([]string)
	if len(out) != 1 {
		t.Errorf("空串应被丢弃：%v", out)
	}
	mustFail(t, "rules", []any{"a\nb"})
}

func TestCleanSubs(t *testing.T) {
	sub := map[string]any{"name": "机场", "url": "https://example.com/sub", "filter": "HK"}
	mustClean(t, "subs", []any{sub})
	mustFail(t, "subs", []any{sub, sub}) // 重名
	mustFail(t, "subs", []any{map[string]any{"name": "a", "url": "bad"}})
	mustFail(t, "subs", []any{map[string]any{"name": "a", "url": "https://x", "filter": 1}})
}

func TestSubNameClash(t *testing.T) {
	if got := SubNameClash("机场 A", []string{"机场_A", "其他"}); got != "机场_A" {
		t.Errorf("SubNameClash = %q", got)
	}
	if got := SubNameClash("机场A", []string{"机场_A"}); got != "" {
		t.Errorf("无冲突应返回空，实际 %q", got)
	}
	if got := SubNameClash("机场", []string{"机场"}); got != "" {
		t.Errorf("自身不应算冲突，实际 %q", got)
	}
}

func TestCleanNodes(t *testing.T) {
	node := map[string]any{"proxy": map[string]any{"name": "n1", "type": "ss", "server": "1.2.3.4", "port": 8388.0}}
	mustClean(t, "nodes", []any{node})
	mustFail(t, "nodes", []any{map[string]any{"proxy": map[string]any{"name": "n1", "type": "ss", "server": "1.2.3.4", "port": 0}}})
	mustFail(t, "nodes", []any{map[string]any{"proxy": map[string]any{"name": "n1", "type": "ss", "server": "1.2.3.4", "port": true}}})
	mustFail(t, "nodes", []any{map[string]any{"proxy": map[string]any{"name": "n1", "type": "ss", "server": "1.2.3.4"}}})
	mustFail(t, "nodes", []any{map[string]any{}})
}

func TestCleanCustomGroups(t *testing.T) {
	out := mustClean(t, "custom_groups", []any{
		map[string]any{"name": "g1", "proxies": []any{"a"}},
	}).([]map[string]any)
	if out[0]["name"] != "g1" {
		t.Errorf("custom_groups 不对：%v", out)
	}
	mustFail(t, "custom_groups", []any{
		map[string]any{"name": "g1", "proxies": []any{"a"}},
		map[string]any{"name": "g1", "proxies": []any{"b"}},
	})
	mustFail(t, "custom_groups", []any{map[string]any{"name": "a,b", "proxies": []any{"x"}}})
}

func TestCleanAdblock(t *testing.T) {
	mustClean(t, "adblock", map[string]any{
		"lists": []any{map[string]any{"id": "l1", "url": "https://example.com/l.txt"}},
		"black": []any{"a.com"}, "white": []any{},
	})
	mustFail(t, "adblock", "notadict")
	mustFail(t, "adblock", map[string]any{"lists": []any{map[string]any{"id": "", "url": "https://x"}}})
	mustFail(t, "adblock", map[string]any{"lists": []any{map[string]any{"id": "l1", "url": "bad"}}})
}

func TestCleanDevices(t *testing.T) {
	mustClean(t, "devices", map[string]any{"192.168.1.1": "电视"})
	mustFail(t, "devices", map[string]any{"192.168.1.1": 123})
	mustFail(t, "devices", "notadict")
}

func TestCleanDeviceRoutesVia(t *testing.T) {
	out := mustClean(t, "device_routes", []any{
		map[string]any{"ip": "192.168.1.5", "target": "DIRECT"},
	})
	if routes, ok := out.([]devroute.RouteEntry); !ok || len(routes) != 1 || routes[0].IP != "192.168.1.5" {
		t.Errorf("device_routes 不对：%v", out)
	}
	mustFail(t, "device_routes", []any{map[string]any{"ip": "bad", "target": "DIRECT"}})
}

func TestCleanSchedule(t *testing.T) {
	mustClean(t, "schedule", map[string]any{"sub_update": "03:00", "latency": 30})
	mustFail(t, "schedule", map[string]any{"sub_update": "25:00"})
	mustFail(t, "schedule", map[string]any{"latency": "abc"})
	mustFail(t, "schedule", "notadict")
}

func TestCleanDNS(t *testing.T) {
	mustClean(t, "dns", map[string]any{"direct": []any{"https://doh.pub/dns-query"}})
	mustFail(t, "dns", map[string]any{"direct": "notalist"})
	mustFail(t, "dns", map[string]any{"policies": []any{"bad"}})
	mustFail(t, "dns", "notadict")
}

func TestCleanScalars(t *testing.T) {
	if got := mustClean(t, "sub_interval", 3600.0); got != 3600 {
		t.Errorf("sub_interval = %v", got)
	}
	mustFail(t, "sub_interval", true)
	mustFail(t, "log_limit", 0.0)
	mustClean(t, "log_limit", 5.0)
	mustClean(t, "region_groups", true)
	mustClean(t, "ipv6", false)
	if got := mustClean(t, "tg_token", "  abc "); got != "abc" {
		t.Errorf("tg_token 应 trim：%v", got)
	}
	mustFail(t, "tg_token", 123.0)
	mustClean(t, "mode", "rule")
	mustFail(t, "mode", "bad")
	mustClean(t, "proxy_mode", "")
	mustClean(t, "proxy_mode", "tun")
	mustFail(t, "proxy_mode", "bad")
	// 未知字段原样透传
	out, err := CleanFields(map[string]any{"mystery": 42}, []string{"mystery"})
	if err != nil || out["mystery"] != 42 {
		t.Errorf("未知字段应透传：%v %v", out, err)
	}
	// 非 dict 请求体
	if _, err := CleanFields("nope", []string{"mode"}); err == nil || !strings.Contains(err.Error(), "JSON 对象") {
		t.Errorf("非 dict 应报错，实际 %v", err)
	}
	// 不在 keys 里的字段不输出
	out, _ = CleanFields(map[string]any{"mode": "rule"}, []string{})
	if len(out) != 0 {
		t.Errorf("keys 为空时应返回空：%v", out)
	}
}
