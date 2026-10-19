package dnsleak

import (
	"strings"
	"testing"
)

func TestIsCnDNS(t *testing.T) {
	for _, s := range []string{
		"https://doh.pub/dns-query",
		"https://dns.alidns.com/dns-query",
		"223.5.5.5",
		"119.29.29.29",
		"system",
		"dhcp://eth0",
		"https://doh.pub/dns-query#x", // # 后缀应先剥离
	} {
		if !IsCnDNS(s) {
			t.Errorf("IsCnDNS(%q) 应为 true", s)
		}
	}
	for _, s := range []string{
		"https://1.1.1.1/dns-query",
		"https://dns.google/dns-query#🚀 节点选择",
		"8.8.8.8",
		"rcode://test",
	} {
		if IsCnDNS(s) {
			t.Errorf("IsCnDNS(%q) 应为 false", s)
		}
	}
}

func TestHostMatch(t *testing.T) {
	cases := []struct {
		pat, name string
		want      bool
	}{
		{"+.example.com", "a.example.com", true},
		{"+.example.com", "example.com", true},
		{"+.example.com", "aexample.com", false},
		{".example.com", "a.example.com", true},
		{".example.com", "example.com", false},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "a.b.example.com", false}, // * 只跨一级
		{"example.com", "example.com", true},
		{"example.com", "a.example.com", false},
		{"EXAMPLE.com", "example.com", true}, // pattern 小写化
	}
	for _, c := range cases {
		if got := HostMatch(c.pat, c.name); got != c.want {
			t.Errorf("HostMatch(%q, %q) = %v, want %v", c.pat, c.name, got, c.want)
		}
	}
}

func TestAntileakDNS(t *testing.T) {
	cur := map[string]any{
		"mode":   "redir-host",
		"direct": []any{"https://doh.pub/dns-query", "https://doh.pub/dns-query#x"},
		"proxy":  []any{"https://doh.pub/dns-query", "https://1.1.1.1/dns-query", "rcode://fake"},
		"pserver": []any{
			"223.5.5.5",                 // 国内、无 # → 保留
			"223.5.5.5#note",            // 有 # → 丢弃
			"https://1.1.1.1/dns-query", // 非国内 → 丢弃
		},
		"fake_filter": []any{},
		"policies":    []any{},
	}
	got := AntileakDNS(cur)
	if got["mode"] != "fake-ip" || got["respect_rules"] != true || got["policy"] != true || got["block_bypass"] != true {
		t.Errorf("基础开关不对：%v", got)
	}
	// 原 cur 不应被改动（深拷贝）
	if cur["mode"] != "redir-host" {
		t.Error("AntileakDNS 改动了输入")
	}
	proxy := strsOf(got["proxy"])
	if len(proxy) != 1 || proxy[0] != "https://1.1.1.1/dns-query#🚀 节点选择" {
		t.Errorf("proxy 不对：%v", proxy)
	}
	direct := strsOf(got["direct"])
	if len(direct) != 1 || direct[0] != "https://doh.pub/dns-query" {
		t.Errorf("direct 不对：%v", direct)
	}
	pserver := strsOf(got["pserver"])
	if len(pserver) != 1 || pserver[0] != "223.5.5.5" {
		t.Errorf("pserver 不对：%v", pserver)
	}
	if len(strsOf(got["fake_filter"])) == 0 {
		t.Error("fake_filter 为空时应用默认值")
	}
}

func TestAntileakDNSFallback(t *testing.T) {
	// proxy 全是国内 DNS → 回退 DNS_DEFAULT["proxy"]
	got := AntileakDNS(map[string]any{
		"direct": []any{}, "proxy": []any{"https://doh.pub/dns-query"},
		"pserver": []any{}, "fake_filter": []any{"x"}, "policies": []any{},
	})
	proxy := strsOf(got["proxy"])
	if len(proxy) != 2 || !strings.Contains(proxy[0], "1.1.1.1") {
		t.Errorf("应回退默认代理 DNS：%v", proxy)
	}
	if len(strsOf(got["direct"])) != 2 {
		t.Errorf("direct 为空时应回退默认值：%v", got["direct"])
	}
	if len(strsOf(got["fake_filter"])) != 1 {
		t.Error("非空 fake_filter 不应被覆盖")
	}
}

func TestResolvServersMissing(t *testing.T) {
	t.Setenv("PANEL_RESOLV", "/nonexistent-resolv-test")
	if got := ResolvServers(); got != nil {
		t.Errorf("读不到应返回 nil：%v", got)
	}
}
