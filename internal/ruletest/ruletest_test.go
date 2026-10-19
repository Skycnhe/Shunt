package ruletest

import (
	"reflect"
	"testing"
)

func TestCleanTarget(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://www.Google.com/path?q=1", "www.google.com"},
		{"http://example.com:8080/x", "example.com"},
		{"  [2001:db8::1]:443  ", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"1.2.3.4", "1.2.3.4"},
		{"Example.COM", "example.com"},
		{"ftp://a.b.c/d?e=f", "a.b.c"},
		{"", ""},
	}
	for _, c := range cases {
		if got := CleanTarget(c.in); got != c.want {
			t.Errorf("CleanTarget(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsIP(t *testing.T) {
	if !IsIP("1.2.3.4") || !IsIP("::1") || !IsIP("2001:db8::1") {
		t.Error("IsIP 应识别合法 IP")
	}
	if IsIP("example.com") || IsIP("") || IsIP("999.1.1.1") {
		t.Error("IsIP 不应把域名/非法串当 IP")
	}
}

func TestChainOf(t *testing.T) {
	proxies := map[string]any{
		"a": map[string]any{"now": "b"},
		"b": map[string]any{"now": "c"},
		"c": map[string]any{"now": ""},
	}
	if got, want := ChainOf("a", proxies), []string{"a", "b", "c"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ChainOf = %v, want %v", got, want)
	}
	// 环：b 指回 a，应停住不死循环
	loop := map[string]any{
		"a": map[string]any{"now": "b"},
		"b": map[string]any{"now": "a"},
	}
	if got, want := ChainOf("a", loop), []string{"a", "b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ChainOf 环 = %v, want %v", got, want)
	}
	// 终点不在 proxies 里
	if got, want := ChainOf("x", proxies), []string{"x"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ChainOf 未知 = %v, want %v", got, want)
	}
}
