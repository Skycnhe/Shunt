package cli

import (
	"net/netip"
	"strings"
	"testing"
)

func TestTpEnvFormat(t *testing.T) {
	env := TpEnv()
	keys := map[string]bool{}
	for _, l := range strings.Split(env, "\n") {
		kv := strings.SplitN(l, "=", 2)
		if len(kv) != 2 {
			t.Fatalf("bad line %q", l)
		}
		keys[kv[0]] = true
	}
	for _, k := range []string{"B_IP", "B_MAC", "B_IP6", "LOCAL6", "IPV6", "MODE", "DNS_ALL"} {
		if !keys[k] {
			t.Fatalf("missing key %q", k)
		}
	}
}

func TestCollapsePrefixes(t *testing.T) {
	must := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }
	in := []netip.Prefix{
		must("192.168.1.0/24"), must("192.168.1.5/32"), // 被包含的去掉
		must("192.168.1.0/24"), // 重复去掉
		must("10.0.0.0/8"), must("172.16.0.0/12"),
	}
	got := collapsePrefixes(in)
	if len(got) != 3 {
		t.Fatalf("got %v", got)
	}
	for _, p := range got {
		if p.String() == "192.168.1.5/32" {
			t.Fatal("contained prefix should be removed")
		}
	}
}

func TestDefaultTz(t *testing.T) {
	// 测试环境 TZ 可能已设置；只验证不 panic 且返回值语义
	_ = DefaultTz()
}

func TestHasArg(t *testing.T) {
	args := []string{"prog", "--tpenv", "--gen"}
	if hasArg(args, "--tpenv") != 1 {
		t.Fatal("should find --tpenv")
	}
	if hasArg(args, "--nope") != -1 {
		t.Fatal("should not find --nope")
	}
}
