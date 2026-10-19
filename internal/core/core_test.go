package core

import (
	"reflect"
	"testing"
)

func TestGroupSig(t *testing.T) {
	cfg := map[string]any{
		"proxy-groups": []any{
			map[string]any{"name": "🚀 节点选择", "type": "select", "proxies": []any{"a", "b"}},
			map[string]any{"name": "🐟 漏网之鱼", "type": "select", "filter": "xxx"},
			map[string]any{"name": "空组", "type": "select"}, // 无 proxies → 空 tuple
			"not-a-map", // 非法项跳过
		},
	}
	got := GroupSig(cfg)
	want := []GroupSigItem{
		{Name: "🚀 节点选择", Type: "select", Filter: "", Proxies: []string{"a", "b"}},
		{Name: "🐟 漏网之鱼", Type: "select", Filter: "xxx", Proxies: []string{}},
		{Name: "空组", Type: "select", Filter: "", Proxies: []string{}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GroupSig = %#v, want %#v", got, want)
	}
	// 相同内容不同实例 → DeepEqual 为真（地区分组无变化判定）
	again := GroupSig(cfg)
	if !reflect.DeepEqual(got, again) {
		t.Fatal("相同配置的 GroupSig 应相等")
	}
	// 顺序/内容变化 → 不等
	cfg2 := map[string]any{
		"proxy-groups": []any{
			map[string]any{"name": "🚀 节点选择", "type": "select", "proxies": []any{"a", "c"}},
		},
	}
	if reflect.DeepEqual(GroupSig(cfg), GroupSig(cfg2)) {
		t.Fatal("节点变化后 GroupSig 应不等")
	}
}

func TestOutboundSig(t *testing.T) {
	cfg := map[string]any{
		"outbounds": []any{
			map[string]any{"tag": "🚀 节点选择", "type": "selector", "outbounds": []any{"a", "b"}},
			map[string]any{"tag": "direct", "type": "direct"}, // 无 outbounds → 跳过
			map[string]any{"tag": "空", "type": "selector", "outbounds": []any{}},
		},
	}
	got := outboundSig(cfg)
	want := []outboundSigItem{
		{Tag: "🚀 节点选择", Outbounds: []string{"a", "b"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("outboundSig = %#v, want %#v", got, want)
	}
	if !reflect.DeepEqual(outboundSig(nil), []outboundSigItem{}) {
		t.Fatal("nil 配置的签名应为空非 nil 切片")
	}
}

func TestSbArchFromMachine(t *testing.T) {
	cases := map[string]string{
		"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64",
		"armv7l": "armv7", "armv8l": "armv7", "armv6l": "armv6",
		"i686": "386", "i386": "386", "riscv64": "riscv64",
		"loongarch64": "loong64", "s390x": "s390x",
	}
	for m, want := range cases {
		if got := sbArchFromMachine(m); got != want {
			t.Errorf("sbArchFromMachine(%q) = %q, want %q", m, got, want)
		}
	}
	if got := sbArchFromMachine("mips"); got != "" {
		t.Errorf("未知架构应返回空串，得到 %q", got)
	}
}

func TestPickPrerelease(t *testing.T) {
	items := []map[string]any{
		{"tag_name": "v1.12.0", "prerelease": false},
		{"tag_name": "v1.13.0-beta", "prerelease": true},
	}
	if got := pickPrerelease(items); got["tag_name"] != "v1.13.0-beta" {
		t.Fatalf("应选 prerelease，得到 %v", got)
	}
	stable := []map[string]any{{"tag_name": "v1.12.0"}}
	if got := pickPrerelease(stable); got["tag_name"] != "v1.12.0" {
		t.Fatalf("无 prerelease 时应取第一个，得到 %v", got)
	}
	if pickPrerelease(nil) != nil {
		t.Fatal("空列表应返回 nil")
	}
}

func TestTruncateTailStr(t *testing.T) {
	if truncate("abcdef", 4) != "abcd" {
		t.Fatal("truncate 前 N 失败")
	}
	if truncate("中文测试文本", 2) != "中文" {
		t.Fatal("truncate 应按 rune 截断")
	}
	if tailStr("abcdef", 2) != "ef" {
		t.Fatal("tailStr 后 N 失败")
	}
}

func TestShellQuote(t *testing.T) {
	if shellQuote("/usr/local/bin/sing-box") != "/usr/local/bin/sing-box" {
		t.Fatal("安全路径不应加引号")
	}
	if q := shellQuote("/tmp/a b/x"); q != "'/tmp/a b/x'" {
		t.Fatalf("含空格路径引号错误: %s", q)
	}
	if shellQuote("") != "''" {
		t.Fatal("空串应为 ''")
	}
}

func TestLastN(t *testing.T) {
	ss := []string{"a", "b", "c", "d"}
	if got := lastN(ss, 3); !reflect.DeepEqual(got, []string{"b", "c", "d"}) {
		t.Fatalf("lastN = %v", got)
	}
	if got := lastN(ss, 10); !reflect.DeepEqual(got, ss) {
		t.Fatalf("lastN 超长应原样返回: %v", got)
	}
}

func TestEnsureMapAndMapWith(t *testing.T) {
	d := map[string]any{}
	m := ensureMap(d, "dns")
	m["block_bypass"] = true
	if d["dns"].(map[string]any)["block_bypass"] != true {
		t.Fatal("ensureMap 应回写到原 map")
	}
	// 已存在时不覆盖
	d2 := map[string]any{"dns": map[string]any{"a": 1}}
	if ensureMap(d2, "dns")["a"] != 1 {
		t.Fatal("ensureMap 不应覆盖已有 map")
	}
	src := map[string]any{"x": 1}
	cp := mapWith(src, "core", "smart")
	if cp["core"] != "smart" || cp["x"] != 1 || src["core"] != nil {
		t.Fatal("mapWith 应浅拷贝并覆盖指定键，不改原 map")
	}
}
