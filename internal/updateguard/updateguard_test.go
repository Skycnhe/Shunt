package updateguard

import (
	"strings"
	"testing"

	"shunt/internal/base"
)

func TestGroupKind(t *testing.T) {
	cases := map[string]string{
		base.GSel:        "select",
		base.GManual:     "manual",
		base.GAuto:       "auto",
		base.GDirect:     "direct",
		"⚖️ 香港哈希":        "lb",
		"⚖️ 香港负载均衡":      "lb",
		"⚖️ 香港轮询":        "lb",
		"香港竞技":           "region",
		"Something Else": "other",
	}
	for n, want := range cases {
		if got := GroupKind(n); got != want {
			t.Errorf("GroupKind(%q) = %q, want %q", n, got, want)
		}
	}
	if got := GroupKind("我的分组", "我的分组"); got != "custom" {
		t.Fatalf("custom = %q", got)
	}
	for _, s := range base.SideGroups {
		if got := GroupKind(s); got != "service" {
			t.Fatalf("side group %q = %q", s, got)
		}
	}
}

func TestGroupMeta(t *testing.T) {
	d := map[string]any{
		"custom_groups": []any{map[string]any{"name": "我的分组"}},
	}
	cfg := map[string]any{
		"proxy-groups": []any{
			map[string]any{"name": base.GSel, "type": "select"},
			map[string]any{"name": "我的分组", "type": "select", "use": []any{"sub1"}},
			map[string]any{"name": "香港竞技", "type": "url-test", "strategy": "round-robin"},
		},
	}
	m := GroupMeta(d, cfg)
	if m[base.GSel]["kind"] != "select" {
		t.Fatalf("sel kind=%v", m[base.GSel])
	}
	if m["我的分组"]["kind"] != "custom" {
		t.Fatalf("custom kind=%v", m["我的分组"])
	}
	if m["我的分组"]["subs"] != true {
		t.Fatalf("subs=%v", m["我的分组"])
	}
	if m["香港竞技"]["kind"] != "region" {
		t.Fatalf("region kind=%v", m["香港竞技"])
	}
}

func TestRenamePolicy(t *testing.T) {
	// 用一份最小的 data 做引用改写冒烟测试
	d := base.DeepCopyDefault()
	d["custom_groups"] = []any{
		map[string]any{"name": "旧组", "type": "select", "proxies": []any{"a"}},
	}
	n := RenamePolicy(d, "旧组", "新组")
	_ = n
}

func TestUpdateGuardScript(t *testing.T) {
	s := UpdateGuardScript([]string{"server.py", "shunt/base.py"})
	for _, want := range []string{
		"#!/bin/sh",
		"sleep 30",
		"manifest.webmanifest",
		"已自动恢复为 v" + base.PanelVersion,
		base.LocalFile("server.py"),
		"rm -f \"$0\"",
		"ProxyHandler({})",
		`&& { rm -f "$0"; exit 0; }`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("script missing %q", want)
		}
	}
	// Python format 转义不应泄漏
	if strings.Contains(s, "{{") || strings.Contains(s, "}}") {
		t.Fatal("format escapes leaked")
	}
}
