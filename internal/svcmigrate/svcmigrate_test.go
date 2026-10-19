package svcmigrate

import (
	"strings"
	"testing"

	"shunt/internal/base"
)

func TestNeedMigrateFalseInTestEnv(t *testing.T) {
	// 测试机上 BASE 不是 /opt/mihomo-panel，不应触发
	if base.Base == "/opt/mihomo-panel" {
		t.Skip("running on a real panel host")
	}
	if NeedMigrate() {
		t.Fatal("should not need migrate in test env")
	}
	if SvcMigrate(0) {
		t.Fatal("SvcMigrate should return false when no migration needed")
	}
}

func TestScriptContent(t *testing.T) {
	s := strings.ReplaceAll(migrateScript, "__BASE__", "/opt/mihomo-panel")
	for _, want := range []string{
		"#!/bin/sh",
		"B=/opt/mihomo-panel",
		"rc-service mihomo-panel stop",
		"rc-update add shunt default",
		`rm -f "$0"`,
		`{ echo "[svc-migrate] 复制 $s 失败"; rm -f "$0"; exit 1; }`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("script missing %q", want)
		}
	}
	if strings.Contains(s, "__BASE__") {
		t.Fatal("placeholder not replaced")
	}
	if strings.Contains(s, "{{") || strings.Contains(s, "}}") {
		t.Fatal("python format escapes leaked into script")
	}
}
