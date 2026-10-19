package data

import (
	"os"
	"path/filepath"
	"testing"

	"shunt/internal/base"
)

func testEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	base.DataFile = filepath.Join(dir, "data.json")
	base.PanelDir = dir
	HistoryFile = filepath.Join(dir, "history.json")
	// reset caches
	dataCache.Lock()
	dataCache.key, dataCache.gen, dataCache.txt = "", 0, ""
	dataCache.Unlock()
	mu.Lock()
	dataGen, configVer = 0, 0
	mu.Unlock()
	return dir
}

func TestLoadDefaults(t *testing.T) {
	testEnv(t)
	d := Load()
	if Str(d, "core") != "mihomo" {
		t.Fatalf("core = %v", Str(d, "core"))
	}
	if Str(d, "proxy_mode") != "tproxy" {
		t.Fatalf("proxy_mode should normalize to tproxy, got %v", Str(d, "proxy_mode"))
	}
	if !Bool(d, "tproxy") {
		t.Fatal("tproxy should default true")
	}
	if Str(d, "secret") == "" {
		t.Fatal("secret should be generated")
	}
	if Int(d, "schema") != base.Schema {
		t.Fatalf("schema = %d", Int(d, "schema"))
	}
	if len(List(d, "tests")) != 6 {
		t.Fatalf("tests len = %d", len(List(d, "tests")))
	}
	// 修改返回的副本不应影响下次 load
	d["core"] = "sing-box"
	d2 := Load()
	if Str(d2, "core") != "mihomo" {
		t.Fatal("Load must return independent copy")
	}
}

func TestSaveUpdate(t *testing.T) {
	testEnv(t)
	v0 := ConfigVersion()
	prev := Update(func(d map[string]any) { d["mode"] = "global" })
	if Str(prev, "mode") != "rule" {
		t.Fatal("Update should return prev copy")
	}
	if ConfigVersion() <= v0 {
		t.Fatal("ConfigVersion should increment")
	}
	d := Load()
	if Str(d, "mode") != "global" {
		t.Fatal("saved value not persisted")
	}
	// history 应记录（mode 不在 HISTORY_SKIP）
	h := ReadJSON(HistoryFile, []any{})
	if len(h) == 0 {
		t.Fatal("history should have entry")
	}
}

func TestRegionHelpers(t *testing.T) {
	flag, label := RegionLabel("🇯🇵 日本")
	if flag != "🇯🇵" || label != "日本" {
		t.Fatalf("got %q %q", flag, label)
	}
	if got := AutoName("🇯🇵 日本"); got != "🇯🇵 日本竞技" {
		t.Fatalf("AutoName = %q", got)
	}
	if got := LbName("🇯🇵 日本", ""); got != "⚖️ 日本哈希" {
		t.Fatalf("LbName = %q", got)
	}
	if got := LbOldName("🇯🇵 日本"); got != "⚖️ 日本负载均衡" {
		t.Fatalf("LbOldName = %q", got)
	}
	mp := LegacyMap()
	if mp["♻️ 自动选择"] != "⚡ 全局自动选择" {
		t.Fatal("legacy map missing")
	}
}

func TestSafe(t *testing.T) {
	if Safe("a/b c") != "a_b_c" {
		t.Fatalf("Safe = %q", Safe("a/b c"))
	}
	if Safe("") != "sub" {
		t.Fatal("Safe empty")
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
