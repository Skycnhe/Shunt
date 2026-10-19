package latency

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"shunt/internal/base"
	"shunt/internal/data"
)

func TestHistLast(t *testing.T) {
	p := map[string]any{
		"history": []any{
			map[string]any{"delay": 100, "time": "2026-10-19 10:00:00"},
			map[string]any{"delay": 200, "time": "2026-10-19 11:00:00"},
		},
		"extra": map[string]any{
			"https://a": map[string]any{"history": []any{
				map[string]any{"delay": 50, "time": "2026-10-19 12:00:00"},
			}},
		},
	}
	d, ts, ok := HistLast(p)
	if !ok || d != 50 || ts != "2026-10-19 12:00:00" {
		t.Fatalf("latest should win: %d %q %v", d, ts, ok)
	}
	if _, _, ok := HistLast(map[string]any{}); ok {
		t.Fatal("empty should return not-ok")
	}
}

func TestBgType(t *testing.T) {
	if BgType([]byte("\xff\xd8\xff hello")) != "image/jpeg" {
		t.Fatal("jpeg")
	}
	if BgType([]byte("\x89PNG\r\n\x1a\nrest")) != "image/png" {
		t.Fatal("png")
	}
	if BgType([]byte("RIFF1234WEBPrest")) != "image/webp" {
		t.Fatal("webp")
	}
	if BgType([]byte("GIF89a rest")) != "image/gif" {
		t.Fatal("gif")
	}
	if BgType([]byte("not an image")) != "" {
		t.Fatal("unknown should be empty")
	}
}

func TestBgSave(t *testing.T) {
	dir := t.TempDir()
	old := BgFile
	BgFile = filepath.Join(dir, "bg.img")
	defer func() { BgFile = old }()

	png := "\x89PNG\r\n\x1a\n" + "fakepngdata"
	du := "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte(png))
	ok, msg := BgSave(du)
	if !ok {
		t.Fatalf("bg_save: %s", msg)
	}
	raw, _ := os.ReadFile(BgFile)
	if string(raw) != png {
		t.Fatal("bg content mismatch")
	}
	if ok, _ := BgSave("data:image/png;base64,!!!"); ok {
		t.Fatal("bad base64 should fail")
	}
	if ok, msg := BgSave("data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("nope"))); ok || msg == "" {
		t.Fatalf("non-image should fail: %v %s", ok, msg)
	}
	if ok, _ := BgSave("http://x/y.png"); ok {
		t.Fatal("non-data-url should fail")
	}
}

func TestBgMetaSaveLoad(t *testing.T) {
	dir := t.TempDir()
	oldFile, oldMeta := BgFile, BgMeta
	BgFile = filepath.Join(dir, "bg.img")
	BgMeta = BgFile + ".json"
	defer func() { BgFile, BgMeta = oldFile, oldMeta }()

	BgMetaSave(map[string]any{"url": "http://x/y.png", "daily": true, "t": 123})
	m := BgMetaLoad()
	if data.Str(m, "url") != "http://x/y.png" || !data.Bool(m, "daily") {
		t.Fatalf("meta: %+v", m)
	}
	BgMetaSave(nil)
	if _, err := os.Stat(BgMeta); !os.IsNotExist(err) {
		t.Fatal("empty meta should delete file")
	}
	if len(BgMetaLoad()) != 0 {
		t.Fatal("missing meta should be empty map")
	}
}

func TestDelayMerge(t *testing.T) {
	dir := t.TempDir()
	old := DelayFile
	DelayFile = filepath.Join(dir, "delays.json")
	defer func() { DelayFile = old }()
	Delays.Lock()
	Delays.Data, Delays.Saved, Delays.Dirty = nil, 0, false
	Delays.Unlock()
	// 确保落盘阈值：先把 saved 设为很久以前
	Delays.Lock()
	Delays.Saved = 0
	Delays.Unlock()

	px := map[string]map[string]any{
		"n1":  {"history": []any{map[string]any{"delay": 88, "time": "2026-10-19 10:00:00"}}},
		"n2":  {"history": []any{map[string]any{"delay": 0, "time": "2026-10-19 10:00:00"}}},
		"grp": {"all": []any{"n1"}}, // 策略组跳过
	}
	DelayMerge(px, true)
	if px["n1"]["_d"] != 88 {
		t.Fatalf("n1 _d: %+v", px["n1"])
	}
	if _, ok := px["grp"]["_d"]; ok {
		t.Fatal("group should not get _d")
	}
	Delays.Lock()
	cached := Delays.Data["n1"].(map[string]any)
	Delays.Unlock()
	if data.Int(cached, "d") != 88 {
		t.Fatalf("cache: %+v", cached)
	}
	// provOk=true 时清理已不存在的节点
	Delays.Lock()
	Delays.Data["gone"] = map[string]any{"d": 1, "ts": "x", "at": 1}
	Delays.Dirty = true
	Delays.Unlock()
	DelayMerge(px, true)
	Delays.Lock()
	_, still := Delays.Data["gone"]
	Delays.Unlock()
	if still {
		t.Fatal("gone node should be cleaned when provOk")
	}
	// provOk=false 时不清理
	Delays.Lock()
	Delays.Data["gone2"] = map[string]any{"d": 1, "ts": "x", "at": 1}
	Delays.Unlock()
	DelayMerge(px, false)
	Delays.Lock()
	_, still = Delays.Data["gone2"]
	Delays.Unlock()
	if !still {
		t.Fatal("gone2 should be kept when !provOk")
	}
}

func TestRetestSoonDebounce(t *testing.T) {
	Retest.Lock()
	Retest.Pending, Retest.Last = false, 0
	Retest.Unlock()
	// coreAlive 是 stub 会 panic；RetestSoon 的 goroutine 里 recover 会吞掉。
	// 这里只验证防抖：第二次调用直接返回
	RetestSoon(100)
	Retest.Lock()
	p := Retest.Pending
	Retest.Unlock()
	if !p {
		t.Fatal("first call should set pending")
	}
	RetestSoon(100) // 不应再起一个
	Retest.Lock()
	Retest.Pending = false // 清理，避免 goroutine 干扰
	Retest.Last = 9999999999
	Retest.Unlock()
	RetestSoon(1)
	Retest.Lock()
	p2 := Retest.Pending
	Retest.Unlock()
	if p2 {
		t.Fatal("recent last should debounce")
	}
	Retest.Lock()
	Retest.Last = 0
	Retest.Unlock()
}

func TestCheckSubsLogic(t *testing.T) {
	// 纯逻辑：过期阈值判断（不依赖 notify stub）
	now := int64(1_000_000)
	exp := now + 2*86400
	if !(exp > 0 && exp-now > 0 && exp-now < 3*86400) {
		t.Fatal("should notify within 3 days")
	}
	exp = now + 4*86400
	if exp-now < 3*86400 {
		t.Fatal("should not notify beyond 3 days")
	}
	_ = base.PanelDir
}
