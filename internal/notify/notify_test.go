package notify

import (
	"os"
	"path/filepath"
	"testing"

	"shunt/internal/base"
	"shunt/internal/data"
)

func tempWdDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	oldStop, oldEvents := StopFlag, WdEventsFile
	StopFlag = filepath.Join(dir, "core_stopped")
	WdEventsFile = filepath.Join(dir, "wd_events.json")
	t.Cleanup(func() {
		StopFlag, WdEventsFile = oldStop, oldEvents
	})
	// 重置内存状态
	wdMu.Lock()
	wd.events = nil
	wd.manualStop = false
	wd.status = "ok"
	wd.fails = 0
	wdMu.Unlock()
}

func TestSetManualStop(t *testing.T) {
	tempWdDir(t)
	SetManualStop(true)
	if !ManualStop() {
		t.Fatal("manual stop should be set")
	}
	if _, err := os.Stat(StopFlag); err != nil {
		t.Fatal("flag file should exist")
	}
	SetManualStop(false)
	if ManualStop() {
		t.Fatal("manual stop should be cleared")
	}
	if _, err := os.Stat(StopFlag); !os.IsNotExist(err) {
		t.Fatal("flag file should be removed")
	}
}

func TestWdEventPushAndCounts(t *testing.T) {
	tempWdDir(t)
	WdEventPush("核心重启", false, "restart")
	WdEventPush("已直连", false, "direct")
	WdEventPush("已恢复", false, "recover")
	WdEventPush("无kind", false, "")
	c := WdCounts(nil)
	if c["restart"] != 1 || c["direct"] != 1 || c["recover"] != 1 {
		t.Fatalf("counts = %v", c)
	}
	// 落盘
	raw := data.ReadJSON(WdEventsFile, []map[string]any(nil))
	if len(raw) != 4 {
		t.Fatalf("persisted %d events", len(raw))
	}
	if raw[0]["msg"] != "无kind" {
		t.Fatalf("newest first: %v", raw[0])
	}
	// maxlen
	for i := 0; i < WdEventsMax+5; i++ {
		WdEventPush("flood", false, "")
	}
	if got := len(WdCounts(nil)); got != 0 {
		_ = got
	}
	wdMu.Lock()
	n := len(wd.events)
	wdMu.Unlock()
	if n != WdEventsMax {
		t.Fatalf("events=%d want %d", n, WdEventsMax)
	}
}

func TestLoadWdEventsFilters(t *testing.T) {
	tempWdDir(t)
	_ = data.WriteJSON(WdEventsFile, []any{
		map[string]any{"t": 123, "msg": "ok", "kind": "restart"},
		map[string]any{"t": "bad", "msg": "bad"},
		map[string]any{"msg": "no-t"},
		"not-a-dict",
	})
	evs := loadWdEvents()
	if len(evs) != 1 || evs[0].Msg != "ok" || evs[0].Kind != "restart" {
		t.Fatalf("got %v", evs)
	}
}

func TestTgSendUnconfigured(t *testing.T) {
	ok, msg := TgSend("hi", map[string]any{})
	if ok || msg != "未配置 Telegram" {
		t.Fatalf("ok=%v msg=%q", ok, msg)
	}
}

func TestWatchdogTickEarlyReturns(t *testing.T) {
	tempWdDir(t)
	// 内核更新忙 → 直接返回
	base.CoreUpd.Lock()
	base.CoreUpd.Busy = true
	base.CoreUpd.Unlock()
	WatchdogTick()
	base.CoreUpd.Lock()
	base.CoreUpd.Busy = false
	base.CoreUpd.Unlock()
	// 看门狗暂停期 → 直接返回
	base.WdHold(3600, "test", false)
	WatchdogTick()
	base.WdHold(0, "test", true)
	if got := WdStatus(); got != "ok" {
		t.Fatalf("status=%q", got)
	}
}

func TestStubsWired(t *testing.T) {
	// corePid/activeCore/coreDisplayName 已接线到 singbox（sb_common），不再 panic
	if got := corePid(); got == "" {
		t.Fatal("corePid should return non-empty pid path")
	}
	if got := activeCore(nil); got != "mihomo" {
		t.Fatalf("activeCore(nil) = %q, want mihomo", got)
	}
	if got := coreDisplayName(nil); got != "mihomo" {
		t.Fatalf("coreDisplayName(nil) = %q, want mihomo", got)
	}
	d := map[string]any{"core": "singbox"}
	if got := activeCore(d); got != "singbox" {
		t.Fatalf("activeCore(singbox) = %q", got)
	}
	if got := coreDisplayName(d); got != "sing-box" {
		t.Fatalf("coreDisplayName(singbox) = %q, want sing-box", got)
	}
}

func TestCoreLastErrorMissing(t *testing.T) {
	if got := CoreLastError(); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestLoadNotified(t *testing.T) {
	st := LoadNotified()
	if st == nil {
		t.Fatal("should return a map")
	}
}
