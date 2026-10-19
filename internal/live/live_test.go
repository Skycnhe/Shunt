package live

import (
	"testing"
	"time"
)

func TestLiveSnapshotIsCopy(t *testing.T) {
	s1 := Live()
	s1["up"] = 99999
	s2 := Live()
	if s2["up"] == 99999 {
		t.Fatal("Live() should return a copy")
	}
	for _, k := range []string{"up", "down", "upTotal", "downTotal", "inuse", "oslimit", "t"} {
		if _, ok := s2[k]; !ok {
			t.Fatalf("missing key %q", k)
		}
	}
}

func TestMemoryOnceNoController(t *testing.T) {
	// 无控制器时应返回零值而不是挂起
	done := make(chan map[string]any, 1)
	go func() { done <- MemoryOnce() }()
	select {
	case got := <-done:
		if got["inuse"] != 0 {
			t.Fatalf("inuse = %v", got["inuse"])
		}
	case <-time.After(15 * time.Second):
		t.Fatal("MemoryOnce hung")
	}
}

func TestConnsSnapshotStub(t *testing.T) {
	// 已接线到 core.ConnsSnapshot：不断言 panic，只断言不抛 panic 且返回可用
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("connsSnapshot panicked: %v", r)
		}
	}()
	_ = connsSnapshot(3)
}
