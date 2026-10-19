package logstream

import (
	"testing"
	"time"
)

func TestTicketRoundTrip(t *testing.T) {
	t1 := TicketNew()
	t2 := TicketNew()
	if t1 == t2 {
		t.Fatal("tickets should be unique")
	}
	if !TicketUse(t1) {
		t.Fatal("fresh ticket should be usable")
	}
	if TicketUse(t1) {
		t.Fatal("ticket should be one-time")
	}
	if TicketUse("nope") {
		t.Fatal("unknown ticket should fail")
	}
}

func TestTicketExpiry(t *testing.T) {
	ticketsMu.Lock()
	TICKETS["old"] = time.Now().Unix() - 1
	ticketsMu.Unlock()
	if TicketUse("old") {
		t.Fatal("expired ticket should fail")
	}
	// 过期票据在发新票时被清理
	TicketNew()
	ticketsMu.Lock()
	_, still := TICKETS["old"]
	ticketsMu.Unlock()
	if still {
		t.Fatal("expired ticket should be swept on TicketNew")
	}
}

func TestStopShutdown(t *testing.T) {
	s := &Stop{}
	if s.Stopped() {
		t.Fatal("fresh stop should not be stopped")
	}
	s.MarkStop()
	if !s.Stopped() {
		t.Fatal("MarkStop should set stopped")
	}
	s.Shutdown() // 无连接时应静默无操作
}

func TestCoreStreamUnreachable(t *testing.T) {
	// 127.0.0.1:9090 无控制器时应返回错误（对应 Python 的 OSError）；
	// 若有控制器在跑，收到一行就主动停，避免测试挂起。
	stop := &Stop{}
	err := CoreStream("/traffic", func(string) { stop.MarkStop() }, stop, 3*time.Second)
	if err == nil {
		t.Skip("a controller is listening on 127.0.0.1:9090; skipping")
	}
}
