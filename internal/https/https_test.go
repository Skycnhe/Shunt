package https

import (
	"net/http"
	"testing"

	"shunt/internal/base"
)

func TestHttpsReady(t *testing.T) {
	if HttpsReady(map[string]any{"https": true}) {
		t.Fatal("cert files should not exist in test env")
	}
	if HttpsReady(map[string]any{"https": false}) {
		t.Fatal("https off should be false")
	}
	if HttpsReady(map[string]any{}) {
		t.Fatal("missing key should be false")
	}
}

func TestNewServer(t *testing.T) {
	s := NewServer("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if s.Addr != "127.0.0.1:0" {
		t.Fatalf("addr=%q", s.Addr)
	}
	if s.ErrorLog == nil {
		t.Fatal("ErrorLog should be set (silent like handle_error)")
	}
	_ = base.PanelSvc
}

func TestLanIPNoPanic(t *testing.T) {
	_ = LanIP() // 沙箱可能无外网路由，返回 "" 也可以，只是不 panic
}
