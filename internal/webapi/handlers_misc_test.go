package webapi

// handlers_misc.go 的测试：/api/logticket 与 /api/logstream（SSE）。

import (
	"net/http/httptest"
	"strings"
	"testing"

	"shunt/internal/logstream"
)

func TestLogticketPost(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "POST", "/api/logticket", nil)
	if code != 200 {
		t.Fatalf("want 200, got %d %v", code, out)
	}
	ticket := toStr(out["ticket"])
	if ticket == "" {
		t.Fatal("ticket 为空")
	}
	// 票据一次性：用掉一次后再次使用应 401
	if !logstream.TicketUse(ticket) {
		t.Fatal("刚签发的票据应可用")
	}
	if logstream.TicketUse(ticket) {
		t.Fatal("票据应一次性有效")
	}
}

func sseRequest(t *testing.T, query string) (int, string, []byte) {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/logstream"+query, nil)
	req.RemoteAddr = "192.168.1.10:54321"
	req.Host = "192.168.1.10"
	rr := httptest.NewRecorder()
	NewServer().Handler().ServeHTTP(rr, req)
	return rr.Code, rr.Header().Get("Content-Type"), rr.Body.Bytes()
}

func TestLogstreamNoTicket(t *testing.T) {
	isolateTestEnv(t, "")
	code, _, body := sseRequest(t, "")
	if code != 401 {
		t.Fatalf("无票据应 401, got %d (%s)", code, body)
	}
}

func TestLogstreamBadTicket(t *testing.T) {
	isolateTestEnv(t, "")
	code, _, _ := sseRequest(t, "?ticket=bogus")
	if code != 401 {
		t.Fatalf("非法票据应 401, got %d", code)
	}
}

func TestLogstreamSSE_NoCore(t *testing.T) {
	isolateTestEnv(t, "")
	ticket := logstream.TicketNew()
	code, ctype, body := sseRequest(t, "?ticket="+ticket+"&level=info")
	if code != 200 {
		t.Fatalf("want 200, got %d (%s)", code, body)
	}
	if !strings.HasPrefix(ctype, "text/event-stream") {
		t.Fatalf("Content-Type 应为 text/event-stream, got %s", ctype)
	}
	// 无核心：连接被拒绝 → 推送 warning 后结束流
	if !strings.Contains(string(body), "data:") {
		t.Fatalf("SSE body 应包含 data: 行, got %q", body)
	}
	t.Logf("SSE body: %q", sseFirstLine(string(body)))
}

func sseFirstLine(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i]
	}
	return s
}
