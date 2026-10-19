package corehttp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"shunt/internal/base"
)

func withTestCtrl(t *testing.T, h http.Handler) {
	t.Helper()
	old := base.Ctrl
	srv := httptest.NewServer(h)
	base.Ctrl = srv.URL
	t.Cleanup(func() {
		base.Ctrl = old
		srv.Close()
	})
}

func TestCtrlSecretCaches(t *testing.T) {
	a := CtrlSecret()
	b := CtrlSecret()
	if a != b {
		t.Fatalf("secret not cached: %q vs %q", a, b)
	}
}

func TestCoreHeadersAndBody(t *testing.T) {
	var sawAuth, sawCT, sawMethod, sawBody string
	withTestCtrl(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		sawCT = r.Header.Get("Content-Type")
		sawMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		sawBody = string(b)
		w.Write([]byte(`{"ok":true}`))
	}))
	code, raw := Core("PUT", "/proxies/x", map[string]any{"name": "n"}, 5)
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	if !strings.HasPrefix(sawAuth, "Bearer ") {
		t.Fatalf("auth = %q", sawAuth)
	}
	if sawCT != "application/json" {
		t.Fatalf("content-type = %q", sawCT)
	}
	if sawMethod != "PUT" || !strings.Contains(sawBody, `"name":"n"`) {
		t.Fatalf("method/body = %q %q", sawMethod, sawBody)
	}
	if string(raw) != `{"ok":true}` {
		t.Fatalf("raw = %q", raw)
	}
}

func TestCoreHTTPErrorPassthrough(t *testing.T) {
	withTestCtrl(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte(`{"message":"nope"}`))
	}))
	code, raw := Core("GET", "/missing", nil, 5)
	if code != 404 || string(raw) != `{"message":"nope"}` {
		t.Fatalf("code=%d raw=%q", code, raw)
	}
}

func TestCoreUnreachable(t *testing.T) {
	old := base.Ctrl
	base.Ctrl = "http://127.0.0.1:1" // 不可能连通
	defer func() { base.Ctrl = old }()
	code, raw := Core("GET", "/version", nil, 2)
	if code != 502 {
		t.Fatalf("code = %d", code)
	}
	var j map[string]any
	if err := json.Unmarshal(raw, &j); err != nil || j["message"] == nil {
		t.Fatalf("raw = %q", raw)
	}
}

func TestCoreJSON(t *testing.T) {
	withTestCtrl(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ok" {
			w.Write([]byte(`{"a":1}`))
			return
		}
		if r.URL.Path == "/badjson" {
			w.Write([]byte(`{oops`))
			return
		}
		w.WriteHeader(500)
	}))
	if got := CoreJSON("/ok", 5); got["a"] != float64(1) {
		t.Fatalf("got %v", got)
	}
	if got := CoreJSON("/badjson", 5); got != nil {
		t.Fatalf("bad json should be nil, got %v", got)
	}
	if got := CoreJSON("/err", 5); got != nil {
		t.Fatalf("non-200 should be nil, got %v", got)
	}
}
