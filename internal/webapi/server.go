package webapi

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"shunt/internal/base"
	"shunt/internal/data"
	"shunt/internal/errlog"
	"shunt/internal/latency"
	"shunt/internal/logstream"
)

// ---------- 访问控制（对应 access.py，webapi 自包含实现） ----------

var lanExtra = []net.IPNet{mustParseCIDR("100.64.0.0/10")} // CGNAT / Tailscale

var lanSuffix = []string{".lan", ".local", ".home", ".internal", ".home.arpa", ".localdomain", ".router", ".intranet", ".ts.net"}

func mustParseCIDR(s string) net.IPNet {
	_, n, _ := net.ParseCIDR(s)
	return *n
}

func isLanIP(ipStr string) bool {
	host, _, err := net.SplitHostPort(ipStr)
	if err != nil {
		host = ipStr
	}
	host = strings.Split(host, "%")[0]
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	for _, n := range lanExtra {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func hostName(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if strings.HasPrefix(h, "[") {
		if i := strings.Index(h, "]"); i >= 0 {
			return h[1:i]
		}
		return h[1:]
	}
	if strings.Count(h, ":") == 1 {
		if i := strings.LastIndex(h, ":"); i >= 0 {
			return h[:i]
		}
	}
	return h
}

type aclCache struct {
	sync.Mutex
	t      time.Time
	public bool
	hosts  map[string]bool
}

var acl = &aclCache{}

func aclCfg() (bool, map[string]bool) {
	acl.Lock()
	defer acl.Unlock()
	if time.Since(acl.t) > 5*time.Second {
		d := data.Load()
		hosts := map[string]bool{}
		for _, h := range data.Strs(d, "allow_hosts") {
			if s := strings.ToLower(strings.TrimSpace(h)); s != "" {
				hosts[s] = true
			}
		}
		for _, h := range strings.Split(os.Getenv("PANEL_ALLOW_HOSTS"), ",") {
			if s := strings.ToLower(strings.TrimSpace(h)); s != "" {
				hosts[s] = true
			}
		}
		acl.public = data.Bool(d, "allow_public") || os.Getenv("PANEL_ALLOW_PUBLIC") == "1"
		acl.hosts = hosts
		acl.t = time.Now()
	}
	return acl.public, acl.hosts
}

func hostOk(host string) bool {
	h := strings.TrimSuffix(hostName(host), ".")
	if h == "" {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	public, hosts := aclCfg()
	return public || h == "localhost" || hosts[h] || hasLanSuffix(h)
}

func hasLanSuffix(h string) bool {
	for _, s := range lanSuffix {
		if strings.HasSuffix(h, s) {
			return true
		}
	}
	return false
}

// ---------- 静态文件（对应 static.py） ----------

var staticTypes = map[string]string{
	"index.html":   "text/html",
	"icon.svg":     "image/svg+xml",
	"icon-180.png": "image/png",
	"icon-512.png": "image/png",
}

var manifest = map[string]any{
	"name": "Shunt 分流", "short_name": "Shunt", "description": "mihomo 旁路由面板",
	"start_url": "/", "scope": "/", "display": "standalone",
	"background_color": "#f2f2f7", "theme_color": "#0a84ff",
	"icons": []any{
		map[string]any{"src": "/icon-180.png", "sizes": "180x180", "type": "image/png"},
		map[string]any{"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"},
	},
}

type staticEntry struct {
	key     string
	raw, gz []byte
	etag    string
	ctype   string
}

var staticCache = struct {
	sync.Mutex
	m map[string]*staticEntry
}{m: map[string]*staticEntry{}}

var iconRe = regexp.MustCompile(`rel="apple-touch-icon" href="data:image/png;base64,([A-Za-z0-9+/=]+)"`)

func staticFile(name string) *staticEntry {
	path := filepath.Join(base.Base, name)
	st, err := os.Stat(path)
	var key string
	if err == nil {
		key = st.ModTime().String() + "|" + itoa64(st.Size())
	} else {
		// 图标缺失时从 index.html 内嵌图标取
		if !strings.HasSuffix(name, ".png") {
			return nil
		}
		idx := staticFile("index.html")
		if idx == nil {
			return nil
		}
		m := iconRe.FindSubmatch(idx.raw)
		if m == nil {
			return nil
		}
		raw, err := base64.StdEncoding.DecodeString(string(m[1]))
		if err != nil {
			return nil
		}
		sum := md5.Sum(raw)
		return &staticEntry{raw: raw, etag: `"i` + hex.EncodeToString(sum[:])[:16] + `"`, ctype: "image/png"}
	}
	staticCache.Lock()
	if e, ok := staticCache.m[name]; ok && e.key == key {
		staticCache.Unlock()
		return e
	}
	staticCache.Unlock()
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var gz []byte
	if !strings.HasSuffix(name, ".png") {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		_, _ = w.Write(raw)
		_ = w.Close()
		gz = buf.Bytes()
	}
	sum := md5.Sum(raw)
	e := &staticEntry{key: key, raw: raw, gz: gz,
		etag:  `"` + hex.EncodeToString(sum[:])[:16] + `"`,
		ctype: staticType(name)}
	staticCache.Lock()
	staticCache.m[name] = e
	staticCache.Unlock()
	return e
}

func staticType(name string) string {
	if t, ok := staticTypes[name]; ok {
		return t
	}
	return "application/octet-stream"
}

func itoa64(n int64) string {
	return strconv.FormatInt(n, 10)
}

func serveStatic(w http.ResponseWriter, r *http.Request, name string) {
	e := staticFile(name)
	if e == nil {
		writeJSON(w, 404, map[string]any{"message": "not found"})
		return
	}
	if inm := r.Header.Get("If-None-Match"); inm != "" && inm == e.etag {
		w.WriteHeader(304)
		return
	}
	h := w.Header()
	h.Set("Content-Type", e.ctype+"; charset=utf-8")
	h.Set("ETag", e.etag)
	h.Set("Cache-Control", "public, max-age=3600")
	if e.gz != nil && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		h.Set("Content-Encoding", "gzip")
		h.Set("Content-Length", strconv.Itoa(len(e.gz)))
		w.WriteHeader(200)
		_, _ = w.Write(e.gz)
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(e.raw)))
	w.WriteHeader(200)
	_, _ = w.Write(e.raw)
}

// ---------- 主分发 ----------

// Server HTTP 服务
type Server struct {
	mux *http.ServeMux
}

// NewServer 创建服务并注册路由（handlers.go 中 RegisterRoutes 注册 API 路由）
func NewServer() *Server {
	s := &Server{mux: http.NewServeMux()}
	RegisterRoutes()
	s.mux.HandleFunc("/", s.serveHTTP)
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	m := r.Method
	p := r.URL.Path
	remoteIP := r.RemoteAddr

	if why := guard(r, m, p, remoteIP); why != "" {
		writeJSON(w, 403, map[string]any{"message": why})
		return
	}

	// 静态
	if m == "GET" && (p == "/" || p == "/index.html" || staticTypes[strings.TrimPrefix(p, "/")] != "") {
		name := "index.html"
		if p != "/" && p != "/index.html" {
			name = strings.TrimPrefix(p, "/")
		}
		serveStatic(w, r, name)
		return
	}
	if m == "GET" && p == "/manifest.webmanifest" {
		raw, _ := json.Marshal(manifest)
		w.Header().Set("Content-Type", "application/manifest+json")
		w.WriteHeader(200)
		_, _ = w.Write(raw)
		return
	}
	if m == "GET" && p == "/bg" {
		serveBG(w, r)
		return
	}
	if !strings.HasPrefix(p, "/api/") {
		writeJSON(w, 404, map[string]any{"message": "not found"})
		return
	}

	// /api/logstream 由 logstream 包处理：EventSource 无法带自定义头，用 /api/logticket 换来的一次性票据
	if p == "/api/logstream" && m == "GET" {
		if !logstream.TicketUse(Q1(r.URL.Query(), "ticket", "")) {
			writeJSON(w, 401, map[string]any{"message": "未登录"})
			return
		}
		ServeLogstreamSSE(w, r)
		return
	}

	body, ok := readBody(r)
	if !ok {
		writeJSON(w, 400, map[string]any{"message": "请求体过大或不是 JSON"})
		return
	}
	h, found := routes[[2]string{m, p}]
	if !found {
		writeJSON(w, 404, map[string]any{"message": "not found"})
		return
	}
	ctx := &Ctx{W: w, R: r, Path: p, Query: r.URL.Query(), Body: body}
	// 对应 Python route() 的 except Exception：handler 内任何异常（含未接线的 STUB）
	// 都记服务端日志并回 500，不让单个请求拖垮连接。
	code, obj := func() (code int, obj any) {
		defer func() {
			if rec := recover(); rec != nil {
				errlog.LogErr(m+" "+p, rec, false)
				code, obj = 500, map[string]any{"message": "内部错误"}
			}
		}()
		return h(ctx)
	}()
	writeJSON(w, code, obj)
}

// serveBG 背景图：CSS url() 无法带请求头，只读、不含敏感信息
func serveBG(w http.ResponseWriter, r *http.Request) {
	// BG_FILE = latency.BgFile（base.PanelDir/bg.img），与 Python shunt/latency.py 一致
	raw, err := os.ReadFile(latency.BgFile)
	if err != nil {
		writeJSON(w, 404, map[string]any{"message": "未设置背景图"})
		return
	}
	ctype := latency.BgType(raw[:16])
	if ctype == "" {
		ctype = detectImageType(raw)
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}

func detectImageType(raw []byte) string {
	if len(raw) > 3 && raw[0] == 0xFF && raw[1] == 0xD8 {
		return "image/jpeg"
	}
	if len(raw) > 8 && string(raw[:8]) == "\x89PNG\r\n\x1a\n" {
		return "image/png"
	}
	if len(raw) > 4 && string(raw[:4]) == "GIF8" {
		return "image/gif"
	}
	return "application/octet-stream"
}
