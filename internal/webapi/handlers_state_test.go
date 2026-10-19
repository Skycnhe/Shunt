package webapi

// handlers_state.go 的测试：路由注册、打码 helper、/api/ping、/api/state。

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"shunt/internal/base"
	"shunt/internal/data"
)

// testWebapiEnv 把 data.json 指向临时目录并写入给定内容；同时重置状态缓存。
func testWebapiEnv(t *testing.T, dataJSON string) {
	t.Helper()
	dir := t.TempDir()
	base.DataFile = filepath.Join(dir, "data.json")
	base.PanelDir = dir
	data.HistoryFile = filepath.Join(dir, "history.json")
	if dataJSON == "" {
		dataJSON = "{}"
	}
	if err := os.WriteFile(base.DataFile, []byte(dataJSON), 0644); err != nil {
		t.Fatal(err)
	}
	svcCache.Lock()
	svcCache.ok = false
	svcCache.Unlock()
	grpCache.Lock()
	grpCache.ok = false
	grpCache.Unlock()
}

// doAPI 走完整 HTTP 分发（含 guard）：LAN RemoteAddr + IP Host；非 GET 自动带 X-Shunt 头。
func doAPI(t *testing.T, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.RemoteAddr = "192.168.1.10:54321"
	req.Host = "192.168.1.10"
	if method != "GET" && method != "HEAD" {
		req.Header.Set("X-Shunt", "1")
	}
	rr := httptest.NewRecorder()
	NewServer().Handler().ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func TestRoutesRegistered(t *testing.T) {
	RegisterRoutes()
	want := [][2]string{
		{"GET", "/api/state"},
		{"GET", "/api/ping"},
		{"GET", "/api/groups"},
		{"PUT", "/api/groups/cfg"},
		{"POST", "/api/groups"},
		{"DELETE", "/api/groups"},
		{"POST", "/api/groups/preview"},
		{"POST", "/api/groups/refresh"},
		{"POST", "/api/subs/update"},
		{"POST", "/api/subs"},
		{"DELETE", "/api/subs"},
		{"POST", "/api/nodes"},
		{"DELETE", "/api/nodes"},
	}
	for _, w := range want {
		if _, ok := routes[w]; !ok {
			t.Errorf("路由未注册：%s %s", w[0], w[1])
		}
	}
	if len(routes) < len(want) {
		t.Errorf("路由数不足：got %d, want at least %d", len(routes), len(want))
	}
}

func TestMaskVal(t *testing.T) {
	cases := []struct{ in, want string }{
		{"123456:ABC-DEF", "123******EF"},
		{"abcdefg", "abc******fg"},
		{"abcdef", "******"},
		{"", "******"},
		{"香港节点", "******"},         // 4 个 rune，按字符计短值全打码
		{"香港节点01", "******"},       // 6 个 rune
		{"香港节点012", "香港节******12"}, // 7 个 rune：露头 3 + 尾 2
	}
	for _, c := range cases {
		if got := maskVal(c.in); got != c.want {
			t.Errorf("maskVal(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMaskSecret(t *testing.T) {
	if got := maskSecret("123456:ABC-DEF"); got != "123******EF" {
		t.Errorf("maskSecret 非空未打码：%v", got)
	}
	if got := maskSecret(""); got != "" {
		t.Errorf("maskSecret 空值应保持空，got %v", got)
	}
	if got := maskSecret(nil); got != "" {
		t.Errorf("maskSecret nil 应返回空串，got %v", got)
	}
}

func TestMaskURL(t *testing.T) {
	cases := []struct {
		name, in, wantPrefix string
		wantFull             string
	}{
		{"普通订阅", "https://sub.example.com/path?token=SECRET123", "https://sub.example.com/", ""},
		{"无路径", "https://sub.example.com", "", "https://sub.example.com"},
		{"仅斜杠", "https://sub.example.com/", "", "https://sub.example.com/"},
		{"带端口", "https://sub.example.com:8443/a?b=1", "https://sub.example.com:8443/", ""},
		{"空", "", "", ""},
		{"非URL", "not a url", "", "not******rl"}, // Python urlparse 同样走 _mask_val（9 字符）
	}
	for _, c := range cases {
		got := maskURL(c.in)
		if c.wantFull != "" {
			if got != c.wantFull {
				t.Errorf("%s: maskURL(%q) = %q, want %q", c.name, c.in, got, c.wantFull)
			}
			continue
		}
		if !strings.HasPrefix(got, c.wantPrefix) {
			t.Errorf("%s: maskURL(%q) = %q, want prefix %q", c.name, c.in, got, c.wantPrefix)
		}
		if strings.Contains(got, "SECRET123") || strings.Contains(got, "token=SECRET123") {
			t.Errorf("%s: token 未被打码：%q", c.name, got)
		}
	}
	// userinfo 应被去掉、主机保留（与 Python mask_url 一致）
	got := maskURL("https://user:pass@sub.example.com/api?token=SECRET123")
	if !strings.HasPrefix(got, "https://sub.example.com/") {
		t.Errorf("userinfo 未剥离：%q", got)
	}
	if strings.Contains(got, "user:pass") || strings.Contains(got, "SECRET123") {
		t.Errorf("敏感部分未打码：%q", got)
	}
}

func TestUnmask(t *testing.T) {
	cur := "https://sub.example.com/api?token=REAL"
	masked := maskURL(cur)
	if got := unmask(masked, cur, maskURL); got != cur {
		t.Errorf("打码值原样提交应换回原值，got %q", got)
	}
	if got := unmask("  "+masked+"  ", cur, maskURL); got != cur {
		t.Errorf("带空白的打码值也应换回原值，got %q", got)
	}
	if got := unmask("https://other.example.com/x", cur, maskURL); got != "https://other.example.com/x" {
		t.Errorf("改过的值不应被替换，got %q", got)
	}
	if got := unmask(masked, "", maskURL); got != masked {
		t.Errorf("cur 为空时应原样返回，got %q", got)
	}
}

func TestStateSubs(t *testing.T) {
	subs := []any{
		map[string]any{"name": "s1", "url": "https://sub.example.com/a?token=SECRET"},
		map[string]any{"name": "s2"},
		"not-a-dict",
	}
	out := stateSubs(subs)
	if len(out) != 3 {
		t.Fatalf("len = %d, want 3", len(out))
	}
	u := out[0].(map[string]any)["url"].(string)
	if !strings.HasPrefix(u, "https://sub.example.com/") || strings.Contains(u, "SECRET") {
		t.Errorf("url 未正确打码：%q", u)
	}
	if out[1].(map[string]any)["url"] != "" {
		t.Errorf("缺失 url 应补空串，got %v", out[1].(map[string]any)["url"])
	}
	if out[2] != "not-a-dict" {
		t.Errorf("非 dict 条目应原样保留，got %v", out[2])
	}
	if len(stateSubs(nil)) != 0 {
		t.Error("nil 输入应返回空列表")
	}
}

func TestToBool(t *testing.T) {
	cases := []struct {
		in   any
		want bool
	}{
		{nil, false}, {true, true}, {false, false},
		{"", false}, {"x", true}, {"false", true}, // Python bool("false") 为真
		{float64(0), false}, {float64(1), true},
		{[]any{}, false}, {[]any{1}, true},
	}
	for _, c := range cases {
		if got := toBool(c.in); got != c.want {
			t.Errorf("toBool(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestStateNodes(t *testing.T) {
	d := map[string]any{"nodes": []any{
		map[string]any{"proxy": map[string]any{"name": "n1", "type": "ss", "server": "1.2.3.4", "port": 8388}},
		map[string]any{"proxy": map[string]any{"name": "残缺"}}, // 缺字段：跳过
		map[string]any{"broken": true}, // 无 proxy：跳过
		"not-a-map",
	}}
	out := stateNodes(d)
	if len(out) != 1 {
		t.Fatalf("len = %d, want 1（残缺条目应跳过）", len(out))
	}
	n := out[0].(map[string]any)
	if n["name"] != "n1" || n["type"] != "ss" || n["server"] != "1.2.3.4" {
		t.Errorf("节点摘要字段不对：%v", n)
	}
}

func TestPing(t *testing.T) {
	testWebapiEnv(t, "{}")
	code, out := doAPI(t, "GET", "/api/ping", nil)
	if code != 200 {
		t.Fatalf("code = %d, want 200", code)
	}
	if out["ok"] != true {
		t.Errorf("ok = %v, want true", out["ok"])
	}
	if out["core"] != "mihomo" {
		t.Errorf("core = %v, want mihomo", out["core"])
	}
	ver, _ := out["version"].(string)
	if ok, _ := regexp.MatchString(`^\d+\.\d+$`, ver); !ok {
		t.Errorf("version 格式不对：%q", ver)
	}
	if out["ad_today"] != float64(0) {
		t.Errorf("ad_today = %v, want 0", out["ad_today"])
	}
}

func TestState(t *testing.T) {
	testWebapiEnv(t, `{
		"subs": [{"name": "s1", "url": "https://sub.example.com/path?token=SECRET123", "filter": "", "exclude": ""}],
		"tg_token": "123456:ABC-DEF",
		"nodes": [{"proxy": {"name": "n1", "type": "ss", "server": "1.2.3.4", "port": 8388}}, {"broken": 1}],
		"adblock": {"enabled": true}
	}`)
	code, out := doAPI(t, "GET", "/api/state", nil)
	if code != 200 {
		t.Fatalf("code = %d, want 200", code)
	}
	if out["panel_version"] != base.PanelVersion {
		t.Errorf("panel_version = %v, want %v", out["panel_version"], base.PanelVersion)
	}
	if out["core"] != "mihomo" {
		t.Errorf("core = %v, want mihomo", out["core"])
	}
	if _, ok := out["running"].(bool); !ok {
		t.Errorf("running 应为 bool，got %v", out["running"])
	}
	// 接线后策略组正常生成 → 非空名单（与 Python 的语义一致）
	if gs, ok := out["groups"].([]any); !ok || len(gs) == 0 {
		t.Errorf("groups 应为非空列表，got %v", out["groups"])
	}
	subs := out["subs"].([]any)
	if len(subs) != 1 {
		t.Fatalf("subs len = %d, want 1", len(subs))
	}
	u := subs[0].(map[string]any)["url"].(string)
	if !strings.HasPrefix(u, "https://sub.example.com/") || strings.Contains(u, "SECRET123") {
		t.Errorf("订阅 URL 未正确打码：%q", u)
	}
	tg, _ := out["tg_token"].(string)
	if !strings.Contains(tg, "******") || tg == "123456:ABC-DEF" {
		t.Errorf("tg_token 未打码：%q", tg)
	}
	nodes := out["nodes"].([]any)
	if len(nodes) != 1 || nodes[0].(map[string]any)["name"] != "n1" {
		t.Errorf("nodes 摘要不对：%v", out["nodes"])
	}
	wd := out["wd"].(map[string]any)
	if wd["max"] != float64(20) {
		t.Errorf("wd.max = %v, want 20", wd["max"])
	}
	if _, ok := wd["counts"].(map[string]any); !ok {
		t.Errorf("wd.counts 缺失：%v", wd)
	}
	if _, ok := out["dns"].(map[string]any); !ok {
		t.Errorf("dns 缺失或类型不对：%v", out["dns"])
	}
	if out["adblock_on"] != true {
		t.Errorf("adblock_on = %v, want true", out["adblock_on"])
	}
	if out["default_exclude"] != base.DefaultExclude {
		t.Errorf("default_exclude = %v", out["default_exclude"])
	}
}
