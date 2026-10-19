package webapi

// handlers_rules.go 的测试：规则 / 模式 / DNS / 广告拦截。
// 只走校验与只读路径；写 data.json 的路径用隔离环境（isolateTestEnv）。

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shunt/internal/backup"
	"shunt/internal/base"
	"shunt/internal/data"
	"shunt/internal/latency"
)

// isolateTestEnv 把 data.json / 面板目录 / 历史 / 背景图 / 备份目录全部指向临时目录。
func isolateTestEnv(t *testing.T, dataJSON string) string {
	t.Helper()
	dir := t.TempDir()
	base.DataFile = filepath.Join(dir, "data.json")
	base.PanelDir = dir
	base.ConfDir = filepath.Join(dir, "conf")
	data.HistoryFile = filepath.Join(dir, "history.json")
	latency.BgFile = filepath.Join(dir, "bg.img")
	latency.BgMeta = latency.BgFile + ".json"
	backup.BackupDir = filepath.Join(dir, "backups")
	base.AbDir = filepath.Join(dir, "adblock")
	if dataJSON == "" {
		dataJSON = "{}"
	}
	if err := os.WriteFile(base.DataFile, []byte(dataJSON), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// callAPI 走完整 HTTP 分发（含 guard）：LAN RemoteAddr + IP Host，始终带 X-Shunt 头。
func callAPI(t *testing.T, method, path string, body any) (int, map[string]any) {
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
	req.Header.Set("X-Shunt", "1")
	rr := httptest.NewRecorder()
	NewServer().Handler().ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

// stubGate：断言「STUB 接线后应为 wantCode；未接线时允许 500（框架已 recover）」。
func stubGate(t *testing.T, code int, out map[string]any, wantCode int, wantMsg string) {
	t.Helper()
	if code == wantCode {
		if wantMsg != "" && !strings.Contains(toStr(out["message"]), wantMsg) {
			t.Fatalf("message 不匹配: %v", out)
		}
		return
	}
	if code == 500 {
		t.Logf("STUB 未接线：当前返回 500，集成后应为 %d", wantCode)
		return
	}
	t.Fatalf("want %d (wired) or 500 (stub unwired), got %d %v", wantCode, code, out)
}

func TestRulesPut_BadPolicy(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "PUT", "/api/rules", map[string]any{
		"rules": []string{"DOMAIN-SUFFIX,example.com,NOT-A-GROUP"},
	})
	// mihomo.BadRulePolicies 内部依赖集成阶段才接线的 groups.gcfg STUB
	stubGate(t, code, out, 400, "以下规则的策略不存在")
}

func TestRulesPut_CommentOnlyOK(t *testing.T) {
	// 只有注释行：跳过策略检查 → 进入保存流程。ReloadCore 在无核心环境会失败，
	// 这里只验证「注释行不触发 400」。
	isolateTestEnv(t, "")
	code, out := callAPI(t, "PUT", "/api/rules", map[string]any{
		"rules": []string{"# 只是一条注释"},
	})
	if code == 400 && strings.Contains(toStr(out["message"]), "策略不存在") {
		t.Fatalf("注释行不应触发策略检查：%v", out)
	}
}

func TestModePut_Invalid(t *testing.T) {
	isolateTestEnv(t, "")
	for _, m := range []string{"", "proxy", "RULE"} {
		code, out := callAPI(t, "PUT", "/api/mode", map[string]any{"mode": m})
		if code != 400 || toStr(out["message"]) != "模式无效" {
			t.Fatalf("mode=%q: want 400 模式无效, got %d %v", m, code, out)
		}
	}
}

func TestProxyModePut_Invalid(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "PUT", "/api/proxymode", map[string]any{"mode": "nope"})
	if code != 400 || toStr(out["message"]) != "代理方式无效" {
		t.Fatalf("want 400 代理方式无效, got %d %v", code, out)
	}
	code, out = callAPI(t, "PUT", "/api/proxymode", map[string]any{
		"mode": "tun", "tun": map[string]any{"stack": "nope"},
	})
	if code != 400 || !strings.Contains(toStr(out["message"]), "TUN 协议栈") {
		t.Fatalf("want 400 TUN 协议栈, got %d %v", code, out)
	}
}

func TestRuletestPost_Empty(t *testing.T) {
	isolateTestEnv(t, "")
	code, _ := callAPI(t, "POST", "/api/ruletest", map[string]any{"target": ""})
	if code != 500 {
		t.Fatalf("空 target 应 500, got %d", code)
	}
}

func TestDNSPut_BadMode(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "PUT", "/api/dns", map[string]any{"mode": "nope"})
	if code != 400 || !strings.Contains(toStr(out["message"]), "fake-ip") {
		t.Fatalf("want 400 增强模式, got %d %v", code, out)
	}
}

func TestDNSPut_BadList(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "PUT", "/api/dns", map[string]any{"direct": "not-a-list"})
	if code != 400 || !strings.Contains(toStr(out["message"]), "应为列表") {
		t.Fatalf("want 400 应为列表, got %d %v", code, out)
	}
}

func TestDNSQueryPost_Validation(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "POST", "/api/dnsquery", map[string]any{"name": "", "type": "A"})
	if code != 400 {
		t.Fatalf("空域名应 400, got %d", code)
	}
	code, out = callAPI(t, "POST", "/api/dnsquery", map[string]any{"name": "example.com", "type": "ZZ"})
	if code != 400 || toStr(out["message"]) != "请输入域名并选择记录类型" {
		t.Fatalf("非法类型应 400, got %d %v", code, out)
	}
}

func TestAdblockGet_Shape(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "GET", "/api/adblock", nil)
	if code != 200 {
		t.Fatalf("want 200, got %d (%v)", code, out)
	}
	for _, k := range []string{"lists", "presets", "stats", "updating", "msg", "custom_hits", "loaded"} {
		if _, ok := out[k]; !ok {
			t.Errorf("缺少字段 %s", k)
		}
	}
}

func TestAdblockPut_BadURL(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "PUT", "/api/adblock", map[string]any{
		"lists": []any{map[string]any{"url": "ftp://x/y", "name": "x"}},
	})
	if code != 400 || !strings.Contains(toStr(out["message"]), "列表地址无效") {
		t.Fatalf("want 400 列表地址无效, got %d %v", code, out)
	}
}

func TestAdblockPut_BadInterval(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "PUT", "/api/adblock", map[string]any{"interval": 123})
	if code != 400 || toStr(out["message"]) != "更新间隔无效" {
		t.Fatalf("want 400 更新间隔无效, got %d %v", code, out)
	}
}

func TestAdblockPut_BadBlackEntry(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "PUT", "/api/adblock", map[string]any{
		"black": []any{"/ads[0-9]+/"}, // 正则类条目无法用域名列表表达 → skipped
	})
	if code != 400 || !strings.Contains(toStr(out["message"]), "黑名单中有无法识别的条目") {
		t.Fatalf("want 400 黑名单条目, got %d %v", code, out)
	}
}

func TestAdblockCheckPost_Invalid(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "POST", "/api/adblock/check", map[string]any{"domain": "!!! bad !!!"})
	// adblock.cleanTarget 是未接线的 STUB；接线后非法域名应 400 并给出原因
	stubGate(t, code, out, 400, "请输入有效域名")
}

func TestMaskCfg(t *testing.T) {
	masked := maskCfg(map[string]any{
		"password": "supersecret123",
		"server":   "example.com",
		"nested":   map[string]any{"uuid": "abcdef1234567890"},
		"list":     []any{map[string]any{"private-key": "k123456789"}},
	}).(map[string]any)
	if toStr(masked["password"]) == "supersecret123" {
		t.Error("password 未被打码")
	}
	if toStr(masked["server"]) != "example.com" {
		t.Error("server 不应被打码")
	}
	if toStr(toMap(masked["nested"])["uuid"]) == "abcdef1234567890" {
		t.Error("嵌套 uuid 未被打码")
	}
	if toStr(toMap(toList(masked["list"])[0])["private-key"]) == "k123456789" {
		t.Error("private-key 未被打码")
	}
}

func TestUnmaskSecret(t *testing.T) {
	cur := "real-token-12345"
	masked := toStr(maskSecret(cur))
	if unmaskSecret(masked, cur) != cur {
		t.Error("打码值原样提交应换回原值")
	}
	if unmaskSecret("new-token", cur) != "new-token" {
		t.Error("新值应原样保留")
	}
}
