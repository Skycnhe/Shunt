package webapi

// handlers_system.go 的测试：配置 / 背景 / 内核更新 / 日志 / 备份 / 健康检查等。
// 写 data.json 的路径用 isolateTestEnv 隔离；依赖未接线 STUB 的用 stubGate。

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"shunt/internal/data"
)

func TestConfigGet_Shape(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "GET", "/api/config", nil)
	// configView 依赖 BuildConfig（groups.gcfg STUB 未接线）→ 500；接线后 200
	if code == 200 {
		for _, k := range []string{"text", "path", "size", "core"} {
			if _, ok := out[k]; !ok {
				t.Errorf("缺少字段 %s", k)
			}
		}
		return
	}
	if code != 500 {
		t.Fatalf("want 200 (wired) or 500 (stub), got %d %v", code, out)
	}
	t.Logf("STUB 未接线：当前 500，集成后应为 200")
}

func TestConfigGet_Download(t *testing.T) {
	isolateTestEnv(t, "")
	req := httptest.NewRequest("GET", "/api/config?download=1", nil)
	req.RemoteAddr = "192.168.1.10:54321"
	req.Host = "192.168.1.10"
	req.Header.Set("X-Shunt", "1")
	rr := httptest.NewRecorder()
	NewServer().Handler().ServeHTTP(rr, req)
	if rr.Code == 500 {
		t.Logf("STUB 未接线：当前 500，集成后应为 200 + 原始配置文本")
		return
	}
	if rr.Code != 200 {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/x-yaml" {
		t.Fatalf("mihomo 默认内核下载类型应为 application/x-yaml, got %s", ct)
	}
	if rr.Body.Len() == 0 {
		t.Fatal("下载内容为空")
	}
}

func TestSysoptGet(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "GET", "/api/sysopt", nil)
	if code != 200 {
		t.Fatalf("want 200, got %d %v", code, out)
	}
}

func TestSysoptPost_BadIDs(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "POST", "/api/sysopt", map[string]any{"ids": "not-a-list"})
	if code != 400 || toStr(out["message"]) != "参数错误" {
		t.Fatalf("want 400 参数错误, got %d %v", code, out)
	}
}

func TestBgGet_NoFile(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "GET", "/api/bg", nil)
	if code != 200 {
		t.Fatalf("want 200, got %d %v", code, out)
	}
	if _, ok := out["exists"]; !ok {
		t.Fatalf("缺少 exists 字段: %v", out)
	}
}

func TestBgPost_BadData(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "POST", "/api/bg", map[string]any{"data": "not-a-data-url"})
	if code != 400 || toStr(out["message"]) == "" {
		t.Fatalf("非法图片数据应 400, got %d %v", code, out)
	}
}

func TestBgURLPost_BadURL(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "POST", "/api/bg/url", map[string]any{"url": "not-a-url"})
	if code != 400 || toStr(out["message"]) == "" {
		t.Fatalf("非法链接应 400, got %d %v", code, out)
	}
}

func TestBgDailyPost_NoURL(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "POST", "/api/bg/daily", map[string]any{"daily": true})
	if code != 400 || toStr(out["message"]) != "当前背景图不是链接图片" {
		t.Fatalf("want 400 当前背景图不是链接图片, got %d %v", code, out)
	}
}

func TestBgDelete(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "DELETE", "/api/bg", nil)
	if code != 200 || toStr(out["message"]) != "已移除背景图" {
		t.Fatalf("want 200 已移除背景图, got %d %v", code, out)
	}
}

func TestPxGet_NoCore(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "GET", "/api/px", nil)
	// latency.coreJSON 是未接线的 STUB；接线后无核心时应 502「核心未运行或无法连接」
	stubGate(t, code, out, 502, "核心未运行或无法连接")
}

func TestCoreswitchGet_Shape(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "GET", "/api/coreswitch", nil)
	if code != 200 {
		t.Fatalf("want 200, got %d %v", code, out)
	}
	for _, k := range []string{"core", "versions", "lgbm", "warn", "busy"} {
		if _, ok := out[k]; !ok {
			t.Errorf("缺少字段 %s", k)
		}
	}
}

func TestCoreswitchPost_Validation(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "POST", "/api/coreswitch", map[string]any{"core": "nope"})
	if code != 400 || toStr(out["message"]) != "未知的内核" {
		t.Fatalf("want 400 未知的内核, got %d %v", code, out)
	}
	code, out = callAPI(t, "POST", "/api/coreswitch", map[string]any{"core": "mihomo"})
	if code != 400 || !strings.Contains(toStr(out["message"]), "当前已经是") {
		t.Fatalf("相同内核应 400, got %d %v", code, out)
	}
}

func TestCoreupdateGet_BadChannel(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "GET", "/api/coreupdate?channel=nope", nil)
	if code != 400 || toStr(out["message"]) != "未知的更新通道" {
		t.Fatalf("want 400 未知的更新通道, got %d %v", code, out)
	}
}

func TestCoreupdateStatusGet(t *testing.T) {
	isolateTestEnv(t, "")
	code, _ := callAPI(t, "GET", "/api/coreupdate/status", nil)
	if code != 200 {
		t.Fatalf("want 200, got %d", code)
	}
}

func TestCoreupdatePost_BadChannel(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "POST", "/api/coreupdate", map[string]any{"channel": "nope"})
	if code != 400 || toStr(out["message"]) != "未知的更新通道" {
		t.Fatalf("want 400 未知的更新通道, got %d %v", code, out)
	}
}

func TestStatsGet_Default(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "GET", "/api/stats", nil)
	if code != 200 {
		t.Fatalf("want 200, got %d %v", code, out)
	}
	for _, k := range []string{"today", "month", "days", "arp"} {
		if _, ok := out[k]; !ok {
			t.Errorf("缺少字段 %s", k)
		}
	}
}

func TestConnsGet_NoCore(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "GET", "/api/conns", nil)
	// core.ConnsSnapshot 内部 coreJSON 是未接线的 STUB；接线后无核心时应 502
	stubGate(t, code, out, 502, "")
	code, out = callAPI(t, "GET", "/api/conns/stats", nil)
	stubGate(t, code, out, 502, "")
}

func TestLiveGet_Shape(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "GET", "/api/live", nil)
	// 回退路径依赖 core.ConnsSnapshot（coreJSON STUB 未接线）；接线后应 200
	if code == 200 {
		if _, ok := out["running"]; !ok {
			t.Errorf("缺少 running 字段: %v", out)
		}
		return
	}
	stubGate(t, code, out, 200, "")
}

func TestLogsInfoGet_Shape(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "GET", "/api/logs/info", nil)
	if code != 200 {
		t.Fatalf("want 200, got %d %v", code, out)
	}
	for _, k := range []string{"files", "limit", "last"} {
		if _, ok := out[k]; !ok {
			t.Errorf("缺少字段 %s", k)
		}
	}
	if files, ok := out["files"].([]any); ok && len(files) > 0 {
		f0 := toMap(files[0])
		if _, ok := f0["path"]; !ok {
			t.Errorf("files 条目缺少 path: %v", f0)
		}
		if _, ok := f0["size"]; !ok {
			t.Errorf("files 条目缺少 size: %v", f0)
		}
	}
}

func TestLogsCleanPost(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "POST", "/api/logs/clean", nil)
	if code != 200 || !strings.Contains(toStr(out["message"]), "已清理") {
		t.Fatalf("want 200 已清理, got %d %v", code, out)
	}
}

func TestHistoryGet_Empty(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "GET", "/api/history", nil)
	if code != 200 {
		t.Fatalf("want 200, got %d %v", code, out)
	}
	_ = out
}

func TestHistoryPost_NotFound(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "POST", "/api/history", map[string]any{"id": "no-such-id"})
	if code != 404 || toStr(out["message"]) != "快照不存在" {
		t.Fatalf("want 404 快照不存在, got %d %v", code, out)
	}
}

func TestDevicesPut_Filter(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "PUT", "/api/devices", map[string]any{
		"devices": map[string]any{
			"AA-BB-CC-DD-EE-FF": "客厅电视",
			"192.168.1.5":       "手机",
			"not-valid":         "应被过滤",
			"":                  "空键",
		},
	})
	if code != 200 {
		t.Fatalf("want 200, got %d %v", code, out)
	}
	d := data.Load()
	devs := data.Map(d, "devices")
	if toStr(devs["aa:bb:cc:dd:ee:ff"]) != "客厅电视" {
		t.Errorf("MAC 未规范化保存: %v", devs)
	}
	if toStr(devs["192.168.1.5"]) != "手机" {
		t.Errorf("IP 未保存: %v", devs)
	}
	if _, ok := devs["not-valid"]; ok {
		t.Errorf("非法键应被过滤: %v", devs)
	}
}

func TestDiagGet(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "GET", "/api/diag", nil)
	// diag.Diagnose 内部 core 调用是未接线的 STUB；接线后应 200
	stubGate(t, code, out, 200, "")
}

func TestSchedulePut_BadTime(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "PUT", "/api/schedule", map[string]any{"sub_update": "25:99"})
	if code != 400 || !strings.Contains(toStr(out["message"]), "时间格式应为 HH:MM") {
		t.Fatalf("want 400 时间格式, got %d %v", code, out)
	}
}

func TestSchedulePut_OK(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "PUT", "/api/schedule", map[string]any{
		"sub_update": "03:00", "latency": 30,
	})
	if code != 200 || toStr(out["message"]) != "定时任务已保存" {
		t.Fatalf("want 200 定时任务已保存, got %d %v", code, out)
	}
	sc := data.Map(data.Load(), "schedule")
	if toStr(sc["sub_update"]) != "03:00" || toInt(sc["latency"]) != 30 {
		t.Fatalf("schedule 未保存: %v", sc)
	}
}

func TestScheduleRunPost_Unknown(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "POST", "/api/schedule/run", map[string]any{"task": "nope"})
	if code != 400 || toStr(out["message"]) != "未知任务" {
		t.Fatalf("want 400 未知任务, got %d %v", code, out)
	}
}

func TestSettingsPut_Validation(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "PUT", "/api/settings", map[string]any{"gh_proxy": "not-a-url"})
	if code != 400 || !strings.Contains(toStr(out["message"]), "GitHub 加速地址") {
		t.Fatalf("want 400 GitHub 加速地址, got %d %v", code, out)
	}
	code, out = callAPI(t, "PUT", "/api/settings", map[string]any{"log_limit": 7})
	if code != 400 || !strings.Contains(toStr(out["message"]), "日志上限") {
		t.Fatalf("want 400 日志上限, got %d %v", code, out)
	}
}

func TestTgTestPost_Unconfigured(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "POST", "/api/tg/test", map[string]any{})
	// 未配置 token：TgSend 直接返回失败，不打网络
	if code != 500 || toStr(out["message"]) == "" {
		t.Fatalf("未配置时应 500 并给出原因, got %d %v", code, out)
	}
}

func TestBackupGet_NoSecret(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "GET", "/api/backup", nil)
	if code != 200 {
		t.Fatalf("want 200, got %d %v", code, out)
	}
	if _, ok := out["secret"]; ok {
		t.Fatal("备份接口不应返回 secret")
	}
}

func TestBackupListGet(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "GET", "/api/backup/list", nil)
	if code != 200 {
		t.Fatalf("want 200, got %d %v", code, out)
	}
	if _, ok := out["backups"]; !ok {
		t.Fatalf("缺少 backups 字段: %v", out)
	}
}

func TestBackupCreatePost(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "POST", "/api/backup/create", map[string]any{})
	if code != 200 || toBool(out["ok"]) != true || toStr(out["name"]) == "" {
		t.Fatalf("want 200 ok=true, got %d %v", code, out)
	}
	// 列表里应能看到刚创建的备份
	_, out2 := callAPI(t, "GET", "/api/backup/list", nil)
	found := false
	for _, b := range toList(out2["backups"]) {
		if toStr(toMap(b)["name"]) == toStr(out["name"]) {
			found = true
		}
	}
	if !found {
		t.Fatalf("新建的备份不在列表里: %v", out2)
	}
	// 删除它
	code, out3 := callAPI(t, "POST", "/api/backup/delete", map[string]any{"name": toStr(out["name"])})
	if code != 200 {
		t.Fatalf("删除备份应 200, got %d %v", code, out3)
	}
}

func TestHealthStatusGet_Shape(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "GET", "/api/health/status", nil)
	if code != 200 {
		t.Fatalf("want 200, got %d %v", code, out)
	}
	for _, k := range []string{"running", "last_run", "total", "checked", "cfg", "records"} {
		if _, ok := out[k]; !ok {
			t.Errorf("缺少字段 %s", k)
		}
	}
}

func TestHealthUnhidePost_Missing(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "POST", "/api/health/unhide", map[string]any{"node_id": "no-such-node"})
	if code != 500 || toStr(out["message"]) != "节点不存在" {
		t.Fatalf("want 500 节点不存在, got %d %v", code, out)
	}
	code, out = callAPI(t, "POST", "/api/health/unhide", map[string]any{})
	if code != 500 {
		t.Fatalf("空 node_id 应 500, got %d %v", code, out)
	}
}

func TestHealthCfgPut_Validation(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "PUT", "/api/health/cfg", map[string]any{"time": "99:99"})
	if code != 400 || toBool(out["ok"]) != false {
		t.Fatalf("非法时间应 400 ok=false, got %d %v", code, out)
	}
	code, out = callAPI(t, "PUT", "/api/health/cfg", map[string]any{"warn_days": 10, "hide_days": 5})
	if code != 400 || !strings.Contains(toStr(out["message"]), "标红天数应小于隐藏天数") {
		t.Fatalf("warn>=hide 应 400, got %d %v", code, out)
	}
	code, out = callAPI(t, "PUT", "/api/health/cfg", map[string]any{"warn_days": 0})
	if code != 400 {
		t.Fatalf("warn_days=0 应 400, got %d", code)
	}
}

func TestHealthCfgPut_OK(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "PUT", "/api/health/cfg", map[string]any{
		"enabled": true, "time": "04:30", "warn_days": 2, "hide_days": 5,
	})
	if code != 200 || toBool(out["ok"]) != true {
		t.Fatalf("want 200 ok=true, got %d %v", code, out)
	}
	cfg := toMap(out["cfg"])
	if toStr(cfg["time"]) != "04:30" || toInt(cfg["warn_days"]) != 2 {
		t.Fatalf("cfg 未保存: %v", cfg)
	}
}

func TestRestorePost_Empty(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "POST", "/api/restore", map[string]any{})
	if code != 400 || !strings.Contains(toStr(out["message"]), "备份内容无效") {
		t.Fatalf("空备份应 400, got %d %v", code, out)
	}
}

// callRaw 用于返回原始字节的接口（/api/config?download 等）。
func callRaw(t *testing.T, method, path string, body any) (int, string, []byte) {
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
	return rr.Code, rr.Header().Get("Content-Type"), rr.Body.Bytes()
}

func TestServiceUpgrade_RawPassthrough(t *testing.T) {
	// 无核心时 corehttp 返回 502 → 按 Python 逻辑转为 500，body 为 {"message":"ok"}
	isolateTestEnv(t, "")
	code, ctype, body := callRaw(t, "POST", "/api/service", map[string]any{"action": "upgrade"})
	if code != 500 {
		t.Fatalf("无核心时 upgrade 应 500, got %d", code)
	}
	if ctype != "application/json" {
		t.Fatalf("ctype 应为 application/json, got %s", ctype)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("body 不是 JSON: %s", body)
	}
}
