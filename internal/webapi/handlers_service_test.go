package webapi

// handlers_service.go 的测试：GET 状态、未知操作、忙时 409、sing-box 下 upgrade 拦截。
// 注意：真正执行 rc-service 的启停路径不测（会操作系统服务）。

import (
	"strings"
	"testing"
)

func TestServiceGet_Shape(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "GET", "/api/service", nil)
	// notify.CoreProcAlive 依赖 corePid STUB（未接线）；接线后应 200
	if code == 200 {
		for _, k := range []string{"busy", "act", "ok", "message", "t", "alive"} {
			if _, ok := out[k]; !ok {
				t.Errorf("缺少字段 %s", k)
			}
		}
		return
	}
	stubGate(t, code, out, 200, "")
}

func TestServicePost_UnknownAction(t *testing.T) {
	isolateTestEnv(t, "")
	code, out := callAPI(t, "POST", "/api/service", map[string]any{"action": "nope"})
	if code != 400 || toStr(out["message"]) != "未知操作" {
		t.Fatalf("want 400 未知操作, got %d %v", code, out)
	}
}

func TestServicePost_Busy409(t *testing.T) {
	isolateTestEnv(t, "")
	svcOpMu.Lock() // 模拟已有启停操作在进行
	defer svcOpMu.Unlock()
	code, out := callAPI(t, "POST", "/api/service", map[string]any{"action": "restart"})
	if code != 409 {
		t.Fatalf("忙时应 409, got %d %v", code, out)
	}
	if !strings.Contains(toStr(out["message"]), "核心，请稍候") {
		t.Fatalf("409 消息格式不对: %v", out)
	}
}

func TestServicePost_UpgradeSingboxBlocked(t *testing.T) {
	isolateTestEnv(t, `{"core": "singbox"}`)
	code, out := callAPI(t, "POST", "/api/service", map[string]any{"action": "upgrade"})
	if code != 400 || !strings.Contains(toStr(out["message"]), "内核更新") {
		t.Fatalf("sing-box 下 upgrade 应 400 提示去内核更新, got %d %v", code, out)
	}
}
