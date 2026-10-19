package webapi

// handlers_nodes.go 的测试：/api/subs 与 /api/nodes 的校验错误路径。
// 成功路径依赖未接线的 stub（订阅下载、核心重载），集成后由联调覆盖。

import (
	"strings"
	"testing"
)

func TestSubsPostValidation(t *testing.T) {
	testWebapiEnv(t, `{"subs": [{"name": "Test 1", "url": "https://a.example.com/sub", "filter": "", "exclude": ""}]}`)
	cases := []struct {
		name string
		body map[string]any
		msg  string
	}{
		{"空名", map[string]any{"name": "", "url": "https://x.example.com"}, "名称或订阅链接无效"},
		{"非法链接", map[string]any{"name": "s1", "url": "not-a-url"}, "名称或订阅链接无效"},
		{"只差符号", map[string]any{"name": "Test_1", "url": "https://x.example.com"}, "只差符号"},
		{"filter 正则无效", map[string]any{"name": "s2", "url": "https://x.example.com", "filter": "(["}, "正则表达式无效"},
		{"exclude 正则无效", map[string]any{"name": "s2", "url": "https://x.example.com", "exclude": "(["}, "正则表达式无效"},
	}
	for _, c := range cases {
		code, out := doAPI(t, "POST", "/api/subs", c.body)
		if code != 400 {
			t.Errorf("%s: code = %d, want 400", c.name, code)
			continue
		}
		if !strings.Contains(out["message"].(string), c.msg) {
			t.Errorf("%s: message = %v, want 包含 %q", c.name, out["message"], c.msg)
		}
	}
}

func TestNodesPostValidation(t *testing.T) {
	testWebapiEnv(t, "{}")

	// 空 links
	code, out := doAPI(t, "POST", "/api/nodes", map[string]any{"links": ""})
	if code != 400 || out["message"] != "没有可导入的节点" {
		t.Errorf("空 links 应 400 没有可导入的节点，got %d %v", code, out)
	}

	// 全是非法行：错误明细拼在消息里
	code, out = doAPI(t, "POST", "/api/nodes", map[string]any{"links": "not a link\nhttp://"})
	if code != 400 {
		t.Fatalf("非法 links 应 400，got %d", code)
	}
	msg := out["message"].(string)
	if !strings.HasPrefix(msg, "没有可导入的节点：\n") || !strings.Contains(msg, "第 1 行") {
		t.Errorf("错误明细格式不对：%q", msg)
	}

	// 缺 links 参数
	code, out = doAPI(t, "POST", "/api/nodes", map[string]any{})
	if code != 400 {
		t.Errorf("缺 links 应 400，got %d", code)
	}
}
