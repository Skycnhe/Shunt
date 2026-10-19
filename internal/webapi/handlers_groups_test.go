package webapi

// handlers_groups.go 的测试：findCycle、preview、groups/cfg 校验、自定义组增删的错误路径。
// 成功路径依赖未接线的 stub（mihomo.BuildConfig 内的 activeCore），集成后由联调覆盖。

import (
	"strings"
	"testing"
)

func TestFindCycle(t *testing.T) {
	mk := func(name string, proxies ...string) map[string]any {
		l := make([]any, len(proxies))
		for i, p := range proxies {
			l[i] = p
		}
		return map[string]any{"name": name, "proxies": l}
	}
	cases := []struct {
		name     string
		groups   []any
		wantCyc  bool
		wantJoin string
	}{
		{"无环", []any{mk("A", "B"), mk("B", "C"), mk("C")}, false, ""},
		{"空", []any{}, false, ""},
		{"简单环", []any{mk("A", "B"), mk("B", "A")}, true, "A → B → A"},
		{"自环", []any{mk("A", "A")}, true, "A → A"},
		{"长环", []any{mk("A", "B"), mk("B", "C"), mk("C", "A")}, true, "A → B → C → A"},
		{"引用外部节点不算环", []any{mk("A", "node1"), mk("B", "A")}, false, ""},
	}
	for _, c := range cases {
		got := findCycle(c.groups)
		if !c.wantCyc && got != nil {
			t.Errorf("%s: 不应有环，got %v", c.name, got)
			continue
		}
		if c.wantCyc {
			if got == nil {
				t.Errorf("%s: 应检测到环", c.name)
				continue
			}
			if j := strings.Join(got, " → "); j != c.wantJoin {
				t.Errorf("%s: 环路径 = %q, want %q", c.name, j, c.wantJoin)
			}
		}
	}
}

const previewData = `{"nodes": [
	{"proxy": {"name": "香港 01", "type": "ss", "server": "1.1.1.1", "port": 1}},
	{"proxy": {"name": "香港 02", "type": "ss", "server": "1.1.1.2", "port": 2}},
	{"proxy": {"name": "美国 01", "type": "ss", "server": "2.2.2.2", "port": 3}}
]}`

func TestGroupsPreview(t *testing.T) {
	testWebapiEnv(t, previewData)

	// 正常：命中 2 个香港节点
	code, out := doAPI(t, "POST", "/api/groups/preview", map[string]any{"filter": "香港"})
	if code != 200 {
		t.Fatalf("code = %d, want 200", code)
	}
	if out["total"] != float64(2) || out["of"] != float64(3) {
		t.Errorf("total/of = %v/%v, want 2/3", out["total"], out["of"])
	}
	if len(out["matched"].([]any)) != 2 {
		t.Errorf("matched = %v, want 2 条", out["matched"])
	}

	// 错误：正则无效
	code, out = doAPI(t, "POST", "/api/groups/preview", map[string]any{"filter": "(["})
	if code != 400 || out["message"] != "正则无效" {
		t.Errorf("无效正则应 400 正则无效，got %d %v", code, out)
	}

	// 空过滤：直接返回空
	code, out = doAPI(t, "POST", "/api/groups/preview", map[string]any{"filter": "   "})
	if code != 200 || out["total"] != float64(0) || len(out["matched"].([]any)) != 0 {
		t.Errorf("空过滤应返回空结果，got %d %v", code, out)
	}

	// 超过 200 条截断（matched 只取前 200，total 保持总数）
	code, out = doAPI(t, "POST", "/api/groups/preview", map[string]any{"filter": "."})
	if code != 200 || out["total"] != float64(3) {
		t.Errorf("通配应命中全部，got %d %v", code, out)
	}
}

func TestGroupsCfgPutValidation(t *testing.T) {
	testWebapiEnv(t, "{}")
	cases := []struct {
		name string
		body map[string]any
		msg  string
	}{
		{"非数字间隔", map[string]any{"interval": "abc"}, "测速间隔 / 容差必须是数字"},
		{"非数字容差", map[string]any{"tolerance": "x"}, "测速间隔 / 容差必须是数字"},
		{"间隔过小", map[string]any{"interval": 10}, "测速间隔应在 30–86400 秒之间"},
		{"间隔过大", map[string]any{"interval": 99999}, "测速间隔应在 30–86400 秒之间"},
		{"容差过大", map[string]any{"tolerance": 2000}, "容差应在 0–1000 ms 之间"},
		{"容差负数", map[string]any{"tolerance": -1}, "容差应在 0–1000 ms 之间"},
		{"非法测速地址", map[string]any{"url": "ftp://x"}, "测速地址必须是 http(s) 链接"},
		{"非链接", map[string]any{"url": "not a url"}, "测速地址必须是 http(s) 链接"},
	}
	for _, c := range cases {
		code, out := doAPI(t, "PUT", "/api/groups/cfg", c.body)
		if code != 400 {
			t.Errorf("%s: code = %d, want 400", c.name, code)
			continue
		}
		if out["message"] != c.msg {
			t.Errorf("%s: message = %v, want %q", c.name, out["message"], c.msg)
		}
	}
}

const customGroupsData = `{"custom_groups": [
	{"name": "dup", "type": "select", "proxies": ["DIRECT"]},
	{"name": "被引用", "type": "select", "proxies": ["DIRECT"]},
	{"name": "引用者", "type": "select", "proxies": ["被引用"]}
]}`

func TestGroupsPostValidation(t *testing.T) {
	testWebapiEnv(t, customGroupsData)

	// 正常校验错误：空名
	code, out := doAPI(t, "POST", "/api/groups", map[string]any{"type": "select", "proxies": []string{"DIRECT"}})
	if code != 400 {
		t.Errorf("空名应 400，got %d %v", code, out)
	}

	// 404：编辑不存在的组
	code, out = doAPI(t, "POST", "/api/groups",
		map[string]any{"name": "新组", "type": "select", "proxies": []string{"DIRECT"}, "orig": "不存在"})
	if code != 404 || !strings.Contains(out["message"].(string), "策略组不存在") {
		t.Errorf("编辑不存在的组应 404，got %d %v", code, out)
	}

	// 400：与已有组重名
	code, out = doAPI(t, "POST", "/api/groups",
		map[string]any{"name": "dup", "type": "select", "proxies": []string{"DIRECT"}})
	if code != 400 || !strings.Contains(out["message"].(string), "已存在同名策略组") {
		t.Errorf("重名应 400，got %d %v", code, out)
	}

	// 400：改名撞已有名
	code, out = doAPI(t, "POST", "/api/groups",
		map[string]any{"name": "dup", "type": "select", "proxies": []string{"DIRECT"}, "orig": "被引用"})
	if code != 400 || !strings.Contains(out["message"].(string), "已存在同名策略组") {
		t.Errorf("改名撞名应 400，got %d %v", code, out)
	}
}

func TestGroupsDeleteValidation(t *testing.T) {
	testWebapiEnv(t, customGroupsData)

	// 404：删不存在的组
	code, out := doAPI(t, "DELETE", "/api/groups", map[string]any{"name": "不存在"})
	if code != 404 || !strings.Contains(out["message"].(string), "策略组不存在") {
		t.Errorf("删不存在的组应 404，got %d %v", code, out)
	}

	// 409：被引用且未传 force
	code, out = doAPI(t, "DELETE", "/api/groups", map[string]any{"name": "被引用"})
	if code != 409 {
		t.Fatalf("被引用的组应 409，got %d %v", code, out)
	}
	if !strings.Contains(out["message"].(string), "被其他策略组引用") {
		t.Errorf("409 消息不对：%v", out["message"])
	}
	users, _ := out["users"].([]any)
	if len(users) != 1 || users[0] != "引用者" {
		t.Errorf("users 应为 [引用者]，got %v", users)
	}

	// 方法/路径不存在 → 404（guard 层面）
	code, _ = doAPI(t, "GET", "/api/groups/preview", nil)
	if code != 404 {
		t.Errorf("GET /api/groups/preview 应 404，got %d", code)
	}
}
