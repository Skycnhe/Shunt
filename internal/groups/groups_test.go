package groups

import (
	"strings"
	"testing"

	"shunt/internal/base"
)

func TestRxLookbehind(t *testing.T) {
	// base.Regions 的 (?<![A-Za-z]) / (?![A-Za-z]) 在 Go RE2 下必须可用（等价改写）
	rx := Rx(`(?<![A-Za-z])HKG?(?![A-Za-z])`)
	if rx == nil {
		t.Fatal("Rx 编译失败")
	}
	for _, s := range []string{"HKG-01", "HK HKG", "node HKG ", "xx,HKG,"} {
		if !rx.MatchString(s) {
			t.Errorf("应匹配 %q", s)
		}
	}
	for _, s := range []string{"XHKGY", "AHKG", "HKGB"} {
		if rx.MatchString(s) {
			t.Errorf("不应匹配 %q（前后是 ASCII 字母）", s)
		}
	}
	// 同一 pattern 走缓存
	if Rx(`(?<![A-Za-z])HKG?(?![A-Za-z])`) != rx {
		t.Error("Rx 缓存未命中")
	}
	if Rx(`([`) != nil {
		t.Error("无效正则应返回 nil")
	}
	if Rx(`([`) != nil {
		t.Error("无效正则缓存应稳定返回 nil")
	}
}

func TestRegionPlanBasic(t *testing.T) {
	d := map[string]any{
		"region_groups": true,
		"subs":          []any{},
	}
	names := []string{"香港 01", "HK-Node HKG", "US Los Angeles", "JP Tokyo", "未知节点"}
	plan := RegionPlan(d, names, false)
	byName := map[string]RegionEntry{}
	for _, e := range plan {
		byName[e.Name] = e
	}
	hk, ok := byName["🇭🇰 香港"]
	if !ok {
		t.Fatalf("缺少香港分组，实际：%v", namesOf(plan))
	}
	if hk.Total != 2 || len(hk.Manual) != 2 {
		t.Errorf("香港 total/manual = %d/%d，want 2/2", hk.Total, len(hk.Manual))
	}
	if hk.Filter == "" || hk.Unknown {
		t.Error("香港 Filter 不应为空，Unknown 应为 false")
	}
	if _, ok := byName["🇺🇸 美国"]; !ok {
		t.Error("缺少美国分组")
	}
	other, ok := byName[base.GOther]
	if !ok {
		t.Fatalf("缺少其他分组，实际：%v", namesOf(plan))
	}
	if other.Total != 1 || len(other.Manual) != 1 || other.Manual[0] != "未知节点" {
		t.Errorf("其他分组 = %+v", other)
	}
	if other.Exclude == "" || !strings.Contains(other.Exclude, "香港") {
		t.Error("其他分组的 Exclude 应为各地区正则的 | 连接")
	}
	// 没有节点的地区不应出现
	if _, ok := byName["🇩🇪 德国"]; ok {
		t.Error("德国无节点，不应出现在规划里")
	}
}

func TestRegionPlanUnknownSubs(t *testing.T) {
	// use=false 且有订阅 → unknown=true，前 5 个常用地区即使 total=0 也保留
	d := map[string]any{
		"region_groups": true,
		"subs":          []any{map[string]any{"name": "sub1"}},
	}
	plan := RegionPlan(d, []string{"香港 01"}, false)
	if len(plan) < 5 {
		t.Fatalf("unknown 时应保留 5 个常用地区，实际 %d 个", len(plan))
	}
	for _, e := range plan[:5] {
		if !e.Unknown {
			t.Errorf("%s 的 Unknown 应为 true", e.Name)
		}
	}
}

func TestRegionPlanDisabled(t *testing.T) {
	d := map[string]any{"region_groups": false}
	if plan := RegionPlan(d, []string{"香港 01"}, false); len(plan) != 0 {
		t.Error("region_groups=false 应返回空")
	}
	if plan := RegionPlan(map[string]any{}, nil, false); len(plan) != 0 {
		t.Error("无 use 无 names 应返回空")
	}
}

func TestCleanCustomGroup(t *testing.T) {
	g, err := CleanCustomGroup(map[string]any{
		"name": "我的组", "type": "url-test", "proxies": []any{"a", "a", "b"},
		"interval": 60, "tolerance": 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	if g["name"] != "我的组" || g["type"] != "url-test" {
		t.Errorf("基本字段不对：%v", g)
	}
	if got := g["proxies"].([]string); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("proxies 去重保序失败：%v", got)
	}
	if g["subs"] != true || g["expose"] != true {
		t.Error("subs/expose 默认应为 true")
	}

	lb, err := CleanCustomGroup(map[string]any{"name": "lb", "type": "load-balance", "filter": "HK"})
	if err != nil {
		t.Fatal(err)
	}
	if lb["strategy"] != "consistent-hashing" {
		t.Error("load-balance 应固定 consistent-hashing")
	}

	bads := []map[string]any{
		{"name": "a,b", "proxies": []any{"x"}},                 // 逗号
		{"name": "", "proxies": []any{"x"}},                    // 空名
		{"name": "ok", "type": "smart", "proxies": []any{"x"}}, // 非法类型
		{"name": "ok"}, // 无成员无 filter
		{"name": "ok", "proxies": []any{"x"}, "filter": "([bad"},                     // 无效正则
		{"name": "ok", "proxies": []any{"x"}, "icon": "notaurl"},                     // 非法图标
		{"name": "ok", "type": "url-test", "proxies": []any{"x"}, "interval": 10},    // 间隔太小
		{"name": "ok", "type": "url-test", "proxies": []any{"x"}, "tolerance": 2000}, // 容差太大
		{"name": "ok", "type": "url-test", "proxies": []any{"x"}, "interval": "abc"}, // 非数字
	}
	for i, b := range bads {
		if _, err := CleanCustomGroup(b); err == nil {
			t.Errorf("bads[%d] 应报错：%v", i, b)
		}
	}
}

func TestGcfg(t *testing.T) {
	gc := Gcfg(map[string]any{"groups_cfg": map[string]any{"interval": 120, "nope": 1}})
	if gc["interval"] != 120 {
		t.Error("groups_cfg 应覆盖默认值")
	}
	if _, ok := gc["nope"]; ok {
		t.Error("非 GROUPS_DEFAULT 的键应被过滤")
	}
	if gc["type"] != "url-test" || gc["strategy"] != "consistent-hashing" {
		t.Error("type/strategy 应被强制固定")
	}
}

func namesOf(plan []RegionEntry) []string {
	var out []string
	for _, e := range plan {
		out = append(out, e.Name)
	}
	return out
}
