package ipinfo

import (
	"testing"
)

func TestLocDedup(t *testing.T) {
	cases := []struct{ in, want string }{
		{"中国 重庆 重庆 电信", "中国 重庆 电信"},
		{"北京市 北京", "北京"},
		{"重庆市 重庆", "重庆"},
		{"吉林省 吉林市", "吉林省 吉林市"}, // 两级地名，保留
		{"中国 上海 电信", "中国 上海 电信"},
		{"", ""},
	}
	for _, c := range cases {
		if got := LocDedup(c.in); got != c.want {
			t.Errorf("LocDedup(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBackoff(t *testing.T) {
	cases := map[int]int{0: 5, 1: 5, 2: 10, 3: 20, 4: 40, 5: 60, 10: 60}
	for n, want := range cases {
		if got := Backoff(n); got != want {
			t.Errorf("Backoff(%d) = %d, want %d", n, got, want)
		}
	}
}

func fullResult() map[string]any {
	return map[string]any{
		"direct": map[string]any{"ip": "1.2.3.4", "loc": "中国 上海 电信"},
		"proxy":  map[string]any{"ip": "5.6.7.8", "loc": "美国 洛杉矶"},
	}
}

func TestGetIPInfoCache(t *testing.T) {
	Reset()
	calls := 0
	q := func() map[string]any { calls++; return fullResult() }
	got := GetIPInfo(q)
	if _, hasRetry := got["retry"]; hasRetry {
		t.Error("两边都查到不应有 retry")
	}
	got2 := GetIPInfo(q)
	if calls != 1 {
		t.Errorf("缓存期内不应重复查询，calls=%d", calls)
	}
	if got2["direct"].(map[string]any)["ip"] != "1.2.3.4" {
		t.Errorf("缓存值不对：%v", got2)
	}
}

func TestGetIPInfoBackoff(t *testing.T) {
	Reset()
	calls := 0
	q := func() map[string]any {
		calls++
		return map[string]any{
			"direct": map[string]any{"ip": "", "loc": ""},
			"proxy":  map[string]any{"ip": "5.6.7.8", "loc": ""},
		}
	}
	got := GetIPInfo(q)
	retry, ok := got["retry"].(int)
	if !ok || retry != 5 {
		t.Fatalf("首次失败 retry 应为 5，实际 %v", got["retry"])
	}
	got2 := GetIPInfo(q)
	if calls != 1 {
		t.Errorf("退避期内不应重查，calls=%d", calls)
	}
	if got2["retry"] != retry && got2["retry"].(int) < 1 {
		t.Errorf("退避期应返回剩余 retry：%v", got2["retry"])
	}
	Reset()
	got3 := GetIPInfo(q)
	if calls != 2 {
		t.Errorf("Reset 后应允许重查，calls=%d", calls)
	}
	if got3["retry"].(int) != 5 {
		t.Errorf("Reset 后退避计数清零，retry 应为 5，实际 %v", got3["retry"])
	}
	// 不 Reset、把 next 拨到过去 → 退避升级
	ipCache.Lock()
	ipCache.next = nowSec() - 1
	ipCache.Unlock()
	got4 := GetIPInfo(q)
	if calls != 3 {
		t.Fatalf("退避期过后应重查，calls=%d", calls)
	}
	if got4["retry"].(int) != 10 {
		t.Errorf("第二次失败退避应为 10，实际 %v", got4["retry"])
	}
	Reset()
}

func TestGetIPInfoPartialGeo(t *testing.T) {
	Reset()
	// 归属地缺一边：仍缓存但只 2 分钟有效——用 fail=0 且 t 被回拨验证
	q := func() map[string]any {
		return map[string]any{
			"direct": map[string]any{"ip": "1.2.3.4", "loc": ""},
			"proxy":  map[string]any{"ip": "5.6.7.8", "loc": "美国"},
		}
	}
	got := GetIPInfo(q)
	if _, hasRetry := got["retry"]; hasRetry {
		t.Error("两边 IP 都查到不应有 retry")
	}
	ipCache.Lock()
	stale := ipCache.t < nowSec()-300 // t 应被回拨约 8 分钟
	ipCache.Unlock()
	if !stale {
		t.Error("归属地缺失时缓存时间应被回拨")
	}
	Reset()
}
