package devroute

import (
	"reflect"
	"strings"
	"testing"
)

func resetSeen() {
	seenState.Lock()
	seenState.m = map[string][]string{}
	seenState.Unlock()
}

func TestNormMac(t *testing.T) {
	if got := NormMac("AA-BB-CC-DD-EE-FF"); got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("NormMac = %q", got)
	}
	if got := NormMac("aa:bb:cc:dd:ee:ff"); got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("NormMac = %q", got)
	}
	for _, bad := range []any{"aa:bb:cc", "zz:bb:cc:dd:ee:ff", "", nil, 123} {
		if got := NormMac(bad); got != "" {
			t.Errorf("NormMac(%v) = %q，应为空", bad, got)
		}
	}
}

func TestNormIP(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{"192.168.1.1", "192.168.1.1"},
		{" 10.0.0.1 ", "10.0.0.1"},
		{"192.168.1.0/24", "192.168.1.0/24"},
		{"::1", "::1"},
		{"bad", ""},
		{"", ""},
		{nil, ""},
	}
	for _, c := range cases {
		if got := NormIP(c.in); got != c.want {
			t.Errorf("NormIP(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCleanDeviceRoutes(t *testing.T) {
	got, err := CleanDeviceRoutes([]any{
		map[string]any{"ip": "192.168.1.5", "target": "DIRECT", "name": "  电视  "},
		map[string]any{"mac": "AA-BB-CC-DD-EE-FF", "target": "REJECT", "enabled": false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("条数 = %d", len(got))
	}
	if got[0].IP != "192.168.1.5" || got[0].Target != "DIRECT" || got[0].Name != "电视" || !got[0].Enabled {
		t.Errorf("条目 1 不对：%+v", got[0])
	}
	if got[1].Mac != "aa:bb:cc:dd:ee:ff" || got[1].Enabled {
		t.Errorf("条目 2 不对：%+v", got[1])
	}
	if got[1].Name != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("无名时 Name 应回退为 key：%+v", got[1])
	}

	bads := []any{
		"notalist",
		[]any{map[string]any{"ip": "1.1.1.1", "mac": "aa:bb:cc:dd:ee:ff", "target": "DIRECT"}},                          // IP/MAC 二选一
		[]any{map[string]any{"target": "DIRECT"}},                                                                       // 都没填
		[]any{map[string]any{"ip": "bad", "target": "DIRECT"}},                                                          // 非法 IP
		[]any{map[string]any{"mac": "bad", "target": "DIRECT"}},                                                         // 非法 MAC
		[]any{map[string]any{"ip": "1.1.1.1", "target": "DIRECT"}, map[string]any{"ip": "1.1.1.1", "target": "DIRECT"}}, // 重复
		[]any{map[string]any{"ip": "1.1.1.1"}},                                                                          // 无目标
		[]any{map[string]any{"ip": "1.1.1.1", "target": "a,b"}},                                                         // 目标含逗号
		[]any{map[string]any{"ip": "1.1.1.1", "target": "DIRECT", "name": 1}},                                           // 名称非文本
		[]any{"baditem"},
	}
	for i, b := range bads {
		if _, err := CleanDeviceRoutes(b); err == nil {
			t.Errorf("bads[%d] 应报错", i)
		}
	}
}

func TestResolveMac(t *testing.T) {
	arp := map[string]string{"192.168.1.6": "AA:BB:CC:DD:EE:FF", "192.168.1.7": "11:22:33:44:55:66"}
	n6 := map[string]string{"fd00::6": "aa:bb:cc:dd:ee:ff"}
	got := ResolveMac("aa:bb:cc:dd:ee:ff", arp, n6)
	// IPv4 排前面
	if want := []string{"192.168.1.6", "fd00::6"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ResolveMac = %v, want %v", got, want)
	}
	if got := ResolveMac("ff:ff:ff:ff:ff:ff", arp, n6); len(got) != 0 {
		t.Errorf("未知 MAC 应返回空：%v", got)
	}
}

func TestDeviceRouteRules(t *testing.T) {
	resetSeen()
	d := map[string]any{
		"device_routes": []any{
			map[string]any{"ip": "192.168.1.5", "target": "🏠 直连", "enabled": true},
			map[string]any{"mac": "aa:bb:cc:dd:ee:ff", "target": "REJECT", "enabled": true},
			map[string]any{"ip": "192.168.1.6", "target": "不存在的组", "enabled": true}, // 应跳过
			map[string]any{"ip": "192.168.1.5", "target": "🏠 直连", "enabled": true},  // 重复地址只取第一条
			map[string]any{"ip": "192.168.1.7", "target": "🏠 直连", "enabled": false}, // 禁用跳过
		},
	}
	tables := [2]map[string]string{{"192.168.1.8": "aa:bb:cc:dd:ee:ff"}, {}}
	got := DeviceRouteRules(d, []string{"🏠 直连", "REJECT"}, tables)
	want := []string{
		"SRC-IP-CIDR,192.168.1.5/32,🏠 直连",
		"SRC-IP-CIDR,192.168.1.8/32,REJECT",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DeviceRouteRules = %v, want %v", got, want)
	}
}

func TestDeviceRouteRulesMacMissing(t *testing.T) {
	resetSeen()
	// MAC 解析不到 IP → 跳过（记日志），不生成规则
	d := map[string]any{
		"device_routes": []any{
			map[string]any{"mac": "aa:bb:cc:dd:ee:ff", "target": "REJECT", "enabled": true},
		},
	}
	got := DeviceRouteRules(d, []string{"REJECT"}, [2]map[string]string{{}, {}})
	if len(got) != 0 {
		t.Errorf("应无规则，实际 %v", got)
	}
}

func TestNormNetIPv6(t *testing.T) {
	resetSeen()
	d := map[string]any{
		"device_routes": []any{
			map[string]any{"ip": "fd00::1", "target": "DIRECT", "enabled": true},
			map[string]any{"ip": "10.0.0.0/8", "target": "DIRECT", "enabled": true},
		},
	}
	got := DeviceRouteRules(d, []string{"DIRECT"})
	if len(got) != 2 || !strings.HasSuffix(got[0], "/128,DIRECT") || !strings.HasSuffix(got[1], "/8,DIRECT") {
		t.Errorf("网段后缀不对：%v", got)
	}
}
