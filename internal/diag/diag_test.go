package diag

import (
	"strings"
	"testing"
)

func TestScrub(t *testing.T) {
	in := `open '/etc/mihomo/config.yaml': no such file, url "https://user:pass@example.com/x"`
	got := scrub(in)
	if strings.Contains(got, "/etc/mihomo/config.yaml") || strings.Contains(got, "user:pass@") {
		t.Errorf("脱敏失败：%q", got)
	}
	if !strings.Contains(got, "'<路径>'") || !strings.Contains(got, `"https://user:***@example.com/x"`) {
		t.Errorf("脱敏格式不对：%q", got)
	}
}

func TestDnsBypassDevices(t *testing.T) {
	conns := map[string]any{"connections": []any{
		map[string]any{"metadata": map[string]any{
			"sniffHost": "www.google.com", "destinationIP": "142.250.1.1", "sourceIP": "192.168.1.5",
		}},
		// Fake-IP 目标：经过面板，不算绕过
		map[string]any{"metadata": map[string]any{
			"sniffHost": "www.google.com", "destinationIP": "198.18.0.5", "sourceIP": "192.168.1.6",
		}},
		// 私网目标：不算
		map[string]any{"metadata": map[string]any{
			"sniffHost": "a.com", "destinationIP": "192.168.1.1", "sourceIP": "192.168.1.7",
		}},
		// 无嗅探域名：不算
		map[string]any{"metadata": map[string]any{
			"destinationIP": "142.250.1.2", "sourceIP": "192.168.1.8",
		}},
		// fc00::/18 也是 Fake-IP 段
		map[string]any{"metadata": map[string]any{
			"sniffHost": "www.youtube.com", "destinationIP": "fc00::1234", "sourceIP": "192.168.1.9",
		}},
	}}
	got := DnsBypassDevices(conns)
	if len(got) != 1 {
		t.Fatalf("应只检出 1 台设备，实际 %v", got)
	}
	doms, ok := got["192.168.1.5"]
	if !ok || !doms["www.google.com"] {
		t.Errorf("检出结果不对：%v", got)
	}
	// 空 conns → 空结果（不触发快照）
	if got := DnsBypassDevices(map[string]any{}); len(got) != 0 {
		t.Errorf("空 conns 应返回空：%v", got)
	}
}
