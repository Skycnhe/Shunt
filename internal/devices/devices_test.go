package devices

import (
	"os"
	"path/filepath"
	"testing"

	"shunt/internal/base"
)

func withLeaseFile(t *testing.T, content string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "leases")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	old := base.LeaseFiles
	base.LeaseFiles = []string{p, "/nonexistent"}
	t.Cleanup(func() { base.LeaseFiles = old })
}

func TestReadLeases(t *testing.T) {
	withLeaseFile(t, "1700000000 aa:bb:cc:dd:ee:ff 192.168.1.10 myhost aa:bb:cc:dd:ee:ff\n"+
		"1700000000 11:22:33:44:55:66 192.168.1.11 * 11:22:33:44:55:66\n"+
		"bad line\n")
	got := ReadLeases()
	if got["192.168.1.10"] != [2]string{"aa:bb:cc:dd:ee:ff", "myhost"} {
		t.Errorf("租约解析不对：%v", got["192.168.1.10"])
	}
	if got["192.168.1.11"] != [2]string{"11:22:33:44:55:66", ""} {
		t.Errorf("主机名 * 应转为空串：%v", got["192.168.1.11"])
	}
}

func TestDeviceMap(t *testing.T) {
	withLeaseFile(t, "1700000000 aa:bb:cc:dd:ee:ff 192.168.1.10 myhost xx\n")
	oldFn := arpTableFn
	arpTableFn = func() map[string]string { return map[string]string{"192.168.1.10": "AA:BB:CC:DD:EE:FF"} }
	t.Cleanup(func() { arpTableFn = oldFn })

	got := DeviceMap([]string{"192.168.1.10", "192.168.1.99", "", "?"})
	d10 := got["192.168.1.10"]
	if d10.Mac != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MAC 应小写：%q", d10.Mac)
	}
	if d10.Name != "myhost" || d10.Src != "DHCP" {
		t.Errorf("DHCP 名/来源不对：%+v", d10)
	}
	// 未知私网 IP：无名、无来源（反向解析入队不阻塞）
	d99 := got["192.168.1.99"]
	if d99.Name != "" || d99.Src != "" {
		t.Errorf("未知设备应无名：%+v", d99)
	}
	if _, ok := got[""]; ok {
		t.Error("空 IP 应跳过")
	}
	if _, ok := got["?"]; ok {
		t.Error("? 应跳过")
	}
}

func TestTunRuntimeErrorFromLog(t *testing.T) {
	oldFn := logTailFn
	logTailFn = func(path string, nbytes int) []string {
		return []string{
			`2024-01-01 level=info msg="started"`,
			`2024-01-01 level=error TUN msg="operation not permitted: create tun"`,
		}
	}
	t.Cleanup(func() { logTailFn = oldFn })
	// 网卡名用一个不可能存在的，避免真的等 4 秒
	if got := TunRuntimeError("no-such-tun-dev-xyz", 0); got != "operation not permitted: create tun" {
		t.Errorf("应从日志提取 msg，实际：%q", got)
	}
}
