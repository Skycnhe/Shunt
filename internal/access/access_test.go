package access

import "testing"

func TestIpIsLan(t *testing.T) {
	cases := map[string]bool{
		"192.168.1.1":     true,
		"10.0.0.5":        true,
		"172.16.9.9":      true,
		"127.0.0.1":       true,
		"::1":             true,
		"169.254.10.20":   true,
		"100.64.0.1":      true, // CGNAT / Tailscale
		"100.127.255.255": true,
		"8.8.8.8":         false,
		"1.1.1.1":         false,
		"114.114.114.114": false,
		"not-an-ip":       false,
		"":                false,
		"fe80::1%eth0":    true, // zone id 剥离
		"::ffff:10.1.2.3": true, // ipv4-mapped
	}
	for ip, want := range cases {
		if got := IpIsLan(ip); got != want {
			t.Errorf("IpIsLan(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestHostName(t *testing.T) {
	cases := map[string]string{
		"example.com:8080": "example.com",
		"Example.COM":      "example.com",
		"[::1]:8080":       "::1",
		"[::1]":            "::1",
		"[fe80::1":         "fe80::1",
		"2001:db8::1":      "2001:db8::1", // 多个冒号：按 IPv6 原样返回
		"  Router.LAN. ":   "router.lan.",
		"shunt.lan.":       "shunt.lan.",
	}
	for in, want := range cases {
		if got := HostName(in); got != want {
			t.Errorf("HostName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHostOk(t *testing.T) {
	if !HostOk("192.168.1.1:8080") {
		t.Error("IP host should be allowed")
	}
	if !HostOk("router.lan") {
		t.Error(".lan should be allowed")
	}
	if !HostOk("nas.local.") {
		t.Error("trailing dot should be trimmed")
	}
	if !HostOk("localhost") {
		t.Error("localhost should be allowed")
	}
	if HostOk("") {
		t.Error("empty host should be rejected")
	}
	if HostOk("mydevice") {
		t.Error("bare single-label hostname should be rejected")
	}
	if HostOk("evil.example.com") {
		t.Error("public domain should be rejected")
	}
}
