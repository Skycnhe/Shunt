// Package access 对应 Python shunt/access.py：访问控制。
// 面板没有密码：只接受局域网来源，Host 必须是 IP / 局域网名（防 DNS 重绑定），
// 改动类请求必须带自定义头（防跨站请求）。
package access

import (
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"shunt/internal/data"
)

// LANExtra 对应 LAN_EXTRA：CGNAT / Tailscale 网段
var LANExtra = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}

// LANSuffix 对应 LAN_SUFFIX
var LANSuffix = []string{".lan", ".local", ".home", ".internal", ".home.arpa", ".localdomain", ".router", ".intranet", ".ts.net"}

var (
	aclMu     sync.Mutex
	aclT      time.Time
	aclPublic bool
	aclHosts  = map[string]bool{}
)

// AclCfg 对应 acl_cfg()：每 5 秒从 data.json + 环境变量刷新一次。
// 返回 (是否允许公网, 允许的 Host 集合副本)。
func AclCfg() (bool, map[string]bool) {
	aclMu.Lock()
	defer aclMu.Unlock()
	if time.Since(aclT) > 5*time.Second {
		d := data.Load()
		env := map[string]bool{}
		for _, h := range strings.Split(os.Getenv("PANEL_ALLOW_HOSTS"), ",") {
			if s := strings.TrimSpace(strings.ToLower(h)); s != "" {
				env[s] = true
			}
		}
		hosts := map[string]bool{}
		for _, h := range data.List(d, "allow_hosts") {
			if s, ok := h.(string); ok {
				if s = strings.TrimSpace(strings.ToLower(s)); s != "" {
					hosts[s] = true
				}
			}
		}
		for h := range env {
			hosts[h] = true
		}
		aclPublic = data.Bool(d, "allow_public") || os.Getenv("PANEL_ALLOW_PUBLIC") == "1"
		aclHosts = hosts
		aclT = time.Now()
	}
	cp := make(map[string]bool, len(aclHosts))
	for h := range aclHosts {
		cp[h] = true
	}
	return aclPublic, cp
}

// IpIsLan 对应 ip_is_lan(ip)：私网 / 回环 / 链路本地 / CGNAT 视为局域网。
func IpIsLan(ip string) bool {
	s := ip
	if i := strings.Index(s, "%"); i >= 0 {
		s = s[:i]
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	if a.Is4In6() {
		a = a.Unmap()
	}
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return true
	}
	for _, n := range LANExtra {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// HostName 对应 host_name(host)：从 Host 头里剥掉端口 / IPv6 方括号。
func HostName(host string) string {
	h := strings.TrimSpace(strings.ToLower(host))
	if strings.HasPrefix(h, "[") {
		if i := strings.Index(h, "]"); i >= 0 {
			return h[1:i]
		}
		return h[1:]
	}
	if strings.Count(h, ":") == 1 {
		return h[:strings.LastIndex(h, ":")]
	}
	return h
}

// HostOk 对应 host_ok(host)：空 Host 拒绝；IP 直接放行；
// 单标签主机名只放行 localhost（防 DNS 重绑定绕过），其余单标签需用户显式加入允许列表。
func HostOk(host string) bool {
	h := strings.TrimRight(HostName(host), ".")
	if h == "" {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	public, hosts := AclCfg()
	if public || h == "localhost" {
		return true
	}
	for _, s := range LANSuffix {
		if strings.HasSuffix(h, s) {
			return true
		}
	}
	return hosts[h]
}
