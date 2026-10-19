// Package devices 对应 Python shunt/devices.py：设备名称解析。
// 按 IP 查设备名：用户备注 → DHCP 租约 → /etc/hosts → 反向解析（后台队列）；
// TunRuntimeError 等待 TUN 网卡出现，失败时从核心日志里定位原因。
package devices

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"shunt/internal/base"
	"shunt/internal/data"
	"shunt/internal/errlog"
	"shunt/internal/ruletest"
	"shunt/internal/stats"
)

// STUB:stats.ArpTable —— 接线到 stats.ArpTable；测试可替换 arpTableFn
var arpTableFn = func() map[string]string { return stats.ArpTable() }

func arpTable() map[string]string { return arpTableFn() }

// STUB:errlog.LogTail —— 接线到 errlog.LogTail（固定读末尾 16KB）；测试可替换 logTailFn
var logTailFn = func(path string, nbytes int) []string { return errlog.LogTail(path) }

func logTail(path string, nbytes int) []string { return logTailFn(path, nbytes) }

// ReadLeases 读取 dnsmasq/dhcp 租约：{ip: (mac, 主机名)}
func ReadLeases() map[string][2]string {
	out := map[string][2]string{}
	for _, path := range base.LeaseFiles {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			p := strings.Fields(line)
			if len(p) >= 4 && ruletest.IsIP(p[2]) {
				host := ""
				if p[3] != "*" {
					host = p[3]
				}
				out[p[2]] = [2]string{strings.ToLower(p[1]), host}
			}
		}
	}
	return out
}

// ReadHosts 读 /etc/hosts：{ip: 主机名}（同 IP 取第一条）
func ReadHosts() map[string]string {
	out := map[string]string{}
	raw, err := os.ReadFile("/etc/hosts")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		p := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(p) >= 2 && ruletest.IsIP(p[0]) {
			if ip := net.ParseIP(p[0]); ip != nil && !ip.IsLoopback() {
				if _, ok := out[p[0]]; !ok {
					out[p[0]] = p[1]
				}
			}
		}
	}
	return out
}

// ---------- 反向解析后台队列 ----------

type rdnsEntry struct {
	name   string
	expire float64
}

var rdnsState = struct {
	sync.Mutex
	cache  map[string]rdnsEntry
	queue  []string
	queued map[string]bool
	wake   chan struct{}
}{cache: map[string]rdnsEntry{}, queued: map[string]bool{}, wake: make(chan struct{}, 1)}

var rdnsSuffixes = []string{".lan", ".local", ".home", ".localdomain"}

func nowSec() float64 { return float64(time.Now().UnixNano()) / 1e9 }

// RdnsLoop 后台反向解析循环（对应 cli.py 启动的 rdns_loop 线程）
func RdnsLoop() {
	for {
		select {
		case <-rdnsState.wake:
		case <-time.After(30 * time.Second):
		}
		for {
			rdnsState.Lock()
			if len(rdnsState.queue) == 0 {
				rdnsState.Unlock()
				break
			}
			ip := rdnsState.queue[0]
			rdnsState.queue = rdnsState.queue[1:]
			delete(rdnsState.queued, ip)
			rdnsState.Unlock()

			name := ""
			// 不再改全局 socket 超时：那会让同时建立的订阅下载、核心更新等连接也只剩 2 秒
			if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
				name = names[0]
			}
			if name != "" && (name == ip || strings.HasSuffix(name, ".in-addr.arpa")) {
				name = ""
			}
			short := name
			for _, suf := range rdnsSuffixes {
				if strings.HasSuffix(name, suf) {
					short = strings.Split(name, ".")[0]
					break
				}
			}
			rdnsState.Lock()
			rdnsState.cache[ip] = rdnsEntry{name: short, expire: nowSec() + 1800}
			// 顺手清理过期条目：RDNS 只增不减会导致无界增长；device_map 对缺失 key 会重新入队，语义不变
			n := nowSec()
			for k, v := range rdnsState.cache {
				if v.expire <= n {
					delete(rdnsState.cache, k)
				}
			}
			rdnsState.Unlock()
		}
	}
}

var rdnsOnce sync.Once

// StartRdnsLoop 启动后台反向解析（cli 启动时调用一次）
func StartRdnsLoop() {
	rdnsOnce.Do(func() { go RdnsLoop() })
}

// DeviceInfo 单个设备的解析结果
type DeviceInfo struct {
	Name string `json:"name"`
	Mac  string `json:"mac"`
	Src  string `json:"src"`
}

// DeviceMap 解析一批 IP：备注 → DHCP → hosts → 反向解析
func DeviceMap(ips []string) map[string]DeviceInfo {
	d := data.Load()
	custom := map[string]string{}
	for k, v := range data.Map(d, "devices") {
		if s, ok := v.(string); ok {
			custom[strings.ToLower(k)] = s
		}
	}
	arp, leases, hosts := arpTable(), ReadLeases(), ReadHosts()
	out := map[string]DeviceInfo{}
	now := nowSec()
	for _, ip := range ips {
		if ip == "" || ip == "?" {
			continue
		}
		mac := ""
		if a, ok := arp[ip]; ok && a != "" {
			mac = a
		} else if l, ok := leases[ip]; ok {
			mac = l[0]
		}
		mac = strings.ToLower(mac)
		name, src := "", ""
		if c := custom[strings.ToLower(ip)]; c != "" {
			name, src = c, "备注"
		} else if mac != "" {
			if c := custom[mac]; c != "" {
				name, src = c, "备注"
			}
		}
		if name == "" {
			if l, ok := leases[ip]; ok && l[1] != "" {
				name, src = l[1], "DHCP"
			}
		}
		if name == "" {
			if h, ok := hosts[ip]; ok {
				name, src = h, "hosts"
			}
		}
		if name == "" {
			rdnsState.Lock()
			r, ok := rdnsState.cache[ip]
			queued := rdnsState.queued[ip]
			rdnsState.Unlock()
			if ok && r.expire > now {
				name, src = r.name, "反向解析"
			} else if (!ok || r.expire <= now) && ruletest.IsIP(ip) && isPrivateIP(ip) && !queued {
				rdnsState.Lock()
				rdnsState.cache[ip] = rdnsEntry{expire: now + 300}
				rdnsState.queue = append(rdnsState.queue, ip)
				rdnsState.queued[ip] = true
				rdnsState.Unlock()
				select {
				case rdnsState.wake <- struct{}{}:
				default:
				}
			}
		}
		s := ""
		if name != "" {
			s = src
		}
		out[ip] = DeviceInfo{Name: name, Mac: mac, Src: s}
	}
	return out
}

func isPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.IsPrivate()
}

var tunMsgRx = regexp.MustCompile(`msg="(.*)"`)

// TunRuntimeError 等待 TUN 网卡出现（最多 wait 秒）；失败时从核心日志里找出原因
func TunRuntimeError(dev string, wait ...int) string {
	w := 4
	if len(wait) > 0 {
		w = wait[0]
	}
	for i := 0; i < w*2; i++ {
		// 必须是 TUN 网卡，避免与 eth0 等同名网卡误判
		if _, err := os.Stat("/sys/class/net/" + dev + "/tun_flags"); err == nil {
			return ""
		}
		time.Sleep(500 * time.Millisecond)
	}
	lines := logTail(base.MihomoLog, 64*1024)
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		lower := strings.ToLower(line)
		if strings.Contains(line, "TUN") && (strings.Contains(lower, "error") || strings.Contains(lower, "fatal")) {
			if m := tunMsgRx.FindStringSubmatch(line); m != nil {
				line = m[1]
			}
			r := []rune(line)
			if len(r) > 240 {
				r = r[len(r)-240:]
			}
			return string(r)
		}
	}
	return fmt.Sprintf("未检测到网卡 %s", dev)
}
