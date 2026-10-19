// Package devroute 对应 Python shunt/devroute.py：按设备分流。
// 把指定设备（IP / 网段 / MAC）的全部流量交给某个策略组、直连或拦截。
// data.json 的 device_routes：[{name, ip, mac, target, enabled}]，ip 与 mac 二选一。
// 生成配置时转换成排在规则前部的 SRC-IP-CIDR 规则；
// MAC 在生成时按 ARP 表（开启 IPv6 时再加 IPv6 邻居表）解析成当前 IP。
// 设备换了 IP 时，定时任务循环发现解析结果与上次写入配置时不同就重载核心。
package devroute

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"shunt/internal/base"
	"shunt/internal/data"
	"shunt/internal/groups"
	"shunt/internal/stats"
)

// STUB:stats.ArpTable —— 接线到 stats.ArpTable；测试可替换 arpTableFn
// （stats → core 已改为 ConnsSnapshotHook 注入，devroute → stats 直接导入不再循环）
var arpTableFn = func() map[string]string { return stats.ArpTable() }

func arpTable() map[string]string { return arpTableFn() }

// RoutesMax 按设备分流条数上限
const RoutesMax = 500

var macRx = regexp.MustCompile(`([0-9a-f]{2}:){5}[0-9a-f]{2}`)

var appliedFile = filepath.Join(base.PanelDir, "devroute_applied.json")

// SEEN：mac -> 上次解析到的 IP 列表：设备暂时不在 ARP 表里（休眠）时沿用，不让规则时有时无、核心反复重载
var seenState = struct {
	sync.Mutex
	m map[string][]string
}{m: map[string][]string{}}

// STATE：last 最近一次生成配置时的 MAC 解析结果；applied 写入正式配置时的
var devState = struct {
	sync.Mutex
	last    map[string][]string
	applied map[string][]string
	loaded  bool
}{}

// _LOGGED：已记过日志的跳过原因（生成配置很频繁，同一原因只记一次）
var loggedState = struct {
	sync.Mutex
	m map[string]bool
}{m: map[string]bool{}}

// RouteEntry 校验后的分流条目
type RouteEntry struct {
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Mac     string `json:"mac"`
	Target  string `json:"target"`
	Enabled bool   `json:"enabled"`
}

// NormMac 规范化 MAC（小写、冒号分隔）；无效返回空串
func NormMac(v any) string {
	s := strings.ToLower(strings.TrimSpace(strOf(v)))
	s = strings.ReplaceAll(s, "-", ":")
	if macRx.MatchString(s) {
		return s
	}
	return ""
}

// NormIP IP / 网段 → 规范写法（单个地址不带前缀）；无效返回空串
func NormIP(v any) string {
	s := strings.TrimSpace(strOf(v))
	if s == "" {
		return ""
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return ""
	}
	return n.String()
}

// CleanDeviceRoutes /api/settings、/api/restore 的形状校验：坏条目抛错（提示可直接给用户看）
func CleanDeviceRoutes(v any) ([]RouteEntry, error) {
	lst, ok := v.([]any)
	if !ok {
		return nil, errors.New("按设备分流应为列表")
	}
	if len(lst) > RoutesMax {
		return nil, fmt.Errorf("按设备分流最多 %d 条", RoutesMax)
	}
	out := []RouteEntry{}
	seen := map[string]bool{}
	for i, e := range lst {
		em, ok := e.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("按设备分流第 %d 项格式不正确", i+1)
		}
		ipRaw, macRaw := strings.TrimSpace(strOf(em["ip"])), strings.TrimSpace(strOf(em["mac"]))
		if (ipRaw != "") == (macRaw != "") {
			return nil, fmt.Errorf("按设备分流第 %d 项：IP 和 MAC 填且只填一个", i+1)
		}
		ip, mac := "", ""
		if ipRaw != "" {
			ip = NormIP(ipRaw)
		} else {
			mac = NormMac(macRaw)
		}
		if ipRaw != "" && ip == "" {
			return nil, fmt.Errorf("按设备分流第 %d 项的 IP / 网段无效：%s", i+1, firstN(ipRaw, 60))
		}
		if macRaw != "" && mac == "" {
			return nil, fmt.Errorf("按设备分流第 %d 项的 MAC 无效：%s", i+1, firstN(macRaw, 60))
		}
		key := ip
		if key == "" {
			key = mac
		}
		if seen[key] {
			return nil, fmt.Errorf("按设备分流重复：%s", key)
		}
		seen[key] = true
		var name string
		if nv, present := em["name"]; present && nv != nil {
			ns, ok := nv.(string)
			if !ok {
				return nil, fmt.Errorf("按设备分流「%s」的名称应为文本", key)
			}
			name = ns
		}
		target := strings.TrimSpace(strOf(em["target"]))
		if target == "" {
			return nil, fmt.Errorf("按设备分流「%s」没有选择目标", key)
		}
		if groups.NameBad.MatchString(target) || len([]rune(target)) > 80 {
			return nil, fmt.Errorf("按设备分流「%s」的目标无效：%s", key, firstN(target, 60))
		}
		nm := firstN(strings.TrimSpace(name), 40)
		if nm == "" {
			nm = key
		}
		enabled := true
		if ev, ok := em["enabled"]; ok {
			enabled, _ = ev.(bool)
		}
		out = append(out, RouteEntry{Name: nm, IP: ip, Mac: mac, Target: target, Enabled: enabled})
	}
	return out, nil
}

// Neigh6 IPv6 邻居表 {ip: mac}（ip -6 neigh）；没有 ip 命令或出错时返回空
func Neigh6() map[string]string {
	out := map[string]string{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "ip", "-6", "neigh", "show").Output()
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		p := strings.Fields(line)
		llIdx, failed := -1, false
		for i, tok := range p {
			if tok == "FAILED" {
				failed = true
			}
			if tok == "lladdr" {
				llIdx = i
			}
		}
		if failed || llIdx < 0 || llIdx+1 >= len(p) {
			continue
		}
		ip, mac := p[0], strings.ToLower(p[llIdx+1])
		if !strings.HasPrefix(strings.ToLower(ip), "fe80:") { // 链路本地地址不会出现在转发流量的源地址里
			out[ip] = mac
		}
	}
	return out
}

func tablesOf(d map[string]any) (map[string]string, map[string]string) {
	arp := map[string]string{}
	func() {
		defer func() { _ = recover() }()
		arp = arpTable()
	}()
	n6 := map[string]string{}
	if data.Bool(d, "ipv6") {
		func() {
			defer func() { _ = recover() }()
			n6 = Neigh6()
		}()
	}
	return arp, n6
}

// ResolveMac MAC 的当前 IP：ARP 表 + IPv6 邻居表
func ResolveMac(mac string, arp, n6 map[string]string) []string {
	ips := []string{}
	for ip, m := range arp {
		if strings.ToLower(strOf(m)) == mac {
			ips = append(ips, ip)
		}
	}
	for ip, m := range n6 {
		if strings.ToLower(strOf(m)) == mac && !containsStr(ips, ip) {
			ips = append(ips, ip)
		}
	}
	sort.Slice(ips, func(i, j int) bool {
		vi, vj := strings.Contains(ips[i], ":"), strings.Contains(ips[j], ":")
		if vi != vj {
			return !vi
		}
		return ips[i] < ips[j]
	})
	return ips
}

// MacMapping 启用的 MAC 条目 → {mac: [IP]}（找不到时沿用上次见到的、仍未被别的设备占用的 IP）
func MacMapping(d map[string]any, tables ...[2]map[string]string) map[string][]string {
	entries := entriesOf(d)
	var macs []string
	for _, e := range entries {
		if e.mac != "" {
			macs = append(macs, e.mac)
		}
	}
	if len(macs) == 0 {
		return map[string][]string{}
	}
	var arp, n6 map[string]string
	if len(tables) > 0 {
		arp, n6 = tables[0][0], tables[0][1]
	} else {
		arp, n6 = tablesOf(d)
	}
	owner := map[string]string{}
	for ip, m := range arp {
		owner[ip] = strings.ToLower(strOf(m))
	}
	for ip, m := range n6 {
		owner[ip] = strings.ToLower(strOf(m))
	}
	out := map[string][]string{}
	for _, mac := range macs {
		ips := ResolveMac(mac, arp, n6)
		seenState.Lock()
		if len(ips) > 0 {
			seenState.m[mac] = ips
		} else {
			kept := []string{}
			for _, ip := range seenState.m[mac] {
				if o, ok := owner[ip]; !ok || o == mac {
					kept = append(kept, ip)
				}
			}
			ips = kept
		}
		seenState.Unlock()
		out[mac] = ips
	}
	return out
}

type devEntry struct {
	name, ip, mac, target string
}

// entriesOf data.json 里启用的、形状正确的条目（坏条目忽略，不让生成配置失败）
func entriesOf(d map[string]any) []devEntry {
	var out []devEntry
	for _, e := range data.List(d, "device_routes") {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if ev, ok := em["enabled"]; ok {
			if b, isBool := ev.(bool); isBool && !b {
				continue
			}
		}
		ip, mac := "", ""
		if strings.TrimSpace(strOf(em["ip"])) != "" {
			ip = NormIP(em["ip"])
		} else {
			mac = NormMac(em["mac"])
		}
		target := strings.TrimSpace(strOf(em["target"]))
		if (ip != "" || mac != "") && target != "" && !groups.NameBad.MatchString(target) {
			name := strOf(em["name"])
			if name == "" {
				name = ip
			}
			if name == "" {
				name = mac
			}
			out = append(out, devEntry{name: name, ip: ip, mac: mac, target: target})
		}
	}
	return out
}

func logOnce(key, msg string) {
	loggedState.Lock()
	_, done := loggedState.m[key]
	if !done {
		loggedState.m[key] = true
	}
	loggedState.Unlock()
	if !done {
		fmt.Println("[device-route]", msg)
	}
}

// normNet IP/网段 → 比较与输出用的规范网段串（裸 IP 补 /32 或 /128）
func normNet(x string) string {
	if ip := net.ParseIP(x); ip != nil {
		if ip.To4() != nil {
			return ip.String() + "/32"
		}
		return ip.String() + "/128"
	}
	_, n, err := net.ParseCIDR(x)
	if err != nil {
		return ""
	}
	return n.String()
}

// DeviceRouteRules 按设备分流 → mihomo 规则列表（SRC-IP-CIDR,<ip>/32|/128|网段,<目标>）。
// 目标策略组不存在、MAC 解析不到 IP 的条目跳过（记日志），不会生成无法加载的配置。同一地址只取第一条。
func DeviceRouteRules(d map[string]any, policies []string, tables ...[2]map[string]string) []string {
	entries := entriesOf(d)
	polSet := map[string]bool{}
	for _, p := range policies {
		polSet[p] = true
	}
	mapping := map[string][]string{}
	for _, e := range entries {
		if e.mac != "" {
			mapping = MacMapping(d, tables...)
			break
		}
	}
	devState.Lock()
	devState.last = sigOf(mapping)
	devState.Unlock()
	rules := []string{}
	used := map[string]bool{}
	for _, e := range entries {
		if !polSet[e.target] {
			logOnce("tgt\x00"+e.name+"\x00"+e.target, fmt.Sprintf("「%s」的目标「%s」不存在，已跳过", e.name, e.target))
			continue
		}
		var nets []string
		if e.ip != "" {
			nets = []string{e.ip}
		} else {
			nets = mapping[e.mac]
			if len(nets) == 0 {
				logOnce("mac\x00"+e.mac, fmt.Sprintf("「%s」（%s）当前找不到 IP，暂不生效", e.name, e.mac))
				continue
			}
		}
		for _, x := range nets {
			n := normNet(x)
			if n == "" || used[n] {
				continue
			}
			used[n] = true
			rules = append(rules, "SRC-IP-CIDR,"+n+","+e.target)
		}
	}
	return rules
}

func sigOf(mapping map[string][]string) map[string][]string {
	sig := make(map[string][]string, len(mapping))
	for m, v := range mapping {
		cp := make([]string, len(v))
		copy(cp, v)
		sig[m] = cp
	}
	return sig
}

// MarkApplied 写入正式配置后调用：记下这份配置里 MAC → IP 的解析结果
// （落盘，开机时 --gen 进程写的面板进程也能读到）
func MarkApplied() {
	devState.Lock()
	sig := devState.last
	devState.applied = sig
	devState.loaded = true
	devState.Unlock()
	if sig != nil || fileExists(appliedFile) {
		_ = os.MkdirAll(filepath.Dir(appliedFile), 0o755)
		toWrite := map[string][]string{}
		if sig != nil {
			toWrite = sig
		}
		raw, _ := json.Marshal(toWrite)
		tmp := appliedFile + ".tmp"
		if err := os.WriteFile(tmp, raw, 0o600); err == nil {
			_ = os.Rename(tmp, appliedFile)
		}
	}
}

// AppliedSig 上次写入配置时的 MAC 解析结果
func AppliedSig() map[string][]string {
	devState.Lock()
	defer devState.Unlock()
	if !devState.loaded {
		devState.loaded = true
		if raw, err := os.ReadFile(appliedFile); err == nil {
			var v map[string][]string
			if json.Unmarshal(raw, &v) == nil {
				devState.applied = v
			}
		}
	}
	return devState.applied
}

// MacChanged MAC 条目解析出的 IP 与当前配置里的不同 → 返回 (新的解析结果, true)，
// 没变返回 (nil, false)（定时任务循环据此重载核心）
func MacChanged(d map[string]any) (map[string][]string, bool) {
	hasMac := false
	for _, e := range entriesOf(d) {
		if e.mac != "" {
			hasMac = true
			break
		}
	}
	if !hasMac {
		return nil, false
	}
	cur := sigOf(MacMapping(d))
	applied := AppliedSig()
	if applied == nil {
		applied = map[string][]string{}
	}
	if strSliceMapEqual(cur, applied) {
		return nil, false
	}
	return cur, true
}

// ---------- 小助手 ----------

func strOf(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func firstN(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func strSliceMapEqual(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok || len(va) != len(vb) {
			return false
		}
		for i := range va {
			if va[i] != vb[i] {
				return false
			}
		}
	}
	return true
}
