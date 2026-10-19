// Package sysopt 对应 Python shunt/sysopt.py：Alpine 系统优化、
// shell 执行（sh / rc_run 语义保真：管道改临时文件、超时 124、zap 重试）、
// 核心进程管理、代理测速、站点图标等。
package sysopt

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"shunt/internal/base"
	"shunt/internal/corehttp"
	"shunt/internal/data"
	"shunt/internal/ipinfo"
)

// ---------- 路径（环境变量可覆盖，对应 PANEL_PROC_SYS / PANEL_SYS_ROOT / PANEL_ETC / PANEL_PROC） ----------

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

var (
	// ProcSys 对应 PROC_SYS
	ProcSys = envOr("PANEL_PROC_SYS", "/proc/sys")
	// SysRoot 对应 SYS_ROOT
	SysRoot = envOr("PANEL_SYS_ROOT", "/sys")
	// Etc 对应 ETC
	Etc = envOr("PANEL_ETC", "/etc")
	// Proc 对应 PROC
	Proc = envOr("PANEL_PROC", "/proc")
	// OptSysctl 对应 OPT_SYSCTL
	OptSysctl = filepath.Join(Etc, "sysctl.d", "98-shunt-optimize.conf")
	// OptLocald 对应 OPT_LOCALD
	OptLocald = filepath.Join(Etc, "local.d", "shunt-optimize.start")
	// OptConfd 对应 OPT_CONFD（核心服务改名后为 conf.d/shunt-core）
	OptConfd = filepath.Join(Etc, "conf.d", base.CoreSvc)
	// OptConfdOld 对应 OPT_CONFD_OLD（旧 conf.d/mihomo）
	OptConfdOld = filepath.Join(Etc, "conf.d", "mihomo")
	// OptLock 对应 OPT_LOCK
	OptLock = &sync.Mutex{}
	// SvcOp 对应 SVC_OP：核心服务控制（启动/停止/重启）全局互斥。
	// Python 用 RLock（可重入）；Go 的 Mutex 不可重入，因此 RcRun 与 SvcRestart
	// 共享内部 rcRunLocked，语义不变：同一时刻只有一个服务控制操作在执行。
	SvcOp = &sync.Mutex{}
	// CoreBins 对应 CORE_BINS：核心可执行文件路径；nil 时取默认三路径（测试可覆盖）
	CoreBins []string
	// FavDir 站点图标缓存目录
	FavDir = filepath.Join(base.PanelDir, "favicons")
)

// ---------- 基础读写 ----------

// MemMb 对应 mem_mb()：内存 MB 数，读不到返回 512。
func MemMb() int {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 512
	}
	m := regexp.MustCompile(`MemTotal:\s+(\d+)`).FindSubmatch(b)
	if m == nil {
		return 512
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return 512
	}
	return n / 1024
}

// Rsys 对应 rsys(key)：读 /proc/sys 参数，空白归一化；读不到返回 ""。
func Rsys(key string) string {
	b, err := os.ReadFile(filepath.Join(ProcSys, strings.ReplaceAll(key, ".", "/")))
	if err != nil {
		return ""
	}
	return strings.Join(strings.Fields(string(b)), " ")
}

// Wsys 对应 wsys(key, val)：写 /proc/sys 参数；失败返回错误描述。
func Wsys(key, val string) string {
	err := os.WriteFile(filepath.Join(ProcSys, strings.ReplaceAll(key, ".", "/")), []byte(val), 0o644)
	if err != nil {
		if pe, ok := err.(*os.PathError); ok {
			return fmt.Sprintf("%s: %v", key, pe.Err)
		}
		return fmt.Sprintf("%s: %v", key, err)
	}
	return ""
}

// Rfile 对应 rfile(path, default)：读文件去首尾空白，读不到返回 default。
func Rfile(path string, def ...string) string {
	d := ""
	if len(def) > 0 {
		d = def[0]
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return d
	}
	return strings.TrimSpace(string(b))
}

// Wfile 对应 wfile(path, val)：写文件，成功返回 true。
func Wfile(path, val string) bool {
	return os.WriteFile(path, []byte(val), 0o644) == nil
}

// NetIfaces 对应 net_ifaces()：物理网卡（有 device 链接，排除 lo / 虚拟网卡 / TUN）。
func NetIfaces() []string {
	dir := filepath.Join(SysRoot, "class", "net")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if _, err := os.Stat(filepath.Join(dir, e.Name(), "device")); err == nil {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// CpuGovs 对应 cpu_govs()。
func CpuGovs() []string {
	return GlobPaths(filepath.Join(SysRoot, "devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor"))
}

// GlobPaths 对应 glob_paths(pat)。
func GlobPaths(pat string) []string {
	m, _ := filepath.Glob(pat)
	return m
}

func kernelRelease() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	b := make([]byte, 0, 65)
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

var (
	ctOnce sync.Once
	ctVal  string
)

// InContainer 对应 in_container()：LXC / Docker 等容器返回 "lxc"/"docker"，否则返回 ""。
func InContainer() string {
	ctOnce.Do(func() {
		v := Rfile("/run/systemd/container")
		if v == "" && (fileExists("/dev/.lxc-boot-id") ||
			strings.Contains(Rfile("/proc/self/mountinfo"), " lxcfs ") ||
			regexp.MustCompile(`/lxc`).MatchString(Rfile("/proc/1/cgroup"))) {
			v = "lxc"
		}
		if v == "" && (fileExists("/.dockerenv") || fileExists("/run/.containerenv") ||
			regexp.MustCompile(`/(docker|kubepods)`).MatchString(Rfile("/proc/1/cgroup"))) {
			v = "docker"
		}
		ctVal = v
	})
	return ctVal
}

// PathWritable 对应 path_writable(path)：把当前值原样写回，判断是否有权修改。
func PathWritable(path string) bool {
	cur, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return os.WriteFile(path, cur, 0o644) == nil
}

var (
	syswMu    sync.Mutex
	syswCache = map[string]bool{}
)

// SysWritable 对应 sys_writable(key)：参数不存在时不缓存。
func SysWritable(key string) bool {
	syswMu.Lock()
	defer syswMu.Unlock()
	if v, ok := syswCache[key]; ok {
		return v
	}
	path := filepath.Join(ProcSys, strings.ReplaceAll(key, ".", "/"))
	if !fileExists(path) {
		return false
	}
	v := PathWritable(path)
	syswCache[key] = v
	return v
}

// NofileTarget 对应 nofile_target()：mihomo 文件句柄目标值，不超过本机硬上限。
func NofileTarget() int {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 1048576
	}
	hard := int64(rl.Max)
	if hard < 0 || hard >= 1048576 {
		return 1048576
	}
	return int(hard)
}

// ---------- 系统优化项 ----------

// OptItem 对应 opt_items() 的每一项。
type OptItem struct {
	ID      string
	Name    string
	Rec     bool
	Ok      bool
	Why     string
	Desc    string
	Sysctl  map[string]string
	Skipped []string
	Part    string
}

// OptItems 对应 opt_items()：按内存 / CPU 计算推荐值。
func OptItems() []OptItem {
	mem, ncpu := MemMb(), runtime.NumCPU()
	buf := 16 << 20
	if mem < 1024 {
		buf = 8 << 20
	}
	ct := mem * 256
	if ct < 32768 {
		ct = 32768
	}
	if ct > 262144 {
		ct = 262144
	}
	rel := kernelRelease()
	bbrOk := strings.Contains(Rsys("net.ipv4.tcp_available_congestion_control"), "bbr") ||
		fileExists("/lib/modules/"+rel+"/kernel/net/ipv4/tcp_bbr.ko") ||
		len(GlobPaths("/lib/modules/"+rel+"/kernel/net/ipv4/tcp_bbr.ko*")) > 0
	govs := CpuGovs()
	govOk := false
	if len(govs) > 0 {
		govOk = strings.Contains(Rfile(filepath.Join(filepath.Dir(govs[0]), "scaling_available_governors")), "performance")
	}
	ctName := InContainer()
	if ctName != "" {
		bbrOk = strings.Contains(Rsys("net.ipv4.tcp_available_congestion_control"), "bbr")
	}
	govOk = govOk && PathWritable(govs[0]) // govOk 为 false 时短路，不会越界
	nof := NofileTarget()
	ifaces := NetIfaces()
	ifSet := map[string]bool{}
	for _, i := range ifaces {
		ifSet[i] = true
	}
	var rpsq []string
	for _, q := range GlobPaths(filepath.Join(SysRoot, "class/net/*/queues/rx-*/rps_cpus")) {
		parts := strings.SplitN(q, "/class/net/", 2)
		if len(parts) == 2 {
			if ifSet[strings.SplitN(parts[1], "/", 2)[0]] {
				rpsq = append(rpsq, q)
			}
		}
	}
	rpsOk := ncpu > 1 && len(rpsq) > 0 && PathWritable(rpsq[0])
	host := "宿主机"
	if ctName == "lxc" {
		host += "（PVE / LXC）"
	}
	bbrWhy := ""
	if !bbrOk {
		if ctName != "" {
			bbrWhy = fmt.Sprintf("宿主机内核未加载 tcp_bbr，请在%s上执行 modprobe tcp_bbr", host)
		} else {
			bbrWhy = "内核没有 tcp_bbr 模块"
		}
	}
	rpsWhy := ""
	if ncpu <= 1 {
		rpsWhy = "单核 CPU 无需开启"
	} else if len(rpsq) == 0 {
		rpsWhy = "未找到物理网卡"
	} else {
		rpsWhy = fmt.Sprintf("网卡参数只读，请在%s上设置", host)
	}
	govWhy := ""
	if len(govs) > 0 && ctName != "" {
		govWhy = fmt.Sprintf("CPU 调频由%s控制", host)
	} else {
		govWhy = "CPU 不支持调频或没有 performance 模式"
	}
	s := func(v any) string { return fmt.Sprintf("%v", v) }
	items := []OptItem{
		{ID: "bbr", Name: "BBR 拥塞控制", Rec: true, Ok: bbrOk, Why: bbrWhy,
			Desc:   "TCP 改用 BBR + fq 队列，丢包或长距离线路下的下载速度明显更高",
			Sysctl: map[string]string{"net.core.default_qdisc": "fq", "net.ipv4.tcp_congestion_control": "bbr"}},
		{ID: "buf", Name: "网络缓冲区", Rec: true, Ok: true,
			Desc: fmt.Sprintf("加大 TCP/UDP 收发缓冲到 %dMB（按 %dMB 内存计算），提升大带宽和 Hysteria2 / TUIC 等 QUIC 协议速度", buf>>20, mem),
			Sysctl: map[string]string{
				"net.core.rmem_max": s(buf), "net.core.wmem_max": s(buf),
				"net.core.rmem_default": "262144", "net.core.wmem_default": "262144",
				"net.ipv4.tcp_rmem":     fmt.Sprintf("4096 131072 %d", buf),
				"net.ipv4.tcp_wmem":     fmt.Sprintf("4096 65536 %d", buf),
				"net.ipv4.udp_rmem_min": "16384", "net.ipv4.udp_wmem_min": "16384",
				"net.core.netdev_max_backlog": "16384", "net.core.somaxconn": "8192",
				"net.ipv4.tcp_max_syn_backlog": "8192"}},
		{ID: "tcp", Name: "TCP 连接优化", Rec: true, Ok: true,
			Desc: "开启 TCP Fast Open 和 MTU 探测（避免某些线路卡在握手），空闲后不降速，扩大可用端口，快速回收 TIME_WAIT",
			Sysctl: map[string]string{
				"net.ipv4.tcp_fastopen": "3", "net.ipv4.tcp_mtu_probing": "1",
				"net.ipv4.tcp_slow_start_after_idle": "0", "net.ipv4.tcp_tw_reuse": "1",
				"net.ipv4.tcp_fin_timeout": "15", "net.ipv4.ip_local_port_range": "10000 65535",
				"net.ipv4.tcp_keepalive_time": "600", "net.ipv4.tcp_notsent_lowat": "131072"}},
		{ID: "conntrack", Name: "连接跟踪表", Rec: true,
			Ok:   Rsys("net.netfilter.nf_conntrack_max") != "",
			Why:  "nf_conntrack 未加载",
			Desc: fmt.Sprintf("连接数上限提高到 %d，已建立连接的超时从 5 天缩短到 2 小时，避免设备多时连接表被占满导致断流", ct),
			Sysctl: map[string]string{
				"net.netfilter.nf_conntrack_max":                     s(ct),
				"net.netfilter.nf_conntrack_tcp_timeout_established": "7200",
				"net.netfilter.nf_conntrack_udp_timeout":             "60",
				"net.netfilter.nf_conntrack_udp_timeout_stream":      "180"}},
		{ID: "fd", Name: "文件句柄上限", Rec: true, Ok: nof > 1024, Why: "本机文件句柄硬上限只有 1024，需在宿主机上调高",
			Desc:   fmt.Sprintf("mihomo 可同时打开的连接数从 1024 提高到 %d，设备多或 BT 下载时不再报 too many open files（下次重启核心生效）", nof),
			Sysctl: map[string]string{"fs.file-max": "1048576", "fs.nr_open": "1048576"}},
		{ID: "rps", Name: "多核网络分流 (RPS)", Rec: ncpu > 1, Ok: rpsOk, Why: rpsWhy,
			Desc:   fmt.Sprintf("把网卡收包分摊到全部 %d 个 CPU 核心，单队列网卡（树莓派、多数 ARM 盒子、虚拟机）满速时不再单核 100%%", ncpu),
			Sysctl: map[string]string{"net.core.rps_sock_flow_entries": "32768"}},
		{ID: "gov", Name: "CPU 性能模式", Rec: false, Ok: govOk, Why: govWhy,
			Desc:   "CPU 一直跑在最高频率，延迟更低更稳定；功耗和发热会增加，散热差的设备慎开",
			Sysctl: map[string]string{}},
		{ID: "ntp", Name: "时间同步", Rec: true, Ok: ctName == "", Why: "容器和宿主机共用系统时钟，请在宿主机上校时",
			Desc:   "安装并开机启动 chrony 自动校时。系统时间不准会导致 TLS 握手失败、VMess / Trojan 等节点全部不可用",
			Sysctl: map[string]string{}},
	}
	for i := range items {
		it := &items[i]
		allk := it.Sysctl
		if len(allk) == 0 || !it.Ok {
			continue
		}
		w := map[string]string{}
		var skipped []string
		for k, v := range allk {
			if SysWritable(k) {
				w[k] = v
			} else {
				skipped = append(skipped, k)
			}
		}
		it.Skipped = skipped
		it.Sysctl = w
		if len(w) == 0 && it.ID != "fd" {
			it.Ok = false
			if ctName != "" {
				it.Why = fmt.Sprintf("这些内核参数在容器里只读，由%s决定", host)
			} else {
				it.Why = "内核参数只读"
			}
		} else if len(skipped) > 0 {
			if ctName != "" {
				it.Part = fmt.Sprintf("有 %d/%d 个参数只读（由%s决定），已跳过", len(skipped), len(allk), host)
			} else {
				it.Part = fmt.Sprintf("有 %d/%d 个参数只读（内核不允许修改），已跳过", len(skipped), len(allk))
			}
		}
	}
	return items
}

// NtpRunning 对应 ntp_running()。
func NtpRunning() bool {
	code, _ := Sh("pidof chronyd || pidof ntpd")
	return code == 0
}

// OptStatus 对应 opt_status()。
func OptStatus() map[string]any {
	d := data.Load()
	on := map[string]bool{}
	for _, s := range data.Strs(d, "sysopt") {
		on[s] = true
	}
	var out []map[string]any
	for _, it := range OptItems() {
		hit := 0
		for k, v := range it.Sysctl {
			if c := Rsys(k); c != "" && c == strings.Join(strings.Fields(v), " ") {
				hit++
			}
		}
		live := len(it.Sysctl) > 0 && hit == len(it.Sysctl)
		switch it.ID {
		case "fd":
			live = (live || len(it.Sysctl) == 0) && strings.Contains(Rfile(OptConfd), fmt.Sprintf(`rc_ulimit="-n %d"`, NofileTarget()))
		case "rps":
			rpsLive := it.Ok
			if rpsLive {
				ifaces := map[string]bool{}
				for _, i := range NetIfaces() {
					ifaces[i] = true
				}
				for _, q := range GlobPaths(filepath.Join(SysRoot, "class/net/*/queues/rx-*/rps_cpus")) {
					parts := strings.SplitN(q, "/class/net/", 2)
					if len(parts) != 2 || !ifaces[strings.SplitN(parts[1], "/", 2)[0]] {
						continue
					}
					v := strings.ReplaceAll(Rfile(q, "0"), ",", "")
					if v == "" {
						v = "0"
					}
					n, err := strconv.ParseInt(v, 16, 64)
					if err != nil || n == 0 {
						rpsLive = false
						break
					}
				}
			}
			live = live && rpsLive
		case "gov":
			govLive := it.Ok
			if govLive {
				for _, g := range CpuGovs() {
					if Rfile(g) != "performance" {
						govLive = false
						break
					}
				}
			}
			live = govLive
		case "ntp":
			live = NtpRunning()
		}
		show := map[string]string{}
		switch it.ID {
		case "bbr":
			show = map[string]string{"当前": orDash(Rsys("net.ipv4.tcp_congestion_control")), "队列": orDash(Rsys("net.core.default_qdisc"))}
		case "buf":
			n, _ := strconv.Atoi(Rsys("net.core.rmem_max"))
			show = map[string]string{"当前上限": fmt.Sprintf("%d KB", n>>10)}
		case "conntrack":
			show = map[string]string{"已用 / 上限": fmt.Sprintf("%s / %s", orDash(Rsys("net.netfilter.nf_conntrack_count")), orDash(Rsys("net.netfilter.nf_conntrack_max")))}
		case "gov":
			if it.Ok && len(CpuGovs()) > 0 {
				show = map[string]string{"当前": Rfile(CpuGovs()[0])}
			}
		}
		why := ""
		if !it.Ok {
			why = it.Why
		}
		part := ""
		if it.Ok {
			part = it.Part
		}
		out = append(out, map[string]any{
			"id": it.ID, "name": it.Name, "desc": it.Desc, "rec": it.Rec, "ok": it.Ok,
			"why": why, "enabled": on[it.ID], "active": live, "show": show, "part": part,
		})
	}
	return map[string]any{
		"items": out, "mem": MemMb(), "cpu": runtime.NumCPU(),
		"kernel": kernelRelease(), "container": InContainer(),
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// OptMigrateConfd 对应 opt_migrate_confd()：服务改名后把旧 conf.d/mihomo 里的 rc_ulimit 搬到 conf.d/shunt-core。
func OptMigrateConfd() bool {
	if OptConfd == OptConfdOld {
		return false
	}
	old, cur := Rfile(OptConfdOld), Rfile(OptConfd)
	m := regexp.MustCompile(`(?m)^rc_ulimit="[^"\n]*"`).FindString(old)
	if m == "" || regexp.MustCompile(`(?m)^rc_ulimit=`).MatchString(cur) {
		return false
	}
	sep := ""
	if cur != "" && !strings.HasSuffix(cur, "\n") {
		sep = "\n"
	}
	Wfile(OptConfd, cur+sep+m+"\n")
	return true
}

// OptFixUlimit 对应 opt_fix_ulimit()：旧版写死 rc_ulimit="-n 1048576"，在硬上限更低的 LXC 容器里按实际上限改小。
func OptFixUlimit() {
	txt := Rfile(OptConfd)
	m := regexp.MustCompile(`(?m)^rc_ulimit="-n (\d+)"`).FindStringSubmatch(txt)
	if m == nil {
		return
	}
	if n, _ := strconv.Atoi(m[1]); n > NofileTarget() {
		txt = strings.Replace(txt, m[0], fmt.Sprintf(`rc_ulimit="-n %d"`, NofileTarget()), 1)
		if !strings.HasSuffix(txt, "\n") {
			txt += "\n"
		}
		Wfile(OptConfd, txt)
	}
}

func optLocald(on map[string]bool) string {
	lines := []string{"#!/bin/sh", "# 由 Shunt 面板生成：系统优化（开机执行）"}
	if on["rps"] {
		n := runtime.NumCPU()
		lines = append(lines,
			fmt.Sprintf("MASK=%x", (1<<n)-1),
			"for q in /sys/class/net/*/queues/rx-*; do",
			`  i=${q#/sys/class/net/}; i=${i%%/*}; [ -e "/sys/class/net/$i/device" ] || continue`,
			`  echo $MASK > "$q/rps_cpus" 2>/dev/null; echo 4096 > "$q/rps_flow_cnt" 2>/dev/null`,
			"done")
	}
	if on["gov"] {
		lines = append(lines, `for g in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do echo performance > "$g" 2>/dev/null; done`)
	}
	if on["bbr"] {
		lines = append(lines, "modprobe tcp_bbr 2>/dev/null; modprobe sch_fq 2>/dev/null")
	}
	if on["conntrack"] {
		lines = append(lines, "modprobe nf_conntrack 2>/dev/null")
	}
	lines = append(lines,
		"[ -f "+OptSysctl+" ] && sysctl -q -p "+OptSysctl+" 2>/dev/null",
		"exit 0")
	return strings.Join(lines, "\n") + "\n"
}

// OptApply 对应 opt_apply(ids)：应用选中的优化项（未选中的恢复原值）；返回 (ok, 消息, 每项错误)。
func OptApply(ids []string) (bool, string, []string) {
	OptLock.Lock()
	defer OptLock.Unlock()
	items := map[string]*OptItem{}
	itemList := OptItems()
	for i := range itemList {
		items[itemList[i].ID] = &itemList[i]
	}
	var want []string
	for _, id := range ids {
		if it, ok := items[id]; ok && it.Ok {
			want = append(want, id)
		}
	}
	wantSet := map[string]bool{}
	for _, id := range want {
		wantSet[id] = true
	}
	d := data.Load()
	prev := map[string]bool{}
	for _, s := range data.Strs(d, "sysopt") {
		prev[s] = true
	}
	orig := map[string]string{}
	for k, v := range data.Map(d, "sysopt_orig") {
		if s, ok := v.(string); ok {
			orig[k] = s
		}
	}
	mods := data.Strs(d, "sysopt_mods")
	var errs []string
	if wantSet["bbr"] && InContainer() == "" {
		Sh("modprobe tcp_bbr; modprobe sch_fq")
		mf := filepath.Join(Etc, "modules")
		found := false
		for _, w := range strings.Fields(Rfile(mf)) {
			if w == "tcp_bbr" {
				found = true
				break
			}
		}
		if !found {
			f, err := os.OpenFile(mf, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				errs = append(errs, fmt.Sprintf("写入 /etc/modules 失败：%v", err))
			} else {
				_, err = f.WriteString("tcp_bbr\n")
				f.Close()
				if err != nil {
					errs = append(errs, fmt.Sprintf("写入 /etc/modules 失败：%v", err))
				} else {
					mods = append(mods, "tcp_bbr")
				}
			}
		}
	}
	if wantSet["conntrack"] && InContainer() == "" {
		Sh("modprobe nf_conntrack")
	}
	// sysctl：先记住原值，再写入；取消的项恢复原值
	conf := []string{"# 由 Shunt 面板生成：系统优化（取消请在面板「设置 → 系统优化」中关闭）"}
	for _, it := range itemList {
		for k, v := range it.Sysctl {
			if wantSet[it.ID] {
				if _, ok := orig[k]; !ok {
					if cur := Rsys(k); cur != "" {
						orig[k] = cur
					}
				}
				if e := Wsys(k, v); e != "" {
					errs = append(errs, e)
				}
				conf = append(conf, fmt.Sprintf("%s = %s", k, v))
			} else if prev[it.ID] {
				if ov, ok := orig[k]; ok {
					Wsys(k, ov)
				}
			}
		}
	}
	if len(conf) > 1 {
		os.MkdirAll(filepath.Dir(OptSysctl), 0o755)
		if err := os.WriteFile(OptSysctl, []byte(strings.Join(conf, "\n")+"\n"), 0o644); err != nil {
			errs = append(errs, fmt.Sprintf("写入 %s 失败：%v", OptSysctl, err))
		}
	} else if fileExists(OptSysctl) {
		os.Remove(OptSysctl)
	}
	// mihomo 文件句柄
	func() {
		txt := Rfile(OptConfd)
		var kept []string
		for _, l := range strings.Split(txt, "\n") {
			if !strings.HasPrefix(l, "rc_ulimit=") {
				kept = append(kept, l)
			}
		}
		txt = strings.TrimSpace(strings.Join(kept, "\n"))
		if wantSet["fd"] {
			if txt != "" {
				txt += "\n"
			}
			txt += fmt.Sprintf(`rc_ulimit="-n %d"`, NofileTarget())
		}
		if txt != "" || fileExists(OptConfd) {
			os.MkdirAll(filepath.Dir(OptConfd), 0o755)
			content := ""
			if txt != "" {
				content = txt + "\n"
			}
			if err := os.WriteFile(OptConfd, []byte(content), 0o644); err != nil {
				errs = append(errs, fmt.Sprintf("写入 %s 失败：%v", OptConfd, err))
			}
		}
	}()
	// RPS
	mask := fmt.Sprintf("%x", (1<<runtime.NumCPU())-1)
	for _, ifc := range NetIfaces() {
		for _, q := range GlobPaths(filepath.Join(SysRoot, "class/net", ifc, "queues/rx-*")) {
			key := "rps:" + q
			if wantSet["rps"] {
				if _, ok := orig[key]; !ok {
					orig[key] = Rfile(filepath.Join(q, "rps_cpus"), "0")
				}
				if !(Wfile(filepath.Join(q, "rps_cpus"), mask) && Wfile(filepath.Join(q, "rps_flow_cnt"), "4096")) {
					errs = append(errs, fmt.Sprintf("%s RPS 写入失败", ifc))
				}
			} else if prev["rps"] {
				if ov, ok := orig[key]; ok {
					Wfile(filepath.Join(q, "rps_cpus"), ov)
					Wfile(filepath.Join(q, "rps_flow_cnt"), "0")
				}
			}
		}
	}
	// CPU 调频
	for _, g := range CpuGovs() {
		key := "gov:" + g
		if wantSet["gov"] {
			if _, ok := orig[key]; !ok {
				orig[key] = Rfile(g)
			}
			if !Wfile(g, "performance") {
				errs = append(errs, "CPU 调频写入失败")
			}
		} else if prev["gov"] {
			if ov, ok := orig[key]; ok {
				Wfile(g, ov)
			}
		}
	}
	// 开机脚本
	nonNtp := false
	for id := range wantSet {
		if id != "ntp" {
			nonNtp = true
			break
		}
	}
	if nonNtp {
		os.MkdirAll(filepath.Dir(OptLocald), 0o755)
		if err := os.WriteFile(OptLocald, []byte(optLocald(wantSet)), 0o755); err != nil {
			errs = append(errs, fmt.Sprintf("写入开机脚本失败：%v", err))
		} else {
			Sh("rc-update add local default")
		}
	} else if fileExists(OptLocald) {
		os.Remove(OptLocald)
	}
	// 时间同步
	if wantSet["ntp"] && !prev["ntp"] && !NtpRunning() {
		code, out := Sh("apk add --no-cache chrony && rc-update add chronyd default && rc-service chronyd start", 120)
		if code != 0 {
			errs = append(errs, "安装 chrony 失败："+tailRunes(out, 150))
		}
	} else if prev["ntp"] && !wantSet["ntp"] {
		Sh("rc-service chronyd stop; rc-update del chronyd default")
	}
	if len(want) == 0 { // 全部关闭：清掉记录，下次重新读取原值
		mf := filepath.Join(Etc, "modules")
		if len(mods) > 0 {
			modSet := map[string]bool{}
			for _, m := range mods {
				modSet[m] = true
			}
			var kept []string
			for _, l := range strings.Split(Rfile(mf), "\n") {
				if !modSet[strings.TrimSpace(l)] {
					kept = append(kept, l)
				}
			}
			content := strings.Join(kept, "\n")
			if len(kept) > 0 {
				content += "\n"
			}
			Wfile(mf, content)
		}
		orig, mods = map[string]string{}, []string{}
	}
	origAny := make(map[string]any, len(orig))
	for k, v := range orig {
		origAny[k] = v
	}
	data.Update(func(x map[string]any) {
		x["sysopt"] = want
		x["sysopt_orig"] = origAny
		x["sysopt_mods"] = mods
	})
	fdChanged := wantSet["fd"] != prev["fd"]
	msg := ""
	if len(want) > 0 {
		msg = fmt.Sprintf("已应用 %d 项优化", len(want))
	} else {
		msg = "已全部恢复为系统默认值"
	}
	if fdChanged {
		msg += "；文件句柄上限在下次重启核心后生效"
	}
	if len(errs) > 0 {
		msg += "；部分失败：" + strings.Join(errs[:min(4, len(errs))], "；")
	}
	return len(errs) == 0, msg, errs
}

func tailRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[len(r)-n:]
	}
	return string(r)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SpeedTest 对应 speed_test(proxy)：经代理 / 直连下载 Cloudflare 测速文件，返回 Mbps。
func SpeedTest(proxy bool) map[string]any {
	const durl = "https://speed.cloudflare.com/__down?bytes=50000000"
	t0 := time.Now()
	n := 0
	var ttfb time.Duration
	client := ProxyClient(proxy)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", durl, nil)
	if err == nil {
		req.Header.Set("User-Agent", base.Ua)
		var resp *http.Response
		resp, err = client.Do(req)
		if err == nil {
			ttfb = time.Since(t0)
			t1 := time.Now()
			buf := make([]byte, 1<<16)
			func() {
				defer resp.Body.Close()
				for time.Since(t1) < 10*time.Second {
					m, rerr := resp.Body.Read(buf)
					n += m
					if rerr != nil {
						break
					}
				}
			}()
			dt := time.Since(t1).Seconds()
			if dt < 0.001 {
				dt = 0.001
			}
			return map[string]any{
				"ok": true, "mbps": round1(float64(n) * 8 / dt / 1e6),
				"mb": round1(float64(n) / 1e6), "ttfb": int(ttfb.Milliseconds()),
			}
		}
	}
	return map[string]any{"ok": false, "error": firstLine(errStr(err), 120), "mb": round1(float64(n) / 1e6)}
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func firstLine(s string, n int) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		s = s[:i]
	}
	return tailRunes(s, n)
}

var (
	nftMu sync.Mutex
	nftOk = -1 // -1 未知，0 不支持，1 支持
	nftT  time.Time
)

// NftOk 对应 nft_ok()：内核是否支持 nftables（sing-box 的 TUN auto_redirect 依赖它）。
func NftOk() bool {
	nftMu.Lock()
	defer nftMu.Unlock()
	if nftOk == -1 || (nftOk == 0 && time.Since(nftT) > 60*time.Second) {
		if err := exec.Command("nft", "list", "tables").Run(); err == nil {
			nftOk = 1
		} else {
			nftOk = 0
		}
		nftT = time.Now()
	}
	return nftOk == 1
}

// Sh 对应 sh(cmd, timeout)：shell=True 是有意的，大量调用方依赖 shell 特性（管道、重定向、&&）。
// 约定：拼进 cmd 的不可信输入调用方必须先用 shellquote 包裹。
// 返回 (退出码, stdout+stderr 去首尾空白)；超时或异常返回 (1, 错误描述)。
func Sh(cmd string, timeoutSec ...int) (int, string) {
	timeout := 60
	if len(timeoutSec) > 0 {
		timeout = timeoutSec[0]
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "sh", "-c", cmd)
	var ob, eb bytes.Buffer
	c.Stdout, c.Stderr = &ob, &eb
	err := c.Run()
	out := strings.TrimSpace(ob.String() + eb.String())
	if err == nil {
		return 0, out
	}
	if ctx.Err() == context.DeadlineExceeded {
		return 1, fmt.Sprintf("Command '%s' timed out after %d seconds", cmd, timeout)
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), out
	}
	return 1, err.Error()
}

var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*m")
var rcBusyRe = regexp.MustCompile(`(?i)already (?:starting|stopping)|is (?:starting|stopping)|has started, but is inactive`)

// rcOnce 对应 _rc_once(cmd, timeout)：输出写临时文件而不是管道（核心/start_post 拉起的子进程会继承管道，
// 用管道时调用方要一直等到这些子进程退出）；单独进程组，超时时连同子进程一起杀掉；超时返回 124。
func rcOnce(cmd string, timeout int) (int, string) {
	f, err := os.CreateTemp("", "shunt-rc-*")
	if err != nil {
		return 1, err.Error()
	}
	name := f.Name()
	defer os.Remove(name)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "sh", "-c", cmd)
	c.Stdin = nil // nil → /dev/null（对应 stdin=DEVNULL）
	c.Stdout, c.Stderr = f, f
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // start_new_session=True
	timedOut := false
	code := 0
	if err := c.Start(); err != nil {
		f.Close()
		return 1, err.Error()
	}
	pid := c.Process.Pid
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case werr := <-done:
		if werr != nil {
			if ee, ok := werr.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				code = 1
			}
		}
	case <-ctx.Done():
		_ = syscall.Kill(-pid, syscall.SIGKILL) // killpg：连同 rc-service/openrc-run 子进程一起杀掉
		<-done
		code, timedOut = 124, true
	}
	f.Close()
	raw, _ := os.ReadFile(name)
	if len(raw) > 64<<10 {
		raw = raw[:64<<10]
	}
	out := strings.TrimSpace(ansiRe.ReplaceAllString(string(raw), ""))
	if timedOut {
		out = strings.TrimSpace(out + "\n（命令超时）")
	}
	return code, out
}

// RcRun 对应 rc_run(act, timeout)：rc-service <核心> start|stop|restart。
// OpenRC 卡在 starting/stopping 时先 zap 再重试一次；超时（124）时先 zap，避免下次报 already stopping。
func RcRun(act string, timeoutSec ...int) (int, string) {
	timeout := 90
	if len(timeoutSec) > 0 {
		timeout = timeoutSec[0]
	}
	SvcOp.Lock()
	defer SvcOp.Unlock()
	return rcRunLocked(act, timeout)
}

func rcRunLocked(act string, timeout int) (int, string) {
	code, out := rcOnce(base.Svc+" "+act, timeout)
	if code != 0 && code != 124 && rcBusyRe.MatchString(out) {
		// zap 只清 OpenRC 的状态，不碰进程：先把核心进程结束掉，否则旧核心变成没人管的孤儿
		KillCoreProcs(15)
		rcOnce(base.Svc+" zap", 15)
		code, out = rcOnce(base.Svc+" "+act, timeout)
		out = "（服务状态卡住，已自动 zap 后重试）\n" + out
	} else if code == 124 {
		if act == "stop" {
			KillCoreProcs(15)
		}
		rcOnce(base.Svc+" zap", 15)
	}
	return code, out
}

// SvcRestart 对应 svc_restart(timeout, why, cancel)：重启核心服务。
// 重启及启动后的加载期内看门狗暂停判定；cancel 在拿到服务锁后调用，返回真则放弃重启。
func SvcRestart(timeoutSec int, why string, cancel func() bool) (int, string) {
	SvcOp.Lock()
	defer SvcOp.Unlock()
	if cancel != nil && cancel() {
		return 1, "已取消：核心已被手动停止"
	}
	base.WdHold(float64(timeoutSec)+60, why, false)
	defer func() {
		base.WdHold(60, why, true) // 命令返回后只再给 60 秒加载时间
		func() {
			defer func() { _ = recover() }()
			ipReset() // STUB：概览 IP 信息，重启后重新查
		}()
	}()
	return rcRunLocked("restart", timeoutSec)
}

// ---------- 核心进程 ----------

// SbBinHook 注入点：对应 sb_common.SB_BIN（sing-box 二进制路径）。
// singbox 已依赖 sysopt（Sh 等），sysopt 不能再 import singbox（循环），
// 因此由 singbox 在 init 中注入（sysopt.SbBinHook = func() string { return SBBin }）。
// 默认实现与 Python 一致：环境变量 SB_BIN，缺省 /usr/local/bin/sing-box。
var SbBinHook = func() string {
	if v := os.Getenv("SB_BIN"); v != "" {
		return v
	}
	return "/usr/local/bin/sing-box"
}

// STUB:sb_common.SB_BIN —— 经 SbBinHook 由 singbox 包注入
func sbBin() string { return SbBinHook() }

// STUB:ipinfo.Reset —— 接线到 ipinfo.Reset；核心重启/切换后作废 IP 缓存
func ipReset() { ipinfo.Reset() }

// STUB:ipinfo._phys_iface —— 接线到 ipinfo.PhysIface；物理网卡检测（DirectRtt 绑定绕过 TUN）
func physIface() string { return ipinfo.PhysIface() }

var checkArgs = map[string]bool{
	"-t": true, "check": true, "version": true, "-v": true,
	"format": true, "rule-set": true, "generate": true, "merge": true,
}

// CoreProcs 对应 core_procs()：所有正在运行的核心进程 pid（按可执行文件识别，不依赖 pid 文件）。
func CoreProcs() []int {
	bins := CoreBins
	if bins == nil {
		bins = []string{base.MihomoBin, base.SmartBin, sbBin()}
	}
	want := map[string]bool{}
	for _, b := range bins {
		if b == "" {
			continue
		}
		rp, err := filepath.EvalSymlinks(b)
		if err != nil {
			rp = b
		}
		want[rp] = true
	}
	var out []int
	names, err := os.ReadDir(Proc)
	if err != nil {
		return out
	}
	me := os.Getpid()
	for _, n := range names {
		name := n.Name()
		pid, err := strconv.Atoi(name)
		if err != nil || pid == me {
			continue
		}
		exe, err := os.Readlink(filepath.Join(Proc, name, "exe"))
		if err != nil {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join(Proc, name, "cmdline"))
		if err != nil {
			continue
		}
		if strings.HasSuffix(exe, " (deleted)") { // 内核更新替换了二进制，旧进程还在跑
			exe = exe[:len(exe)-len(" (deleted)")]
		}
		erp, err := filepath.EvalSymlinks(exe)
		if err != nil {
			erp = exe
		}
		if !want[erp] && !want[exe] {
			continue
		}
		args := bytes.Split(cmdline, []byte{0})
		skip := false
		for _, a := range args[1:] {
			if checkArgs[string(a)] {
				skip = true // selftest / 校验 / 查版本，不是常驻核心
				break
			}
		}
		if skip {
			continue
		}
		out = append(out, pid)
	}
	return out
}

// KillCoreProcs 对应 kill_core_procs(grace)：先 TERM（sing-box 正常退出时才把 Fake-IP 映射写进 cache.db），
// grace 秒后还在就 KILL。返回结束的个数。
func KillCoreProcs(graceSec int) int {
	pids := CoreProcs()
	for _, p := range pids {
		_ = syscall.Kill(p, syscall.SIGTERM)
	}
	end := time.Now().Add(time.Duration(graceSec) * time.Second)
	for time.Now().Before(end) && anyAlive(pids) {
		time.Sleep(200 * time.Millisecond)
	}
	for _, p := range pids {
		if alive(p) {
			_ = syscall.Kill(p, syscall.SIGKILL)
		}
	}
	return len(pids)
}

func anyAlive(pids []int) bool {
	for _, p := range pids {
		if alive(p) {
			return true
		}
	}
	return false
}

func alive(pid int) bool {
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	// 已退出但还没被回收的僵尸进程不算
	b, err := os.ReadFile(filepath.Join(Proc, strconv.Itoa(pid), "stat"))
	if err != nil {
		return true
	}
	s := string(b)
	i := strings.LastIndex(s, ")")
	if i < 0 {
		return true
	}
	fields := strings.Fields(s[i+1:])
	if len(fields) == 0 {
		return true
	}
	return fields[0] != "Z"
}

// ProxyClient 对应 proxy_opener(proxy)：经 mixed 端口或直连的 http.Client。
// 重定向沿用 SafeRedirectHandler 语义：目标为非公网地址时拦截；
// 走代理时跳过本地 DNS 校验（由代理自己解析），字面内网 IP 仍拦截。
// 注：foundation base 包尚未提供 SafeRedirectHandler，这里用 base.UrlHostForbidden
// 实现其核心判定（SSRF 防护），集成时可替换为 base 的实现。
func ProxyClient(proxy bool) *http.Client {
	tr := &http.Transport{Proxy: nil}
	if proxy {
		px, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", base.Mixed))
		tr.Proxy = http.ProxyURL(px)
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if base.UrlHostForbidden(req.URL.String(), proxy) {
				return fmt.Errorf("redirect to non-public address blocked: %s", req.URL.Host)
			}
			return nil
		},
	}
}

// ---------- 测速 ----------

// rttTLSConfig 复用：对应 _RTT_CTX（SSL context 创建含 CA 加载约几十 ms；tls.Config 只读共享是线程安全的）
var (
	tlsOnce    sync.Once
	tlsRootCAs *x509.CertPool
)

func rttTLSConfig(serverName string) *tls.Config {
	tlsOnce.Do(func() {
		if pool, err := x509.SystemCertPool(); err == nil {
			tlsRootCAs = pool
		}
	})
	return &tls.Config{ServerName: serverName, RootCAs: tlsRootCAs}
}

// SiteRtt 对应 site_rtt(url, timeout)：经 mixed 端口建连（DNS/TCP/TLS 握手不计时），
// 在同一连接上再请求一次，只计这一次的往返。失败返回错误。
func SiteRtt(rawurl string, timeoutSec int) (int, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return 0, err
	}
	https := u.Scheme == "https"
	port := u.Port()
	if port == "" {
		if https {
			port = "443"
		} else {
			port = "80"
		}
	}
	pnum, _ := strconv.Atoi(port)
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	host := u.Hostname()
	deadline := time.Duration(timeoutSec) * time.Second
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", base.Mixed), deadline)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(deadline))
	if https {
		_, err = fmt.Fprintf(conn, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: curl/8\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n",
			host, pnum, host, pnum)
		if err != nil {
			return 0, err
		}
		br := bufio.NewReader(conn)
		status, err := br.ReadString('\n')
		if err != nil {
			return 0, err
		}
		if !strings.Contains(status, " 200") {
			return 0, fmt.Errorf("proxy CONNECT failed: %s", strings.TrimSpace(status))
		}
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" || line == "\n" || line == "" {
				break
			}
		}
		tlsConn := tls.Client(conn, rttTLSConfig(host))
		_ = tlsConn.SetDeadline(time.Now().Add(deadline))
		if err := tlsConn.Handshake(); err != nil {
			return 0, err
		}
		conn = tlsConn
		_ = conn.SetDeadline(time.Now().Add(deadline))
	} else {
		// 普通 HTTP 走代理时请求行用完整 URL
		path = fmt.Sprintf("http://%s:%d%s", host, pnum, path)
	}
	_ = conn.SetDeadline(time.Now().Add(deadline))
	st := time.Now()
	willClose, err := headOnce(conn, path, host)
	if err != nil {
		return 0, err
	}
	first := int(time.Since(st).Milliseconds())
	if willClose {
		return first, nil
	}
	_ = conn.SetDeadline(time.Now().Add(deadline))
	st = time.Now()
	if _, err := headOnce(conn, path, host); err != nil {
		return first, nil // 第二次请求失败时退回第一次的总耗时
	}
	ms := int(time.Since(st).Milliseconds())
	if ms < 1 {
		ms = 1
	}
	return ms, nil
}

// headOnce 发送一次 HEAD 请求，返回连接是否会关闭。
func headOnce(conn net.Conn, reqLine, host string) (bool, error) {
	_, err := fmt.Fprintf(conn, "HEAD %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n",
		reqLine, host)
	if err != nil {
		return false, err
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		return false, err
	}
	willClose := strings.Contains(status, "HTTP/1.0") // 对应 http.client will_close 的近似判定
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return false, err
		}
		if line == "\r\n" || line == "\n" || line == "" {
			break
		}
		lh := strings.ToLower(line)
		if strings.HasPrefix(lh, "connection:") {
			if strings.Contains(lh, "close") {
				willClose = true
			} else if strings.Contains(lh, "keep-alive") {
				willClose = false
			}
		}
	}
	return willClose, nil
}

// DirectRtt 对应 direct_rtt(timeout)：直连（不走代理）延迟，与概览「百度」卡片同一口径。
func DirectRtt(timeoutSec int) int {
	mode := "rule"
	if cfg := corehttp.CoreJSON("/configs", 3); cfg != nil {
		if m := data.Str(cfg, "mode"); m != "" {
			mode = strings.ToLower(m)
		}
	}
	if mode != "global" {
		if ms, err := SiteRtt(base.DirectHc, timeoutSec); err == nil && ms > 0 {
			return ms
		}
	}
	var got []int
	for i := 0; i < 2; i++ {
		code, raw := corehttp.Core("GET", "/proxies/DIRECT/delay?url="+url.QueryEscape(base.DirectHc)+
			"&timeout="+strconv.Itoa(timeoutSec*1000), nil, timeoutSec+2)
		ms := 0
		if code == 200 {
			var j map[string]any
			if json.Unmarshal(raw, &j) == nil {
				ms = data.Int(j, "delay")
			}
		}
		if ms <= 0 {
			break
		}
		got = append(got, ms)
	}
	if len(got) > 0 {
		m := got[0]
		for _, v := range got[1:] {
			if v < m {
				m = v
			}
		}
		return m
	}
	iface := ""
	func() {
		defer func() { _ = recover() }() // STUB 未接线时按 Python 的 ImportError 处理：不用 --interface
		iface = physIface()
	}()
	cmd := []string{"curl"}
	if iface != "" {
		cmd = append(cmd, "--interface", iface)
	}
	cmd = append(cmd, "-s", "-I", "-o", "/dev/null", "-o", "/dev/null", "-w", "%{time_total}\\n",
		"--max-time", strconv.Itoa(timeoutSec), base.DirectHc, base.DirectHc)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec*2+2)*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).Output()
	if err != nil {
		return -1
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return -1
	}
	f, err := strconv.ParseFloat(fields[len(fields)-1], 64)
	if err != nil {
		return -1
	}
	ms := int(f * 1000)
	if ms <= 0 {
		return -1
	}
	if ms < 1 {
		ms = 1
	}
	return ms
}

var (
	siteMu    sync.Mutex
	siteHist  = map[string][]int{}
	siteLastT time.Time
	siteLastR []map[string]any
)

// SiteHistN 每个站点保留最近 30 次（约 30 分钟）
const SiteHistN = 30

// DelayTest 对应 delay_test(force)：多个浏览器同时打开概览时 20 秒内复用同一次结果，历史只记一次。
func DelayTest(force bool) []map[string]any {
	if !force {
		siteMu.Lock()
		r, t := siteLastR, siteLastT
		siteMu.Unlock()
		if r != nil && time.Since(t) < 20*time.Second {
			return r
		}
	}
	tests := []any(base.TestsDefault)
	if l := data.List(data.Load(), "tests"); len(l) > 0 {
		tests = l
	}
	out := make([]map[string]any, len(tests))
	var wg sync.WaitGroup
	for i, tt := range tests {
		wg.Add(1)
		go func(i int, tt any) {
			defer wg.Done()
			tm, _ := tt.(map[string]any)
			name, u := data.Str(tm, "name"), data.Str(tm, "url")
			ms := -1
			if v, err := SiteRtt(u, 6); err == nil {
				ms = v
			}
			out[i] = map[string]any{"name": name, "url": u, "ms": ms}
		}(i, tt)
	}
	wg.Wait()
	siteMu.Lock()
	defer siteMu.Unlock()
	if !force && siteLastR != nil && time.Since(siteLastT) < 20*time.Second {
		return siteLastR // 测速期间已有更新鲜的结果，直接复用，丢弃本次结果
	}
	names := map[string]bool{}
	for _, o := range out {
		names[data.Str(o, "name")] = true
	}
	for k := range siteHist {
		if !names[k] {
			delete(siteHist, k)
		}
	}
	for _, o := range out {
		n := data.Str(o, "name")
		h := append(siteHist[n], data.Int(o, "ms"))
		if len(h) > SiteHistN {
			h = h[len(h)-SiteHistN:]
		}
		siteHist[n] = h
		hist := make([]any, len(h))
		for i, v := range h {
			hist[i] = v
		}
		o["hist"] = hist
	}
	siteLastT = time.Now()
	siteLastR = out
	return out
}

// ---------- 站点图标 ----------

var (
	favMu      sync.Mutex
	favFail    = map[string]int64{}
	favFailMax = 2000 // 失败记录上限：超限淘汰最旧的，防止无界增长
	hostRe     = regexp.MustCompile(`^[a-z0-9.-]{1,253}$`)
)

// ImgType 对应 img_type(b)：按魔数识别位图图标，返回 Content-Type；
// SVG、HTML 等可执行脚本的格式一律不认（防 XSS）。
func ImgType(b []byte) string {
	switch {
	case len(b) >= 4 && bytes.Equal(b[:4], []byte{0x00, 0x00, 0x01, 0x00}):
		return "image/x-icon"
	case len(b) >= 8 && bytes.Equal(b[:8], []byte("\x89PNG\r\n\x1a\n")):
		return "image/png"
	case len(b) >= 6 && (bytes.Equal(b[:6], []byte("GIF87a")) || bytes.Equal(b[:6], []byte("GIF89a"))):
		return "image/gif"
	case len(b) >= 3 && bytes.Equal(b[:3], []byte{0xff, 0xd8, 0xff}):
		return "image/jpeg"
	case len(b) >= 12 && bytes.Equal(b[:4], []byte("RIFF")) && bytes.Equal(b[8:12], []byte("WEBP")):
		return "image/webp"
	}
	return ""
}

// FavHosts 对应 fav_hosts(d)：允许取图标的站点，只限「延迟站点」列表里出现过的 host，
// 防止面板被当作任意 URL 的同源代理。
func FavHosts(d map[string]any) map[string]bool {
	if d == nil {
		d = data.Load()
	}
	tests := []any(base.TestsDefault)
	if l := data.List(d, "tests"); len(l) > 0 {
		tests = l
	}
	out := map[string]bool{}
	for _, tt := range tests {
		tm, _ := tt.(map[string]any)
		u, err := url.Parse(data.Str(tm, "url"))
		if err != nil {
			continue
		}
		if h := strings.ToLower(u.Hostname()); h != "" {
			out[h] = true
		}
	}
	return out
}

// Favicon 对应 favicon(url, allowed)：经代理下载站点图标；缓存 7 天，失败的 1 小时内不重试。
// allowed 为 nil 时用 FavHosts 计算。返回 (图标字节, Content-Type)，取不到返回 (nil, "")。
func Favicon(rawurl string, allowed map[string]bool) ([]byte, string) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, ""
	}
	host := strings.ToLower(u.Hostname())
	if !hostRe.MatchString(host) {
		return nil, ""
	}
	if allowed == nil {
		allowed = FavHosts(nil)
	}
	if !allowed[host] {
		return nil, ""
	}
	path := filepath.Join(FavDir, host)
	if fi, err := os.Stat(path); err == nil && time.Since(fi.ModTime()) < 7*24*time.Hour {
		if b, err := os.ReadFile(path); err == nil {
			if ct := ImgType(b); ct != "" {
				return b, ct
			}
			os.Remove(path) // 旧版本缓存的 SVG 等非位图：删掉重新获取
		}
	}
	favMu.Lock()
	failT := favFail[host]
	favMu.Unlock()
	if time.Now().Unix()-failT < 3600 {
		return nil, ""
	}
	parts := strings.Split(host, ".")
	root := host
	if len(parts) >= 2 {
		root = strings.Join(parts[len(parts)-2:], ".") // api.telegram.org 没有图标时用 telegram.org 的
	}
	tries := []string{"https://" + host + "/favicon.ico"}
	if root != host {
		tries = append(tries, "https://"+root+"/favicon.ico", "https://www."+root+"/favicon.ico")
	}
	tries = append(tries, "https://www.google.com/s2/favicons?domain="+host+"&sz=64")
	op := ProxyClient(true)
	for _, tu := range tries {
		if err := base.DlCheck(tu, true); err != nil { // SSRF 防护：走代理下载，跳过本地 DNS 校验
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", tu, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := op.Do(req)
		cancel()
		if err != nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}
		if len(b) > 60 && ImgType(b) != "" {
			os.MkdirAll(FavDir, 0o755)
			_ = os.WriteFile(path, b, 0o644)
			return b, ImgType(b)
		}
	}
	favMu.Lock()
	if len(favFail) >= favFailMax {
		oldest, oldestT := "", int64(1<<62)
		for k, v := range favFail {
			if v < oldestT {
				oldest, oldestT = k, v
			}
		}
		delete(favFail, oldest)
	}
	favFail[host] = time.Now().Unix()
	favMu.Unlock()
	return nil, ""
}
