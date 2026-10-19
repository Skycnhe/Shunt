// Package cli 对应 Python shunt/cli.py：命令行入口与面板启动。
package cli

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"shunt/internal/adblock"
	"shunt/internal/base"
	"shunt/internal/data"
	"shunt/internal/devices"
	"shunt/internal/errlog"
	"shunt/internal/https"
	"shunt/internal/latency"
	"shunt/internal/live"
	"shunt/internal/logclean"
	"shunt/internal/migrate"
	"shunt/internal/mihomo"
	"shunt/internal/schedule"
	"shunt/internal/singbox"
	"shunt/internal/stats"
	"shunt/internal/svcmigrate"
	"shunt/internal/sysopt"
	"shunt/internal/updateguard"
	"shunt/internal/webapi"
)

// ---------------------------------------------------------------- STUB（其他 agent 的模块，集成时接线）

// statsCollector 对应 stats.Stats（Python cli.py 的 STATS）
type statsCollector = stats.Stats

func newStats() *statsCollector { return stats.NewStats() }

// adStatsCollector 对应 adblock.AdStats（Python cli.py 的 AD_STATS）
type adStatsCollector = adblock.AdStats

func newAdStats() *adStatsCollector { return adblock.NewAdStats() }

// dnsCfg 对应 mihomo.DnsCfg
func dnsCfg(d map[string]any) map[string]any { return mihomo.DnsCfg(d) }

// activeCore 对应 singbox.ActiveCore（sb_common.active_core；cli.py 里同名引用）
func activeCore(d map[string]any) string { return singbox.ActiveCore(d) }

// writeCoreFile 对应 singbox.WriteCoreFile
func writeCoreFile(core string) { singbox.WriteCoreFile(core) }

// writeActiveConfig 对应 singbox.WriteActiveConfig
func writeActiveConfig(d map[string]any) string { return singbox.WriteActiveConfig(d) }

// monitorLoop 对应 latency.MonitorLoop
func monitorLoop() { latency.MonitorLoop() }

// schedLoop 对应 schedule.SchedLoop
func schedLoop() { schedule.SchedLoop() }

// rdnsLoop 对应 devices.RdnsLoop
func rdnsLoop() { devices.RdnsLoop() }

// webHandler 对应 webapi：Python 为 BaseHTTPRequestHandler 子类，Go 里为已注册路由的 http.Handler
func webHandler() http.Handler { return webapi.NewServer().Handler() }

// ----------------------------------------------------------------

// TpEnv 对应 tp_env()：供 tproxy.sh eval 的环境变量（绕过列表、IPv6 开关、本机 IPv6 网段，值均经过过滤）。
func TpEnv() string {
	d := data.Load()
	var items []string
	for _, x := range data.List(d, "bypass") {
		if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
			items = append(items, strings.TrimSpace(s))
		}
	}
	macRe := regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$`)
	var macs []string
	seen := map[string]bool{}
	for _, x := range items {
		if macRe.MatchString(x) {
			m := strings.ToLower(strings.ReplaceAll(x, "-", ":"))
			if !seen[m] {
				seen[m] = true
				macs = append(macs, m)
			}
		}
	}
	var ips, ip6s []netip.Prefix
	for _, x := range items {
		p, err := netip.ParsePrefix(x)
		if err != nil {
			// ipaddress.ip_network(x, strict=False)：单个地址视为 /32 或 /128
			if addr, err2 := netip.ParseAddr(strings.Split(x, "%")[0]); err2 == nil {
				bits := 32
				if addr.Is6() {
					bits = 128
				}
				p = netip.PrefixFrom(addr, bits)
			} else {
				continue
			}
		}
		p = p.Masked()
		if p.Addr().Is4() {
			ips = append(ips, p)
		} else {
			ip6s = append(ip6s, p)
		}
	}
	// nftables 的 interval 集合不接受重叠 / 重复的元素，先合并（去重 + 去被包含；
	// Python 的 collapse_addresses 还会合并相邻网段，相邻不冲突，此处等价）
	ips = collapsePrefixes(ips)
	ip6s = collapsePrefixes(ip6s)
	var local6 []netip.Prefix
	_, out := sysopt.Sh("ip -o -6 addr show scope global 2>/dev/null")
	for _, m := range regexp.MustCompile(`inet6 ([0-9a-fA-F:]+/\d+)`).FindAllStringSubmatch(out, -1) {
		if p, err := netip.ParsePrefix(m[1]); err == nil {
			local6 = append(local6, p.Masked())
		}
	}
	local6 = collapsePrefixes(local6)
	strs := func(ps []netip.Prefix) string {
		var s []string
		for _, p := range ps {
			s = append(s, p.String())
		}
		return strings.Join(s, ",")
	}
	ipv6 := 0
	if truthy(d["ipv6"]) {
		ipv6 = 1
	}
	dnsAll := 0
	func() {
		defer func() { _ = recover() }() // STUB 未接线时按关闭处理
		if data.Bool(dnsCfg(d), "block_bypass") {
			dnsAll = 1
		}
	}()
	mode, _ := d["proxy_mode"].(string)
	return fmt.Sprintf("B_IP='%s'\nB_MAC='%s'\nB_IP6='%s'\nLOCAL6='%s'\nIPV6=%d\nMODE=%s\nDNS_ALL=%d",
		strs(ips), strings.Join(macs, ","), strs(ip6s), strs(local6), ipv6, shellQuote(mode), dnsAll)
}

// collapsePrefixes 去重并去掉被更大网段包含的前缀（已排序）。
func collapsePrefixes(ps []netip.Prefix) []netip.Prefix {
	uniq := []netip.Prefix{}
	seen := map[string]bool{}
	for _, p := range ps {
		if !seen[p.String()] {
			seen[p.String()] = true
			uniq = append(uniq, p)
		}
	}
	sort.Slice(uniq, func(i, j int) bool {
		if c := uniq[i].Addr().Compare(uniq[j].Addr()); c != 0 {
			return c < 0
		}
		return uniq[i].Bits() < uniq[j].Bits()
	})
	var out []netip.Prefix
	for _, p := range uniq {
		contained := false
		for _, q := range out {
			if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
				contained = true
				break
			}
		}
		if !contained {
			out = append(out, p)
		}
	}
	return out
}

func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0
	case int:
		return t != 0
	default:
		return true
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\\''`) + "'"
}

// DefaultTz 对应 default_tz()：设备没设时区时按北京时间算「今天」。
func DefaultTz() bool {
	if os.Getenv("TZ") != "" {
		return false
	}
	if _, err := os.Stat("/etc/localtime"); err == nil {
		return false
	}
	os.Setenv("TZ", "CST-8")
	// Go 不解析 "CST-8" 这类 POSIX 时区名（time.LoadLocation 只认 IANA 名），
	// 用等价的固定 +8 时区；子进程沿用 TZ 环境变量自行解析。
	time.Local = time.FixedZone("CST", 8*3600)
	return true
}

// dropWarp 对应 _drop_warp()：v10.1.0 去掉了 WARP，结束旧版留下的 WARP 实例、
// 撤掉它挂的透明代理规则（恢复直连），删除其配置目录。
func dropWarp() {
	pidf := "/run/shunt-warp.pid"
	wdir := filepath.Join(base.PanelDir, "warp")
	if b, err := os.ReadFile(pidf); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			ok := false
			if cb, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
				ok = bytes.Contains(cb, []byte(wdir)) // pid 已被别的进程复用则跳过
			}
			if ok {
				_ = syscall.Kill(pid, syscall.SIGTERM)
				sysopt.Sh(fmt.Sprintf("sh %s stop", shellQuote(base.TproxySh)), 30)
				fmt.Printf("%s [upgrade] 已结束旧版 WARP 实例，局域网恢复直连；需要代理请在顶栏启动核心\n",
					time.Now().Format("2006-01-02 15:04:05"))
			}
		}
		_ = os.Remove(pidf)
	}
	_ = os.RemoveAll(wdir)
}

func hasArg(args []string, flag string) int {
	for i, a := range args {
		if a == flag {
			return i
		}
	}
	return -1
}

// Main 对应 main()：命令行入口。带参数时执行一次性命令，否则启动面板。
func Main() {
	DefaultTz()
	args := os.Args[1:]
	if hasArg(args, "--bypass") >= 0 { // 兼容旧版 tproxy.sh
		env := map[string]string{}
		for _, l := range strings.Split(TpEnv(), "\n") {
			if kv := strings.SplitN(l, "=", 2); len(kv) == 2 {
				env[kv[0]] = kv[1]
			}
		}
		fmt.Println(strings.Trim(env["B_IP"], "'") + "|" + strings.Trim(env["B_MAC"], "'"))
		os.Exit(0)
	}
	if hasArg(args, "--tpenv") >= 0 {
		fmt.Println(TpEnv())
		os.Exit(0)
	}
	if hasArg(args, "--gen") >= 0 { // init.d/shunt-core 启动前调用：按当前内核生成配置
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintln(os.Stderr, "文件句柄修正失败：", r)
				}
			}()
			sysopt.OptFixUlimit()
		}()
		dd := data.Load()
		writeCoreFile(activeCore(dd))
		fmt.Println(writeActiveConfig(dd))
		os.Exit(0)
	}
	if i := hasArg(args, "--allow-public"); i >= 0 { // 允许 / 禁止从外网访问面板
		next := "on"
		if i+1 < len(args) {
			next = args[i+1]
		}
		on := next == "on" || next == "1" || next == "yes" || next == "true"
		data.Update(func(x map[string]any) { x["allow_public"] = on })
		if on {
			fmt.Println("已允许外网访问面板（面板没有密码，请用防火墙或反向代理自行加访问控制）")
		} else {
			fmt.Println("已恢复为只允许局域网访问")
		}
		os.Exit(0)
	}
	if i := hasArg(args, "--allow-host"); i >= 0 { // 允许用这个域名访问面板；--allow-host -x 删除
		rest := []string{}
		if i+1 < len(args) {
			rest = args[i+1:]
		}
		if len(rest) == 0 {
			hosts := data.Strs(data.Load(), "allow_hosts")
			cur := strings.Join(hosts, ", ")
			if cur == "" {
				cur = "（无，IP 和 .lan/.local 等局域网域名始终允许）"
			}
			fmt.Println("当前允许的域名：", cur)
			os.Exit(0)
		}
		h := strings.TrimSpace(strings.ToLower(rest[0]))
		plain := strings.TrimLeft(h, "-")
		del := strings.HasPrefix(h, "-")
		data.Update(func(x map[string]any) {
			var cur []string
			for _, y := range data.Strs(x, "allow_hosts") {
				if y != plain {
					cur = append(cur, y)
				}
			}
			if del {
				x["allow_hosts"] = cur
			} else {
				x["allow_hosts"] = append(cur, h)
			}
		})
		if del {
			fmt.Println("已删除 " + plain)
		} else {
			fmt.Println("已允许 " + h)
		}
		os.Exit(0)
	}
	if hasArg(args, "--snapshot") >= 0 { // install.sh 升级前调用：记下各组当前选择
		if migrate.SnapshotSelections(false) != nil {
			fmt.Println("saved")
		} else {
			fmt.Println("skip")
		}
		os.Exit(0)
	}
	if hasArg(args, "--gen-cert") >= 0 {
		ok, out := https.GenCert()
		fmt.Println(out)
		if !ok {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if hasArg(args, "--help") >= 0 || hasArg(args, "-h") >= 0 {
		fmt.Println(`用法: shunt [选项]
无参数时启动面板。

一次性命令：
  --bypass          打印绕过列表（供 tproxy.sh，格式 B_IP|B_MAC）
  --tpenv           打印供 tproxy.sh eval 的环境变量
  --gen             按当前内核生成配置并打印路径（init.d/shunt-core 启动前调用）
  --allow-public [on|off]  允许 / 禁止从外网访问面板
  --allow-host [域名|-域名]  查看 / 允许 / 删除可访问面板的域名
  --snapshot        升级前记下各组当前选择
  --gen-cert        生成自签名证书
  --help, -h        显示本帮助`)
		os.Exit(0)
	}
	d := data.Load()
	_ = os.Remove(filepath.Join(base.PanelDir, "sessions.json")) // v6.8.2 起没有登录会话，删掉旧版留下的会话文件
	dropWarp()
	st := newStats()
	ad := newAdStats()
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGTERM)
	go func() {
		<-sigc
		st.Flush() // 让 finally 有机会保存统计
		ad.Flush()
		os.Exit(0)
	}()
	go st.Loop()
	go monitorLoop()
	go ad.Loop()
	go ad.DnsLoop()
	go live.LiveLoop("/traffic")
	go live.LiveLoop("/memory")
	go logclean.LogLoop()
	go schedLoop()
	go rdnsLoop()
	go migrate.StartupMigrate()
	func() {
		defer func() {
			if r := recover(); r != nil {
				errlog.LogErr("文件句柄修正", fmt.Errorf("%v", r), false)
			}
		}()
		sysopt.OptMigrateConfd()
		sysopt.OptFixUlimit()
	}()
	svcmigrate.SvcMigrate(20) // v7.7.6 服务改名：旧设备在线更新后自动迁移到 shunt / shunt-core
	if _, err := os.Stat(updateguard.RollbackNote); err == nil {
		if b, err := os.ReadFile(updateguard.RollbackNote); err == nil {
			errlog.LogErr("面板在线更新", string(b), false)
		}
		_ = os.Remove(updateguard.RollbackNote)
	}
	srv := https.NewServer(fmt.Sprintf("0.0.0.0:%d", base.Port), webHandler())
	scheme := "http"
	serve := func() error { return srv.ListenAndServe() }
	if https.HttpsReady(d) {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12} // 禁用 TLS 1.0/1.1
		scheme = "https"
		serve = func() error { return srv.ListenAndServeTLS(base.CertFile, base.KeyFile) }
	}
	fmt.Printf("Shunt listening on %s://0.0.0.0:%d\n", scheme, base.Port)
	_ = serve()
	st.Flush()
	ad.Flush()
}
