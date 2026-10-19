// Package diag 对应 Python shunt/diag.py：网络诊断（一键诊断）。
// 检查核心状态、配置校验、转发/TProxy/TUN、DNS 服务、国内外解析、
// 直连与代理连通性、DNS 绕过设备、磁盘空间，输出脱敏后的诊断项列表。
package diag

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"shunt/internal/base"
	"shunt/internal/core"
	"shunt/internal/corehttp"
	"shunt/internal/data"
	"shunt/internal/errlog"
	"shunt/internal/mihomo"
	"shunt/internal/singbox"
	"shunt/internal/sysopt"
)

// checkConfig 对应 mihomo.CheckConfig：用 mihomo -t 校验配置
func checkConfig(path string) (bool, string) { return mihomo.CheckConfig(path) }

// mhBin 对应 mihomo.MhBin：mihomo 系内核程序路径
func mhBin(kind ...string) string { return mihomo.MhBin(kind...) }

// safeDev 对应 mihomo.SafeDev：TUN 网卡名清洗
func safeDev(name string) string { return mihomo.SafeDev(name) }

// dnsCfg 对应 mihomo.DnsCfg
func dnsCfg(d map[string]any) map[string]any { return mihomo.DnsCfg(d) }

// coreReq 对应 corehttp.Core
func coreReq(method, path string, timeoutSec int) (int, []byte) {
	return corehttp.Core(method, path, nil, timeoutSec)
}

// connsSnapshot 对应 core.ConnsSnapshot（Python diag.py 调用 conns_snapshot(5)，ttl 默认 2）
func connsSnapshot(timeoutSec int) map[string]any {
	m, _ := core.ConnsSnapshot(timeoutSec, 2).(map[string]any)
	return m
}

// activeCore 对应 singbox.ActiveCore（sb_common.active_core）
func activeCore(d ...map[string]any) string { return singbox.ActiveCore(d...) }

// coreDisplayName 对应 singbox.Cores：内核展示名
func coreDisplayName(kind string) string {
	if n, ok := singbox.Cores[kind]; ok {
		return n
	}
	return kind
}

// sbBin 对应 singbox.SBBin（SB_BIN）
func sbBin() string { return singbox.SBBin }

// sbConf 对应 singbox.SBConf（SB_CONF）
func sbConf() string { return singbox.SBConf }

// sbStateWarn 对应 singbox.SBState["warn"]
func sbStateWarn() []string {
	var out []string
	if l, ok := singbox.SBState["warn"].([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// checkSbConfig 对应 singbox.CheckSbConfig：sing-box check 校验配置
func checkSbConfig(path string) (bool, string) { return singbox.CheckSbConfig(path) }

// proxyOpener 对应 sysopt.ProxyClient：经 mixed 端口或直连的 http.Client（proxy_opener 默认 proxy=True）
func proxyOpener(viaProxy ...bool) *http.Client {
	proxy := true
	if len(viaProxy) > 0 {
		proxy = viaProxy[0]
	}
	return sysopt.ProxyClient(proxy)
}

// sh 对应 sysopt.Sh，返回 (exitCode, stdout+stderr)
func sh(cmd string, timeoutSec int) (int, string) { return sysopt.Sh(cmd, timeoutSec) }

// errlogErrs 对应 errlog.Errs：24 小时内的面板内部错误
func errlogErrs() []map[string]any { return errlog.Errs() }

// DnsProbe 向 mihomo DNS 端口发一个最小的 A 查询；返回 (成功, 毫秒, rcode, 错误)
func DnsProbe(server, name string) (bool, int, int, error) {
	var qid [2]byte
	if _, err := rand.Read(qid[:]); err != nil {
		return false, 0, 0, err
	}
	var pkt []byte
	pkt = append(pkt, qid[0], qid[1], 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, x := range strings.Split(name, ".") {
		pkt = append(pkt, byte(len(x)))
		pkt = append(pkt, x...)
	}
	pkt = append(pkt, 0x00, 0x00, 0x01, 0x00, 0x01)
	conn, err := net.Dial("udp", server)
	if err != nil {
		return false, 0, 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	st := time.Now()
	if _, err := conn.Write(pkt); err != nil {
		return false, 0, 0, err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return false, 0, 0, err
	}
	d := buf[:n]
	rcode := int(d[3] & 0x0F)
	an := int(binary.BigEndian.Uint16(d[6:8]))
	return rcode == 0 && an > 0, int(time.Since(st).Milliseconds()), rcode, nil
}

var (
	scrubPath1 = regexp.MustCompile(`'/[^']*'`)
	scrubPath2 = regexp.MustCompile(`"/[^"]*"`)
	scrubCred  = regexp.MustCompile(`(https?://[^/\s:]+:)[^@/\s]+@`)
)

// scrub 诊断页脱敏：异常信息里可能带文件绝对路径或 URL 中的账号密码，展示前替换
func scrub(s string) string {
	s = scrubPath1.ReplaceAllString(s, "'<路径>'")
	s = scrubPath2.ReplaceAllString(s, `"<路径>"`)
	s = scrubCred.ReplaceAllString(s, `$1***@`)
	return s
}

// DnsBypassDevices 检测 DNS 绕过面板的设备。
//
// 原理：Fake-IP 模式下，设备 DNS 经过面板时拿到的目标是 198.18.x.x；
// 若某连接嗅探到了域名（sniffHost），但目标 IP 是公网真实 IP，
// 说明该设备自己解析了域名（DNS 没经过面板，如用了主路由 DNS / 私人 DNS）。
// sing-box 1.13+ 移除了 sniff_override_destination，这种情况拿污染 IP 必死；
// mihomo 的 sniffer 会改写目标地址所以不受影响。
//
// 返回 {设备IP: {域名...}}；conns 为空时返回空 map。
func DnsBypassDevices(conns map[string]any) map[string]map[string]bool {
	if conns == nil {
		conns = connsSnapshot(5)
	}
	devs := map[string]map[string]bool{}
	if len(conns) == 0 {
		return devs
	}
	for _, x := range toList(conns["connections"]) {
		xm, _ := x.(map[string]any)
		if xm == nil {
			continue
		}
		md, _ := xm["metadata"].(map[string]any)
		if md == nil {
			continue
		}
		sniff := strings.ToLower(strings.TrimSpace(strOf(md["sniffHost"])))
		dip := strings.TrimSpace(strOf(md["destinationIP"]))
		sip := strings.TrimSpace(strOf(md["sourceIP"]))
		if sniff == "" || dip == "" || sip == "" {
			continue
		}
		ip := net.ParseIP(dip)
		if ip == nil {
			continue
		}
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		inFake := false
		for _, n := range base.FakeIPNets {
			if n.Contains(ip) {
				inFake = true
				break
			}
		}
		if inFake {
			continue
		}
		// 公网 IP + 嗅探到域名 = 设备 DNS 未经过面板
		if devs[sip] == nil {
			devs[sip] = map[string]bool{}
		}
		devs[sip][sniff] = true
	}
	return devs
}

// DiagItem 诊断项
type DiagItem struct {
	Name   string `json:"name"`
	OK     any    `json:"ok"` // true / false / "warn"
	Detail string `json:"detail"`
	Fix    string `json:"fix"`
}

// Diagnose 一键诊断
func Diagnose() []DiagItem {
	d := data.Load()
	mode := data.Str(d, "proxy_mode")
	var out []DiagItem
	item := func(name string, ok any, detail, fix string) {
		f := fix
		if ok == true {
			f = ""
		}
		out = append(out, DiagItem{Name: name, OK: ok, Detail: detail, Fix: f})
	}

	now := float64(time.Now().UnixNano()) / 1e9
	var recent []map[string]any
	for _, e := range errlogErrs() {
		var t float64
		switch v := e["t"].(type) {
		case float64:
			t = v
		case int:
			t = float64(v)
		case int64:
			t = float64(v)
		}
		if now-t < 86400 {
			recent = append(recent, e)
		}
	}
	if len(recent) > 0 {
		var parts []string
		for _, e := range recent {
			if len(parts) >= 5 {
				break
			}
			var t int64
			switch v := e["t"].(type) {
			case float64:
				t = int64(v)
			case int:
				t = int64(v)
			case int64:
				t = v
			}
			parts = append(parts, time.Unix(t, 0).Format("01-02 15:04")+" "+strOf(e["where"])+"："+scrub(strOf(e["msg"])))
		}
		detail := firstN(strings.Join(parts, "；"), 600)
		item(fmt.Sprintf("面板内部错误（24 小时内 %d 条）", len(recent)), "warn", detail,
			"完整记录在 /var/log/mihomo-panel.log，反馈问题时请附上")
	}

	code, ver := coreReq("GET", "/version", 5)
	alive := code == 200
	kind := activeCore(d)
	sb := kind == "singbox"
	verStr := "核心未运行或控制器无响应"
	if alive {
		var vj map[string]any
		if json.Unmarshal(ver, &vj) == nil {
			verStr, _ = vj["version"].(string)
		}
	}
	item(coreDisplayName(kind)+" 核心", alive, verStr,
		"在顶部点「启动」，或执行 rc-service shunt-core restart 并查看 /var/log/mihomo.log")
	if sb {
		if fileExists(sbBin()) && fileExists(sbConf()) {
			ok, errMsg := checkSbConfig(sbConf())
			detail := "通过"
			if !ok {
				detail = lastN(errMsg, 200)
			}
			item("配置校验 (sing-box check)", ok, detail, "在设置中撤销最近的修改，或切回 mihomo")
		}
		if warns := sbStateWarn(); len(warns) > 0 {
			item("sing-box 兼容提示", "warn", firstN(strings.Join(warns, "；"), 300), "详见 设置 → 核心 → 内核切换")
		}
	}
	cfg := filepath.Join(base.ConfDir, "config.yaml")
	if !sb && fileExists(mhBin(kind)) && fileExists(cfg) {
		ok, errMsg := checkConfig(cfg)
		detail := "通过"
		if !ok {
			detail = lastN(errMsg, 200)
		}
		item("配置校验 (mihomo -t)", ok, detail, "在设置中撤销最近的修改，或恢复备份")
	}
	fwd := false
	if raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		fwd = strings.TrimSpace(string(raw)) == "1"
	}
	var fwdOK any = fwd
	if mode == "off" && !fwd {
		fwdOK = "warn"
	}
	fwdDetail := "未开启"
	if fwd {
		fwdDetail = "已开启"
	}
	item("IPv4 转发", fwdOK, fwdDetail, "sysctl -w net.ipv4.ip_forward=1，并写入 /etc/sysctl.conf")
	_, st := sh(base.TproxySh+" status", 10)
	st = lastLine(st)
	switch mode {
	case "tproxy":
		ok := st == "tproxy"
		detail := "未检测到 nftables TProxy 规则"
		if ok {
			detail = "nftables 规则已加载"
		}
		item("TProxy 规则", ok, detail,
			"在设置里重新选择「TProxy」，或执行 /opt/mihomo-panel/tproxy.sh start；需要 nftables 与 nft_tproxy 模块")
	case "tun":
		dev := safeDev(data.Str(data.Map(d, "tun"), "device"))
		hasTun := fileExists("/dev/net/tun")
		tunDetail := "缺少 /dev/net/tun"
		if hasTun {
			tunDetail = "/dev/net/tun 存在"
		}
		item("TUN 模块", hasTun, tunDetail, "modprobe tun，并把 tun 加入 /etc/modules（install.sh 会自动处理）")
		up := dirExists("/sys/class/net/" + dev)
		upDetail := "未找到该网卡"
		if up {
			upDetail = "已创建"
		}
		item("TUN 网卡 "+dev, up, upDetail, "确认核心以 root 运行且日志里没有 TUN 报错；切换协议栈为 gvisor 再试")
		var dnsOK any = "warn"
		dnsDetail := "未加载，局域网设备需把 DNS 指向本机 1053 或开启后重试"
		if st == "dns" {
			dnsOK = true
			dnsDetail = "已加载"
		}
		item("DNS 重定向 (53 → 1053)", dnsOK, dnsDetail, "执行 /opt/mihomo-panel/tproxy.sh dns")
	default:
		item("代理方式", "warn", "已关闭透明代理，仅 7890 端口（HTTP/SOCKS）可用", "在设置里选择 TProxy 或 TUN")
	}

	if alive {
		if ok, ms, rc, err := DnsProbe("127.0.0.1:1053", "www.baidu.com"); err != nil {
			item("DNS 服务 (127.0.0.1:1053)", false, firstN(err.Error(), 120), "确认核心 DNS 已监听 1053 端口")
		} else if ok {
			item("DNS 服务 (127.0.0.1:1053)", true, fmt.Sprintf("解析 www.baidu.com 用时 %d ms", ms), "")
		} else {
			item("DNS 服务 (127.0.0.1:1053)", false, fmt.Sprintf("返回码 %d", rc), "检查 设置 → DNS 中的直连 DNS 是否可达")
		}
		for _, hc := range [][2]string{{"www.baidu.com", "国内域名解析"}, {"www.google.com", "国外域名解析"}} {
			host, label := hc[0], hc[1]
			c2, raw := coreReq("GET", "/dns/query?name="+host+"&type=A", 10)
			ok, detail, fix := false, "查询失败", "检查 DNS 设置"
			var j map[string]any
			if json.Unmarshal(raw, &j) == nil {
				var ans []string
				for _, a := range toList(j["Answer"]) {
					if am, good := a.(map[string]any); good {
						if toInt(am["type"]) == 1 {
							if ds, isStr := am["data"].(string); isStr {
								ans = append(ans, ds)
							}
						}
					}
				}
				statusOK := false
				if sv, present := j["Status"]; present && sv != nil {
					statusOK = toInt(sv) == 0
				}
				if c2 == 200 && statusOK && len(ans) > 0 {
					ok = true
					detail = strings.Join(firstNStr(ans, 2), ", ")
				} else {
					detail = fmt.Sprintf("失败（Status %s）", pyRepr(j["Status"]))
				}
				fix = "检查直连 / 代理 DNS 设置"
				if strings.Contains(host, "google") {
					fix += "；代理 DNS 依赖节点可用"
				}
			}
			item(label, ok, detail, fix)
		}
		if sb && data.Str(dnsCfg(d), "mode") == "fake-ip" {
			// sing-box 1.13+ 无 sniff_override_destination：设备 DNS 绕过面板时，
			// 规则按嗅探域名命中了代理组，但实际连的是污染 IP，必定失败（mihomo 不受影响）
			if bypass := DnsBypassDevices(nil); len(bypass) > 0 {
				var parts []string
				i := 0
				for sip, v := range bypass {
					if i >= 5 {
						break
					}
					var doms []string
					for dom := range v {
						doms = append(doms, dom)
					}
					sort.Strings(doms)
					parts = append(parts, fmt.Sprintf("%s（%d 个域名，如 %s）", sip, len(v), doms[0]))
					i++
				}
				item("DNS 绕过检测", "warn", "以下设备 DNS 未经过面板："+strings.Join(parts, "；"),
					"将该设备的 DNS 指向旁路由（或主路由 DHCP 下发旁路由 DNS），或在 设置→DNS 开启「阻止客户端绕过 DNS」")
			}
		}
	}

	type reachRes struct {
		ok bool
		v  any
	}
	res := map[string]reachRes{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	reach := func(url string, useProxy bool) (bool, any) {
		st := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
		if err != nil {
			return false, firstN(err.Error(), 100)
		}
		req.Header.Set("User-Agent", "curl/8")
		resp, err := proxyOpener(useProxy).Do(req)
		if err != nil {
			return false, firstN(err.Error(), 100)
		}
		_ = resp.Body.Close()
		return true, int(time.Since(st).Milliseconds())
	}
	for _, a := range [][3]any{
		{"direct", "https://www.baidu.com", false},
		{"cn", "https://www.baidu.com", true},
		{"proxy", "https://www.gstatic.com/generate_204", true},
	} {
		wg.Add(1)
		go func(k, url string, p bool) {
			defer wg.Done()
			ok, v := reach(url, p)
			mu.Lock()
			res[k] = reachRes{ok, v}
			mu.Unlock()
		}(a[0].(string), a[1].(string), a[2].(bool))
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(40 * time.Second):
	}
	for _, e := range [][3]string{
		{"direct", "本机直连外网", "检查旁路由的网关 / DNS 设置（应指向主路由）"},
		{"cn", "经代理访问国内", "核心或 7890 端口异常，查看日志"},
		{"proxy", "经代理访问国外", "当前节点不可用：去「节点」测速并切换，或更新订阅"},
	} {
		r, found := res[e[0]]
		if !found {
			r = reachRes{false, "超时"}
		}
		if r.ok {
			ms, _ := r.v.(int)
			item(e[1], true, fmt.Sprintf("%d ms（完整请求：DNS + TCP + TLS + 首包，比概览的复用连接延迟高）", ms), "")
		} else {
			item(e[1], false, strOf(r.v), e[2])
		}
	}

	var stfs syscall.Statfs_t
	if err := syscall.Statfs(base.ConfDir, &stfs); err == nil {
		free := float64(stfs.Bavail) * float64(stfs.Bsize) / (1 << 20)
		var ok any = true
		if free <= 20 {
			ok = false
		} else if free <= 100 {
			ok = "warn"
		}
		item("磁盘空间", ok, fmt.Sprintf("剩余 %.0f MB", free), "清理日志（设置 → 日志清理）或扩容")
	}
	return out
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

func toList(v any) []any {
	l, _ := v.([]any)
	return l
}

func toInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	}
	return 0
}

func firstN(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

func firstNStr(ss []string, n int) []string {
	if len(ss) > n {
		return ss[:n]
	}
	return ss
}

func lastN(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[len(r)-n:])
	}
	return s
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "off"
	}
	lines := strings.Split(s, "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// pyRepr Status 字段的展示：Python 里 None → "None"，数字按原样
func pyRepr(v any) string {
	if v == nil {
		return "None"
	}
	switch x := v.(type) {
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprint(x)
	case string:
		return x
	default:
		return fmt.Sprint(v)
	}
}
