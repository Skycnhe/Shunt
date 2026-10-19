// Package dnsleak 对应 Python shunt/dnsleak.py：DNS 防泄露。
// 一键防泄露设置（antileak_dns）、域名上游路由估算（dns_route）、
// 配置检查 + bash.ws 在线泄露检测（leak_check）。
package dnsleak

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"shunt/internal/base"
	"shunt/internal/corehttp"
	"shunt/internal/data"
	"shunt/internal/mihomo"
	"shunt/internal/notify"
	"shunt/internal/ruleutil"
	"shunt/internal/sysopt"
	"shunt/internal/unlock"
)

// mihomo.DnsCfg 接线：data.json 的 dns 设置补齐默认值并规范化
func dnsCfg(d map[string]any) map[string]any { return mihomo.DnsCfg(d) }

// mihomo.PolicyParts 接线：返回 (类型, [名称])，类型为 geosite / rule-set / domain
func policyParts(m string) (string, []string) { return mihomo.PolicyParts(m) }

// corehttp.Core 接线
func coreReq(method, path string, timeoutSec int) (int, []byte) {
	return corehttp.Core(method, path, nil, timeoutSec)
}

// sysopt.Sh 接线，返回 (exitCode, stdout+stderr)
func sh(cmd string, timeoutSec int) (int, string) { return sysopt.Sh(cmd, timeoutSec) }

// notify.CoreAlive 接线
func coreAlive() bool { return notify.CoreAlive() }

var (
	cnGeoRx    = regexp.MustCompile(`(?i)^(?:cn|private|.*@cn|.*-cn|tld-cn|geolocation-cn)$`)
	cnDomainRx = regexp.MustCompile(`(?i)^[+*.]*[\w.\-]*\.(?:cn|lan|local|arpa|home|localdomain)$`)
	leakIDRx   = regexp.MustCompile(`^[a-z0-9]{6,40}$`)
	inet6Rx    = regexp.MustCompile(`inet6 [23]`)
)

func resolvPath() string {
	if p := os.Getenv("PANEL_RESOLV"); p != "" {
		return p
	}
	return "/etc/resolv.conf"
}

// IsCnDNS 是否国内 / 本机 DNS（泄露检测用）
func IsCnDNS(x string) bool {
	if i := strings.Index(x, "#"); i >= 0 {
		x = x[:i]
	}
	return base.CnDNS.MatchString(x) || strings.HasPrefix(x, "system") || strings.HasPrefix(x, "dhcp://")
}

// AntileakDNS 一键防泄露：fake-ip + respect-rules + 默认上游走代理 DNS + 国内域名走直连 DNS + 阻止客户端绕过
func AntileakDNS(cur map[string]any) map[string]any {
	dc := deepCopyMap(cur)
	dc["mode"] = "fake-ip"
	dc["respect_rules"] = true
	dc["policy"] = true
	dc["block_bypass"] = true
	direct := []string{}
	for _, x := range strsOf(dc["direct"]) {
		if !strings.Contains(x, "#") {
			direct = append(direct, x)
		}
	}
	if len(direct) == 0 {
		direct = append([]string{}, strsOf(base.DNSDefault["direct"])...)
	}
	dc["direct"] = direct
	proxy := []string{}
	for _, x := range strsOf(dc["proxy"]) {
		if IsCnDNS(x) || strings.HasPrefix(x, "rcode://") {
			continue // 国内 / 本机 DNS 不能作为代理 DNS
		}
		if ruleutil.DnsPolicyOf(x) == "" {
			if i := strings.Index(x, "#"); i >= 0 {
				x = x[:i]
			}
			x = x + "#" + base.GSel
		}
		proxy = append(proxy, x)
	}
	if len(proxy) == 0 {
		proxy = append([]string{}, strsOf(base.DNSDefault["proxy"])...)
	}
	dc["proxy"] = proxy
	pserver := []string{}
	for _, x := range strsOf(dc["pserver"]) {
		if !strings.Contains(x, "#") && IsCnDNS(x) {
			pserver = append(pserver, x)
		}
	}
	dc["pserver"] = pserver
	if len(strsOf(dc["fake_filter"])) == 0 {
		dc["fake_filter"] = append([]string{}, base.DefaultFakeFilter...)
	}
	policies := []any{}
	for _, pe := range listOf(dc["policies"]) {
		if pem, ok := pe.(map[string]any); ok && !LeakyPolicy(pem) {
			policies = append(policies, pe)
		}
	}
	dc["policies"] = policies
	return dc
}

// LeakyPolicy 自定义 nameserver-policy 把非国内域名交给国内 DNS
func LeakyPolicy(pe map[string]any) bool {
	kind, parts := policyParts(data.Str(pe, "match"))
	if kind == "rule-set" {
		return false
	}
	allCn := true
	for _, p := range parts {
		rx := cnDomainRx
		if kind == "geosite" {
			rx = cnGeoRx
		}
		if !rx.MatchString(p) {
			allCn = false
			break
		}
	}
	if allCn {
		return false
	}
	servers := strsOf(pe["servers"])
	hasCn := false
	for _, x := range servers {
		if IsCnDNS(x) {
			hasCn = true
			break
		}
	}
	if !hasCn {
		return false
	}
	for _, x := range servers {
		if !strings.HasPrefix(x, "rcode://") {
			return true
		}
	}
	return false
}

// HostMatch hosts / 策略域名匹配（+. / . / * 通配）
func HostMatch(pattern, name string) bool {
	pattern = strings.ToLower(pattern)
	switch {
	case strings.HasPrefix(pattern, "+."):
		return name == pattern[2:] || strings.HasSuffix(name, pattern[1:])
	case strings.HasPrefix(pattern, "."):
		return strings.HasSuffix(name, pattern)
	case strings.Contains(pattern, "*"):
		rx, err := regexp.Compile(`^(?:` + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, `[^.]+`) + `)$`)
		if err != nil {
			return false
		}
		return rx.MatchString(name)
	default:
		return name == pattern
	}
}

// DnsRoute 估算一个域名由哪组上游解析（GEOSITE 需要核心数据库，这里按规则顺序给出说明）
func DnsRoute(name string, d map[string]any) string {
	dc := dnsCfg(d)
	short := func(xs []string) string {
		var parts []string
		for _, x := range xs {
			if len(parts) >= 2 {
				break
			}
			x = strings.ReplaceAll(x, "https://", "")
			x = strings.ReplaceAll(x, "/dns-query", "")
			parts = append(parts, x)
		}
		s := strings.Join(parts, "、")
		if len(xs) > 2 {
			s += " 等"
		}
		return s
	}
	for _, h := range listOf(dc["hosts"]) {
		hm, ok := h.(map[string]any)
		if !ok {
			continue
		}
		domain := data.Str(hm, "domain")
		if HostMatch(domain, name) {
			return fmt.Sprintf("hosts 静态记录（%s → %s，不查询上游）",
				domain, strings.Join(firstNStrs(strsOf(hm["value"]), 3), ", "))
		}
	}
	for _, pe := range listOf(dc["policies"]) {
		pem, ok := pe.(map[string]any)
		if !ok {
			continue
		}
		kind, parts := policyParts(data.Str(pem, "match"))
		if kind == "domain" {
			for _, part := range parts {
				if HostMatch(part, name) {
					return fmt.Sprintf("自定义策略 %s → %s", part, short(strsOf(pem["servers"])))
				}
			}
		}
	}
	var geo []string
	for _, pe := range listOf(dc["policies"]) {
		pem, ok := pe.(map[string]any)
		if !ok {
			continue
		}
		if kind, _ := policyParts(data.Str(pem, "match")); kind != "domain" {
			geo = append(geo, data.Str(pem, "match"))
		}
	}
	head := ""
	if len(geo) > 0 {
		head = "先匹配自定义 " + strings.Join(firstNStrs(geo, 3), "、") + "；"
	}
	proxy := strsOf(dc["proxy"])
	if len(proxy) == 0 {
		return head + fmt.Sprintf("全部走直连 DNS（%s）——未设置代理 DNS，国外域名会泄露", short(strsOf(dc["direct"])))
	}
	if toBool(dc["policy"]) {
		return head + fmt.Sprintf("属于 geosite:cn / private → 直连 DNS（%s）；其他域名 → 代理 DNS（%s）",
			short(strsOf(dc["direct"])), short(proxy))
	}
	return head + fmt.Sprintf("全部走代理 DNS（%s）", short(proxy))
}

// DnsProbeIP 向 mihomo DNS 端口查询 A 记录，返回 (rcode, [IP])
func DnsProbeIP(name string, server ...string) (int, []string, error) {
	addr := "127.0.0.1:1053"
	if len(server) > 0 && server[0] != "" {
		addr = server[0]
	}
	var qid [2]byte
	if _, err := rand.Read(qid[:]); err != nil {
		return 0, nil, err
	}
	var pkt []byte
	pkt = append(pkt, qid[0], qid[1], 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, x := range strings.Split(name, ".") {
		pkt = append(pkt, byte(len(x)))
		pkt = append(pkt, x...)
	}
	pkt = append(pkt, 0x00, 0x00, 0x01, 0x00, 0x01)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := conn.Write(pkt); err != nil {
		return 0, nil, err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, nil, err
	}
	data := buf[:n]
	rcode := int(data[3] & 0x0F)
	an := int(binary.BigEndian.Uint16(data[6:8]))
	i := 12
	for data[i] != 0 { // 跳过问题部分
		i += int(data[i]) + 1
	}
	i += 5
	var ips []string
	for k := 0; k < an; k++ {
		if data[i]&0xC0 == 0xC0 {
			i += 2
		} else {
			for data[i] != 0 {
				i += int(data[i]) + 1
			}
			i++
		}
		typ := int(binary.BigEndian.Uint16(data[i : i+2]))
		rdlen := int(binary.BigEndian.Uint16(data[i+8 : i+10]))
		i += 10
		if typ == 1 && rdlen == 4 {
			ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", data[i], data[i+1], data[i+2], data[i+3]))
		}
		i += rdlen
	}
	return rcode, ips, nil
}

// ResolvServers /etc/resolv.conf 里的 nameserver
func ResolvServers() []string {
	raw, err := os.ReadFile(resolvPath())
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(raw), "\n") {
		p := strings.Fields(l)
		if len(p) > 1 && strings.HasPrefix(strings.TrimSpace(l), "nameserver") {
			out = append(out, p[1])
		}
	}
	return out
}

// LeakEntry bash.ws 记录的一条解析器 / 出口
type LeakEntry struct {
	IP          string `json:"ip"`
	Country     string `json:"country"`
	CountryName string `json:"country_name"`
	Org         string `json:"org"`
	CN          bool   `json:"cn,omitempty"`
}

// LeakLiveResult 在线泄露检测结果
type LeakLiveResult struct {
	OK        *bool       `json:"ok"`
	Resolvers []LeakEntry `json:"resolvers"`
	Egress    []LeakEntry `json:"egress"`
	Error     string      `json:"error"`
	Source    string      `json:"source"`
}

// LeakLive 经代理访问 bash.ws 的 DNS 泄露测试：用 mihomo 的解析器（/dns/query，与客户端走同样的上游分流）
// 解析一组随机子域名，再读取 bash.ws 记录到的递归解析器 IP / 国家
func LeakLive() LeakLiveResult {
	out := LeakLiveResult{Source: "bash.ws"}
	if err := leakLiveInto(&out); err != nil {
		msg := firstN(err.Error(), 160)
		if msg == "" {
			msg = "error"
		}
		out.Error = "在线检测失败：" + msg
	}
	return out
}

func leakLiveInto(out *LeakLiveResult) error {
	code, _, tid := unlock.Fetch("https://bash.ws/id", 10, nil)
	tid = strings.TrimSpace(tid)
	if code != 200 || !leakIDRx.MatchString(tid) {
		return fmt.Errorf("获取测试 ID 失败（HTTP %d）", code)
	}
	var wg sync.WaitGroup
	for i := 1; i <= 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { _ = recover() }()
			coreReq("GET", fmt.Sprintf("/dns/query?name=%d.%s.bash.ws&type=A", i, tid), 10)
		}(i)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(100 * time.Second):
	}
	time.Sleep(time.Second)
	_, _, body := unlock.Fetch("https://bash.ws/dnsleak/test/"+tid+"?json", 15, nil)
	var items []map[string]any
	if err := json.Unmarshal([]byte(body), &items); err != nil {
		return err
	}
	for _, x := range items {
		e := LeakEntry{
			IP:          strOf(x["ip"]),
			Country:     strings.ToUpper(strOf(x["country"])),
			CountryName: strOf(x["country_name"]),
			Org:         firstNonEmpty(strOf(x["asn"]), strOf(x["org"])),
		}
		switch strOf(x["type"]) {
		case "dns":
			e.CN = e.Country == "CN"
			out.Resolvers = append(out.Resolvers, e)
		case "ip":
			out.Egress = append(out.Egress, e)
		}
	}
	if len(out.Resolvers) == 0 {
		out.Error = "bash.ws 没有记录到解析请求（代理 DNS 可能不可用）"
		return nil
	}
	ok := true
	for _, r := range out.Resolvers {
		if r.CN {
			ok = false
			break
		}
	}
	out.OK = &ok
	return nil
}

// LeakItem 检测项
type LeakItem struct {
	Name   string `json:"name"`
	OK     any    `json:"ok"` // true / false / "warn"
	Detail string `json:"detail"`
	Fix    string `json:"fix"`
}

// LeakCheck DNS 泄露检测；live=true 且核心运行时做在线检测
func LeakCheck(live bool) map[string]any {
	d := data.Load()
	dc := dnsCfg(d)
	var items []LeakItem
	item := func(name string, ok any, detail, fix string) {
		f := fix
		if ok == true {
			f = ""
		}
		items = append(items, LeakItem{Name: name, OK: ok, Detail: detail, Fix: f})
	}

	if data.Str(dc, "mode") == "fake-ip" {
		item("增强模式", true, "fake-ip：客户端只拿到 198.18.x.x，域名由 mihomo 按规则处理", "")
	} else {
		item("增强模式", "warn", "redir-host：客户端拿到真实 IP，可能绕过按域名分流", "改用 fake-ip")
	}
	proxy, direct := strsOf(dc["proxy"]), strsOf(dc["direct"])
	ns := proxy
	if len(ns) == 0 {
		ns = direct
	}
	var badNs []string
	for _, x := range ns {
		if IsCnDNS(x) {
			badNs = append(badNs, x)
		}
	}
	var unrouted []string
	for _, x := range proxy {
		if ruleutil.DnsPolicyOf(x) == "" && !toBool(dc["respect_rules"]) {
			unrouted = append(unrouted, x)
		}
	}
	switch {
	case len(proxy) == 0:
		item("默认上游（未知 / 国外域名）", false,
			"未设置代理 DNS，所有域名都发给直连 DNS："+strings.Join(firstNStrs(direct, 2), "、"),
			"添加代理 DNS，如 https://1.1.1.1/dns-query#🚀 节点选择")
	case len(badNs) > 0:
		item("默认上游（未知 / 国外域名）", false,
			"代理 DNS 里有国内 / 本机解析器："+strings.Join(firstNStrs(badNs, 3), "、"),
			"从代理 DNS 中删除它们，国内 DNS 只放在直连 DNS")
	case len(unrouted) > 0:
		item("默认上游（未知 / 国外域名）", "warn",
			"这些代理 DNS 没有指定 #策略组，且未开启 respect-rules，会直连发出："+strings.Join(firstNStrs(unrouted, 2), "、"),
			"开启 respect-rules，或在地址后加 #🚀 节点选择")
	default:
		item("默认上游（未知 / 国外域名）", true,
			"代理 DNS 经节点查询："+strings.Join(firstNStrs(proxy, 2), "、"), "")
	}
	if toBool(dc["policy"]) {
		item("国内域名分流", true,
			"geosite:cn / private → 直连 DNS，其余全部走代理 DNS（不再按 geolocation-!cn 白名单，未知域名也不会发给国内 DNS）", "")
	} else {
		item("国内域名分流", "warn",
			"国内域名也走代理 DNS：不泄露，但国内 CDN 解析可能不是最近节点", "开启「国内域名走直连 DNS」")
	}
	if toBool(dc["respect_rules"]) {
		item("respect-rules", true,
			"DNS 查询连接遵循分流规则，节点域名用国内 DoH 解析（proxy-server-nameserver）", "")
	} else {
		item("respect-rules", "warn", "未开启", "开启 respect-rules")
	}
	item("fallback / 系统 hosts", true,
		"未使用 fallback（避免同时向国内外 DNS 发同一查询）；use-system-hosts 已关闭；prefer-h3 已关闭", "")
	var lp []string
	for _, pe := range listOf(dc["policies"]) {
		if pem, ok := pe.(map[string]any); ok && LeakyPolicy(pem) {
			lp = append(lp, data.Str(pem, "match"))
		}
	}
	if len(lp) > 0 {
		item("自定义 DNS 策略", false,
			"以下非国内域名被交给国内 DNS："+strings.Join(firstNStrs(lp, 3), "、"), "改为代理 DNS，或删除这些策略")
	}
	if toBool(dc["block_bypass"]) {
		item("阻止客户端绕过 DNS", true, "已拒绝局域网设备的 DoT / DoQ（853）与常见公共 DoH 服务器", "")
	} else {
		item("阻止客户端绕过 DNS", "warn",
			"未开启：浏览器 / 手机的“安全 DNS”、私人 DNS 可能直连国内 DoH，绕过 mihomo", "开启「阻止客户端绕过 DNS」")
	}
	mode := data.Str(d, "proxy_mode")
	if mode == "off" {
		item("DNS 劫持", "warn", "透明代理已关闭，客户端 DNS 不经过 mihomo", "在设置里选择 TProxy 或 TUN，并把客户端 DNS 设为旁路由")
	} else {
		_, st := sh(base.TproxySh+" status", 10)
		st = lastLine(st)
		okh := st == "tproxy" || st == "dns" || mode == "tun"
		detail := "未检测到 53 → 1053 重定向规则"
		if okh {
			if mode == "tun" {
				detail = "TUN dns-hijack any:53"
			} else {
				detail = "发往旁路由 53 端口的查询重定向到 1053"
			}
		}
		item("DNS 劫持", okh, detail, "执行 /opt/mihomo-panel/tproxy.sh apply")
	}
	_, ip6out := sh("ip -o -6 addr show scope global 2>/dev/null", 10)
	has6 := inet6Rx.MatchString(ip6out)
	if !data.Bool(d, "ipv6") {
		if has6 {
			item("IPv6", "warn",
				"本机有公网 IPv6，但 IPv6 透明代理未开启：客户端可能通过主路由下发的 IPv6 DNS（RDNSS）绕过",
				"在主路由关闭 IPv6 DNS 下发 / DHCPv6，或开启 IPv6 透明代理")
		} else {
			item("IPv6", true, "未开启 IPv6，mihomo DNS 不返回 AAAA，与透明代理一致", "")
		}
	} else {
		item("IPv6", true, "IPv6 透明代理已开启，DNS 同时处理 AAAA", "")
	}
	sniffer := true
	if v, ok := d["sniffer"]; ok {
		sniffer, _ = v.(bool)
	}
	if sniffer {
		item("域名嗅探", true, "已开启：按 IP 发起的连接也能识别域名分流", "")
	} else {
		item("域名嗅探", "warn", "未开启：Fake-IP 过滤的域名、直接按 IP 的连接无法按域名分流", "设置 → 核心服务 → 开启域名嗅探")
	}
	if rs := ResolvServers(); len(rs) > 0 {
		item("旁路由本机解析", true,
			"/etc/resolv.conf："+strings.Join(firstNStrs(rs, 3), "、")+"。面板自身的外网请求经 mihomo 代理（远端解析），规则测试改用 mihomo DNS，本机只解析国内 / 直连目标", "")
	} else {
		item("旁路由本机解析", "warn", "/etc/resolv.conf 没有 nameserver",
			"把 /etc/resolv.conf 指向主路由或国内 DNS（如 223.5.5.5）")
	}

	out := map[string]any{"items": items, "live": nil, "fakeip": nil}
	if live && coreAlive() {
		rc, ips, err := DnsProbeIP("www.google.com")
		if err != nil {
			item("客户端查询测试", false, "向 127.0.0.1:1053 查询失败："+err.Error(), "确认核心 DNS 已监听 1053")
		} else {
			fake := len(ips) > 0 && allInFakeNet(ips)
			out["fakeip"] = map[string]any{"name": "www.google.com", "ips": ips, "rcode": rc, "fake": fake}
			if data.Str(dc, "mode") == "fake-ip" {
				joined := strings.Join(ips, ", ")
				if joined == "" {
					joined = "无记录"
				}
				detail := "www.google.com → " + joined
				if fake {
					detail += "（Fake-IP，客户端查询不触发上游解析）"
				}
				var ok any = "warn"
				if fake {
					ok = true
				}
				item("客户端查询测试", ok, detail, "检查 Fake-IP 过滤列表是否包含该域名")
			}
		}
		lv := LeakLive()
		out["live"] = lv
		switch {
		case lv.OK != nil && *lv.OK:
			var parts []string
			for _, r := range firstNLeak(lv.Resolvers, 4) {
				country := r.Country
				if country == "" {
					country = "?"
				}
				parts = append(parts, fmt.Sprintf("%s（%s %s）", r.IP, country, firstN(r.Org, 30)))
			}
			item("在线泄露检测", true, "上游解析器："+strings.Join(parts, "、"), "")
		case lv.OK != nil:
			var cn []LeakEntry
			for _, r := range lv.Resolvers {
				if r.CN {
					cn = append(cn, r)
				}
			}
			var shown []string
			for _, r := range firstNLeak(cn, 4) {
				shown = append(shown, fmt.Sprintf("%s（%s）", r.IP, firstN(r.Org, 30)))
			}
			item("在线泄露检测", false, "发现国内解析器："+strings.Join(shown, "、"), "点击「一键应用防泄露设置」")
		default:
			item("在线泄露检测", "warn", lv.Error, "确认节点可用后重试；离线时以上配置检查仍然有效")
		}
	} else if live {
		item("在线泄露检测", "warn", "核心未运行，只做了配置检查", "启动核心后重试")
	}
	bad, warn := 0, 0
	for _, x := range items {
		if x.OK == false {
			bad++
		} else if x.OK == "warn" {
			warn++
		}
	}
	out["bad"] = bad
	out["warn"] = warn
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

func listOf(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out
	}
	return nil
}

func strsOf(v any) []string {
	switch x := v.(type) {
	case []string:
		return append([]string{}, x...)
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func toBool(v any) bool {
	b, _ := v.(bool)
	return b
}

func firstNStrs(ss []string, n int) []string {
	if len(ss) > n {
		return ss[:n]
	}
	return ss
}

func firstNLeak(es []LeakEntry, n int) []LeakEntry {
	if len(es) > n {
		return es[:n]
	}
	return es
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func firstN(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
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

func allInFakeNet(ips []string) bool {
	_, n, _ := net.ParseCIDR("198.18.0.0/15")
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil || !n.Contains(ip) {
			return false
		}
	}
	return true
}

func deepCopyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = deepCopyVal(v)
	}
	return out
}

func deepCopyVal(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return deepCopyMap(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = deepCopyVal(e)
		}
		return out
	default:
		return v
	}
}
