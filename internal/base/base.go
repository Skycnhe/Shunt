// Package base 对应 Python shunt/base.py：基础常量、环境路径、进程内共享状态与通用工具。
package base

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ---------- 进程内共享状态 ----------

var wdHoldState = struct {
	sync.Mutex
	until float64
	why   string
}{}

// WdHold 对应 wd_hold(sec, why, reset)：reset=true 直接改成从现在起 sec 秒
func WdHold(sec float64, why string, reset bool) {
	wdHoldState.Lock()
	defer wdHoldState.Unlock()
	t := float64(time.Now().UnixNano())/1e9 + sec
	if reset || t > wdHoldState.until {
		wdHoldState.until = t
	}
	wdHoldState.why = why
}

// WdHoldState 返回看门狗暂停状态（until, why）
func WdHoldState() (float64, string) {
	wdHoldState.Lock()
	defer wdHoldState.Unlock()
	return wdHoldState.until, wdHoldState.why
}

var updState = struct {
	sync.Mutex
	busy bool
}{}

// CoreUpd 内核更新状态：coreupdate 与 notify 共用
var CoreUpd = struct {
	sync.Mutex
	Busy    bool
	Stage   string
	Pct     int
	Ok      *bool
	Message string
	Log     []string
	T       int64
}{}

// UpdBegin 面板更新 / 内核更新互斥。kind="panel" 置面板忙标志，其余置 CoreUpd。
func UpdBegin(kind string) bool {
	updState.Lock()
	defer updState.Unlock()
	CoreUpd.Lock()
	defer CoreUpd.Unlock()
	if updState.busy || CoreUpd.Busy {
		return false
	}
	if kind == "panel" {
		updState.busy = true
	} else {
		CoreUpd.Busy = true
	}
	return true
}

// UpdEnd 释放更新忙标志
func UpdEnd(kind string) {
	updState.Lock()
	defer updState.Unlock()
	CoreUpd.Lock()
	defer CoreUpd.Unlock()
	if kind == "panel" {
		updState.busy = false
	} else {
		CoreUpd.Busy = false
	}
}

// UpdBusyMsg 忙时的提示文案
func UpdBusyMsg() string {
	CoreUpd.Lock()
	defer CoreUpd.Unlock()
	if CoreUpd.Busy {
		return "内核正在更新或切换，请稍后再试"
	}
	return "面板正在更新，请稍后再试"
}

var massTest = struct {
	sync.Mutex
	active map[any]int64
}{active: make(map[any]int64)}

// MassBegin 登记一次全节点测速，返回凭据交给 MassEnd
func MassBegin() any {
	tok := new(int)
	now := time.Now().Unix()
	massTest.Lock()
	defer massTest.Unlock()
	massTest.active[tok] = now
	return tok
}

// MassEnd 注销一次全节点测速
func MassEnd(tok any) {
	massTest.Lock()
	defer massTest.Unlock()
	delete(massTest.active, tok)
}

// MassTesting 是否有全节点测速在进行；顺带清掉超时的登记（自愈）
func MassTesting() bool {
	now := time.Now().Unix()
	massTest.Lock()
	defer massTest.Unlock()
	for tok, t0 := range massTest.active {
		if now-t0 > MassMaxAge {
			delete(massTest.active, tok)
		}
	}
	return len(massTest.active) > 0
}

// ---------- 通用工具 ----------

// UrlHostForbidden SSRF 防护：下载类 URL 的目标主机必须解析到公网地址
func UrlHostForbidden(rawurl string, viaProxy bool) bool {
	u, err := url.Parse(rawurl)
	if err != nil {
		return true
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(u.Hostname()), "."))
	if host == "" || host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return !isGlobalIP(ip)
	}
	if viaProxy {
		return false
	}
	addrs, err := net.LookupIP(host)
	if err != nil {
		return true
	}
	for _, ip := range addrs {
		if !isGlobalIP(ip) && !inFakeNets(ip) {
			return true
		}
	}
	return false
}

// isGlobalIP 对应 Python ipaddress 的 is_global：回环/链路本地/组播/未指定/私网/198.18.0.0/15 基准测试网段都不是 global
func isGlobalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return false
	}
	_, bench, _ := net.ParseCIDR("198.18.0.0/15")
	if bench.Contains(ip) {
		return false
	}
	return ip.IsGlobalUnicast()
}

func inFakeNets(ip net.IP) bool {
	for _, n := range FakeIPNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// DlCheck 下载入口统一校验：目标非公网地址时返回 error
func DlCheck(rawurl string, viaProxy bool) error {
	if UrlHostForbidden(rawurl, viaProxy) {
		u, _ := url.Parse(rawurl)
		h := ""
		if u != nil {
			h = u.Hostname()
		}
		return fmt.Errorf("目标地址非公网，已拦截（SSRF 防护）：%s", h)
	}
	return nil
}

var noProxyClient = &http.Client{
	Transport: &http.Transport{Proxy: nil},
	Timeout:   30 * time.Second,
}

// UdpDNSQuery 向本机 DNS 端口发一个 A 记录查询；收到同 ID 的应答即视为成功
func UdpDNSQuery(name string, port int, host string, timeoutSec int) bool {
	if port == 0 {
		port = 1053
	}
	if host == "" {
		host = "127.0.0.1"
	}
	var qid [2]byte
	if _, err := randRead(qid[:]); err != nil {
		return false
	}
	pkt := append([]byte{}, qid[0], qid[1], 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, lab := range strings.Split(strings.Trim(name, "."), ".") {
		if lab == "" {
			continue
		}
		pkt = append(pkt, byte(len(lab)))
		pkt = append(pkt, lab...)
	}
	pkt = append(pkt, 0x00, 0x00, 0x01, 0x00, 0x01)
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(host), Port: port})
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
	if _, err := conn.Write(pkt); err != nil {
		return false
	}
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return false
		}
		if n >= 12 && buf[0] == qid[0] && buf[1] == qid[1] && buf[2]&0x80 != 0 {
			return true
		}
	}
}

func randRead(b []byte) (int, error) {
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.Read(b)
}

const (
	PanelVersion = "10.2.7"
	Schema       = 9
	MaxBody      = 32 * 1024 * 1024 // 请求体上限 32MB（备份恢复可能较大）

	CtrlHost = "127.0.0.1"
	CtrlPort = 9090
	Mixed    = 7890

	// 组名
	GSel    = "🚀 节点选择"
	GYt     = "📹 YouTube"
	GGg     = "🔍 Google"
	GTg     = "📲 Telegram"
	GFinal  = "🐟 漏网之鱼"
	GAi     = "🤖 AI 服务"
	GNf     = "🎬 Netflix"
	GManual = "🖐️ 手动选择"
	GDirect = "🏠 直连"
	GGlobal = "⚡ 全局自动选择"
	GAuto   = "⚡ 全局自动选择"

	LbPrefix = "⚖️ "
	AutoTail = "竞技"
	LbTail   = "负载均衡"

	AutoTailOld = "自动优选"    // v6–v6.7.2 的地区组后缀，仅用于迁移
	LegacyAuto  = "♻️ 自动选择" // v5 及以前的名称，读取旧数据时自动迁移

	LbSuffix   = "均衡" // 旧版（v5）地区组后缀，仅用于迁移
	AutoSuffix = "自动" // 旧版（v5）地区组后缀，仅用于迁移

	GOther = "🌐 其他"

	Hc       = "https://www.gstatic.com/generate_204"
	DirectHc = "https://www.baidu.com"
	Ua       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
	CnEcs    = "223.5.5.0/24"
	LanIn    = "IN-TYPE,TPROXY/TUN/REDIR"

	PrimaryRegions = 5
	MassMaxAge     = 300 // 单次测速登记超过 5 分钟视为失效
)

var (
	// 部署相关路径（环境变量可覆盖；测试可直接改写这些 var）
	Base     = baseDir()
	ConfDir  = envOr("MIHOMO_DIR", "/etc/mihomo")
	DataFile = envOr("PANEL_DATA", "/etc/mihomo-panel/data.json")

	PanelDir   = filepath.Dir(DataFile)
	StatsFile  = filepath.Join(PanelDir, "stats.json")
	NotifyFile = filepath.Join(PanelDir, "notify.json")
	CertFile   = filepath.Join(PanelDir, "cert.pem")
	KeyFile    = filepath.Join(PanelDir, "key.pem")

	Port      = envInt("PANEL_PORT", 8080)
	MihomoBin = envOr("MIHOMO_BIN", "/usr/local/bin/mihomo")
	SmartBin  = envOr("SMART_BIN", "/usr/local/bin/mihomo-smart")
	TproxySh  = envOr("PANEL_TPROXY", filepath.Join(Base, "tproxy.sh"))

	Ctrl = fmt.Sprintf("http://%s:%d", CtrlHost, CtrlPort)

	WdInterval = envInt("PANEL_WD_INTERVAL", 30) // 看门狗检查间隔（秒）

	CoreSvc  = coreSvcName()
	PanelSvc = panelSvcName()
	Svc      = envOr("PANEL_SVC", "rc-service "+coreSvcName()) // 核心服务控制命令（测试环境可覆盖）

	LogFiles  = logFiles()
	MihomoLog = firstLog()

	AbDir       = filepath.Join(ConfDir, "adblock")
	AbStatsFile = filepath.Join(PanelDir, "adblock_stats.json")

	LgbmURL = envOr("SMART_REPO", "https://github.com/vernesong/mihomo/releases") + "/download/LightGBM-Model/Model.bin"
)

var (
	ProxyModes   = []string{"tproxy", "tun", "off"}
	TunStacks    = []string{"system", "gvisor", "mixed"}
	GroupTypes   = []string{"select", "url-test", "fallback", "load-balance"}
	LbStrategies = []string{"consistent-hashing"} // v6.7.1 起负载均衡只保留一致性哈希

	SideGroups = []string{GYt, GGg, GTg, GAi, GNf, GFinal}
	AutoOrder  = []string{"日本", "新加坡", "香港", "美国"} // 「自动优选」组在节点选择中的顺序
	LbOrder    = []string{"香港", "日本", "新加坡", "美国"} // 「负载均衡」组的顺序

	DefaultExclude = "剩余|到期|官网|流量|过期|Expire|Traffic"

	// 客户端绕过 DNS 时的常见公共 DoH / DoT 服务器 IP
	DohIPs = []string{
		"1.1.1.1/32", "1.0.0.1/32", "8.8.8.8/32", "8.8.4.4/32", "9.9.9.9/32", "149.112.112.112/32",
		"208.67.222.222/32", "208.67.220.220/32", "94.140.14.14/32", "94.140.15.15/32", "101.101.101.101/32",
		"185.222.222.222/32", "45.11.45.11/32", "223.5.5.5/32", "223.6.6.6/32", "119.29.29.29/32",
		"1.12.12.12/32", "120.53.53.53/32", "180.76.76.76/32", "180.184.1.1/32", "180.184.2.2/32",
		"2606:4700:4700::1111/128", "2606:4700:4700::1001/128", "2001:4860:4860::8888/128",
		"2001:4860:4860::8844/128", "2620:fe::fe/128", "2400:3200::1/128", "2400:3200:baba::1/128",
		"2402:4e00::/128",
	}
	DohDomains = []string{
		"+.dns.google", "+.cloudflare-dns.com", "+.one.one.one.one", "+.dns.quad9.net",
		"+.doh.opendns.com", "+.dns.adguard-dns.com", "+.dns.adguard.com", "+.dns.nextdns.io",
		"+.doh.pub", "+.dot.pub", "+.dns.alidns.com", "+.doh.360.cn", "+.dns.twnic.tw",
		"+.mozilla.cloudflare-dns.com", "+.chrome.cloudflare-dns.com", "+.dns.sb", "+.doh.dns.sb",
	}
)

// FakeIPNets 路由器自己用本机 DNS 时公网域名会解析成的地址（SSRF 校验放行）
var FakeIPNets = []net.IPNet{
	mustCIDR("198.18.0.0/15"),
	mustCIDR("fc00::/18"),
	mustCIDR("fdfe:dcba:9876::/64"),
}

func mustCIDR(s string) net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return *n
}

// CnDNS 国内 DNS 服务器特征（泄露检测用）
var CnDNS = regexp.MustCompile(`(?i)(?:^|[/@\[])(?:223\.5\.5\.5|223\.6\.6\.6|2400:3200|119\.29\.29\.29|119\.28\.28\.28|182\.254\.11[68]\.116|1\.12\.12\.12|120\.53\.53\.53|2402:4e00|114\.114\.11[45]\.11[45]|180\.76\.76\.76|180\.184\.[12]\.[12]|101\.226\.4\.6|218\.30\.118\.6|117\.50\.\d+\.\d+|52\.80\.\d+\.\d+|[\w.-]*(?:alidns\.com|doh\.pub|dot\.pub|dnspod\.(?:cn|com)|360\.cn|114dns\.com|onedns\.net|baidu\.com|volces\.com))(?:[:/#\]]|$)`)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return def
}

func baseDir() string {
	if v := os.Getenv("PANEL_BASE"); v != "" {
		return v
	}
	exe, err := os.Executable()
	if err != nil {
		return "/opt/mihomo-panel"
	}
	return filepath.Dir(exe)
}

func coreSvcName() string {
	if _, err := os.Stat("/etc/init.d/shunt-core"); err == nil {
		return "shunt-core"
	}
	return "mihomo"
}

func panelSvcName() string {
	if _, err := os.Stat("/etc/init.d/shunt"); err == nil {
		return "shunt"
	}
	return "mihomo-panel"
}

func logFiles() []string {
	var out []string
	for _, x := range strings.Split(envOr("PANEL_LOGS", "/var/log/mihomo.log,/var/log/mihomo-panel.log"), ",") {
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

func firstLog() string {
	if len(LogFiles) > 0 {
		return LogFiles[0]
	}
	return "/var/log/mihomo.log"
}

// LocalFile 部署文件 f 的本地路径（init.d/ 下的优先用 /etc/init.d/ 的系统版本）
func LocalFile(f string) string {
	if strings.HasPrefix(f, "init.d/") {
		sysf := "/etc/init.d/" + f[7:]
		if Base == "/opt/mihomo-panel" {
			if _, err := os.Stat(sysf); err == nil {
				return sysf
			}
		}
		return filepath.Join(Base, f)
	}
	return filepath.Join(Base, f)
}
