// Package ipinfo 对应 Python shunt/ipinfo.py：公网 IP 与归属地查询（概览页展示）。
// 代理出口经核心 mixed 端口查；本地公网先经代理取国内服务（规则直连中国网站时拿到真实 IP，
// 自带中文归属地），拿不到或与出口相同时改为绕过核心直连查询。两边并行。
package ipinfo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"shunt/internal/base"
	"shunt/internal/corehttp"
	"shunt/internal/errlog"
)

// corehttp.Core 接线
func coreReq(method, path string, timeoutSec int) (int, []byte) {
	return corehttp.Core(method, path, nil, timeoutSec)
}

// errlog.LogErr 接线
func logErr(where string, err error) { errlog.LogErr(where, err, false) }

// proxyOpener 本地实现（对应 sysopt.proxy_opener / ProxyClient）：
// 经 mixed 端口或直连的 http.Client。重定向沿用 SafeRedirectHandler 语义：
// 目标为非公网地址时拦截；走代理时跳过本地 DNS 校验（由代理自己解析），字面内网 IP 仍拦截。
// 不直接调用 sysopt.ProxyClient：sysopt → ipinfo（Reset / PhysIface）已存在，import 会循环。
func proxyOpener(viaProxy ...bool) *http.Client {
	p := true
	if len(viaProxy) > 0 {
		p = viaProxy[0]
	}
	tr := &http.Transport{Proxy: nil}
	if p {
		px, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", base.Mixed))
		tr.Proxy = http.ProxyURL(px)
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if base.UrlHostForbidden(req.URL.String(), p) {
				return fmt.Errorf("redirect to non-public address blocked: %s", req.URL.Host)
			}
			return nil
		},
	}
}

// sh 本地实现（对应 sysopt.Sh）：shell 执行 + 超时，返回 (退出码, stdout+stderr 去首尾空白)；
// 超时或异常返回 (1, 错误描述)。不直接调用 sysopt.Sh：sysopt → ipinfo 已存在，import 会循环。
func sh(cmd string, timeoutSec int) (int, string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
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
		return 1, fmt.Sprintf("Command '%s' timed out after %d seconds", cmd, timeoutSec)
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), out
	}
	return 1, err.Error()
}

// IPEcho 返回纯文本公网 IP
const IPEcho = "https://api.ipify.org"

const geoURL1 = "http://ip-api.com/json/%s?lang=zh-CN&fields=status,country,regionName,city"
const geoURL2 = "https://ipwho.is/%s?lang=zh-CN" // 备用归属地服务（HTTPS）

// cacheTTL 两边都查到才缓存 10 分钟；公网 IP 变化不频繁
const cacheTTL = 600.0

var ipCache = struct {
	sync.Mutex
	t    float64
	v    map[string]any
	fail int
	next float64
}{}

// Backoff 查询失败后的重试间隔：5、10、20、40、60、60… 秒
func Backoff(n int) int {
	return int(math.Min(60, 5*math.Pow(2, float64(max(0, n-1)))))
}

// Reset 核心重启 / 切换后作废缓存：出口可能变了，失败的结果也立刻允许重查
func Reset() {
	ipCache.Lock()
	defer ipCache.Unlock()
	ipCache.t, ipCache.v, ipCache.fail, ipCache.next = 0, nil, 0, 0
}

// CoreReady 代理出口查询的前提：核心控制接口有响应、mixed 端口能连上。
// 重启瞬间两者都不在，此时查只会白等超时
func CoreReady() bool {
	code, _ := coreReq("GET", "/version", 3)
	if code != 200 {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", "127.0.0.1:"+strconv.Itoa(base.Mixed))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func fetchURL(url string, viaProxy bool, timeoutSec int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	resp, err := proxyOpener(viaProxy).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

var (
	devRx  = regexp.MustCompile(`\bdev (\S+)`)
	linkRx = regexp.MustCompile(`^\d+: (\S+?):.*state UP`)
)

// PhysIface 导出 physIface：物理网卡名（ipinfo._phys_iface），
// 供 sysopt 的 DirectRtt 绑定网卡绕过 TUN 直连。
func PhysIface() string { return physIface() }

// physIface 物理网卡：优先默认路由的非 TUN dev；TUN 接管默认路由时，
// 退化为第一个 UP 的非 TUN/非 lo 网卡。
// TUN 模式会拦截本机全部流量，直连请求必须绑定物理网卡才能绕过 TUN 拿到真实公网 IP。
func physIface() string {
	if _, out := sh("ip -4 route show default", 5); out != "" {
		for _, line := range strings.Split(out, "\n") {
			if m := devRx.FindStringSubmatch(line); m != nil && !isTun(m[1]) {
				return m[1]
			}
		}
	}
	if _, out := sh("ip -o link show", 5); out != "" {
		for _, line := range strings.Split(out, "\n") {
			if m := linkRx.FindStringSubmatch(line); m != nil && m[1] != "lo" && !isTun(m[1]) {
				return m[1]
			}
		}
	}
	return ""
}

func isTun(dev string) bool {
	return strings.HasPrefix(dev, "tun") || strings.HasPrefix(dev, "utun") || dev == "mihomo" ||
		strings.HasPrefix(dev, "docker") || strings.HasPrefix(dev, "br-") || strings.HasPrefix(dev, "veth")
}

var cnIPRx = regexp.MustCompile(`当前 IP：([0-9.]+)\s*来自于：(.+)`)

// fetchCnIP 经代理端口取国内 IP 查询服务。若代理按规则直连中国网站，可拿到真实公网 IP；
// 响应自带中文归属地（格式：当前 IP：x.x.x.x  来自于：...），无需再查 geo。
func fetchCnIP() (string, string) {
	txt, err := fetchURL("https://myip.ipip.net", true, 10)
	if err != nil {
		logErr("出口 IP 查询 (myip.ipip.net)", err)
		return "", ""
	}
	if m := cnIPRx.FindStringSubmatch(txt); m != nil {
		return strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
	}
	return "", ""
}

var (
	traceIPRx = regexp.MustCompile(`(?m)^ip=([0-9a-fA-F:.]+)`)
	ipEchoRx  = regexp.MustCompile(`^[0-9a-fA-F:.]+$`)
)

// fetchDirectIP 直连取公网 IP：
// 1. 优先 https://1.1.1.1/cdn-cgi/trace（固定 IP 无需 DNS，不受 fake-ip 污染），绑定物理网卡绕过 TUN
// 2. 回退 api.ipify.org（DNS 可能被 fake-ip 污染）
// 3. 回退普通直连
func fetchDirectIP() string {
	if dev := physIface(); dev != "" {
		code, out := sh(fmt.Sprintf("curl -s --interface %s --max-time 10 https://1.1.1.1/cdn-cgi/trace", shellQuote(dev)), 15)
		if code == 0 {
			if m := traceIPRx.FindStringSubmatch(out); m != nil {
				return m[1]
			}
		}
		code, out = sh(fmt.Sprintf("curl -s --interface %s --max-time 10 %s", shellQuote(dev), IPEcho), 15)
		out = strings.TrimSpace(out)
		if code == 0 && ipEchoRx.MatchString(out) {
			return out
		}
	}
	// 不绑网卡、也不走代理：1.1.1.1 是字面 IP，不依赖本机 DNS（核心重启时本机 DNS 可能指向还没起来的核心）
	code, out := sh("curl -s --noproxy '*' --max-time 8 https://1.1.1.1/cdn-cgi/trace", 12)
	if code == 0 {
		if m := traceIPRx.FindStringSubmatch(out); m != nil {
			return m[1]
		}
	}
	txt, _ := fetchURL(IPEcho, false, 10)
	return txt
}

var locSuffixRx = regexp.MustCompile(`(?:省|市|自治区|特别行政区|壮族自治区|回族自治区|维吾尔自治区)$`)

// LocDedup 归属地去掉相邻重复的地名：「中国 重庆 重庆 电信」→「中国 重庆 电信」，「北京市 北京」也算重复
func LocDedup(loc string) string {
	strip := func(s string) string { return locSuffixRx.ReplaceAllString(s, "") }
	var out []string
	for _, p := range strings.Fields(loc) {
		if len(out) > 0 {
			prev := out[len(out)-1]
			sp, spp := strip(p), strip(prev)
			// 完全相同，或只差一个「市 / 省」后缀（重庆市 / 重庆）才算重复；吉林省 / 吉林市 是两级地名，保留
			if p == prev || (sp == spp && (p == sp || prev == spp)) {
				if len([]rune(p)) < len([]rune(prev)) {
					out[len(out)-1] = p // 保留更短的写法（重庆 而不是 重庆市）
				}
				continue
			}
		}
		out = append(out, p)
	}
	return strings.Join(out, " ")
}

func geoParse(txt string) string {
	var j map[string]any
	if txt == "" {
		return ""
	}
	if err := json.Unmarshal([]byte(txt), &j); err != nil {
		return ""
	}
	if j["status"] == "success" { // ip-api.com
		return joinNonEmpty(" ", strOf(j["country"]), strOf(j["regionName"]), strOf(j["city"]))
	}
	if j["success"] == true { // ipwho.is
		return joinNonEmpty(" ", strOf(j["country"]), strOf(j["region"]), strOf(j["city"]))
	}
	return ""
}

// geo 归属地：ip-api.com 直连 → 经内核 mixed 端口 → 备用 ipwho.is。
// 以前只直连 ip-api.com 一次：路由器本机 DNS 指向内核时，ip-api.com 可能被解析成 Fake-IP 而直连不通，
// 或撞上 ip-api 免费版每分钟 45 次的限额，代理出口就只有 IP 没有归属地
func geo(ip string) string {
	if ip == "" {
		return ""
	}
	ready := -1 // -1 未知
	for _, c := range [][2]any{{geoURL1, false}, {geoURL1, true}, {geoURL2, true}, {geoURL2, false}} {
		u, via := c[0].(string), c[1].(bool)
		if via {
			if ready == -1 {
				if CoreReady() {
					ready = 1
				} else {
					ready = 0
				}
			}
			if ready == 0 {
				continue
			}
		}
		txt, _ := fetchURL(fmt.Sprintf(u, ip), via, 8)
		if loc := geoParse(txt); loc != "" {
			return loc
		}
	}
	logErr("IP 归属地查询", errors.New(ip+" 所有归属地服务都没有结果"))
	return ""
}

// queryIP 代理出口强制经核心 mixed 端口；本地公网先经代理取国内服务（规则直连中国网站时拿到真实 IP，
// 自带中文归属地），拿不到或与出口相同时改为绕过核心直连查询。两边并行，避免串行超时累加到半分钟以上
func queryIP() map[string]any {
	res := map[string]any{}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ip := ""
		if CoreReady() {
			txt, _ := fetchURL(IPEcho, true, 10)
			ip = txt
		}
		res["proxy"] = map[string]any{"ip": ip, "loc": LocDedup(geo(ip))}
	}()
	directIP, directLoc := "", ""
	if CoreReady() {
		directIP, directLoc = fetchCnIP()
	}
	wg.Wait()
	proxyIP := ""
	if p, ok := res["proxy"].(map[string]any); ok {
		proxyIP, _ = p["ip"].(string)
	}
	if directIP == "" || directIP == proxyIP {
		directIP = fetchDirectIP()
		directLoc = geo(directIP)
	}
	return map[string]any{
		"direct": map[string]any{"ip": directIP, "loc": LocDedup(directLoc)},
		"proxy":  res["proxy"],
	}
}

// GetIPInfo 返回 {"direct": {"ip","loc"}, "proxy": {"ip","loc"}, "retry": 秒}；查不到的一边 ip 为空串。
// 以前查询失败（核心刚重启、开机网络未就绪）的空结果也缓存 10 分钟，前端又只在进概览时拉一次，于是一直显示「-」。
// 现在只有两边都查到才缓存；有失败就按 5→60 秒退避重查，retry 告诉前端多久后再来拉。
// query 供测试注入；nil 时用真实查询。
func GetIPInfo(query func() map[string]any) map[string]any {
	if query == nil {
		query = queryIP
	}
	ipCache.Lock()
	defer ipCache.Unlock()
	now := nowSec()
	if ipCache.v != nil {
		if ipCache.fail == 0 && now-ipCache.t < cacheTTL {
			return ipCache.v
		}
		if ipCache.fail > 0 && now < ipCache.next {
			out := shallowCopy(ipCache.v)
			out["retry"] = max(1, int(ipCache.next-now+0.999))
			return out
		}
	}
	v := query()
	now = nowSec()
	direct, _ := v["direct"].(map[string]any)
	proxy, _ := v["proxy"].(map[string]any)
	if strOf(direct["ip"]) != "" && strOf(proxy["ip"]) != "" {
		// 归属地缺一边时只缓存 2 分钟（cacheTTL - 120 秒前视为过期），下次再补查
		t := now
		if strOf(direct["loc"]) == "" || strOf(proxy["loc"]) == "" {
			t = now - cacheTTL + 120
		}
		ipCache.t, ipCache.v, ipCache.fail, ipCache.next = t, v, 0, 0
		return v
	}
	ipCache.fail++
	wait := Backoff(ipCache.fail)
	ipCache.t, ipCache.v, ipCache.next = now, v, now+float64(wait)
	out := shallowCopy(v)
	out["retry"] = wait
	return out
}

// ---------- 小助手 ----------

func nowSec() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func strOf(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func joinNonEmpty(sep string, parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}

func shallowCopy(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// shellQuote 最小版 shlex.quote：安全字符原样返回，否则单引号包裹
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.ContainsRune("@%_+=:,./-", c)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
