// Package ruletest 对应 Python shunt/ruletest.py：规则测试。
// 对目标发起真实 CONNECT（经 mixed 端口）并监听核心日志，优先从 /connections
// 读命中规则与链路；live 抓不到时退化为静态规则匹配。
package ruletest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"shunt/internal/base"
	"shunt/internal/corehttp"
	"shunt/internal/logstream"
)

// STUB:corehttp.CoreJSON —— 接线到 corehttp.CoreJSON
func coreJSON(path string, timeoutSec int) map[string]any { return corehttp.CoreJSON(path, timeoutSec) }

// STUB:logstream.CoreStream —— 接线到 logstream.CoreStream。
// 本包的 stop 是 map 式字典（Python 的 stop dict：stop["stop"]=True 置位），
// 这里桥接到 logstream.Stop；调用方写 stop["sock"] 提前关连接的语义由
// CoreStream 内部的 defer conn.Close() 覆盖（置位后最多再等一个 idle 周期）。
func coreStream(path string, sink func(string), stop map[string]any) {
	st := &logstream.Stop{}
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(50 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if b, _ := stop["stop"].(bool); b {
					st.MarkStop()
					return
				}
			}
		}
	}()
	_ = logstream.CoreStream(path, sink, st, 10*time.Second)
}

var schemeRx = regexp.MustCompile(`(?i)^[a-z]+://`)

// CleanTarget 规范化测试目标：去 scheme / 路径 / 查询串，IPv6 去括号，域名小写
func CleanTarget(t string) string {
	t = strings.TrimSpace(t)
	t = schemeRx.ReplaceAllString(t, "")
	if i := strings.Index(t, "/"); i >= 0 {
		t = t[:i]
	}
	if i := strings.Index(t, "?"); i >= 0 {
		t = t[:i]
	}
	if strings.HasPrefix(t, "[") {
		return strings.SplitN(t[1:], "]", 2)[0]
	}
	if strings.Count(t, ":") == 1 {
		t = strings.SplitN(t, ":", 2)[0]
	}
	return strings.ToLower(t)
}

// IsIP 是否 IP 字面量（v4 / v6）
func IsIP(s string) bool {
	return net.ParseIP(s) != nil
}

// ChainOf 跟随 proxies 的 now 指针展开完整链路（防环）
func ChainOf(name string, proxies map[string]any) []string {
	out := []string{name}
	seen := map[string]bool{name: true}
	for {
		pm, ok := proxies[out[len(out)-1]].(map[string]any)
		if !ok {
			break
		}
		now, _ := pm["now"].(string)
		if now == "" || seen[now] {
			break
		}
		out = append(out, now)
		seen[now] = true
	}
	return out
}

// LiveRule 经 mixed 端口对目标发起 CONNECT，同时监听核心日志：
// 优先从 /connections 读取命中规则与链路；节点不通时从日志里的 "dial X (match Rule/payload)" 读取。
// 返回的 map 含 "error" 键表示未捕获到连接；连接本身失败返回 error。
func LiveRule(host string) (map[string]any, error) {
	var mu sync.Mutex
	var logs []string
	stop := map[string]any{}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = recover() }()
		coreStream("/logs?level=info", func(line string) {
			mu.Lock()
			logs = append(logs, line)
			mu.Unlock()
		}, stop)
	}()
	time.Sleep(300 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+fmt.Sprint(base.Mixed), 8*time.Second)
	if err != nil {
		stop["stop"] = true
		return nil, err
	}
	defer func() {
		conn.Close()
		stop["stop"] = true
		if s, ok := stop["sock"].(net.Conn); ok && s != nil {
			_ = s.Close()
		}
	}()

	hp := host + ":443"
	if strings.Contains(host, ":") {
		hp = "[" + host + "]:443"
	}
	_, port, _ := net.SplitHostPort(conn.LocalAddr().String())
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hp, hp)
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	buf := make([]byte, 256)
	first := "(等待超时)"
	if n, err := conn.Read(buf); err == nil {
		first = strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
	}

	srcRx := regexp.MustCompile(`(?:127\.0\.0\.1|\[?::1\]?):` + regexp.QuoteMeta(port) + `\b`)
	dialRx := regexp.MustCompile(`dial (.+?) \(match (\w+)/(.*?)\) .*? error: (.*)`)
	matchRx := regexp.MustCompile(`match (\w+)\((.*?)\) using (.+)$`)
	for i := 0; i < 10; i++ {
		if c := coreJSON("/connections", 3); c != nil {
			if cl, ok := c["connections"].([]any); ok {
				for _, x := range cl {
					xm, _ := x.(map[string]any)
					if xm == nil {
						continue
					}
					md, _ := xm["metadata"].(map[string]any)
					if md == nil {
						continue
					}
					sp := fmt.Sprint(md["sourcePort"])
					sip, _ := md["sourceIP"].(string)
					if sp == port && (sip == "127.0.0.1" || sip == "::1") {
						var chains []string
						for _, ch := range toStrList(xm["chains"]) {
							chains = append([]string{ch}, chains...)
						}
						return map[string]any{
							"method": "live", "rule": xm["rule"], "payload": strOf(xm["rulePayload"]),
							"chain": chains, "note": "连接已建立",
						}, nil
					}
				}
			}
		}
		mu.Lock()
		lines := append([]string(nil), logs...)
		mu.Unlock()
		for _, line := range lines {
			var lj map[string]any
			if err := json.Unmarshal([]byte(line), &lj); err != nil {
				continue
			}
			msg, _ := lj["payload"].(string)
			if !srcRx.MatchString(msg) {
				continue
			}
			if m := dialRx.FindStringSubmatch(msg); m != nil {
				proxies := map[string]any{}
				if pj := coreJSON("/proxies", 3); pj != nil {
					proxies, _ = pj["proxies"].(map[string]any)
				}
				return map[string]any{
					"method": "live", "rule": m[2], "payload": m[3],
					"chain": ChainOf(m[1], proxies), "note": "节点连接失败：" + firstN(m[4], 200),
				}, nil
			}
			if m := matchRx.FindStringSubmatch(msg); m != nil {
				proxies := map[string]any{}
				if pj := coreJSON("/proxies", 3); pj != nil {
					proxies, _ = pj["proxies"].(map[string]any)
				}
				pol := strings.TrimSpace(strings.SplitN(m[3], "[", 2)[0])
				return map[string]any{
					"method": "live", "rule": m[1], "payload": m[2],
					"chain": ChainOf(pol, proxies), "note": "连接已结束",
				}, nil
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return map[string]any{"error": "未捕获到连接（" + first + "）"}, nil
}

// StaticRule 静态规则匹配：逐条走核心 /rules，命中即返回；
// geosite / geoip（非 private）/ ruleset 等无法本地判定的记入 uncertain。
func StaticRule(host string) map[string]any {
	var rules []any
	if rj := coreJSON("/rules", 5); rj != nil {
		rules, _ = rj["rules"].([]any)
	}
	proxies := map[string]any{}
	if pj := coreJSON("/proxies", 5); pj != nil {
		proxies, _ = pj["proxies"].(map[string]any)
	}

	var ips []net.IP
	ipsLoaded := false
	getIPs := func() []net.IP {
		if !ipsLoaded {
			ipsLoaded = true
			if IsIP(host) {
				ips = []net.IP{net.ParseIP(host)}
			} else {
				// 经 mihomo 的 DNS 解析（按 nameserver-policy 分流），不用本机系统 DNS
				for _, qt := range []string{"A", "AAAA"} {
					j := coreJSON("/dns/query?name="+url.QueryEscape(host)+"&type="+qt, 8)
					if j == nil {
						continue
					}
					for _, a := range toList(j["Answer"]) {
						am, _ := a.(map[string]any)
						if am == nil {
							continue
						}
						if t := toInt(am["type"]); t == 1 || t == 28 {
							if ds, ok := am["data"].(string); ok && IsIP(ds) {
								ips = append(ips, net.ParseIP(ds))
							}
						}
					}
				}
			}
		}
		return ips
	}

	var uncertain []string
	dashRx := regexp.MustCompile(`[-_]`)
	for _, r := range rules {
		rm, _ := r.(map[string]any)
		if rm == nil {
			continue
		}
		rtype, _ := rm["type"].(string)
		t := strings.ToLower(dashRx.ReplaceAllString(rtype, ""))
		pl := strOf(rm["payload"])
		var hit *bool
		set := func(b bool) { hit = &b }
		switch t {
		case "domain":
			set(host == strings.ToLower(pl))
		case "domainsuffix":
			lp := strings.ToLower(pl)
			set(host == lp || strings.HasSuffix(host, "."+lp))
		case "domainkeyword":
			set(strings.Contains(host, strings.ToLower(pl)))
		case "domainregex":
			if rx, err := regexp.Compile(pl); err == nil {
				set(rx.MatchString(host))
			}
		case "ipcidr", "ipcidr6":
			if _, nw, err := net.ParseCIDR(pl); err == nil {
				found := false
				for _, ip := range getIPs() {
					if (nw.IP.To4() != nil) == (ip.To4() != nil) && nw.Contains(ip) {
						found = true
						break
					}
				}
				set(found)
			} else if ip := net.ParseIP(pl); ip != nil {
				// 单个 IP 视为 /32（/128）
				found := false
				for _, i := range getIPs() {
					if i.Equal(ip) {
						found = true
						break
					}
				}
				set(found)
			}
		case "geoip":
			if lp := strings.ToLower(pl); lp == "private" || lp == "lan" {
				found := false
				for _, ip := range getIPs() {
					if ip.IsPrivate() {
						found = true
						break
					}
				}
				set(found)
			}
		case "dstport":
			found := false
			for _, seg := range regexp.MustCompile(`[/,]`).Split(pl, -1) {
				a, z := seg, seg
				if i := strings.Index(seg, "-"); i >= 0 {
					a, z = seg[:i], seg[i+1:]
				}
				ai, aerr := parsePortNum(strings.TrimSpace(a))
				zi, zerr := parsePortNum(strings.TrimSpace(z))
				if aerr == nil && zerr == nil && ai <= 443 && 443 <= zi {
					found = true
					break
				}
			}
			set(found)
		case "match":
			set(true)
		}
		switch t {
		case "geosite", "geoip", "ruleset", "and", "or", "not", "srcipcidr",
			"processname", "processpath", "inport", "intype", "network",
			"srcport", "inname", "inuser":
			hit = nil
		}
		if hit == nil {
			if len(uncertain) < 8 {
				uncertain = append(uncertain, fmt.Sprintf("%s,%s → %s", rtype, pl, strOf(rm["proxy"])))
			}
			continue
		}
		if *hit {
			return map[string]any{
				"method": "static", "rule": rtype, "payload": pl,
				"chain": ChainOf(strOf(rm["proxy"]), proxies), "uncertain": uncertain,
			}
		}
	}
	return map[string]any{"method": "static", "rule": "-", "payload": "", "chain": []string{}, "uncertain": uncertain}
}

// RuleTest 规则测试：先 live，抓不到再静态匹配
func RuleTest(target string) (map[string]any, error) {
	host := CleanTarget(target)
	if host == "" {
		return nil, errors.New("请输入域名或 IP")
	}
	var res map[string]any
	liveErr := ""
	if r, err := LiveRule(host); err != nil {
		liveErr = err.Error()
	} else if e, hasErr := r["error"]; hasErr {
		liveErr = strOf(e)
	} else {
		res = r
	}
	if res == nil {
		res = StaticRule(host)
		res["live_error"] = liveErr
	}
	res["host"] = host
	return res, nil
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

func toStrList(v any) []string {
	var out []string
	for _, x := range toList(v) {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func toInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case string:
		var n int
		_, _ = fmt.Sscan(strings.TrimSpace(x), &n)
		return n
	}
	return 0
}

func parsePortNum(s string) (int, error) {
	var n int
	_, err := fmt.Sscan(s, &n)
	if err != nil || s == "" {
		return 0, errors.New("bad port")
	}
	// fmt.Sscan("12x", &n) 会吞掉后缀，这里要求纯数字
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("bad port")
		}
	}
	return n, nil
}

func firstN(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
