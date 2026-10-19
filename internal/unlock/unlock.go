// Package unlock 对应 Python shunt/unlock.py：流媒体解锁检测。
// 各项检测经代理出口访问服务商页面，并行执行后汇总。
package unlock

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"shunt/internal/base"
	"shunt/internal/sysopt"
)

// STUB:sysopt.ProxyOpener —— 接线到 sysopt.ProxyClient（viaProxy=true 时走 127.0.0.1:mixed 代理）
func proxyOpener(viaProxy ...bool) *http.Client {
	p := len(viaProxy) > 0 && viaProxy[0]
	return sysopt.ProxyClient(p)
}

// Fetch 经代理 GET：返回 (状态码, 最终 URL, 正文前 600KB)。4xx/5xx 也返回 body，不抛错。
func Fetch(url string, timeoutSec int, headers map[string]string) (int, string, string) {
	if timeoutSec <= 0 {
		timeoutSec = 10
	}
	h := map[string]string{"User-Agent": base.Ua, "Accept-Language": "en-US,en;q=0.9"}
	for k, v := range headers {
		h[k] = v
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, url, ""
	}
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := proxyOpener().Do(req)
	if err != nil {
		return 0, url, ""
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 600000))
	finalURL := url
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	return resp.StatusCode, finalURL, string(raw)
}

var (
	cfLocRx = regexp.MustCompile(`(?m)^loc=([A-Z]{2})`)
	cfIPRx  = regexp.MustCompile(`(?m)^ip=(\S+)`)
)

// CfLoc 查 Cloudflare /cdn-cgi/trace 的地区与出口 IP
func CfLoc(host string) (string, string) {
	_, _, b := Fetch("https://"+host+"/cdn-cgi/trace", 8, nil)
	loc, ip := "", ""
	if m := cfLocRx.FindStringSubmatch(b); m != nil {
		loc = m[1]
	}
	if m := cfIPRx.FindStringSubmatch(b); m != nil {
		ip = m[1]
	}
	return loc, ip
}

func ckEgress() map[string]any {
	loc, ip := CfLoc("www.cloudflare.com")
	text := ip
	if text == "" {
		text = "无法获取"
	}
	return map[string]any{"ok": loc != "", "text": text, "region": loc}
}

var (
	nfRx1 = regexp.MustCompile(`"requestCountry":\{"id":"([A-Z]{2})"`)
	nfRx2 = regexp.MustCompile(`"country":"([A-Z]{2})"`)
	nfRx3 = regexp.MustCompile(`netflix\.com/([a-z]{2})(?:-[a-z]{2})?/title`)
)

func ckNetflix() map[string]any {
	code, url, body := Fetch("https://www.netflix.com/title/81280792", 10, nil)
	region := ""
	switch {
	case nfRx1.FindStringSubmatch(body) != nil:
		region = nfRx1.FindStringSubmatch(body)[1]
	case nfRx2.FindStringSubmatch(body) != nil:
		region = nfRx2.FindStringSubmatch(body)[1]
	case nfRx3.FindStringSubmatch(url) != nil:
		region = strings.ToUpper(nfRx3.FindStringSubmatch(url)[1])
	}
	switch code {
	case 200:
		return map[string]any{"ok": true, "text": "完整解锁", "region": region}
	case 404:
		return map[string]any{"ok": "partial", "text": "仅自制剧", "region": region}
	case 403:
		return map[string]any{"ok": false, "text": "不可用（403）"}
	default:
		return map[string]any{"ok": false, "text": fmt.Sprintf("未知（HTTP %d）", code)}
	}
}

var blockedRx = regexp.MustCompile(`(?i)VPN|blocked|Access denied`)

func ckChatgpt() map[string]any {
	_, _, b1 := Fetch("https://ios.chat.openai.com/", 10, nil)
	code2, _, b2 := Fetch("https://chatgpt.com/", 10, nil)
	region, _ := CfLoc("chatgpt.com")
	text := b1 + b2
	if strings.Contains(text, "unsupported_country") {
		return map[string]any{"ok": false, "text": "地区不支持", "region": region}
	}
	if blockedRx.MatchString(b1) && !strings.Contains(firstNBytes(b1, 2000), "cf-") {
		return map[string]any{"ok": false, "text": "IP 被封锁", "region": region}
	}
	if (code2 == 200 || code2 == 403) && region != "" {
		return map[string]any{"ok": true, "text": "可用", "region": region}
	}
	return map[string]any{"ok": false, "text": fmt.Sprintf("未知（HTTP %d）", code2), "region": region}
}

var (
	disRx1 = regexp.MustCompile(`"countryCode"\s*:\s*"([A-Z]{2})"`)
	disRx2 = regexp.MustCompile(`Region:\s*([A-Z]{2})`)
	disRx3 = regexp.MustCompile(`disneyplus\.com/(?:[a-z]{2}-)?([a-z]{2})(?:/|$)`)
)

func ckDisney() map[string]any {
	code, url, body := Fetch("https://www.disneyplus.com/", 10, nil)
	if strings.Contains(url, "unavailable") || strings.Contains(strings.ToLower(body), "not available in your region") {
		return map[string]any{"ok": false, "text": "地区不支持"}
	}
	region := ""
	switch {
	case disRx1.FindStringSubmatch(body) != nil:
		region = disRx1.FindStringSubmatch(body)[1]
	case disRx2.FindStringSubmatch(body) != nil:
		region = disRx2.FindStringSubmatch(body)[1]
	case disRx3.FindStringSubmatch(url) != nil:
		region = strings.ToUpper(disRx3.FindStringSubmatch(url)[1])
	}
	if code == 200 {
		text := "可访问"
		if region != "" {
			text = "可用"
		}
		return map[string]any{"ok": true, "text": text, "region": region}
	}
	return map[string]any{"ok": false, "text": fmt.Sprintf("不可用（HTTP %d）", code)}
}

var (
	ytRx1 = regexp.MustCompile(`"countryCode":"([A-Z]{2})"`)
	ytRx2 = regexp.MustCompile(`"INNERTUBE_CONTEXT_GL":"([A-Z]{2})"`)
)

func ckYoutube() map[string]any {
	code, _, body := Fetch("https://www.youtube.com/premium", 10, map[string]string{"Cookie": "CONSENT=YES+1"})
	if strings.Contains(body, "www.google.cn") {
		return map[string]any{"ok": false, "text": "不可用", "region": "CN"}
	}
	region := ""
	switch {
	case ytRx1.FindStringSubmatch(body) != nil:
		region = ytRx1.FindStringSubmatch(body)[1]
	case ytRx2.FindStringSubmatch(body) != nil:
		region = ytRx2.FindStringSubmatch(body)[1]
	}
	if strings.Contains(body, "Premium is not available in your country") {
		return map[string]any{"ok": false, "text": "Premium 不可用", "region": region}
	}
	lower := strings.ToLower(body)
	if code == 200 && (strings.Contains(lower, "ad-free") || strings.Contains(lower, "premium")) {
		return map[string]any{"ok": true, "text": "Premium 可用", "region": region}
	}
	return map[string]any{"ok": false, "text": fmt.Sprintf("未知（HTTP %d）", code), "region": region}
}

var geminiRx = regexp.MustCompile(`45631641(?:,null,true|\\?":true)`)

func ckGemini() map[string]any {
	code, _, body := Fetch("https://gemini.google.com/", 10, nil)
	if geminiRx.MatchString(body) {
		return map[string]any{"ok": true, "text": "可用"}
	}
	if code == 200 {
		return map[string]any{"ok": false, "text": "地区可能不支持"}
	}
	return map[string]any{"ok": false, "text": fmt.Sprintf("不可用（HTTP %d）", code)}
}

// UnlockCheck 一项解锁检测
type UnlockCheck struct {
	Name string
	Fn   func() map[string]any
}

// UnlockChecks 检测项列表（顺序与 Python UNLOCK 一致）
var UnlockChecks = []UnlockCheck{
	{"出口位置", ckEgress},
	{"Netflix", ckNetflix},
	{"ChatGPT", ckChatgpt},
	{"Disney+", ckDisney},
	{"YouTube Premium", ckYoutube},
	{"Gemini", ckGemini},
}

// UnlockTest 并行跑全部解锁检测；单项异常记为检测失败，超时记为"超时"
func UnlockTest() []map[string]any {
	out := make([]map[string]any, len(UnlockChecks))
	var wg sync.WaitGroup
	for i, c := range UnlockChecks {
		wg.Add(1)
		go func(i int, c UnlockCheck) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					msg := fmt.Sprint(r)
					if msg == "" {
						msg = "panic"
					}
					out[i] = map[string]any{"ok": false, "text": "检测失败：" + firstN(msg, 60), "name": c.Name}
				}
			}()
			r := c.Fn()
			r["name"] = c.Name
			out[i] = r
		}(i, c)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(180 * time.Second):
	}
	res := make([]map[string]any, len(UnlockChecks))
	for i, o := range out {
		if o == nil {
			res[i] = map[string]any{"name": UnlockChecks[i].Name, "ok": false, "text": "超时"}
		} else {
			res[i] = o
		}
	}
	return res
}

func firstN(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

func firstNBytes(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
