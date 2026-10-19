package singbox

// sb_subs.py：sing-box 不能自己拉取订阅，由面板下载、解析成节点后写进配置

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"shunt/internal/base"
	"shunt/internal/data"
)

// SubsWait 并发更新订阅整体最多等这么多秒
const SubsWait = 180

var debugLock sync.Mutex // sub-debug.txt 并发写保护

// yamlFull 设备装了 py3-yaml 时用完整解析器；Go 版面板保持零依赖，等价于 ImportError 分支（恒返回 nil）
func yamlFull(text string) map[string]any { return nil }

var sectionKeyRe = regexp.MustCompile(`^['"]?([^:'"]+)['"]?\s*:`)

// yamlSection 取出顶层 key: 段落原文（到下一个顶层键为止）
func yamlSection(text, key string) string {
	var out []string
	on := false
	for _, ln := range strings.Split(strings.ReplaceAll(text, "\t", "  "), "\n") {
		var first byte
		if len(ln) > 0 {
			first = ln[0]
		}
		top := first != 0 && first != ' ' && first != '-' && first != '#'
		if top {
			m := sectionKeyRe.FindStringSubmatch(ln)
			on = m != nil && strings.TrimSpace(m[1]) == key
			if on {
				_, rest, _ := strings.Cut(ln, ":")
				out = append(out, key+":"+rest)
			}
			continue
		}
		if on {
			out = append(out, ln)
		}
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "\n")
}

// yamlItems 整段解析失败时，按列表项逐条解析，坏的跳过
func yamlItems(sec string) []map[string]any {
	lines := strings.Split(sec, "\n")
	if len(lines) > 0 {
		lines = lines[1:]
	}
	ind := -1
	for _, x := range lines {
		if strings.HasPrefix(strings.TrimSpace(x), "-") {
			ind = len(x) - len(strings.TrimLeft(x, " "))
			break
		}
	}
	if ind < 0 {
		return nil
	}
	var items [][]string
	var cur []string
	for _, ln := range lines {
		if strings.HasPrefix(strings.TrimSpace(ln), "-") && len(ln)-len(strings.TrimLeft(ln, " ")) == ind {
			if len(cur) > 0 {
				items = append(items, cur)
			}
			cur = []string{ln}
		} else if len(cur) > 0 {
			cur = append(cur, ln)
		}
	}
	if len(cur) > 0 {
		items = append(items, cur)
	}
	var out []map[string]any
	for _, it := range items {
		v, err := YamlLite("x:\n" + strings.Join(it, "\n"))
		if err != nil {
			stubLogErr("订阅节点解析（跳过一条）", err)
			continue
		}
		var x any
		if m, ok := v.(map[string]any); ok {
			x = m["x"]
		}
		if lst, ok := x.([]any); ok && len(lst) > 0 {
			if d, ok := lst[0].(map[string]any); ok {
				out = append(out, d)
			}
		}
	}
	return out
}

var listItemRe = regexp.MustCompile(`^\s*-\s`)

// SubYaml Clash/mihomo 订阅 → {"proxies": [...], "proxy-providers": {...}}，尽量容错
func SubYaml(text string) map[string]any {
	if y := yamlFull(text); y != nil {
		proxies, _ := y["proxies"].([]any)
		if proxies == nil {
			proxies = []any{}
		}
		provs, _ := y["proxy-providers"].(map[string]any)
		if provs == nil {
			provs = map[string]any{}
		}
		return map[string]any{"proxies": proxies, "proxy-providers": provs}
	}
	res := map[string]any{"proxies": []any{}, "proxy-providers": map[string]any{}}
	for _, key := range []string{"proxies", "proxy-providers"} {
		sec := yamlSection(text, key)
		if sec == "" {
			continue
		}
		var v any
		if parsed, err := YamlLite(sec); err == nil {
			if m, ok := parsed.(map[string]any); ok {
				v = m[key]
			}
		}
		if key == "proxies" {
			nItems := 0
			for _, ln := range strings.Split(sec, "\n") {
				if listItemRe.MatchString(ln) {
					nItems++
				}
			}
			vl, _ := v.([]any)
			if vl == nil || len(vl) < nItems {
				if alt := yamlItems(sec); len(alt) > len(vl) {
					vl = make([]any, len(alt))
					for i, a := range alt {
						vl[i] = a
					}
				}
			}
			if vl != nil {
				res[key] = vl
			} else {
				res[key] = []any{}
			}
		} else {
			if vm, ok := v.(map[string]any); ok {
				res[key] = vm
			} else {
				res[key] = map[string]any{}
			}
		}
	}
	return res
}

var (
	subYAMLRe  = regexp.MustCompile(`(?m)^['"]?(proxies|proxy-providers)['"]?\s*:`)
	linkLineRe = regexp.MustCompile(`^\s*[A-Za-z][\w+.\-]*://`)
	wsRe       = regexp.MustCompile(`\s+`)
)

var sbOutboundSkipTypes = map[string]bool{"selector": true, "urltest": true, "direct": true, "block": true, "dns": true}

// ParseSubText 订阅内容 → mihomo 风格节点列表。支持 Clash YAML、sing-box JSON、Base64 / 明文分享链接
func ParseSubText(text string, fetch func(string) (string, error), depth int) ([]map[string]any, []string) {
	t := strings.TrimLeft(strings.TrimSpace(text), "\ufeff")
	if strings.HasPrefix(t, "{") {
		var j map[string]any
		if err := json.Unmarshal([]byte(t), &j); err == nil {
			if obs, ok := j["outbounds"].([]any); ok {
				out := []map[string]any{}
				for _, oAny := range obs {
					o, ok := oAny.(map[string]any)
					if !ok || sbOutboundSkipTypes[data.Str(o, "type")] {
						continue
					}
					if data.Str(o, "tag") == "" || data.Str(o, "server") == "" {
						continue
					}
					out = append(out, map[string]any{"_sb": o, "name": data.Str(o, "tag"), "type": o["type"]})
				}
				return out, []string{}
			}
		}
	}
	if subYAMLRe.MatchString(t) {
		y := SubYaml(t)
		ps, _ := y["proxies"].([]any)
		// 名称统一成文本：YAML 里 name: 2024 会解析成数字，后面的筛选正则 / 去重遇到数字会抛错，整个订阅更新失败
		out := []map[string]any{}
		for _, pAny := range ps {
			p, ok := pAny.(map[string]any)
			if !ok {
				continue
			}
			if p["name"] == nil || p["name"] == "" || data.Str(p, "type") == "" {
				continue
			}
			name := strings.TrimSpace(toStr(p["name"]))
			if name == "" {
				continue
			}
			np := copyMap(p)
			np["name"] = name
			out = append(out, np)
		}
		var errs []string
		pv, _ := y["proxy-providers"].(map[string]any)
		// 聚合配置：mihomo 自己会去拉 proxy-providers，sing-box 不会，这里由面板逐个下载展开
		for pname, provAny := range pv {
			prov, ok := provAny.(map[string]any)
			if !ok || data.Str(prov, "url") == "" || depth > 1 || fetch == nil {
				continue
			}
			txt, err := fetch(data.Str(prov, "url"))
			if err != nil {
				errs = append(errs, pname+"："+firstN(err.Error(), 80))
				continue
			}
			sub, e2 := ParseSubText(txt, fetch, depth+1)
			names := map[string]bool{}
			for _, x := range out {
				names[data.Str(x, "name")] = true
			}
			for _, x := range sub {
				if names[data.Str(x, "name")] {
					x["name"] = data.Str(x, "name") + " [" + pname + "]"
				}
				out = append(out, x)
			}
			errs = append(errs, e2...)
		}
		if len(out) > 0 || len(ps) > 0 || len(pv) > 0 {
			return out, errs
		}
		if len(errs) > 0 {
			return []map[string]any{}, errs
		}
		return []map[string]any{}, []string{"订阅是 mihomo 配置，但没读到 proxies 节点"}
	}
	body := t
	if !strings.Contains(t, "://") {
		if dec, err := stubB64d(wsRe.ReplaceAllString(t, "")); err == nil {
			body = dec
		} else {
			body = ""
		}
	}
	out := []map[string]any{}
	var errs []string
	i := 0
	for _, rawLine := range strings.Split(body, "\n") {
		x := strings.TrimSpace(rawLine)
		if !linkLineRe.MatchString(x) {
			continue
		}
		i++
		p, err := stubParseLink(x)
		if err != nil {
			errs = append(errs, fmt.Sprintf("第 %d 条：%s", i, err))
			continue
		}
		name := data.Str(p, "name")
		if name == "" {
			name = fmt.Sprintf("%s-%s:%v", data.Str(p, "type"), data.Str(p, "server"), p["port"])
		}
		p["name"] = strings.TrimSpace(name)
		out = append(out, p)
	}
	return out, errs
}

func proxyOrder() []bool {
	if stubCoreAlive() {
		return []bool{true, false}
	}
	return []bool{false}
}

// subGet 下载订阅里嵌套的 proxy-providers 地址：先代理后直连
func subGet(url, ua string) (string, error) {
	var last error
	for _, useProxy := range proxyOrder() {
		// STUB:sysopt.proxy_opener 经由 stubHTTPGet；SSRF 防护见 base.DlCheck（直连时校验 DNS，走代理时由代理解析）
		if err := base.DlCheck(url, useProxy); err != nil {
			last = err
			continue
		}
		body, _, err := stubHTTPGet(url, ua, useProxy, 20<<20, 30)
		if err != nil {
			last = err
			continue
		}
		return string(body), nil
	}
	if last == nil {
		return "", fmt.Errorf("下载失败")
	}
	return "", fmt.Errorf("%s", firstN(last.Error(), 120))
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// SbFetchSub 下载并解析一个订阅，写入缓存；返回 (节点数, 消息)
func SbFetchSub(s map[string]any, gh string) (int, string, error) {
	_ = gh // Python 签名保留 gh 参数，函数体内未使用
	last := ""
	for _, ua := range SBUa {
		n, msg, l, ok := sbFetchSubWithUA(s, ua)
		if ok {
			return n, msg, nil
		}
		if l != "" {
			last = l
		}
	}
	if last == "" {
		last = "下载失败"
	}
	return 0, "", fmt.Errorf("%s", last)
}

func sbFetchSubWithUA(s map[string]any, ua string) (n int, msg string, last string, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			n, msg, last, ok = 0, "", firstN(fmt.Sprint(r), 150), false
		}
	}()
	var body []byte
	var info string
	subURL := data.Str(s, "url")
	for _, useProxy := range proxyOrder() {
		// 每次新建请求：走代理失败后复用请求会让「直连重试」仍然连到代理
		if err := base.DlCheck(subURL, useProxy); err != nil {
			last = firstN(err.Error(), 150)
			continue
		}
		b, hdr, err := stubHTTPGet(subURL, ua, useProxy, 20<<20, 30)
		if err != nil {
			last = firstN(err.Error(), 150)
			continue
		}
		body, info = b, hdr.Get("subscription-userinfo")
		break
	}
	if body == nil {
		return 0, "", last, false
	}
	nodes, errs := ParseSubText(string(body), func(u string) (string, error) { return subGet(u, ua) }, 0)
	if len(nodes) == 0 {
		last = "没有解析出节点"
		if len(errs) > 0 {
			last += "：" + errs[0]
		}
		func() { // 留一份原文方便排查（只保留最近一次）；原文含节点密码，600 权限
			debugLock.Lock()
			defer debugLock.Unlock()
			dbg := filepath.Join(base.PanelDir, "sub-debug.txt")
			b2 := body
			if len(b2) > 2<<20 {
				b2 = b2[:2<<20]
			}
			if os.WriteFile(dbg, b2, 0o600) == nil {
				_ = os.Chmod(dbg, 0o600)
			}
		}()
		// mihomo 已下载过这个订阅时，用它的缓存兜底
		cache := filepath.Join(base.ConfDir, "providers", data.Safe(data.Str(s, "name"))+".yaml")
		if cb, err := os.ReadFile(cache); err == nil {
			nodes, errs = ParseSubText(string(cb), func(u string) (string, error) { return subGet(u, ua) }, 0)
		}
		if len(nodes) == 0 {
			return 0, "", last, false
		}
	}
	flt := data.Str(s, "filter")
	exc := base.DefaultExclude
	if v, present := s["exclude"]; present {
		if v == nil {
			exc = ""
		} else {
			exc = toStr(v)
		}
	}
	var rf, re_ *regexp.Regexp
	if flt != "" {
		rf = stubRx(flt)
	}
	if exc != "" {
		re_ = stubRx(exc)
	}
	kept := []map[string]any{}
	for _, p := range nodes {
		nm := data.Str(p, "name")
		if rf != nil && !rf.MatchString(nm) {
			continue
		}
		if re_ != nil && re_.MatchString(nm) {
			continue
		}
		kept = append(kept, p)
	}
	nodes = kept
	ui := map[string]any{}
	for _, part := range strings.Split(info, ";") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		v = strings.TrimSpace(v)
		if (k == "upload" || k == "download" || k == "total" || k == "expire") && isDigits(v) {
			iv, _ := strconv.Atoi(v)
			ui[strings.ToUpper(k[:1])+k[1:]] = iv
		}
	}
	if err := data.WriteJSON(stubSubCachePath(data.Str(s, "name")), map[string]any{
		"name": data.Str(s, "name"), "updated": int(time.Now().Unix()), "nodes": nodes,
		"info": ui, "skipped": len(errs), "ua": ua,
	}); err != nil {
		return 0, "", firstN(err.Error(), 150), false
	}
	m := fmt.Sprintf("%d 个节点", len(nodes))
	if len(errs) > 0 {
		m += fmt.Sprintf("（%d 条无法识别已跳过）", len(errs))
	}
	return len(nodes), m, "", true
}

// SbUpdateSubs 并发更新订阅：每个订阅一个 goroutine（单个订阅仍串行走 UA/代理/直连回退），整体耗时取决于最慢的一个
func SbUpdateSubs(names []string, d map[string]any) ([]string, []string) {
	if d == nil {
		d = data.Load()
	}
	gh := data.Str(d, "gh_proxy")
	var subs []map[string]any
	for _, sAny := range data.List(d, "subs") {
		s, ok := sAny.(map[string]any)
		if !ok {
			continue
		}
		if len(names) > 0 && !containsStr(names, data.Str(s, "name")) {
			continue
		}
		subs = append(subs, s)
	}
	type res struct {
		okMsg, badMsg string
		ok, done      bool
	}
	results := make([]res, len(subs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i, s := range subs {
		wg.Add(1)
		go func(i int, s map[string]any) {
			defer wg.Done()
			_, msg, err := SbFetchSub(s, gh)
			mu.Lock()
			defer mu.Unlock()
			results[i].done = true
			if err != nil {
				results[i].badMsg = fmt.Sprintf("%s：%s", data.Str(s, "name"), err)
			} else {
				results[i].ok = true
				results[i].okMsg = fmt.Sprintf("%s：%s", data.Str(s, "name"), msg)
			}
		}(i, s)
	}
	doneCh := make(chan struct{})
	go func() { wg.Wait(); close(doneCh) }()
	select {
	case <-doneCh:
	case <-time.After(SubsWait * time.Second):
	}
	okOut := []string{}
	badOut := []string{}
	mu.Lock()
	for i, s := range subs {
		r := results[i]
		switch {
		case r.done && r.ok:
			okOut = append(okOut, r.okMsg)
		case r.done:
			badOut = append(badOut, r.badMsg)
		default: // 超时还没结束的 goroutine 之后再写结果也不影响这里返回的快照
			badOut = append(badOut, fmt.Sprintf("%s：下载超时", data.Str(s, "name")))
		}
	}
	mu.Unlock()
	stubProvUpdate(nil)
	return okOut, badOut
}
