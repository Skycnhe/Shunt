package adblock

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"shunt/internal/base"
	"shunt/internal/core"
	"shunt/internal/corehttp"
	"shunt/internal/data"
	"shunt/internal/errlog"
	"shunt/internal/logstream"
	"shunt/internal/mihomo"
	"shunt/internal/ruletest"
	"shunt/internal/ruleutil"
	"shunt/internal/singbox"
	"shunt/internal/sysopt"
)

// ---- 跨包 stub（其他 agent 的模块，待联调时替换为真实调用）----

// errlog.log_err 接线
func logErr(what string, err error) {
	errlog.LogErr(what, err, false)
}

// mihomo.build_config 接线
func buildConfig(d map[string]any) map[string]any {
	return mihomo.BuildConfig(d)
}

// core.reload_core 接线（无 prev，不回滚）
func reloadCore() (bool, string) {
	return core.ReloadCore(nil)
}

// corehttp.core 接线
func coreCall(method, path string, body any, timeoutSec int) (int, []byte, error) {
	code, data := corehttp.Core(method, path, body, timeoutSec)
	return code, data, nil
}

// sb_common.active_core 接线 —— var 形式以便测试注入
var activeCore = singbox.ActiveCore

// sb_config.sb_sync_assets 接线（need 为空时内部按 SbRuleNeed 计算）
func sbSyncAssets(d map[string]any, force ...bool) []string {
	f := len(force) > 0 && force[0]
	return singbox.SbSyncAssets(d, f, nil)
}

// sysopt.proxy_opener 接线：经 mixed 端口或直连的 http.Client
func proxyOpener(useProxy bool) *http.Client {
	return sysopt.ProxyClient(useProxy)
}

// ruletest.clean_target 接线
func cleanTarget(s string) string {
	return ruletest.CleanTarget(s)
}

// logstream.core_stream 接线
func coreStream(path string, sink func(string), stop map[string]any) {
	st := &logstream.Stop{}
	if b, ok := stop["stop"].(bool); ok {
		st.Stop = b
	}
	_ = logstream.CoreStream(path, sink, st, 0)
}

// ABState 更新状态（对应 AB_STATE）
var ABState = struct {
	sync.Mutex
	Updating bool
	Msg      string
	Last     int64
}{}

// AbMeta 读各列表的下载元信息
func AbMeta() map[string]any {
	return data.ReadJSON(filepath.Join(base.AbDir, "meta.json"), map[string]any{})
}

// Download 下载文本：先经代理（mixed 端口），失败再直连
func Download(rawurl string, timeoutSec int, limit int64) (string, error) {
	errMsg := ""
	for _, useProxy := range []bool{true, false} {
		// SSRF 防护：直连时校验 DNS，走代理时由代理解析（字面内网 IP 永远拦截）
		if err := base.DlCheck(rawurl, useProxy); err != nil {
			errMsg = firstN(err.Error(), 160)
			continue
		}
		req, err := http.NewRequest("GET", rawurl, nil)
		if err != nil {
			errMsg = firstN(err.Error(), 160)
			continue
		}
		req.Header.Set("User-Agent", base.Ua)
		client := proxyOpener(useProxy)
		client.Timeout = time.Duration(timeoutSec) * time.Second
		resp, err := client.Do(req)
		if err != nil {
			errMsg = firstN(err.Error(), 160)
			continue
		}
		if resp.StatusCode >= 400 {
			resp.Body.Close()
			errMsg = fmt.Sprintf("HTTP %d", resp.StatusCode)
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		resp.Body.Close()
		if err != nil {
			errMsg = firstN(err.Error(), 160)
			continue
		}
		if int64(len(body)) > limit {
			return "", errors.New("文件过大（超过 40MB）")
		}
		return strings.ToValidUTF8(string(body), ""), nil
	}
	if errMsg == "" {
		errMsg = "下载失败"
	}
	return "", errors.New(errMsg)
}

func firstN(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// AbFetch 下载并转换一个列表，写入 <id>.txt / <id>.allow.txt，返回 meta
func AbFetch(lst map[string]any) (map[string]any, error) {
	text, err := Download(data.Str(lst, "url"), 60, 40<<20)
	if err != nil {
		return nil, err
	}
	bs, be, as_, ae, skipped := ParseFilter(text, false)
	lines, n := DomainLines(bs, be)
	alines, na := DomainLines(as_, ae)
	if n == 0 && na == 0 {
		return nil, errors.New("没有解析出任何域名，确认是 AdGuard / hosts / 域名列表格式")
	}
	id := data.Str(lst, "id")
	if err := WriteLines(filepath.Join(base.AbDir, id+".txt"), lines); err != nil {
		return nil, err
	}
	if err := WriteLines(filepath.Join(base.AbDir, id+".allow.txt"), alines); err != nil {
		return nil, err
	}
	return map[string]any{"count": n, "allow": na, "skipped": skipped, "updated": time.Now().Unix(), "error": ""}, nil
}

// listEnabled 列表是否启用（缺省为启用，与 Python 的 l.get("enabled", True) 一致）
func listEnabled(lm map[string]any) bool {
	if v, ok := lm["enabled"]; ok {
		b, _ := v.(bool)
		return b
	}
	return true
}

// AbCompose 根据用户黑/白名单与各列表的 @@ 规则生成 custom.txt / allow.txt
func AbCompose(d map[string]any) error {
	ab := data.Map(d, "adblock")
	bs, be, _, _, _ := ParseFilter(strings.Join(data.Strs(ab, "black"), "\n"), true)
	lines, _ := DomainLines(bs, be)
	if err := WriteLines(filepath.Join(base.AbDir, "custom.txt"), lines); err != nil {
		return err
	}
	ws, we, was, wae, _ := ParseFilter(strings.Join(data.Strs(ab, "white"), "\n"), true)
	suffix, exact := Union(ws, was), Union(we, wae)
	for _, l := range data.List(ab, "lists") {
		lm, ok := l.(map[string]any)
		if !ok || !listEnabled(lm) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(base.AbDir, data.Str(lm, "id")+".allow.txt"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "+.") {
				suffix[line[2:]] = true
			} else if line != "" {
				exact[line] = true
			}
		}
	}
	lines, _ = DomainLines(suffix, exact)
	return WriteLines(filepath.Join(base.AbDir, "allow.txt"), lines)
}

// configJSON 对应 Python 的 json.dumps(build_config(d), ensure_ascii=False, indent=2)
func configJSON(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
	return strings.TrimSuffix(buf.String(), "\n")
}

// AbApply 列表文件变化后让核心生效：配置结构没变时只刷新对应 rule-provider，否则走完整的校验 + 重载
func AbApply() (bool, string) {
	d := data.Load()
	if activeCore(d) == "singbox" { // 广告列表转换成 sing-box 规则集后重载
		sbSyncAssets(d)
		AbCacheClear()
		return reloadCore()
	}
	same := false
	if raw, err := os.ReadFile(filepath.Join(base.ConfDir, "config.yaml")); err == nil {
		same = string(raw) == configJSON(buildConfig(d))
	}
	if same {
		prov, _ := ruleutil.AdblockProviders(d)
		for name := range prov {
			_, _, _ = coreCall("PUT", "/providers/rules/"+url.PathEscape(name), nil, 60)
		}
		AbCacheClear()
		return true, "规则已刷新"
	}
	AbCacheClear()
	return reloadCore()
}

// AdblockUpdate 下载全部（或指定）启用的列表；在后台 goroutine 里调用
func AdblockUpdate(ids []string, apply bool) (bool, string) {
	ABState.Lock()
	if ABState.Updating {
		ABState.Unlock()
		return false, "正在更新中"
	}
	ABState.Updating, ABState.Msg = true, "正在下载规则列表…"
	ABState.Unlock()
	defer func() {
		ABState.Lock()
		ABState.Updating = false
		ABState.Unlock()
	}()

	d := data.Load()
	ab := data.Map(d, "adblock")
	idSet := map[string]bool{}
	for _, id := range ids {
		idSet[id] = true
	}
	var lists []map[string]any
	for _, l := range data.List(ab, "lists") {
		lm, ok := l.(map[string]any)
		if !ok || !listEnabled(lm) {
			continue
		}
		if len(ids) > 0 && !idSet[data.Str(lm, "id")] {
			continue
		}
		lists = append(lists, lm)
	}
	meta := AbMeta()
	res := map[string]map[string]any{}
	var resMu sync.Mutex
	done := make(chan struct{}, len(lists))
	for _, l := range lists {
		go func(l map[string]any) {
			defer func() { done <- struct{}{} }()
			m, err := AbFetch(l)
			id := data.Str(l, "id")
			resMu.Lock()
			defer resMu.Unlock()
			if err != nil {
				prev, _ := meta[id].(map[string]any)
				m2 := map[string]any{}
				for k, v := range prev {
					m2[k] = v
				}
				m2["error"], m2["checked"] = firstN(err.Error(), 200), time.Now().Unix()
				res[id] = m2
			} else {
				res[id] = m
			}
		}(l)
	}
	for range lists {
		select {
		case <-done:
		case <-time.After(150 * time.Second):
		}
	}
	for k, v := range res {
		meta[k] = v
	}
	_ = os.MkdirAll(base.AbDir, 0o755)
	_ = data.WriteJSON(filepath.Join(base.AbDir, "meta.json"), meta)
	_ = AbCompose(data.Load())
	var bad []string
	for _, l := range lists {
		if m := res[data.Str(l, "id")]; m != nil && data.Str(m, "error") != "" {
			bad = append(bad, data.Str(l, "name"))
		}
	}
	ok, msg := true, ""
	if apply {
		ok, msg = AbApply()
	}
	ABState.Lock()
	ABState.Last = time.Now().Unix()
	if len(bad) > 0 {
		ABState.Msg = "部分列表下载失败：" + strings.Join(bad, "、")
	} else {
		ABState.Msg = fmt.Sprintf("已更新 %d 个列表", len(lists))
	}
	if !ok {
		ABState.Msg += "；" + msg
	}
	finalMsg := ABState.Msg
	ABState.Unlock()
	return ok && len(bad) == 0, finalMsg
}

// ---------- 规则查询缓存 ----------

type abCacheEntry struct {
	mt  float64
	suf map[string]bool
	ex  map[string]bool
}

var (
	abCacheMu sync.Mutex
	abCache   = map[string]abCacheEntry{}
)

// AbIdle 缓存空闲释放秒数
const AbIdle = 300

var abGC = struct {
	sync.Mutex
	last  float64
	timer *time.Timer
}{}

func nowFloat() float64 { return float64(time.Now().UnixNano()) / 1e9 }

// AbCacheClear 清空查询缓存
func AbCacheClear() {
	abCacheMu.Lock()
	defer abCacheMu.Unlock()
	abCache = map[string]abCacheEntry{}
}

func abTouch() {
	// 记一次使用；没有待执行的释放定时器就起一个。几十万条的 HaGeZi / anti-AD 列表转成 set 要占几十 MB，
	// 以前查一次就常驻到下次更新，现在 5 分钟没人查就释放
	abGC.Lock()
	defer abGC.Unlock()
	abGC.last = nowFloat()
	if abGC.timer == nil {
		abGC.timer = time.AfterFunc(AbIdle*time.Second, abGCDo)
	}
}

func abGCDo() {
	abGC.Lock()
	defer abGC.Unlock()
	if left := abGC.last + AbIdle - nowFloat(); left > 1 {
		abGC.timer = time.AfterFunc(time.Duration(left*float64(time.Second)), abGCDo)
		return
	}
	abGC.timer = nil
	AbCacheClear()
}

// AbSets 读规则文件为 (后缀集合, 精确集合)，带 mtime 缓存
func AbSets(path string) (map[string]bool, map[string]bool) {
	st, err := os.Stat(path)
	if err != nil {
		return map[string]bool{}, map[string]bool{}
	}
	mt := float64(st.ModTime().UnixNano()) / 1e9
	abTouch()
	abCacheMu.Lock()
	defer abCacheMu.Unlock()
	if c, ok := abCache[path]; ok && c.mt == mt {
		return c.suf, c.ex
	}
	suf, ex := map[string]bool{}, map[string]bool{}
	raw, err := os.ReadFile(path)
	if err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "+.") {
				suf[line[2:]] = true
			} else if line != "" {
				ex[line] = true
			}
		}
	}
	abCache[path] = abCacheEntry{mt: mt, suf: suf, ex: ex}
	return suf, ex
}

// AbMatch 查域名是否命中规则：返回命中的规则写法（精确返回域名本身，后缀返回 +.父域）
func AbMatch(host string, suf, ex map[string]bool) (string, bool) {
	if ex[host] {
		return host, true
	}
	for _, p := range Parents(host, true) {
		if suf[p] {
			return "+." + p, true
		}
	}
	return "", false
}

// AbCheck 查一个域名会被哪些规则拦截/放行
func AbCheck(target string) (map[string]any, error) {
	if target == "" {
		return nil, errors.New("请输入有效域名")
	}
	host := cleanTarget(target)
	if NormDomain(host) == "" {
		return nil, errors.New("请输入有效域名")
	}
	d := data.Load()
	ab := data.Map(d, "adblock")
	names := map[string]string{}
	for _, l := range data.List(ab, "lists") {
		if lm, ok := l.(map[string]any); ok {
			names[data.Str(lm, "id")] = data.Str(lm, "name")
		}
	}
	var blocked, allowed []map[string]any
	ws, we, was, wae, _ := ParseFilter(strings.Join(data.Strs(ab, "white"), "\n"), true)
	if r, ok := AbMatch(host, Union(ws, was), Union(we, wae)); ok {
		allowed = append(allowed, map[string]any{"name": "自定义白名单", "rule": r})
	}
	for _, l := range data.List(ab, "lists") {
		lm, ok := l.(map[string]any)
		if !ok || !listEnabled(lm) {
			continue
		}
		suf, ex := AbSets(filepath.Join(base.AbDir, data.Str(lm, "id")+".allow.txt"))
		if r, ok := AbMatch(host, suf, ex); ok {
			allowed = append(allowed, map[string]any{"name": data.Str(lm, "name") + "（@@ 例外）", "rule": r})
		}
	}
	bs, be, _, _, _ := ParseFilter(strings.Join(data.Strs(ab, "black"), "\n"), true)
	if r, ok := AbMatch(host, bs, be); ok {
		blocked = append(blocked, map[string]any{"name": "自定义黑名单", "rule": r})
	}
	for _, l := range data.List(ab, "lists") {
		lm, ok := l.(map[string]any)
		if !ok || !listEnabled(lm) {
			continue
		}
		suf, ex := AbSets(filepath.Join(base.AbDir, data.Str(lm, "id")+".txt"))
		if r, ok := AbMatch(host, suf, ex); ok {
			blocked = append(blocked, map[string]any{"name": names[data.Str(lm, "id")], "rule": r})
		}
	}
	enabled := data.Bool(ab, "enabled")
	return map[string]any{
		"host": host, "enabled": enabled, "blocked_by": blocked, "allowed_by": allowed,
		"blocked": len(blocked) > 0 && len(allowed) == 0 && enabled,
	}, nil
}

// IsFakeIP Fake-IP 网段（198.18.0.0/15 等）的地址：没反查到域名的连接，不能当成「被拦截的域名」进排行
func IsFakeIP(host string) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	for _, n := range base.FakeIPNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
