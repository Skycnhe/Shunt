// Package latency 对应 Python shunt/latency.py：节点延迟缓存与背景图。
package latency

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"shunt/internal/base"
	"shunt/internal/core"
	"shunt/internal/corehttp"
	"shunt/internal/data"
	"shunt/internal/errlog"
	notifypkg "shunt/internal/notify"
	"shunt/internal/singbox"
)

// ---- 跨包 stub 接线（对应各包的导出函数，直接调用）----

// core → latency 的延迟绑定注入（对应 Python core.py 函数内 from .latency import retest_soon）：
// latency 顶层导入 core，core 不能再反向导入 latency，故在这里把实现注入 core 的钩子。
func init() { core.SetRetestSoon(RetestSoon) }

// STUB:errlog.log_err
func logErr(what string, err error) {
	errlog.LogErr(what, err, false)
}

// STUB:core.refresh_regions（latency → core 顶层导入，与 Python 一致）
var refreshRegions = core.RefreshRegions

// STUB:corehttp.core（corehttp.Core 不返回 error，失败用 502 状态码表示）
func coreCall(method, path string, body any, timeoutSec int) (int, []byte, error) {
	code, raw := corehttp.Core(method, path, body, timeoutSec)
	return code, raw, nil
}

// STUB:corehttp.core_json
func coreJSON(path string, timeoutSec int) map[string]any {
	return corehttp.CoreJSON(path, timeoutSec)
}

// STUB:sb_common.active_core
func activeCore(d ...map[string]any) string {
	return singbox.ActiveCore(d...)
}

// STUB:sb_config.sb_fake_providers
func sbFakeProviders(d map[string]any) map[string]any {
	return singbox.SbFakeProviders(d)
}

// STUB:sysopt.proxy_opener（对应 Python proxy_opener：经本机 MIXED 端口走代理）
// sysopt 包未导出 ProxyOpener（其他模块各自持有 stub），此处按 Python 语义实现
func proxyOpener(useProxy bool) *http.Client {
	tr := &http.Transport{Proxy: nil}
	if useProxy {
		mixed, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", base.Mixed))
		tr.Proxy = http.ProxyURL(mixed)
	}
	return &http.Client{Transport: tr}
}

// STUB:notify.WD —— 直接读 notify 包的真实状态，不再维护局部副本
func wdStatus() string {
	return notifypkg.WdStatus()
}

// STUB:notify.check_nodes
func checkNodes() {
	notifypkg.CheckNodes()
}

// STUB:notify.core_alive
func coreAlive() bool {
	return notifypkg.CoreAlive()
}

// STUB:notify.load_notified
func loadNotified() map[string]any {
	return notifypkg.LoadNotified()
}

// STUB:notify.notify
func notify(msg string) {
	notifypkg.Notify(msg)
}

// STUB:notify.watchdog_tick
func watchdogTick() {
	notifypkg.WatchdogTick()
}

// init 把本包实现注入 core（core 不能反向导入 latency，会循环引用；
// 模式与 migrate.go 的 core.SetSnapshotSelections 一致）。
func init() {
	core.SetRetestSoon(RetestSoon)
}

// ---------- 延迟缓存 ----------

// DelayFile 延迟缓存文件；BgFile 外观背景图
var (
	DelayFile = filepath.Join(base.PanelDir, "delays.json")
	BgFile    = filepath.Join(base.PanelDir, "bg.img")
	BgMeta    = BgFile + ".json" // 链接背景图：{"url": 链接, "daily": 每天刷新, "t": 上次下载时间}
)

// BgMax 背景图上限 8MB
const BgMax = 8 * 1 << 20

// Delays 延迟缓存：{节点: {d, ts, at}}；saved 上次落盘，dirty 有未落盘修改
var Delays = struct {
	sync.Mutex
	Data  map[string]any
	Saved int64
	Dirty bool
}{}

// Retest 补测状态
var Retest = struct {
	sync.Mutex
	Pending bool
	Last    int64
}{}

var delayMu sync.Mutex

func nowSec() int64 { return time.Now().Unix() }

// HistLast 节点所有测速记录（history 与各地址的 extra.history）里时间最新的一条 → (延迟, 时间串, 是否有)
func HistLast(p map[string]any) (int, string, bool) {
	var lists []any
	lists = append(lists, p["history"])
	for _, v := range data.Map(p, "extra") {
		if vm, ok := v.(map[string]any); ok {
			lists = append(lists, vm["history"])
		}
	}
	bestD, bestT := 0, ""
	found := false
	for _, l := range lists {
		arr, ok := l.([]any)
		if !ok || len(arr) == 0 {
			continue
		}
		e, ok := arr[len(arr)-1].(map[string]any)
		if !ok {
			continue
		}
		if _, ok := e["delay"]; !ok {
			continue
		}
		t := data.Str(e, "time")
		if !found || t > bestT {
			bestD, bestT, found = data.Int(e, "delay"), t, true
		}
	}
	return bestD, bestT, found
}

// DelayMerge 用核心的最新记录更新缓存，并给每个节点写入 _d（延迟）/_dt（测速时间）。
// provOk=False（订阅节点列表没取到）时不清理「已不存在」的节点，免得把订阅节点的缓存延迟全删掉
func DelayMerge(px map[string]map[string]any, provOk bool) map[string]map[string]any {
	delayMu.Lock()
	defer delayMu.Unlock()
	Delays.Lock()
	defer Delays.Unlock()
	if Delays.Data == nil {
		Delays.Data = data.ReadJSON(DelayFile, map[string]any{})
		if Delays.Data == nil {
			Delays.Data = map[string]any{}
		}
	}
	datum, now := Delays.Data, nowSec()
	for name, p := range px {
		if _, isGroup := p["all"]; isGroup { // 策略组的延迟取当前节点，前端处理
			continue
		}
		if r, ts, ok := HistLast(p); ok {
			old, _ := datum[name].(map[string]any)
			if old == nil || data.Str(old, "ts") != ts {
				datum[name] = map[string]any{"d": r, "ts": ts, "at": now}
				Delays.Dirty = true
			}
		}
		if c, ok := datum[name].(map[string]any); ok {
			p["_d"], p["_dt"] = data.Int(c, "d"), int64(data.Int(c, "at"))
		}
	}
	if len(px) > 0 && provOk {
		for n := range datum {
			if _, ok := px[n]; !ok { // 节点已不存在
				delete(datum, n)
				Delays.Dirty = true
			}
		}
	}
	if Delays.Dirty && now-Delays.Saved > 30 {
		if err := data.WriteJSON(DelayFile, datum); err != nil {
			logErr("保存延迟缓存", err)
		} else {
			Delays.Saved, Delays.Dirty = now, false
		}
	}
	return px
}

// FixGlobal mihomo 的「全局」模式走内置 GLOBAL 组，它默认选第一项 DIRECT（全局模式反而不走代理）：
// 没选过代理时指向「🚀 节点选择」
func FixGlobal() {
	if activeCore() == "singbox" { // sing-box 的 Global 已直接指向节点选择
		return
	}
	g := coreJSON("/proxies/GLOBAL", 5)
	if g == nil {
		return
	}
	now := data.Str(g, "now")
	switch now {
	case "", "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE":
	default:
		return
	}
	all := map[string]bool{}
	for _, v := range data.List(g, "all") {
		if s, ok := v.(string); ok {
			all[s] = true
		}
	}
	if all[base.GSel] {
		_, _, _ = coreCall("PUT", "/proxies/GLOBAL", map[string]any{"name": base.GSel}, 5)
	}
}

// RetestSoon 重载/重启后核心的测速记录清空：稍后在后台用「🖐️ 手动选择」（select 组，不会清除 url-test 的固定）测一遍全部节点
func RetestSoon(waitSec int) {
	Retest.Lock()
	if Retest.Pending || nowSec()-Retest.Last < 60 {
		Retest.Unlock()
		return
	}
	Retest.Pending = true
	Retest.Unlock()
	go func() {
		defer func() {
			Retest.Lock()
			Retest.Pending = false
			Retest.Unlock()
		}()
		defer func() {
			if r := recover(); r != nil {
				// 定时测速中的 stub panic / 异常只记日志
			}
		}()
		for i := 0; i < 20; i++ {
			if i == 0 {
				time.Sleep(time.Duration(waitSec) * time.Second)
			} else {
				time.Sleep(3 * time.Second)
			}
			if coreAlive() {
				break
			}
		}
		FixGlobal()
		if coreJSON("/proxies/"+url.PathEscape(base.GManual), 5) != nil {
			_, _, _ = coreCall("GET", "/group/"+url.PathEscape(base.GManual)+"/delay?url="+url.QueryEscape(base.Hc)+"&timeout=5000", nil, 60)
		}
		Retest.Lock()
		Retest.Last = nowSec()
		Retest.Unlock()
		ProxiesMerged()
	}()
}

var bgURLRe = regexp.MustCompile(`(?s)^data:image/[\w.+-]+;base64,(.+)$`)

// BgSave data:image/...;base64,xxx → 保存背景图；只接受 JPEG / PNG / WebP / GIF
func BgSave(dataURL string) (bool, string) {
	m := bgURLRe.FindStringSubmatch(dataURL)
	if m == nil {
		return false, "图片格式不正确"
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(m[1]))
	if err != nil {
		if raw2, err2 := base64.RawStdEncoding.DecodeString(strings.TrimSpace(m[1])); err2 == nil {
			raw, err = raw2, nil
		}
	}
	if err != nil {
		return false, "图片数据无法解析"
	}
	if len(raw) > BgMax {
		return false, "图片不能超过 8MB"
	}
	if BgType(raw[:min(16, len(raw))]) == "" {
		return false, "只支持 JPG / PNG / WebP / GIF"
	}
	return writeBg(raw)
}

func writeBg(raw []byte) (bool, string) {
	tmp := BgFile + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return false, err.Error()
	}
	if err := os.Rename(tmp, BgFile); err != nil {
		return false, err.Error()
	}
	return true, "背景图已保存"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// BgMetaLoad 读链接背景图元信息
func BgMetaLoad() map[string]any {
	return data.ReadJSON(BgMeta, map[string]any{})
}

// BgMetaSave 保存链接背景图元信息（空则删除）
func BgMetaSave(m map[string]any) {
	if len(m) > 0 {
		tmp := BgMeta + ".tmp"
		raw, _ := json.Marshal(m)
		if err := os.WriteFile(tmp, raw, 0o644); err == nil {
			_ = os.Rename(tmp, BgMeta)
		}
	} else if _, err := os.Stat(BgMeta); err == nil {
		_ = os.Remove(BgMeta)
	}
}

var bgLinkRe = regexp.MustCompile(`^https?://\S+$`)

// BgFetch 由路由器下载图片链接保存为背景图（先走代理，失败再直连）
func BgFetch(rawurl string) (bool, string) {
	rawurl = strings.TrimSpace(rawurl)
	if !bgLinkRe.MatchString(rawurl) {
		return false, "请输入 http(s) 开头的图片链接"
	}
	if err := base.DlCheck(rawurl, false); err != nil { // SSRF 防护：禁止内网目标
		return false, err.Error()
	}
	var raw []byte
	errMsg := ""
	for _, useProxy := range []bool{true, false} {
		// 每次新建 Request：走代理时客户端把代理地址写进请求，复用会让直连也连到代理端口
		req, err := http.NewRequest("GET", rawurl, nil)
		if err != nil {
			errMsg = err.Error()
			continue
		}
		req.Header.Set("User-Agent", base.Ua)
		req.Header.Set("Accept", "image/avif,image/webp,image/*,*/*;q=0.8")
		client := proxyOpener(useProxy)
		client.Timeout = 20 * time.Second
		resp, err := client.Do(req)
		if err != nil {
			errMsg = firstLine(err.Error())
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, BgMax+1))
		resp.Body.Close()
		if err != nil {
			errMsg = firstLine(err.Error())
			continue
		}
		if resp.StatusCode >= 400 {
			errMsg = "HTTP " + resp.Status
			continue
		}
		raw = body
		break
	}
	if raw == nil {
		return false, "下载失败：" + orDefault(errMsg, "无法连接")
	}
	if len(raw) > BgMax {
		return false, "图片不能超过 8MB"
	}
	if BgType(raw[:min(16, len(raw))]) == "" {
		return false, "链接返回的不是 JPG / PNG / WebP / GIF 图片"
	}
	if ok, msg := writeBg(raw); !ok {
		return false, msg
	}
	return true, "背景图已下载到路由器"
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// BgType 按文件头识别图片类型
func BgType(head []byte) string {
	if len(head) >= 3 && head[0] == 0xff && head[1] == 0xd8 && head[2] == 0xff {
		return "image/jpeg"
	}
	if len(head) >= 8 && string(head[:8]) == "\x89PNG\r\n\x1a\n" {
		return "image/png"
	}
	if len(head) >= 12 && string(head[:4]) == "RIFF" && string(head[8:12]) == "WEBP" {
		return "image/webp"
	}
	if len(head) >= 4 && string(head[:4]) == "GIF8" {
		return "image/gif"
	}
	return ""
}

// ProxiesMerged /proxies + 订阅节点（mihomo 在 /providers/proxies，sing-box 由面板拼出）合并成一份，并补上缓存的延迟
func ProxiesMerged() map[string]map[string]any {
	a := coreJSON("/proxies", 8)
	if a == nil {
		return nil
	}
	px := map[string]map[string]any{}
	for k, v := range data.Map(a, "proxies") {
		if pm, ok := v.(map[string]any); ok {
			px[k] = pm
		}
	}
	provOk := false
	func() {
		defer func() { _ = recover() }()
		pj := ProvJSON()
		prov, ok := data.Map(pj, "providers"), pj != nil
		provOk = ok
		for _, pv := range prov {
			pvm, ok := pv.(map[string]any)
			if !ok {
				continue
			}
			for _, n := range data.List(pvm, "proxies") {
				nm, ok := n.(map[string]any)
				if !ok || data.Str(nm, "name") == "" {
					continue
				}
				cur := px[data.Str(nm, "name")]
				if cur == nil {
					px[data.Str(nm, "name")] = nm
				} else if _, _, hasCur := HistLast(cur); !hasCur {
					if _, _, hasNew := HistLast(nm); hasNew { // 同名节点：保留有测速记录的那份
						cur["history"] = nm["history"]
						cur["extra"] = nm["extra"]
					}
				}
			}
		}
	}()
	DelayMerge(px, provOk)
	groupTypes := map[string]bool{"Direct": true, "Reject": true, "RejectDrop": true, "Pass": true, "Compatible": true, "Dns": true}
	var nodes []map[string]any
	for _, p := range px {
		if _, isGroup := p["all"]; !isGroup && !groupTypes[data.Str(p, "type")] {
			nodes = append(nodes, p)
		}
	}
	hasDelay := false
	for _, p := range nodes {
		if _, ok := p["_d"]; ok {
			hasDelay = true
			break
		}
	}
	if len(nodes) > 0 && !hasDelay { // 一个延迟都没有（刚启动/刚重载）：后台补测
		RetestSoon(1)
	}
	return px
}

// ProvJSON 订阅节点（mihomo /providers/proxies 格式）；sing-box 由面板按缓存拼出同样的结构
func ProvJSON() map[string]any {
	if activeCore() == "singbox" {
		return sbFakeProviders(data.Load())
	}
	if pj := coreJSON("/providers/proxies", 8); pj != nil {
		return pj
	}
	return map[string]any{}
}

// CheckSubs 检查订阅到期与流量，必要时推送通知
func CheckSubs() {
	prov := data.Map(ProvJSON(), "providers")
	names := map[string]bool{}
	for _, s := range data.List(data.Load(), "subs") {
		if sm, ok := s.(map[string]any); ok {
			names[data.Str(sm, "name")] = true
		}
	}
	st := loadNotified()
	changed := false
	now := float64(nowSec())
	for name, p := range prov {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		si := data.Map(pm, "subscriptionInfo")
		if !names[name] || si == nil {
			continue
		}
		exp := float64(data.Int(si, "Expire"))
		k := "exp:" + name
		if exp > 0 && exp-now > 0 && exp-now < 3*86400 && data.Float(st, k) != exp {
			st[k] = exp
			changed = true
			notify("⏰ 订阅「" + name + "」将于 " + time.Unix(int64(exp), 0).Format("2006-01-02 15:04") + " 到期")
		}
		total := float64(data.Int(si, "Total"))
		used := float64(data.Int(si, "Upload") + data.Int(si, "Download"))
		k = "traffic:" + name
		high := total > 0 && used/total > 0.9
		if high && !data.Bool(st, k) {
			notify(fmt.Sprintf("📶 订阅「%s」流量已用 %.0f%%（%.1f / %.1f GB）", name, used/total*100, used/(1<<30), total/(1<<30)))
		}
		if high != data.Bool(st, k) {
			st[k] = high
			changed = true
		}
	}
	if changed {
		_ = data.WriteJSON(base.NotifyFile, st)
	}
}

// MonitorLoop 看门狗/节点/订阅/地区组监控循环
func MonitorLoop() {
	tk := time.NewTicker(time.Duration(base.WdInterval) * time.Second)
	defer tk.Stop()
	n := 0
	for range tk.C {
		n++
		tasks := []struct {
			fn    func()
			every int
		}{
			{watchdogTick, 1},
			{checkNodes, 20},
			{CheckSubs, 120},
			{func() { _, _ = refreshRegions() }, 20},
		}
		for _, t := range tasks {
			due := n%t.every == 0 || (t.every == 120 && n == 2)
			if !due {
				continue
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						// 监控任务异常只打印
					}
				}()
				st := wdStatus()
				// watchdog_tick 总是执行；其他任务只在核心 ok/off 时执行
				if t.every == 1 || st == "ok" || st == "off" {
					t.fn()
				}
			}()
		}
	}
}
