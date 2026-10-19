// Package schedule 对应 Python shunt/schedule.py：定时任务。
package schedule

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"shunt/internal/adblock"
	"shunt/internal/base"
	"shunt/internal/core"
	"shunt/internal/corehttp"
	"shunt/internal/data"
	"shunt/internal/devroute"
	"shunt/internal/errlog"
	"shunt/internal/groups"
	"shunt/internal/health"
	"shunt/internal/latency"
	"shunt/internal/notify"
	"shunt/internal/singbox"
	"shunt/internal/sysopt"
)

// ---- 跨包 stub 接线（对应各包的导出函数，直接调用）----

// STUB:errlog.log_err
var logErr = func(what string, err error) { errlog.LogErr(what, err, false) }

// STUB:core.refresh_regions
var refreshRegions = core.RefreshRegions

// STUB:core.reload_core（prev 缺省 nil，对应 Python reload_core(prev=None)）
var reloadCore = func() (bool, string) { return core.ReloadCore(nil) }

// STUB:corehttp.core（corehttp.Core 不返回 error，失败用 502 状态码表示）
var coreCall = func(method, path string, body any, timeoutSec int) (int, []byte, error) {
	code, raw := corehttp.Core(method, path, body, timeoutSec)
	return code, raw, nil
}

// STUB:corehttp.core_json
var coreJSON = corehttp.CoreJSON

// STUB:sb_common.active_core（singbox.ActiveCore 为变参，需包装）
var activeCore = func(d map[string]any) string { return singbox.ActiveCore(d) }

// STUB:groups.sb_sub_cache
var sbSubCache = groups.SbSubCache

// STUB:sb_subs.sb_update_subs
var sbUpdateSubs = singbox.SbUpdateSubs

// STUB:sb_config.sb_sync_assets（need 为 nil 时内部自动计算）
var sbSyncAssets = func(d map[string]any, force bool) []string {
	return singbox.SbSyncAssets(d, force, nil)
}

// STUB:sysopt.svc_restart
var svcRestart = sysopt.SvcRestart

// STUB:notify.WD["manual_stop"]
var wdManualStop = notify.ManualStop

// STUB:devroute.mac_changed（(map[string][]string, bool) 转为 map[string]any / nil）
var macChanged = func(d map[string]any) map[string]any {
	m, changed := devroute.MacChanged(d)
	if !changed {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ---------- 状态 ----------

// Event 定时任务事件
type Event struct {
	T   int64  `json:"t"`
	Msg string `json:"msg"`
}

// Sched 事件（最多 30 条）与各任务上次执行时间
var Sched = struct {
	sync.Mutex
	Events []Event
	Done   map[string]float64
}{Done: map[string]float64{}}

// TaskNames 任务名映射
var TaskNames = map[string]string{
	"sub_update": "定时更新订阅", "core_restart": "定时重启核心", "geo_update": "定时更新 GEO",
	"latency": "自动测速", "adblock": "更新广告规则", "health": "节点健康检查",
}

// DailyFile 每天定点任务的最近执行记录（面板重启后不会把今天已跑过的任务再跑一遍）
var DailyFile = filepath.Join(base.PanelDir, "sched_done.json")

var (
	dailyMu   sync.Mutex
	dailyData map[string]any
	hhmmRe    = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)
)

func nowFloat() float64 { return float64(time.Now().UnixNano()) / 1e9 }

// withDaily 在锁内访问每天任务记录（懒加载）
func withDaily(fn func(d map[string]any)) {
	dailyMu.Lock()
	defer dailyMu.Unlock()
	if dailyData == nil {
		dailyData = data.ReadJSON(DailyFile, map[string]any{})
		if dailyData == nil {
			dailyData = map[string]any{}
		}
	}
	fn(dailyData)
}

func dailySetLocked(d map[string]any, k, date, at string) {
	d[k] = map[string]any{"date": date, "at": at}
	if err := data.WriteJSON(DailyFile, d); err != nil {
		logErr("保存定时任务记录", err)
	}
}

// DailyDue 每天定点任务是否该执行：到点或已过点（当天补跑）且今天还没跑过；返回 True 时已记为今天执行过（不会重复触发）。
//   - 原来要求当前 HH:MM 正好等于设定值：循环被长任务卡住跨过那一分钟，当天就漏跑了
//   - 第一次见到这个任务、或设定时刻刚被改过，而今天的时刻已经过了：记为今天已执行，从下一次开始
//     （刚升级 / 开机 / 改时间时不会立刻把今天错过的任务全跑一遍，比如定时重启）
//   - 设定时刻无效（如 25:00）或为空：永不触发
func DailyDue(k, at, nowHm, today string) bool {
	if at == "" || !hhmmRe.MatchString(at) {
		return false
	}
	due := false
	withDaily(func(d map[string]any) {
		rec, _ := d[k].(map[string]any)
		if rec != nil && data.Str(rec, "date") == today {
			if data.Str(rec, "at") != at { // 今天已经跑过、之后改了时刻：只更新记录，明天按新时刻
				dailySetLocked(d, k, today, at)
			}
			return
		}
		if nowHm < at { // 还没到点：记下设定时刻，到点时才认得出「这是没改过的时刻」
			if rec == nil || data.Str(rec, "at") != at {
				prevDate := ""
				if rec != nil {
					prevDate = data.Str(rec, "date")
				}
				dailySetLocked(d, k, prevDate, at)
			}
			return
		}
		if rec == nil || data.Str(rec, "at") != at {
			dailySetLocked(d, k, today, at)
			return
		}
		dailySetLocked(d, k, today, at)
		due = true
	})
	return due
}

// SchedEvent 记录一条定时任务事件（保留最近 30 条）
func SchedEvent(msg string) {
	Sched.Lock()
	Sched.Events = append([]Event{{T: time.Now().Unix(), Msg: msg}}, Sched.Events...)
	if len(Sched.Events) > 30 {
		Sched.Events = Sched.Events[:30]
	}
	Sched.Unlock()
	fmt.Printf("%s [schedule] %s\n", time.Now().Format("2006-01-02 15:04:05"), msg)
}

// SubsUpdate 更新订阅（names 为空 = 全部）并刷新地区组：sing-box 由面板下载，mihomo 让核心重新拉取。
// 返回 (成功列表, 失败列表「名称：原因」, 刷新地区组的提示)；where 给出时刷新地区组出错只记日志不抛出
func SubsUpdate(names []string, d map[string]any, where string) ([]string, []string, string) {
	if d == nil {
		d = data.Load()
	}
	var okl, bad []string
	if activeCore(d) == "singbox" {
		okl, bad = sbUpdateSubs(names, d)
	} else {
		targets := names
		if len(targets) == 0 {
			for _, s := range data.List(d, "subs") {
				if sm, ok := s.(map[string]any); ok {
					targets = append(targets, data.Str(sm, "name"))
				}
			}
		}
		for _, nm := range targets {
			code, raw, err := coreCall("PUT", "/providers/proxies/"+url.PathEscape(nm), nil, 120)
			if err != nil || code >= 300 {
				reason := ""
				if err != nil {
					reason = err.Error()
				} else {
					reason = string(raw)
				}
				bad = append(bad, nm+"："+firstNRunes(reason, 100))
			} else {
				okl = append(okl, nm)
			}
		}
	}
	msg := ""
	func() {
		defer func() {
			if r := recover(); r != nil {
				if where == "" {
					panic(r)
				}
				logErr(where, fmt.Errorf("%v", r))
				msg = ""
			}
		}()
		_, msg = refreshRegions()
	}()
	return okl, bad, msg
}

func firstNRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

func lastNRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[len(r)-n:])
	}
	return s
}

// RunTask 执行一个定时任务，返回 (ok, msg)
func RunTask(name string) (bool, string) {
	d := data.Load()
	switch name {
	case "sub_update":
		_, bad, _ := SubsUpdate(nil, d, "定时任务：刷新地区分组")
		if len(bad) == 0 {
			return true, "订阅已更新"
		}
		return false, "以下订阅更新失败：" + strings.Join(bad, "；")
	case "geo_update":
		if activeCore(d) == "singbox" {
			bad := sbSyncAssets(d, true)
			ok, _ := reloadCore()
			if len(bad) == 0 {
				return ok, "GEO / 规则集已更新"
			}
			return false, "部分规则集更新失败：" + firstNRunes(strings.Join(bad, "；"), 200)
		}
		code, raw, err := coreCall("POST", "/configs/geo", map[string]any{}, 180)
		if err != nil {
			return false, firstNRunes(err.Error(), 200)
		}
		if code < 300 {
			return true, "GEO 数据库已更新"
		}
		return false, firstNRunes(string(raw), 200)
	case "core_restart":
		if wdManualStop() { // 用户手动停止了核心：定时重启不能替用户把它拉起来
			return true, "核心已手动停止，跳过定时重启"
		}
		code, out := svcRestart(90, "定时重启核心", wdManualStop)
		if code == 0 {
			return true, "核心已重启"
		}
		return false, lastNRunes(out, 200)
	case "latency":
		// GLOBAL 只含 config 里的节点和策略组，订阅节点要经「🖐️ 手动选择」（含全部节点）测速
		code, _, _ := coreCall("GET", "/group/GLOBAL/delay?url="+url.QueryEscape(base.Hc)+"&timeout=5000", nil, 120)
		n := 0
		if coreJSON("/proxies/"+url.PathEscape(base.GManual), 8) != nil {
			c2, r2, _ := coreCall("GET", "/group/"+url.PathEscape(base.GManual)+"/delay?url="+url.QueryEscape(base.Hc)+"&timeout=5000", nil, 120)
			if c2 == 200 {
				var m map[string]any
				if err := json.Unmarshal(r2, &m); err == nil {
					for _, v := range m {
						if f, ok := v.(float64); ok && f > 0 && f == float64(int(f)) {
							n++
						}
					}
				}
			}
			if code == 200 || c2 == 200 || c2 == 504 {
				code = 200
			}
		}
		return code == 200, fmt.Sprintf("节点测速完成，%d 个节点可达", n)
	case "adblock":
		return adblock.AdblockUpdate(nil, true)
	case "health":
		return health.RunCheck()
	}
	return false, "未知任务"
}

// SchedLoop 定时任务主循环（20 秒一轮）
func SchedLoop() {
	tk := time.NewTicker(20 * time.Second)
	defer tk.Stop()
	n := 0
	for range tk.C {
		n++
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Println("schedule error", r)
				}
			}()
			schedTick(n)
		}()
	}
}

func schedTick(n int) {
	d := data.Load()
	sc := data.Map(d, "schedule")
	if sc == nil {
		sc = map[string]any{}
	}
	now := time.Now().Format("15:04")
	today := time.Now().Format("2006-01-02")
	var due []string
	for _, k := range []string{"sub_update", "core_restart", "geo_update"} {
		if DailyDue(k, data.Str(sc, k), now, today) {
			due = append(due, k)
		}
	}
	// 节点健康检查：每天到点且启用时执行（已过点、今天还没跑也补跑）
	hcfg := health.HealthCfg(d)
	if data.Bool(hcfg, "enabled") && DailyDue("health", data.Str(hcfg, "time"), now, today) {
		due = append(due, "health")
	}
	if mins := data.Int(sc, "latency"); mins > 0 {
		Sched.Lock()
		last := Sched.Done["latency"]
		Sched.Unlock()
		if nowFloat()-last >= float64(mins*60) {
			due = append(due, "latency")
		}
	}
	if activeCore(d) == "singbox" && len(data.List(d, "subs")) > 0 { // mihomo 的订阅由核心按间隔自动更新；sing-box 由面板代劳
		iv := data.Int(d, "sub_interval")
		if iv == 0 {
			iv = 86400
		}
		if iv < 600 {
			iv = 600
		}
		last := 0.0
		first := true
		for _, s := range data.List(d, "subs") {
			if sm, ok := s.(map[string]any); ok {
				u := data.Float(sbSubCache(data.Str(sm, "name")), "updated")
				if first || u < last {
					last, first = u, false
				}
			}
		}
		Sched.Lock()
		sbDone := Sched.Done["sb_subs"]
		Sched.Unlock()
		if sbDone > last {
			last = sbDone
		}
		if nowFloat()-last >= float64(iv) {
			Sched.Lock()
			Sched.Done["sb_subs"] = nowFloat()
			Sched.Unlock()
			_, bad_, _ := SubsUpdate(nil, d, "")
			if len(bad_) > 0 {
				SchedEvent("订阅自动更新：✗ " + firstNRunes(strings.Join(bad_, "；"), 200))
			}
		}
	}
	bm := latency.BgMetaLoad()
	if data.Bool(bm, "daily") && data.Str(bm, "url") != "" {
		Sched.Lock()
		bgDone := Sched.Done["bg"]
		Sched.Unlock()
		last := float64(data.Int(bm, "t"))
		if bgDone > last {
			last = bgDone
		}
		if nowFloat()-last >= 86400 {
			Sched.Lock()
			Sched.Done["bg"] = nowFloat() // 失败也等一天，避免反复重试
			Sched.Unlock()
			if ok, _ := latency.BgFetch(data.Str(bm, "url")); ok {
				bm["t"] = time.Now().Unix()
				latency.BgMetaSave(bm)
			}
		}
	}
	ab := data.Map(d, "adblock")
	if ab != nil && data.Bool(ab, "enabled") && len(data.List(ab, "lists")) > 0 && data.Int(ab, "interval") > 0 {
		adblock.ABState.Lock()
		abLast := adblock.ABState.Last
		adblock.ABState.Unlock()
		lastBase := float64(abLast)
		if m := float64(AbLastUpdate()); m > lastBase {
			lastBase = m
		}
		if nowFloat()-lastBase >= float64(data.Int(ab, "interval")) {
			due = append(due, "adblock")
		}
	}
	if n%3 == 0 { // 每分钟：按设备分流里 MAC 对应的 IP 变了就重新生成配置
		DevrouteTick(d)
	}
	for _, k := range due {
		if k == "latency" {
			Sched.Lock()
			Sched.Done[k] = nowFloat()
			Sched.Unlock()
		}
		if k == "adblock" {
			adblock.ABState.Lock()
			adblock.ABState.Last = time.Now().Unix() // 失败也等下一个周期，避免频繁重试
			adblock.ABState.Unlock()
		}
		ok, msg := RunTask(k)
		if k != "latency" || !ok {
			mark := "✓"
			if !ok {
				mark = "✗"
			}
			SchedEvent(TaskNames[k] + "：" + mark + " " + msg)
		}
	}
}

var devrouteState = struct {
	sync.Mutex
	tried map[string]any
	has   bool
}{}

// DevrouteTick 按设备分流的 MAC 条目：ARP / DHCP / IPv6 邻居表解析出的 IP 与当前配置不同时重载核心。
// 只读 /proc/net/arp 和租约文件（开 IPv6 时多跑一次 ip -6 neigh），没有 MAC 条目时什么都不做
func DevrouteTick(d map[string]any) {
	if wdManualStop() {
		return
	}
	cur := macChanged(d)
	if cur == nil {
		return
	}
	devrouteState.Lock()
	same := devrouteState.has && reflect.DeepEqual(devrouteState.tried, cur)
	if !same {
		devrouteState.tried, devrouteState.has = cur, true
	}
	devrouteState.Unlock()
	if same { // 上次因 MAC 解析变化而重载时的解析结果：重载失败也不对同一结果反复重试
		return
	}
	ok, msg := reloadCore()
	if ok {
		SchedEvent("按设备分流：设备 IP 有变化，已更新配置")
	} else {
		SchedEvent("按设备分流：设备 IP 有变化，更新配置失败 " + firstNRunes(msg, 120))
	}
}

// AbLastUpdate 各广告列表最近一次成功更新时间的最大值
func AbLastUpdate() int64 {
	var max int64
	for _, v := range adblock.AbMeta() {
		if vm, ok := v.(map[string]any); ok {
			if u := int64(data.Int(vm, "updated")); u > max {
				max = u
			}
		}
	}
	return max
}
