// Package health 对应 Python shunt/health.py：节点健康检查——定时测速，连续失败的节点标红/自动隐藏。
package health

import (
	"encoding/json"
	"net/url"
	"strconv"
	"sync"
	"time"

	"shunt/internal/base"
	"shunt/internal/corehttp"
	"shunt/internal/data"
)

// STUB:corehttp.core —— 接线到 corehttp.Core。
// corehttp.Core 把连接失败映射为 (502, 错误体)，永不抛错，因此 err 恒为 nil。
func coreCall(method, path string, body any, timeoutSec int) (int, []byte, error) {
	code, raw := corehttp.Core(method, path, body, timeoutSec)
	return code, raw, nil
}

// STUB:corehttp.core_json —— 接线到 corehttp.CoreJSON
func coreJSON(path string, timeoutSec int) map[string]any {
	return corehttp.CoreJSON(path, timeoutSec)
}

// HealthState 运行状态（对应 HEALTH_STATE）
var HealthState = struct {
	sync.Mutex
	Running bool
	LastRun int64
	Total   int
	Checked int
}{}

// DefaultCfg 默认健康检查配置
var DefaultCfg = map[string]any{"enabled": false, "time": "03:00", "warn_days": 3, "hide_days": 7}

// HealthCfg 读取健康检查配置（data.json 的 health_cfg 字段）
func HealthCfg(d map[string]any) map[string]any {
	if d == nil {
		d = data.Load()
	}
	cfg := map[string]any{}
	for k, v := range DefaultCfg {
		cfg[k] = v
	}
	for k, v := range data.Map(d, "health_cfg") {
		cfg[k] = v
	}
	return cfg
}

// SaveHealthCfg 保存健康检查配置（与其他写入共用 data.Update，不会和同时保存的设置互相覆盖）
func SaveHealthCfg(cfg map[string]any) {
	cp := map[string]any{}
	for k, v := range cfg {
		cp[k] = v
	}
	data.Update(func(d map[string]any) {
		d["health_cfg"] = cp
	})
}

func today() string { return time.Now().Format("2006-01-02") }

// RecordOne 更新单个节点的健康记录。成功：清零并取消隐藏；失败：按天去重计数
func RecordOne(rec map[string]any, ok bool, latency int) map[string]any {
	if rec == nil {
		rec = map[string]any{}
	}
	if ok {
		rec["fail_days"] = 0
		rec["fail_dates"] = []any{}
		rec["hidden"] = false
		rec["last_ok"] = time.Now().Unix()
		if latency != 0 {
			rec["latency"] = latency
		}
	} else {
		var dates []string
		seen := map[string]bool{}
		for _, v := range data.List(rec, "fail_dates") {
			if s, ok := v.(string); ok && !seen[s] {
				seen[s] = true
				dates = append(dates, s)
			}
		}
		t := today()
		if !seen[t] {
			dates = append(dates, t)
			// 只保留最近 30 天的记录
			if len(dates) > 30 {
				dates = dates[len(dates)-30:]
			}
		}
		var arr []any
		for _, s := range dates {
			arr = append(arr, s)
		}
		rec["fail_dates"] = arr
		rec["fail_days"] = len(dates)
		rec["last_fail"] = time.Now().Unix()
	}
	return rec
}

// ApplyResults 合并一次全量测速结果：{node_name: latency_ms(0=失败)}。
// universe：当前全部节点名；给出时只删除不在其中的节点记录（失败节点保留并计数），
// 不给时按 results 的键清理（兼容旧调用）。
// d 给出时只在这份数据上合并（不落盘）；否则在 data.Update() 的锁内读-改-写 data.json
func ApplyResults(results map[string]int, d map[string]any, universe []string) map[string]any {
	var out map[string]any
	merge := func(dd map[string]any) {
		cfg := HealthCfg(dd)
		health := data.Map(dd, "health")
		if health == nil {
			health = map[string]any{}
		}
		for name, latency := range results {
			rec, _ := health[name].(map[string]any)
			if rec == nil {
				rec = map[string]any{"fail_days": 0, "fail_dates": []any{}, "hidden": false}
			}
			RecordOne(rec, latency > 0, latency)
			// 自动隐藏达到阈值的节点
			if data.Int(rec, "fail_days") >= cfgInt(cfg, "hide_days", 7) {
				rec["hidden"] = true
			}
			health[name] = rec
		}
		// 清理已删除节点的记录
		allNodes := map[string]bool{}
		if universe == nil {
			for name := range results {
				allNodes[name] = true
			}
		} else {
			for _, name := range universe {
				allNodes[name] = true
			}
			for name := range results {
				allNodes[name] = true
			}
		}
		for name := range health {
			if !allNodes[name] {
				delete(health, name)
			}
		}
		dd["health"] = health
		out = health
	}
	if d != nil {
		merge(d)
	} else {
		data.Update(merge)
	}
	return out
}

func cfgInt(cfg map[string]any, k string, def int) int {
	if cfg == nil {
		return def
	}
	if _, ok := cfg[k]; !ok {
		return def
	}
	return data.Int(cfg, k)
}

// MergeDelay 把 /group/…/delay 的应答整理成 {节点: 延迟(0=失败)}。
// mihomo 与 sing-box 的 clash API 都只返回测速成功的节点，失败的直接缺席；
// mihomo 全部失败时返回 504，sing-box 返回空对象。全集取自组的 all 成员，缺席的记为失败
func MergeDelay(members []string, code int, payload map[string]any) map[string]int {
	ok := map[string]any{}
	if code == 200 && payload != nil {
		ok = payload
	}
	var nodes []string
	if members != nil {
		nodes = members
	} else {
		for k := range ok {
			nodes = append(nodes, k)
		}
	}
	results := map[string]int{}
	for _, n := range nodes {
		if base.BuiltinPolicies[n] {
			continue
		}
		v := 0
		switch x := ok[n].(type) {
		case float64:
			if x > 0 && x == float64(int(x)) {
				v = int(x)
			}
		case int:
			if x > 0 {
				v = x
			}
		}
		results[n] = v
	}
	return results
}

// Unhide 手动取消隐藏节点，清零计数重新评估
func Unhide(name string) bool {
	d := data.Load()
	if _, ok := data.Map(d, "health")[name]; !ok {
		return false
	}
	found := false
	data.Update(func(dd map[string]any) {
		health := data.Map(dd, "health")
		if health == nil {
			return
		}
		if rec, ok := health[name].(map[string]any); ok {
			rec["hidden"] = false
			rec["fail_days"] = 0
			rec["fail_dates"] = []any{}
			dd["health"] = health
			found = true
		}
	})
	return found
}

// GetRecords 返回所有节点的健康记录
func GetRecords(d map[string]any) map[string]any {
	if d == nil {
		d = data.Load()
	}
	if h := data.Map(d, "health"); h != nil {
		return h
	}
	return map[string]any{}
}

// RunCheck 执行一次全量健康检查：经核心 delay 接口批量测速
func RunCheck() (bool, string) {
	HealthState.Lock()
	HealthState.Running = true
	HealthState.Checked = 0
	HealthState.Unlock()
	defer func() {
		HealthState.Lock()
		HealthState.Running = false
		HealthState.Unlock()
	}()
	// 用「🖐️ 手动选择」组测速（含全部节点），不影响 url-test 组的固定选择
	pg := coreJSON("/proxies/"+url.PathEscape(base.GManual), 8)
	if pg == nil {
		return false, "手动选择组不存在"
	}
	var members []string
	for _, v := range data.List(pg, "all") {
		if s, ok := v.(string); ok {
			members = append(members, s)
		}
	}
	code, raw, err := coreCall("GET", "/group/"+url.PathEscape(base.GManual)+"/delay?url="+url.QueryEscape(base.Hc)+"&timeout=5000", nil, 180)
	if err != nil {
		return false, "测速接口异常：" + err.Error()
	}
	if code != 200 && code != 504 { // 504：mihomo 全部节点超时，按全部失败记录
		return false, "测速接口返回 " + strconv.Itoa(code)
	}
	var payload map[string]any
	if code == 200 {
		if err := json.Unmarshal(raw, &payload); err != nil {
			return false, "测速结果解析失败"
		}
	}
	results := MergeDelay(members, code, payload)
	if len(results) == 0 {
		return false, "手动选择组里没有节点"
	}
	HealthState.Lock()
	HealthState.Total = len(results)
	HealthState.Checked = len(results)
	HealthState.Unlock()
	var universe []string
	for name := range results {
		universe = append(universe, name)
	}
	ApplyResults(results, nil, universe)
	HealthState.Lock()
	HealthState.LastRun = time.Now().Unix()
	HealthState.Unlock()
	okCount := 0
	for _, v := range results {
		if v > 0 {
			okCount++
		}
	}
	return true, "检查完成：" + strconv.Itoa(okCount) + "/" + strconv.Itoa(len(results)) + " 个节点正常"
}

// RunCheckBg 后台 goroutine 执行检查，调用立即返回
func RunCheckBg() bool {
	HealthState.Lock()
	defer HealthState.Unlock()
	if HealthState.Running {
		return false
	}
	go RunCheck()
	return true
}
