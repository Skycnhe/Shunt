// Package data 对应 Python shunt/data.py：data.json 读写、规范化、配置快照与地区组名工具。
package data

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"shunt/internal/base"
	"shunt/internal/ruleutil"
)

var (
	HistoryFile = filepath.Join(base.PanelDir, "history.json")
	HistoryMax  = 10
	HistorySkip = map[string]bool{
		"tests_rev": true, "core": true, "secret": true, "devices": true,
		"https": true, "schema": true, "sysopt": true, "sysopt_orig": true,
		"sysopt_mods": true, "health": true, "health_cfg": true,
	}
	KeyLabel = map[string]string{
		"subs": "订阅", "nodes": "节点", "rules": "自定义规则", "rulesets": "规则集",
		"dns": "DNS", "adblock": "广告拦截", "custom_groups": "自定义策略组",
		"groups_cfg": "地区分组", "region_groups": "地区分组", "proxy_mode": "代理方式",
		"tun": "TUN", "ipv6": "IPv6", "bypass": "绕过设备", "mode": "代理模式",
		"sniffer": "域名嗅探", "schedule": "定时任务", "tests": "延迟站点",
		"device_routes": "按设备分流", "sub_interval": "订阅间隔",
		"tg_token": "Telegram", "tg_chat": "Telegram", "watchdog": "看门狗",
		"log_limit": "日志上限", "gh_proxy": "GitHub 加速", "tproxy": "代理方式",
	}

	LbKinds   = [][2]string{{"consistent-hashing", "哈希"}}
	LbDropped = [][2]string{{"round-robin", "轮询"}, {"sticky-sessions", "粘性"}}
)

var (
	mu          sync.Mutex // 对应 LOCK（可重入场景已拆分为内部 locked 版本）
	historyLock sync.Mutex

	dataCache struct {
		sync.Mutex
		key string
		gen int
		txt string
	}
	dataGen    int
	configVer  int
	permsFixed bool
	oldPwKeys  = []string{"password", "pw_hash", "pw_default"}
	nonWordRe  = regexp.MustCompile(`[^\w\-]`)
)

// ---------- 类型安全访问 ----------

func Str(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func Int(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return 0
}

func Bool(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	b, _ := m[key].(bool)
	return b
}

func Float(m map[string]any, key string) float64 {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	}
	return 0
}

func List(m map[string]any, key string) []any {
	if m == nil {
		return nil
	}
	l, _ := m[key].([]any)
	return l
}

func Map(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	mm, _ := m[key].(map[string]any)
	return mm
}

// Strs 取字符串列表
func Strs(m map[string]any, key string) []string {
	var out []string
	for _, v := range List(m, key) {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ---------- 读写 ----------

func dataKey() string {
	st, err := os.Stat(base.DataFile)
	if err != nil {
		return ""
	}
	return base.DataFile + "|" + strconv.FormatInt(st.ModTime().UnixNano(), 10) + "|" + strconv.FormatInt(st.Size(), 10)
}

// Load 返回 data.json 的一份独立副本（调用方可随意修改）
func Load() map[string]any {
	fixLegacyPerms()
	key := dataKey()
	dataCache.Lock()
	gen := dataGen
	if key != "" && dataCache.key == key && dataCache.gen == gen && dataCache.txt != "" {
		txt := dataCache.txt
		dataCache.Unlock()
		var d map[string]any
		_ = json.Unmarshal([]byte(txt), &d)
		return d
	}
	dataCache.Unlock()
	d := loadUncached()
	if key != "" {
		if txt, err := json.Marshal(d); err == nil {
			dataCache.Lock()
			dataCache.key, dataCache.gen, dataCache.txt = key, gen, string(txt)
			dataCache.Unlock()
		}
	}
	return d
}

func loadUncached() map[string]any {
	var d map[string]any
	if raw, err := os.ReadFile(base.DataFile); err == nil {
		_ = json.Unmarshal(raw, &d)
	}
	if d == nil {
		d = map[string]any{}
	}
	for k, v := range base.Default {
		if _, ok := d[k]; !ok {
			d[k] = deepCopy(v)
		} else if k != "devices" {
			if dm, ok := d[k].(map[string]any); ok {
				if vm, ok := v.(map[string]any); ok {
					for kk, vv := range vm {
						if _, ok := dm[kk]; !ok {
							dm[kk] = deepCopy(vv)
						}
					}
				}
			}
		}
	}
	if !contains(base.ProxyModes, Str(d, "proxy_mode")) {
		if Bool(d, "tproxy") {
			d["proxy_mode"] = "tproxy"
		} else {
			d["proxy_mode"] = "off"
		}
	}
	d["tproxy"] = Str(d, "proxy_mode") == "tproxy"
	dirty := false
	if len(List(d, "tests")) == 0 {
		d["tests"] = deepCopy(base.TestsDefault)
		d["tests_rev"] = 2
		dirty = true
	} else if Int(d, "tests_rev") < 2 {
		cur := [][2]string{}
		for _, t := range List(d, "tests") {
			if tm, ok := t.(map[string]any); ok {
				cur = append(cur, [2]string{Str(tm, "name"), Str(tm, "url")})
			}
		}
		base5 := [][2]string{}
		for i := 0; i < 5 && i < len(base.TestsDefault); i++ {
			if tm, ok := base.TestsDefault[i].(map[string]any); ok {
				base5 = append(base5, [2]string{Str(tm, "name"), Str(tm, "url")})
			}
		}
		if equalPairs(cur, base5) {
			if len(base.TestsDefault) > 5 {
				d["tests"] = append(List(d, "tests"), deepCopy(base.TestsDefault[5]))
			}
		} else if len(cur) == 6 && equalPairs(cur[:5], base5) &&
			cur[5] == [2]string{"哔哩哔哩", "https://www.bilibili.com"} {
			lst := List(d, "tests")
			lst[5] = deepCopy(base.TestsDefault[5])
			d["tests"] = lst
		}
		d["tests_rev"] = 2
		dirty = true
	}
	for _, k := range oldPwKeys {
		if _, ok := d[k]; ok {
			delete(d, k)
			dirty = true
		}
	}
	if Str(d, "secret") == "" {
		d["secret"] = tokenHex(16)
		dirty = true
	}
	if Int(d, "schema") < base.Schema {
		gc := Map(d, "groups_cfg")
		if gc == nil {
			gc = map[string]any{}
			d["groups_cfg"] = gc
		}
		gc["strategy"] = "consistent-hashing"
		if Int(d, "schema") < 9 {
			if gc["interval"] == nil || Int(gc, "interval") == 300 {
				gc["interval"] = 60
			}
			if gc["tolerance"] == nil || Int(gc, "tolerance") == 50 {
				gc["tolerance"] = 0
			}
		}
		MigrateNames(d)
		for _, g := range List(d, "custom_groups") {
			if gm, ok := g.(map[string]any); ok && Str(gm, "type") == "load-balance" {
				gm["strategy"] = "consistent-hashing"
			}
		}
		d["schema"] = base.Schema
		dirty = true
	}
	if dirty {
		saveLocked(d)
	}
	return d
}

// Save 原子写 data.json（600 权限），并使缓存 / 配置版本失效
func Save(d map[string]any) {
	mu.Lock()
	defer mu.Unlock()
	saveLocked(d)
}

func saveLocked(d map[string]any) {
	_ = os.MkdirAll(filepath.Dir(base.DataFile), 0o755)
	tmp := base.DataFile + ".tmp"
	raw, _ := json.MarshalIndent(d, "", "  ")
	_ = os.WriteFile(tmp, raw, 0o600)
	_ = os.Chmod(tmp, 0o600)
	_ = os.Rename(tmp, base.DataFile)
	dataGen++
	dataCache.Lock()
	dataCache.txt = ""
	dataCache.Unlock()
	configVer++
}

// ConfigVersion data.json 每次 save() 自增：/api/ping 用它判断配置是否变化
func ConfigVersion() int {
	mu.Lock()
	defer mu.Unlock()
	return configVer
}

// Update 在锁内读-改-写 data.json，返回修改前的副本
func Update(fn func(d map[string]any)) map[string]any {
	mu.Lock()
	d := loadUncached()
	prev := deepCopyMap(d)
	fn(d)
	saveLocked(d)
	mu.Unlock()
	historyLock.Lock()
	defer historyLock.Unlock()
	if err := historyPush(prev, d); err != nil {
		println("history error", err.Error())
	}
	return prev
}

// HistoryPush 对外：手动记一次快照
func HistoryPush(prev, cur map[string]any) error {
	historyLock.Lock()
	defer historyLock.Unlock()
	return historyPush(prev, cur)
}

func historyPush(prev, cur map[string]any) error {
	var keys []string
	for k := range unionKeys(prev, cur) {
		if HistorySkip[k] {
			continue
		}
		if !jsonEqual(prev[k], cur[k]) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	h := ReadJSON(HistoryFile, []any{})
	snap := map[string]any{}
	for k, v := range prev {
		if !HistorySkip[k] {
			snap[k] = v
		}
	}
	if len(h) > 0 {
		if hm, ok := h[0].(map[string]any); ok && jsonEqual(hm["data"], snap) {
			return nil
		}
	}
	var labels []string
	seen := map[string]bool{}
	for _, k := range keys {
		lb := KeyLabel[k]
		if lb == "" {
			lb = k
		}
		if !seen[lb] {
			seen[lb] = true
			labels = append(labels, lb)
		}
	}
	entry := map[string]any{
		"id": tokenHex(4), "t": time.Now().Unix(),
		"changed": labels, "data": snap,
	}
	h = append([]any{entry}, h...)
	if len(h) > HistoryMax {
		h = h[:HistoryMax]
	}
	return WriteJSON(HistoryFile, h, 0o600)
}

// ReadJSON 读 JSON 文件，失败返回默认值
func ReadJSON[T any](path string, def T) T {
	raw, err := os.ReadFile(path)
	if err != nil {
		return def
	}
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		return def
	}
	return v
}

// WriteJSON 原子写 JSON，默认 600
func WriteJSON(path string, obj any, mode ...os.FileMode) error {
	m := os.FileMode(0o600)
	if len(mode) > 0 {
		m = mode[0]
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	raw, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, m); err != nil {
		return err
	}
	_ = os.Chmod(tmp, m)
	return os.Rename(tmp, path)
}

// Safe 文件名安全化
func Safe(name string) string {
	s := nonWordRe.ReplaceAllString(name, "_")
	if s == "" {
		return "sub"
	}
	return s
}

func fixLegacyPerms() {
	if permsFixed {
		return
	}
	permsFixed = true
	paths := []string{HistoryFile, filepath.Join(base.PanelDir, "sub-debug.txt")}
	if es, err := os.ReadDir(filepath.Join(base.PanelDir, "sb_subs")); err == nil {
		for _, e := range es {
			if strings.HasSuffix(e.Name(), ".json") {
				paths = append(paths, filepath.Join(base.PanelDir, "sb_subs", e.Name()))
			}
		}
	}
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			_ = os.Chmod(p, 0o600)
		}
	}
}

// ---------- 内部工具 ----------

func deepCopy(v any) any {
	raw, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(raw, &out)
	return out
}

func deepCopyMap(m map[string]any) map[string]any {
	raw, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out == nil {
		out = map[string]any{}
	}
	return out
}

func jsonEqual(a, b any) bool {
	ra, _ := json.Marshal(a)
	rb, _ := json.Marshal(b)
	return string(ra) == string(rb)
}

func unionKeys(a, b map[string]any) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func equalPairs(a, b [][2]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func tokenHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---------- 地区组名工具 ----------

// RegionLabel 「🇺🇸 美国」→ (「🇺🇸」, 「美国」)
func RegionLabel(rname string) (string, string) {
	flag, label, _ := strings.Cut(rname, " ")
	return flag, label
}

// AutoName 「🇯🇵 日本竞技」：url-test，始终选延迟最低的节点
func AutoName(rname string, tail ...string) string {
	t := base.AutoTail
	if len(tail) > 0 {
		t = tail[0]
	}
	flag, label := RegionLabel(rname)
	return flag + " " + label + t
}

// LbName 「⚖️ 日本哈希」（旧版还有「⚖️ 日本轮询」「⚖️ 日本粘性」）
func LbName(rname, strategy string) string {
	if strategy == "" {
		strategy = "consistent-hashing"
	}
	_, label := RegionLabel(rname)
	return base.LbPrefix + label + lbAll()[strategy]
}

func lbAll() map[string]string {
	m := map[string]string{}
	for _, k := range LbKinds {
		m[k[0]] = k[1]
	}
	for _, k := range LbDropped {
		m[k[0]] = k[1]
	}
	return m
}

// LbNames 当前策略的负载均衡组名
func LbNames(rname string) []string {
	var out []string
	for _, k := range LbKinds {
		out = append(out, LbName(rname, k[0]))
	}
	return out
}

// LbDroppedNames 已下线的轮询/粘性组名（仅迁移用）
func LbDroppedNames(rname string) []string {
	var out []string
	for _, k := range LbDropped {
		out = append(out, LbName(rname, k[0]))
	}
	return out
}

// LbOldName v6.6.8 及以前的单个「⚖️ 日本负载均衡」组
func LbOldName(rname string) string {
	_, label := RegionLabel(rname)
	return base.LbPrefix + label + base.LbTail
}

// RegionLbSet 所有地区负载均衡组名集合
func RegionLbSet() map[string]bool {
	out := map[string]bool{}
	for _, r := range base.Regions {
		for _, n := range LbNames(r.Name) {
			out[n] = true
		}
	}
	for _, n := range LbNames(base.GOther) {
		out[n] = true
	}
	return out
}

// LegacyMap 旧版策略组名 → 新名称
func LegacyMap() map[string]string {
	m := map[string]string{base.LegacyAuto: base.GAuto}
	rnames := []string{}
	for _, r := range base.Regions {
		rnames = append(rnames, r.Name)
	}
	rnames = append(rnames, base.GOther)
	for _, rname := range rnames {
		m[rname] = AutoName(rname)
		m[rname+base.AutoSuffix] = AutoName(rname)
		m[AutoName(rname, base.AutoTailOld)] = AutoName(rname)
		m[rname+base.LbSuffix] = LbName(rname, "")
		m[LbOldName(rname)] = LbName(rname, "")
		for _, n := range LbDroppedNames(rname) {
			m[n] = LbName(rname, "")
		}
	}
	return m
}

// MapDNSServer 按 mp 改写 DNS 服务器的 "#策略" 后缀
func MapDNSServer(x string, mp map[string]string) string {
	pol := ruleutil.DnsPolicyOf(x)
	if pol != "" {
		if np, ok := mp[pol]; ok {
			head, tail, _ := strings.Cut(x, "#")
			return head + "#" + np + tail[len(pol):]
		}
	}
	return x
}

// MapRefs 按 mp 改写各类策略组引用；drop 中的名字从自定义组成员里删除。返回改动数
func MapRefs(d map[string]any, mp map[string]string, drop ...string) int {
	n := 0
	dropSet := map[string]bool{}
	for _, x := range drop {
		dropSet[x] = true
	}
	var rules []any
	for _, r := range List(d, "rules") {
		rs, _ := r.(string)
		parts := strings.Split(rs, ",")
		i := ruleutil.RulePolicyIndex(parts)
		if !strings.HasPrefix(rs, "#") && i > 0 {
			if np, ok := mp[strings.TrimSpace(parts[i])]; ok {
				parts[i] = np
				n++
			}
		}
		rules = append(rules, strings.Join(parts, ","))
	}
	if _, ok := d["rules"]; ok {
		d["rules"] = rules
	}
	for _, r := range List(d, "rulesets") {
		if rm, ok := r.(map[string]any); ok {
			if np, ok := mp[Str(rm, "target")]; ok {
				rm["target"] = np
				n++
			}
		}
	}
	for _, e := range List(d, "device_routes") {
		if em, ok := e.(map[string]any); ok {
			if np, ok := mp[Str(em, "target")]; ok {
				em["target"] = np
				n++
			}
		}
	}
	for _, g := range List(d, "custom_groups") {
		if gm, ok := g.(map[string]any); ok {
			var old []string
			for _, p := range List(gm, "proxies") {
				if s, ok := p.(string); ok {
					old = append(old, s)
				}
			}
			var nw []string
			for _, mm := range old {
				if dropSet[mm] {
					continue
				}
				if np, ok := mp[mm]; ok {
					mm = np
				}
				if !contains(nw, mm) {
					nw = append(nw, mm)
				}
			}
			if !equalStrs(nw, old) {
				var arr []any
				for _, s := range nw {
					arr = append(arr, s)
				}
				gm["proxies"] = arr
				n++
			}
		}
	}
	dc := Map(d, "dns")
	if dc != nil {
		for _, k := range []string{"direct", "proxy", "pserver"} {
			if _, ok := dc[k]; ok {
				var out []any
				for _, x := range List(dc, k) {
					if s, ok := x.(string); ok {
						y := MapDNSServer(s, mp)
						if y != s {
							n++
						}
						out = append(out, y)
					} else {
						out = append(out, x)
					}
				}
				dc[k] = out
			}
		}
		for _, pe := range List(dc, "policies") {
			if pem, ok := pe.(map[string]any); ok {
				var out []any
				changed := false
				for _, x := range List(pem, "servers") {
					if s, ok := x.(string); ok {
						y := MapDNSServer(s, mp)
						if y != s {
							changed = true
						}
						out = append(out, y)
					} else {
						out = append(out, x)
					}
				}
				if changed {
					n++
				}
				pem["servers"] = out
			}
		}
	}
	return n
}

// MigrateNames 旧版策略组名迁移到新名称
func MigrateNames(d map[string]any) int {
	mp := LegacyMap()
	filt := map[string]string{}
	for k, v := range mp {
		if k != v {
			filt[k] = v
		}
	}
	return MapRefs(d, filt)
}

func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
