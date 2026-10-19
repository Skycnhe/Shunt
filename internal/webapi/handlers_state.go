package webapi

// 对应 Python shunt/webapi.py：GET /api/state、GET /api/ping。

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"shunt/internal/adblock"
	"shunt/internal/base"
	"shunt/internal/corehttp"
	"shunt/internal/data"
	"shunt/internal/errlog"
	"shunt/internal/groups"
	"shunt/internal/mihomo"
	"shunt/internal/notify"
	"shunt/internal/schedule"
	"shunt/internal/singbox"
	"shunt/internal/sysopt"
	"shunt/internal/updateguard"
)

func registerStateRoutes() {
	Route("GET", "/api/state", apiStateGet)
	Route("GET", "/api/ping", apiPingGet)
}

// ---------- 通用小助手 ----------

func nowFloat() float64 { return float64(time.Now().UnixNano()) / 1e9 }

// toBool 对应 Python bool() 的真值判定（JSON 解码后的类型）。
func toBool(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0
	case float32:
		return t != 0
	case int:
		return t != 0
	case int64:
		return t != 0
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	default:
		return true
	}
}

// ---------- 敏感值打码（对应 webapi.py 的 _mask_val/mask_secret/mask_url/unmask；helpers.go 复用） ----------

// maskVal 敏感值掩盖中间：长值露头 3 + 尾 2，短值全打码（按 rune 计，与 Python len() 一致）。
func maskVal(v string) string {
	r := []rune(v)
	if len(r) > 6 {
		return string(r[:3]) + "******" + string(r[len(r)-2:])
	}
	return "******"
}

// maskSecret /api/state 里的 TG token：空值保持空（前端据此显示「未配置」），非空打码。
func maskSecret(v any) any {
	if s, ok := v.(string); ok && s != "" {
		return maskVal(s)
	}
	if v == nil {
		return ""
	}
	return v
}

// maskURL 订阅 URL 打码：保留协议和主机（去掉 user:pass@），路径与查询串（通常带 token）打码。
func maskURL(u string) string {
	if u == "" {
		return ""
	}
	sp, err := url.Parse(u)
	if err != nil {
		return maskVal(u)
	}
	netloc := sp.Host
	if sp.User != nil {
		netloc = sp.User.String() + "@" + sp.Host
	}
	head := sp.Scheme + "://" + netloc
	if sp.Scheme == "" || netloc == "" || !strings.HasPrefix(u, head) {
		return maskVal(u)
	}
	rest := u[len(head):]
	host := sp.Scheme + "://" + sp.Host
	if strings.Trim(rest, "/") == "" {
		return host + rest
	}
	return host + "/" + maskVal(strings.TrimLeft(rest, "/"))
}

// unmask 前端把打码后的占位值原样提交回来 = 没改：换回服务端保存的原值。
func unmask(newVal, curVal string, masker func(string) string) string {
	if curVal != "" && strings.TrimSpace(newVal) == masker(curVal) {
		return curVal
	}
	return newVal
}

// stateSubs /api/state 的订阅列表：URL 打码后下发。
func stateSubs(subs any) []any {
	out := []any{}
	lst, _ := subs.([]any)
	for _, s := range lst {
		sm, ok := s.(map[string]any)
		if !ok {
			out = append(out, s)
			continue
		}
		cp := make(map[string]any, len(sm)+1)
		for k, v := range sm {
			cp[k] = v
		}
		if u, ok := cp["url"].(string); ok {
			cp["url"] = maskURL(u)
		} else if cp["url"] == nil {
			cp["url"] = ""
		}
		out = append(out, cp)
	}
	return out
}

// ---------- /api/state ----------

// svcCache 对应 _SVC_CACHE：rc-service 状态 + 核心 /version 缓存 10 秒。
var svcCache = struct {
	sync.Mutex
	ok   bool
	t    float64
	st   string
	code int
	ver  string
}{}

// svcStatus 对应 _svc_status()。
func svcStatus() (st string, code int, ver string) {
	svcCache.Lock()
	if svcCache.ok && nowFloat()-svcCache.t < 10 {
		st, code, ver = svcCache.st, svcCache.code, svcCache.ver
		svcCache.Unlock()
		return st, code, ver
	}
	svcCache.Unlock()

	_, st = sysopt.Sh(base.Svc + " status")
	code, raw := corehttp.Core("GET", "/version", nil, 5)
	ver = "-"
	if code == 200 {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err == nil {
			if v, _ := m["version"].(string); v != "" {
				ver = v
			}
		}
	}
	svcCache.Lock()
	svcCache.ok, svcCache.t, svcCache.st, svcCache.code, svcCache.ver = true, nowFloat(), st, code, ver
	svcCache.Unlock()
	return st, code, ver
}

// grpCache 对应 _GRP_CACHE：按（配置版本, 订阅节点名单版本）缓存策略组，避免每次完整 build_config。
var grpCache = struct {
	sync.Mutex
	ok     bool
	key    [2]int
	groups []string
	meta   map[string]map[string]any
}{}

// sbGroupView 对应 sb_group_view()：sing-box 下地区负载均衡并入自动优选（从名单和 meta 里去掉），
// 负载均衡 / 故障转移按自动测速运行（meta 改标 url-test，sb_from 记原类型）。原地修改 meta，返回过滤后的组名单。
func sbGroupView(gs []string, meta map[string]map[string]any) []string {
	lbs := data.RegionLbSet()
	for n, m := range meta {
		if lbs[n] {
			delete(meta, n)
			continue
		}
		if t, _ := m["type"].(string); t == "load-balance" || t == "fallback" {
			m["sb_from"] = t
			m["type"] = "url-test"
		}
	}
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		if !lbs[g] {
			out = append(out, g)
		}
	}
	return out
}

// stateGroups 对应 state_groups(d)：/api/state 的策略组名单与元数据。
// 生成失败时返回空名单（记日志），不让整个面板 500。
func stateGroups(d map[string]any) ([]string, map[string]map[string]any) {
	key := [2]int{data.ConfigVersion(), groups.ProviderRev()}
	grpCache.Lock()
	if grpCache.ok && grpCache.key == key {
		gs, gm := grpCache.groups, grpCache.meta
		grpCache.Unlock()
		return gs, gm
	}
	grpCache.Unlock()

	gs := []string{}
	gm := map[string]map[string]any{}
	func() {
		defer func() {
			if r := recover(); r != nil {
				errlog.LogErr("/api/state：生成策略组", fmt.Errorf("%v", r), true)
				gs = []string{}
				gm = map[string]map[string]any{}
			}
		}()
		groups.ProviderNodes() // 先刷新订阅节点名单（60 秒内存缓存），名单变化会推进 provider_rev()
		cfg := mihomo.BuildConfig(d)
		for _, g := range data.List(cfg, "proxy-groups") {
			if gm2, ok := g.(map[string]any); ok {
				gs = append(gs, data.Str(gm2, "name"))
			}
		}
		gm = updateguard.GroupMeta(d, cfg)
		if singbox.ActiveCore(d) == "singbox" {
			gs = sbGroupView(gs, gm)
		}
	}()

	grpCache.Lock()
	grpCache.ok, grpCache.key, grpCache.groups, grpCache.meta = true, key, gs, gm
	grpCache.Unlock()
	return gs, gm
}

// stateNodes 对应 state_nodes(d)：手动节点的摘要；残缺条目跳过，不让整个 /api/state 500。
func stateNodes(d map[string]any) []any {
	out := []any{}
	for _, n := range data.List(d, "nodes") {
		nm, ok := n.(map[string]any)
		if !ok {
			continue
		}
		px, ok := nm["proxy"].(map[string]any)
		if !ok {
			continue
		}
		name, ok1 := px["name"].(string)
		typ, ok2 := px["type"].(string)
		server, ok3 := px["server"].(string)
		if !ok1 || !ok2 || !ok3 {
			continue
		}
		if _, hasPort := px["port"]; !hasPort {
			continue
		}
		out = append(out, map[string]any{"name": name, "type": typ, "server": server, "port": px["port"]})
	}
	return out
}

// schedEvents 对应 list(SCHED["events"])[:20]。
func schedEvents() []any {
	schedule.Sched.Lock()
	defer schedule.Sched.Unlock()
	evs := schedule.Sched.Events
	if len(evs) > 20 {
		evs = evs[:20]
	}
	out := make([]any, 0, len(evs))
	for _, e := range evs {
		out = append(out, e)
	}
	return out
}

// wdEvents 看门狗事件：与 Python 同源（每次 wd_event 都落盘为同一 JSON），取落盘文件。
func wdEvents() []any {
	evs := data.ReadJSON[[]any](notify.WdEventsFile, []any{})
	if len(evs) > 20 {
		evs = evs[:20]
	}
	if evs == nil {
		evs = []any{}
	}
	return evs
}

// dnsCfgSafe 对应 /api/state 里 try/except 包裹的 dns_cfg(d)：失败记日志并回退 DNS_DEFAULT。
func dnsCfgSafe(d map[string]any) (out any) {
	defer func() {
		if r := recover(); r != nil {
			errlog.LogErr("/api/state：DNS 设置", fmt.Errorf("%v", r), false)
			out = base.DNSDefault
		}
	}()
	out = mihomo.DnsCfg(d)
	return out
}

func apiStateGet(c *Ctx) (int, any) {
	d := data.Load()
	st, code, version := svcStatus()
	gs, gmeta := stateGroups(d)
	out := map[string]any{
		"running":         strings.Contains(st, "started") || code == 200,
		"version":         version,
		"groups":          gs,
		"group_meta":      gmeta,
		"nodes":           stateNodes(d),
		"default_exclude": base.DefaultExclude,
		"sched_events":    schedEvents(),
		"panel_version":   base.PanelVersion,
		"core":            singbox.ActiveCore(d),
		"wd": map[string]any{
			"status":     notify.WdStatus(),
			"last_check": notify.WdLastCheck(),
			"events":     wdEvents(),
			"counts":     notify.WdCounts(nil),
			"max":        notify.WdEventsMax,
		},
	}
	for _, k := range []string{"mode", "subs", "rules", "rulesets", "bypass", "tests", "sub_interval", "ipv6",
		"https", "watchdog", "tg_token", "proxy_mode", "tun", "log_limit", "schedule", "devices",
		"device_routes", "sniffer", "gh_proxy"} {
		out[k] = d[k]
	}
	// 与 /api/config 一致：订阅 URL（常带 token）和 TG token 打码；前端原样提交回来时由 unmask() 换回原值
	out["subs"] = stateSubs(d["subs"])
	out["tg_token"] = maskSecret(d["tg_token"])
	out["dns"] = dnsCfgSafe(d)
	adOn := false
	if ab, ok := d["adblock"].(map[string]any); ok {
		adOn = toBool(ab["enabled"])
	}
	out["adblock_on"] = adOn
	return c.Send(200, out)
}

// ---------- /api/ping ----------

func apiPingGet(c *Ctx) (int, any) {
	// 轻量心跳：前端 15 秒轮询，version 变化时才拉全量 /api/state。
	// version = 配置版本（data.json 每次 save 自增）+ 订阅节点名单版本（新订阅下载完、节点增删时地区组会变）
	adToday := 0
	if adblock.AdStatsInst != nil {
		adToday = adblock.AdStatsInst.Today()
	}
	d := data.Load()
	return c.Send(200, map[string]any{
		"ok":       true,
		"core":     singbox.ActiveCore(d),
		"version":  fmt.Sprintf("%d.%d", data.ConfigVersion(), groups.ProviderRev()),
		"ad_today": adToday,
	})
}
