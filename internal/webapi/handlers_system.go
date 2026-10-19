package webapi

// handlers_system.go：系统类路由（对应 webapi.py 的配置 / 背景 / 内核更新 / 日志 / 备份 / 健康检查等）。

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"shunt/internal/adblock"
	"shunt/internal/backup"
	"shunt/internal/base"
	"shunt/internal/core"
	"shunt/internal/coreupdate"
	"shunt/internal/data"
	"shunt/internal/devices"
	"shunt/internal/diag"
	"shunt/internal/health"
	"shunt/internal/https"
	"shunt/internal/ipinfo"
	"shunt/internal/latency"
	"shunt/internal/live"
	"shunt/internal/logclean"
	"shunt/internal/notify"
	"shunt/internal/panelupdate"
	"shunt/internal/ruletest"
	"shunt/internal/schedule"
	"shunt/internal/singbox"
	"shunt/internal/stats"
	"shunt/internal/sysopt"
	"shunt/internal/validate"
)

func registerSystemRoutes() {
	Route("GET", "/api/config", hConfigGet)
	Route("GET", "/api/sysopt", hSysoptGet)
	Route("POST", "/api/sysopt", hSysoptPost)
	Route("GET", "/api/speedtest", hSpeedtestGet)
	Route("GET", "/api/direct_delay", hDirectDelayGet)
	Route("GET", "/api/bg", hBgGet)
	Route("POST", "/api/bg", hBgPost)
	Route("POST", "/api/bg/url", hBgURLPost)
	Route("POST", "/api/bg/daily", hBgDailyPost)
	Route("DELETE", "/api/bg", hBgDelete)
	Route("GET", "/api/px", hPxGet)
	Route("GET", "/api/coreswitch", hCoreswitchGet)
	Route("POST", "/api/coreswitch", hCoreswitchPost)
	Route("GET", "/api/coreupdate", hCoreupdateGet)
	Route("GET", "/api/coreupdate/status", hCoreupdateStatusGet)
	Route("POST", "/api/coreupdate", hCoreupdatePost)
	Route("GET", "/api/selfupdate", hSelfupdateGet)
	Route("POST", "/api/selfupdate", hSelfupdatePost)
	Route("GET", "/api/stats", hStatsGet)
	Route("GET", "/api/conns", hConnsGet)
	Route("GET", "/api/conns/stats", hConnsStatsGet)
	Route("GET", "/api/live", hLiveGet)
	Route("GET", "/api/logs/info", hLogsInfoGet)
	Route("POST", "/api/logs/clean", hLogsCleanPost)
	Route("GET", "/api/history", hHistoryGet)
	Route("POST", "/api/history", hHistoryPost)
	Route("GET", "/api/devices", hDevicesGet)
	Route("PUT", "/api/devices", hDevicesPut)
	Route("GET", "/api/diag", hDiagGet)
	Route("GET", "/api/ipinfo", hIPInfoGet)
	Route("PUT", "/api/schedule", hSchedulePut)
	Route("POST", "/api/schedule/run", hScheduleRunPost)
	Route("PUT", "/api/settings", hSettingsPut)
	Route("PUT", "/api/https", hHTTPSPut)
	Route("POST", "/api/tg/test", hTgTestPost)
	Route("GET", "/api/backup", hBackupGet)
	Route("GET", "/api/backup/list", hBackupListGet)
	Route("POST", "/api/backup/create", hBackupCreatePost)
	Route("POST", "/api/backup/restore", hBackupRestorePost)
	Route("POST", "/api/backup/delete", hBackupDeletePost)
	Route("GET", "/api/health/status", hHealthStatusGet)
	Route("POST", "/api/health/check", hHealthCheckPost)
	Route("POST", "/api/health/unhide", hHealthUnhidePost)
	Route("PUT", "/api/health/cfg", hHealthCfgPut)
	Route("POST", "/api/restore", hRestorePost)
}

// GET /api/config
func hConfigGet(c *Ctx) (int, any) {
	d := data.Load()
	txt := configView(d)
	sbm := singbox.ActiveCore(d) == "singbox"
	if _, dl := c.Query["download"]; dl {
		ctype := "application/x-yaml"
		if sbm {
			ctype = "application/json"
		}
		return rawResp(200, []byte(txt), ctype)
	}
	return 200, map[string]any{"text": txt, "path": singbox.CoreConfPath(singbox.ActiveCore(d)),
		"size": len(txt), "core": singbox.ActiveCore(d)}
}

// GET /api/sysopt
func hSysoptGet(c *Ctx) (int, any) {
	return 200, sysopt.OptStatus()
}

// POST /api/sysopt
func hSysoptPost(c *Ctx) (int, any) {
	idsRaw, ok := c.Body["ids"]
	idsList, isList := idsRaw.([]any)
	if !ok || !isList {
		return 400, map[string]any{"message": "参数错误"}
	}
	ids := make([]string, 0, len(idsList))
	for _, v := range idsList {
		ids = append(ids, toStr(v))
	}
	ok2, msg, errs := sysopt.OptApply(ids)
	resp := map[string]any{"ok": ok2, "message": msg, "errors": errs}
	for k, v := range sysopt.OptStatus() {
		resp[k] = v
	}
	return 200, resp
}

// GET /api/speedtest
func hSpeedtestGet(c *Ctx) (int, any) {
	via := Q1(c.Query, "via", "proxy")
	return 200, sysopt.SpeedTest(via == "proxy")
}

// GET /api/direct_delay：直连国内延迟（DIRECT 是国内直连，单独测百度）
func hDirectDelayGet(c *Ctx) (int, any) {
	return 200, map[string]any{"ms": sysopt.DirectRtt(6)}
}

// GET /api/bg
func hBgGet(c *Ctx) (int, any) {
	bm := latency.BgMetaLoad()
	st, err := os.Stat(latency.BgFile)
	if err != nil {
		return 200, map[string]any{"exists": false}
	}
	return 200, map[string]any{"exists": true, "v": st.ModTime().Unix(), "size": st.Size(),
		"url": toStr(bm["url"]), "daily": toBool(bm["daily"])}
}

// POST /api/bg
func hBgPost(c *Ctx) (int, any) {
	ok, msg := latency.BgSave(c.BodyStr("data"))
	if !ok {
		return 400, map[string]any{"message": msg}
	}
	latency.BgMetaSave(map[string]any{}) // 改为上传的图片：不再按链接刷新
	var v int64
	if st, err := os.Stat(latency.BgFile); err == nil {
		v = st.ModTime().Unix()
	}
	return 200, map[string]any{"message": msg, "v": v}
}

// POST /api/bg/url
func hBgURLPost(c *Ctx) (int, any) {
	u := strings.TrimSpace(c.BodyStr("url"))
	if u == "" {
		u = toStr(latency.BgMetaLoad()["url"])
	}
	ok, msg := latency.BgFetch(u)
	if !ok {
		return 400, map[string]any{"message": msg}
	}
	latency.BgMetaSave(map[string]any{"url": u, "daily": toBool(c.Body["daily"]), "t": time.Now().Unix()})
	var v int64
	if st, err := os.Stat(latency.BgFile); err == nil {
		v = st.ModTime().Unix()
	}
	return 200, map[string]any{"message": msg, "v": v}
}

// POST /api/bg/daily
func hBgDailyPost(c *Ctx) (int, any) {
	bm := latency.BgMetaLoad()
	if toStr(bm["url"]) == "" {
		return 400, map[string]any{"message": "当前背景图不是链接图片"}
	}
	bm["daily"] = toBool(c.Body["daily"])
	latency.BgMetaSave(bm)
	msg := "已关闭每天自动更新"
	if toBool(bm["daily"]) {
		msg = "已开启每天自动更新"
	}
	return 200, map[string]any{"message": msg}
}

// DELETE /api/bg
func hBgDelete(c *Ctx) (int, any) {
	_ = os.Remove(latency.BgFile)
	latency.BgMetaSave(map[string]any{})
	return 200, map[string]any{"message": "已移除背景图"}
}

// GET /api/px
func hPxGet(c *Ctx) (int, any) {
	px := latency.ProxiesMerged()
	if px == nil {
		return 502, map[string]any{"message": "核心未运行或无法连接"}
	}
	latency.Retest.Lock()
	pending := latency.Retest.Pending
	latency.Retest.Unlock()
	return 200, map[string]any{"proxies": px, "retesting": pending}
}

// GET /api/coreswitch
func hCoreswitchGet(c *Ctx) (int, any) {
	d := data.Load()
	coreName := singbox.ActiveCore(d)
	if coreName == "singbox" {
		if w, _ := singbox.SBState["warn"].([]any); len(w) == 0 {
			if w2, _ := singbox.SBState["warn"].([]string); len(w2) == 0 {
				_, warn, _ := singbox.BuildSingbox(d)
				singbox.SBState["warn"] = warn
			}
		}
	}
	var warn any = []any{}
	if coreName == "singbox" {
		warn = singbox.SBState["warn"]
	}
	base.CoreUpd.Lock()
	busy := base.CoreUpd.Busy
	base.CoreUpd.Unlock()
	return 200, map[string]any{
		"core": coreName,
		"versions": map[string]any{
			"mihomo":  coreupdate.BinVersion(base.MihomoBin),
			"smart":   coreupdate.BinVersion(base.SmartBin),
			"singbox": singbox.SbVersion(),
		},
		"lgbm": fileExists(coreupdate.LgbmFile),
		"warn": warn,
		"busy": busy,
	}
}

// POST /api/coreswitch
func hCoreswitchPost(c *Ctx) (int, any) {
	kind := c.BodyStr("core")
	if _, ok := singbox.Cores[kind]; !ok {
		return 400, map[string]any{"message": "未知的内核"}
	}
	if kind == activeCore() {
		return 400, map[string]any{"message": "当前已经是 " + singbox.Cores[kind]}
	}
	gh := data.Str(data.Load(), "gh_proxy")
	ok, msg := coreupdate.CoreJobStart(func(args ...any) {
		core.CoreSwitchJob(toStr(args[0]), toStr(args[1]))
	}, kind, gh)
	if ok {
		return 200, map[string]any{"message": msg}
	}
	return 409, map[string]any{"message": msg}
}

// GET /api/coreupdate
func hCoreupdateGet(c *Ctx) (int, any) {
	ch := Q1(c.Query, "channel", "stable")
	coreQ := Q1(c.Query, "core")
	if coreQ == "" {
		coreQ = activeCore()
	}
	kind := "mihomo"
	if coreQ == "smart" {
		kind = "smart"
	}
	if _, ok := coreupdate.CoreChannels[ch]; !ok {
		return 400, map[string]any{"message": "未知的更新通道"}
	}
	ok, info := coreupdate.CoreCheck(ch, data.Str(data.Load(), "gh_proxy"), kind)
	base.CoreUpd.Lock()
	info["busy"] = base.CoreUpd.Busy
	base.CoreUpd.Unlock()
	if ok {
		return 200, info
	}
	return 502, info
}

// GET /api/coreupdate/status
func hCoreupdateStatusGet(c *Ctx) (int, any) {
	return 200, coreupdate.CoreUpdStatus()
}

// POST /api/coreupdate
func hCoreupdatePost(c *Ctx) (int, any) {
	coreQ := c.BodyStr("core")
	if coreQ == "" {
		coreQ = activeCore()
	}
	kind := "mihomo"
	if coreQ == "smart" {
		kind = "smart"
	}
	gh := data.Str(data.Load(), "gh_proxy")
	if c.BodyStr("action") == "lgbm" {
		n, err := coreupdate.LgbmFetch(gh)
		if err != nil {
			return 502, map[string]any{"message": "模型下载失败：" + truncateRunes(err.Error(), 200)}
		}
		if activeCore() == "smart" {
			_, _ = core.ReloadCore(nil)
		}
		return c.Reply(true, fmt.Sprintf("LightGBM 模型已更新（%d MB）", n/1<<20))
	}
	var ok bool
	var msg string
	if c.BodyStr("action") == "rollback" {
		ok, msg = coreupdate.CoreJobStart(func(args ...any) {
			coreupdate.CoreRollbackJob(toStr(args[0]))
		}, kind)
	} else {
		ch := c.BodyStr("channel")
		if kind == "smart" {
			ch = "alpha"
		} else if ch == "" {
			ch = "stable"
		}
		if _, okCh := coreupdate.CoreChannels[ch]; !okCh {
			return 400, map[string]any{"message": "未知的更新通道"}
		}
		force := toBool(c.Body["force"])
		ok, msg = coreupdate.CoreJobStart(func(args ...any) {
			coreupdate.CoreUpdateJob(toStr(args[0]), toStr(args[1]), toBool(args[2]), toStr(args[3]))
		}, ch, gh, force, kind)
	}
	if ok {
		return 200, map[string]any{"message": msg}
	}
	return 409, map[string]any{"message": msg}
}

// GET /api/selfupdate
func hSelfupdateGet(c *Ctx) (int, any) {
	ok, info := panelupdate.SelfUpdate(false, data.Str(data.Load(), "gh_proxy"))
	if ok {
		return 200, info
	}
	return 502, info
}

// POST /api/selfupdate
func hSelfupdatePost(c *Ctx) (int, any) {
	if c.BodyStr("action") == "rollback" {
		ok, msg := panelupdate.SelfRollback()
		return c.Reply(ok, msg)
	}
	ok, info := panelupdate.SelfUpdate(true, data.Str(data.Load(), "gh_proxy"))
	if ok {
		return 200, info
	}
	return 500, info
}

// GET /api/stats
func hStatsGet(c *Ctx) (int, any) {
	// Go 侧尚无全局 Stats 实例（集成阶段接线）：沿用 Python 里 STATS 为空时的兜底形状
	return 200, map[string]any{"today": map[string]any{}, "month": map[string]any{},
		"days": []any{}, "arp": map[string]any{}}
}

// GET /api/conns：精简后的连接列表（与 /connections 共享 2 秒快照）
func hConnsGet(c *Ctx) (int, any) {
	snap := core.ConnsSnapshot(5, 2)
	if snap == nil {
		return 502, map[string]any{"message": "mihomo 未运行或无法连接"}
	}
	keep := []string{"sourceIP", "host", "sniffHost", "destinationIP", "destinationPort", "network"}
	var out []any
	for _, xAny := range toList(toMap(snap)["connections"]) {
		x := toMap(xAny)
		md := toMap(x["metadata"])
		meta := map[string]any{}
		for _, k := range keep {
			meta[k] = md[k]
		}
		up, down := x["upload"], x["download"]
		if up == nil {
			up = 0
		}
		if down == nil {
			down = 0
		}
		out = append(out, map[string]any{
			"id": x["id"], "start": x["start"], "upload": up, "download": down,
			"rule": x["rule"], "rulePayload": x["rulePayload"], "chains": x["chains"],
			"metadata": meta,
		})
	}
	return 200, map[string]any{"connections": out}
}

// GET /api/conns/stats：概览只要两个数字，不必传整份连接列表
func hConnsStatsGet(c *Ctx) (int, any) {
	snap := core.ConnsSnapshot(5, 2)
	if snap == nil {
		return 502, map[string]any{"message": "mihomo 未运行或无法连接"}
	}
	conns := toList(toMap(snap)["connections"])
	devs := map[string]bool{}
	for _, xAny := range conns {
		if ip := toStr(toMap(toMap(xAny)["metadata"])["sourceIP"]); ip != "" {
			devs[ip] = true
		}
	}
	return 200, map[string]any{"count": len(conns), "devices": len(devs)}
}

// GET /api/live
func hLiveGet(c *Ctx) (int, any) {
	out := live.Live()
	t := toFloat(out["t"])
	now := float64(time.Now().UnixNano()) / 1e9
	if now-t > 5 { // 后台 /traffic 流未就绪（核心刚启动或已停止）时退回连接快照
		snap := core.ConnsSnapshot(3, 2)
		var upTotal, downTotal any = 0, 0
		if snap != nil {
			sm := toMap(snap)
			upTotal, downTotal = sm["uploadTotal"], sm["downloadTotal"]
		}
		out["up"], out["down"], out["upTotal"], out["downTotal"] = 0, 0, upTotal, downTotal
		out["stale"] = true
	}
	if !toBool(out["inuse"]) {
		for k, v := range live.MemoryOnce() {
			out[k] = v
		}
	}
	out["running"] = now-t < 5 || toBool(out["inuse"])
	return 200, out
}

// GET /api/logs/info
func hLogsInfoGet(c *Ctx) (int, any) {
	var files []any
	for _, l := range logclean.LogSizes() {
		files = append(files, map[string]any{"path": l.Path, "size": l.Size})
	}
	last, _ := logclean.LogState()
	return 200, map[string]any{"files": files, "limit": data.Int(data.Load(), "log_limit"), "last": last}
}

// POST /api/logs/clean
func hLogsCleanPost(c *Ctx) (int, any) {
	freed := logclean.LogClean(true)
	var files []any
	for _, l := range logclean.LogSizes() {
		files = append(files, map[string]any{"path": l.Path, "size": l.Size})
	}
	return 200, map[string]any{"message": "已清理，释放 " + adblock.FmtSize(float64(freed)), "files": files}
}

// GET /api/history
func hHistoryGet(c *Ctx) (int, any) {
	h := data.ReadJSON(data.HistoryFile, []any{})
	var out []any
	for _, xAny := range h {
		x := toMap(xAny)
		out = append(out, map[string]any{"id": x["id"], "t": x["t"], "changed": x["changed"]})
	}
	return 200, out
}

// POST /api/history：恢复到某次快照
func hHistoryPost(c *Ctx) (int, any) {
	h := data.ReadJSON(data.HistoryFile, []any{})
	var snap map[string]any
	wantID := c.BodyStr("id")
	for _, xAny := range h {
		if x := toMap(xAny); toStr(x["id"]) == wantID {
			snap = x
			break
		}
	}
	if snap == nil {
		return 404, map[string]any{"message": "快照不存在"}
	}
	prev := data.Update(func(d map[string]any) {
		for k, v := range toMap(snap["data"]) {
			if !data.HistorySkip[k] {
				d[k] = v
			}
		}
		data.MigrateNames(d)
	})
	_ = adblock.AbCompose(data.Load())
	ok, msg := core.ReloadCore(prev)
	if ok {
		_, _ = tpApply()
	}
	if ok {
		t := time.Unix(int64(toFloat(snap["t"])), 0)
		msg = "已恢复到 " + t.Format("01-02 15:04") + " 的配置"
	}
	return c.Reply(ok, msg)
}

// GET /api/devices
func hDevicesGet(c *Ctx) (int, any) {
	ips := map[string]bool{}
	for ip := range stats.ArpTable() {
		ips[ip] = true
	}
	for ip := range devices.ReadLeases() {
		ips[ip] = true
	}
	// Python 还会读 stats.STATS 的 days；Go 侧尚无全局 Stats 实例（集成阶段接线）
	if snap := core.ConnsSnapshot(5, 2); snap != nil { // 与连接页 / 统计共用 2 秒快照，不再单独全量抓取
		for _, xAny := range toList(toMap(snap)["connections"]) {
			if ip := toStr(toMap(toMap(xAny)["metadata"])["sourceIP"]); ip != "" {
				ips[ip] = true
			}
		}
	}
	var list []string
	for ip := range ips {
		if ip != "" {
			list = append(list, ip)
		}
	}
	sort.Strings(list)
	d := data.Load()
	return 200, map[string]any{"map": devices.DeviceMap(list), "custom": d["devices"]}
}

// PUT /api/devices
func hDevicesPut(c *Ctx) (int, any) {
	devs := map[string]any{}
	for k, v := range c.BodyMap("devices") {
		kk := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(k), "-", ":"))
		vv := truncateRunes(strings.TrimSpace(toStr(v)), 40)
		if kk != "" && vv != "" && (ruletest.IsIP(kk) || macRe.MatchString(kk)) {
			devs[kk] = vv
		}
	}
	data.Update(func(d map[string]any) { d["devices"] = devs })
	return 200, map[string]any{"message": fmt.Sprintf("已保存 %d 个设备备注", len(devs))}
}

// GET /api/diag
func hDiagGet(c *Ctx) (int, any) {
	return 200, diag.Diagnose()
}

// GET /api/ipinfo
func hIPInfoGet(c *Ctx) (int, any) {
	return 200, ipinfo.GetIPInfo(nil)
}

// PUT /api/schedule
func hSchedulePut(c *Ctx) (int, any) {
	sc := map[string]any{}
	for _, k := range []string{"sub_update", "core_restart", "geo_update"} {
		v := strings.TrimSpace(c.BodyStr(k))
		if v != "" && !hhmmRe.MatchString(v) {
			return 400, map[string]any{"message": "时间格式应为 HH:MM：" + v}
		}
		sc[k] = v
	}
	lat := toInt(c.Body["latency"])
	if lat != 0 && lat != 10 && lat != 30 && lat != 60 && lat != 180 {
		lat = 0
	}
	sc["latency"] = lat
	data.Update(func(d map[string]any) { d["schedule"] = sc })
	return 200, map[string]any{"message": "定时任务已保存"}
}

// POST /api/schedule/run
func hScheduleRunPost(c *Ctx) (int, any) {
	k := c.BodyStr("task")
	name, ok := schedule.TaskNames[k]
	if !ok {
		return 400, map[string]any{"message": "未知任务"}
	}
	ok2, msg := schedule.RunTask(k)
	mark := "✓"
	if !ok2 {
		mark = "✗"
	}
	schedule.SchedEvent("手动执行 " + name + "：" + mark + " " + msg)
	return c.Reply(ok2, msg)
}

// PUT /api/settings
func hSettingsPut(c *Ctx) (int, any) {
	allowed := []string{"rulesets", "bypass", "tests", "sub_interval", "region_groups", "ipv6",
		"watchdog", "tg_token", "tg_chat", "log_limit", "sniffer", "gh_proxy", "device_routes"}
	if v, ok := c.Body["gh_proxy"]; ok {
		s := strings.TrimSpace(toStr(v))
		if s != "" {
			if !ghRe.MatchString(s) {
				return 400, map[string]any{"message": "GitHub 加速地址格式应为 https://ghfast.top/"}
			}
			if !strings.HasSuffix(s, "/") {
				s += "/"
			}
		}
		c.Body["gh_proxy"] = s
	}
	if v, ok := c.Body["tg_token"]; ok { // 打码的 token 原样提交回来 = 没改
		c.Body["tg_token"] = unmaskSecret(toStr(v), data.Str(data.Load(), "tg_token"))
	}
	if v, ok := c.Body["sniffer"]; ok {
		c.Body["sniffer"] = toBool(v)
	}
	if v, ok := c.Body["log_limit"]; ok {
		if n := toInt(v); n != 1 && n != 2 && n != 5 && n != 10 && n != 20 {
			return 400, map[string]any{"message": "日志上限只能是 1 / 2 / 5 / 10 / 20 MB"}
		}
	}
	// 形状校验：残缺的规则集 / 绕过设备 / 延迟站点直接 400，不写进 data.json
	newVals, err := validate.CleanFields(c.Body, allowed)
	if err != nil {
		return 400, map[string]any{"message": err.Error()}
	}
	test := data.Load()
	for k, v := range newVals {
		test[k] = v
	}
	if perr := probeData(test); perr != "" {
		return 400, map[string]any{"message": perr}
	}
	prev := data.Update(func(d map[string]any) {
		for k, v := range newVals {
			d[k] = v
		}
	})
	d := data.Load()
	msg := "已保存"
	bodyKeys := map[string]bool{}
	for k := range c.Body {
		bodyKeys[k] = true
	}
	needReload := bodyKeys["rulesets"] || bodyKeys["sub_interval"] || bodyKeys["region_groups"] ||
		bodyKeys["ipv6"] || bodyKeys["sniffer"] || bodyKeys["device_routes"] ||
		(bodyKeys["bypass"] && data.Str(d, "proxy_mode") == "tun")
	if needReload {
		ok, m := core.ReloadCore(prev)
		if !ok {
			return 500, map[string]any{"message": m}
		}
		msg = m
	}
	if (bodyKeys["bypass"] || bodyKeys["ipv6"]) && data.Str(d, "proxy_mode") != "off" {
		_, _ = tpApply()
	}
	if bodyKeys["device_routes"] {
		if miss := deviceRouteMissing(d); len(miss) > 0 {
			n := len(miss)
			if n > 5 {
				n = 5
			}
			if msg == "" {
				msg = "已保存"
			}
			msg += "；以下设备的目标策略组不存在，暂不生效：" + strings.Join(miss[:n], "、")
		}
	}
	// 注意：Python 在关闭看门狗时会置 WD["status"] = "off"，Go 的 notify 包未导出该 setter，
	// 集成阶段接线（见报告）；此处不做任何操作。
	return 200, map[string]any{"message": msg}
}

// PUT /api/https
func hHTTPSPut(c *Ctx) (int, any) {
	on := toBool(c.Body["enable"])
	if on && !(fileExists(base.CertFile) && fileExists(base.KeyFile)) {
		ok, out := https.GenCert()
		if !ok {
			return 500, map[string]any{"message": "生成证书失败（需要 openssl）：" + tailRunes(out, 200)}
		}
	}
	data.Update(func(d map[string]any) { d["https"] = on })
	https.RestartSelf()
	scheme, label := "http", "HTTP"
	if on {
		scheme, label = "https", "HTTPS"
	}
	return 200, map[string]any{"message": "面板将以 " + label + " 重启", "scheme": scheme}
}

// POST /api/tg/test
func hTgTestPost(c *Ctx) (int, any) {
	d := data.Load()
	if v, ok := c.Body["tg_token"]; ok {
		d["tg_token"] = unmaskSecret(toStr(v), data.Str(d, "tg_token"))
		d["tg_chat"] = c.BodyStr("tg_chat")
	}
	ok, msg := notify.TgSend("✅ 测试消息：通知已配置成功", d)
	return c.Reply(ok, msg)
}

// GET /api/backup：整份配置（去掉 secret）
func hBackupGet(c *Ctx) (int, any) {
	d := data.Load()
	out := map[string]any{}
	for k, v := range d {
		if k != "secret" {
			out[k] = v
		}
	}
	return 200, out
}

// GET /api/backup/list
func hBackupListGet(c *Ctx) (int, any) {
	return 200, map[string]any{"backups": backup.List()}
}

// POST /api/backup/create
func hBackupCreatePost(c *Ctx) (int, any) {
	ok, name := backup.Create(base.PanelVersion, "")
	if ok {
		return 200, map[string]any{"ok": true, "name": name, "message": name}
	}
	return 500, map[string]any{"ok": false, "name": "", "message": "备份失败：" + name}
}

// POST /api/backup/restore
func hBackupRestorePost(c *Ctx) (int, any) {
	ok, msg := backup.Restore(strings.TrimSpace(c.BodyStr("name")))
	return c.Reply(ok, msg)
}

// POST /api/backup/delete
func hBackupDeletePost(c *Ctx) (int, any) {
	ok, msg := backup.Delete(strings.TrimSpace(c.BodyStr("name")))
	return c.Reply(ok, msg)
}

// GET /api/health/status
func hHealthStatusGet(c *Ctx) (int, any) {
	health.HealthState.Lock()
	running, lastRun, total, checked := health.HealthState.Running, health.HealthState.LastRun,
		health.HealthState.Total, health.HealthState.Checked
	health.HealthState.Unlock()
	return 200, map[string]any{
		"running": running, "last_run": lastRun, "total": total, "checked": checked,
		"cfg": health.HealthCfg(nil), "records": health.GetRecords(nil),
	}
}

// POST /api/health/check
func hHealthCheckPost(c *Ctx) (int, any) {
	ok := health.RunCheckBg()
	msg := "检查正在进行中"
	if ok {
		msg = "已开始检查"
	}
	return 200, map[string]any{"ok": ok, "message": msg}
}

// POST /api/health/unhide
func hHealthUnhidePost(c *Ctx) (int, any) {
	name := strings.TrimSpace(c.BodyStr("node_id"))
	ok := name != "" && health.Unhide(name)
	if ok {
		return c.Reply(true, "已取消隐藏")
	}
	return c.Reply(false, "节点不存在")
}

// PUT /api/health/cfg
func hHealthCfgPut(c *Ctx) (int, any) {
	cfg := health.HealthCfg(nil)
	if v, ok := c.Body["enabled"]; ok {
		cfg["enabled"] = toBool(v)
	}
	if v, ok := c.Body["time"]; ok {
		t := strings.TrimSpace(toStr(v))
		if !hhmmRe.MatchString(t) {
			return 400, map[string]any{"ok": false, "message": "时间格式应为 HH:MM"}
		}
		cfg["time"] = t
	}
	for _, k := range []string{"warn_days", "hide_days"} {
		if v, ok := c.Body[k]; ok {
			n := toInt(v)
			if n < 1 || n > 30 {
				return 400, map[string]any{"ok": false, "message": k + " 应为 1-30 的整数"}
			}
			cfg[k] = n
		}
	}
	if toInt(cfg["warn_days"]) >= toInt(cfg["hide_days"]) {
		return 400, map[string]any{"ok": false, "message": "标红天数应小于隐藏天数"}
	}
	health.SaveHealthCfg(cfg)
	return 200, map[string]any{"ok": true, "cfg": cfg}
}

// POST /api/restore：从备份文件恢复
func hRestorePost(c *Ctx) (int, any) {
	keys := []string{"mode", "tproxy", "subs", "rules", "rulesets", "bypass", "tests", "sub_interval",
		"region_groups", "nodes", "ipv6", "watchdog", "tg_token", "tg_chat", "proxy_mode", "tun",
		"log_limit", "adblock", "dns", "devices", "device_routes", "schedule", "groups_cfg",
		"custom_groups", "sniffer", "gh_proxy"}
	// 恢复残缺 / 旧格式的备份：任何一项形状不对都整体拒绝，不写进 data.json
	vals, err := validate.CleanFields(c.Body, keys)
	if err != nil {
		return 400, map[string]any{"message": "备份内容无效：" + err.Error()}
	}
	if len(vals) == 0 {
		return 400, map[string]any{"message": "备份内容无效：没有可恢复的设置"}
	}
	applyBackup := func(d map[string]any) {
		for k, v := range vals {
			d[k] = deepCopyAny(v)
		}
		if _, hasPM := vals["proxy_mode"]; !hasPM {
			if tp, ok := vals["tproxy"]; ok {
				if toBool(tp) {
					d["proxy_mode"] = "tproxy"
				} else {
					d["proxy_mode"] = "off"
				}
			}
		}
		if !containsStr(base.ProxyModes, data.Str(d, "proxy_mode")) {
			if data.Bool(d, "tproxy") {
				d["proxy_mode"] = "tproxy"
			} else {
				d["proxy_mode"] = "off"
			}
		}
		data.MigrateNames(d) // 旧版备份里的地区组名自动换成新名称
	}
	test := data.Load()
	applyBackup(test)
	if perr := probeData(test); perr != "" {
		return 400, map[string]any{"message": "备份内容无效：" + perr}
	}
	prev := data.Update(applyBackup)
	_ = adblock.AbCompose(data.Load())
	ok, msg := core.ReloadCore(prev)
	if ok {
		_, _ = tpApply()
	}
	prefix := ""
	if ok {
		prefix = "已恢复，"
	}
	return c.Reply(ok, prefix+msg)
}
