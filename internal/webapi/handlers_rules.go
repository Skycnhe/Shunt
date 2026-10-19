package webapi

// handlers_rules.go：规则类路由（对应 webapi.py 的规则 / DNS / 广告拦截部分）。

import (
	"net/url"
	"strings"

	"shunt/internal/adblock"
	"shunt/internal/base"
	"shunt/internal/core"
	"shunt/internal/corehttp"
	"shunt/internal/data"
	"shunt/internal/devices"
	"shunt/internal/dnsleak"
	"shunt/internal/latency"
	"shunt/internal/mihomo"
	"shunt/internal/notify"
	"shunt/internal/ruletest"
	"shunt/internal/singbox"
	"shunt/internal/sysopt"
)

func registerRuleRoutes() {
	Route("PUT", "/api/rules", hRulesPut)
	Route("PUT", "/api/mode", hModePut)
	Route("PUT", "/api/proxymode", hProxyModePut)
	Route("POST", "/api/ruletest", hRuletestPost)
	Route("PUT", "/api/dns", hDNSPut)
	Route("GET", "/api/dnsleak", hDNSLeakGet)
	Route("POST", "/api/dnsquery", hDNSQueryPost)
	Route("GET", "/api/adblock", hAdblockGet)
	Route("PUT", "/api/adblock", hAdblockPut)
	Route("POST", "/api/adblock/update", hAdblockUpdatePost)
	Route("POST", "/api/adblock/check", hAdblockCheckPost)
}

// PUT /api/rules
func hRulesPut(c *Ctx) (int, any) {
	var rules []string
	for _, r := range c.BodyList("rules") {
		if s := strings.TrimSpace(toStr(r)); s != "" {
			rules = append(rules, s)
		}
	}
	var nonComment []string
	for _, r := range rules {
		if !strings.HasPrefix(r, "#") {
			nonComment = append(nonComment, r)
		}
	}
	if bad := mihomo.BadRulePolicies(nonComment, data.Load()); len(bad) > 0 {
		n := len(bad)
		if n > 5 {
			n = 5
		}
		return 400, map[string]any{"message": "以下规则的策略不存在：" + strings.Join(bad[:n], "；")}
	}
	anyRules := make([]any, len(rules))
	for i, r := range rules {
		anyRules[i] = r
	}
	prev := data.Update(func(d map[string]any) { d["rules"] = anyRules })
	ok, msg := core.ReloadCore(prev)
	return c.Reply(ok, msg)
}

// PUT /api/mode
func hModePut(c *Ctx) (int, any) {
	mode := c.BodyStr("mode")
	if mode != "rule" && mode != "global" && mode != "direct" {
		return 400, map[string]any{"message": "模式无效"}
	}
	d := data.Load()
	sb := singbox.ActiveCore(d) == "singbox"
	d["mode"] = mode
	data.Save(d)
	singbox.WriteActiveConfig(d)
	m := mode
	if sb {
		m = strings.ToUpper(m[:1]) + m[1:] // Python: mode.capitalize()
	}
	_, _ = corehttp.Core("PATCH", "/configs", map[string]any{"mode": m}, 10)
	if mode == "global" {
		latency.FixGlobal()
	}
	return 200, map[string]any{"message": "ok"}
}

// PUT /api/proxymode（对应 set_proxy_mode）
func hProxyModePut(c *Ctx) (int, any) {
	mode := c.BodyStr("mode")
	if !containsStr(base.ProxyModes, mode) {
		return 400, map[string]any{"message": "代理方式无效"}
	}
	tunIn := c.BodyMap("tun")
	if v, ok := tunIn["stack"]; ok && v != nil {
		if !containsStr(base.TunStacks, toStr(v)) {
			return 400, map[string]any{"message": "TUN 协议栈只能是 system / gvisor / mixed"}
		}
	}
	prev := data.Update(func(d map[string]any) {
		d["proxy_mode"], d["tproxy"] = mode, mode == "tproxy"
		t := data.Map(d, "tun")
		if t == nil {
			t = map[string]any{}
			d["tun"] = t
		}
		for _, k := range []string{"stack", "auto_redirect", "strict_route"} {
			if v, ok := tunIn[k]; ok {
				if k == "stack" {
					t[k] = v
				} else {
					t[k] = toBool(v)
				}
			}
		}
		if v, ok := tunIn["device"]; ok {
			t["device"] = mihomo.SafeDev(toStr(v))
		}
	})
	ok, msg := core.ReloadCore(prev) // TUN 开关在配置里，先校验并重载核心
	if !ok {
		return 500, map[string]any{"message": msg}
	}
	// Python: WD["tp_off"] = False
	notify.SetWdField("tp_off", false)
	code, out := tpApply()
	label := map[string]string{"tproxy": "TProxy", "tun": "TUN", "off": "关闭"}[mode]
	note := ""
	if mode == "tun" && !notify.ManualStop() {
		// 核心手动停止时不检查（TUN 网卡要等核心启动才创建）；TUN 网卡创建失败时核心照常运行，需要单独确认
		d := data.Load()
		tun := data.Map(d, "tun")
		dev := mihomo.SafeDev(data.Str(tun, "device"))
		err := devices.TunRuntimeError(dev)
		autoRedir := true
		if v, ok := tun["auto_redirect"]; ok {
			autoRedir = toBool(v)
		}
		if activeCore() == "singbox" && autoRedir && !sysopt.NftOk() {
			note = "（内核不支持 nftables，auto-redirect 未启用）"
		}
		if err != "" && strings.Contains(strings.ToLower(err), "redirect") && autoRedir {
			// auto-redirect 依赖 nftables / iptables，内核不支持时自动关闭后重试一次
			data.Update(func(d2 map[string]any) {
				if t2 := data.Map(d2, "tun"); t2 != nil {
					t2["auto_redirect"] = false
				}
			})
			ok2, msg2 := core.ReloadCore(nil)
			if ok2 {
				err = devices.TunRuntimeError(dev)
			} else {
				err = msg2
			}
			if err == "" {
				note = "（auto-redirect 不可用，已自动关闭）"
			} else {
				note = ""
			}
		}
		if err != "" { // TUN 起不来时局域网会断网：恢复为原来的代理方式
			data.Save(prev)
			_, _ = core.ReloadCore(nil)
			_, _ = tpApply()
			return 500, map[string]any{"message": "TUN 启动失败，已恢复原来的代理方式：" + err +
				"。可尝试：关闭 auto-redirect、换用 gvisor 协议栈、确认以 root 运行并已加载 tun 模块（modprobe tun）"}
		}
	}
	if notify.ManualStop() {
		note += "（核心已手动停止，启动后生效）"
	}
	if code != 0 {
		return 500, map[string]any{"message": "核心已切换为 " + label + "，但 nftables 规则处理失败：" + tailRunes(out, 200)}
	}
	lastLine := ""
	if lines := strings.Split(strings.TrimRight(out, "\n"), "\n"); len(lines) > 0 {
		lastLine = lines[len(lines)-1]
	}
	return 200, map[string]any{"message": "代理方式：" + label + note + "。" + lastLine}
}

// POST /api/ruletest
func hRuletestPost(c *Ctx) (int, any) {
	res, err := ruletest.RuleTest(c.BodyStr("target"))
	if err != nil {
		return 500, map[string]any{"message": "内部错误"}
	}
	return 200, res
}

// PUT /api/dns（对应 save_dns）
func hDNSPut(c *Ctx) (int, any) {
	d0 := data.Load()
	cur := mihomo.DnsCfg(d0)
	var dc map[string]any
	switch {
	case toBool(c.Body["reset"]):
		dc = copyStrMap(base.DNSDefault)
	case c.BodyStr("preset") == "antileak":
		dc = dnsleak.AntileakDNS(cur)
	default:
		dc = copyStrMap(cur)
		for _, k := range base.DNSLists {
			if v, ok := c.Body[k]; ok {
				l, isList := v.([]any)
				if !isList {
					return 400, map[string]any{"message": k + " 应为列表"}
				}
				var out []string
				for _, x := range l {
					if s := strings.TrimSpace(toStr(x)); s != "" {
						out = append(out, s)
					}
				}
				dc[k] = out
			}
		}
		for _, k := range []string{"mode", "cache"} {
			if v, ok := c.Body[k]; ok {
				dc[k] = v
			}
		}
		for _, k := range []string{"policy", "respect_rules", "block_bypass"} {
			if v, ok := c.Body[k]; ok {
				dc[k] = toBool(v)
			}
		}
		for _, k := range []string{"hosts", "policies"} {
			if v, ok := c.Body[k]; ok {
				l, isList := v.([]any)
				if !isList {
					return 400, map[string]any{"message": k + " 应为列表"}
				}
				dc[k] = l
			}
		}
	}
	if m := toStr(dc["mode"]); m != "fake-ip" && m != "redir-host" {
		return 400, map[string]any{"message": "增强模式只能是 fake-ip 或 redir-host"}
	}
	if ca := toStr(dc["cache"]); ca != "arc" && ca != "lru" {
		return 400, map[string]any{"message": "缓存算法只能是 arc 或 lru"}
	}
	dc = mihomo.DnsCfg(map[string]any{"dns": dc})
	if errs := mihomo.ValidateDns(dc, d0); len(errs) > 0 {
		n := len(errs)
		if n > 5 {
			n = 5
		}
		return 400, map[string]any{"message": strings.Join(errs[:n], "；")}
	}
	sniff := c.BodyStr("preset") == "antileak" && !data.Bool(d0, "sniffer")
	prev := data.Update(func(d map[string]any) {
		d["dns"] = dc
		if sniff {
			d["sniffer"] = true
		}
	})
	ok, msg := core.ReloadCore(prev)
	if ok && toBool(mihomo.DnsCfg(prev)["block_bypass"]) != toBool(dc["block_bypass"]) &&
		data.Str(prev, "proxy_mode") != "off" {
		_, _ = tpApply() // 重新加载 nftables：是否劫持发往任意服务器的 53 端口
	}
	if ok {
		_, _ = corehttp.Core("POST", "/cache/dns/flush", nil, 10)
		if toStr(dc["mode"]) == "fake-ip" {
			_, _ = corehttp.Core("POST", "/cache/fakeip/flush", nil, 10)
		}
	}
	done := "DNS 设置已生效"
	if c.BodyStr("preset") == "antileak" {
		done = "已应用防泄露设置"
	}
	if !ok {
		return c.Reply(false, msg)
	}
	return c.Reply(true, done)
}

// GET /api/dnsleak
func hDNSLeakGet(c *Ctx) (int, any) {
	_, noLive := c.Query["nolive"]
	return 200, dnsleak.LeakCheck(!noLive)
}

// POST /api/dnsquery
func hDNSQueryPost(c *Ctx) (int, any) {
	name := ruletest.CleanTarget(c.BodyStr("name"))
	qtype := strings.ToUpper(c.BodyStr("type"))
	if qtype == "" {
		qtype = "A"
	}
	valid := map[string]bool{"A": true, "AAAA": true, "CNAME": true, "MX": true, "TXT": true,
		"NS": true, "HTTPS": true, "SRV": true, "PTR": true}
	if name == "" || !valid[qtype] {
		return 400, map[string]any{"message": "请输入域名并选择记录类型"}
	}
	start := nowMs()
	code, raw := corehttp.Core("GET", "/dns/query?name="+url.QueryEscape(name)+"&type="+qtype, nil, 15)
	ms := int(nowMs() - start)
	var j map[string]any
	if err := jsonUnmarshal(raw, &j); err != nil {
		j = map[string]any{"message": string(raw)}
	}
	if code != 200 {
		if code != 502 {
			return code, map[string]any{"message": firstNonEmpty(toStr(j["message"]), "查询失败")}
		}
		return 502, map[string]any{"message": firstNonEmpty(toStr(j["message"]), "查询失败")}
	}
	ans := j["Answer"]
	if ans == nil {
		ans = []any{}
	}
	return 200, map[string]any{"name": name, "type": qtype, "ms": ms, "status": j["Status"],
		"answer": ans, "policy": dnsleak.DnsRoute(name, data.Load())}
}

// GET /api/adblock
func hAdblockGet(c *Ctx) (int, any) {
	d := data.Load()
	meta := adblock.AbMeta()
	var rep map[string]any
	if adblock.AdStatsInst != nil {
		rep = adblock.AdStatsInst.Report()
	} else {
		rep = map[string]any{"today": 0, "top": []any{}, "lists": map[string]any{}, "days": []any{}}
	}
	repLists := toMap(rep["lists"])
	ab := data.Map(d, "adblock")
	var lists []any
	for _, lAny := range data.List(ab, "lists") {
		l := toMap(lAny)
		if l == nil {
			continue
		}
		merged := copyStrMap(l)
		for k, v := range toMap(meta[toStr(l["id"])]) {
			merged[k] = v
		}
		merged["hits"] = toInt(repLists[toStr(l["id"])])
		lists = append(lists, merged)
	}
	var loaded map[string]any
	if singbox.ActiveCore(d) == "singbox" {
		// sing-box 的 clash_api 没有规则集信息：按已转换好的规则集文件统计
		if data.Bool(ab, "enabled") {
			loaded = singbox.SbAbLoaded(d)
		} else {
			loaded = map[string]any{}
		}
	} else {
		prov := toMap(corehttp.CoreJSON("/providers/rules", 10)["providers"])
		loaded = map[string]any{}
		for k, v := range prov {
			if strings.HasPrefix(k, "ad-") {
				loaded[k] = toMap(v)["ruleCount"]
			}
		}
	}
	resp := map[string]any{}
	for k, v := range ab {
		if k != "lists" {
			resp[k] = v
		}
	}
	adblock.ABState.Lock()
	updating, abMsg := adblock.ABState.Updating, adblock.ABState.Msg
	adblock.ABState.Unlock()
	resp["lists"] = lists
	resp["presets"] = base.AbPresets
	resp["stats"] = rep
	resp["updating"] = updating
	resp["msg"] = abMsg
	resp["custom_hits"] = toInt(repLists["custom"])
	resp["loaded"] = loaded
	return 200, resp
}

// PUT /api/adblock（对应 save_adblock）
func hAdblockPut(c *Ctx) (int, any) {
	ab := data.Map(data.Load(), "adblock")
	inLists := c.BodyList("lists")
	if inLists == nil {
		if _, ok := c.Body["lists"]; !ok {
			inLists = data.List(ab, "lists")
		} else {
			inLists = []any{}
		}
	}
	var lists []any
	seen := map[string]bool{}
	for _, lAny := range inLists {
		l := toMap(lAny)
		u := strings.TrimSpace(toStr(l["url"]))
		name := truncateRunes(strings.TrimSpace(toStr(l["name"])), 40)
		if name == "" && strings.Count(u, "/") >= 2 {
			parts := strings.Split(u, "/")
			if len(parts) >= 3 {
				name = parts[2]
			}
		}
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			return 400, map[string]any{"message": "列表地址无效：" + firstNonEmpty(u, "(空)")}
		}
		lid := adblock.ListID(u)
		if seen[lid] {
			continue
		}
		seen[lid] = true
		lists = append(lists, map[string]any{"id": lid, "name": firstNonEmpty(name, lid), "url": u,
			"enabled": toBoolDef(l["enabled"], hasKey(l, "enabled"), true)})
	}
	clean := func(key string) []string {
		var src []any
		if v, ok := c.Body[key]; ok {
			src = toList(v)
		} else {
			src = data.List(ab, key)
		}
		var out []string
		for _, x := range src {
			if s := strings.TrimSpace(toStr(x)); s != "" {
				out = append(out, s)
			}
		}
		if len(out) > 20000 {
			out = out[:20000]
		}
		return out
	}
	interval := data.Int(ab, "interval")
	if v, ok := c.Body["interval"]; ok {
		interval = toInt(v)
	}
	newAb := map[string]any{
		"enabled":  toBoolDef(c.Body["enabled"], hasKey(c.Body, "enabled"), data.Bool(ab, "enabled")),
		"lists":    lists,
		"black":    clean("black"),
		"white":    clean("white"),
		"interval": interval,
		"dns":      toBoolDef(c.Body["dns"], hasKey(c.Body, "dns"), data.Bool(ab, "dns")),
	}
	if !containsInt([]int{0, 21600, 43200, 86400, 259200, 604800}, interval) {
		return 400, map[string]any{"message": "更新间隔无效"}
	}
	for _, kl := range [][2]string{{"black", "黑名单"}, {"white", "白名单"}} {
		key, label := kl[0], kl[1]
		entries := newAb[key].([]string)
		_, _, _, _, sk := adblock.ParseFilter(strings.Join(entries, "\n"), true)
		if sk > 0 {
			var bad []string
			for _, x := range entries {
				b1, b2, a1, a2, _ := adblock.ParseFilter(x, true)
				if len(b1)+len(b2)+len(a1)+len(a2) == 0 {
					bad = append(bad, x)
				}
			}
			n := len(bad)
			if n > 5 {
				n = 5
			}
			return 400, map[string]any{"message": label + "中有无法识别的条目：" + strings.Join(bad[:n], "；")}
		}
	}
	prev := data.Update(func(d map[string]any) { d["adblock"] = newAb })
	var need []string
	for _, lAny := range lists {
		l := toMap(lAny)
		if toBool(l["enabled"]) {
			if !fileExists(base.AbDir + "/" + toStr(l["id"]) + ".txt") {
				need = append(need, toStr(l["id"]))
			}
		}
	}
	_ = adblock.AbCompose(data.Load())
	ok, msg := core.ReloadCore(prev)
	if !ok {
		_ = adblock.AbCompose(data.Load())
		return 500, map[string]any{"message": msg}
	}
	adblock.AbCacheClear()
	adblock.ABState.Lock()
	updating := adblock.ABState.Updating
	adblock.ABState.Unlock()
	if toBool(newAb["enabled"]) && len(need) > 0 && !updating {
		go adblock.AdblockUpdate(need, true)
		return 200, map[string]any{"message": "已保存，正在下载新增的列表…"}
	}
	return 200, map[string]any{"message": "已保存并生效"}
}

// POST /api/adblock/update
func hAdblockUpdatePost(c *Ctx) (int, any) {
	adblock.ABState.Lock()
	updating := adblock.ABState.Updating
	adblock.ABState.Unlock()
	if updating {
		return 409, map[string]any{"message": "正在更新中，请稍候"}
	}
	var ids []string
	for _, v := range c.BodyList("ids") {
		ids = append(ids, toStr(v))
	}
	go adblock.AdblockUpdate(ids, true)
	return 200, map[string]any{"message": "已开始下载，完成后自动生效"}
}

// POST /api/adblock/check
func hAdblockCheckPost(c *Ctx) (int, any) {
	res, err := adblock.AbCheck(c.BodyStr("domain"))
	if err != nil {
		// 无效域名：给出原因，不再 500「内部错误」
		return 400, map[string]any{"message": err.Error()}
	}
	return 200, res
}
