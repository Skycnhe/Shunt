// Package validate 对应 Python shunt/validate.py：/api/settings、/api/restore 的数据形状校验。
// 残缺或类型不对的条目返回 400，不写进 data.json。
// 只查形状与取值范围，策略组引用等语义检查仍在各接口里做。
package validate

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"shunt/internal/base"
	"shunt/internal/data"
	"shunt/internal/devroute"
	"shunt/internal/groups"
)

var (
	rsBehaviors = []string{"domain", "ipcidr", "classical"}
	rsFormats   = []string{"yaml", "text", "mrs"}
	macRx       = regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$`)
	urlRx       = regexp.MustCompile(`^https?://\S+$`)
	schedRx     = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)
)

// ListMax 列表类字段的条数上限
const ListMax = 20000

func asList(v any, label string) ([]any, error) {
	lst, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s应为列表", label)
	}
	if len(lst) > ListMax {
		return nil, fmt.Errorf("%s条目过多", label)
	}
	return lst, nil
}

func asStr(v any, label string, allowEmpty bool) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s应为文本", label)
	}
	s = strings.TrimSpace(s)
	if s == "" && !allowEmpty {
		return "", fmt.Errorf("%s不能为空", label)
	}
	return s, nil
}

func asURL(v any, label string) (string, error) {
	s, err := asStr(v, label, false)
	if err != nil {
		return "", err
	}
	if !urlRx.MatchString(s) {
		return "", fmt.Errorf("%s应为 http(s) 地址：%s", label, firstN(s, 80))
	}
	return s, nil
}

// CleanRulesets 规则集列表校验
func CleanRulesets(v any) (any, error) {
	lst, err := asList(v, "规则集")
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	seen := map[string]bool{}
	for i, r := range lst {
		rm, ok := r.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("规则集第 %d 项格式不正确", i+1)
		}
		name, err := asStr(rm["name"], fmt.Sprintf("规则集第 %d 项的名称", i+1), false)
		if err != nil {
			return nil, err
		}
		if groups.NameBad.MatchString(name) || len([]rune(name)) > 60 {
			return nil, fmt.Errorf("规则集名称不能含逗号、# 或引号，且不超过 60 字：%s", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("规则集重名：%s", name)
		}
		seen[name] = true
		u, err := asURL(rm["url"], fmt.Sprintf("规则集「%s」的地址", name))
		if err != nil {
			return nil, err
		}
		beh, _ := rm["behavior"].(string)
		if beh == "" {
			beh = "domain"
		}
		if !containsStr(rsBehaviors, beh) {
			return nil, fmt.Errorf("规则集「%s」的类型只能是 %s", name, strings.Join(rsBehaviors, " / "))
		}
		format, _ := rm["format"].(string)
		if format == "" {
			format = "yaml"
		}
		if !containsStr(rsFormats, format) {
			return nil, fmt.Errorf("规则集「%s」的格式只能是 %s", name, strings.Join(rsFormats, " / "))
		}
		target, _ := rm["target"].(string)
		if target == "" {
			target = base.GSel
		}
		target, err = asStr(target, fmt.Sprintf("规则集「%s」的目标策略", name), false)
		if err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"name": name, "url": u, "behavior": beh, "format": format, "target": target,
		})
	}
	return out, nil
}

// BypassOK 绕过设备条目：MAC / IP / 网段
func BypassOK(x string) bool {
	if macRx.MatchString(x) {
		return true
	}
	if net.ParseIP(x) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(x)
	return err == nil
}

// CleanBypass 绕过设备列表校验
func CleanBypass(v any) (any, error) {
	lst, err := asList(v, "绕过设备")
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, x := range lst {
		s, err := asStr(x, "绕过设备的条目", true)
		if err != nil {
			return nil, err
		}
		if s == "" {
			continue
		}
		if !BypassOK(s) {
			return nil, fmt.Errorf("绕过设备只能填 IP、网段或 MAC 地址：%s", firstN(s, 60))
		}
		out = append(out, s)
	}
	return out, nil
}

// CleanTests 延迟站点列表校验
func CleanTests(v any) (any, error) {
	lst, err := asList(v, "延迟站点")
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for i, t := range lst {
		tm, ok := t.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("延迟站点第 %d 项格式不正确", i+1)
		}
		name, err := asStr(tm["name"], fmt.Sprintf("延迟站点第 %d 项的名称", i+1), false)
		if err != nil {
			return nil, err
		}
		u, err := asURL(tm["url"], fmt.Sprintf("延迟站点「%s」的网址", name))
		if err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"name": firstN(name, 40), "url": u})
	}
	if len(out) == 0 {
		return nil, errors.New("延迟站点不能为空")
	}
	return out, nil
}

// CleanRules 自定义规则列表校验
func CleanRules(v any) (any, error) {
	lst, err := asList(v, "自定义规则")
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, x := range lst {
		s, err := asStr(x, "自定义规则", true)
		if err != nil {
			return nil, err
		}
		if strings.ContainsAny(s, "\n\r") {
			return nil, errors.New("自定义规则不能含换行")
		}
		if s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}

// SubNameClash 订阅名只差符号（「机场 A」和「机场_A」）时会共用同一个节点缓存文件，互相覆盖：返回冲突的那个名字
func SubNameClash(name string, others []string) string {
	k := data.Safe(name)
	for _, o := range others {
		if o != name && data.Safe(o) == k {
			return o
		}
	}
	return ""
}

// CleanSubs 订阅列表校验
func CleanSubs(v any) (any, error) {
	lst, err := asList(v, "订阅")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for i, s := range lst {
		sm, ok := s.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("订阅第 %d 项格式不正确", i+1)
		}
		name, err := asStr(sm["name"], fmt.Sprintf("订阅第 %d 项的名称", i+1), false)
		if err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, fmt.Errorf("订阅重名：%s", name)
		}
		seen[name] = true
		if _, err := asURL(sm["url"], fmt.Sprintf("订阅「%s」的地址", name)); err != nil {
			return nil, err
		}
		for _, k := range []string{"filter", "exclude"} {
			if fv, ok := sm[k]; ok && fv != nil {
				if _, isStr := fv.(string); !isStr {
					return nil, fmt.Errorf("订阅「%s」的 %s 应为文本", name, k)
				}
			}
		}
	}
	return v, nil
}

func portOK(v any) bool {
	if _, isBool := v.(bool); isBool {
		return false
	}
	var n int64
	switch x := v.(type) {
	case int:
		n = int64(x)
	case int64:
		n = x
	case float64:
		n = int64(x) // Python int() 截断
	case json.Number:
		p, err := x.Int64()
		if err != nil {
			return false
		}
		n = p
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return false
		}
		p, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return false
		}
		n = p
	default:
		return false
	}
	return 0 < n && n < 65536
}

// CleanNodes 节点列表校验
func CleanNodes(v any) (any, error) {
	lst, err := asList(v, "节点")
	if err != nil {
		return nil, err
	}
	for i, n := range lst {
		var p map[string]any
		if nm, ok := n.(map[string]any); ok {
			p, _ = nm["proxy"].(map[string]any)
		}
		if p == nil {
			return nil, fmt.Errorf("节点第 %d 项缺少 proxy", i+1)
		}
		name, err := asStr(p["name"], fmt.Sprintf("节点第 %d 项的名称", i+1), false)
		if err != nil {
			return nil, err
		}
		if _, err := asStr(p["type"], fmt.Sprintf("节点「%s」的类型", name), false); err != nil {
			return nil, err
		}
		if _, err := asStr(p["server"], fmt.Sprintf("节点「%s」的服务器", name), false); err != nil {
			return nil, err
		}
		if !portOK(p["port"]) {
			return nil, fmt.Errorf("节点「%s」的端口无效", name)
		}
	}
	return v, nil
}

// CleanCustomGroups 自定义策略组列表校验
func CleanCustomGroups(v any) (any, error) {
	lst, err := asList(v, "自定义策略组")
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	seen := map[string]bool{}
	for i, g := range lst {
		gm, ok := g.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("自定义策略组第 %d 项格式不正确", i+1)
		}
		cg, err := groups.CleanCustomGroup(gm)
		if err != nil {
			return nil, err
		}
		if seen[cg["name"].(string)] {
			return nil, fmt.Errorf("策略组重名：%s", cg["name"])
		}
		seen[cg["name"].(string)] = true
		out = append(out, cg)
	}
	return out, nil
}

// CleanAdblock 广告拦截设置校验
func CleanAdblock(v any) (any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("广告拦截设置应为对象")
	}
	lists, err := asList(listOr(m["lists"], []any{}), "广告拦截列表")
	if err != nil {
		return nil, err
	}
	for i, l := range lists {
		lm, ok := l.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("广告拦截列表第 %d 项格式不正确", i+1)
		}
		id, _ := lm["id"].(string)
		if strings.TrimSpace(id) == "" {
			return nil, fmt.Errorf("广告拦截列表第 %d 项格式不正确", i+1)
		}
		if _, err := asURL(lm["url"], fmt.Sprintf("广告拦截列表「%s」的地址", id)); err != nil {
			return nil, err
		}
	}
	for _, kl := range [][2]string{{"black", "黑名单"}, {"white", "白名单"}} {
		bl, err := asList(listOr(m[kl[0]], []any{}), kl[1])
		if err != nil {
			return nil, err
		}
		for _, x := range bl {
			if _, err := asStr(x, kl[1], true); err != nil {
				return nil, err
			}
		}
	}
	return v, nil
}

// CleanDevices 设备备注校验
func CleanDevices(v any) (any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("设备备注格式不正确")
	}
	for _, x := range m {
		if _, ok := x.(string); !ok {
			return nil, errors.New("设备备注格式不正确")
		}
	}
	return v, nil
}

// CleanSchedule 定时任务校验
func CleanSchedule(v any) (any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("定时任务应为对象")
	}
	for _, k := range []string{"sub_update", "core_restart", "geo_update"} {
		x, _ := m[k].(string)
		if x != "" && !schedRx.MatchString(x) {
			return nil, fmt.Errorf("定时任务时间格式应为 HH:MM：%s", x)
		}
	}
	if lv, present := m["latency"]; present && lv != nil {
		if !isLatencyNum(lv) {
			return nil, errors.New("自动测速间隔应为数字")
		}
	}
	return v, nil
}

func isLatencyNum(v any) bool {
	switch x := v.(type) {
	case bool:
		return true // Python int(True) 合法
	case int, int64, float64, json.Number:
		return true
	case string:
		_, err := strconv.Atoi(strings.TrimSpace(x))
		return err == nil
	default:
		return false
	}
}

func cleanDNS(v any) (any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("DNS 设置应为对象")
	}
	keys := append(append([]string{}, base.DNSLists...), "hosts", "policies")
	for _, k := range keys {
		if x, present := m[k]; present {
			if _, isList := x.([]any); !isList {
				return nil, fmt.Errorf("DNS 的 %s 应为列表", k)
			}
		}
	}
	for _, pe := range listOf(m["policies"]) {
		pem, ok := pe.(map[string]any)
		if !ok {
			return nil, errors.New("DNS 分流策略格式不正确")
		}
		if sv, present := pem["servers"]; present && sv != nil {
			if _, isList := sv.([]any); !isList {
				return nil, errors.New("DNS 分流策略格式不正确")
			}
		}
	}
	return v, nil
}

func dictOf(label string) func(any) (any, error) {
	return func(v any) (any, error) {
		if _, ok := v.(map[string]any); !ok {
			return nil, fmt.Errorf("%s应为对象", label)
		}
		return v, nil
	}
}

func intOf(label string, lo, hi float64) func(any) (any, error) {
	num := func(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }
	return func(v any) (any, error) {
		fail := func() (any, error) { return nil, fmt.Errorf("%s应为 %s–%s 的数字", label, num(lo), num(hi)) }
		if _, isBool := v.(bool); isBool {
			return fail()
		}
		var f float64
		switch x := v.(type) {
		case int:
			f = float64(x)
		case int64:
			f = float64(x)
		case float64:
			f = x
		case json.Number:
			n, err := x.Float64()
			if err != nil {
				return fail()
			}
			f = n
		default:
			return fail()
		}
		if !(lo <= f && f <= hi) {
			return fail()
		}
		return int(f), nil
	}
}

func boolOf(v any) (any, error) {
	switch x := v.(type) {
	case nil:
		return false, nil
	case bool:
		return x, nil
	case string:
		return x != "", nil
	case float64:
		return x != 0, nil
	case int:
		return x != 0, nil
	case []any:
		return len(x) > 0, nil
	case map[string]any:
		return len(x) > 0, nil
	default:
		return true, nil
	}
}

func textOf(label string) func(any) (any, error) {
	return func(v any) (any, error) {
		if v == nil {
			return "", nil
		}
		switch x := v.(type) {
		case string:
			return strings.TrimSpace(x), nil
		case int:
			return strconv.Itoa(x), nil
		case int64:
			return strconv.FormatInt(x, 10), nil
		default:
			return nil, fmt.Errorf("%s应为文本", label)
		}
	}
}

func choiceOf(label string, opts []string) func(any) (any, error) {
	return func(v any) (any, error) {
		s, _ := v.(string)
		for _, o := range opts {
			if s == o {
				return s, nil
			}
		}
		return nil, fmt.Errorf("%s只能是 %s", label, strings.Join(opts, " / "))
	}
}

// Cleaners 字段名 → 校验函数（对应 Python CLEANERS）
var Cleaners = map[string]func(any) (any, error){
	"rulesets":      CleanRulesets,
	"bypass":        CleanBypass,
	"tests":         CleanTests,
	"rules":         CleanRules,
	"subs":          CleanSubs,
	"nodes":         CleanNodes,
	"custom_groups": CleanCustomGroups,
	"adblock":       CleanAdblock,
	"devices":       CleanDevices,
	"device_routes": func(v any) (any, error) { return devroute.CleanDeviceRoutes(v) },
	"schedule":      CleanSchedule,
	"dns":           cleanDNS,
	"tun":           dictOf("TUN 设置"),
	"groups_cfg":    dictOf("地区分组设置"),
	"sub_interval":  intOf("订阅更新间隔", 0, 100000000),
	"log_limit":     intOf("日志上限", 1, 100),
	"region_groups": boolOf,
	"ipv6":          boolOf,
	"watchdog":      boolOf,
	"sniffer":       boolOf,
	"tproxy":        boolOf,
	"tg_token":      textOf("Telegram Token"),
	"tg_chat":       textOf("Telegram Chat ID"),
	"gh_proxy":      textOf("GitHub 加速地址"),
	"mode":          choiceOf("代理模式", []string{"rule", "global", "direct"}),
	"proxy_mode":    choiceOf("代理方式", append(append([]string{}, base.ProxyModes...), "")),
}

// CleanFields 按 CLEANERS 校验并规范化 b 中出现在 keys 里的字段，返回新 dict；有问题抛错（提示可直接给用户看）
func CleanFields(b any, keys []string) (map[string]any, error) {
	bm, ok := b.(map[string]any)
	if !ok {
		return nil, errors.New("请求内容应为 JSON 对象")
	}
	out := map[string]any{}
	for _, k := range keys {
		if v, present := bm[k]; present {
			if fn, ok := Cleaners[k]; ok {
				nv, err := fn(v)
				if err != nil {
					return nil, err
				}
				out[k] = nv
			} else {
				out[k] = v
			}
		}
	}
	return out, nil
}

// ---------- 小助手 ----------

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func firstN(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

func listOf(v any) []any {
	l, _ := v.([]any)
	return l
}

func listOr(v any, def []any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return def
}
