package singbox

// sb_rules.py：mihomo 规则字符串 → sing-box 路由规则。

import (
	"fmt"
	"regexp"
	"strings"

	"shunt/internal/ruleutil"
)

// GeoSrsEntry GEOIP/GEOSITE → (tag, 规则集条目)。SBRules.UseGeo 与 sb_geo_rule_sets 共用，避免两处硬编码同一 URL 格式。
func GeoSrsEntry(kind, name string) (string, map[string]any) {
	tag := ruleutil.RsTag(kind, name)
	return tag, map[string]any{
		"kind": "geo",
		"url":  fmt.Sprintf("%s/%s/%s.srs", SBGeo, kind, strings.ToLower(name)),
		"path": fmt.Sprintf("%s-%s.srs", kind, strings.ToLower(name)),
	}
}

// splitTop 「(A,b),(C,d)」按最外层逗号拆分
func splitTop(s string) []string {
	var out []string
	depth := 0
	var cur strings.Builder
	for _, ch := range s {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
		}
		if ch == ',' && depth == 0 {
			out = append(out, cur.String())
			cur.Reset()
		} else {
			cur.WriteRune(ch)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

var (
	logicalRe  = regexp.MustCompile(`(?i)^(AND|OR|NOT)\s*,\s*\((.*)\)$`)
	intOnlyRe  = regexp.MustCompile(`^\d+$`)
	intRangeRe = regexp.MustCompile(`^\d+-\d+$`)
)

// condKind: ok=可翻译 / never=永不命中（False）/ unsupported=不支持（None）
type condKind int

const (
	condUnsupported condKind = iota
	condNever
	condOK
)

type condResult struct {
	rule map[string]any
	kind condKind
}

// SBRules 收集翻译过程中用到的规则集、入站，以及无法翻译的条目
type SBRules struct {
	Cfg      map[string]any
	Inbounds map[string]bool // 入站 tag 集合
	Alias    map[string]string
	RuleSets map[string]any
	Warn     *[]string
}

// NewSBRules 构造 SBRules；warn 为共享的警告列表（build 流程里与外层共用同一份）
func NewSBRules(cfg map[string]any, inbounds map[string]bool, alias map[string]string, ruleSets map[string]any, warn *[]string) *SBRules {
	return &SBRules{Cfg: cfg, Inbounds: inbounds, Alias: alias, RuleSets: ruleSets, Warn: warn}
}

// UseGeo 注册 GEO 规则集并返回其 tag
func (s *SBRules) UseGeo(kind, name string) string {
	tag, entry := GeoSrsEntry(kind, name)
	if _, ok := s.RuleSets[tag]; !ok {
		s.RuleSets[tag] = entry
	}
	return tag
}

// Cond 单个匹配条件 → sing-box 规则字段；不支持时 kind=condUnsupported，永不命中时 kind=condNever
func (s *SBRules) Cond(typ, val string) condResult {
	typ, val = strings.ToUpper(strings.TrimSpace(typ)), strings.TrimSpace(val)
	switch typ {
	case "DOMAIN":
		return condResult{map[string]any{"domain": []any{strings.ToLower(val)}}, condOK}
	case "DOMAIN-SUFFIX":
		return condResult{map[string]any{"domain_suffix": []any{strings.ToLower(strings.TrimLeft(val, "."))}}, condOK}
	case "DOMAIN-KEYWORD":
		return condResult{map[string]any{"domain_keyword": []any{strings.ToLower(val)}}, condOK}
	case "DOMAIN-REGEX":
		return condResult{map[string]any{"domain_regex": []any{val}}, condOK}
	case "DOMAIN-WILDCARD":
		k, v := ruleutil.MhDomain(val)
		return condResult{map[string]any{k: []any{v}}, condOK}
	case "IP-CIDR", "IP-CIDR6":
		return condResult{map[string]any{"ip_cidr": []any{val}}, condOK}
	case "SRC-IP-CIDR":
		return condResult{map[string]any{"source_ip_cidr": []any{val}}, condOK}
	case "DST-PORT", "SRC-PORT", "IN-PORT":
		key := map[string]string{"DST-PORT": "port", "SRC-PORT": "source_port", "IN-PORT": "port"}[typ]
		var ports []any
		var ranges []any
		for _, x := range strings.Split(strings.ReplaceAll(val, "/", ","), ",") {
			x = strings.TrimSpace(x)
			if intOnlyRe.MatchString(x) {
				n, _ := atoi(x)
				ports = append(ports, n)
			} else if intRangeRe.MatchString(x) {
				ranges = append(ranges, strings.ReplaceAll(x, "-", ":"))
			}
		}
		if typ == "IN-PORT" {
			return condResult{nil, condUnsupported}
		}
		c := map[string]any{}
		if len(ports) > 0 {
			c[key] = ports
		}
		if len(ranges) > 0 {
			c[key+"_range"] = ranges
		}
		if len(c) == 0 {
			return condResult{nil, condUnsupported}
		}
		return condResult{c, condOK}
	case "NETWORK":
		return condResult{map[string]any{"network": []any{strings.ToLower(val)}}, condOK}
	case "GEOSITE":
		return condResult{map[string]any{"rule_set": []any{s.UseGeo("geosite", val)}}, condOK}
	case "GEOIP":
		if low := strings.ToLower(val); low == "private" || low == "lan" {
			return condResult{map[string]any{"ip_is_private": true}, condOK}
		}
		return condResult{map[string]any{"rule_set": []any{s.UseGeo("geoip", val)}}, condOK}
	case "RULE-SET":
		if _, ok := s.RuleSets[val]; ok {
			return condResult{map[string]any{"rule_set": []any{val}}, condOK}
		}
		return condResult{nil, condUnsupported}
	case "IN-TYPE":
		want := map[string]string{"TPROXY": "tproxy-in", "TUN": "tun-in", "MIXED": "mixed-in", "HTTP": "mixed-in", "SOCKS5": "mixed-in"}
		seen := map[string]bool{}
		for _, x := range strings.Split(strings.ToUpper(val), "/") {
			if tag, ok := want[x]; ok {
				if s.Inbounds[tag] {
					seen[tag] = true
				}
			}
		}
		var tags []any
		for t := range seen {
			tags = append(tags, t)
		}
		sortAny(tags)
		if len(tags) == 0 {
			return condResult{nil, condNever}
		}
		return condResult{map[string]any{"inbound": tags}, condOK}
	case "PROCESS-NAME", "PROCESS-PATH":
		key := "process_name"
		if typ == "PROCESS-PATH" {
			key = "process_path"
		}
		return condResult{map[string]any{key: []any{val}}, condOK}
	}
	return condResult{nil, condUnsupported}
}

// Logical AND/OR/NOT 组合规则
func (s *SBRules) Logical(typ, inner string) condResult {
	var subs []any
	for _, part := range splitTop(inner) {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "(") && strings.HasSuffix(part, ")") {
			part = part[1 : len(part)-1]
		}
		r := s.Match(part)
		if r.kind != condOK {
			return r
		}
		subs = append(subs, r.rule)
	}
	if len(subs) == 0 {
		return condResult{nil, condUnsupported}
	}
	if typ == "NOT" {
		var r map[string]any
		if len(subs) == 1 {
			r = copyMap(subs[0].(map[string]any))
		} else {
			r = map[string]any{"type": "logical", "mode": "and", "rules": subs}
		}
		inv, _ := r["invert"].(bool)
		r["invert"] = !inv
		return condResult{r, condOK}
	}
	return condResult{map[string]any{"type": "logical", "mode": strings.ToLower(typ), "rules": subs}, condOK}
}

// Match 不含策略的匹配部分 → 规则 dict / 不支持 / 永不命中
func (s *SBRules) Match(body string) condResult {
	if m := logicalRe.FindStringSubmatch(strings.TrimSpace(body)); m != nil {
		return s.Logical(strings.ToUpper(m[1]), m[2])
	}
	typ, val, _ := strings.Cut(body, ",")
	if val == "" {
		return condResult{nil, condUnsupported}
	}
	v, _, _ := strings.Cut(val, ",")
	return s.Cond(typ, v)
}

// Action 策略 → sing-box 动作；PASS 返回 nil（无动作）
func (s *SBRules) Action(pol string) map[string]any {
	pol = strings.TrimSpace(pol)
	if a, ok := s.Alias[pol]; ok {
		pol = a
	}
	switch pol {
	case "REJECT":
		return map[string]any{"action": "reject"}
	case "REJECT-DROP":
		return map[string]any{"action": "reject", "method": "drop"}
	case "DIRECT", "COMPATIBLE":
		return map[string]any{"action": "route", "outbound": "DIRECT"}
	case "PASS":
		return nil
	}
	return map[string]any{"action": "route", "outbound": pol}
}

// Rule 完整规则「类型,值,策略[,no-resolve]」→ (规则 dict 或 nil, 是否需要先解析域名)
func (s *SBRules) Rule(line string) (map[string]any, bool) {
	parts := strings.Split(line, ",")
	i := ruleutil.RulePolicyIndex(parts)
	var body, pol string
	if ul := strings.ToUpper(line); strings.HasPrefix(ul, "AND,") || strings.HasPrefix(ul, "OR,") || strings.HasPrefix(ul, "NOT,") {
		k := strings.LastIndex(line, ")")
		body = line[:k+1]
		pol, _, _ = strings.Cut(strings.Trim(line[k+1:], ","), ",")
	} else {
		body = strings.Join(parts[:i], ",")
		pol = parts[i]
	}
	typ, _, _ := strings.Cut(body, ",")
	typ = strings.ToUpper(strings.TrimSpace(typ))
	if typ == "MATCH" {
		return nil, false
	}
	act := s.Action(pol)
	r := s.Match(body)
	if act == nil || r.kind == condNever {
		return nil, false
	}
	if r.kind == condUnsupported {
		*s.Warn = append(*s.Warn, fmt.Sprintf("规则「%s」sing-box 不支持，已跳过", firstN(line, 80)))
		return nil, false
	}
	m := copyMap(r.rule)
	for k, v := range act {
		m[k] = v
	}
	needs := (typ == "GEOIP" || typ == "IP-CIDR" || typ == "IP-CIDR6") &&
		!hasNoResolve(parts[i+1:]) && !isTrue(m["ip_is_private"])
	return m, needs
}

func hasNoResolve(tail []string) bool {
	for _, x := range tail {
		if strings.ToLower(strings.TrimSpace(x)) == "no-resolve" {
			return true
		}
	}
	return false
}

func isTrue(v any) bool {
	b, _ := v.(bool)
	return b
}

func copyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func firstN(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

func atoi(s string) (int, error) {
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(ch-'0')
	}
	return n, nil
}

func sortAny(v []any) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && fmt.Sprint(v[j]) < fmt.Sprint(v[j-1]); j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}
