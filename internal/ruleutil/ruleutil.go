// Package ruleutil 对应 Python shunt/ruleutil.py：规则工具（叶子模块），只依赖 base。
package ruleutil

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"shunt/internal/base"
)

var domainRx = regexp.MustCompile(`^(?:[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9\-]{1,59})$`)

// DomainValid 校验域名格式（Python 原正则的 (?=.{1,253}$) 前瞻改为长度检查，RE2 不支持前瞻）
func DomainValid(s string) bool {
	s = strings.ToLower(s)
	if len(s) < 1 || len(s) > 253 {
		return false
	}
	return domainRx.MatchString(s)
}

// RulePolicyIndex 返回规则行中策略字段的位置（跳过末尾的 no-resolve / src）
func RulePolicyIndex(parts []string) int {
	i := len(parts) - 1
	for i > 0 {
		switch strings.TrimSpace(strings.ToLower(parts[i])) {
		case "no-resolve", "src":
			i--
		default:
			return i
		}
	}
	return i
}

// DnsPolicyOf 取 DNS 服务器 "#策略" 后缀中的策略名
func DnsPolicyOf(server string) string {
	_, tail, found := strings.Cut(server, "#")
	if !found {
		return ""
	}
	head := strings.SplitN(tail, "&", 2)[0]
	if strings.Contains(head, "=") {
		return ""
	}
	return head
}

// MhDomain mihomo 域名通配（+.a.com / *.a.com / a.*.com）→ (sing-box 字段, 值)
func MhDomain(x string) (string, string) {
	x = strings.ToLower(strings.TrimSpace(x))
	pre := ""
	if strings.HasPrefix(x, "+.") {
		x, pre = x[2:], `(?:[^.]+\.)*`
	} else if strings.HasPrefix(x, ".") {
		x, pre = x[1:], `(?:[^.]+\.)+`
	}
	if strings.Contains(x, "*") {
		// 含通配：只能用正则，否则 domain_suffix 会把「stun.*.*」当成字面量，永远匹配不到
		escaped := strings.ReplaceAll(regexp.QuoteMeta(x), `\*`, `[^.]+`)
		return "domain_regex", "^" + pre + escaped + "$"
	}
	if pre != "" {
		if strings.HasSuffix(pre, "*") {
			return "domain_suffix", x
		}
		return "domain_suffix", "." + x
	}
	return "domain", x
}

// RsTag 规则集 tag：geosite/geoip 加 kind 前缀
func RsTag(kind, name string) string {
	if kind == "geosite" || kind == "geoip" {
		return strings.ToLower(kind + "-" + name)
	}
	return name
}

// AdblockProviders 广告拦截的 provider 与规则（mihomo 格式）
func AdblockProviders(d map[string]any) (map[string]any, []string) {
	ab, _ := d["adblock"].(map[string]any)
	if ab == nil || !isTrue(ab["enabled"]) {
		return map[string]any{}, nil
	}
	prov := map[string]any{}
	add := func(name, fn string) {
		path := filepath.Join(base.AbDir, fn)
		if st, err := os.Stat(path); err == nil && st.Size() > 0 {
			prov[name] = map[string]any{"type": "file", "behavior": "domain", "format": "text", "path": "./adblock/" + fn}
		}
	}
	add("ad-allow", "allow.txt")
	add("ad-custom", "custom.txt")
	if lists, ok := ab["lists"].([]any); ok {
		for _, li := range lists {
			lm, ok := li.(map[string]any)
			if !ok {
				continue
			}
			en, _ := lm["enabled"].(bool)
			id, _ := lm["id"].(string)
			if !en && lm["enabled"] != nil {
				continue
			}
			if matched, _ := regexp.MatchString(`^[0-9a-f]{8}$`, id); matched {
				add("ad-"+id, id+".txt")
			}
		}
	}
	var rules []string
	for k := range prov {
		if k == "ad-allow" {
			continue
		}
		if _, ok := prov["ad-allow"]; ok {
			rules = append(rules, "AND,((RULE-SET,"+k+"),(NOT,((RULE-SET,ad-allow)))),REJECT")
		} else {
			rules = append(rules, "RULE-SET,"+k+",REJECT")
		}
	}
	return prov, rules
}

func isTrue(v any) bool {
	b, _ := v.(bool)
	return b
}
