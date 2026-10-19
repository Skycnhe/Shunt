package adblock

import (
	"crypto/md5"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// 订阅 AdGuard/ABP（||domain^、@@||domain^）、hosts（0.0.0.0 domain）与纯域名列表，转换为 mihomo
// behavior=domain / format=text 的本地 rule-provider 文件：
//   ||a.com^ → "+.a.com"（含子域）；hosts / 纯域名 → "a.com"（仅该域名，与 AdGuard Home 语义一致）
// 规则：AND,((RULE-SET,ad-xxx),(NOT,((RULE-SET,ad-allow)))),REJECT —— 白名单优先，且被放行的域名继续走正常分流

var (
	clashRx  = regexp.MustCompile(`^(domain|domain-suffix),([^,\s]+)(?:,.*)?$`)
	abpRx    = regexp.MustCompile(`^(@@)?\|\|([^\^/|$]+)\^\|?(?:\$(.*))?$`)
	skipRx   = regexp.MustCompile(`^(?:domain-keyword|domain-regex|ip-cidr6?|ip-asn|geoip|geosite|process-name|user-agent|url-regex|dst-port|src-ip-cidr),`)
	domainRx = regexp.MustCompile(`^(?:[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9\-]{1,59})$`)
)

// HostsIPs hosts 文件中表示"屏蔽"的 IP 写法
var HostsIPs = map[string]bool{
	"0.0.0.0": true, "127.0.0.1": true, "::": true, "::1": true,
	"0:0:0:0:0:0:0:0": true, "::0": true, "0": true, "255.255.255.255": true,
}

// HostsSkip hosts 文件中跳过的特殊域名
var HostsSkip = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true, "broadcasthost": true,
	"ip6-localhost": true, "ip6-loopback": true, "ip6-localnet": true, "ip6-mcastprefix": true,
	"ip6-allnodes": true, "ip6-allrouters": true, "ip6-allhosts": true, "0.0.0.0": true,
}

// FmtSize 字节数 → 人类可读
func FmtSize(n float64) string {
	for _, u := range []string{"B", "KB", "MB", "GB"} {
		if n < 1024 || u == "GB" {
			if u == "B" {
				return fmt.Sprintf("%.0f %s", n, u)
			}
			return fmt.Sprintf("%.1f %s", n, u)
		}
		n /= 1024
	}
	return ""
}

// ListID 列表 URL → 8 位 ID（md5 前 8 位）
func ListID(rawurl string) string {
	sum := md5.Sum([]byte(strings.TrimSpace(rawurl)))
	return fmt.Sprintf("%x", sum)[:8]
}

// NormDomain 域名规范化：非法返回 ""
func NormDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimRight(s, ".")
	if s == "" || strings.Contains(s, "*") {
		return ""
	}
	if len(s) > 253 || !domainRx.MatchString(s) { // Go regexp 无 lookahead，长度单独校验
		return ""
	}
	return s
}

// ParseFilter 解析过滤列表文本。返回 (block后缀, block精确, allow后缀, allow精确, 跳过数)
func ParseFilter(text string, plainSuffix bool) (bs, be, as_, ae map[string]bool, skipped int) {
	bs, be, as_, ae = map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.ContainsAny(line[:1], "!#[") {
			continue
		}
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "payload:") {
			continue
		}
		if strings.HasPrefix(low, "- ") { // Clash YAML payload：  - DOMAIN-SUFFIX,a.com / - '+.a.com'
			low = strings.Trim(strings.TrimSpace(low[2:]), "'\"")
			if low == "" {
				continue
			}
		}
		if cm := clashRx.FindStringSubmatch(low); cm != nil { // Clash 规则列表
			if dom := NormDomain(cm[2]); dom != "" {
				if cm[1] == "domain-suffix" {
					bs[dom] = true
				} else {
					be[dom] = true
				}
			} else {
				skipped++
			}
			continue
		}
		if skipRx.MatchString(low) { // KEYWORD / IP 类无法用域名列表表达
			skipped++
			continue
		}
		if strings.HasPrefix(low, "||") || strings.HasPrefix(low, "@@") {
			m := abpRx.FindStringSubmatch(low)
			if m == nil {
				// 允许 @@domain / @@|domain^ 之类的简写出现在用户白名单里
				if plainSuffix && strings.HasPrefix(low, "@@") {
					if dom := NormDomain(strings.Trim(low[2:], "|^")); dom != "" {
						as_[dom] = true
						continue
					}
				}
				skipped++
				continue
			}
			allow, dom, mods := m[1] == "@@", m[2], m[3]
			badMod := false
			if mods != "" {
				for _, x := range strings.Split(mods, ",") {
					x = strings.TrimSpace(x)
					if x != "important" && x != "" {
						badMod = true // $client= / $dnstype= / $denyallow= 等修饰符无法用域名规则等价表达
						break
					}
				}
			}
			if badMod {
				skipped++
				continue
			}
			if dom = NormDomain(dom); dom == "" {
				skipped++
				continue
			}
			if allow {
				as_[dom] = true
			} else {
				bs[dom] = true
			}
			continue
		}
		if low[0] == '|' || low[0] == '/' || strings.ContainsAny(low, "$^*/\\") {
			skipped++ // 正则、URL 规则、通配符等
			continue
		}
		parts := strings.Fields(strings.SplitN(low, "#", 2)[0])
		if len(parts) >= 2 && HostsIPs[parts[0]] {
			for _, h := range parts[1:] {
				dom := NormDomain(h)
				if dom != "" && !HostsSkip[dom] {
					be[dom] = true
				} else if !HostsSkip[h] {
					skipped++
				}
			}
		} else if len(parts) == 1 {
			dom := NormDomain(strings.TrimLeft(parts[0], "+."))
			if dom == "" {
				skipped++
			} else if plainSuffix || strings.HasPrefix(parts[0], "+.") || strings.HasPrefix(parts[0], ".") {
				bs[dom] = true
			} else {
				be[dom] = true
			}
		} else {
			skipped++
		}
	}
	return bs, be, as_, ae, skipped
}

// Parents 域名的各级父域；includeSelf 时包含自身
func Parents(dom string, includeSelf bool) []string {
	parts := strings.Split(dom, ".")
	start := 1
	if includeSelf {
		start = 0
	}
	var out []string
	for i := start; i < len(parts); i++ {
		out = append(out, strings.Join(parts[i:], "."))
	}
	return out
}

// Prune 去掉已被上级 +. 规则覆盖的条目
func Prune(suffix, exact map[string]bool) (map[string]bool, map[string]bool) {
	suffix2 := map[string]bool{}
	for s := range suffix {
		covered := false
		for _, p := range Parents(s, false) {
			if suffix[p] {
				covered = true
				break
			}
		}
		if !covered {
			suffix2[s] = true
		}
	}
	exact2 := map[string]bool{}
	for e := range exact {
		covered := false
		for _, p := range Parents(e, true) {
			if suffix[p] {
				covered = true
				break
			}
		}
		if !covered {
			exact2[e] = true
		}
	}
	return suffix2, exact2
}

// DomainLines 后缀+精确集合 → 排序后的规则行（+.x 含子域）与总数
func DomainLines(suffix, exact map[string]bool) ([]string, int) {
	suffix, exact = Prune(suffix, exact)
	lines := make([]string, 0, len(suffix)+len(exact))
	for x := range suffix {
		lines = append(lines, "+."+x)
	}
	for x := range exact {
		lines = append(lines, x)
	}
	sort.Strings(lines)
	return lines, len(suffix) + len(exact)
}

// WriteLines 原子写规则行文件
func WriteLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Union 集合合并
func Union(sets ...map[string]bool) map[string]bool {
	out := map[string]bool{}
	for _, s := range sets {
		for k := range s {
			out[k] = true
		}
	}
	return out
}
