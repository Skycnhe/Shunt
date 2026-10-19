package adblock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shunt/internal/base"
)

func TestNormDomain(t *testing.T) {
	cases := map[string]string{
		"Example.COM.":  "example.com",
		"  a.b.com  ":   "a.b.com",
		"*.a.com":       "",
		"not a domain":  "",
		"":              "",
		"a":             "",
		"xn--fiqs8s.cn": "xn--fiqs8s.cn",
	}
	for in, want := range cases {
		if got := NormDomain(in); got != want {
			t.Fatalf("NormDomain(%q) = %q, want %q", in, got, want)
		}
	}
	if NormDomain(strings.Repeat("a", 250)+".com") != "" {
		t.Fatal("over 253 chars should be rejected")
	}
}

func TestParseFilterABP(t *testing.T) {
	text := "||ads.example.com^\n@@||allow.example.com^\n! comment\n# another\n[Adblock]\n"
	bs, be, as_, ae, skipped := ParseFilter(text, false)
	if !bs["ads.example.com"] || len(be) != 0 {
		t.Fatalf("ABP block: bs=%v be=%v", bs, be)
	}
	if !as_["allow.example.com"] || len(ae) != 0 {
		t.Fatalf("ABP allow: as=%v ae=%v", as_, ae)
	}
	if skipped != 0 {
		t.Fatalf("skipped should be 0, got %d", skipped)
	}
}

func TestParseFilterModifiers(t *testing.T) {
	// $important 允许，其他修饰符跳过
	bs, _, _, _, skipped := ParseFilter("||a.com^$important\n||b.com^$client=foo\n||c.com^$denyallow=x.com\n", false)
	if !bs["a.com"] || bs["b.com"] || bs["c.com"] {
		t.Fatalf("modifiers: %v skipped=%d", bs, skipped)
	}
	if skipped != 2 {
		t.Fatalf("skipped=%d", skipped)
	}
}

func TestParseFilterHosts(t *testing.T) {
	text := "0.0.0.0 bad.com tracker.com\n127.0.0.1 evil.org\n0.0.0.0 localhost\n::1 ipv6bad.net\n"
	_, be, _, _, skipped := ParseFilter(text, false)
	for _, d := range []string{"bad.com", "tracker.com", "evil.org", "ipv6bad.net"} {
		if !be[d] {
			t.Fatalf("%s should be exact-blocked: %v", d, be)
		}
	}
	if be["localhost"] {
		t.Fatal("localhost should be skipped")
	}
	if skipped != 0 {
		t.Fatalf("skipped=%d", skipped)
	}
}

func TestParseFilterPlain(t *testing.T) {
	bs, be, _, _, _ := ParseFilter("plain.com\n+.suf.com\n.sub.com\n", false)
	if !be["plain.com"] {
		t.Fatalf("plain domain should be exact: %v", be)
	}
	if !bs["suf.com"] || !bs["sub.com"] {
		t.Fatalf("+. /. prefix should be suffix: %v", bs)
	}
	// plain_suffix=true 时纯域名也进后缀
	bs2, be2, _, _, _ := ParseFilter("plain.com\n", true)
	if !bs2["plain.com"] || len(be2) != 0 {
		t.Fatalf("plain_suffix: %v %v", bs2, be2)
	}
}

func TestParseFilterClash(t *testing.T) {
	text := "DOMAIN-SUFFIX,clash.com\nDOMAIN,exact.net\nIP-CIDR,1.1.1.0/24\nDOMAIN-KEYWORD,ad\n- DOMAIN-SUFFIX,yaml.com\n- '+.quoted.com'\npayload:\n"
	bs, be, _, _, skipped := ParseFilter(text, false)
	if !bs["clash.com"] || !bs["yaml.com"] || !bs["quoted.com"] {
		t.Fatalf("clash suffix: %v", bs)
	}
	if !be["exact.net"] {
		t.Fatalf("clash exact: %v", be)
	}
	if skipped != 2 { // IP-CIDR + DOMAIN-KEYWORD
		t.Fatalf("skipped=%d", skipped)
	}
}

func TestParseFilterMisc(t *testing.T) {
	// 正则 / URL 规则 / 通配符跳过
	_, _, _, _, skipped := ParseFilter("/ads\\.com/\n|http://x.com/ads\n||bad*.com^\n", false)
	if skipped != 3 {
		t.Fatalf("skipped=%d", skipped)
	}
	// @@ 简写白名单（plain_suffix）
	_, _, as_, _, skipped := ParseFilter("@@white.com\n@@|pipe.com^\n", true)
	if !as_["white.com"] || !as_["pipe.com"] {
		t.Fatalf("shorthand allow: %v skipped=%d", as_, skipped)
	}
	// 无效域名计数
	_, _, _, _, skipped = ParseFilter("not_a_domain\n", false)
	if skipped != 1 {
		t.Fatalf("skipped=%d", skipped)
	}
}

func TestPrune(t *testing.T) {
	suffix := map[string]bool{"a.com": true, "sub.a.com": true, "b.com": true}
	exact := map[string]bool{"x.a.com": true, "y.com": true, "b.com": true}
	s2, e2 := Prune(suffix, exact)
	if s2["sub.a.com"] || !s2["a.com"] || !s2["b.com"] {
		t.Fatalf("suffix prune: %v", s2)
	}
	if e2["x.a.com"] || e2["b.com"] || !e2["y.com"] {
		t.Fatalf("exact prune: %v", e2)
	}
}

func TestDomainLines(t *testing.T) {
	lines, n := DomainLines(map[string]bool{"b.com": true, "a.com": true}, map[string]bool{"z.com": true})
	if n != 3 {
		t.Fatalf("count=%d", n)
	}
	want := []string{"+.a.com", "+.b.com", "z.com"}
	if len(lines) != 3 || lines[0] != want[0] || lines[1] != want[1] || lines[2] != want[2] {
		t.Fatalf("lines=%v", lines)
	}
}

func TestParents(t *testing.T) {
	p := Parents("a.b.com", true)
	if len(p) != 3 || p[0] != "a.b.com" || p[2] != "com" {
		t.Fatalf("parents self: %v", p)
	}
	p = Parents("a.b.com", false)
	if len(p) != 2 || p[0] != "b.com" {
		t.Fatalf("parents: %v", p)
	}
}

func TestAbMatch(t *testing.T) {
	suf := map[string]bool{"ads.com": true}
	ex := map[string]bool{"evil.com": true}
	if r, ok := AbMatch("evil.com", suf, ex); !ok || r != "evil.com" {
		t.Fatalf("exact: %q %v", r, ok)
	}
	if r, ok := AbMatch("sub.ads.com", suf, ex); !ok || r != "+.ads.com" {
		t.Fatalf("suffix: %q %v", r, ok)
	}
	if _, ok := AbMatch("good.com", suf, ex); ok {
		t.Fatal("should not match")
	}
}

func TestFmtSize(t *testing.T) {
	if FmtSize(512) != "512 B" {
		t.Fatalf("B: %s", FmtSize(512))
	}
	if FmtSize(2048) != "2.0 KB" {
		t.Fatalf("KB: %s", FmtSize(2048))
	}
	if FmtSize(5*1024*1024) != "5.0 MB" {
		t.Fatalf("MB: %s", FmtSize(5*1024*1024))
	}
}

func TestListID(t *testing.T) {
	id := ListID("https://example.com/list.txt")
	if len(id) != 8 {
		t.Fatalf("id len: %q", id)
	}
	if ListID("https://example.com/list.txt ") != id {
		t.Fatal("should trim space")
	}
	if ListID("https://other.com/") == id {
		t.Fatal("different url should differ")
	}
}

func TestWriteLinesRoundtrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "x.txt")
	if err := WriteLines(p, []string{"+.a.com", "b.com"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if string(raw) != "+.a.com\nb.com\n" {
		t.Fatalf("content: %q", raw)
	}
	if err := WriteLines(p, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(p)
	if string(raw) != "" {
		t.Fatalf("empty: %q", raw)
	}
}

func TestIsFakeIP(t *testing.T) {
	if !IsFakeIP("198.18.0.11") || !IsFakeIP("198.19.5.5") {
		t.Fatal("fake-ip range")
	}
	if IsFakeIP("8.8.8.8") || IsFakeIP("not-an-ip") {
		t.Fatal("public / invalid should be false")
	}
	if !IsFakeIP("[198.18.0.1]") {
		t.Fatal("bracketed should be stripped")
	}
}

func TestAbCompose(t *testing.T) {
	dir := t.TempDir()
	old := base.AbDir
	base.AbDir = dir
	defer func() { base.AbDir = old }()

	// 准备一个列表的 allow 文件
	os.WriteFile(filepath.Join(dir, "abcd1234.allow.txt"), []byte("+.fromlist.com\n"), 0o644)
	d := map[string]any{"adblock": map[string]any{
		"black": []any{"||blacked.com^", "exactblack.net"},
		"white": []any{"||whited.com^", "@@shorthand.org"},
		"lists": []any{map[string]any{"id": "abcd1234", "enabled": true}},
	}}
	if err := AbCompose(d); err != nil {
		t.Fatal(err)
	}
	custom, _ := os.ReadFile(filepath.Join(dir, "custom.txt"))
	if !strings.Contains(string(custom), "+.blacked.com") || !strings.Contains(string(custom), "exactblack.net") {
		t.Fatalf("custom.txt: %q", custom)
	}
	allow, _ := os.ReadFile(filepath.Join(dir, "allow.txt"))
	for _, want := range []string{"+.whited.com", "+.shorthand.org", "+.fromlist.com"} {
		if !strings.Contains(string(allow), want) {
			t.Fatalf("allow.txt missing %s: %q", want, allow)
		}
	}
}
