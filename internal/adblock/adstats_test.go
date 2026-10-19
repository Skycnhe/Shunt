package adblock

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"shunt/internal/base"
)

func mkLine(payload string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(map[string]any{"payload": payload})
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	return string(b)
}

func newTestStats(t *testing.T) *AdStats {
	t.Helper()
	dir := t.TempDir()
	old, oldCore := base.AbStatsFile, activeCore
	base.AbStatsFile = filepath.Join(dir, "adblock_stats.json")
	activeCore = func(d ...map[string]any) string { return "mihomo" }
	t.Cleanup(func() { base.AbStatsFile, activeCore = old, oldCore })
	return NewAdStats()
}

func TestSinkMihomo(t *testing.T) {
	s := newTestStats(t)
	s.Sink(mkLine("--> ads.example.com:443 match RuleSet(ad-1a2b3c4d) using REJECT"))
	s.Sink(mkLine("--> ok.example.com:443 match RuleSet(ad-1a2b3c4d) using DIRECT"))
	s.Sink(mkLine("--> x:1 doesn't match anything"))
	s.Sink("not json at all")
	s.Sink(`{"payload":"no arrow here"}`) // 无 --> 直接跳过
	if s.Today() != 1 {
		t.Fatalf("today should be 1, got %d", s.Today())
	}
	r := s.Report()
	if r["today"].(int) != 1 {
		t.Fatalf("report today: %v", r["today"])
	}
	top := r["top"].([]any)
	if len(top) != 1 || top[0].([]any)[0].(string) != "ads.example.com" {
		t.Fatalf("top: %v", top)
	}
	lists := r["lists"].(map[string]int)
	if lists["1a2b3c4d)"] != 1 { // 与 Python 一致：key 含右括号
		t.Fatalf("lists: %v", lists)
	}
}

func TestSinkFakeIPExcluded(t *testing.T) {
	s := newTestStats(t)
	s.Sink(mkLine("--> 198.18.0.11:443 match RuleSet(ad-aaaaaaaa) using REJECT"))
	r := s.Report()
	if r["today"].(int) != 1 {
		t.Fatalf("count should include fake-ip: %v", r["today"])
	}
	if len(r["top"].([]any)) != 0 {
		t.Fatalf("fake-ip should not enter top: %v", r["top"])
	}
}

func TestSinkSb(t *testing.T) {
	s := newTestStats(t)
	s.SinkSb(mkLine("[12 5ms] inbound/tproxy[tcp:192.168.1.2]: inbound connection to ads.sb.com:443"))
	s.SinkSb(mkLine("[12 8ms] router: match[3] example.com rule_set=ad-bb11cc22 => reject"))
	if s.Today() != 1 {
		t.Fatalf("sb reject should count: %d", s.Today())
	}
	// sniffed 更新域名
	s.SinkSb(mkLine("[13 5ms] inbound/tproxy[tcp:192.168.1.3]: inbound connection to 198.18.0.5:443"))
	s.SinkSb(mkLine("[13 6ms] router: sniffed protocol: tls, domain: sniffed.com"))
	s.SinkSb(mkLine("[13 9ms] router: match[1] x rule_set=ad-bb11cc22 => reject"))
	r := s.Report()
	top := r["top"].([]any)
	found := false
	for _, e := range top {
		if e.([]any)[0].(string) == "sniffed.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("sniffed domain should be in top: %v", top)
	}
	// DNS 查询 + 拦截（predefined：Python 分支顺序决定只有它能走到 SB_DREJ）
	s.SinkSb(mkLine("[20 1ms] dns: exchange bad.dns.com. IN A"))
	s.SinkSb(mkLine("[20 2ms] dns: match[0] bad.dns.com rule_set=ad-cc33dd44 => predefined"))
	if s.Today() != 3 {
		t.Fatalf("dns reject should count: %d", s.Today())
	}
}

func TestDnsSampleAndFlush(t *testing.T) {
	s := newTestStats(t)
	s.DnsSample(10)
	s.DnsSample(20)
	s.Flush()
	raw, _ := os.ReadFile(base.AbStatsFile)
	var disk map[string]any
	if err := json.Unmarshal(raw, &disk); err != nil {
		t.Fatal(err)
	}
	if _, ok := disk["hours"]; !ok {
		t.Fatal("hours should persist")
	}
	// retention：塞入旧数据再 flush
	s2 := NewAdStats()
	for i := 0; i < 5; i++ {
		k := "2000-01-0" + string(rune('1'+i))
		s2.data.Days[k] = &AdDay{Top: map[string]int{}, Lists: map[string]int{}}
	}
	s2.Flush()
	if len(s2.data.Days) != 2 {
		t.Fatalf("days should keep 2, got %d", len(s2.data.Days))
	}
}

func TestDnsReportModes(t *testing.T) {
	s := newTestStats(t)
	// 无数据 → recent 模式
	r := s.dnsReport(map[string][2]float64{}, []float64{5, 6, 7})
	if r["mode"] != "recent" {
		t.Fatalf("mode: %v", r["mode"])
	}
	if r["last"].(float64) != 7 {
		t.Fatalf("last: %v", r["last"])
	}
	// 足够采样 → 5min 模式
	d5 := map[string][2]float64{
		"2026-10-19 10:00": {100, 2},
		"2026-10-19 10:05": {200, 4},
	}
	r = s.dnsReport(d5, nil)
	if r["mode"] != "5min" || r["avg"].(float64) != 50 {
		t.Fatalf("5min: %v", r)
	}
	if r["samples"].(float64) != 6 {
		t.Fatalf("samples: %v", r["samples"])
	}
}

func TestReportHours(t *testing.T) {
	s := newTestStats(t)
	r := s.Report()
	hours := r["hours"].([]any)
	if len(hours) != 24 {
		t.Fatalf("hours len: %d", len(hours))
	}
	dns := r["dns"].(map[string]any)
	if dns["mode"] != "recent" {
		t.Fatalf("dns mode: %v", dns)
	}
}
