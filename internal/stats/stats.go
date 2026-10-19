// Package stats 对应 Python shunt/stats.py：流量统计。
package stats

import (
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"shunt/internal/base"
	"shunt/internal/data"
)

// ConnsSnapshotHook 对应 core.conns_snapshot（ttl=2 秒，与 Python conns_snapshot(timeout=5, ttl=2) 一致）。
// stats 不能 import core（core → mihomo → devroute → stats 会循环），由 core 包在 init 中注入；
// 未注入时返回 nil（调用方按"抓取失败"处理）。
var ConnsSnapshotHook = func(timeoutSec int, ttlSec float64) map[string]any { return nil }

func connsSnapshot(timeoutSec int) map[string]any {
	return ConnsSnapshotHook(timeoutSec, 2)
}

type statsDay struct {
	Up   int64               `json:"up"`
	Down int64               `json:"down"`
	Dev  map[string][2]int64 `json:"dev"`
	Node map[string][2]int64 `json:"node"`
}

type statsData struct {
	Days map[string]*statsDay `json:"days"`
}

// Stats 流量统计
type Stats struct {
	mu     sync.Mutex
	data   statsData
	conns  map[string][2]int64
	tot    [2]int64
	hasTot bool
	saved  float64
}

// NewStats 构造（读已有 stats.json）
func NewStats() *Stats {
	d := data.ReadJSON(base.StatsFile, statsData{})
	if d.Days == nil {
		d.Days = map[string]*statsDay{}
	}
	for _, b := range d.Days {
		if b.Dev == nil {
			b.Dev = map[string][2]int64{}
		}
		if b.Node == nil {
			b.Node = map[string][2]int64{}
		}
	}
	return &Stats{data: d, conns: map[string][2]int64{}, saved: nowFloat()}
}

func nowFloat() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func (s *Stats) bucket(day string) *statsDay {
	b, ok := s.data.Days[day]
	if !ok {
		b = &statsDay{Dev: map[string][2]int64{}, Node: map[string][2]int64{}}
		s.data.Days[day] = b
	}
	return b
}

// Poll 抓一次 /connections 快照并累加
func (s *Stats) Poll() {
	c := connsSnapshot(5)
	if c == nil {
		s.mu.Lock()
		s.conns, s.hasTot = map[string][2]int64{}, false
		s.mu.Unlock()
		return
	}
	ut, dt := data.Int(c, "uploadTotal"), data.Int(c, "downloadTotal")
	cur := map[string][2]int64{}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.bucket(time.Now().Format("2006-01-02"))
	first := !s.hasTot
	if !first {
		// 核心重启后计数归零
		if int64(ut) >= s.tot[0] {
			b.Up += int64(ut) - s.tot[0]
		} else {
			b.Up += int64(ut)
		}
		if int64(dt) >= s.tot[1] {
			b.Down += int64(dt) - s.tot[1]
		} else {
			b.Down += int64(dt)
		}
	}
	s.tot, s.hasTot = [2]int64{int64(ut), int64(dt)}, true
	for _, x := range data.List(c, "connections") {
		xm, ok := x.(map[string]any)
		if !ok {
			continue
		}
		id := data.Str(xm, "id")
		up, dn := int64(data.Int(xm, "upload")), int64(data.Int(xm, "download"))
		cur[id] = [2]int64{up, dn}
		if first {
			continue
		}
		pu, pd := s.conns[id][0], s.conns[id][1]
		du, dd := up-pu, dn-pd
		if du < 0 {
			du = 0
		}
		if dd < 0 {
			dd = 0
		}
		if du == 0 && dd == 0 {
			continue
		}
		src := data.Str(data.Map(xm, "metadata"), "sourceIP")
		if src == "" {
			src = "?"
		}
		node := "DIRECT"
		if chains := data.List(xm, "chains"); len(chains) > 0 {
			if cs, ok := chains[0].(string); ok {
				node = cs
			}
		}
		for _, pair := range [][2]string{{"dev", src}, {"node", node}} {
			var m map[string][2]int64
			if pair[0] == "dev" {
				m = b.Dev
			} else {
				m = b.Node
			}
			k := pair[1]
			e := m[k]
			m[k] = [2]int64{e[0] + du, e[1] + dd}
		}
	}
	s.conns = cur
	if nowFloat()-s.saved > 60 {
		s.flushLocked()
	}
}

// Flush 落盘（只保留 60 天）
func (s *Stats) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flushLocked()
}

func (s *Stats) flushLocked() {
	keys := make([]string, 0, len(s.data.Days))
	for k := range s.data.Days {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 60 {
		keys = keys[len(keys)-60:]
	}
	keep := map[string]*statsDay{}
	for _, k := range keys {
		keep[k] = s.data.Days[k]
	}
	s.data.Days = keep
	_ = data.WriteJSON(base.StatsFile, s.data)
	s.saved = nowFloat()
}

// aggRow 聚合行
type aggRow struct {
	Up, Down int64
	Dev      [][3]any
	Node     [][3]any
}

func agg(days map[string]*statsDay, keys []string) map[string]any {
	r := aggRow{}
	devAgg, nodeAgg := map[string][2]int64{}, map[string][2]int64{}
	for _, k := range keys {
		b, ok := days[k]
		if !ok {
			continue
		}
		r.Up += b.Up
		r.Down += b.Down
		for n, v := range b.Dev {
			e := devAgg[n]
			devAgg[n] = [2]int64{e[0] + v[0], e[1] + v[1]}
		}
		for n, v := range b.Node {
			e := nodeAgg[n]
			nodeAgg[n] = [2]int64{e[0] + v[0], e[1] + v[1]}
		}
	}
	r.Dev = topList(devAgg)
	r.Node = topList(nodeAgg)
	return map[string]any{"up": r.Up, "down": r.Down, "dev": r.Dev, "node": r.Node}
}

func topList(m map[string][2]int64) [][3]any {
	out := make([][3]any, 0, len(m))
	for n, v := range m {
		out = append(out, [3]any{n, v[0], v[1]})
	}
	sort.Slice(out, func(i, j int) bool {
		ai := out[i][1].(int64) + out[i][2].(int64)
		aj := out[j][1].(int64) + out[j][2].(int64)
		return ai > aj
	})
	if len(out) > 100 {
		out = out[:100]
	}
	return out
}

// Report 上报：今日 / 本月 / 每日 / ARP 表
func (s *Stats) Report() map[string]any {
	s.mu.Lock()
	days := map[string]*statsDay{}
	for k, v := range s.data.Days {
		cp := *v
		days[k] = &cp
	}
	s.mu.Unlock()
	today := time.Now().Format("2006-01-02")
	month := time.Now().Format("2006-01")
	var todayKeys, monthKeys []string
	for k := range days {
		if k == today {
			todayKeys = append(todayKeys, k)
		}
		if strings.HasPrefix(k, month) {
			monthKeys = append(monthKeys, k)
		}
	}
	var dayRows []any
	for _, k := range sortedKeys(days) {
		dayRows = append(dayRows, map[string]any{"date": k, "up": days[k].Up, "down": days[k].Down})
	}
	return map[string]any{
		"today": agg(days, todayKeys),
		"month": agg(days, monthKeys),
		"days":  dayRows,
		"arp":   ArpTable(),
	}
}

func sortedKeys(m map[string]*statsDay) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Loop 每 5 秒 poll 一次
func (s *Stats) Loop() {
	tk := time.NewTicker(5 * time.Second)
	defer tk.Stop()
	for range tk.C {
		func() {
			defer func() {
				_ = recover()
			}()
			s.Poll()
		}()
	}
}

// ArpTable 读 /proc/net/arp 得 IP→MAC 表
func ArpTable() map[string]string {
	out := map[string]string{}
	raw, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return out
	}
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines[1:] {
		p := strings.Fields(line)
		if len(p) >= 4 && p[3] != "00:00:00:00:00:00" {
			out[p[0]] = p[3]
		}
	}
	return out
}
