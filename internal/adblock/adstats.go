package adblock

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"shunt/internal/base"
	"shunt/internal/data"
)

// AdStats 订阅核心 info 日志，统计命中广告规则 (REJECT) 的连接；
// 另按小时统计全部连接请求数、拦截数和 DNS 解析耗时（概览「域名过滤」）
type AdStats struct {
	mu       sync.Mutex
	data     AdStatsData
	saved    float64
	reqBatch int // 未持锁攒批的 req 增量（sink 系单线程调用，无竞争）
	sbHosts  map[string]string
}

var (
	adRX    = regexp.MustCompile(`--> (\S+?):\d+ match .*?RuleSet[,(](ad-[0-9a-z]+\))` + `.* using REJECT`)
	adRXAll = regexp.MustCompile(`--> \S+ (?:match|doesn't match)`)

	sbLine  = regexp.MustCompile(`^\[(\d+) \d+ms\] (.*)$`)
	sbTo    = regexp.MustCompile(`inbound/(\w+)\[([^\]]+)\]: inbound (?:packet )?connection to (\S+?):\d+$`)
	sbSniff = regexp.MustCompile(`router: sniffed (?:packet )?protocol: \w+, domain: (\S+)`)
	sbFake  = regexp.MustCompile(`router: found fakeip domain: (\S+)`)
	sbRej   = regexp.MustCompile(`router: match\[\d+\] .*?\brule_set=(ad-[0-9a-z]+).*=> reject`)
	sbQn    = regexp.MustCompile(`dns: exchange (\S+?)\.? IN `)
	sbDrej  = regexp.MustCompile(`dns: match\[\d+\] .*?\brule_set=(ad-[0-9a-z]+).*=> (?:predefined|reject)`)
)

// ReqBatch req 计数攒批：攒够这么多行或持锁时一次性合并，减少逐行加锁
const ReqBatch = 100

// AdDay 单日拦截统计
type AdDay struct {
	Count int            `json:"count"`
	Top   map[string]int `json:"top"`
	Lists map[string]int `json:"lists"`
}

// AdHour 单小时统计
type AdHour struct {
	Req int        `json:"req"`
	Blk int        `json:"blk"`
	Dns [2]float64 `json:"dns"`
}

// AdStatsData 落盘结构
type AdStatsData struct {
	Days      map[string]*AdDay     `json:"days"`
	Hours     map[string]*AdHour    `json:"hours"`
	Dns5      map[string][2]float64 `json:"dns5"`
	DnsRecent []float64             `json:"dns_recent"`
}

// NewAdStats 构造（读已有统计文件）
func NewAdStats() *AdStats {
	d := data.ReadJSON(base.AbStatsFile, AdStatsData{})
	if d.Days == nil {
		d.Days = map[string]*AdDay{}
	}
	if d.Hours == nil {
		d.Hours = map[string]*AdHour{}
	}
	if d.Dns5 == nil {
		d.Dns5 = map[string][2]float64{}
	}
	if len(d.DnsRecent) > 60 {
		d.DnsRecent = d.DnsRecent[len(d.DnsRecent)-60:]
	}
	return &AdStats{data: d, saved: nowFloat(), sbHosts: map[string]string{}}
}

// AdStatsInst 进程内单例（对应 Python 的 AD_STATS）
var AdStatsInst *AdStats

func (s *AdStats) hour() *AdHour {
	k := time.Now().Format("2006-01-02 15")
	h, ok := s.data.Hours[k]
	if !ok {
		h = &AdHour{}
		s.data.Hours[k] = h
	}
	return h
}

// DnsSample 记录一次 DNS 解析耗时采样
func (s *AdStats) DnsSample(ms float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.hour()
	h.Dns[0] += ms
	h.Dns[1]++
	t := time.Now()
	k := t.Format("2006-01-02 15:") + twoDigits(t.Minute()/5*5) // 5 分钟一段，24 小时 288 段
	b := s.data.Dns5[k]
	b[0] += ms
	b[1]++
	s.data.Dns5[k] = b
	s.data.DnsRecent = append(s.data.DnsRecent, ms)
	if len(s.data.DnsRecent) > 60 {
		s.data.DnsRecent = s.data.DnsRecent[len(s.data.DnsRecent)-60:]
	}
}

func twoDigits(n int) string {
	if n < 10 {
		return "0" + string(rune('0'+n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

// mergeReqLocked 调用方已持锁：把攒批的 req 增量一次性合并
func (s *AdStats) mergeReqLocked() {
	if s.reqBatch > 0 {
		s.hour().Req += s.reqBatch
		s.reqBatch = 0
	}
}

// Hit 记录一次广告拦截命中
func (s *AdStats) Hit(host, prov string) {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mergeReqLocked()
	k := time.Now().Format("2006-01-02")
	b, ok := s.data.Days[k]
	if !ok {
		b = &AdDay{Top: map[string]int{}, Lists: map[string]int{}}
		s.data.Days[k] = b
	}
	b.Count++
	if host != "?" && !IsFakeIP(host) { // 反查不到域名的 Fake-IP / 未知连接只计总数，不进排行
		b.Top[host] = b.Top[host] + 1
	}
	key := prov
	if strings.HasPrefix(key, "ad-") {
		key = key[3:]
	}
	b.Lists[key] = b.Lists[key] + 1
	s.hour().Blk++
	if len(b.Top) > 5000 { // 防止长尾域名无限增长
		b.Top = topN(b.Top, 2000)
	}
}

func topN(m map[string]int, n int) map[string]int {
	type kv struct {
		k string
		v int
	}
	arr := make([]kv, 0, len(m))
	for k, v := range m {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].v > arr[j].v })
	out := map[string]int{}
	for i := 0; i < n && i < len(arr); i++ {
		out[arr[i].k] = arr[i].v
	}
	return out
}

// Sink mihomo info 日志行回调
func (s *AdStats) Sink(line string) {
	// 子串预过滤：两个正则都要求 payload 含 "-->"，绝大多数日志行直接跳过 json 解析
	if !strings.Contains(line, "-->") {
		return
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(line), &obj); err != nil {
		return
	}
	msg, _ := obj["payload"].(string)
	if adRXAll.MatchString(msg) {
		s.reqBatch++
		if s.reqBatch >= ReqBatch {
			s.mu.Lock()
			s.mergeReqLocked()
			s.mu.Unlock()
		}
	}
	if strings.Contains(msg, "REJECT") {
		if m := adRX.FindStringSubmatch(msg); m != nil {
			s.Hit(m[1], m[2])
		}
	}
	if nowFloat()-s.saved > 60 {
		s.Flush()
	}
}

// SinkSb sing-box debug 日志行回调：按连接 ID 记住目标域名，命中 ad- 规则集的 reject / DNS 拦截记为一次拦截
func (s *AdStats) SinkSb(line string) {
	// 子串预过滤：各分支的 body 关键字，绝大多数 debug 行直接跳过 json 解析
	if !strings.Contains(line, "inbound/") && !strings.Contains(line, "sniffed") &&
		!strings.Contains(line, "reject") && !strings.Contains(line, "dns: ") && !strings.Contains(line, "fakeip") {
		return
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(line), &obj); err != nil {
		return
	}
	msg, _ := obj["payload"].(string)
	m := sbLine.FindStringSubmatch(msg)
	if m == nil {
		return
	}
	cid, body := m[1], m[2]
	if len(s.sbHosts) > 5000 {
		s.sbHosts = map[string]string{}
	}
	if mm := sbTo.FindStringSubmatch(body); mm != nil {
		if mm[2] != "dns-in" {
			s.sbHosts[cid] = mm[3]
			s.reqBatch++
			if s.reqBatch >= ReqBatch {
				s.mu.Lock()
				s.mergeReqLocked()
				s.mu.Unlock()
			}
		}
	} else if strings.Contains(body, "sniffed") {
		if mm := sbSniff.FindStringSubmatch(body); mm != nil {
			s.sbHosts[cid] = mm[1]
		}
	} else if strings.Contains(body, "found fakeip domain") {
		// 透明代理进来的目标是 198.18.x.x，sing-box 按 Fake-IP 映射还原出域名再匹配规则；
		// 以前只记了入站的 IP，嗅探不到域名（QUIC、非 TLS 等）时排行里就出现 198.18.0.11 这样的地址
		if mm := sbFake.FindStringSubmatch(body); mm != nil {
			if cur, ok := s.sbHosts[cid]; !ok || IsFakeIP(cur) {
				s.sbHosts[cid] = mm[1]
			}
		}
	} else if strings.Contains(body, "=> reject") {
		if mm := sbRej.FindStringSubmatch(body); mm != nil {
			host := s.sbHosts[cid]
			delete(s.sbHosts, cid)
			if host == "" {
				host = "?"
			}
			s.Hit(host, mm[1])
		}
	} else if strings.HasPrefix(body, "dns: ") {
		if mm := sbQn.FindStringSubmatch(body); mm != nil {
			s.sbHosts["q"+cid] = mm[1]
		} else if mm := sbDrej.FindStringSubmatch(body); mm != nil {
			host := s.sbHosts["q"+cid]
			delete(s.sbHosts, "q"+cid)
			if host == "" {
				host = "?"
			}
			s.Hit(host, mm[1])
		}
	}
	if nowFloat()-s.saved > 60 {
		s.Flush()
	}
}

// Flush 落盘：days 留 2 天、hours 留 48 小时、dns5 留 288 段
func (s *AdStats) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mergeReqLocked()
	s.data.Days = keepLastDay(s.data.Days, 2)
	s.data.Hours = keepLastHour(s.data.Hours, 48)
	s.data.Dns5 = keepLastDns5(s.data.Dns5, 288)
	for _, b := range s.data.Days {
		b.Top = topN(b.Top, 500)
	}
	_ = data.WriteJSON(base.AbStatsFile, s.data)
	s.saved = nowFloat()
}

func keepLastDay(m map[string]*AdDay, n int) map[string]*AdDay {
	keys := sortedStrKeys(m)
	if len(keys) > n {
		keys = keys[len(keys)-n:]
	}
	out := map[string]*AdDay{}
	for _, k := range keys {
		out[k] = m[k]
	}
	return out
}

func keepLastHour(m map[string]*AdHour, n int) map[string]*AdHour {
	keys := sortedStrKeys(m)
	if len(keys) > n {
		keys = keys[len(keys)-n:]
	}
	out := map[string]*AdHour{}
	for _, k := range keys {
		out[k] = m[k]
	}
	return out
}

func keepLastDns5(m map[string][2]float64, n int) map[string][2]float64 {
	keys := sortedStrKeys(m)
	if len(keys) > n {
		keys = keys[len(keys)-n:]
	}
	out := map[string][2]float64{}
	for _, k := range keys {
		out[k] = m[k]
	}
	return out
}

// Today 今日拦截总数
func (s *AdStats) Today() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.data.Days[time.Now().Format("2006-01-02")]; ok {
		return b.Count
	}
	return 0
}

// Report 上报
func (s *AdStats) Report() map[string]any {
	s.mu.Lock()
	days := map[string]*AdDay{}
	for k, v := range s.data.Days {
		cp := *v
		cp.Top = map[string]int{}
		for kk, vv := range v.Top {
			cp.Top[kk] = vv
		}
		cp.Lists = map[string]int{}
		for kk, vv := range v.Lists {
			cp.Lists[kk] = vv
		}
		days[k] = &cp
	}
	hours := map[string]*AdHour{}
	for k, v := range s.data.Hours {
		cp := *v
		hours[k] = &cp
	}
	d5 := map[string][2]float64{}
	for k, v := range s.data.Dns5 {
		d5[k] = v
	}
	recent := append([]float64{}, s.data.DnsRecent...)
	s.mu.Unlock()

	b, ok := days[time.Now().Format("2006-01-02")]
	if !ok {
		b = &AdDay{Top: map[string]int{}, Lists: map[string]int{}}
	}
	now := time.Now().Unix() / 3600 * 3600
	var h24 []any
	for i := 23; i >= 0; i-- { // 最近 24 个小时段，缺的补 0
		k := time.Unix(now-int64(i*3600), 0).Format("2006-01-02 15")
		e, ok := hours[k]
		if !ok {
			e = &AdHour{}
		}
		var dnsAvg any
		if e.Dns[1] > 0 {
			dnsAvg = math.Round(e.Dns[0]/e.Dns[1]*10) / 10
		}
		h24 = append(h24, map[string]any{"h": k[len(k)-2:], "req": e.Req, "blk": e.Blk, "dns": dnsAvg})
	}
	var top []any
	for k, v := range b.Top {
		if k != "?" && !IsFakeIP(k) { // 旧版本记下的 Fake-IP 也不显示
			top = append(top, []any{k, v})
		}
	}
	sort.Slice(top, func(i, j int) bool { return top[i].([]any)[1].(int) > top[j].([]any)[1].(int) })
	if len(top) > 20 {
		top = top[:20]
	}
	var dayRows []any
	for _, k := range sortedStrKeys(days) {
		dayRows = append(dayRows, map[string]any{"date": k, "count": days[k].Count})
	}
	return map[string]any{
		"today": b.Count, "top": top, "lists": b.Lists,
		"days": dayRows, "hours": h24,
		"dns": s.dnsReport(d5, recent),
	}
}

func sortedStrKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// dnsReport 解析耗时：24 小时 288 个 5 分钟段（null = 该段没采样）；
// 有效段不足 2 个时（刚安装 / 刚重启）用最近的原始采样画曲线
func (s *AdStats) dnsReport(d5 map[string][2]float64, recent []float64) map[string]any {
	now := time.Now().Unix() / 300 * 300
	var seg []any
	for i := 287; i >= 0; i-- {
		t := time.Unix(now-int64(i*300), 0)
		k := t.Format("2006-01-02 15:") + twoDigits(t.Minute()/5*5)
		b, ok := d5[k]
		if ok && b[1] > 0 {
			seg = append(seg, math.Round(b[0]/b[1]*10)/10)
		} else {
			seg = append(seg, nil)
		}
	}
	vals := 0
	var tot, cnt float64
	for _, b := range d5 {
		if b[1] > 0 {
			vals++
			tot += b[0]
			cnt += b[1]
		}
	}
	var avg, last any
	if cnt > 0 {
		avg = math.Round(tot/cnt*10) / 10
	}
	if len(recent) > 0 {
		last = recent[len(recent)-1]
	}
	series := any(seg)
	mode := "5min"
	if vals < 2 {
		if len(recent) > 30 {
			recent = recent[len(recent)-30:]
		}
		series, mode = recent, "recent"
	}
	return map[string]any{
		"avg": avg, "last": last, "samples": cnt,
		"series": series, "mode": mode,
		"core": activeCore(),
	}
}

func tokenHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// DnsProbe 经核心解析器查随机子域名（绕过缓存）：国内域名走直连 DNS、国外域名走代理 DNS，记录平均耗时
func (s *AdStats) DnsProbe() {
	sb := activeCore() == "singbox" // sing-box 的 Clash API 没有 /dns/query，改为直接向 dns-in(1053) 发 UDP 查询
	var ms []int
	for _, b := range []string{"baidu.com", "google.com"} {
		name := "shunt-" + tokenHex(4) + "." + b
		st := time.Now()
		var ok bool
		if sb {
			ok = base.UdpDNSQuery(name, 1053, "127.0.0.1", 8)
		} else {
			code, _, err := coreCall("GET", "/dns/query?name="+name+"&type=A", nil, 8)
			ok = err == nil && code == 200
		}
		if ok {
			el := int(time.Since(st).Milliseconds())
			if el < 1 {
				el = 1
			}
			ms = append(ms, el)
		}
	}
	if len(ms) > 0 {
		sum := 0
		for _, v := range ms {
			sum += v
		}
		s.DnsSample(math.Round(float64(sum) / float64(len(ms))))
	}
}

// DnsLoop 启动后先连测 3 次（每 10 秒）让曲线马上有数据，之后每 60 秒一次
func (s *AdStats) DnsLoop() {
	time.Sleep(8 * time.Second)
	n := 0
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logErr("广告拦截 DNS 统计", nil)
				}
			}()
			s.DnsProbe()
		}()
		n++
		if n < 3 {
			time.Sleep(10 * time.Second)
		} else {
			time.Sleep(60 * time.Second)
		}
	}
}

// Loop 订阅核心日志流
func (s *AdStats) Loop() {
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logErr("广告拦截统计", nil)
				}
			}()
			sb := activeCore() == "singbox" // sing-box 的规则命中只在 debug 级别日志里
			if sb {
				coreStream("/logs?level=debug", s.SinkSb, map[string]any{})
			} else {
				coreStream("/logs?level=info", s.Sink, map[string]any{})
			}
		}()
		time.Sleep(3 * time.Second)
	}
}
