// Package notify 对应 Python shunt/notify.py：Telegram 通知、
// 故障自动直连（watchdog）+ 定期告警。
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"shunt/internal/base"
	"shunt/internal/core"
	"shunt/internal/corehttp"
	"shunt/internal/coreupdate"
	"shunt/internal/data"
	"shunt/internal/errlog"
	"shunt/internal/singbox"
	"shunt/internal/sysopt"
)

func init() {
	// core 不能导入 notify（notify → singbox → mihomo → core），反向注入：
	// core 侧的 coreAlive / notifySend / setManualStop / wdManualStop 经此钩子接线。
	core.SetNotifyHooks(core.NotifyHooks{
		CoreAlive:     CoreAlive,
		Send:          Notify,
		SetManualStop: SetManualStop,
		ManualStop:    ManualStop,
	})
	// coreupdate 不能导入 notify（notify → core → coreupdate），反向注入。
	coreupdate.SetNotifyHooks(coreupdate.NotifyHooks{
		CoreAlive: CoreAlive,
		Send:      Notify,
	})
	// singbox 不能导入 notify（notify → singbox），core_alive 经 hook 注入。
	singbox.CoreAliveHook = CoreAlive
}

// STUB:sb_common.CORE_PID —— 接线到 singbox.CorePidPath（变量）
// （Python 值为环境变量 PANEL_CORE_PID，或 /etc/init.d/shunt-core 存在时 /run/shunt-core.pid，否则 /run/mihomo.pid）
func corePid() string { return singbox.CorePidPath }

// STUB:sb_common.active_core —— 接线到 singbox.ActiveCore
func activeCore(d map[string]any) string { return singbox.ActiveCore(d) }

// STUB:sb_common.CORES —— 接线到 singbox.Cores
// （Python 值为 {"mihomo": "mihomo", "smart": "mihomo Smart", "singbox": "sing-box"}，取 active_core(d) 对应的显示名，缺省 "mihomo"）
func coreDisplayName(d map[string]any) string {
	if n, ok := singbox.Cores[singbox.ActiveCore(d)]; ok {
		return n
	}
	return "mihomo"
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

// TgSend 对应 tg_send(text, d)：先走代理发送，核心挂了再直连。
func TgSend(text string, d map[string]any) (bool, string) {
	if d == nil {
		d = data.Load()
	}
	token, chat := data.Str(d, "tg_token"), data.Str(d, "tg_chat")
	if token == "" || chat == "" {
		return false, "未配置 Telegram"
	}
	body, _ := json.Marshal(map[string]any{
		"chat_id": chat,
		"text":    fmt.Sprintf("[Shunt@%s]\n%s", hostname(), text),
	})
	u := "https://api.telegram.org/bot" + token + "/sendMessage"
	errMsg := ""
	for _, useProxy := range []bool{true, false} { // 先走代理，核心挂了再直连
		req, err := http.NewRequest("POST", u, bytes.NewReader(body))
		if err != nil {
			errMsg = err.Error()
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		client := sysopt.ProxyClient(useProxy)
		client.Timeout = 10 * time.Second
		resp, err := client.Do(req)
		if err != nil {
			errMsg = err.Error()
			continue
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 400 { // 对应 urllib.error.HTTPError
			var ej map[string]any
			if json.Unmarshal(raw, &ej) == nil {
				if desc, ok := ej["description"].(string); ok && desc != "" {
					return false, desc
				}
			}
			return false, strings.TrimSpace(string(raw))
		}
		var j map[string]any
		if json.Unmarshal(raw, &j) == nil {
			if ok, _ := j["ok"].(bool); ok {
				return true, "已发送"
			}
		}
	}
	return false, "发送失败：" + errMsg
}

// Notify 对应 notify(text)：后台发送 Telegram 通知。
func Notify(text string) {
	go TgSend(text, nil)
}

// ---------------------------------------------------------------- 故障自动直连 (watchdog) + 定期告警

// StopFlag 对应 STOP_FLAG：「手动停止」标志落盘路径
var StopFlag = filepath.Join(base.PanelDir, "core_stopped")

// WdEventsFile 对应 WD_EVENTS_FILE：看门狗事件落盘路径
var WdEventsFile = filepath.Join(base.PanelDir, "wd_events.json")

// WdEventsMax 对应 WD_EVENTS_MAX：只留最近 20 条
const WdEventsMax = 20

// HangLog 对应 HANG_LOG：核心卡死时的现场转储路径
var HangLog = func() string {
	if v := os.Getenv("PANEL_HANG_LOG"); v != "" {
		return v
	}
	return "/var/log/shunt-core-hang.log"
}()

// WdEvent 看门狗事件记录。
type WdEvent struct {
	T    int64
	Msg  string
	Kind string
}

var (
	wdMu sync.Mutex
	wd   = struct {
		status     string
		fails      int
		events     []WdEvent // 新 → 旧，最多 WdEventsMax 条
		lastCheck  int64
		manualStop bool
		tpOff      bool
	}{status: "ok"}
)

func init() {
	wd.events = loadWdEvents()
	wd.manualStop = fileExists(StopFlag)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func loadWdEvents() []WdEvent {
	raw := data.ReadJSON(WdEventsFile, []any(nil))
	var out []WdEvent
	for _, item := range raw {
		e, ok := item.(map[string]any)
		if !ok {
			continue
		}
		t, tOk := toInt64(e["t"])
		msg, mOk := e["msg"].(string)
		if !tOk || !mOk {
			continue
		}
		kind, _ := e["kind"].(string)
		out = append(out, WdEvent{T: t, Msg: msg, Kind: kind})
		if len(out) >= WdEventsMax {
			break
		}
	}
	return out
}

func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

// SetManualStop 对应 set_manual_stop(on)：置位 / 清除「用户手动停止了核心」：内存 + 标志文件。
func SetManualStop(on bool) {
	wdMu.Lock()
	wd.manualStop = on
	wdMu.Unlock()
	if on {
		_ = os.WriteFile(StopFlag, []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o644)
	} else {
		_ = os.Remove(StopFlag)
	}
}

// ManualStop 返回「用户手动停止了核心」标志。
func ManualStop() bool {
	wdMu.Lock()
	defer wdMu.Unlock()
	return wd.manualStop
}

// WdStatus 返回看门狗当前状态。
func WdStatus() string {
	wdMu.Lock()
	defer wdMu.Unlock()
	return wd.status
}

// WdLastCheck 返回看门狗上次检查时间戳（对应 WD["last_check"]）。
func WdLastCheck() int64 {
	wdMu.Lock()
	defer wdMu.Unlock()
	return wd.lastCheck
}

// SetWdField 设置看门狗字段（对应 WD[key] = val）。
// 支持 "status"（string）、"tp_off"（bool）、"last_check"（int）、
// "fails"（int）、"manual_stop"（bool)；未知 key 忽略。
func SetWdField(key string, val any) {
	wdMu.Lock()
	defer wdMu.Unlock()
	switch key {
	case "status":
		if s, ok := val.(string); ok {
			wd.status = s
		}
	case "tp_off":
		wd.tpOff = toBool(val)
	case "last_check":
		if t, ok := toInt64(val); ok {
			wd.lastCheck = t
		}
	case "fails":
		if n, ok := toInt64(val); ok {
			wd.fails = int(n)
		}
	case "manual_stop":
		wd.manualStop = toBool(val)
	}
}

func toBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t != "" && t != "0" && t != "false"
	case int:
		return t != 0
	case int64:
		return t != 0
	case float64:
		return t != 0
	default:
		return v != nil
	}
}

// WdCounts 对应 wd_counts(events)：记录里的自动重启 / 切换直连 / 恢复次数。
// events 为 nil 时用当前看门狗事件。
func WdCounts(events []WdEvent) map[string]int {
	c := map[string]int{"restart": 0, "direct": 0, "recover": 0}
	if events == nil {
		wdMu.Lock()
		events = append([]WdEvent(nil), wd.events...)
		wdMu.Unlock()
	}
	for _, e := range events {
		if _, ok := c[e.Kind]; ok {
			c[e.Kind]++
		}
	}
	return c
}

// WdEventPush 对应 wd_event(msg, push, kind)：记录看门狗事件（落盘保留最近 20 条），push 时发 Telegram 通知。
func WdEventPush(msg string, push bool, kind string) {
	e := WdEvent{T: time.Now().Unix(), Msg: msg, Kind: kind}
	wdMu.Lock()
	wd.events = append([]WdEvent{e}, wd.events...)
	if len(wd.events) > WdEventsMax {
		wd.events = wd.events[:WdEventsMax]
	}
	evs := append([]WdEvent(nil), wd.events...)
	wdMu.Unlock()
	arr := make([]map[string]any, len(evs))
	for i, x := range evs {
		m := map[string]any{"t": x.T, "msg": x.Msg}
		if x.Kind != "" {
			m["kind"] = x.Kind
		}
		arr[i] = m
	}
	_ = data.WriteJSON(WdEventsFile, arr)
	fmt.Printf("%s [watchdog] %s\n", time.Now().Format("2006-01-02 15:04:05"), msg)
	if push {
		Notify(msg)
	}
}

// CoreAlive 对应 core_alive()。
func CoreAlive() bool {
	code, _ := corehttp.Core("GET", "/version", nil, 5)
	return code == 200
}

// CoreAliveConfirmed 对应 core_alive_confirmed(retries, gap)：看门狗用，一次 /version 超时不算无响应，
// 再隔几秒复查，连续都失败才判定故障。
func CoreAliveConfirmed(retries, gapSec int) bool {
	if CoreAlive() {
		return true
	}
	for i := 0; i < retries; i++ {
		time.Sleep(time.Duration(gapSec) * time.Second)
		if code, _ := corehttp.Core("GET", "/version", nil, 8); code == 200 {
			return true
		}
	}
	return false
}

// CoreProcAlive 对应 core_proc_alive()：核心进程是否还在（pid 文件 + kill 0），
// 用来区分「进程退出」和「进程在但控制接口卡住」。
func CoreProcAlive() bool {
	b, err := os.ReadFile(corePid())
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

// CoreFdUsage 对应 core_fd_usage()：核心进程已用 / 上限文件句柄，如「1021/1024」；读不到返回空串。
func CoreFdUsage() string {
	b, err := os.ReadFile(corePid())
	if err != nil {
		return ""
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return ""
	}
	ents, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return ""
	}
	used := len(ents)
	lim := ""
	if lb, err := os.ReadFile(fmt.Sprintf("/proc/%d/limits", pid)); err == nil {
		for _, line := range strings.Split(string(lb), "\n") {
			if strings.HasPrefix(line, "Max open files") {
				if f := strings.Fields(line); len(f) >= 4 {
					lim = f[3]
				}
				break
			}
		}
	}
	if lim != "" {
		return fmt.Sprintf("%d/%s", used, lim)
	}
	return strconv.Itoa(used)
}

// CoreHangDump 对应 core_hang_dump(why)：控制接口无响应、进程仍在时，重启前把核心日志末尾和
// Go 协程栈（SIGQUIT）存进 HANG_LOG。只保留最近一次（最多约 512KB）。
func CoreHangDump(why string) bool {
	b, err := os.ReadFile(corePid())
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return false
	}
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	tail := func(n int64) (int64, []byte) {
		f, err := os.Open(base.MihomoLog)
		if err != nil {
			return 0, nil
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return 0, nil
		}
		end := st.Size()
		off := end - n
		if off < 0 {
			off = 0
		}
		if _, err := f.Seek(off, 0); err != nil {
			return 0, nil
		}
		buf := make([]byte, end-off)
		m := 0
		for m < len(buf) {
			k, err := f.Read(buf[m:])
			m += k
			if err != nil {
				break
			}
		}
		return end, buf[:m]
	}
	off, before := tail(64 * 1024)
	_ = syscall.Kill(pid, syscall.SIGQUIT) // Go 运行时收到 SIGQUIT 把所有协程栈打到 stderr（即核心日志）后退出
	for i := 0; i < 20; i++ {
		time.Sleep(250 * time.Millisecond)
		if syscall.Kill(pid, 0) != nil {
			break
		}
	}
	time.Sleep(300 * time.Millisecond)
	end, _ := tail(0)
	var dump []byte
	if end > off {
		if f, err := os.Open(base.MihomoLog); err == nil {
			_, _ = f.Seek(off, 0)
			dump = make([]byte, 448*1024)
			m := 0
			for m < len(dump) {
				k, err := f.Read(dump[m:])
				m += k
				if err != nil {
					break
				}
			}
			dump = dump[:m]
			f.Close()
		}
	}
	f, err := os.Create(HangLog)
	if err != nil {
		return false
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "===== %s %s =====\n----- 核心日志末尾 -----\n", time.Now().Format("2006-01-02 15:04:05"), why)
	_, _ = f.Write(before)
	_, _ = f.Write([]byte("\n----- SIGQUIT 协程栈 -----\n"))
	_, _ = f.Write(dump)
	return true
}

// CoreLastError 对应 core_last_error()：核心日志末尾 16KB 里最后一条 FATAL / ERROR / panic。
func CoreLastError() string {
	lines := errlog.LogTail(base.MihomoLog)
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if (strings.Contains(line, "FATAL") || strings.Contains(line, " ERROR ") ||
			strings.Contains(line, "panic:") || strings.Contains(line, "level=error") ||
			strings.Contains(line, "level=fatal")) && !strings.Contains(line, "missing fakeip record") {
			return tailRunes(strings.TrimSpace(line), 160)
		}
	}
	return ""
}

func tailRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[len(r)-n:]
	}
	return string(r)
}

func boolDef(d map[string]any, key string, def bool) bool {
	v, ok := d[key]
	if !ok || v == nil {
		return def
	}
	b, _ := v.(bool)
	return b
}

// WatchdogTick 对应 watchdog_tick()：看门狗单轮检查。语义保真：
// busy/暂停期/关闭/测速中直接返回；核心恢复时清手动停止并恢复透明代理；
// 故障 1-2 次自动重启（带现场转储），3 次后切直连，直连下每 10 次再试拉起。
func WatchdogTick() {
	base.CoreUpd.Lock()
	busy := base.CoreUpd.Busy
	base.CoreUpd.Unlock()
	if busy { // 内核更新过程中核心会重启，不算故障
		return
	}
	if until, _ := base.WdHoldState(); float64(time.Now().UnixNano())/1e9 < until {
		return // 面板自己正在重启 / 重载核心（含启动后的加载期）
	}
	d := data.Load()
	setLastCheck(time.Now().Unix())
	if !boolDef(d, "watchdog", true) {
		setStatus("off")
		return
	}
	if base.MassTesting() { // 全节点测速进行中：核心高负载，/version 可能超时，暂停故障判定
		return
	}
	redirecting := data.Str(d, "proxy_mode") != "off" // TProxy 或 TUN
	cname := coreDisplayName(d)
	if CoreAliveConfirmed(2, 3) {
		// 核心在跑：「手动停止」已过时，恢复看门狗（只在没人控制服务时清）
		if ManualStop() && sysopt.SvcOp.TryLock() {
			func() {
				defer sysopt.SvcOp.Unlock()
				if CoreProcAlive() {
					SetManualStop(false)
				}
			}()
		}
		if st := getStatus(); st == "restarting" || st == "direct" {
			msg := cname + " 核心已恢复"
			tpOff := getTpOff()
			if tpOff && redirecting {
				code, out := sysopt.Sh(base.TproxySh + " apply")
				if code == 0 {
					msg += "，透明代理已重新开启"
				} else {
					msg += "，但重新开启透明代理失败：" + tailRunes(out, 120)
				}
			}
			setTpOff(false)
			WdEventPush(msg, true, "recover")
		}
		wdMu.Lock()
		wd.status, wd.fails = "ok", 0
		wdMu.Unlock()
		return
	}
	if ManualStop() {
		setStatus("stopped")
		return
	}
	fails := addFail()
	if fails <= 2 {
		setStatus("restarting")
		procAlive := CoreProcAlive()
		why := "进程已退出"
		if procAlive {
			why = "控制接口无响应（进程仍在）"
		}
		errLine := CoreLastError()
		fd := ""
		if procAlive {
			fd = CoreFdUsage()
		}
		if fd != "" {
			why += "，文件句柄 " + fd
		}
		if fd != "" && CoreHangDump(why) {
			why += "，现场已存到 " + HangLog
		}
		msg := fmt.Sprintf("%s 核心%s，第 %d 次自动重启", cname, why, fails)
		if errLine != "" {
			msg += "；日志最后一条错误：" + errLine
		}
		WdEventPush(msg, fails == 1, "restart")
		_, _ = sysopt.SvcRestart(60, "看门狗重启核心", func() bool { return ManualStop() })
		return
	}
	if getStatus() != "direct" {
		setStatus("direct")
		if redirecting {
			_, _ = sysopt.Sh(base.TproxySh + " stop") // TUN 模式下核心退出时 TUN 设备与路由随之消失，这里再撤掉 DNS 重定向
			setTpOff(true)
		}
		WdEventPush(fmt.Sprintf("%s 核心重启 2 次仍无响应，已关闭透明代理，局域网暂时直连上网", cname), true, "direct")
	} else if fails%10 == 0 { // 直连状态下每 5 分钟再尝试拉起一次
		_, _ = sysopt.SvcRestart(60, "看门狗重启核心", func() bool { return ManualStop() })
		if redirecting {
			// rc 的 start_post 不管核心是否真的起来都会重新挂上规则：一律撤掉，局域网保持直连；
			// 核心若已恢复，下一轮确认后再重新开启
			_, _ = sysopt.Sh(base.TproxySh + " stop")
			setTpOff(true)
		}
	}
}

func setStatus(s string) {
	wdMu.Lock()
	defer wdMu.Unlock()
	wd.status = s
}

func getStatus() string {
	wdMu.Lock()
	defer wdMu.Unlock()
	return wd.status
}

func setLastCheck(t int64) {
	wdMu.Lock()
	defer wdMu.Unlock()
	wd.lastCheck = t
}

func addFail() int {
	wdMu.Lock()
	defer wdMu.Unlock()
	wd.fails++
	return wd.fails
}

func getTpOff() bool {
	wdMu.Lock()
	defer wdMu.Unlock()
	return wd.tpOff
}

func setTpOff(v bool) {
	wdMu.Lock()
	defer wdMu.Unlock()
	wd.tpOff = v
}

// LoadNotified 对应 load_notified()。
func LoadNotified() map[string]any {
	return data.ReadJSON(base.NotifyFile, map[string]any{})
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

// CheckNodes 对应 check_nodes()：节点选择里所有节点都超时 → 通知（只在状态变化时发）。
func CheckNodes() {
	d := data.Load()
	if data.Str(d, "mode") == "direct" || data.Str(d, "tg_token") == "" || data.Str(d, "tg_chat") == "" {
		return // 没配置 Telegram 时不必每 10 分钟测一遍全部节点
	}
	// 用「🖐️ 手动选择」测速：对 url-test 组调用 /group/…/delay 会被 mihomo 清除用户的📌固定选择
	pg := corehttp.CoreJSON("/proxies/"+url.PathEscape(base.GManual), 10)
	if pg == nil {
		return
	}
	code, raw := corehttp.Core("GET", "/group/"+url.PathEscape(base.GManual)+"/delay?url="+
		url.QueryEscape(base.Hc)+"&timeout=5000", nil, 30)
	res := map[string]any{}
	if code == 200 {
		_ = json.Unmarshal(raw, &res)
	}
	allDown := true
	for _, v := range res {
		if f, ok := toFloat(v); ok && f > 0 {
			allDown = false
			break
		}
	}
	st := LoadNotified()
	if allDown != boolDef(st, "allnodes", false) {
		st["allnodes"] = allDown
		_ = data.WriteJSON(base.NotifyFile, st)
		if allDown {
			Notify("⚠️ 节点选择中的所有节点均测速超时，请检查订阅或网络")
		} else {
			Notify("✅ 节点已恢复可用")
		}
	}
}
