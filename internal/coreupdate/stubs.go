package coreupdate

// 本文件集中声明 coreupdate 依赖的外部模块 stub。
// 各模块移植完成，stub 已全部接线到真实实现（直接赋值、小适配闭包，
// 或循环依赖处的延迟注入）；`// STUB:<包>.<函数>` 注释保留，标注每个接线的来源。
// 值拷贝类（CORES）标注为本地拷贝，sb_common 移植后删除。

import (
	"net/http"
	"time"

	"shunt/internal/errlog"
	"shunt/internal/sysopt"
)

// ---------- mihomo（循环依赖：延迟注入）----------
//
// coreupdate → mihomo → devroute → stats → core → coreupdate，直接导入会循环。
// 由 mihomo 包的 init 经 SetMihomoHooks 注入；未注入时为安全默认值。

// STUB:mihomo.mh_bin
var mhBin = func(string) string { return "" }

// STUB:mihomo.write_config
// Python write_config 失败时抛异常，故注入后仍沿用 panic(err)，与 core 包一致。
var writeConfig = func(map[string]any, string) string { return "" }

// MihomoHooks 注入到 coreupdate 的 mihomo 函数组。
type MihomoHooks struct {
	MhBin       func(kind string) string
	WriteConfig func(d map[string]any, path string) (string, error)
}

// SetMihomoHooks 供 mihomo 包的 init 注入实现。
func SetMihomoHooks(h MihomoHooks) {
	if h.MhBin != nil {
		mhBin = h.MhBin
	}
	if h.WriteConfig != nil {
		wc := h.WriteConfig
		writeConfig = func(d map[string]any, path string) string {
			s, err := wc(d, path)
			if err != nil {
				panic(err)
			}
			return s
		}
	}
}

// ---------- singbox（循环依赖：延迟注入）----------
//
// coreupdate → singbox → mihomo → devroute → stats → core → coreupdate，
// 直接导入会循环。由 singbox 包的 init 经 SetSingboxHooks 注入；未注入时返回 ""。

// STUB:sb_common.active_core
var activeCore = func(d ...map[string]any) string { return "" }

// SingboxHooks 注入到 coreupdate 的 singbox 函数组。
type SingboxHooks struct {
	ActiveCore func(d ...map[string]any) string
}

// SetSingboxHooks 供 singbox 包的 init 注入实现。
func SetSingboxHooks(h SingboxHooks) {
	if h.ActiveCore != nil {
		activeCore = h.ActiveCore
	}
}

// coresMap 是 sb_common.CORES 的本地值拷贝；sb_common 移植后删除本拷贝。
// STUB:sb_common.CORES
var coresMap = map[string]string{"mihomo": "mihomo", "smart": "mihomo Smart", "singbox": "sing-box"}

// STUB:sysopt.sh
var shRun = func(cmd string, timeoutSec int) (int, string) { return sysopt.Sh(cmd, timeoutSec) }

// STUB:sysopt.svc_restart
// Python 默认 why="面板重启核心"；各调用处均未传 why/cancel，沿用默认值。
var svcRestart = func(timeoutSec int) { _, _ = sysopt.SvcRestart(timeoutSec, "面板重启核心", nil) }

// STUB:sysopt.proxy_opener
// Go 侧对应 sysopt.ProxyClient(proxy) *http.Client（已含 SafeRedirectHandler
// 语义的重定向 SSRF 校验）；这里适配成调用方期望的 opener 接口
// （Open 做一次 GET，带 UA 与超时，返回 Body/ContentLength/FinalURL）。
var proxyOpener = func(proxy bool) opener { return proxyOpenAdapter{proxy: proxy} }

type proxyOpenAdapter struct{ proxy bool }

func (a proxyOpenAdapter) Open(rawurl, ua string, timeoutSec int) (*HttpResponse, error) {
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	client := sysopt.ProxyClient(a.proxy)
	client.Timeout = time.Duration(timeoutSec) * time.Second
	req, err := http.NewRequest(http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	finalURL := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	return &HttpResponse{Body: resp.Body, ContentLength: resp.ContentLength, FinalURL: finalURL}, nil
}

// ---------- notify（循环依赖：延迟注入）----------
//
// notify → core → coreupdate，直接导入会循环。由 notify 包的 init
// 经 SetNotifyHooks 注入；未注入时为安全默认值。

// STUB:notify.core_alive
var coreAlive = func() bool { return false }

// STUB:notify.notify
var notifySend = func(string) {}

// NotifyHooks 注入到 coreupdate 的 notify 函数组。
type NotifyHooks struct {
	CoreAlive func() bool
	Send      func(text string)
}

// SetNotifyHooks 供 notify 包的 init 注入实现。
func SetNotifyHooks(h NotifyHooks) {
	if h.CoreAlive != nil {
		coreAlive = h.CoreAlive
	}
	if h.Send != nil {
		notifySend = h.Send
	}
}

// STUB:errlog.log_err
// Python 默认 tb=False，调用处均未传 tb，沿用。
var logErr = func(where string, err error) { errlog.LogErr(where, err, false) }

// logErrSafe 在"Python 会吞掉异常"的路径上调用 log_err：
// stub 未接线时静默跳过，避免二次 panic。
func logErrSafe(where string, err error) {
	defer func() { _ = recover() }()
	logErr(where, err)
}
