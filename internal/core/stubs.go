package core

// 本文件集中声明 core 依赖的外部模块 stub。
// 各模块移植完成，stub 已全部接线到真实实现（直接赋值或小适配闭包）；
// `// STUB:<包>.<函数>` 注释保留，标注每个接线的来源。
// 值拷贝类（SB_BIN/SB_CONF/SB_API/SB_REPO/CORES）标注为本地拷贝，
// sb_common 移植后删除。

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"shunt/internal/corehttp"
	"shunt/internal/data"
	"shunt/internal/errlog"
	"shunt/internal/groups"
	"shunt/internal/mihomo"
	"shunt/internal/singbox"
	"shunt/internal/sysopt"
)

// STUB:sb_common.SB_BIN / SB_DIR / SB_CONF / SB_API / SB_REPO（本地值拷贝）
var (
	sbBin  = getenv("SB_BIN", "/usr/local/bin/sing-box")
	sbConf = filepath.Join(getenv("SB_DIR", "/etc/sing-box"), "config.json")
	sbAPI  = getenv("SB_API", "https://api.github.com/repos/SagerNet/sing-box/releases")
	sbRepo = getenv("SB_REPO", "https://github.com/SagerNet/sing-box/releases")
	// STUB:sb_common.CORES（本地值拷贝）
	sbCores = map[string]string{"mihomo": "mihomo", "smart": "mihomo Smart", "singbox": "sing-box"}
)

// STUB:notify.core_alive —— 延迟绑定（notify → singbox → mihomo → core，
// core 侧不能再顶层导入 notify，否则循环引用；模式与 SetRetestSoon / SetMihomoHooks 一致）。
// 由 notify 包的 init 经 SetNotifyHooks 注入；未注入时为安全默认值。
var coreAlive = func() bool { return false }

// STUB:notify.notify —— 延迟绑定（同上）；未注入时为 no-op。
var notifySend = func(string) {}

// STUB:notify.set_manual_stop —— 延迟绑定（同上）；未注入时为 no-op。
var setManualStop = func(bool) {}

// STUB:notify.WD["manual_stop"] —— 延迟绑定（同上）；未注入时按 false（未手动停止）。
var wdManualStop = func() bool { return false }

// NotifyHooks 注入到 core 的 notify 函数组。
type NotifyHooks struct {
	CoreAlive     func() bool
	Send          func(text string)
	SetManualStop func(on bool)
	ManualStop    func() bool
}

// SetNotifyHooks 供 notify 包的 init 注入 notify 实现。
func SetNotifyHooks(h NotifyHooks) {
	if h.CoreAlive != nil {
		coreAlive = h.CoreAlive
	}
	if h.Send != nil {
		notifySend = h.Send
	}
	if h.SetManualStop != nil {
		setManualStop = h.SetManualStop
	}
	if h.ManualStop != nil {
		wdManualStop = h.ManualStop
	}
}

// STUB:corehttp.core
// corehttp.Core 返回 (int, []byte)，调用方按 any 处理（含 []byte 分支），直接透传即可。
var coreAPI = func(method, path string, body any, timeoutSec int) (int, any) {
	return corehttp.Core(method, path, body, timeoutSec)
}

// STUB:corehttp.core_json
// 保持 nil 语义：CoreJSON 失败返回 nil map，调用方用 `c == nil` 判断，
// 直接包进 any 会变成非 nil 接口，故显式转回 nil。
var coreJSON = func(path string, timeoutSec int) any {
	if m := corehttp.CoreJSON(path, timeoutSec); m != nil {
		return m
	}
	return nil
}

// STUB:groups.provider_nodes
var providerNodes = func(fresh bool) map[string]any {
	out := map[string]any{}
	for name, lst := range groups.ProviderNodes(fresh) {
		out[name] = lst
	}
	return out
}

// STUB:groups.PROV（PROV.update(t=0, data=None)：失效订阅节点缓存）
// Go 侧没有导出失效函数；ProviderNodes(true) 跳过 60 秒缓存立即重读并回填，
// 效果等价（由懒失效变为立即刷新，调用处 sb_switch 随后即重启核心，无实质差异）。
var provInvalidate = func() { groups.ProviderNodes(true) }

// STUB:groups.gcfg
var gcfgOf = groups.Gcfg

// STUB:mihomo.build_config
var buildConfig = func(d map[string]any) map[string]any { return mihomo.BuildConfig(d) }

// STUB:mihomo.check_config
var checkConfig = func(path, kind string) (bool, string) { return mihomo.CheckConfig(path, kind) }

// STUB:mihomo.write_config
// Python write_config 失败时抛异常；调用方均按异常路径处理（回滚处有 recover），
// 故这里沿用 panic(err) 而不是吞掉错误。
var writeConfig = func(d map[string]any, path string) string {
	s, err := mihomo.WriteConfig(d, path)
	if err != nil {
		panic(err)
	}
	return s
}

// STUB:mihomo.mh_bin
var mhBin = func(kind string) string { return mihomo.MhBin(kind) }

// STUB:mihomo.dns_cfg
var dnsCfg = mihomo.DnsCfg

// STUB:sb_common.active_core
var activeCore = singbox.ActiveCore

// STUB:sb_common.write_core_file
var writeCoreFile = singbox.WriteCoreFile

// STUB:sb_config.build_singbox
// Python build_singbox(d) 返回三元组 (配置, 警告列表, 规则集需求)，调用方取 [0] 为配置，
// 故打包成 []any 保持调用方逻辑不变。
var buildSingbox = func(d map[string]any) []any {
	cfg, warn, need := singbox.BuildSingbox(d)
	return []any{cfg, warn, need}
}

// STUB:sb_config.check_sb_config
var checkSbConfig = func(path string) (bool, string) { return singbox.CheckSbConfig(path) }

// STUB:sb_config.sb_hot_reload
var sbHotReload = singbox.SbHotReload

// STUB:sb_config.sb_log_error
var sbLogError = singbox.SbLogError

// STUB:sb_config.sb_rule_need
// Go 侧返回 map[string]any（内层为 map[string]any），调用方要 map[string]map[string]string，
// 逐项转换（只保留字符串值，与 Python 侧全字符串字典一致）。
var sbRuleNeed = func(d map[string]any) map[string]map[string]string {
	out := map[string]map[string]string{}
	for tag, rsdAny := range singbox.SbRuleNeed(d) {
		rsd, _ := rsdAny.(map[string]any)
		if rsd == nil {
			continue
		}
		m := make(map[string]string, len(rsd))
		for k, v := range rsd {
			if s, ok := v.(string); ok {
				m[k] = s
			}
		}
		out[tag] = m
	}
	return out
}

// STUB:sb_config.sb_sync_assets
// Python 签名 sb_sync_assets(d, force=False, need=None)：need 为 None 时内部计算。
// 保持 nil 与空 map 的区分：nil → 传 nil 让 Go 侧自行计算；force 沿用默认 false。
var sbSyncAssets = func(d map[string]any, need map[string]map[string]string) []string {
	var nm map[string]any
	if need != nil {
		nm = make(map[string]any, len(need))
		for tag, rsd := range need {
			m := make(map[string]any, len(rsd))
			for k, v := range rsd {
				m[k] = v
			}
			nm[tag] = m
		}
	}
	return singbox.SbSyncAssets(d, false, nm)
}

// STUB:sb_config.write_sb_config
var writeSbConfig = func(d map[string]any, path string) string { return singbox.WriteSbConfig(d, path) }

// STUB:sb_config.sb_version
var sbVersion = singbox.SbVersion

// STUB:sb_config.SB_STATE["warn"]
// Python 侧是 build_singbox 写入的模块级缓存；Go 侧无此全局状态，
// 按 webapi/diag 既有做法（需要时用当前 data 重算）即时计算。
var sbStateWarn = func() []string {
	_, warn, _ := singbox.BuildSingbox(data.Load())
	return warn
}

// STUB:sb_subs.sb_update_subs
// Python sb_update_subs(names=None, d=None)：names 为空表示更新全部订阅，
// 对应 Go 侧传 nil names。
var sbUpdateSubs = func(d map[string]any) ([]string, []string) { return singbox.SbUpdateSubs(nil, d) }

// STUB:sysopt.sh
var shRun = func(cmd string, timeoutSec int) (int, string) { return sysopt.Sh(cmd, timeoutSec) }

// STUB:sysopt.svc_restart
// Python 默认 why="面板重启核心"；各调用处均未传 why/cancel，沿用默认值。
var svcRestart = func(timeoutSec int) { _, _ = sysopt.SvcRestart(timeoutSec, "面板重启核心", nil) }

// STUB:errlog.log_err
// Python 默认 tb=False，调用处均未传 tb，沿用。
var logErr = func(where string, err error) { errlog.LogErr(where, err, false) }

// logErrSafe 在"Python 会吞掉异常"的路径上调用 log_err：
// stub 未接线时静默跳过，避免二次 panic。
func safeLogErr(where string, err error) {
	defer func() { _ = recover() }()
	logErr(where, err)
}

// STUB:migrate.snapshot_selections —— 延迟绑定（migrate → core 已是顶层导入，
// core 侧不能再顶层导入 migrate，否则循环引用；模式与上面的 SetRetestSoon 一致）。
// 由 migrate 包的 init 注入；未注入时为 no-op。
var snapshotSelectionsFn func(force bool) map[string]any

// SetSnapshotSelections 供 migrate 包的 init 注入 snapshot_selections 实现。
func SetSnapshotSelections(fn func(force bool) map[string]any) { snapshotSelectionsFn = fn }

var snapshotSelections = func(force bool) {
	if snapshotSelectionsFn != nil {
		snapshotSelectionsFn(force)
	}
}

// STUB:migrate.restore_selections —— 延迟绑定（同上）。
var restoreSelectionsFn func() int

// SetRestoreSelections 供 migrate 包的 init 注入 restore_selections 实现。
func SetRestoreSelections(fn func() int) { restoreSelectionsFn = fn }

var restoreSelections = func() {
	if restoreSelectionsFn != nil {
		restoreSelectionsFn()
	}
}

// STUB:latency.retest_soon —— 延迟绑定（对应 Python core.py 的函数内 from .latency import retest_soon）：
// latency → core 已是顶层导入（与 Python 一致），core 侧不能再顶层导入 latency，否则循环引用。
// 用 var 钩子由上层注入；未注入时为 no-op。
// Python 默认 wait=6，调用处未传参，沿用。
var retestSoonFn func(waitSec int)

// SetRetestSoon 供导入 core + latency 的上层（如 latency 包的 init）注入 retest_soon 实现。
func SetRetestSoon(fn func(waitSec int)) { retestSoonFn = fn }

var retestSoon = func() {
	if retestSoonFn != nil {
		retestSoonFn(6)
	}
}

// ---------- 小工具 ----------

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func isFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// copyFileMode 对应 shutil.copy2：复制内容并保留源文件权限。
func copyFileMode(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fi.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, fi.Mode().Perm())
}

// shellQuote 对应 shlex.quote 的常用情形（路径/命令片段）。
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '_' || c == '@' || c == '%' || c == '+' || c == '=' || c == ':' ||
			c == ',' || c == '.' || c == '/' || c == '-') {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// truncate 取前 n 个 rune（对应 Python 的 s[:n] 在中文场景的近似）。
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// tailStr 取后 n 个 rune（对应 Python 的 s[-n:]）。
func tailStr(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[len(r)-n:])
	}
	return s
}

func boolPtr(b bool) *bool { return &b }
