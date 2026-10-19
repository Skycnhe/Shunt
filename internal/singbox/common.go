package singbox

// sb_common.py：sing-box 内核常量与当前内核判定。
// 面板数据（订阅、节点、规则、DNS、设备）两个内核共用；切换内核时按各自格式生成独立的配置文件：
//   mihomo   → /etc/mihomo/config.yaml
//   sing-box → /etc/sing-box/config.json
// sing-box 没有负载均衡 / 故障转移组：自定义的这两类组降级为 urltest（自动测速），地区「⚖️ 负载均衡」组与
// 「自动优选」完全相同，不再重复生成，引用它的地方自动改指向同地区的「自动优选」。

import (
	"os"
	"path/filepath"

	"shunt/internal/base"
	"shunt/internal/coreupdate"
	"shunt/internal/groups"
	"shunt/internal/mihomo"
	"shunt/internal/sysopt"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

var (
	// SBBin sing-box 可执行文件
	SBBin = envOr("SB_BIN", "/usr/local/bin/sing-box")
	// SBDir sing-box 配置目录
	SBDir = envOr("SB_DIR", "/etc/sing-box")
	// SBConf sing-box 主配置
	SBConf = filepath.Join(SBDir, "config.json")
	// SBRuleDir 规则集文件目录
	SBRuleDir = envOr("SB_RULES", filepath.Join(SBDir, "rules"))
	// SBSubDir 面板下载的 sing-box 订阅缓存目录
	SBSubDir = filepath.Join(base.PanelDir, "sb_subs")
	// CoreFile init.d/shunt-core 读取它决定启动哪个内核
	CoreFile = filepath.Join(base.PanelDir, "core")
	// CorePidPath 核心进程 pid 文件
	CorePidPath = corePidPath()
)

// Cores 内核代号 → 显示名
var Cores = map[string]string{"mihomo": "mihomo", "smart": "mihomo Smart", "singbox": "sing-box"}

const (
	// SBGeo sing-box geo 规则集下载基址
	SBGeo = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo"
	// SBRepo sing-box 发布页
	SBRepo = "https://github.com/SagerNet/sing-box/releases"
	// SBApi sing-box GitHub releases API
	SBApi = "https://api.github.com/repos/SagerNet/sing-box/releases"
)

// SBUa 订阅下载时轮换的 User-Agent
var SBUa = []string{"clash.meta", "v2rayN/6.45"}

// SBState 跨调用共享状态：{"warn": [...], "subs": {...}}
var SBState = map[string]any{"warn": []any{}, "subs": map[string]any{}}

func corePidPath() string {
	if v := os.Getenv("PANEL_CORE_PID"); v != "" {
		return v
	}
	if _, err := os.Stat("/etc/init.d/shunt-core"); err == nil {
		return "/run/shunt-core.pid"
	}
	return "/run/mihomo.pid"
}

// ActiveCore 当前内核代号（d 缺省时读面板数据）
func ActiveCore(d ...map[string]any) string {
	var dd map[string]any
	if len(d) > 0 {
		dd = d[0]
	}
	c := ""
	if dd != nil {
		if s, ok := dd["core"].(string); ok {
			c = s
		}
	}
	if c == "" {
		c = "mihomo"
	}
	if _, ok := Cores[c]; ok {
		return c
	}
	return "mihomo"
}

// CoreConfPath 当前（或指定）内核的配置文件路径
func CoreConfPath(kind ...string) string {
	k := ""
	if len(kind) > 0 {
		k = kind[0]
	}
	if k == "" {
		k = ActiveCore()
	}
	if k == "singbox" {
		return SBConf
	}
	return filepath.Join(base.ConfDir, "config.yaml")
}

// WriteCoreFile 记录当前内核代号，供 init.d/shunt-core 读取
func WriteCoreFile(kind string) {
	// STUB:sysopt.wfile / STUB:errlog.log_err 经由 stub 调用
	if !stubWFile(CoreFile, kind+"\n") {
		stubLogErr("记录当前内核", os.ErrInvalid)
	}
}

// SbStateWarn SB_STATE["warn"] 的字符串列表（核心/规则集警告，对应 sb_config.SB_STATE["warn"]）
func SbStateWarn() []string {
	if w, ok := SBState["warn"].([]string); ok {
		return w
	}
	var out []string
	if w, ok := SBState["warn"].([]any); ok {
		for _, x := range w {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func init() {
	// 反向依赖注入（避免 import cycle）：
	// mihomo / groups 不能 import singbox（singbox 依赖 mihomo.BuildConfig、groups.Gcfg 等），
	// 它们的 ActiveCoreHook 由这里指向 singbox.ActiveCore。
	mihomo.ActiveCoreHook = func(d map[string]any) string { return ActiveCore(d) }
	groups.ActiveCoreHook = func() string { return ActiveCore() }
	// sysopt 不能 import singbox（singbox 依赖 sysopt.Sh 等），SB_BIN 经 hook 注入。
	sysopt.SbBinHook = func() string { return SBBin }
	// coreupdate 不能 import singbox（经 mihomo→devroute→stats→core 成环），
	// active_core 经 hook 注入。
	coreupdate.SetSingboxHooks(coreupdate.SingboxHooks{
		ActiveCore: ActiveCore,
	})
}
