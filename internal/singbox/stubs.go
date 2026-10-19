package singbox

// 本文件：跨包调用接线。被调用的函数属于其他包（mihomo/groups/corehttp/devroute/
// sysopt/notify/errlog/links），为可测试性保留包级 func 变量形式：默认实现直接
// 转调真实函数，测试中可临时替换（defer 恢复）。
//
// 反向依赖（notify.CoreAlive）经 CoreAliveHook 注入：singbox 不能 import notify
// （notify 反向依赖 singbox.CorePidPath 等），由 notify 包在 init 中赋值。

import (
	"errors"
	"io"
	"net/http"
	"time"

	"shunt/internal/corehttp"
	"shunt/internal/devroute"
	"shunt/internal/errlog"
	"shunt/internal/groups"
	"shunt/internal/links"
	"shunt/internal/mihomo"
	"shunt/internal/sysopt"
)

// SubNode 订阅节点（名 + mihomo 风格节点 dict），对应 groups.SbSubOutbounds 的 NamedNode。
type SubNode struct {
	Name  string
	Proxy map[string]any
}

// CoreAliveHook 核心是否在运行（对应 notify.core_alive）；notify 包可在 init 中注入
// 自己的实现。默认实现与 notify.CoreAlive 等价（GET /version 判 200），经由可安全
// import 的 corehttp，避免 singbox → notify 的循环引用。
var CoreAliveHook = func() bool {
	code, _ := corehttp.Core("GET", "/version", nil, 5)
	return code == 200
}

// ---------- mihomo ----------

// builtinGeo 对应 mihomo.BUILTIN_GEO：内置规则里的 GEOSITE/GEOIP（kind, 值）。
var builtinGeo = mihomo.BuiltinGeo

// stubBuildConfig 对应 mihomo.build_config
var stubBuildConfig = func(d map[string]any) map[string]any { return mihomo.BuildConfig(d) }

// stubBuildRuleProviders 对应 mihomo.build_rule_providers — 只取返回元组的第 1 项（rule-providers）
var stubBuildRuleProviders = func(d, dc map[string]any) map[string]any {
	rp, _, _ := mihomo.BuildRuleProviders(d, dc)
	return rp
}

// stubDnsCfg 对应 mihomo.dns_cfg
var stubDnsCfg = mihomo.DnsCfg

// stubFixDNSPolicy 对应 mihomo.fix_dns_policy
var stubFixDNSPolicy = mihomo.FixDnsPolicy

// stubIsIPAddr 对应 mihomo.is_ip_addr
var stubIsIPAddr = mihomo.IsIPAddr

// stubPolicyParts 对应 mihomo.policy_parts — 返回 (类型, [名称])，类型为 geosite / rule-set / domain
var stubPolicyParts = mihomo.PolicyParts

// stubTunParams 对应 mihomo.tun_params — 返回 {enable, stack, device, auto_redirect, strict_route}
var stubTunParams = mihomo.TunParams

// stubWriteAtomic 对应 mihomo.write_atomic
var stubWriteAtomic = func(path string, obj any) {
	m, _ := obj.(map[string]any)
	if m == nil {
		m = map[string]any{}
	}
	_ = mihomo.WriteAtomic(path, m)
}

// stubWriteConfig 对应 mihomo.write_config
var stubWriteConfig = func(d map[string]any) string {
	s, _ := mihomo.WriteConfig(d)
	return s
}

// ---------- groups ----------

// stubProvUpdate 对应 groups.PROV.update — build_singbox 传 {订阅名: [节点名]}，
// sb_update_subs 传 nil（t=0, data=None：失效订阅节点缓存）
var stubProvUpdate = groups.ProvUpdate

// stubGcfg 对应 groups.gcfg
var stubGcfg = groups.Gcfg

// stubRx 对应 groups.rx — 编译正则（缓存）；无效时返回 nil
var stubRx = groups.Rx

// stubSubCachePath 对应 groups.sub_cache_path
var stubSubCachePath = groups.SubCachePath

// stubSbSubCache 对应 groups.sb_sub_cache
var stubSbSubCache = groups.SbSubCache

// stubSbProviderNodes 对应 groups.sb_provider_nodes — {订阅名: [节点名]}
var stubSbProviderNodes = groups.SbProviderNodes

// stubSbSubOutbounds 对应 groups.sb_sub_outbounds — {订阅名: [{Name, Proxy}]}
var stubSbSubOutbounds = func(d map[string]any) map[string][]SubNode {
	out := map[string][]SubNode{}
	for k, v := range groups.SbSubOutbounds(d) {
		for _, n := range v {
			out[k] = append(out[k], SubNode{Name: n.Name, Proxy: n.Node})
		}
	}
	return out
}

// ---------- corehttp ----------

// stubCoreJSON 对应 corehttp.core_json
var stubCoreJSON = corehttp.CoreJSON

// ---------- devroute ----------

// stubMarkApplied 对应 devroute.mark_applied
var stubMarkApplied = devroute.MarkApplied

// ---------- sysopt ----------

// stubWFile 对应 sysopt.wfile
var stubWFile = sysopt.Wfile

// stubNftOk 对应 sysopt.nft_ok
var stubNftOk = sysopt.NftOk

// stubSh 对应 sysopt.sh — 返回 (exit code, stdout+stderr)
var stubSh = func(cmd string, timeoutSec int) (int, string) { return sysopt.Sh(cmd, timeoutSec) }

// stubSvcRestart 对应 sysopt.svc_restart
var stubSvcRestart = func(timeoutSec int) { sysopt.SvcRestart(timeoutSec, "面板重启核心", nil) }

// stubHTTPGet 对应 sysopt.proxy_opener — 走/不走 127.0.0.1:7890 代理 GET，
// 返回 body（上限 maxBytes）与响应头
var errTooLarge = errors.New("文件过大（超过上限）")

var stubHTTPGet = func(url, ua string, useProxy bool, maxBytes int64, timeoutSec int) ([]byte, http.Header, error) {
	client := sysopt.ProxyClient(useProxy)
	client.Timeout = time.Duration(timeoutSec) * time.Second
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, err
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, nil, errTooLarge
	}
	return body, resp.Header, nil
}

// ---------- notify ----------

// stubCoreAlive 对应 notify.core_alive（经 CoreAliveHook 注入，避免 import cycle）
var stubCoreAlive = func() bool { return CoreAliveHook() }

// ---------- errlog ----------

// stubLogErr 对应 errlog.log_err
var stubLogErr = func(where string, err error) { errlog.LogErr(where, err, false) }

// stubLogTail 对应 errlog.log_tail — 读文件末尾，按行返回；读不了返回 nil
var stubLogTail = errlog.LogTail

// ---------- links ----------

// stubB64d 对应 links.b64d
var stubB64d = links.B64d

// stubParseLink 对应 links.parse_link — 分享链接 → mihomo 风格节点 dict
var stubParseLink = links.ParseLink
