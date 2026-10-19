package webapi

// helpers.go：rules/system/service/misc 四组 handler 的共享小工具。
// 尽量贴近 Python shunt/webapi.py 的语义（真值判定、掩盖规则、截断按字符等）。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"shunt/internal/base"
	"shunt/internal/data"
	"shunt/internal/errlog"
	"shunt/internal/mihomo"
	"shunt/internal/notify"
	"shunt/internal/singbox"
	"shunt/internal/sysopt"
	"shunt/internal/updateguard"
)

// ---------- 通用取值 ----------

func toStr(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		return fmt.Sprint(t)
	}
}

func toBoolDef(v any, present bool, def bool) bool {
	if !present {
		return def
	}
	return toBool(v)
}

func toInt(v any) int {
	switch t := v.(type) {
	case nil:
		return 0
	case float64:
		return int(t)
	case float32:
		return int(t)
	case int:
		return t
	case int64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	case bool:
		if t {
			return 1
		}
		return 0
	default:
		return 0
	}
}

func toFloat(v any) float64 {
	switch t := v.(type) {
	case nil:
		return 0
	case float64:
		return t
	case float32:
		return float64(t)
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f
	default:
		return 0
	}
}

func toMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func toList(v any) []any {
	l, _ := v.([]any)
	return l
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// truncateRunes 按字符截断（对应 Python 的 s[:n]）。
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// tailRunes 取末尾 n 个字符（对应 Python 的 s[-n:]）。
func tailRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[len(r)-n:])
}

func deepCopyAny(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return v
	}
	return out
}

func copyStrMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// jsonIndentNoHTML 对应 json.dumps(obj, ensure_ascii=False, indent=2)。
func jsonIndentNoHTML(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
	return strings.TrimSuffix(buf.String(), "\n")
}

// ---------- maskCfg（对应 webapi.py 的 _mask_cfg；maskVal/maskSecret/maskURL/unmask 复用 handlers_state.go） ----------

var maskWords = []string{"password", "passwd", "uuid", "token", "psk", "secret", "privatekey"}

// activeCore 对应 Python 的 active_core()：无参调用时自动 load() 再判定。
// 注意 Go 的 singbox.ActiveCore() 无参时恒返回 "mihomo"，不能直接套用。
func activeCore() string {
	return singbox.ActiveCore(data.Load())
}

// unmaskSecret 打码的 token 原样提交回来 = 没改：换回服务端保存的原值（maskSecret 的 string 适配）。
func unmaskSecret(newVal, curVal string) string {
	return unmask(newVal, curVal, func(s string) string { return toStr(maskSecret(s)) })
}

func maskCfg(o any) any {
	switch t := o.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, v := range t {
			nk := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(k, "-", ""), "_", ""))
			hit := false
			for _, w := range maskWords {
				if strings.Contains(nk, w) {
					hit = true
					break
				}
			}
			if hit {
				if _, ok := v.(string); ok {
					out[k] = maskVal(toStr(v))
				} else {
					out[k] = maskCfg(v)
				}
			} else {
				out[k] = maskCfg(v)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = maskCfg(x)
		}
		return out
	default:
		return o
	}
}

// ---------- 原始字节响应（文件下载 / 核心透传，不经过 JSON 序列化） ----------

// RawBody 在 writeJSON 中特殊处理：按原样写出字节。
type RawBody struct {
	Body  []byte
	CType string
}

func rawResp(code int, body []byte, ctype string) (int, any) {
	return code, RawBody{Body: body, CType: ctype}
}

// ---------- 配置探查 / 校验 ----------

// probeData 对应 probe_data(d)：按生成配置的方式完整走一遍，返回错误提示或空串。
func probeData(d map[string]any) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			errlog.LogErr("保存前检查配置", r, false)
			msg = truncateRunes(fmt.Sprintf("数据格式不正确，未保存：%v", r), 300)
		}
	}()
	cfg := mihomo.BuildConfig(d)
	updateguard.GroupMeta(d, cfg)
	mihomo.DnsCfg(d)
	for _, nAny := range data.List(d, "nodes") {
		px := toMap(toMap(nAny)["proxy"])
		for _, k := range []string{"name", "type", "server", "port"} {
			if _, ok := px[k]; !ok {
				panic("nodes[].proxy 缺少 " + k)
			}
		}
	}
	if singbox.ActiveCore(d) == "singbox" {
		singbox.BuildSingbox(d)
	}
	return ""
}

// deviceRouteMissing 对应 device_route_missing(d)：按设备分流里目标策略组已不存在的条目名。
func deviceRouteMissing(d map[string]any) []string {
	var pol map[string]bool
	func() {
		defer func() { _ = recover() }()
		pol = map[string]bool{}
		cfg := mihomo.BuildConfig(d)
		for _, g := range toList(cfg["proxy-groups"]) {
			pol[toStr(toMap(g)["name"])] = true
		}
		for _, n := range data.List(d, "nodes") {
			pol[toStr(toMap(toMap(n)["proxy"])["name"])] = true
		}
	}()
	if pol == nil {
		return []string{}
	}
	for k := range base.BuiltinPolicies {
		pol[k] = true
	}
	var out []string
	for _, eAny := range data.List(d, "device_routes") {
		e := toMap(eAny)
		if e == nil {
			continue
		}
		if en, ok := e["enabled"]; ok && !toBool(en) {
			continue
		}
		if pol[toStr(e["target"])] {
			continue
		}
		out = append(out, firstNonEmpty(toStr(e["name"]), toStr(e["ip"]), toStr(e["mac"])))
	}
	return out
}

// tpApply 对应 tp_apply()：按当前代理方式重载 nftables 规则。
func tpApply() (int, string) {
	if notify.ManualStop() {
		return 0, ""
	}
	return sysopt.Sh(base.TproxySh+" apply", 60)
}

// configView 对应 config_view(d, masked=True)：配置文本视图。
func configView(d map[string]any) string {
	var cfg map[string]any
	if singbox.ActiveCore(d) == "singbox" {
		c, _, _ := singbox.BuildSingbox(d)
		cfg = c
	} else {
		cfg = mihomo.BuildConfig(d)
	}
	return jsonIndentNoHTML(maskCfg(cfg))
}

var (
	hhmmRe = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)
	ghRe   = regexp.MustCompile(`^https?://[\w.\-:]+/?$`)
	macRe  = regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)
)

func hasKey(m map[string]any, k string) bool {
	_, ok := m[k]
	return ok
}

func containsInt(xs []int, n int) bool {
	for _, x := range xs {
		if x == n {
			return true
		}
	}
	return false
}

// nowMs 当前毫秒时间戳。
func nowMs() int64 {
	return time.Now().UnixNano() / 1e6
}

func jsonUnmarshal(raw []byte, v any) error {
	return json.Unmarshal(raw, v)
}

// fileExists 文件是否存在。
func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
