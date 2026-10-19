package mihomo

// 极简 YAML 序列化：把 map[string]any / []any / 标量写成标准缩进式 YAML（mihomo 配置用）。
//
// 不引入第三方库。字符串引号规则与 shunt/sb_yaml.py 的解析习惯对齐：
//   - 可安全裸写的标量直接输出；其余用双引号包裹、JSON 风格转义
//     （sb_yaml.py 对 "..." 用 json.loads 解析，对 '...' 按 '' 转义处理，
//     双引号 + JSON 转义是两侧都能无损 round-trip 的写法）。
//   - 含 ":" 的键必须加引号，否则按 "key: value" 切分会丢失键的一部分。

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Marshal 将配置结构序列化为 YAML 文本。
func Marshal(v any) (string, error) {
	var b strings.Builder
	writeNode(&b, v, 0)
	return b.String(), nil
}

var yamlNumRe = regexp.MustCompile(`^[-+]?(\d+(\.\d+)?|\.\d+)([eE][-+]?\d+)?$`)
var yamlLeadZeroRe = regexp.MustCompile(`^[-+]?0\d`)

// yamlPlainOK 判断字符串能否作为裸标量输出。
func yamlPlainOK(s string) bool {
	if s == "" || s != strings.TrimSpace(s) {
		return false
	}
	switch strings.ToLower(s) {
	case "true", "false", "yes", "no", "on", "off", "null", "~":
		return false
	}
	if yamlNumRe.MatchString(s) && !yamlLeadZeroRe.MatchString(s) {
		return false // 看起来像数字的必须加引号，否则会被解析成数字
	}
	if strings.ContainsRune("-?:,[]{}#&*!|>'\"%@`", rune(s[0])) {
		return false
	}
	if strings.HasSuffix(s, ":") || strings.Contains(s, ": ") || strings.Contains(s, " #") {
		return false
	}
	for _, r := range s {
		if (r < 0x20 && r != '\t') || r == 0x7f {
			return false
		}
	}
	return true
}

// yamlQuote 双引号包裹并做 JSON 风格转义。
func yamlQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func yamlStr(s string) string {
	if yamlPlainOK(s) {
		return s
	}
	return yamlQuote(s)
}

// yamlKey 键的序列化：含冒号的键必须加引号（否则 "a:b: v" 会被切错）。
func yamlKey(k string) string {
	if strings.Contains(k, ":") {
		return yamlQuote(k)
	}
	return yamlStr(k)
}

func yamlScalar(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		if t {
			return "true"
		}
		return "false"
	case string:
		return yamlStr(t)
	case int:
		return strconv.Itoa(t)
	case int8:
		return strconv.FormatInt(int64(t), 10)
	case int16:
		return strconv.FormatInt(int64(t), 10)
	case int32:
		return strconv.FormatInt(int64(t), 10)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint:
		return strconv.FormatUint(uint64(t), 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	case float32:
		return yamlFloat(float64(t))
	case float64:
		return yamlFloat(t)
	default:
		return yamlStr(fmt.Sprintf("%v", v))
	}
}

func yamlFloat(f float64) string {
	if !math.IsInf(f, 0) && !math.IsNaN(f) && f == math.Trunc(f) && math.Abs(f) < 1e15 {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// writeNode 在 indent 缩进处写一个完整节点（末尾带换行）。
func writeNode(b *strings.Builder, v any, indent int) {
	pad := strings.Repeat(" ", indent)
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 {
			b.WriteString("{}\n")
			return
		}
		for _, k := range sortedKeys(t) {
			b.WriteString(pad + yamlKey(k) + ":")
			writeChild(b, t[k], indent)
		}
	case []any:
		if len(t) == 0 {
			b.WriteString("[]\n")
			return
		}
		for _, item := range t {
			b.WriteString(pad + "-")
			writeSeqItem(b, item, indent)
		}
	default:
		b.WriteString(yamlScalar(v) + "\n")
	}
}

// writeChild 写 "key:" 后面的值：标量同行，集合换行后缩进一级。
func writeChild(b *strings.Builder, v any, indent int) {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 {
			b.WriteString(" {}\n")
			return
		}
		b.WriteByte('\n')
		writeNode(b, t, indent+2)
	case []any:
		if len(t) == 0 {
			b.WriteString(" []\n")
			return
		}
		b.WriteByte('\n')
		writeNode(b, t, indent+2)
	default:
		b.WriteString(" " + yamlScalar(v) + "\n")
	}
}

// writeSeqItem 写 "- " 之后的内容：map 用紧凑形式（首个键与 "-" 同行）。
func writeSeqItem(b *strings.Builder, v any, indent int) {
	if m, ok := v.(map[string]any); ok {
		if len(m) == 0 {
			b.WriteString(" {}\n")
			return
		}
		keys := sortedKeys(m)
		b.WriteString(" " + yamlKey(keys[0]) + ":")
		writeChild(b, m[keys[0]], indent+2)
		sub := strings.Repeat(" ", indent+2)
		for _, k := range keys[1:] {
			b.WriteString(sub + yamlKey(k) + ":")
			writeChild(b, m[k], indent+2)
		}
		return
	}
	if l, ok := v.([]any); ok {
		if len(l) == 0 {
			b.WriteString(" []\n")
			return
		}
		b.WriteByte('\n')
		writeNode(b, l, indent+2)
		return
	}
	b.WriteString(" " + yamlScalar(v) + "\n")
}
