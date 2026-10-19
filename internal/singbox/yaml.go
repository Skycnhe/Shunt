package singbox

// sb_yaml.py：极简 YAML 读取（只为解析 Clash 订阅里的 proxies 列表；面板保持零依赖）

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// yStripComment 去掉行尾注释（引号内的 # 不算）
func yStripComment(s string) string {
	var q rune
	rs := []rune(s)
	for i, ch := range rs {
		if q != 0 {
			if ch == q && (q == '\'' || rs[i-1] != '\\') {
				q = 0
			}
		} else if ch == '\'' || ch == '"' {
			q = ch
		} else if ch == '#' && (i == 0 || rs[i-1] == ' ' || rs[i-1] == '\t') {
			return strings.TrimRightFunc(string(rs[:i]), unicode.IsSpace)
		}
	}
	return strings.TrimRightFunc(s, unicode.IsSpace)
}

var (
	yIntRe   = regexp.MustCompile(`^[-+]?\d+$`)
	yFloatRe = regexp.MustCompile(`^[-+]?\d+\.\d+$`)
)

// yScalar 解析 YAML 标量
func yScalar(s string) any {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if len(s) > 1 && s[0] == '"' && s[len(s)-1] == '"' {
		var v any
		if err := json.Unmarshal([]byte(s), &v); err == nil {
			return v
		}
		return s[1 : len(s)-1]
	}
	if len(s) > 1 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	switch strings.ToLower(s) {
	case "true", "yes", "on":
		return true
	case "false", "no", "off":
		return false
	case "null", "~":
		return nil
	}
	if t := strings.TrimLeft(s, "+-"); yIntRe.MatchString(s) && !(len(t) > 1 && t[0] == '0') {
		if n, err := strconv.Atoi(s); err == nil {
			return n
		}
	}
	if yFloatRe.MatchString(s) {
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
	}
	return s
}

// yFlowParser 解析 {..} / [..] 流式集合
type yFlowParser struct{ s string }

func (p *yFlowParser) ws(i int) int {
	for i < len(p.s) && (p.s[i] == ' ' || p.s[i] == '\t' || p.s[i] == '\r' || p.s[i] == '\n') {
		i++
	}
	return i
}

func (p *yFlowParser) scalar(i int, stops string) (any, int) {
	i = p.ws(i)
	if i < len(p.s) && (p.s[i] == '\'' || p.s[i] == '"') {
		q := p.s[i]
		j := i + 1
		for j < len(p.s) {
			if p.s[j] == q {
				if q == '\'' && j+1 < len(p.s) && p.s[j+1] == '\'' {
					j += 2
					continue
				}
				if q == '"' && p.s[j-1] == '\\' {
					j++
					continue
				}
				break
			}
			j++
		}
		end := j + 1
		if end > len(p.s) {
			end = len(p.s)
		}
		return yScalar(p.s[i:end]), j + 1
	}
	j := i
	for j < len(p.s) && !strings.ContainsRune(stops, rune(p.s[j])) {
		if p.s[j] == ':' && strings.Contains(stops, "}") && (j+1 >= len(p.s) || strings.ContainsRune(" ,}", rune(p.s[j+1]))) {
			break
		}
		j++
	}
	return yScalar(p.s[i:j]), j
}

func (p *yFlowParser) value(i int, stops string) (any, int, error) {
	i = p.ws(i)
	if i < len(p.s) && (p.s[i] == '{' || p.s[i] == '[') {
		return p.flow(i)
	}
	v, ni := p.scalar(i, stops)
	return v, ni, nil
}

// flow 解析流式集合，返回 (值, 结束位置)
func (p *yFlowParser) flow(i int) (any, int, error) {
	i = p.ws(i)
	if i >= len(p.s) {
		return nil, i, fmt.Errorf("YAML 流式集合为空")
	}
	if p.s[i] == '{' {
		out := map[string]any{}
		i++
		for {
			i = p.ws(i)
			if i >= len(p.s) {
				return nil, i, fmt.Errorf("YAML 花括号未闭合")
			}
			if p.s[i] == '}' {
				return out, i + 1, nil
			}
			k, ni := p.scalar(i, ",}")
			i = p.ws(ni)
			var v any
			if i < len(p.s) && p.s[i] == ':' {
				var err error
				v, i, err = p.value(i+1, ",}")
				if err != nil {
					return nil, i, err
				}
			}
			out[pyStr(k)] = v
			i = p.ws(i)
			if i < len(p.s) && p.s[i] == ',' {
				i++
			}
		}
	}
	if p.s[i] == '[' {
		out := []any{}
		i++
		for {
			i = p.ws(i)
			if i >= len(p.s) {
				return nil, i, fmt.Errorf("YAML 方括号未闭合")
			}
			if p.s[i] == ']' {
				return out, i + 1, nil
			}
			v, ni, err := p.value(i, ",]")
			if err != nil {
				return nil, ni, err
			}
			i = ni
			out = append(out, v)
			i = p.ws(i)
			if i < len(p.s) && p.s[i] == ',' {
				i++
			}
		}
	}
	v, ni := p.scalar(i, "")
	return v, ni, nil
}

// yFlow 解析 {..} / [..] 流式集合，返回 (值, 结束位置)
func yFlow(s string, i int) (any, int, error) {
	return (&yFlowParser{s: s}).flow(i)
}

// FlowMax 一个流式集合最多跨这么多行，超过就当它没闭合，不再往后吞
const FlowMax = 200

// yDepth 括号深度变化：引号里的不算（引号只在值的开头才算引号，Bob's 这种普通文字里的撇号不算）
func yDepth(s string) int {
	var q byte
	n := 0
	prev := byte(',')
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if q != 0 {
			if ch == q && (q == '\'' || s[i-1] != '\\') {
				q = 0
				prev = ch
			}
			continue
		}
		if (ch == '\'' || ch == '"') && (prev == '{' || prev == '[' || prev == ',' || prev == ':') {
			q = ch
		} else if ch == '{' || ch == '[' {
			n++
		} else if ch == '}' || ch == ']' {
			n--
		}
		if ch != ' ' && ch != '\t' {
			prev = ch
		}
	}
	return n
}

var flowKeyRe = regexp.MustCompile(`^\s*(?:-\s+)*(?:(?:"(?:[^"\\]|\\.)*"|'[^']*'|[^\s'"{}\[\],:#-][^:#]*?|-[^\s:#][^:#]*?)\s*:\s+)?`)

// yFlowStart 行内流式集合（{..} / [..]）开始的位置：「- {a: 1}」「key: [a, b]」「[a]」；没有返回 -1
func yFlowStart(c string) int {
	i := 0
	if loc := flowKeyRe.FindStringIndex(c); loc != nil {
		i = loc[1]
	}
	if i < len(c) && (c[i] == '{' || c[i] == '[') {
		return i
	}
	return -1
}

// pyStr Python str() 语义（流式映射键 / YAML 映射键用）
func pyStr(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	case int:
		return strconv.Itoa(t)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	default:
		return fmt.Sprint(t)
	}
}

type yLine struct {
	indent int
	text   string
}

// ySplitKV 切分「key: value」；返回 (key, value, 是否切分成功)
func ySplitKV(t string) (any, string, bool) {
	if len(t) > 0 && (t[0] == '\'' || t[0] == '"') {
		q := t[0]
		j := strings.IndexByte(t[1:], q)
		if j >= 0 {
			j++
		}
		for q == '"' && j > 0 && t[j-1] == '\\' {
			nj := strings.IndexByte(t[j+1:], q)
			if nj < 0 {
				j = -1
				break
			}
			j = j + 1 + nj
		}
		if j > 0 && j+1 < len(t) && t[j+1] == ':' {
			return yScalar(t[:j+1]), strings.TrimSpace(t[j+2:]), true
		}
		return nil, "", false
	}
	m := yKVRe.FindStringSubmatch(t)
	if m == nil {
		return nil, "", false
	}
	return strings.TrimSpace(m[1]), strings.TrimSpace(m[2]), true
}

var yKVRe = regexp.MustCompile(`^([^:{}\[\],]+?)\s*:(?:\s+(.*)|$)`)

// yInline 解析行内值
func yInline(v string) (any, error) {
	if strings.HasPrefix(v, "{") || strings.HasPrefix(v, "[") {
		val, _, err := yFlow(v, 0)
		return val, err
	}
	if v == "|" || v == ">" || v == "|-" || v == ">-" {
		return "", nil
	}
	return yScalar(v), nil
}

func isBlockScalar(v string) bool {
	return v == "|" || v == ">" || v == "|-" || v == ">-"
}

// yBlock 递归解析块状结构；lines 会被原地改写（「- key: v」等价于下一级映射的第一行）
func yBlock(lines []yLine, i, ind int) (any, int, error) {
	if i >= len(lines) {
		return nil, i, nil
	}
	if t := lines[i].text; strings.HasPrefix(t, "- ") || t == "-" {
		out := []any{}
		for i < len(lines) && lines[i].indent == ind && (strings.HasPrefix(lines[i].text, "- ") || lines[i].text == "-") {
			rest := strings.TrimSpace(lines[i].text[1:])
			if rest == "" {
				if i+1 < len(lines) && lines[i+1].indent > ind {
					v, ni, err := yBlock(lines, i+1, lines[i+1].indent)
					if err != nil {
						return nil, ni, err
					}
					out = append(out, v)
					i = ni
				} else {
					out = append(out, nil)
					i++
				}
				continue
			}
			var kvOk bool
			if !(strings.HasPrefix(rest, "{") || strings.HasPrefix(rest, "[")) {
				_, _, kvOk = ySplitKV(rest)
			}
			if !kvOk {
				v, err := yInline(rest)
				if err != nil {
					return nil, i, err
				}
				out = append(out, v)
				i++
				continue
			}
			sub := ind + len(lines[i].text) - len(rest)
			lines[i] = yLine{sub, rest} // 「- key: v」等价于下一级映射的第一行
			v, ni, err := yBlock(lines, i, sub)
			if err != nil {
				return nil, ni, err
			}
			out = append(out, v)
			i = ni
		}
		return out, i, nil
	}
	out := map[string]any{}
	for i < len(lines) && lines[i].indent == ind && !strings.HasPrefix(lines[i].text, "- ") {
		kvK, kvV, kvOk := ySplitKV(lines[i].text)
		if !kvOk {
			i++
			continue
		}
		k, v := kvK, kvV
		i++
		if v != "" && !isBlockScalar(v) {
			iv, err := yInline(v)
			if err != nil {
				return nil, i, err
			}
			out[pyStr(k)] = iv
		} else if i < len(lines) && (lines[i].indent > ind || (lines[i].indent == ind && strings.HasPrefix(lines[i].text, "- "))) {
			if isBlockScalar(v) {
				var parts []string
				for i < len(lines) && lines[i].indent > ind {
					parts = append(parts, lines[i].text)
					i++
				}
				sep := "\n"
				if strings.HasPrefix(v, ">") {
					sep = " "
				}
				out[pyStr(k)] = strings.Join(parts, sep)
			} else {
				bv, ni, err := yBlock(lines, i, lines[i].indent)
				if err != nil {
					return nil, ni, err
				}
				out[pyStr(k)] = bv
				i = ni
			}
		} else {
			out[pyStr(k)] = nil
		}
	}
	return out, i, nil
}

// YamlLite 块状 / 流式映射与列表、引号字符串、注释；不支持锚点等高级语法
func YamlLite(text string) (any, error) {
	var raw []string
	for _, line := range strings.Split(strings.ReplaceAll(text, "\t", "  "), "\n") {
		t := strings.TrimSpace(line)
		if t == "---" || t == "..." || t == "" || strings.HasPrefix(strings.TrimLeftFunc(line, unicode.IsSpace), "#") {
			continue
		}
		raw = append(raw, line)
	}
	var lines []yLine
	buf := ""
	depth := 0
	nbuf := 0
	indentOf := func(s string) int { return len(s) - len(strings.TrimLeft(s, " ")) }
	for _, line := range raw { // 跨行的流式集合合并成一行
		c := yStripComment(line)
		if buf != "" {
			buf += " " + strings.TrimSpace(c)
			depth += yDepth(c)
			nbuf++
		} else {
			st := yFlowStart(c)
			if st < 0 { // 这一行没有流式集合（块状写法里的 HK[01 之类不算括号）
				lines = append(lines, yLine{indentOf(c), strings.TrimSpace(c)})
				continue
			}
			buf, depth, nbuf = c, yDepth(c[st:]), 1
		}
		// 以前每行都对整段已合并的内容重新去注释、数括号，且引号里的 [ 也计数：
		// 一个节点名带「[」就让后面所有行并成一行，2000 个节点要十几秒（平方级）。现在逐行累计，最多合并 FlowMax 行
		if depth <= 0 || nbuf >= FlowMax {
			lines = append(lines, yLine{indentOf(buf), strings.TrimSpace(buf)})
			buf = ""
		}
	}
	if buf != "" {
		lines = append(lines, yLine{indentOf(buf), strings.TrimSpace(buf)})
	}
	if len(lines) == 0 {
		return nil, nil
	}
	v, _, err := yBlock(lines, 0, lines[0].indent)
	return v, err
}
