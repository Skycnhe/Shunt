// Package links 对应 Python shunt/links.py：单节点链接解析。
package links

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"shunt/internal/base"
	"shunt/internal/data"
)

// B64d base64（兼容 urlsafe、无 padding）解码
func B64d(s string) (string, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(strings.ReplaceAll(s, "-", "+"), "_", "/")
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Q1 取查询参数中第一个非空值
func Q1(qs url.Values, keys ...string) string {
	for _, k := range keys {
		if v := qs[k]; len(v) > 0 && v[0] != "" {
			return v[0]
		}
	}
	return ""
}

// Truthy "1"/"true"/"yes" 判定
func Truthy(v string) bool {
	switch strings.ToLower(v) {
	case "1", "true", "yes":
		return true
	}
	return false
}

var (
	ipv6HPRe = regexp.MustCompile(`^\[([0-9A-Fa-f:.]+)\]:([\d,\-]+)$`)
	ipv4HPRe = regexp.MustCompile(`^([^:\[\]]+):([\d,\-]+)$`)
)

// HostPort 返回 (host, port_spec)，兼容 [IPv6]:port 与 hy2 的多端口 443,2000-3000
func HostPort(netloc string) (string, string, error) {
	hp := netloc
	if i := strings.LastIndex(hp, "@"); i >= 0 {
		hp = hp[i+1:]
	}
	if m := ipv6HPRe.FindStringSubmatch(hp); m != nil {
		return m[1], m[2], nil
	}
	if m := ipv4HPRe.FindStringSubmatch(hp); m != nil {
		return m[1], m[2], nil
	}
	return "", "", fmt.Errorf("服务器地址或端口无效")
}

// splitURL 不校验端口合法性地拆分链接（Go 的 url.Parse 会拒绝 hy2 的多端口写法）
func splitURL(line string) (hostport, query, frag, userinfo string) {
	rest := line
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.Index(rest, "#"); i >= 0 {
		frag = rest[i+1:]
		rest = rest[:i]
	}
	if i := strings.Index(rest, "?"); i >= 0 {
		query = rest[i+1:]
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		userinfo = rest[:i]
		rest = rest[i+1:]
	}
	return rest, query, frag, userinfo
}

func unq(s string) string {
	v, err := url.PathUnescape(s)
	if err != nil {
		return s
	}
	return v
}

// LinkParts URL 形式的链接 → (查询参数, 主机, 端口, 名称, 用户名, 密码, 是否有密码)；firstPort：端口范围只取第一个
func LinkParts(line string, firstPort bool) (url.Values, string, string, string, string, string, bool, error) {
	hostport, query, frag, userinfo := splitURL(line)
	qs, err := url.ParseQuery(query)
	if err != nil {
		return nil, "", "", "", "", "", false, err
	}
	host, port, err := HostPort(hostport)
	if err != nil {
		return nil, "", "", "", "", "", false, err
	}
	if firstPort {
		port = regexp.MustCompile(`[,\-]`).Split(port, -1)[0]
	}
	user, pw, hasPw := "", "", false
	if userinfo != "" {
		if i := strings.Index(userinfo, ":"); i >= 0 {
			user, pw, hasPw = unq(userinfo[:i]), unq(userinfo[i+1:]), true
		} else {
			user = unq(userinfo)
		}
	}
	return qs, host, port, unq(frag), user, pw, hasPw, nil
}

// CommonTLS 通用 TLS 参数
func CommonTLS(p map[string]any, qs url.Values, sniKey string) {
	if sniKey == "" {
		sniKey = "servername"
	}
	if sni := Q1(qs, "sni", "peer", "serverName"); sni != "" {
		p[sniKey] = sni
	}
	if alpn := Q1(qs, "alpn"); alpn != "" {
		var a []any
		for _, x := range strings.Split(alpn, ",") {
			if x != "" {
				a = append(a, x)
			}
		}
		if a != nil {
			p["alpn"] = a
		}
	}
	if fp := Q1(qs, "fp"); fp != "" {
		p["client-fingerprint"] = fp
	}
	if Truthy(Q1(qs, "allowInsecure", "insecure", "allow_insecure", "skip-cert-verify")) {
		p["skip-cert-verify"] = true
	}
}

// Transport 传输层参数
func Transport(p map[string]any, net string, qs url.Values) error {
	net = strings.ToLower(net)
	if net == "" {
		net = "tcp"
	}
	host, path := Q1(qs, "host"), Q1(qs, "path")
	switch net {
	case "ws", "httpupgrade":
		p["network"] = "ws"
		o := map[string]any{"path": orDefault(path, "/")}
		if host != "" {
			o["headers"] = map[string]any{"Host": host}
		}
		if net == "httpupgrade" {
			o["v2ray-http-upgrade"] = true
		}
		p["ws-opts"] = o
	case "grpc":
		p["network"] = "grpc"
		p["grpc-opts"] = map[string]any{"grpc-service-name": Q1(qs, "serviceName", "path")}
	case "h2", "http":
		p["network"] = "h2"
		o := map[string]any{"path": orDefault(path, "/")}
		if host != "" {
			o["host"] = strings.Split(host, ",")
		}
		p["h2-opts"] = o
	case "tcp":
		if Q1(qs, "headerType") == "http" {
			p["network"] = "http"
			o := map[string]any{"path": []any{orDefault(path, "/")}}
			if host != "" {
				o["headers"] = map[string]any{"Host": strings.Split(host, ",")}
			}
			p["http-opts"] = o
		}
	default:
		return fmt.Errorf("不支持的传输方式 %s", net)
	}
	return nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func jmGet(j map[string]any, k string) any { return j[k] }

func jStr(j map[string]any, k string) string {
	s, _ := jmGet(j, k).(string)
	return s
}

func jInt(j map[string]any, k string) (int, error) {
	switch v := jmGet(j, k).(type) {
	case float64:
		return int(v), nil
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		return n, err
	case int:
		return v, nil
	}
	return 0, fmt.Errorf("字段 %s 缺失或无效", k)
}

// ParseVmess vmess://base64(json)
func ParseVmess(line string) (map[string]any, error) {
	body := line[8:]
	if i := strings.Index(body, "#"); i >= 0 {
		body = body[:i]
	}
	dec, err := B64d(body)
	if err != nil {
		return nil, err
	}
	var j map[string]any
	if err := json.Unmarshal([]byte(dec), &j); err != nil {
		return nil, err
	}
	add, _ := j["add"].(string)
	port, err := jInt(j, "port")
	if err != nil {
		return nil, err
	}
	uuid, _ := j["id"].(string)
	aid, _ := jInt(j, "aid")
	p := map[string]any{
		"name": jStr(j, "ps"), "type": "vmess", "server": add, "port": port,
		"uuid": uuid, "alterId": aid, "cipher": orDefault(jStr(j, "scy"), "auto"), "udp": true,
	}
	if tls := j["tls"]; tls == "tls" || tls == true {
		p["tls"] = true
		if sni := orDefault(jStr(j, "sni"), jStr(j, "host")); sni != "" {
			p["servername"] = sni
		}
		if alpn := jStr(j, "alpn"); alpn != "" {
			p["alpn"] = strings.Split(alpn, ",")
		}
		if fp := jStr(j, "fp"); fp != "" {
			p["client-fingerprint"] = fp
		}
		if Truthy(jStr(j, "allowInsecure") + jStr(j, "skip-cert-verify")) {
			p["skip-cert-verify"] = true
		}
	}
	qs := url.Values{
		"path":        {jStr(j, "path")},
		"host":        {jStr(j, "host")},
		"serviceName": {jStr(j, "path")},
		"headerType":  {jStr(j, "type")},
	}
	if err := Transport(p, jStr(j, "net"), qs); err != nil {
		return nil, err
	}
	return p, nil
}

// ParseSs ss:// 链接（含旧格式）
func ParseSs(line string) (map[string]any, error) {
	body := line[5:]
	frag := ""
	if i := strings.Index(body, "#"); i >= 0 {
		frag, body = body[i+1:], body[:i]
	}
	var userinfo, rest string
	if strings.Contains(body, "@") {
		i := strings.LastIndex(body, "@")
		userinfo, rest = unq(body[:i]), body[i+1:]
	} else { // 旧格式 ss://base64(method:pass@host:port)
		b, qpart := body, ""
		if i := strings.Index(b, "?"); i >= 0 {
			b, qpart = b[:i], b[i:]
		}
		dec, err := B64d(strings.TrimRight(b, "/"))
		if err != nil {
			return nil, err
		}
		if i := strings.LastIndex(dec, "@"); i >= 0 {
			userinfo, rest = dec[:i], dec[i+1:]
		} else {
			userinfo, rest = "", dec
		}
		if qpart != "" {
			rest += "?" + qpart
		}
	}
	if !strings.Contains(userinfo, ":") {
		dec, err := B64d(userinfo)
		if err != nil {
			return nil, err
		}
		userinfo = dec
	}
	method, password := userinfo, ""
	if i := strings.Index(userinfo, ":"); i >= 0 {
		method, password = userinfo[:i], userinfo[i+1:]
	}
	qs, host, port, _, _, _, _, err := LinkParts("ss://x@"+rest, false)
	if err != nil {
		return nil, err
	}
	pn, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	p := map[string]any{"name": unq(frag), "type": "ss", "server": host, "port": pn,
		"cipher": method, "password": password, "udp": true}
	if plugin := Q1(qs, "plugin"); plugin != "" {
		parts := strings.Split(plugin, ";")
		opts := map[string]string{}
		for _, x := range parts[1:] {
			kv := strings.SplitN(x+"=", "=", 2)
			opts[kv[0]] = kv[1]
		}
		switch parts[0] {
		case "obfs-local", "simple-obfs", "obfs":
			p["plugin"] = "obfs"
			p["plugin-opts"] = map[string]any{"mode": orDefault(opts["obfs"], "http"), "host": orDefault(opts["obfs-host"], "bing.com")}
		case "v2ray-plugin":
			p["plugin"] = "v2ray-plugin"
			p["plugin-opts"] = map[string]any{"mode": orDefault(opts["mode"], "websocket"), "host": opts["host"],
				"path": orDefault(opts["path"], "/"), "tls": strings.Contains(opts["tls"], "tls")}
		default:
			return nil, fmt.Errorf("不支持的 ss 插件 %s", parts[0])
		}
	}
	return p, nil
}

// ParseVless vless:// 链接
func ParseVless(line string) (map[string]any, error) {
	qs, host, port, name, user, _, _, err := LinkParts(line, false)
	if err != nil {
		return nil, err
	}
	pn, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	p := map[string]any{"name": name, "type": "vless", "server": host, "port": pn, "uuid": user, "udp": true}
	if sec := Q1(qs, "security"); sec == "tls" || sec == "reality" || sec == "xtls" {
		p["tls"] = true
		CommonTLS(p, qs, "servername")
	}
	if Q1(qs, "security") == "reality" {
		p["reality-opts"] = map[string]any{"public-key": Q1(qs, "pbk"), "short-id": Q1(qs, "sid")}
		if _, ok := p["client-fingerprint"]; !ok {
			p["client-fingerprint"] = "chrome"
		}
	}
	if flow := Q1(qs, "flow"); flow != "" {
		p["flow"] = flow
	}
	if enc := Q1(qs, "encryption"); enc != "" && enc != "none" {
		p["encryption"] = enc
	}
	if err := Transport(p, Q1(qs, "type"), qs); err != nil {
		return nil, err
	}
	return p, nil
}

// ParseTrojan trojan:// 链接
func ParseTrojan(line string) (map[string]any, error) {
	qs, host, port, name, user, _, _, err := LinkParts(line, false)
	if err != nil {
		return nil, err
	}
	pn, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	p := map[string]any{"name": name, "type": "trojan", "server": host, "port": pn, "password": user, "udp": true}
	CommonTLS(p, qs, "sni")
	if err := Transport(p, Q1(qs, "type"), qs); err != nil {
		return nil, err
	}
	return p, nil
}

var portSplitRe = regexp.MustCompile(`[,\-]`)

// ParseHysteria2 hysteria2:// / hy2:// 链接
func ParseHysteria2(line string) (map[string]any, error) {
	qs, host, port, name, user, pw, hasPw, err := LinkParts(line, false)
	if err != nil {
		return nil, err
	}
	auth := user
	if hasPw {
		auth += ":" + pw
	}
	first, err := strconv.Atoi(portSplitRe.Split(port, -1)[0])
	if err != nil {
		return nil, err
	}
	p := map[string]any{"name": name, "type": "hysteria2", "server": host, "port": first, "password": auth, "udp": true}
	if !isDigits(port) {
		p["ports"] = port
	}
	CommonTLS(p, qs, "sni")
	delete(p, "client-fingerprint")
	if obfs := Q1(qs, "obfs"); obfs != "" && obfs != "none" {
		p["obfs"] = obfs
		p["obfs-password"] = Q1(qs, "obfs-password")
	}
	return p, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ParseTuic tuic:// 链接
func ParseTuic(line string) (map[string]any, error) {
	qs, host, port, name, user, pw, _, err := LinkParts(line, false)
	if err != nil {
		return nil, err
	}
	pn, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	p := map[string]any{"name": name, "type": "tuic", "server": host, "port": pn, "uuid": user, "password": pw,
		"udp": true, "alpn": []any{"h3"}}
	CommonTLS(p, qs, "sni")
	delete(p, "client-fingerprint")
	p["congestion-controller"] = orDefault(Q1(qs, "congestion_control", "congestion-control"), "bbr")
	p["udp-relay-mode"] = orDefault(Q1(qs, "udp_relay_mode", "udp-relay-mode"), "native")
	if Truthy(Q1(qs, "disable_sni")) {
		p["disable-sni"] = true
	}
	return p, nil
}

// ParseAnytls anytls:// 链接
func ParseAnytls(line string) (map[string]any, error) {
	qs, host, port, name, user, _, _, err := LinkParts(line, true)
	if err != nil {
		return nil, err
	}
	pn, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	p := map[string]any{"name": name, "type": "anytls", "server": host, "port": pn, "password": user, "udp": true}
	CommonTLS(p, qs, "sni")
	return p, nil
}

// ParseHysteria hysteria:// / hy:// 链接
func ParseHysteria(line string) (map[string]any, error) {
	qs, host, port, name, user, _, _, err := LinkParts(line, true)
	if err != nil {
		return nil, err
	}
	pn, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	p := map[string]any{"name": name, "type": "hysteria", "server": host, "port": pn, "udp": true,
		"up": orDefault(Q1(qs, "upmbps", "up"), "10"), "down": orDefault(Q1(qs, "downmbps", "down"), "50")}
	if auth := orDefault(Q1(qs, "auth", "auth_str"), user); auth != "" {
		p["auth-str"] = auth
	}
	if obfs := Q1(qs, "obfsParam", "obfs-password", "obfs"); obfs != "" {
		p["obfs"] = obfs
	}
	CommonTLS(p, qs, "sni")
	delete(p, "client-fingerprint")
	return p, nil
}

// ParseSocks socks:// / socks5:// / socks5h:// 链接
func ParseSocks(line string) (map[string]any, error) {
	_, host, port, name, user, pw, hasPw, err := LinkParts(line, true)
	if err != nil {
		return nil, err
	}
	if !hasPw && user != "" && !strings.Contains(user, ":") {
		if dec, derr := B64d(user); derr == nil {
			u, pw2, _ := strings.Cut(dec, ":")
			user, pw, hasPw = u, pw2, true
		}
	}
	pn, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	p := map[string]any{"name": name, "type": "socks5", "server": host, "port": pn, "udp": true}
	if user != "" {
		p["username"] = user
		p["password"] = pw
	}
	return p, nil
}

// LinkParsers 链接类型 → 解析函数
var LinkParsers = map[string]func(string) (map[string]any, error){
	"vmess": ParseVmess, "ss": ParseSs, "vless": ParseVless, "trojan": ParseTrojan,
	"hysteria2": ParseHysteria2, "hy2": ParseHysteria2, "tuic": ParseTuic, "anytls": ParseAnytls,
	"hysteria": ParseHysteria, "hy": ParseHysteria,
	"socks": ParseSocks, "socks5": ParseSocks, "socks5h": ParseSocks,
}

// ParseLink 按 scheme 分发解析
func ParseLink(line string) (map[string]any, error) {
	line = strings.TrimSpace(line)
	scheme := strings.ToLower(strings.SplitN(line, "://", 2)[0])
	fn, ok := LinkParsers[scheme]
	if !ok {
		return nil, fmt.Errorf("不支持的链接类型 %s://", scheme)
	}
	return fn(line)
}

// AddLinks 解析多行链接，返回 (新增节点列表, 错误列表)；节点名自动去重
func AddLinks(text string, existing []map[string]any, d map[string]any) ([]map[string]any, []string) {
	taken := map[string]bool{}
	for _, n := range existing {
		if pm, ok := n["proxy"].(map[string]any); ok {
			if name, ok := pm["name"].(string); ok {
				taken[name] = true
			}
		}
	}
	for n := range ReservedNames(d) {
		taken[n] = true
	}
	var out []map[string]any
	var errs []string
	i := 0
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		i++
		p, err := ParseLink(line)
		if err == nil && (p["server"] == nil || p["server"] == "" || p["port"] == nil || p["port"] == 0) {
			err = fmt.Errorf("缺少服务器或端口")
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("第 %d 行：%s", i, err))
			continue
		}
		baseName := strings.TrimSpace(data.Str(p, "name"))
		if baseName == "" {
			baseName = fmt.Sprintf("%s-%s:%v", p["type"], p["server"], p["port"])
		}
		name, k := baseName, 2
		for taken[name] {
			name, k = fmt.Sprintf("%s (%d)", baseName, k), k+1
		}
		p["name"] = name
		taken[name] = true
		out = append(out, map[string]any{"link": line, "proxy": p})
	}
	return out, errs
}

// ReservedNames 面板保留名（策略组名等，不能用作节点名）
func ReservedNames(d map[string]any) map[string]bool {
	var regs []string
	for _, r := range base.Regions {
		regs = append(regs, r.Name)
	}
	regs = append(regs, base.GOther)
	out := map[string]bool{
		base.GSel: true, base.GAuto: true, base.GManual: true, base.GDirect: true,
		base.LegacyAuto: true, "GLOBAL": true,
	}
	for _, s := range base.SideGroups {
		out[s] = true
	}
	for p := range base.BuiltinPolicies {
		out[p] = true
	}
	for _, r := range regs {
		out[r] = true
		out[r+base.LbSuffix] = true
		out[r+base.AutoSuffix] = true
		out[data.AutoName(r)] = true
		out[data.AutoName(r, base.AutoTailOld)] = true
		out[data.LbOldName(r)] = true
		for _, n := range data.LbNames(r) {
			out[n] = true
		}
		for _, n := range data.LbDroppedNames(r) {
			out[n] = true
		}
	}
	if d != nil {
		for _, g := range data.List(d, "custom_groups") {
			if gm, ok := g.(map[string]any); ok {
				out[data.Str(gm, "name")] = true
			}
		}
	}
	return out
}
