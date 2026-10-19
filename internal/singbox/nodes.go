package singbox

// sb_nodes.py：mihomo 字段 → sing-box outbound

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"shunt/internal/data"
)

// toInt 宽松转 int（处理 "443" 这类字符串端口）
func toInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int8:
		return int(t)
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return n
		}
	}
	return 0
}

// isTruthy Python 真值语义（None/""/[]/{}/0/False 为假）
func isTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	case int:
		return t != 0
	case float64:
		return t != 0
	}
	return true
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func toStrList(v any) []string {
	var out []string
	switch t := v.(type) {
	case []any:
		for _, x := range t {
			out = append(out, toStr(x))
		}
	case []string:
		out = t
	case string:
		out = []string{t}
	}
	return out
}

// sbTLS 构造 sing-box tls 段；无 tls 且非 force 时返回 nil
func sbTLS(p map[string]any, sniKey string, force bool) map[string]any {
	if sniKey == "" {
		sniKey = "servername"
	}
	if !data.Bool(p, "tls") && !force {
		return nil
	}
	t := map[string]any{"enabled": true}
	sni := data.Str(p, sniKey)
	if sni == "" {
		sni = data.Str(p, "sni")
	}
	if sni == "" {
		sni = data.Str(p, "servername")
	}
	if sni != "" {
		t["server_name"] = sni
	}
	if data.Bool(p, "skip-cert-verify") {
		t["insecure"] = true
	}
	if alpnV, ok := p["alpn"]; ok && alpnV != nil {
		var a []any
		truthy := true
		switch t := alpnV.(type) {
		case []any:
			if len(t) == 0 {
				truthy = false
			}
			for _, x := range t {
				a = append(a, toStr(x))
			}
		case string:
			if t == "" {
				truthy = false
			}
			for _, x := range strings.Split(t, ",") {
				a = append(a, x)
			}
		default:
			a = []any{toStr(alpnV)}
		}
		if truthy {
			t["alpn"] = a
		}
	}
	if data.Bool(p, "disable-sni") {
		t["disable_sni"] = true
	}
	fp := data.Str(p, "client-fingerprint")
	if ro := data.Map(p, "reality-opts"); ro != nil {
		t["reality"] = map[string]any{
			"enabled":    true,
			"public_key": data.Str(ro, "public-key"),
			"short_id":   data.Str(ro, "short-id"),
		}
		if fp == "" {
			fp = "chrome"
		}
	}
	if fp != "" && fp != "none" {
		ffp := fp
		if ffp == "random" {
			ffp = "chrome"
		}
		t["utls"] = map[string]any{"enabled": true, "fingerprint": ffp}
	}
	return t
}

var wsEdRe = regexp.MustCompile(`[?&]ed=(\d+)`)

// sbTransport 构造 sing-box transport 段；tcp/空返回 nil；不支持的抛错
func sbTransport(p map[string]any) (map[string]any, error) {
	net_ := strings.ToLower(data.Str(p, "network"))
	if net_ == "" {
		net_ = "tcp"
	}
	switch net_ {
	case "ws":
		o := data.Map(p, "ws-opts")
		path := data.Str(o, "path")
		if path == "" {
			path = "/"
		}
		hdr := map[string]any{}
		for k, v := range data.Map(o, "headers") {
			if l, ok := v.([]any); ok && len(l) > 0 {
				hdr[k] = toStr(l[0])
			} else {
				hdr[k] = toStr(v)
			}
		}
		if data.Bool(o, "v2ray-http-upgrade") {
			t := map[string]any{"type": "httpupgrade", "path": path}
			if h, ok := hdr["Host"]; ok {
				t["host"] = h
				delete(hdr, "Host")
			}
			if len(hdr) > 0 {
				t["headers"] = hdr
			}
			return t, nil
		}
		t := map[string]any{"type": "ws", "path": path}
		if m := wsEdRe.FindStringSubmatch(path); m != nil {
			t["path"] = wsEdRe.ReplaceAllString(path, "")
			if t["path"] == "" {
				t["path"] = "/"
			}
			n, _ := strconv.Atoi(m[1])
			t["max_early_data"] = n
			t["early_data_header_name"] = "Sec-WebSocket-Protocol"
		} else if med := data.Str(o, "max-early-data"); med != "" {
			t["max_early_data"] = toInt(o["max-early-data"])
			edhn := data.Str(o, "early-data-header-name")
			if edhn == "" {
				edhn = "Sec-WebSocket-Protocol"
			}
			t["early_data_header_name"] = edhn
		}
		if len(hdr) > 0 {
			t["headers"] = hdr
		}
		return t, nil
	case "grpc":
		o := data.Map(p, "grpc-opts")
		return map[string]any{"type": "grpc", "service_name": data.Str(o, "grpc-service-name")}, nil
	case "h2":
		o := data.Map(p, "h2-opts")
		path := data.Str(o, "path")
		if path == "" {
			path = "/"
		}
		t := map[string]any{"type": "http", "path": path}
		if h, ok := o["host"]; ok && h != nil {
			var hosts []any
			for _, x := range toStrList(h) {
				hosts = append(hosts, x)
			}
			t["host"] = hosts
		}
		return t, nil
	case "http":
		o := data.Map(p, "http-opts")
		var path string
		if ph, ok := o["path"]; ok && ph != nil {
			if l, isList := ph.([]any); isList && len(l) > 0 {
				path = toStr(l[0])
			} else {
				path = toStr(ph)
			}
		} else {
			path = "/"
		}
		method := data.Str(o, "method")
		if method == "" {
			method = "GET"
		}
		t := map[string]any{"type": "http", "path": path, "method": method}
		if hosts, ok := data.Map(o, "headers")["Host"]; ok && hosts != nil {
			var hl []any
			for _, x := range toStrList(hosts) {
				hl = append(hl, x)
			}
			t["host"] = hl
		}
		return t, nil
	case "tcp", "":
		return nil, nil
	}
	return nil, fmt.Errorf("sing-box 不支持传输方式 %s", net_)
}

var mbpsRe = regexp.MustCompile(`\s*(\d+)`)

// mbps "10 Mbps" → 10
func mbps(v any) int {
	if v == nil {
		return 0
	}
	if m := mbpsRe.FindStringSubmatch(toStr(v)); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

// SbOutbound mihomo 风格节点 → sing-box outbound；不支持的协议返回 error
func SbOutbound(p map[string]any, tag string) (map[string]any, error) {
	if sb, ok := p["_sb"].(map[string]any); ok && sb != nil {
		o := copyMap(sb)
		o["tag"] = tag
		return o, nil
	}
	t := strings.ToLower(data.Str(p, "type"))
	o := map[string]any{"tag": tag, "server": data.Str(p, "server"), "server_port": toInt(p["port"])}
	if data.Str(o, "server") == "" || toInt(o["server_port"]) == 0 {
		return nil, fmt.Errorf("缺少服务器或端口")
	}
	switch t {
	case "ss":
		o["type"] = "shadowsocks"
		o["method"] = data.Str(p, "cipher")
		o["password"] = data.Str(p, "password")
		pl := data.Str(p, "plugin")
		po := data.Map(p, "plugin-opts")
		switch pl {
		case "obfs":
			mode := data.Str(po, "mode")
			if mode == "" {
				mode = "http"
			}
			host := data.Str(po, "host")
			if host == "" {
				host = "bing.com"
			}
			o["plugin"] = "obfs-local"
			o["plugin_opts"] = fmt.Sprintf("obfs=%s;obfs-host=%s", mode, host)
		case "v2ray-plugin":
			opts := []string{}
			mode := data.Str(po, "mode")
			if mode == "" {
				mode = "websocket"
			}
			opts = append(opts, "mode="+mode)
			if h := data.Str(po, "host"); h != "" {
				opts = append(opts, "host="+h)
			}
			if ph := data.Str(po, "path"); ph != "" {
				opts = append(opts, "path="+ph)
			}
			if data.Bool(po, "tls") {
				opts = append(opts, "tls")
			}
			o["plugin"] = "v2ray-plugin"
			o["plugin_opts"] = strings.Join(opts, ";")
		case "":
		default:
			return nil, fmt.Errorf("sing-box 不支持 ss 插件 %s", pl)
		}
		if data.Bool(p, "udp-over-tcp") {
			o["udp_over_tcp"] = true
		}
	case "vmess":
		o["type"] = "vmess"
		o["uuid"] = data.Str(p, "uuid")
		o["security"] = data.Str(p, "cipher")
		if o["security"] == "" {
			o["security"] = "auto"
		}
		o["alter_id"] = toInt(p["alterId"])
	case "vless":
		o["type"] = "vless"
		o["uuid"] = data.Str(p, "uuid")
		o["packet_encoding"] = "xudp"
		if f := data.Str(p, "flow"); f != "" {
			o["flow"] = f
		}
	case "trojan":
		o["type"] = "trojan"
		o["password"] = data.Str(p, "password")
		o["tls"] = sbTLS(p, "sni", true)
	case "hysteria2":
		o["type"] = "hysteria2"
		o["password"] = data.Str(p, "password")
		if ports := toStr(p["ports"]); ports != "" {
			var sp []any
			for _, x := range strings.Split(strings.ReplaceAll(ports, "/", ","), ",") {
				x = strings.TrimSpace(x)
				if x == "" {
					continue
				}
				if strings.Contains(x, "-") {
					sp = append(sp, strings.ReplaceAll(x, "-", ":"))
				} else {
					sp = append(sp, x+":"+x)
				}
			}
			o["server_ports"] = sp
		}
		if obfs := data.Str(p, "obfs"); obfs != "" {
			o["obfs"] = map[string]any{"type": obfs, "password": data.Str(p, "obfs-password")}
		}
		if mbps(p["up"]) != 0 {
			o["up_mbps"] = mbps(p["up"])
		}
		if mbps(p["down"]) != 0 {
			o["down_mbps"] = mbps(p["down"])
		}
		o["tls"] = sbTLS(p, "sni", true)
	case "tuic":
		o["type"] = "tuic"
		o["uuid"] = data.Str(p, "uuid")
		o["password"] = data.Str(p, "password")
		o["congestion_control"] = data.Str(p, "congestion-controller")
		if o["congestion_control"] == "" {
			o["congestion_control"] = "bbr"
		}
		o["udp_relay_mode"] = data.Str(p, "udp-relay-mode")
		if o["udp_relay_mode"] == "" {
			o["udp_relay_mode"] = "native"
		}
		if data.Bool(p, "reduce-rtt") {
			o["zero_rtt_handshake"] = true
		}
		cp := copyMap(p)
		if !isTruthy(p["alpn"]) {
			cp["alpn"] = []any{"h3"}
		}
		o["tls"] = sbTLS(cp, "sni", true)
	case "hysteria":
		o["type"] = "hysteria"
		up, down := mbps(p["up"]), mbps(p["down"])
		if up == 0 {
			up = 10
		}
		if down == 0 {
			down = 50
		}
		o["up_mbps"] = up
		o["down_mbps"] = down
		if a := data.Str(p, "auth-str"); a != "" {
			o["auth_str"] = a
		} else if a := data.Str(p, "auth_str"); a != "" {
			o["auth_str"] = a
		}
		if obfs := data.Str(p, "obfs"); obfs != "" {
			o["obfs"] = obfs
		}
		o["tls"] = sbTLS(p, "sni", true)
	case "anytls":
		o["type"] = "anytls"
		o["password"] = data.Str(p, "password")
		o["tls"] = sbTLS(p, "sni", true)
	case "http", "socks5":
		if t == "http" {
			o["type"] = "http"
		} else {
			o["type"] = "socks"
			o["version"] = "5"
		}
		if u := data.Str(p, "username"); u != "" {
			o["username"] = u
			o["password"] = data.Str(p, "password")
		}
	case "ssh":
		o["type"] = "ssh"
		o["user"] = data.Str(p, "username")
		if o["user"] == "" {
			o["user"] = "root"
		}
		if pw := data.Str(p, "password"); pw != "" {
			o["password"] = pw
		}
		if pk := data.Str(p, "private-key"); pk != "" {
			o["private_key"] = pk
		}
	default:
		name := t
		if name == "" {
			name = "未知"
		}
		return nil, fmt.Errorf("sing-box 不支持 %s 协议", name)
	}
	if t == "vmess" || t == "vless" || t == "http" || t == "socks5" {
		if tls := sbTLS(p, "servername", false); tls != nil {
			o["tls"] = tls
		}
	}
	if t == "vmess" || t == "vless" || t == "trojan" {
		tr, err := sbTransport(p)
		if err != nil {
			return nil, err
		}
		if tr != nil {
			o["transport"] = tr
		}
	}
	if o["tls"] == nil {
		delete(o, "tls")
	}
	if v, ok := p["udp"]; ok && v == false && t == "ss" {
		o["network"] = "tcp"
	}
	return o, nil
}
