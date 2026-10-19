// Package webapi 对应 Python shunt/webapi.py：HTTP 路由框架与 API 处理器。
package webapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"shunt/internal/base"
)

// Ctx 单个请求上下文
type Ctx struct {
	W     http.ResponseWriter
	R     *http.Request
	Path  string
	Query url.Values
	Body  map[string]any // JSON 请求体（GET 为空 map）
}

// Handler API 处理器：返回 (HTTP 状态码, 响应对象序列化为 JSON)
type Handler func(*Ctx) (int, any)

var routes = map[[2]string]Handler{}

// Route 注册路由
func Route(method, path string, h Handler) {
	routes[[2]string{method, path}] = h
}

// Send 写 JSON 响应
func (c *Ctx) Send(code int, obj any) (int, any) {
	return code, obj
}

// Reply 快捷：ok→200，否则→500，body {"message": msg}
func (c *Ctx) Reply(ok bool, msg string) (int, any) {
	if ok {
		return 200, map[string]any{"message": msg}
	}
	return 500, map[string]any{"message": msg}
}

// Deny 403 拒绝
func (c *Ctx) Deny(why string) (int, any) {
	return 403, map[string]any{"message": why}
}

// BodyStr/BodyInt 等请求体取值助手
func (c *Ctx) BodyStr(key string) string {
	s, _ := c.Body[key].(string)
	return s
}

func (c *Ctx) BodyList(key string) []any {
	l, _ := c.Body[key].([]any)
	return l
}

func (c *Ctx) BodyMap(key string) map[string]any {
	m, _ := c.Body[key].(map[string]any)
	return m
}

// Q1 取 query 参数（对应 links.q1）
func Q1(q url.Values, key string, def ...string) string {
	if v := q.Get(key); v != "" {
		return v
	}
	if len(def) > 0 {
		return def[0]
	}
	return ""
}

func writeJSON(w http.ResponseWriter, code int, obj any) {
	// RawBody：原始字节响应（文件下载 / 核心透传），不经过 JSON 序列化
	if rb, ok := obj.(RawBody); ok {
		ctype := rb.CType
		if ctype == "" {
			ctype = "application/octet-stream"
		}
		w.Header().Set("Content-Type", ctype)
		w.WriteHeader(code)
		_, _ = w.Write(rb.Body)
		return
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		raw = []byte(`{"message":"内部错误"}`)
		code = 500
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write(raw)
}

func readBody(r *http.Request) (map[string]any, bool) {
	body := map[string]any{}
	if r.Body == nil {
		return body, true
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, base.MaxBody+1))
	if err != nil {
		return nil, false
	}
	if len(raw) == 0 {
		return body, true
	}
	// 可能是 JSON 数组（少数接口），统一包一层
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, false
	}
	switch t := v.(type) {
	case map[string]any:
		return t, true
	case []any:
		return map[string]any{"_list": t}, true
	default:
		return body, true
	}
}

func hasShuntHeader(r *http.Request) bool {
	h := r.Header
	return h.Get("X-Shunt") != "" || h.Get("X-Token") != ""
}

// guard 访问控制：返回非空字符串表示拒绝原因
func guard(r *http.Request, m, p string, remoteIP string) string {
	if !isLanIP(remoteIP) {
		return "面板仅允许局域网访问（没有密码）。在路由器上执行：shunt --allow-public on（面板没有密码，请自行做好防护）"
	}
	host := r.Host
	if !hostOk(host) {
		h := hostName(host)
		return "域名 " + h + " 不在允许列表（防止 DNS 重绑定攻击）。用 IP 访问，或在路由器上执行：shunt --allow-host " + h
	}
	if m != "GET" && m != "HEAD" && strings.HasPrefix(p, "/api/") {
		if origin := r.Header.Get("Origin"); origin != "" && origin != "null" {
			if u, err := url.Parse(origin); err == nil {
				if !strings.EqualFold(u.Host, host) {
					return "跨站请求已拒绝"
				}
			}
		}
		if !hasShuntHeader(r) {
			return "缺少 X-Shunt 请求头，跨站请求已拒绝（脚本调用接口请加上 -H 'X-Shunt: 1'）"
		}
	}
	if (m == "GET" || m == "HEAD") && sensitiveGet[p] {
		if !hasShuntHeader(r) {
			return "缺少 X-Shunt 请求头，机密接口拒绝访问（脚本调用请加上 -H 'X-Shunt: 1'）"
		}
	}
	return ""
}

var sensitiveGet = map[string]bool{
	"/api/backup":      true,
	"/api/backup/list": true,
	"/api/config":      true,
	"/api/history":     true,
}
