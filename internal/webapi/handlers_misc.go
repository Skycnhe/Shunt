package webapi

// handlers_misc.go：杂项路由（/api/logticket + /api/logstream 的 SSE 实现）。

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"shunt/internal/data"
	"shunt/internal/logstream"
	"shunt/internal/singbox"
)

func registerMiscRoutes() {
	Route("POST", "/api/logticket", hLogticketPost)
}

// POST /api/logticket：EventSource 无法带自定义头，用一次性票据换日志流
func hLogticketPost(c *Ctx) (int, any) {
	return 200, map[string]any{"ticket": logstream.TicketNew()}
}

func sseJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return `{"type":"error","payload":"内部错误"}`
	}
	return string(raw)
}

func isConnRefused(err error) bool {
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		return false
	}
	var sysErr *os.SyscallError
	if errors.As(opErr.Err, &sysErr) {
		return sysErr.Err == syscall.ECONNREFUSED
	}
	return false
}

// ServeLogstreamSSE 对应 Python 的 logstream(level)：SSE 实时日志流。
// 由 server.go 在票据校验通过后直接调用，绕过 JSON 响应框架，直接写 w。
func ServeLogstreamSSE(w http.ResponseWriter, r *http.Request) {
	level := Q1(r.URL.Query(), "level", "info")
	switch level {
	case "debug", "info", "warning", "error":
	default:
		level = "info"
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	fl, _ := w.(http.Flusher)
	flush := func() {
		if fl != nil {
			fl.Flush()
		}
	}

	ch := make(chan string, 64)
	send := func(s string) {
		select {
		case ch <- s:
		default: // 客户端已断开：丢弃，避免 reader 协程泄漏
		}
	}
	stop := &logstream.Stop{}
	cname := singbox.Cores[singbox.ActiveCore(data.Load())]
	if cname == "" {
		cname = "mihomo"
	}

	go func() {
		defer send("@@END@@")
		err := logstream.CoreStream("/logs?level="+level, send, stop, 0)
		if stop.Stopped() {
			return // 客户端已断开，不再推送结束提示
		}
		switch {
		case err == nil:
			send(sseJSON(map[string]any{"type": "warning",
				"payload": fmt.Sprintf("日志流已结束（%s 可能已重启），正在重连…", cname)}))
		case isConnRefused(err): // 核心进程不在（重启中 / 已停止 / 崩溃）：控制端口没人监听
			send(sseJSON(map[string]any{"type": "warning",
				"payload": fmt.Sprintf("%s 内核未运行或正在重启，等待恢复…", cname), "retry": 1}))
		default:
			send(sseJSON(map[string]any{"type": "error",
				"payload": fmt.Sprintf("无法连接 %s 日志流：%s", cname, err)}))
		}
	}()

	defer func() {
		stop.MarkStop()
		stop.Shutdown()
	}()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case line := <-ch:
			if line == "@@END@@" {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", line)
			flush()
		case <-ticker.C:
			fmt.Fprint(w, ": ping\n\n") // 心跳，同时探测浏览器是否断开
			flush()
		}
	}
}
