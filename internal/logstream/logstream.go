// Package logstream 对应 Python shunt/logstream.py：实时日志 (SSE)。
// 以原始 socket 读取 mihomo 的 chunked JSON 行流，逐行回调。
package logstream

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"shunt/internal/base"
	"shunt/internal/data"
)

var (
	ticketsMu sync.Mutex
	// TICKETS 日志流（EventSource 无法带请求头）用的一次性票据
	TICKETS = map[string]int64{}
)

// Stop 对应 core_stream 的 stop 字典：置位即结束流；Sock 供调用方提前关闭连接。
type Stop struct {
	mu   sync.Mutex
	Stop bool
	Sock net.Conn
}

// Stopped 是否已被置位。
func (s *Stop) Stopped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Stop
}

// MarkStop 置位停止标志。
func (s *Stop) MarkStop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Stop = true
}

// Shutdown 关闭底层的 socket（对应 Python 的 sock.shutdown(SHUT_RDWR)），让阻塞的读取立即返回。
func (s *Stop) Shutdown() {
	s.mu.Lock()
	c := s.Sock
	s.mu.Unlock()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseRead()
		_ = tc.CloseWrite()
	}
}

// CoreStream 对应 core_stream(path, sink, stop, idle)：
// 以原始 socket 读取 mihomo 的 chunked JSON 行流，逐行回调 sink；stop 被置位或连接断开时结束。
// idle：超过该秒数没有数据视为断线（/traffic /memory 每秒推送，可用来发现半开连接）。
func CoreStream(path string, sink func(string), stop *Stop, idle time.Duration) error {
	d := data.Load()
	secret := data.Str(d, "secret")
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", base.CtrlHost, base.CtrlPort), 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop.mu.Lock()
	stop.Sock = conn
	stop.mu.Unlock()
	if idle > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(idle))
	}
	_, err = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n",
		path, base.CtrlHost, secret)
	if err != nil {
		return err
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	chunked := false
	for {
		h, err := br.ReadString('\n')
		if err != nil || h == "\r\n" || h == "\n" || h == "" {
			break
		}
		lh := strings.ToLower(h)
		if strings.HasPrefix(lh, "transfer-encoding:") && strings.Contains(lh, "chunked") {
			chunked = true
		}
	}
	if !strings.Contains(status, " 200") {
		return fmt.Errorf("mihomo 返回 %s", strings.TrimSpace(status))
	}
	var buf []byte
	for !stop.Stopped() {
		if idle > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(idle))
		}
		var data []byte
		if chunked {
			sizeLine, err := br.ReadString('\n')
			if err != nil || sizeLine == "" {
				break
			}
			sizeStr := strings.TrimSpace(strings.SplitN(sizeLine, ";", 2)[0])
			size, err := strconv.ParseInt(sizeStr, 16, 64)
			if err != nil || size == 0 {
				break
			}
			data = make([]byte, size)
			n := 0
			for n < int(size) {
				m, err := br.Read(data[n:])
				n += m
				if err != nil {
					break
				}
			}
			if n != int(size) {
				break
			}
			_, _ = br.ReadString('\n') // chunk 末尾的 CRLF
		} else {
			line, err := br.ReadString('\n')
			if err != nil || line == "" {
				break
			}
			data = []byte(line)
		}
		buf = append(buf, data...)
		for {
			i := bytes.IndexByte(buf, '\n')
			if i < 0 {
				break
			}
			line := buf[:i]
			buf = buf[i+1:]
			if len(bytes.TrimSpace(line)) > 0 {
				sink(string(line))
			}
		}
	}
	return nil
}

// TicketNew 对应 ticket_new()：一次性票据，60 秒有效。
func TicketNew() string {
	now := time.Now().Unix()
	ticketsMu.Lock()
	defer ticketsMu.Unlock()
	for k, v := range TICKETS {
		if v <= now {
			delete(TICKETS, k)
		}
	}
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	t := base64.RawURLEncoding.EncodeToString(b) // 对应 secrets.token_urlsafe(18)
	TICKETS[t] = now + 60
	return t
}

// TicketUse 对应 ticket_use(t)：票据一次性有效，过期返回 false。
func TicketUse(t string) bool {
	ticketsMu.Lock()
	defer ticketsMu.Unlock()
	exp, ok := TICKETS[t]
	delete(TICKETS, t)
	return ok && exp > time.Now().Unix()
}
