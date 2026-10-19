// Package corehttp 对应 Python shunt/corehttp.py：核心控制器 HTTP（叶子模块），
// 与 mihomo/sing-box 控制器 API 对话。只依赖 base、data，无环。
package corehttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"shunt/internal/base"
	"shunt/internal/data"
)

var (
	secretMu   sync.Mutex
	secretOK   bool
	secretMT   int64
	secretSize int64
	secretVal  string
)

// CtrlSecret 对应 ctrl_secret()：控制器密钥按 data.json 修改时间缓存，
// 每秒的实时请求不再反复读取解析整份配置。
func CtrlSecret() string {
	secretMu.Lock()
	defer secretMu.Unlock()
	var mt, size int64
	statOK := false
	if st, err := os.Stat(base.DataFile); err == nil {
		mt, size, statOK = st.ModTime().UnixNano(), st.Size(), true
	}
	if !statOK || !secretOK || secretMT != mt || secretSize != size {
		d := data.Load()
		secretVal = data.Str(d, "secret")
		secretMT, secretSize, secretOK = mt, size, true
	}
	return secretVal
}

// directClient 访问本机控制器绝不走系统代理（对应 DIRECT_OPENER）。
func directClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: &http.Transport{Proxy: nil},
		Timeout:   timeout,
	}
}

// Core 对应 core(method, path, body, timeout)：调用核心控制器 API，返回 (状态码, 响应体)。
// 全节点测速（GET /group/*/delay）期间登记 mass 测试，看门狗暂停判定。
func Core(method, path string, body any, timeoutSec int) (int, []byte) {
	if timeoutSec <= 0 {
		timeoutSec = 10
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 502, errorBody(fmt.Sprintf("mihomo 未运行或无法连接: %v", err))
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, base.Ctrl+path, rdr)
	if err != nil {
		return 502, errorBody(fmt.Sprintf("mihomo 未运行或无法连接: %v", err))
	}
	req.Header.Set("Authorization", "Bearer "+CtrlSecret())
	req.Header.Set("Content-Type", "application/json")
	mass := method == "GET" && strings.Contains(path, "/group/") && strings.Contains(path, "/delay")
	var tok any
	if mass {
		tok = base.MassBegin()
	}
	defer func() {
		if tok != nil {
			base.MassEnd(tok)
		}
	}()
	resp, err := directClient(time.Duration(timeoutSec) * time.Second).Do(req)
	if err != nil {
		// 对应 urllib HTTPError → (e.code, e.read()) 与其他异常 → 502
		return 502, errorBody(fmt.Sprintf("mihomo 未运行或无法连接: %v", err))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func errorBody(msg string) []byte {
	b, _ := json.Marshal(map[string]string{"message": msg})
	return b
}

// CoreJSON 对应 core_json(path, timeout)：GET 并解析 JSON，非 200 或解析失败返回 nil。
func CoreJSON(path string, timeoutSec int) map[string]any {
	code, raw := Core("GET", path, nil, timeoutSec)
	if code != 200 {
		return nil
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	return v
}
