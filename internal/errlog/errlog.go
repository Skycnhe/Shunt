// Package errlog 对应 Python shunt/errlog.py：
// 原本被吞掉的异常记到面板日志和「诊断」页；同一处同一错误 10 分钟只记一次。
package errlog

import (
	"fmt"
	"os"
	"reflect"
	"runtime/debug"
	"sync"
	"time"
)

const (
	// MaxErrs 对应 ERRS deque(maxlen=30)
	MaxErrs = 30
	// dedupSecs 同一 key 去重窗口（秒）
	dedupSecs = 600
	// maxSeen 去重表上限，超限清空
	maxSeen = 500
	// msgMax 错误消息截断长度（字符）
	msgMax = 300
	// tbMax 堆栈截取长度（字节）
	tbMax = 1500
	// tailBytes log_tail 默认读取的末尾字节数
	tailBytes = 16 * 1024
)

var (
	mu      sync.Mutex
	errs    []map[string]any
	errSeen = map[[2]string]int64{}
)

// Errs 返回最近的错误记录（新 → 旧），返回副本。
func Errs() []map[string]any {
	mu.Lock()
	defer mu.Unlock()
	out := make([]map[string]any, len(errs))
	copy(out, errs)
	return out
}

func errTypeName(err error) string {
	t := reflect.TypeOf(err)
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Name() != "" {
		return t.Name()
	}
	return t.String()
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

// LogErr 对应 log_err(where, e, tb)：把原本被吞掉的异常记到面板日志和「诊断」里。
// e 可为 error 或任意值（对应 Python 传非异常字符串的用法）。
func LogErr(where string, e any, tb bool) {
	var msg string
	if err, ok := e.(error); ok && err != nil {
		msg = truncateRunes(errTypeName(err)+": "+err.Error(), msgMax)
	} else if e != nil {
		msg = truncateRunes(fmt.Sprintf("%v", e), msgMax)
	}
	key := [2]string{where, msg}
	now := time.Now().Unix()
	mu.Lock()
	if now-errSeen[key] < dedupSecs {
		mu.Unlock()
		return
	}
	errSeen[key] = now
	if len(errSeen) > maxSeen {
		errSeen = map[[2]string]int64{}
	}
	errs = append([]map[string]any{{"t": now, "where": where, "msg": msg}}, errs...)
	if len(errs) > MaxErrs {
		errs = errs[:MaxErrs]
	}
	mu.Unlock()
	extra := ""
	if tb {
		if _, ok := e.(error); ok {
			st := string(debug.Stack())
			if len(st) > tbMax {
				st = st[len(st)-tbMax:]
			}
			extra = "\n" + st
		}
	}
	fmt.Printf("[error] %s: %s%s\n", where, msg, extra)
}

// LogTail 对应 log_tail(path)：读文件末尾 16KB，按行返回（用于从核心日志里找最近的错误）；读不了返回 nil。
func LogTail(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	off := st.Size() - tailBytes
	if off < 0 {
		off = 0
	}
	if _, err := f.Seek(off, 0); err != nil {
		return nil
	}
	buf := make([]byte, st.Size()-off)
	n := 0
	for n < len(buf) {
		m, err := f.Read(buf[n:])
		n += m
		if err != nil {
			break
		}
	}
	lines := []string{}
	for _, ln := range splitLines(string(buf[:n])) {
		lines = append(lines, ln)
	}
	return lines
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	} else if start == len(s) && len(s) > 0 {
		// 以换行结尾：Python splitlines() 不产生末尾空行
	}
	return out
}
