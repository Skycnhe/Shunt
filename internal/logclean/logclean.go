// Package logclean 对应 Python shunt/logclean.py：日志自动清理。
package logclean

import (
	"fmt"
	"os"
	"sync"
	"time"

	"shunt/internal/base"
	"shunt/internal/data"
)

// trimKeep trim_log 默认保留的行数
const trimKeep = 200

// tailBytes 截断时从末尾向前读取的字节数
const tailBytes = 256 * 1024

var (
	stateMu  sync.Mutex
	lastTrim int64
	trimmed  []string
)

// LogState 返回清理状态（对应 LOG_STATE）。
func LogState() (int64, []string) {
	stateMu.Lock()
	defer stateMu.Unlock()
	cp := make([]string, len(trimmed))
	copy(cp, trimmed)
	return lastTrim, cp
}

// LogSize 单个日志文件的大小记录。
type LogSize struct {
	Path string
	Size int64 // -1 表示文件不存在
}

// LogSizes 对应 log_sizes()。
func LogSizes() []LogSize {
	out := make([]LogSize, 0, len(base.LogFiles))
	for _, p := range base.LogFiles {
		size := int64(-1)
		if st, err := os.Stat(p); err == nil {
			size = st.Size()
		}
		out = append(out, LogSize{Path: p, Size: size})
	}
	return out
}

// TrimLog 对应 trim_log(path, keep)：原地截断，只保留最后 keep 行。
// 写入方（OpenRC output_log）以 O_APPEND 打开，截断后会继续追加到新末尾。
// 返回释放的字节数，失败返回 0。
func TrimLog(path string, keep int) int64 {
	f, err := os.OpenFile(path, os.O_RDWR, 0o644)
	if err != nil {
		return 0
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0
	}
	size := st.Size()
	off := size - tailBytes
	if off < 0 {
		off = 0
	}
	if _, err := f.Seek(off, 0); err != nil {
		return 0
	}
	tail := make([]byte, size-off)
	n := 0
	for n < len(tail) {
		m, err := f.Read(tail[n:])
		n += m
		if err != nil {
			break
		}
	}
	lines := splitLinesKeep(tail[:n])
	if len(lines) > keep {
		lines = lines[len(lines)-keep:]
	}
	data := joinBytes(lines)
	if _, err := f.Seek(0, 0); err != nil {
		return 0
	}
	if _, err := f.Write(data); err != nil {
		return 0
	}
	if err := f.Truncate(int64(len(data))); err != nil {
		return 0
	}
	return size - int64(len(data))
}

func splitLinesKeep(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' {
			out = append(out, b[start:i+1])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

func joinBytes(parts [][]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// LogClean 对应 log_clean(force)：超过上限（log_limit MB，默认 5）的日志截断。返回释放的字节数。
func LogClean(force bool) int64 {
	d := data.Load()
	limit := data.Float(d, "log_limit")
	if limit == 0 {
		limit = 5
	}
	limit *= 1024 * 1024
	var freed int64
	for _, x := range LogSizes() {
		if x.Size > 0 && (force || float64(x.Size) > limit) {
			freed += TrimLog(x.Path, trimKeep)
		}
	}
	stateMu.Lock()
	lastTrim = time.Now().Unix()
	stateMu.Unlock()
	return freed
}

// LogLoop 对应 log_loop()：每分钟检查一次。
func LogLoop() {
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("log clean error %v\n", r)
				}
			}()
			if freed := LogClean(false); freed > 0 {
				fmt.Printf("%s [log] 日志超过上限，已截断释放 %d KB\n",
					time.Now().Format("2006-01-02 15:04:05"), freed/1024)
			}
		}()
		time.Sleep(60 * time.Second)
	}
}
