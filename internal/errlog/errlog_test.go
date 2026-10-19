package errlog

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogErrDedup(t *testing.T) {
	mu.Lock()
	errs = nil
	errSeen = map[[2]string]int64{}
	mu.Unlock()
	LogErr("test", errors.New("boom"), false)
	LogErr("test", errors.New("boom"), false) // 10 分钟内去重
	if got := len(Errs()); got != 1 {
		t.Fatalf("dedup failed, got %d records", got)
	}
	e := Errs()[0]
	if e["where"] != "test" {
		t.Fatalf("where = %v", e["where"])
	}
	if !strings.Contains(e["msg"].(string), "boom") {
		t.Fatalf("msg = %v", e["msg"])
	}
	if _, ok := e["t"].(int64); !ok {
		t.Fatalf("t not int64: %T", e["t"])
	}
}

func TestLogErrNonError(t *testing.T) {
	mu.Lock()
	errs = nil
	errSeen = map[[2]string]int64{}
	mu.Unlock()
	LogErr("plain", "只是一个字符串", false) // 对应 Python 传非异常的用法
	if got := len(Errs()); got != 1 {
		t.Fatalf("got %d records", got)
	}
	if Errs()[0]["msg"] != "只是一个字符串" {
		t.Fatalf("msg = %v", Errs()[0]["msg"])
	}
}

func TestLogErrMaxLen(t *testing.T) {
	mu.Lock()
	errs = nil
	errSeen = map[[2]string]int64{}
	mu.Unlock()
	for i := 0; i < MaxErrs+10; i++ {
		// 差异放在前 300 字符内，避免被截断后去重
		LogErr("flood", errors.New(fmt.Sprintf("err-%03d ", i)+strings.Repeat("x", 400)), false)
	}
	if got := len(Errs()); got != MaxErrs {
		t.Fatalf("maxlen: got %d", got)
	}
	if n := len([]rune(Errs()[0]["msg"].(string))); n > msgMax {
		t.Fatalf("msg not truncated: %d runes", n)
	}
}

func TestLogTail(t *testing.T) {
	if LogTail(filepath.Join(t.TempDir(), "nope.log")) != nil {
		t.Fatal("missing file should return nil")
	}
	p := filepath.Join(t.TempDir(), "a.log")
	content := "line1\nline2\nline3\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got := LogTail(p)
	if len(got) != 3 || got[0] != "line1" || got[2] != "line3" {
		t.Fatalf("got %q", got)
	}
	// 大文件只读末尾
	big := strings.Repeat("x\n", 20000)
	if err := os.WriteFile(p, []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	got = LogTail(p)
	if len(got) == 20000 {
		t.Fatal("should only read the tail")
	}
	_ = time.Now()
}
