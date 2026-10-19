package logclean

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrimLog(t *testing.T) {
	p := filepath.Join(t.TempDir(), "test.log")
	var sb strings.Builder
	for i := 0; i < 500; i++ {
		sb.WriteString(strings.Repeat("x", 50) + "\n")
	}
	orig := sb.String()
	if err := os.WriteFile(p, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	freed := TrimLog(p, 200)
	if freed <= 0 {
		t.Fatalf("freed = %d, want > 0", freed)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 200 {
		t.Fatalf("kept %d lines, want 200", len(lines))
	}
	// 保留的应是最后 200 行
	origLines := strings.Split(strings.TrimRight(orig, "\n"), "\n")
	if lines[0] != origLines[300] || lines[199] != origLines[499] {
		t.Fatal("kept wrong lines")
	}
}

func TestTrimLogMissing(t *testing.T) {
	if got := TrimLog(filepath.Join(t.TempDir(), "nope.log"), 200); got != 0 {
		t.Fatalf("got %d", got)
	}
}

func TestLogSizes(t *testing.T) {
	sizes := LogSizes()
	if len(sizes) == 0 {
		t.Fatal("no log files listed")
	}
	for _, s := range sizes {
		if s.Path == "" {
			t.Fatal("empty path")
		}
	}
}

func TestLogCleanUpdatesState(t *testing.T) {
	before, _ := LogState()
	freed := LogClean(false) // 不强制：真实日志文件一般未超限
	_ = freed
	after, _ := LogState()
	if after < before {
		t.Fatal("last should be updated")
	}
	if after == 0 {
		t.Fatal("last should be set")
	}
}
