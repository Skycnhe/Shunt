package migrate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotSelectionsSkipped(t *testing.T) {
	dir := t.TempDir()
	old := SelFile
	SelFile = filepath.Join(dir, "selected.json")
	defer func() { SelFile = old }()
	// 文件已存在 → 返回 nil（skip）
	if err := os.WriteFile(SelFile, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := SnapshotSelections(false); got != nil {
		t.Fatalf("want nil, got %v", got)
	}
	// force 会覆盖（无控制器时 core_json 为 nil → 仍返回 nil）
	if got := SnapshotSelections(true); got != nil {
		t.Fatalf("want nil without controller, got %v", got)
	}
}

func TestRestoreSelectionsEmpty(t *testing.T) {
	dir := t.TempDir()
	old := SelFile
	SelFile = filepath.Join(dir, "selected.json")
	defer func() { SelFile = old }()
	if got := RestoreSelections(); got != 0 {
		t.Fatalf("got %d", got)
	}
}

func TestStubsWired(t *testing.T) {
	// activeCore 已接线到 singbox.ActiveCore，不再 panic
	if got := activeCore(nil); got != "mihomo" {
		t.Fatalf("activeCore(nil) = %q, want mihomo", got)
	}
	// reloadCore 已接线到 core.ReloadCore：测试环境无核心，返回失败但不抛 panic
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("reloadCore panicked: %v", r)
			}
		}()
		_, _ = reloadCore()
	}()
}
