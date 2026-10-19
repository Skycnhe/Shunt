package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shunt/internal/base"
)

func setupTest(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	oldBase, oldData, oldDir := base.Base, base.DataFile, BackupDir
	base.Base = filepath.Join(dir, "panel")
	base.DataFile = filepath.Join(dir, "data", "data.json")
	BackupDir = filepath.Join(dir, "data", "backups")
	t.Cleanup(func() { base.Base, base.DataFile, BackupDir = oldBase, oldData, oldDir })
	if err := os.MkdirAll(base.Base, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"server.py", "index.html", "CHANGELOG.md"} {
		if err := os.WriteFile(filepath.Join(base.Base, f), []byte("v1-"+f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(base.DataFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base.DataFile, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, base.Base
}

func TestParseName(t *testing.T) {
	if ParseName("shunt-backup-v10.2.7-20261019-120000.tar.gz") != "10.2.7" {
		t.Fatal("version parse")
	}
	if ParseName("shunt-backup-v10.2.7-20261019-120000-2.tar.gz") != "10.2.7" {
		t.Fatal("version parse with suffix")
	}
	if ParseName("random.tar.gz") != "" || ParseName("../x.tar.gz") != "" {
		t.Fatal("invalid names should return empty")
	}
}

func TestCreateListDelete(t *testing.T) {
	setupTest(t)
	ok, name := Create("10.2.7", "")
	if !ok {
		t.Fatalf("create failed: %s", name)
	}
	if !strings.HasPrefix(name, "shunt-backup-v10.2.7-") || !strings.HasSuffix(name, ".tar.gz") {
		t.Fatalf("bad name: %s", name)
	}
	st, _ := os.Stat(filepath.Join(BackupDir, name))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("backup should be 600, got %o", st.Mode().Perm())
	}
	lst := List()
	if len(lst) != 1 || lst[0].Name != name || lst[0].Version != "10.2.7" {
		t.Fatalf("list: %+v", lst)
	}
	ok, msg := Delete(name)
	if !ok {
		t.Fatalf("delete failed: %s", msg)
	}
	if len(List()) != 0 {
		t.Fatal("list should be empty after delete")
	}
	// 非法文件名拒绝
	if ok, _ := Delete("../evil.tar.gz"); ok {
		t.Fatal("path traversal should be rejected")
	}
	if ok, msg := Delete("shunt-backup-v1-20261019-120000.tar.gz"); ok || msg != "备份不存在" {
		t.Fatalf("missing backup: %v %s", ok, msg)
	}
}

func TestCreateVersionSanitize(t *testing.T) {
	setupTest(t)
	ok, name := Create("1.0/beta:2", "")
	if !ok {
		t.Fatalf("create: %s", name)
	}
	if strings.ContainsAny(name, "/:") {
		t.Fatalf("unsafe chars in name: %s", name)
	}
	if ParseName(name) != "1.0_beta_2" {
		t.Fatalf("sanitized version: %s", name)
	}
}

func TestCleanupKeepsN(t *testing.T) {
	setupTest(t)
	for i := 0; i < 12; i++ {
		if ok, _ := Create("9.9.9", ""); !ok {
			t.Fatal("create failed")
		}
	}
	// 同一秒冲突会加后缀，保证 12 个都能建出来
	if len(List()) != KeepN {
		t.Fatalf("should keep %d, got %d", KeepN, len(List()))
	}
}

func TestRestore(t *testing.T) {
	setupTest(t)
	ok, name := Create("10.2.7", "")
	if !ok {
		t.Fatalf("create: %s", name)
	}
	// 改掉当前文件再恢复
	os.WriteFile(filepath.Join(base.Base, "server.py"), []byte("v2-changed"), 0o644)
	os.WriteFile(base.DataFile, []byte(`{"a":2}`), 0o600)
	ok, msg := Restore(name)
	if !ok {
		t.Fatalf("restore failed: %s", msg)
	}
	b, _ := os.ReadFile(filepath.Join(base.Base, "server.py"))
	if string(b) != "v1-server.py" {
		t.Fatalf("server.py not restored: %q", b)
	}
	b, _ = os.ReadFile(base.DataFile)
	if string(b) != `{"a":1}` {
		t.Fatalf("data.json not restored: %q", b)
	}
	st, _ := os.Stat(base.DataFile)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("data.json should be 600, got %o", st.Mode().Perm())
	}
	// 恢复时自动备份了当前版本：至少 2 个备份
	if len(List()) < 2 {
		t.Fatalf("auto-backup missing: %+v", List())
	}
	if ok, _ := Restore("../evil.tar.gz"); ok {
		t.Fatal("restore should reject traversal")
	}
}
