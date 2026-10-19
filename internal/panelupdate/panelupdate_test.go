package panelupdate

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"shunt/internal/base"
)

func TestGitBlobSHA(t *testing.T) {
	// git hash-object 验证过的向量："hello world\n" → 3b18e512dba79e4c8300dd08aeb37f8e728b8dad
	if got := GitBlobSHA([]byte("hello world\n")); got != "3b18e512dba79e4c8300dd08aeb37f8e728b8dad" {
		t.Fatalf("GitBlobSHA = %s", got)
	}
	// 空内容：sha1("blob 0\x00") = e69de29bb2d1d6434b8b29ae775ad8c2e48c5391
	if got := GitBlobSHA(nil); got != "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391" {
		t.Fatalf("GitBlobSHA(nil) = %s", got)
	}
}

func TestRemoteVersion(t *testing.T) {
	src := []byte("#!/usr/bin/env python3\nPANEL_VERSION = \"10.2.7\"\n")
	if got := RemoteVersion(src); got != "10.2.7" {
		t.Fatalf("RemoteVersion = %q", got)
	}
	if got := RemoteVersion([]byte("no version here")); got != "?" {
		t.Fatalf("无版本号时应返回 ?，得到 %q", got)
	}
	// 只匹配行首（multiline）
	src2 := []byte("x = 'PANEL_VERSION = \"9.9.9\"'\nPANEL_VERSION = \"8.8.8\"\n")
	if got := RemoteVersion(src2); got != "8.8.8" {
		t.Fatalf("应匹配行首的定义，得到 %q", got)
	}
}

func TestParseFileList(t *testing.T) {
	shas := map[string]string{
		"server.py": "aaa", "index.html": "bbb", "tproxy.sh": "ccc",
		"init.d/shunt": "ddd", UpdList: "eee",
	}
	raw := "# 注释行\nserver.py\nindex.html  # 行尾注释\ntproxy.sh\ninit.d/shunt\n\n"
	got, err := parseFileList(raw, shas)
	if err != nil {
		t.Fatalf("parseFileList 失败: %v", err)
	}
	want := []string{"server.py", "index.html", "tproxy.sh", "init.d/shunt"}
	if !slices.Equal(got, want) {
		t.Fatalf("parseFileList = %v, want %v", got, want)
	}

	// 路径穿越
	if _, err := parseFileList("server.py\n../evil.sh\nindex.html", shas); err == nil {
		t.Fatal("../ 应被拒绝")
	}
	// 以点开头
	if _, err := parseFileList("server.py\n.hidden\nindex.html", shas); err == nil {
		t.Fatal("以 . 开头的路径应被拒绝")
	}
	// 清单里的文件在仓库中不存在
	if _, err := parseFileList("server.py\nnope.py\nindex.html", shas); err == nil {
		t.Fatal("仓库中不存在的文件应被拒绝")
	}
	// 缺少 server.py
	if _, err := parseFileList("index.html\ntproxy.sh", shas); err == nil {
		t.Fatal("缺少 server.py 应被拒绝")
	}
	// 缺少 index.html
	if _, err := parseFileList("server.py\ntproxy.sh", shas); err == nil {
		t.Fatal("缺少 index.html 应被拒绝")
	}
	// 非法字符
	if _, err := parseFileList("server.py\nfoo;bar\nindex.html", shas); err == nil {
		t.Fatal("非法字符应被拒绝")
	}
}

func TestRemoteFileListFallback(t *testing.T) {
	// 无校验值 → 内置清单的拷贝
	got, err := RemoteFileList("", "", nil)
	if err != nil {
		t.Fatalf("RemoteFileList 失败: %v", err)
	}
	if !slices.Equal(got, UpdFiles) {
		t.Fatalf("回退清单不一致: %v", got)
	}
	got[0] = "MUTATED"
	if UpdFiles[0] == "MUTATED" {
		t.Fatal("返回的应是拷贝，修改不应影响 UpdFiles")
	}
	// 清单文件不在 shas 中 → 内置清单
	got2, err := RemoteFileList("", "deadbeef", map[string]string{"server.py": "x"})
	if err != nil {
		t.Fatalf("RemoteFileList 失败: %v", err)
	}
	if !slices.Equal(got2, UpdFiles) {
		t.Fatalf("回退清单不一致: %v", got2)
	}
}

// TestUndoReplace 验证替换失败后的恢复逻辑：
// bak 中有旧版的文件 → 恢复旧版；bak 中没有（新增文件）→ 删掉。
func TestUndoReplace(t *testing.T) {
	dir := t.TempDir()
	oldBase := base.Base
	base.Base = dir
	defer func() { base.Base = oldBase }()

	bak := filepath.Join(dir, ".backup")
	os.MkdirAll(bak, 0o755)
	// f1：新增文件（bak 里没有）→ 应被删除
	f1 := filepath.Join(dir, "newfile.txt")
	os.WriteFile(f1, []byte("new"), 0o644)
	// f2：已有文件（bak 里有旧版）→ 应恢复旧版
	f2 := filepath.Join(dir, "server.py")
	os.WriteFile(f2, []byte("broken-new"), 0o644)
	os.WriteFile(filepath.Join(bak, "server.py"), []byte("old-good"), 0o644)

	undoReplace([]string{"newfile.txt", "server.py"}, bak)

	if _, err := os.Stat(f1); !os.IsNotExist(err) {
		t.Fatal("新增文件 newfile.txt 应被删除")
	}
	content, err := os.ReadFile(f2)
	if err != nil || string(content) != "old-good" {
		t.Fatalf("server.py 应恢复旧版，得到 %q (err=%v)", content, err)
	}
}

// TestSelfRollbackNoBackup 无 .backup/server.py 时直接返回失败，不碰忙标志。
func TestSelfRollbackNoBackup(t *testing.T) {
	dir := t.TempDir()
	oldBase := base.Base
	base.Base = dir
	defer func() { base.Base = oldBase }()

	ok, msg := SelfRollback()
	if ok {
		t.Fatal("无备份时应返回失败")
	}
	if msg != "没有可回滚的备份" {
		t.Fatalf("msg = %q", msg)
	}
}

// TestSelfUpdateBusy 忙标志被占用时 apply=true 应直接拒绝。
func TestSelfUpdateBusy(t *testing.T) {
	if !base.UpdBegin("panel") {
		t.Skip("panel 忙标志已被占用，跳过")
	}
	defer base.UpdEnd("panel")
	ok, info := SelfUpdate(true, "")
	if ok {
		t.Fatal("忙时应返回失败")
	}
	if info["message"] != base.UpdBusyMsg() {
		t.Fatalf("message = %v", info["message"])
	}
}

func TestTruncateTailStr(t *testing.T) {
	if truncate("abcdef", 4) != "abcd" || truncate("中文测试", 2) != "中文" {
		t.Fatal("truncate 失败")
	}
	if tailStr("abcdef", 2) != "ef" || tailStr("短", 10) != "短" {
		t.Fatal("tailStr 失败")
	}
	if truncate("commitsha1234567890", 10) != "commitsha1" {
		t.Fatal("commit 截断失败")
	}
}

func TestShellQuote(t *testing.T) {
	if shellQuote("/tmp/a.sh") != "/tmp/a.sh" {
		t.Fatal("安全路径不应加引号")
	}
	if q := shellQuote("/tmp/a b.sh"); q != "'/tmp/a b.sh'" {
		t.Fatalf("引号错误: %s", q)
	}
}
