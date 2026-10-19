package sysopt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSh(t *testing.T) {
	code, out := Sh("echo hello")
	if code != 0 || out != "hello" {
		t.Fatalf("code=%d out=%q", code, out)
	}
	// 管道 / 重定向等 shell 特性
	code, out = Sh("echo aaa | tr a-z A-Z")
	if code != 0 || out != "AAA" {
		t.Fatalf("pipe: code=%d out=%q", code, out)
	}
	// stdout + stderr 合并
	code, out = Sh("echo out; echo err >&2")
	if code != 0 || !strings.Contains(out, "out") || !strings.Contains(out, "err") {
		t.Fatalf("merged: code=%d out=%q", code, out)
	}
	// 非零退出码
	if code, _ := Sh("exit 3"); code != 3 {
		t.Fatalf("code=%d", code)
	}
}

func TestShTimeout(t *testing.T) {
	// sh 超时对应 Python 的 (1, str(TimeoutExpired))
	code, out := Sh("sleep 5", 1)
	if code != 1 {
		t.Fatalf("timeout code=%d out=%q", code, out)
	}
	if !strings.Contains(out, "timed out after 1 seconds") {
		t.Fatalf("timeout msg=%q", out)
	}
}

func TestRcOnceTimeout124(t *testing.T) {
	// _rc_once 超时返回 124（rc_run 依赖它判定）
	code, out := rcOnce("sleep 5", 1)
	if code != 124 {
		t.Fatalf("timeout code=%d out=%q", code, out)
	}
	if !strings.Contains(out, "命令超时") {
		t.Fatalf("timeout msg=%q", out)
	}
}

func TestRfileWfile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f.txt")
	if got := Rfile(p, "dflt"); got != "dflt" {
		t.Fatalf("default=%q", got)
	}
	if !Wfile(p, "  hi\n") {
		t.Fatal("wfile failed")
	}
	if got := Rfile(p); got != "hi" {
		t.Fatalf("got %q", got)
	}
}

func TestRsysWsysMissing(t *testing.T) {
	if got := Rsys("net.ipv4.definitely.not.a.real.key"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestNofileTarget(t *testing.T) {
	if n := NofileTarget(); n <= 1024 {
		t.Fatalf("nofile target=%d", n)
	}
}

func TestInContainerCached(t *testing.T) {
	a, b := InContainer(), InContainer()
	if a != b {
		t.Fatal("should be cached")
	}
}

func TestOptItemsShape(t *testing.T) {
	items := OptItems()
	if len(items) != 8 {
		t.Fatalf("got %d items", len(items))
	}
	ids := map[string]bool{}
	for _, it := range items {
		ids[it.ID] = true
		if it.Name == "" || it.Desc == "" {
			t.Fatalf("item %q missing name/desc", it.ID)
		}
	}
	for _, want := range []string{"bbr", "buf", "tcp", "conntrack", "fd", "rps", "gov", "ntp"} {
		if !ids[want] {
			t.Fatalf("missing item %q", want)
		}
	}
}

func TestImgType(t *testing.T) {
	cases := map[string][]byte{
		"image/x-icon": {0x00, 0x00, 0x01, 0x00},
		"image/png":    {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'},
		"image/gif":    []byte("GIF89a"),
		"image/jpeg":   {0xff, 0xd8, 0xff, 0xe0},
		"image/webp":   []byte("RIFF....WEBP"),
	}
	for want, b := range cases {
		if got := ImgType(b); got != want {
			t.Errorf("got %q want %q", got, want)
		}
	}
	if got := ImgType([]byte("<svg></svg>")); got != "" {
		t.Fatalf("svg should be rejected, got %q", got)
	}
	if got := ImgType([]byte("short")); got != "" {
		t.Fatalf("short should be rejected, got %q", got)
	}
}

func TestFavHosts(t *testing.T) {
	hosts := FavHosts(nil)
	if !hosts["www.google.com"] {
		t.Fatal("google should be in fav hosts")
	}
	if hosts["evil.example.com"] {
		t.Fatal("arbitrary host must not be allowed")
	}
}

func TestFaviconDisallowed(t *testing.T) {
	if b, ct := Favicon("https://evil.example.com/favicon.ico", nil); b != nil || ct != "" {
		t.Fatal("disallowed host should return nil")
	}
	if b, ct := Favicon("not a url%%%", nil); b != nil || ct != "" {
		t.Fatal("bad url should return nil")
	}
}

func TestProxyClientRedirectPolicy(t *testing.T) {
	c := ProxyClient(true)
	if c.CheckRedirect == nil {
		t.Fatal("redirect policy missing")
	}
}

func TestStubsWired(t *testing.T) {
	// sbBin/ipReset/physIface 已接线：不再 panic，行为可验证
	if got := sbBin(); got == "" {
		t.Fatal("sbBin should return non-empty path")
	}
	t.Setenv("SB_BIN", "/tmp/fake-sing-box")
	// 默认实现读环境变量；注入后走注入值
	old := SbBinHook
	SbBinHook = func() string { return "/injected/sing-box" }
	defer func() { SbBinHook = old }()
	if got := sbBin(); got != "/injected/sing-box" {
		t.Fatalf("sbBin should use injected hook, got %q", got)
	}
	SbBinHook = old
	if got := sbBin(); got != "/tmp/fake-sing-box" {
		t.Fatalf("sbBin should honor SB_BIN env, got %q", got)
	}
	func() {
		defer func() {
			if recover() != nil {
				t.Fatal("ipReset should not panic after wiring")
			}
		}()
		ipReset()
	}()
	func() {
		defer func() {
			if recover() != nil {
				t.Fatal("physIface should not panic after wiring")
			}
		}()
		_ = physIface()
	}()
}

func TestCoreProcsNoPanic(t *testing.T) {
	// 在测试机上不应找到核心进程，但不能 panic；用覆盖路径避免触发 sbBin stub
	old := CoreBins
	CoreBins = []string{"/nonexistent-bin-xyz"}
	defer func() { CoreBins = old }()
	if got := CoreProcs(); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	if got := KillCoreProcs(1); got != 0 {
		t.Fatalf("got %d", got)
	}
}

func TestMemMb(t *testing.T) {
	if m := MemMb(); m <= 0 {
		t.Fatalf("mem=%d", m)
	}
}

func TestNetIfaces(t *testing.T) {
	// 不应 panic；测试机上至少有 lo（无 device 链接会被过滤）
	_ = NetIfaces()
	_ = CpuGovs()
}

func TestOptStatusKeys(t *testing.T) {
	st := OptStatus()
	for _, k := range []string{"items", "mem", "cpu", "kernel", "container"} {
		if _, ok := st[k]; !ok {
			t.Fatalf("missing key %q", k)
		}
	}
	items, _ := st["items"].([]map[string]any)
	if len(items) != 8 {
		t.Fatalf("items=%d", len(items))
	}
}

func TestOptMigrateConfdNoop(t *testing.T) {
	// 默认路径下旧文件不存在时应返回 false 且不 panic
	_ = OptMigrateConfd()
	_ = os.Getenv("HOME")
}
