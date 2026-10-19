package coreupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"shunt/internal/base"
)

func TestCoreArchFrom(t *testing.T) {
	cases := []struct {
		machine, cpuinfo, want string
	}{
		// x86_64：四 flags 齐全 → amd64-v3
		{"x86_64", "flags : fpu vme avx2 bmi2 fma movbe sse", "amd64-v3"},
		// 缺一个 → 兼容版
		{"x86_64", "flags : fpu vme avx2 bmi2 sse", "amd64-compatible"},
		// /proc/cpuinfo 不可读时传入空串 → 兼容版
		{"x86_64", "", "amd64-compatible"},
		{"aarch64", "", "arm64"},
		{"arm64", "", "arm64"},
		{"armv7l", "", "armv7"},
		{"armv8l", "", "armv7"},
		{"armv6l", "", "armv6"},
		{"i686", "", "386"},
		{"i386", "", "386"},
		{"riscv64", "", "riscv64"},
		{"loongarch64", "", "loong64-abi2"},
		{"mips", "", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		if got := coreArchFrom(c.machine, c.cpuinfo); got != c.want {
			t.Errorf("coreArchFrom(%q, %q) = %q, want %q", c.machine, c.cpuinfo, got, c.want)
		}
	}
}

func TestParseBinVersion(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Mihomo Meta v1.19.32 linux amd64 with go1.24.0", "v1.19.32"},
		{"Mihomo Meta alpha-9f053c4 linux arm64", "alpha-9f053c4"},
		{"", ""},
		{"something else entirely", ""},
		{"mihomo meta v1.0", ""}, // 大小写敏感：必须 "Mihomo Meta"
	}
	for _, c := range cases {
		if got := parseBinVersion(c.in); got != c.want {
			t.Errorf("parseBinVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGhRepoRe(t *testing.T) {
	m := ghRepoRe.FindStringSubmatch("https://github.com/MetaCubeX/mihomo/releases")
	if m == nil || m[1] != "MetaCubeX/mihomo" {
		t.Fatalf("ghRepoRe 提取失败: %v", m)
	}
	if ghRepoRe.MatchString("https://gitee.com/MetaCubeX/mihomo/releases") {
		t.Fatal("ghRepoRe 不应匹配非 github.com 地址")
	}
	if ghRepoRe.MatchString("https://github.com/only-one/releases") {
		t.Fatal("ghRepoRe 不应匹配缺少 owner/repo 的地址")
	}
}

func TestHashReader(t *testing.T) {
	src := "hello world, this is a test payload"
	var progSeen []float64
	hr := &hashReader{r: strings.NewReader(src), h: sha256.New(), prog: func(p float64) { progSeen = append(progSeen, p) }, total: int64(len(src))}
	buf := make([]byte, 7)
	var out []byte
	for {
		n, err := hr.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			break
		}
	}
	if string(out) != src {
		t.Fatalf("hashReader 透传数据不一致: %q", out)
	}
	sum := sha256.Sum256([]byte(src))
	if hr.sum() != hex.EncodeToString(sum[:]) {
		t.Fatalf("hashReader SHA256 不一致: %s", hr.sum())
	}
	if hr.n != int64(len(src)) {
		t.Fatalf("hashReader 计数 %d, want %d", hr.n, len(src))
	}
	if len(progSeen) == 0 || progSeen[len(progSeen)-1] != 1 {
		t.Fatalf("hashReader 进度回调异常: %v", progSeen)
	}
}

func TestCuLogPrependAndCap(t *testing.T) {
	base.CoreUpd.Lock()
	saved := base.CoreUpd.Log
	base.CoreUpd.Log = nil
	base.CoreUpd.Unlock()
	defer func() {
		base.CoreUpd.Lock()
		base.CoreUpd.Log = saved
		base.CoreUpd.Unlock()
	}()
	p := 42
	Cu("阶段一", &p, "第一条")
	Cu("阶段二", nil, "")
	base.CoreUpd.Lock()
	log := append([]string{}, base.CoreUpd.Log...)
	pct := base.CoreUpd.Pct
	stage := base.CoreUpd.Stage
	base.CoreUpd.Unlock()
	if len(log) != 2 {
		t.Fatalf("日志条数 %d, want 2", len(log))
	}
	if !strings.HasSuffix(log[0], " 阶段二") { // msg 为空时用 stage
		t.Fatalf("最新日志应在最前: %q", log[0])
	}
	if !strings.HasSuffix(log[1], " 第一条") {
		t.Fatalf("旧日志应在后面: %q", log[1])
	}
	if pct != 42 || stage != "阶段二" {
		t.Fatalf("stage/pct 未更新: %q %d", stage, pct)
	}
	// 上限 30 条
	for i := 0; i < 40; i++ {
		Cu("x", nil, "msg")
	}
	base.CoreUpd.Lock()
	n := len(base.CoreUpd.Log)
	base.CoreUpd.Unlock()
	if n != 30 {
		t.Fatalf("日志上限应为 30，实际 %d", n)
	}
}

func TestCoreUpdStatusCopy(t *testing.T) {
	Cu("测试", nil, "快照拷贝测试")
	st := CoreUpdStatus()
	log, ok := st["log"].([]string)
	if !ok {
		t.Fatalf("log 类型 %T, want []string", st["log"])
	}
	if len(log) == 0 {
		t.Fatal("log 不应为空")
	}
	log[0] = "MUTATED"
	st2 := CoreUpdStatus()
	if st2["log"].([]string)[0] == "MUTATED" {
		t.Fatal("CoreUpdStatus 应返回拷贝，外部修改不应影响内部状态")
	}
}

func TestCoreChannels(t *testing.T) {
	if CoreChannels["stable"] != "latest/download" || CoreChannels["alpha"] != "download/Prerelease-Alpha" {
		t.Fatalf("CoreChannels 值漂移: %v", CoreChannels)
	}
}

func TestTruncateTailStr(t *testing.T) {
	if truncate("abcdef", 4) != "abcd" {
		t.Fatal("truncate 前 N 失败")
	}
	if truncate("中文测试文本", 2) != "中文" {
		t.Fatal("truncate 应按 rune 截断")
	}
	if tailStr("abcdef", 2) != "ef" {
		t.Fatal("tailStr 后 N 失败")
	}
	if tailStr("短", 10) != "短" {
		t.Fatal("tailStr 不足 N 时应原样返回")
	}
}

func TestShellQuote(t *testing.T) {
	if shellQuote("/usr/local/bin/mihomo") != "/usr/local/bin/mihomo" {
		t.Fatal("安全路径不应加引号")
	}
	if q := shellQuote("/tmp/a b/c"); q != "'/tmp/a b/c'" {
		t.Fatalf("含空格路径引号错误: %s", q)
	}
	if q := shellQuote("a'b"); q != `'a'\''b'` {
		t.Fatalf("单引号转义错误: %s", q)
	}
}
