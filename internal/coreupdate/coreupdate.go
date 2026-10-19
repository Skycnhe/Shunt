// Package coreupdate 移植自 shunt/core_update.py：mihomo 内核在线更新。
//
// 导出命名按"Python foo_bar → Go FooBar"契约：CoreCheck、CoreJobStart、
// CoreUpdateJob、CoreRollbackJob、CoreUpdStatus、BinVersion、LgbmFetch、
// LgbmFetchReload、LgbmFile、CoreChannels 等。
//
// 跨包依赖中，internal/core（ReloadCore）通过 ReloadCoreHook 注入以避免
// import cycle；其余外部模块（mihomo/sb_common/sysopt/notify/errlog）
// 均为 stubs.go 中的私有 stub，待对应模块移植后接线。
package coreupdate

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"shunt/internal/base"
	"shunt/internal/data"
)

// CoreRepo / SmartRepo 对应 CORE_REPO / SMART_REPO（环境变量可覆盖）。
var (
	CoreRepo  = getenv("CORE_REPO", "https://github.com/MetaCubeX/mihomo/releases")
	SmartRepo = getenv("SMART_REPO", "https://github.com/vernesong/mihomo/releases")
	// LgbmFile 对应 LGBM_FILE：LightGBM 模型路径。
	LgbmFile = filepath.Join(base.ConfDir, "Model.bin")
)

// CoreChannels 对应 CORE_CHANNELS。
var CoreChannels = map[string]string{"stable": "latest/download", "alpha": "download/Prerelease-Alpha"}

// ReloadCoreHook 注入点：core_update.py 顶部 `from .core import reload_core`。
// coreupdate → core 直接 import 会形成循环，因此由 internal/core 在 init 中注入
// 真实实现；core 包未加载时的安全回退（正常构建下 core 的 init 已注入，无需 panic）。
// STUB:core.ReloadCore
var ReloadCoreHook = func(prev map[string]any) (bool, string) {
	return false, "core.ReloadCore 未接线（internal/core 未初始化）"
}

// ---------- CoreUpd 状态辅助 ----------

func cuSet(ok *bool, message *string, t *int64) {
	base.CoreUpd.Lock()
	defer base.CoreUpd.Unlock()
	if ok != nil {
		base.CoreUpd.Ok = ok
	}
	if message != nil {
		base.CoreUpd.Message = *message
	}
	if t != nil {
		base.CoreUpd.T = *t
	}
}

func cuPct(p int) {
	base.CoreUpd.Lock()
	defer base.CoreUpd.Unlock()
	base.CoreUpd.Pct = p
}

func cuBusy(b bool) {
	base.CoreUpd.Lock()
	defer base.CoreUpd.Unlock()
	base.CoreUpd.Busy = b
}

// Cu 对应 _cu(stage, pct, msg)：更新阶段/进度并写日志（最新在前，最多 30 条）。
// pct 为 nil 表示不改进度。msg 为空时用 stage。
func Cu(stage string, pct *int, msg string) {
	if msg == "" {
		msg = stage
	}
	line := time.Now().Format("15:04:05") + " " + msg
	base.CoreUpd.Lock()
	defer base.CoreUpd.Unlock()
	base.CoreUpd.Stage = stage
	if pct != nil {
		base.CoreUpd.Pct = *pct
	}
	base.CoreUpd.Log = append([]string{line}, base.CoreUpd.Log...)
	if len(base.CoreUpd.Log) > 30 {
		base.CoreUpd.Log = base.CoreUpd.Log[:30]
	}
}

// finishCoreJob 对应各 job 末尾的 finally：
// CORE_UPD["pct"] = 100；_cu("完成"/"失败", 100, message)；busy = False。
// stub 尚未接线时的 panic 也在这里收敛为 ok=False，与 Python except 同语义。
func finishCoreJob() {
	if r := recover(); r != nil {
		msg := fmt.Sprint(r)
		cuSet(boolPtr(false), &msg, nil)
	}
	cuPct(100)
	base.CoreUpd.Lock()
	ok := base.CoreUpd.Ok != nil && *base.CoreUpd.Ok
	message := base.CoreUpd.Message
	base.CoreUpd.Unlock()
	stage := "失败"
	if ok {
		stage = "完成"
	}
	p := 100
	Cu(stage, &p, message)
	cuBusy(false)
}

// ---------- 架构 / 版本 ----------

// machineName 对应 os.uname().machine。
func machineName() string {
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return "unknown"
	}
	var b []byte
	for _, c := range uts.Machine {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	if len(b) == 0 {
		return "unknown"
	}
	return string(b)
}

// coreArchFrom 是 CoreArch 的纯函数核心（可测试）：x86_64 按 CPU flags 选
// amd64-v3 / amd64-compatible，其余查表。
func coreArchFrom(machine, cpuinfo string) string {
	if machine == "x86_64" {
		if strings.Contains(cpuinfo, " avx2") && strings.Contains(cpuinfo, " bmi2") &&
			strings.Contains(cpuinfo, " fma") && strings.Contains(cpuinfo, " movbe") {
			return "amd64-v3"
		}
		return "amd64-compatible"
	}
	return map[string]string{
		"aarch64": "arm64", "arm64": "arm64", "armv7l": "armv7", "armv8l": "armv7",
		"armv6l": "armv6", "i686": "386", "i386": "386", "riscv64": "riscv64",
		"loongarch64": "loong64-abi2",
	}[machine]
}

// CoreArch 对应 core_arch()。
func CoreArch() string {
	m := machineName()
	if m == "x86_64" {
		if buf, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			return coreArchFrom(m, string(buf))
		}
		return "amd64-compatible"
	}
	return coreArchFrom(m, "")
}

var binVerRe = regexp.MustCompile(`Mihomo\s+Meta\s+(\S+)`)

// parseBinVersion 从 `mihomo -v` 输出提取版本号（纯函数，可测试）。
func parseBinVersion(out string) string {
	m := binVerRe.FindStringSubmatch(out)
	if m == nil {
		return ""
	}
	return m[1]
}

// BinVersion 对应 bin_version(path)：执行 `path -v` 取版本号；不能运行返回 ""。
func BinVersion(path string) string {
	if !isFile(path) {
		return ""
	}
	code, out := shRun(shellQuote(path)+" -v", 15)
	if code != 0 {
		return ""
	}
	return parseBinVersion(out)
}

// ---------- 下载 ----------

// HttpResponse 对应 proxy_opener(...).open(...) 返回的响应对象。
type HttpResponse struct {
	Body          io.ReadCloser
	ContentLength int64
	FinalURL      string
}

// opener 是 proxy_opener 返回对象的最小接口（STUB:sysopt.proxy_opener 的边界）。
type opener interface {
	Open(rawurl, ua string, timeoutSec int) (*HttpResponse, error)
}

// errSkipProxy 内部哨兵：核心未运行时跳过"经代理"尝试（不记错）。
var errSkipProxy = errors.New("skip proxy")

// openTry 单次下载尝试；stub 未接线时的 panic 在此收敛为本轮错误，
// 与 Python try/except 逐个尝试的语义一致。
func openTry(rawurl string, useProxy bool, timeoutSec int) (resp *HttpResponse, err error) {
	defer func() {
		if r := recover(); r != nil {
			resp, err = nil, fmt.Errorf("%v", r)
		}
	}()
	effProxy := false
	if useProxy {
		if !coreAlive() {
			return nil, errSkipProxy
		}
		effProxy = true
	}
	if err := base.DlCheck(rawurl, effProxy); err != nil {
		return nil, err
	}
	return proxyOpener(effProxy).Open(rawurl, base.Ua, timeoutSec)
}

func hostOf(rawurl string) string {
	if u, err := url.Parse(rawurl); err == nil {
		return u.Hostname()
	}
	return ""
}

func tryErrLabel(rawurl string, useProxy bool, err error) string {
	suffix := ""
	if useProxy {
		suffix = "(代理)"
	}
	return hostOf(rawurl) + suffix + ": " + truncate(err.Error(), 120)
}

// OpenURL 对应 open_url(url, gh, timeout)：GitHub 下载三路尝试——
// 先走加速地址（gh），再经 mihomo 代理，最后直连。
func OpenURL(rawurl, gh string, timeoutSec int) (*HttpResponse, error) {
	type urlTry struct {
		url      string
		useProxy bool
	}
	var tries []urlTry
	if gh != "" {
		tries = append(tries, urlTry{strings.TrimRight(gh, "/") + "/" + rawurl, false})
	}
	tries = append(tries, urlTry{rawurl, true}, urlTry{rawurl, false})
	errMsg := ""
	for _, tr := range tries {
		resp, err := openTry(tr.url, tr.useProxy, timeoutSec)
		if err == errSkipProxy {
			continue
		}
		if err != nil {
			errMsg = tryErrLabel(tr.url, tr.useProxy, err)
			continue
		}
		return resp, nil
	}
	return nil, errors.New(errMsg)
}

// GhAPI 对应 gh_api(path, timeout)：直连或经 mihomo 代理访问 GitHub API
// （绝不走第三方加速镜像：校验值必须来自 GitHub 本身）。
func GhAPI(path string, timeoutSec int) (map[string]any, error) {
	resp, err := OpenURL("https://api.github.com"+path, "", timeoutSec)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var j map[string]any
	if err := json.Unmarshal(buf, &j); err != nil {
		return nil, err
	}
	return j, nil
}

var ghRepoRe = regexp.MustCompile(`^https://github\.com/([^/]+/[^/]+)/releases`)

// ReleaseDigest 对应 release_digest(repo_url, tag, name)：
// GitHub Release 资产的 SHA256（API 的 digest 字段）；拿不到返回 ""。
func ReleaseDigest(repoURL, tag, name string) string {
	m := ghRepoRe.FindStringSubmatch(repoURL)
	if m == nil {
		return ""
	}
	j, err := GhAPI("/repos/"+m[1]+"/releases/tags/"+url.PathEscape(tag), 15)
	if err != nil {
		logErrSafe("获取内核校验值", err)
		return ""
	}
	for _, a := range data.List(j, "assets") {
		am, _ := a.(map[string]any)
		if am == nil {
			continue
		}
		if data.Str(am, "name") == name && strings.HasPrefix(data.Str(am, "digest"), "sha256:") {
			return strings.TrimPrefix(data.Str(am, "digest"), "sha256:")
		}
	}
	return ""
}

var verRe = regexp.MustCompile(`^[\w.\-]+$`)

// CoreRemoteVersion 对应 core_remote_version(channel, gh, kind)。
func CoreRemoteVersion(channel, gh, kind string) (string, error) {
	var u string
	if kind == "smart" {
		u = SmartRepo + "/download/Prerelease-Alpha/version.txt"
	} else {
		u = CoreRepo + "/" + CoreChannels[channel] + "/version.txt"
	}
	resp, err := OpenURL(u, gh, 20)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(io.LimitReader(resp.Body, 200))
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(buf))
	if !verRe.MatchString(v) {
		return "", fmt.Errorf("获取到的版本号无效：%s", truncate(v, 40))
	}
	return v, nil
}

// CoreCheck 对应 core_check(channel, gh, kind="mihomo")。
func CoreCheck(channel, gh, kind string) (bool, map[string]any) {
	arch, b := CoreArch(), mhBin(kind)
	if kind == "smart" {
		channel = "alpha"
	}
	if arch == "" {
		arch = machineName()
	}
	current := BinVersion(b)
	if current == "" {
		current = "未安装"
	}
	info := map[string]any{
		"current": current, "arch": arch, "channel": channel,
		"backup": BinVersion(b + ".bak"), "remote": "", "core": kind,
	}
	remote, err := CoreRemoteVersion(channel, gh, kind)
	if err != nil {
		info["message"] = "获取最新版本失败：" + err.Error()
		return false, info
	}
	info["remote"] = remote
	info["latest"] = remote == current
	if remote == current {
		info["message"] = "已是最新"
	} else {
		info["message"] = "可更新到 " + remote
	}
	return true, info
}

// hashReader 对应 HashReader：边读边算 SHA256 的包装（流式解压时用）。
type hashReader struct {
	r     io.Reader
	h     hash.Hash
	n     int64
	prog  func(float64)
	total int64
}

func (hr *hashReader) Read(p []byte) (int, error) {
	n, err := hr.r.Read(p)
	if n > 0 {
		hr.h.Write(p[:n])
		hr.n += int64(n)
		if hr.total > 0 && hr.prog != nil {
			hr.prog(math.Min(1, float64(hr.n)/float64(hr.total)))
		}
	}
	return n, err
}

func (hr *hashReader) sum() string {
	return hex.EncodeToString(hr.h.Sum(nil))
}

// CopyReplace 对应 copy_replace(src, dst)：复制到临时文件再改名替换。
// dst 可能是正在运行（卡住/反复重启）的程序，直接覆盖写会因 ETXTBSY 失败，
// 回滚恰恰在新程序起不来时发生，以前这一步失败会让回滚落空。
func CopyReplace(src, dst string) error {
	tmp := dst + ".rb"
	if err := copyFileMode(src, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// coreSwapAndRestart 对应 _core_swap_and_restart(src, label, kind)：
// 把 src 换成正式核心并重启；30 秒内控制接口没起来就自动换回原来的核心。
func coreSwapAndRestart(src, label, kind string) (bool, string) {
	B := mhBin(kind)
	bak := B + ".bak"
	hadOld := isFile(B)
	if hadOld && src != bak {
		if err := copyFileMode(B, bak); err != nil {
			return false, err.Error()
		}
	}
	if src == bak { // 回滚：当前核心与备份互换，方便再"回滚"回来
		tmp := B + ".swap"
		if err := copyFileMode(B, tmp); err != nil {
			return false, err.Error()
		}
		if err := os.Rename(bak, B); err != nil {
			return false, err.Error()
		}
		if err := os.Rename(tmp, bak); err != nil {
			return false, err.Error()
		}
	} else {
		if err := os.Rename(src, B); err != nil {
			return false, err.Error()
		}
	}
	if activeCore() != kind { // 这个内核没在运行：只替换程序，切换过去时生效
		p := 95
		Cu("完成", &p, fmt.Sprintf("已替换为 %s（当前内核是 %s，切到 %s 时生效）",
			label, coresMap[activeCore()], coresMap[kind]))
		return true, ""
	}
	p := 90
	Cu("重启核心", &p, fmt.Sprintf("已替换为 %s，正在重启核心", label))
	svcRestart(90)
	for i := 0; i < 30; i++ {
		time.Sleep(time.Second)
		if coreAlive() {
			return true, ""
		}
	}
	if hadOld && src != bak { // 新核心起不来 → 自动恢复
		p := 95
		Cu("自动回滚", &p, "新核心 30 秒内未响应，正在恢复原核心")
		if err := CopyReplace(bak, B); err != nil {
			return false, err.Error()
		}
		svcRestart(90)
		_, out := shRun(fmt.Sprintf("tail -n 5 '%s'", base.MihomoLog), 60)
		return false, "新核心启动失败，已自动恢复为原核心。日志：" + tailStr(out, 300)
	}
	return false, "核心重启后 30 秒内未响应，请查看日志"
}

// MhFetch 对应 mh_fetch(kind, channel, gh, prog)：下载 mihomo / mihomo Smart
// 到 <程序>.new 并校验能运行；返回 (临时文件, 版本号)。
func MhFetch(kind, channel, gh string, prog func(float64)) (tmp string, nv string, err error) {
	B := mhBin(kind)
	arch := CoreArch()
	if arch == "" {
		return "", "", fmt.Errorf("不支持的 CPU 架构：%s", machineName())
	}
	ver, err := CoreRemoteVersion(channel, gh, kind)
	if err != nil {
		return "", "", err
	}
	if free, ferr := diskFree(filepath.Dir(B)); ferr == nil && free < 80<<20 {
		return "", "", fmt.Errorf("%s 剩余空间不足（%d MB，至少需要 80 MB）", filepath.Dir(B), free>>20)
	}
	tag := ver
	if kind == "smart" || channel == "alpha" {
		tag = "Prerelease-Alpha"
	}
	repo := CoreRepo
	if kind == "smart" {
		repo = SmartRepo
	}
	u := repo + "/download/" + tag + "/mihomo-linux-" + arch + "-" + ver + ".gz"
	name := u[strings.LastIndex(u, "/")+1:]
	digest := ReleaseDigest(repo, tag, name)
	if digest == "" && gh != "" {
		Cu("下载", nil, "拿不到 GitHub 校验值，不使用加速镜像（避免下载到被篡改的文件）")
		gh = ""
	}
	Cu("下载", nil, "下载 "+name)
	tmp = B + ".new"
	defer func() {
		if err != nil {
			os.Remove(tmp)
		}
	}()
	resp, err := OpenURL(u, gh, 30)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	hr := &hashReader{r: resp.Body, h: sha256.New(), prog: prog, total: resp.ContentLength}
	gz, err := gzip.NewReader(hr)
	if err != nil {
		return "", "", err
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		gz.Close()
		return "", "", err
	}
	buf := make([]byte, 1<<16)
	var size int64
	for {
		n, rerr := gz.Read(buf)
		if n > 0 {
			size += int64(n)
			if size > 200<<20 {
				f.Close()
				gz.Close()
				return "", "", errors.New("解压后的文件异常过大，已中止")
			}
			if _, werr := f.Write(buf[:n]); werr != nil {
				f.Close()
				gz.Close()
				return "", "", werr
			}
		}
		if rerr != nil {
			break
		}
	}
	gz.Close()
	f.Close()
	for { // gzip 尾部之后若还有数据也计入校验
		n, rerr := hr.Read(buf)
		if n == 0 || rerr != nil {
			break
		}
	}
	if digest != "" && hr.sum() != digest {
		return "", "", errors.New("内核文件 SHA256 与 GitHub 不一致（可能被加速镜像篡改），未做任何替换")
	}
	if digest != "" {
		Cu("下载", nil, "SHA256 校验通过")
	} else {
		Cu("下载", nil, "未能获取 GitHub 校验值，已改为直连 / 代理下载")
	}
	os.Chmod(tmp, 0o755)
	nv = BinVersion(tmp)
	if nv == "" {
		return "", "", errors.New("新核心无法运行（架构不匹配或文件损坏），未做任何替换")
	}
	return tmp, nv, nil
}

// CoreUpdateJob 对应 core_update_job(channel, gh, force, kind)：后台任务，
// 由 CoreJobStart 以 goroutine 启动，状态写入 base.CoreUpd。
func CoreUpdateJob(channel, gh string, force bool, kind string) {
	B := mhBin(kind)
	tmp := B + ".new"
	defer func() { os.Remove(tmp) }()
	defer finishCoreJob()
	if err := coreUpdateJobInner(channel, gh, force, kind, B, tmp); err != nil {
		msg := err.Error()
		cuSet(boolPtr(false), &msg, nil)
	}
}

func coreUpdateJobInner(channel, gh string, force bool, kind, B, tmp string) error {
	p := 2
	Cu("获取版本", &p, "正在获取最新版本号")
	ver, err := CoreRemoteVersion(channel, gh, kind)
	if err != nil {
		return err
	}
	cur := BinVersion(B)
	if ver == cur && !force {
		ok := true
		msg := fmt.Sprintf("已是最新版本 %s，无需更新", cur)
		cuSet(&ok, &msg, nil)
		return nil
	}
	cuPct(5)
	tmp, nv, err := MhFetch(kind, channel, gh, func(pc float64) { cuPct(5 + int(70*pc)) })
	if err != nil {
		return err
	}
	p = 84
	Cu("校验", &p, fmt.Sprintf("新核心 %s，正在用它检查配置", nv))
	var cfg string
	if activeCore() == kind { // 正在用：拿当前配置校验；没在用：按它的格式生成一份再校验
		cfg = filepath.Join(base.ConfDir, "config.yaml")
	} else {
		cfg = writeConfig(mapWith(data.Load(), "core", kind), filepath.Join(base.ConfDir, "config.yaml.chk"))
	}
	code, out := shRun(fmt.Sprintf("'%s' -t -d '%s' -f '%s'", tmp, base.ConfDir, cfg), 90)
	if strings.HasSuffix(cfg, ".chk") {
		os.Remove(cfg)
	}
	if code != 0 {
		return errors.New("新核心不兼容当前配置，未做任何替换：" + tailStr(out, 300))
	}
	ok, msg := coreSwapAndRestart(tmp, nv, kind)
	if !ok {
		return errors.New(msg)
	}
	okTrue := true
	curLabel := cur
	if curLabel == "" {
		curLabel = "无"
	}
	msg = fmt.Sprintf("%s 已从 %s 更新到 %s", coresMap[kind], curLabel, nv)
	if cur != "" {
		msg += "，旧版本已备份，可一键回滚"
	}
	cuSet(&okTrue, &msg, nil)
	tg := data.Load()
	if data.Str(tg, "tg_token") != "" && data.Str(tg, "tg_chat") != "" {
		notifySend(fmt.Sprintf("⬆️ %s 内核已更新：%s → %s", coresMap[kind], curLabel, nv))
	}
	return nil
}

// LgbmFetch 对应 lgbm_fetch(gh)：下载 LightGBM 模型到 LgbmFile（约 9 MB，
// Smart 组 uselightgbm 用）；返回下载字节数。
func LgbmFetch(gh string) (int, error) {
	tmp := LgbmFile + ".new"
	defer func() {
		if _, err := os.Stat(tmp); err == nil {
			os.Remove(tmp)
		}
	}()
	digest := ReleaseDigest(SmartRepo, "LightGBM-Model", "Model.bin")
	ghEff := gh
	if digest == "" {
		ghEff = ""
	}
	resp, err := OpenURL(base.LgbmURL, ghEff, 60)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}
	hr := &hashReader{r: resp.Body, h: sha256.New()}
	buf := make([]byte, 1<<16)
	var n int64
	for {
		k, rerr := hr.Read(buf)
		if k > 0 {
			n += int64(k)
			if n > 64<<20 {
				f.Close()
				return 0, errors.New("模型文件异常过大，已中止")
			}
			if _, werr := f.Write(buf[:k]); werr != nil {
				f.Close()
				return 0, werr
			}
		}
		if rerr != nil {
			break
		}
	}
	f.Close()
	if n < 1<<20 {
		return 0, errors.New("下载的模型文件不完整")
	}
	if digest != "" && hr.sum() != digest {
		return 0, errors.New("模型文件 SHA256 与 GitHub 不一致")
	}
	if err := os.Rename(tmp, LgbmFile); err != nil {
		return 0, err
	}
	return int(n), nil
}

// LgbmFetchReload 对应 lgbm_fetch_reload()：下载模型，当前是 smart 内核时重载。
// 调用方以 `go LgbmFetchReload()` 启动。
func LgbmFetchReload() {
	if err := lgbmFetchReloadInner(); err != nil {
		fmt.Fprintf(os.Stderr, "LightGBM 模型下载失败：%v\n", err)
	}
}

func lgbmFetchReloadInner() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	gh := data.Str(data.Load(), "gh_proxy")
	if _, err := LgbmFetch(gh); err != nil {
		return err
	}
	if activeCore() == "smart" {
		ReloadCoreHook(nil)
	}
	return nil
}

// CoreRollbackJob 对应 core_rollback_job(kind)：一键回滚到 .bak 备份。
func CoreRollbackJob(kind string) {
	defer finishCoreJob()
	if err := coreRollbackJobInner(kind); err != nil {
		msg := err.Error()
		cuSet(boolPtr(false), &msg, nil)
	}
}

func coreRollbackJobInner(kind string) error {
	B := mhBin(kind)
	old := BinVersion(B + ".bak")
	if old == "" {
		return errors.New("没有可回滚的内核备份")
	}
	cur := BinVersion(B)
	ok, msg := coreSwapAndRestart(B+".bak", old, kind)
	if !ok {
		return errors.New(msg)
	}
	okTrue := true
	m := fmt.Sprintf("已回滚：%s → %s（%s 保留为备份）", cur, old, cur)
	cuSet(&okTrue, &m, nil)
	return nil
}

// CoreJobStart 对应 core_job_start(fn, *args)：锁内检查并置忙后起 goroutine，
// 与面板更新、其他内核任务互斥。
func CoreJobStart(fn func(...any), args ...any) (bool, string) {
	if !base.UpdBegin("core") {
		return false, base.UpdBusyMsg()
	}
	base.CoreUpd.Lock()
	base.CoreUpd.Stage = "开始"
	base.CoreUpd.Pct = 0
	base.CoreUpd.Ok = nil
	base.CoreUpd.Message = ""
	base.CoreUpd.T = time.Now().Unix()
	base.CoreUpd.Log = nil
	base.CoreUpd.Unlock()
	go fn(args...)
	return true, "已开始"
}

// CoreUpdStatus 对应 core_upd_status()：返回 CoreUpd 的快照拷贝。
func CoreUpdStatus() map[string]any {
	base.CoreUpd.Lock()
	defer base.CoreUpd.Unlock()
	var ok any
	if base.CoreUpd.Ok != nil {
		ok = *base.CoreUpd.Ok
	}
	return map[string]any{
		"busy":    base.CoreUpd.Busy,
		"stage":   base.CoreUpd.Stage,
		"pct":     base.CoreUpd.Pct,
		"ok":      ok,
		"message": base.CoreUpd.Message,
		"log":     append([]string{}, base.CoreUpd.Log...),
		"t":       base.CoreUpd.T,
	}
}

// ---------- 小工具 ----------

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func isFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// copyFileMode 对应 shutil.copy2：复制内容并保留源文件权限。
func copyFileMode(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fi.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, fi.Mode().Perm())
}

// shellQuote 对应 shlex.quote 的常用情形（路径/命令片段）。
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if regexp.MustCompile(`^[a-zA-Z0-9_@%+=:,./-]+$`).MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// truncate 取前 n 个 rune（对应 Python 的 s[:n] 在中文场景的近似）。
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// tailStr 取后 n 个 rune（对应 Python 的 s[-n:]）。
func tailStr(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[len(r)-n:])
	}
	return s
}

func boolPtr(b bool) *bool { return &b }

// mapWith 浅拷贝 d 并覆盖一个键（对应 dict(load(), core=kind)）。
func mapWith(d map[string]any, k string, v any) map[string]any {
	out := make(map[string]any, len(d)+1)
	for key, val := range d {
		out[key] = val
	}
	out[k] = v
	return out
}

// diskFree 返回目录所在文件系统的可用字节数。
func diskFree(dir string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}
