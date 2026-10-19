package core

// 本文件移植自 shunt/sb_switch.py：内核切换（mihomo↔sing-box）与 sing-box 更新。

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"shunt/internal/base"
	"shunt/internal/coreupdate"
	"shunt/internal/data"
)

// ---------- CoreUpd 状态辅助（本包） ----------

func cuSet(ok *bool, msg *string) {
	base.CoreUpd.Lock()
	defer base.CoreUpd.Unlock()
	if ok != nil {
		base.CoreUpd.Ok = ok
	}
	if msg != nil {
		base.CoreUpd.Message = *msg
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

// finishSwitchJob 对应 core_switch_job / sb_update_job 末尾的 finally：
// pct=100；_cu("完成"/"失败", 100, message)；busy=False。
// stub 未接线时的 panic 收敛为 ok=False，与 Python except 同语义。
func finishSwitchJob() {
	if r := recover(); r != nil {
		msg := fmt.Sprint(r)
		cuSet(boolPtr(false), &msg)
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
	coreupdate.Cu(stage, &p, message)
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

// sbArchFromMachine 是 SbArch 的纯函数核心（可测试）。
func sbArchFromMachine(m string) string {
	return map[string]string{
		"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64",
		"armv7l": "armv7", "armv8l": "armv7", "armv6l": "armv6",
		"i686": "386", "i386": "386", "riscv64": "riscv64",
		"loongarch64": "loong64", "s390x": "s390x",
	}[m]
}

// SbArch 对应 sb_arch()。
func SbArch() string { return sbArchFromMachine(machineName()) }

// isMusl 对应 is_musl()。
func isMusl() bool {
	if m, _ := filepath.Glob("/lib/ld-musl-*"); len(m) > 0 {
		return true
	}
	_, err := os.Stat("/etc/alpine-release")
	return err == nil
}

var tagVerRe = regexp.MustCompile(`/tag/v?([\w.\-]+)`)

// SbRemoteVersion 对应 sb_remote_version(channel, gh)：
// 最新正式版 / 预发布版的版本号（不带 v）。GitHub API 受限时从跳转地址里取版本号。
func SbRemoteVersion(channel, gh string) (string, error) {
	apiURL := sbAPI + "?per_page=10"
	if channel == "stable" {
		apiURL = sbAPI + "/latest"
	}
	if v, err := sbRemoteVersionAPI(apiURL, channel); err == nil {
		return v, nil
	} else if channel != "stable" {
		return "", err
	}
	// API 受限时从跳转地址里取版本号
	resp, err := coreupdate.OpenURL(sbRepo+"/latest", gh, 15)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	m := tagVerRe.FindStringSubmatch(resp.FinalURL)
	if m == nil {
		return "", errors.New("获取 sing-box 版本号失败")
	}
	return m[1], nil
}

// sbRemoteVersionAPI 走 GitHub API 取版本号；v 为空也视为失败（与 Python 里
// `if v: return v` 后落入跳转逻辑一致）。
func sbRemoteVersionAPI(apiURL, channel string) (string, error) {
	resp, err := coreupdate.OpenURL(apiURL, "", 15)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(io.LimitReader(resp.Body, 400000))
	if err != nil {
		return "", err
	}
	var j any
	if err := json.Unmarshal(buf, &j); err != nil {
		return "", err
	}
	var item map[string]any
	if channel != "stable" {
		arr, _ := j.([]any)
		for _, x := range arr { // next((x for x in j if x.get("prerelease")), j[0])
			if xm, ok := x.(map[string]any); ok && data.Bool(xm, "prerelease") {
				item = xm
				break
			}
		}
		if item == nil && len(arr) > 0 {
			item, _ = arr[0].(map[string]any)
		}
	} else {
		item, _ = j.(map[string]any)
	}
	if item == nil {
		return "", errors.New("GitHub API 未返回版本信息")
	}
	v := strings.TrimLeft(data.Str(item, "tag_name"), "v")
	if v == "" {
		return "", errors.New("GitHub API 未返回版本信息")
	}
	return v, nil
}

// pickPrerelease 供测试：从 release 列表选第一个 prerelease，没有则取第一个。
func pickPrerelease(items []map[string]any) map[string]any {
	for _, x := range items {
		if data.Bool(x, "prerelease") {
			return x
		}
	}
	if len(items) > 0 {
		return items[0]
	}
	return nil
}

// ---------- 下载 / 安装 ----------

// sbFetch 对应 sb_fetch(url, gh, digest="")：下载并做大小/完整性/SHA256 校验。
// 没有校验值时不走第三方镜像（gh 置空）。
func sbFetch(url, gh, digest string) ([]byte, error) {
	if digest == "" {
		gh = ""
	}
	resp, err := coreupdate.OpenURL(url, gh, 60)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	total := resp.ContentLength
	var buf bytes.Buffer
	var n int64
	chunk := make([]byte, 1<<16)
	for {
		k, rerr := resp.Body.Read(chunk)
		if k > 0 {
			n += int64(k)
			if n > 120<<20 {
				return nil, errors.New("下载文件异常过大，已中止")
			}
			buf.Write(chunk[:k])
			if total > 0 {
				cuPct(10 + int(50*n/total))
			}
		}
		if rerr != nil {
			break
		}
	}
	if total > 0 && n < total {
		return nil, fmt.Errorf("下载不完整 %d/%d", n, total)
	}
	if digest != "" {
		sum := sha256.Sum256(buf.Bytes())
		if hex.EncodeToString(sum[:]) != digest {
			return nil, errors.New("SHA256 与 GitHub 不一致（可能被加速镜像篡改）")
		}
	}
	return buf.Bytes(), nil
}

// extractSingBox 从 tar.gz 包中取出 sing-box 可执行文件内容。
func extractSingBox(tgz []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.FileInfo().Mode().IsRegular() && filepath.Base(hdr.Name) == "sing-box" {
			return io.ReadAll(tr)
		}
	}
	return nil, errors.New("压缩包里没有 sing-box 程序")
}

// sbInstall 对应 sb_install(channel, gh, force=False)：
// 下载 sing-box 到 SB_BIN（旧版本备份为 .bak）；返回 (版本号, 是否有变化)。
func sbInstall(channel, gh string, force bool) (string, bool, error) {
	arch := SbArch()
	if arch == "" {
		return "", false, fmt.Errorf("sing-box 不支持当前 CPU 架构：%s", machineName())
	}
	ver, err := SbRemoteVersion(channel, gh)
	if err != nil {
		return "", false, err
	}
	cur := sbVersion()
	if cur == ver && !force {
		return ver, false, nil
	}
	// 1.14 起普通 linux 包依赖 glibc，Alpine(musl) 上跑不起来，优先下 -musl 版
	var variants []string
	if isMusl() {
		variants = []string{"-musl", "", "-glibc"}
	} else {
		variants = []string{"", "-glibc", "-musl"}
	}
	tmp := sbBin + ".new"
	var errs []string
	nv := ""
	for _, v := range variants {
		name := fmt.Sprintf("sing-box-%s-linux-%s%s.tar.gz", ver, arch, v)
		p := 10
		coreupdate.Cu("下载", &p, "下载 "+name)
		digest := coreupdate.ReleaseDigest(sbRepo, "v"+ver, name)
		tgz, err := sbFetch(sbRepo+"/download/v"+ver+"/"+name, gh, digest)
		var bin []byte
		if err == nil {
			bin, err = extractSingBox(tgz)
		}
		if err == nil {
			err = os.WriteFile(tmp, bin, 0o755)
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %s", name, truncate(err.Error(), 100)))
			continue
		}
		os.Chmod(tmp, 0o755)
		nv = sbVersion(tmp)
		if nv != "" {
			break
		}
		_, out := shRun(shellQuote(tmp)+" version", 15)
		errs = append(errs, fmt.Sprintf("%s: 无法运行 %s", name, truncate(strings.TrimSpace(out), 100)))
		os.Remove(tmp)
	}
	if nv == "" {
		return "", false, errors.New("下载的 sing-box 无法运行（架构不匹配或文件损坏）：" + strings.Join(errs, "；"))
	}
	if isFile(sbBin) {
		if err := copyFileMode(sbBin, sbBin+".bak"); err != nil {
			return "", false, err
		}
	}
	if err := os.Rename(tmp, sbBin); err != nil {
		return "", false, err
	}
	return nv, true, nil
}

// ---------- 内核切换 ----------

// CoreSwitchJob 对应 core_switch_job(kind, gh)：
// 切换内核：准备程序与数据 → 生成并校验配置 → 写入启动选择 → 重启；失败自动换回原内核。
// 调用方以 `go CoreSwitchJob(kind, gh)` 启动（Python 侧是 daemon 线程）。
func CoreSwitchJob(kind, gh string) {
	defer finishSwitchJob()
	if err := coreSwitchJobInner(kind, gh); err != nil {
		msg := err.Error()
		cuSet(boolPtr(false), &msg)
	}
}

var fatalLogRe = regexp.MustCompile(`FATAL|ERROR|level=(?:error|fatal)`)
var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

func coreSwitchJobInner(kind, gh string) error {
	prev := activeCore()
	label := sbCores[kind]
	dnsAutoFix := false // 切到 sing-box 时是否自动开启了「阻止客户端绕过 DNS」
	var d map[string]any
	if kind == "singbox" {
		if sbVersion() == "" {
			p := 5
			coreupdate.Cu("安装 sing-box", &p, "设备上还没有 sing-box，正在下载最新正式版")
			nv, _, err := sbInstall("stable", gh, false)
			if err != nil {
				return err
			}
			p = 62
			coreupdate.Cu("安装 sing-box", &p, "已安装 sing-box "+nv)
		}
		d = data.Load()
		if !data.Bool(dnsCfg(d), "block_bypass") {
			// sing-box 1.13+ 移除了 sniff_override_destination，设备 DNS 绕过面板时拿到污染 IP 必死；
			// mihomo 的 sniffer 默认改写目标地址所以不受影响。切到 sing-box 时自动开启防绕过。
			dnsMap := ensureMap(d, "dns")
			dnsMap["block_bypass"] = true
			dnsAutoFix = true
		}
		if len(data.List(d, "subs")) > 0 {
			p := 65
			coreupdate.Cu("下载订阅", &p, "sing-box 不能自己拉取订阅，由面板下载并解析节点")
			okList, badList := sbUpdateSubs(d)
			for _, x := range append(append([]string{}, okList...), badList...) {
				coreupdate.Cu("下载订阅", nil, x)
			}
			if len(okList) == 0 {
				return fmt.Errorf("订阅全部下载失败，未切换：%s", truncate(strings.Join(badList, "；"), 300))
			}
		}
		p := 75
		coreupdate.Cu("规则集", &p, "下载 sing-box 格式的 GEO / 规则集文件")
		bad := sbSyncAssets(d, nil)
		for _, x := range bad[:min(5, len(bad))] {
			coreupdate.Cu("规则集", nil, "✗ "+x)
		}
		var crit []string
		for _, x := range bad {
			head := x
			if i := strings.Index(x, "："); i >= 0 {
				head = x[:i]
			}
			if head == "geosite-cn" || head == "geoip-cn" || head == "geosite-private" {
				crit = append(crit, x)
			}
		}
		if len(crit) > 0 { // 缺了国内/私有地址规则集，相关规则会被裁掉，国内流量全部走「漏网之鱼」代理，宁可不切
			return fmt.Errorf("国内分流规则集下载失败，未切换（可在 设置 里填 GitHub 加速地址后重试）：%s",
				truncate(strings.Join(crit, "；"), 300))
		}
		tmp := writeSbConfig(d, sbConf+".new")
		ok, chkErr := checkSbConfig(tmp)
		if !ok {
			os.Remove(tmp)
			return errors.New("sing-box 配置校验失败，未切换：" + chkErr)
		}
		if err := os.Rename(tmp, sbConf); err != nil {
			return err
		}
	} else {
		if kind == "smart" && coreupdate.BinVersion(base.SmartBin) == "" {
			p := 5
			coreupdate.Cu("安装 Smart 内核", &p, "设备上还没有 mihomo Smart，正在从 vernesong/mihomo 下载")
			tmp, _, err := coreupdate.MhFetch("smart", "alpha", gh, func(pc float64) { cuPct(5 + int(55*pc)) })
			if err != nil {
				return err
			}
			if err := os.Rename(tmp, base.SmartBin); err != nil {
				return err
			}
			p = 62
			coreupdate.Cu("安装 Smart 内核", &p, "已安装 "+coreupdate.BinVersion(base.SmartBin))
		}
		if coreupdate.BinVersion(mhBin(kind)) == "" {
			return fmt.Errorf("设备上没有可用的 %s 程序，请先在「内核更新」里安装", label)
		}
		d = mapWith(data.Load(), "core", kind) // 按目标内核生成（Smart：竞技组改为 smart 类型）
		if kind == "smart" && data.Bool(gcfgOf(d), "lgbm") {
			if _, err := os.Stat(coreupdate.LgbmFile); os.IsNotExist(err) {
				p := 64
				coreupdate.Cu("LightGBM 模型", &p, "下载 LightGBM 模型 Model.bin")
				if _, ferr := coreupdate.LgbmFetch(gh); ferr != nil {
					coreupdate.Cu("LightGBM 模型", nil, "✗ 模型下载失败，Smart 组先用内置算法："+truncate(ferr.Error(), 120))
				}
			}
		}
		cfgPath := filepath.Join(base.ConfDir, "config.yaml")
		tmp := writeConfig(d, cfgPath+".new")
		ok, chkErr := checkConfig(tmp, kind)
		if !ok {
			os.Remove(tmp)
			return fmt.Errorf("%s 配置校验失败，未切换：%s", label, chkErr)
		}
		if err := os.Rename(tmp, cfgPath); err != nil {
			return err
		}
	}
	snapshotSelections(true)
	data.Update(func(x map[string]any) {
		x["core"] = kind
		if dnsAutoFix {
			ensureMap(x, "dns")["block_bypass"] = true
		}
	})
	writeCoreFile(kind)
	provInvalidate()
	p := 88
	coreupdate.Cu("重启核心", &p, fmt.Sprintf("正在以 %s 重启核心（局域网会断网几秒）", label))
	setManualStop(false)
	svcRestart(90)
	alive := false
	for i := 0; i < 30; i++ {
		time.Sleep(time.Second)
		if coreAlive() {
			alive = true
			break
		}
	}
	if !alive {
		_, out := shRun(fmt.Sprintf("tail -n 30 '%s'", base.MihomoLog), 60)
		var tails []string
		for _, l := range strings.Split(out, "\n") {
			if fatalLogRe.MatchString(l) {
				tails = append(tails, l)
			}
		}
		data.Update(func(x map[string]any) { x["core"] = prev })
		writeCoreFile(prev)
		svcRestart(90)
		log := tailStr(ansiRe.ReplaceAllString(strings.Join(lastN(tails, 3), "\n"), ""), 400)
		suffix := "请查看核心日志"
		if log != "" {
			suffix = "日志：" + log
		}
		return fmt.Errorf("%s 30 秒内未响应，已切回 %s。%s", label, sbCores[prev], suffix)
	}
	go restoreSelections()
	if dnsAutoFix && data.Str(d, "proxy_mode") != "off" {
		shRun(base.TproxySh+" apply", 15) // block_bypass 变化：重载 nftables 劫持任意目标的 53 端口
	}
	msg := "已切换到 " + label
	if kind == "singbox" {
		if w := sbStateWarn(); len(w) > 0 {
			msg += fmt.Sprintf("（%d 条兼容提示见设置 → 核心）", len(w))
		}
	}
	if dnsAutoFix {
		msg += "；已自动开启「阻止客户端绕过 DNS」（sing-box 要求设备 DNS 经过面板，如不需要可在 设置→DNS 关闭）"
	}
	okTrue := true
	cuSet(&okTrue, &msg)
	notifySend(fmt.Sprintf("🔀 内核已切换：%s → %s", sbCores[prev], label))
	return nil
}

// SbUpdateJob 对应 sb_update_job(channel, gh, force)：sing-box 在线更新。
// 调用方以 `go SbUpdateJob(channel, gh, force)` 启动。
func SbUpdateJob(channel, gh string, force bool) {
	defer finishSwitchJob()
	if err := sbUpdateJobInner(channel, gh, force); err != nil {
		msg := err.Error()
		cuSet(boolPtr(false), &msg)
	}
}

func sbUpdateJobInner(channel, gh string, force bool) error {
	cur := sbVersion()
	p := 3
	coreupdate.Cu("获取版本", &p, "正在获取 sing-box 最新版本号")
	nv, changed, err := sbInstall(channel, gh, force)
	if err != nil {
		return err
	}
	if !changed {
		ok := true
		msg := fmt.Sprintf("已是最新版本 %s，无需更新", nv)
		cuSet(&ok, &msg)
		return nil
	}
	p = 70
	coreupdate.Cu("校验", &p, fmt.Sprintf("用 sing-box %s 检查当前配置", nv))
	if activeCore() == "singbox" {
		ok, chkErr := checkSbConfig(sbConf)
		if !ok {
			if cerr := coreupdate.CopyReplace(sbBin+".bak", sbBin); cerr != nil {
				return cerr
			}
			return errors.New("新版 sing-box 不兼容当前配置，已恢复原版本：" + chkErr)
		}
		p = 85
		coreupdate.Cu("重启核心", &p, "正在重启核心")
		svcRestart(90)
		alive := false
		for i := 0; i < 30; i++ {
			time.Sleep(time.Second)
			if coreAlive() {
				alive = true
				break
			}
		}
		if !alive {
			if cerr := coreupdate.CopyReplace(sbBin+".bak", sbBin); cerr != nil {
				return cerr
			}
			svcRestart(90)
			return errors.New("新版 sing-box 30 秒内未响应，已恢复原版本")
		}
	}
	ok := true
	curLabel := cur
	if curLabel == "" {
		curLabel = "未安装"
	}
	msg := fmt.Sprintf("sing-box 已从 %s 更新到 %s", curLabel, nv)
	if cur != "" {
		msg += "，旧版本已备份"
	}
	cuSet(&ok, &msg)
	return nil
}

// ---------- 小工具 ----------

// ensureMap 取 d[key] 的 map，不存在则创建（对应 setdefault）。
func ensureMap(d map[string]any, key string) map[string]any {
	m, _ := d[key].(map[string]any)
	if m == nil {
		m = map[string]any{}
		d[key] = m
	}
	return m
}

// mapWith 浅拷贝 d 并覆盖一个键（对应 dict(load(), core=kind)）。
func mapWith(d map[string]any, k string, v any) map[string]any {
	out := make(map[string]any, len(d)+1)
	for key, val := range d {
		out[key] = val
	}
	out[k] = v
	return out
}

// lastN 取后 n 个元素（对应 Python 的 tail[-3:]）。
func lastN(ss []string, n int) []string {
	if len(ss) > n {
		return ss[len(ss)-n:]
	}
	return ss
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
