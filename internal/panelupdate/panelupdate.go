// Package panelupdate 移植自 shunt/panel_update.py：面板在线更新。
//
// 核心机制（保真移植）：下载全部文件 → 与本地逐字节比对 → 只替换有差异的
// 文件；替换前备份旧文件到 .backup；替换中途失败则把已替换的文件逐个恢复
// （不留下新 server.py + 旧 index.html 的混合版本）；重启后由 update_guard
// 在 90 秒内守护，失败自动回滚。
//
// 导出命名按"Python foo_bar → Go FooBar"契约：SelfUpdate、SelfRollback、
// RemoteFileList、PanelManifest、GitBlobSHA、FetchRaw、RemoteVersion 等。
package panelupdate

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"shunt/internal/base"
	"shunt/internal/coreupdate"
)

// PanelRaw 对应 PANEL_RAW（环境变量可覆盖）。
var PanelRaw = getenv("PANEL_RAW", "https://raw.githubusercontent.com/Skycnhe/Shunt/Hk002")

// UpdFiles 对应 UPD_FILES：内置部署文件清单（拿不到仓库清单时的回退）。
var UpdFiles = []string{"server.py", "index.html", "tproxy.sh", "selftest.sh", "init.d/shunt", "init.d/shunt-core"}

// UpdList 对应 UPD_LIST：仓库里的部署文件清单文件名。
const UpdList = "update-files.txt"

var updPathRe = regexp.MustCompile(`^[\w.\-]+(/[\w.\-]+)*$`)
var panelRawRe = regexp.MustCompile(`^https://raw\.githubusercontent\.com/([^/]+/[^/]+)/(.+?)/?$`)
var panelVerRe = regexp.MustCompile(`(?m)^PANEL_VERSION = "([^"]+)"`)

// RemoteFileList 对应 remote_file_list(gh, commit, shas)：
// 读取仓库里的部署文件清单（必须通过 GitHub 校验）；
// 没有或拿不到校验值时用内置列表。
func RemoteFileList(gh, commit string, shas map[string]string) ([]string, error) {
	if len(shas) == 0 {
		return slices.Clone(UpdFiles), nil
	}
	sha, ok := shas[UpdList]
	if !ok {
		return slices.Clone(UpdFiles), nil
	}
	raw, err := FetchRaw(UpdList, gh, commit, sha)
	if err != nil {
		return nil, err
	}
	return parseFileList(string(raw), shas)
}

// parseFileList 是 RemoteFileList 的纯函数核心（可测试）：解析并校验清单内容。
func parseFileList(raw string, shas map[string]string) ([]string, error) {
	var out []string
	for _, ln := range strings.Split(raw, "\n") {
		f := strings.TrimSpace(strings.SplitN(ln, "#", 2)[0])
		if f == "" {
			continue
		}
		if !updPathRe.MatchString(f) || slices.Contains(strings.Split(f, "/"), "..") || strings.HasPrefix(f, ".") {
			return nil, fmt.Errorf("部署清单里有不安全的路径：%s", f)
		}
		if _, ok := shas[f]; !ok {
			return nil, fmt.Errorf("部署清单里的 %s 在仓库中不存在", f)
		}
		out = append(out, f)
	}
	for _, need := range []string{"server.py", "index.html"} {
		if !slices.Contains(out, need) {
			return nil, fmt.Errorf("部署清单缺少 %s", need)
		}
	}
	return out, nil
}

// PanelManifest 对应 panel_manifest()：返回 (commit, {路径: git blob sha1})；
// 失败返回 ("", {})。
func PanelManifest() (string, map[string]string) {
	fail := func() (string, map[string]string) { return "", map[string]string{} }
	m := panelRawRe.FindStringSubmatch(PanelRaw)
	if m == nil {
		return fail()
	}
	c, err := coreupdate.GhAPI("/repos/"+m[1]+"/commits/"+m[2], 15)
	if err != nil {
		logErrSafe("获取面板校验值", err)
		return fail()
	}
	treeSHA := nestedStr(c, "commit", "tree", "sha")
	t, err := coreupdate.GhAPI("/repos/"+m[1]+"/git/trees/"+treeSHA+"?recursive=1", 15)
	if err != nil {
		logErrSafe("获取面板校验值", err)
		return fail()
	}
	shas := map[string]string{}
	for _, x := range listOf(t, "tree") {
		xm, _ := x.(map[string]any)
		if xm == nil || strOf(xm, "type") != "blob" {
			continue
		}
		shas[strOf(xm, "path")] = strOf(xm, "sha")
	}
	return strOf(c, "sha"), shas
}

func nestedStr(m map[string]any, keys ...string) string {
	var cur any = m
	for _, k := range keys {
		cm, _ := cur.(map[string]any)
		if cm == nil {
			return ""
		}
		cur = cm[k]
	}
	s, _ := cur.(string)
	return s
}

func listOf(m map[string]any, key string) []any {
	l, _ := m[key].([]any)
	return l
}

func strOf(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// GitBlobSHA 对应 git_blob_sha(data)：git blob 对象的 SHA1。
func GitBlobSHA(data []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(data))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// FetchRaw 对应 fetch_raw(f, gh, commit=None, sha=None)：下载面板文件。
// 有 GitHub 给的校验值时可以走加速镜像，下载后逐个比对；没有校验值时不走镜像。
// 每条线路的失败原因都会汇总，便于判断是代理还是直连的问题。
func FetchRaw(f, gh, commit, sha string) ([]byte, error) {
	baseURL := strings.TrimRight(PanelRaw, "/")
	if commit != "" {
		baseURL = baseURL[:strings.LastIndex(baseURL, "/")+1] + commit
	}
	u := baseURL + "/" + f
	if sha == "" {
		gh = ""
	}
	type urlTry struct {
		url      string
		useProxy bool
	}
	var tries []urlTry
	if gh != "" {
		tries = append(tries, urlTry{strings.TrimRight(gh, "/") + "/" + u, false})
	}
	tries = append(tries, urlTry{u, true}, urlTry{u, false}) // 先经 mihomo 代理，再直连
	var errs []string
	for _, tr := range tries {
		data, err := fetchTry(f, tr.url, tr.useProxy, sha)
		if err != nil {
			label := "(直连)"
			if tr.useProxy {
				label = "(代理)"
			}
			errs = append(errs, fmt.Sprintf("%s%s: %s", hostOf(tr.url), label, truncate(err.Error(), 120)))
			continue
		}
		return data, nil
	}
	return nil, fmt.Errorf("下载 %s 失败：%s", f, strings.Join(errs, "；"))
}

// fetchTry 单次下载尝试；stub 未接线时的 panic 收敛为本轮错误，
// 与 Python try/except 逐个尝试的语义一致。
func fetchTry(f, rawurl string, useProxy bool, sha string) (data []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			data, err = nil, fmt.Errorf("%v", r)
		}
	}()
	if err := base.DlCheck(rawurl, useProxy); err != nil { // SSRF 防护
		return nil, err
	}
	sep := "?"
	if strings.Contains(rawurl, "?") {
		sep = "&"
	}
	cacheBust := fmt.Sprintf("%s%st=%d", rawurl, sep, time.Now().Unix())
	resp, err := proxyOpener(useProxy).Open(cacheBust, base.Ua, 20)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err = io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if sha != "" && GitBlobSHA(data) != sha {
		return nil, fmt.Errorf("文件校验失败（与 GitHub 上的不一致，可能被加速镜像篡改）")
	}
	return data, nil
}

// SelfRollback 对应 self_rollback()：把 .backup 里的文件（上次更新前的版本）全部放回去。
func SelfRollback() (bool, string) {
	bak := filepath.Join(base.Base, ".backup")
	if !isFile(filepath.Join(bak, "server.py")) {
		return false, "没有可回滚的备份"
	}
	if !base.UpdBegin("panel") {
		return false, base.UpdBusyMsg()
	}
	defer base.UpdEnd("panel")
	err := filepath.WalkDir(bak, func(path string, de fs.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return err
		}
		rel, err := filepath.Rel(bak, path)
		if err != nil {
			return err
		}
		dst := base.LocalFile(rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return copyFileMode(path, dst) // 对应 shutil.copy2
	})
	if err != nil {
		return false, err.Error()
	}
	restartSelf()
	return true, "已回滚到更新前的版本，面板正在重启"
}

// undoReplace 对应 _undo_replace(done, bak)：替换到一半失败时，已替换的文件
// 放回旧版（新增的文件删掉），不留下混合版本。
func undoReplace(done []string, bak string) {
	for _, f := range done {
		dst, src := base.LocalFile(f), filepath.Join(bak, f)
		func() {
			defer func() {
				if r := recover(); r != nil {
					logErrSafe("面板更新失败后恢复 "+f, fmt.Errorf("%v", r))
				}
			}()
			if isFile(src) {
				if err := copyFile(src, dst+".new"); err != nil {
					panic(err)
				}
				if err := os.Rename(dst+".new", dst); err != nil {
					panic(err)
				}
			} else { // 新增的文件：删掉
				if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
					panic(err)
				}
			}
		}()
	}
}

// RemoteVersion 对应 remote_version(src)：从 server.py 源码提取 PANEL_VERSION。
func RemoteVersion(src []byte) string {
	m := panelVerRe.FindSubmatch(src)
	if m == nil {
		return "?"
	}
	return string(m[1])
}

// pySyntaxCheck 对应 self_update 中的 compile(server.py)：有 python3 时做语法校验，
// 没有时跳过（Go 侧无内置 Python 解析器）。
func pySyntaxCheck(src []byte) error {
	p, err := exec.LookPath("python3")
	if err != nil {
		return nil
	}
	tmp, err := os.CreateTemp("", "server-*.py")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(src); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	out, err := exec.Command(p, "-m", "py_compile", tmp.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SelfUpdate 对应 self_update(apply=False, gh="")：
// 检查 / 应用 GitHub 上的新版面板：下载全部文件 → 校验 → 备份 → 替换 → 重启面板。
// 只检查不替换时不占用忙标志；真正更新时与内核更新/切换/回滚互斥。
func SelfUpdate(apply bool, gh string) (ok bool, info map[string]any) {
	if apply && !base.UpdBegin("panel") {
		return false, map[string]any{"message": base.UpdBusyMsg()}
	}
	if apply {
		defer base.UpdEnd("panel")
	}
	defer func() {
		// 对应 except Exception：stub 未接线或真实异常都转为 (False, {message})，
		// 不让后台 goroutine 直接崩溃。
		if r := recover(); r != nil {
			ok = false
			info = map[string]any{"message": fmt.Sprint(r)}
		}
	}()
	files := map[string][]byte{}
	var changed []string
	commit, shas := PanelManifest()
	flist, err := RemoteFileList(gh, commit, shas)
	if err != nil {
		return false, map[string]any{"message": err.Error()}
	}
	for _, f := range flist {
		data, err := FetchRaw(f, gh, commit, shas[f])
		if err != nil {
			return false, map[string]any{"message": err.Error()}
		}
		files[f] = data
		local, err := os.ReadFile(base.LocalFile(f)) // 逐字节比对
		if err != nil || !bytes.Equal(local, data) {
			changed = append(changed, f)
		}
	}
	info = map[string]any{
		"current":  base.PanelVersion,
		"remote":   RemoteVersion(files["server.py"]),
		"changed":  changed,
		"source":   PanelRaw,
		"verified": len(shas) > 0,
		"commit":   truncate(commit, 10),
	}
	if !apply {
		if len(changed) == 0 {
			info["message"] = "已是最新"
		} else {
			info["message"] = fmt.Sprintf("有 %d 个文件可更新", len(changed))
		}
		return true, info
	}
	if len(changed) == 0 {
		info["message"] = "已是最新，无需更新"
		return true, info
	}
	// 校验：Python 语法、HTML 完整、shell 语法
	if err := pySyntaxCheck(files["server.py"]); err != nil {
		return false, map[string]any{"message": "新版 server.py 语法错误：" + err.Error()}
	}
	if !bytes.Contains(files["index.html"], []byte("</html>")) ||
		!bytes.Contains(files["index.html"], []byte("<script>")) {
		return false, map[string]any{"message": "新版 index.html 不完整"}
	}
	tmpd := filepath.Join(base.Base, ".update")
	os.RemoveAll(tmpd)
	for f, data := range files {
		p := filepath.Join(tmpd, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return false, map[string]any{"message": err.Error()}
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			return false, map[string]any{"message": err.Error()}
		}
		if strings.HasSuffix(f, ".sh") || strings.HasPrefix(f, "init.d/") {
			code, out := shRun("sh -n "+shellQuote(p), 60) // f 来自远端清单：引用防注入
			if code != 0 {
				return false, map[string]any{"message": fmt.Sprintf("新版 %s 语法错误：%s", f, tailStr(out, 200))}
			}
		}
	}
	bak := filepath.Join(base.Base, ".backup")
	os.RemoveAll(bak)
	if err := os.MkdirAll(bak, 0o755); err != nil {
		return false, map[string]any{"message": err.Error()}
	}
	for _, f := range flist {
		if isFile(base.LocalFile(f)) {
			bp := filepath.Join(bak, f)
			if err := os.MkdirAll(filepath.Dir(bp), 0o755); err != nil {
				return false, map[string]any{"message": err.Error()}
			}
			if err := copyFileMode(base.LocalFile(f), bp); err != nil {
				return false, map[string]any{"message": err.Error()}
			}
		}
	}
	// 版本备份：更新前自动打一个带版本号的 tar.gz（失败不阻断更新）
	tryBackupCreate()
	var done []string
	for _, f := range changed {
		dst := base.LocalFile(f)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			undoReplace(done, bak)
			return false, map[string]any{"message": "替换文件失败，已恢复原文件：" + err.Error()}
		}
		if err := copyFile(filepath.Join(tmpd, f), dst+".new"); err != nil {
			undoReplace(done, bak)
			return false, map[string]any{"message": "替换文件失败，已恢复原文件：" + err.Error()}
		}
		mode := os.FileMode(0o644)
		if strings.HasSuffix(f, ".sh") || strings.HasPrefix(f, "init.d/") {
			mode = 0o755
		}
		os.Chmod(dst+".new", mode)
		if err := os.Rename(dst+".new", dst); err != nil {
			undoReplace(done, bak)
			return false, map[string]any{"message": "替换文件失败，已恢复原文件：" + err.Error()}
		}
		done = append(done, f)
	}
	os.RemoveAll(tmpd)
	startUpdateGuard(flist)
	restartSelf()
	verified := ""
	if len(shas) > 0 {
		verified = "，已通过 GitHub 校验"
	}
	info["message"] = fmt.Sprintf("已更新 %d 个文件（%s）%s，面板正在重启；新版启动失败会在 90 秒内自动回滚",
		len(changed), strings.Join(changed, "、"), verified)
	return true, info
}

// tryBackupCreate 对应更新前的自动版本备份：失败不阻断更新。
// backup 未接线（stub panic）或返回失败时只记录，不中断。
func tryBackupCreate() {
	defer func() { _ = recover() }()
	ok, name := backupCreate()
	if !ok {
		logErrSafe("面板在线更新", fmt.Errorf("更新前自动备份失败：%s", name))
	}
}
