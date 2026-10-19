// Package backup 对应 Python shunt/backup.py：版本备份/恢复——把面板文件打包成带版本号的 tar.gz，支持一键回滚。
package backup

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"shunt/internal/base"
)

// BackupDir 备份目录：跟 data.json 同级
var BackupDir = func() string {
	abs, err := filepath.Abs(base.DataFile)
	if err != nil {
		abs = base.DataFile
	}
	return filepath.Join(filepath.Dir(abs), "backups")
}()

// KeepN 保留最近多少个备份
const KeepN = 10

// 打包进备份的文件（相对于 BASE）
var files = []string{"server.py", "index.html", "CHANGELOG.md"}

// BackupInfo 备份条目
type BackupInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Size    int64  `json:"size"`
	Mtime   int64  `json:"mtime"`
}

func ensureDir() error {
	return os.MkdirAll(BackupDir, 0o700)
}

// fixPerms 备份里有 data.json（订阅 URL、节点密码、TG token）：旧版按默认 umask 建成 644 的收紧为 600
func fixPerms() {
	_ = os.Chmod(BackupDir, 0o700)
	entries, err := os.ReadDir(BackupDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".tar.gz") || e.IsDir() {
			continue
		}
		fp := filepath.Join(BackupDir, e.Name())
		if st, err := os.Stat(fp); err == nil && st.Mode().Perm()&0o077 != 0 {
			_ = os.Chmod(fp, 0o600)
		}
	}
}

var unsafeVerRe = regexp.MustCompile(`[^0-9A-Za-z.\-]`)

func backupName(version, ts string) string {
	if ts == "" {
		ts = time.Now().Format("20060102-150405")
	}
	// 版本号里的非法字符替换掉，保证文件名安全
	safeVer := unsafeVerRe.ReplaceAllString(orUnknown(version), "_")
	return fmt.Sprintf("shunt-backup-v%s-%s.tar.gz", safeVer, ts)
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

var nameRe = regexp.MustCompile(`^shunt-backup-v(.+?)-(\d{8}-\d{6})(-\d+)?\.tar\.gz$`)

// ParseName 从文件名解析出 version，失败返回 ""
func ParseName(name string) string {
	m := nameRe.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	return m[1]
}

// Create 创建备份，失败不抛异常。返回 (ok, name_or_message)。
// version: 打上的版本号，默认当前 PanelVersion。
// keep: 清理旧备份时必须保留的文件名（恢复时保住正要恢复的那个）。
func Create(version, keep string) (bool, string) {
	if version == "" {
		version = base.PanelVersion
	}
	if err := ensureDir(); err != nil {
		return false, err.Error()
	}
	name := backupName(version, "")
	path := filepath.Join(BackupDir, name)
	// 同名极小概率冲突（同一秒两次），加后缀
	for i := 1; fileExists(path); i++ {
		name = strings.TrimSuffix(backupName(version, ""), ".tar.gz") + fmt.Sprintf("-%d.tar.gz", i)
		path = filepath.Join(BackupDir, name)
	}
	// 一开始就以 600 创建（不经过默认 umask 的 644 窗口）；O_EXCL 防止同名覆盖
	fd, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, err.Error()
	}
	werr := func() error {
		gz := gzip.NewWriter(fd)
		tw := tar.NewWriter(gz)
		addFile := func(src, arcname string) error {
			fi, err := os.Stat(src)
			if err != nil || fi.IsDir() {
				return nil // 不存在就跳过（Python 的 tf.add 只在 isfile 时调用）
			}
			hdr, err := tar.FileInfoHeader(fi, "")
			if err != nil {
				return err
			}
			hdr.Name = arcname
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			f, err := os.Open(src)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.Copy(tw, f)
			return err
		}
		for _, rel := range files {
			if err := addFile(filepath.Join(base.Base, rel), rel); err != nil {
				return err
			}
		}
		if err := addFile(base.DataFile, "data.json"); err != nil {
			return err
		}
		if err := tw.Close(); err != nil {
			return err
		}
		return gz.Close()
	}()
	_ = fd.Close()
	if werr != nil {
		_ = os.Remove(path)
		return false, werr.Error()
	}
	Cleanup(KeepN, keep)
	return true, name
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// List 返回备份列表，按时间倒序
func List() []BackupInfo {
	_ = ensureDir()
	fixPerms()
	var out []BackupInfo
	entries, err := os.ReadDir(BackupDir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		fn := e.Name()
		if !strings.HasSuffix(fn, ".tar.gz") {
			continue
		}
		ver := ParseName(fn)
		if ver == "" {
			continue
		}
		st, err := os.Stat(filepath.Join(BackupDir, fn))
		if err != nil {
			continue
		}
		out = append(out, BackupInfo{Name: fn, Version: ver, Size: st.Size(), Mtime: st.ModTime().Unix()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mtime > out[j].Mtime })
	return out
}

// backupPath 校验备份文件名并返回 (路径, 错误)：拒绝路径穿越、不是备份格式的名字和不存在的文件
func backupPath(name string) (string, string) {
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "..") {
		return "", "非法文件名"
	}
	if ParseName(name) == "" {
		return "", "不是有效的备份文件"
	}
	fp := filepath.Join(BackupDir, name)
	if !fileExists(fp) {
		return "", "备份不存在"
	}
	return fp, ""
}

// Delete 删除指定备份。返回 (ok, message)
func Delete(name string) (bool, string) {
	fp, errMsg := backupPath(name)
	if errMsg != "" {
		return false, errMsg
	}
	if err := os.Remove(fp); err != nil {
		return false, err.Error()
	}
	return true, "已删除"
}

// Cleanup 只保留最近 keep 个，删除最旧的（protect 指定的文件不删）
func Cleanup(keep int, protect string) {
	all := List()
	var items []BackupInfo
	for _, it := range all {
		if it.Name != protect {
			items = append(items, it)
		}
	}
	start := keep - (len(all) - len(items))
	if start < 0 {
		start = 0
	}
	if start > len(items) {
		start = len(items)
	}
	for _, it := range items[start:] {
		_ = os.Remove(filepath.Join(BackupDir, it.Name))
	}
}

// Restore 恢复指定备份。返回 (ok, message)。
// 流程：先自动备份当前版本（防呆）→ 解压覆盖 server.py/index.html/data.json。
// 恢复 server.py 后需重启面板进程才生效。
func Restore(name string) (bool, string) {
	fp, errMsg := backupPath(name)
	if errMsg != "" {
		return false, errMsg
	}
	// 防呆：先备份当前。已有 10 个备份时，新备份会挤掉最旧的一个——恰好是要恢复的这个时以前会把它删掉再报「恢复失败」
	ok, cur := Create("", name)
	if !ok {
		return false, "备份当前版本失败，中止恢复：" + cur
	}
	if errMsg := extract(fp); errMsg != "" {
		return false, errMsg
	}
	return true, "已恢复到 " + name + "（已自动备份当前版本 " + cur + "）。恢复 server.py 后需重启面板生效。"
}

func extract(fp string) string {
	f, err := os.Open(fp)
	if err != nil {
		return "恢复失败：" + err.Error()
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "恢复失败：" + err.Error()
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	// 解压到唯一临时目录再搬，避免半截覆盖和并发冲突
	tmpd, err := os.MkdirTemp(BackupDir, "restore_")
	if err != nil {
		return "恢复失败：" + err.Error()
	}
	defer os.RemoveAll(tmpd)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "恢复失败：" + err.Error()
		}
		// 安全检查：不允许绝对路径、..、symlink/hardlink
		if strings.HasPrefix(hdr.Name, "/") || strings.Contains(hdr.Name, "..") {
			return "备份文件内容非法"
		}
		if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink {
			return "备份文件含非法链接"
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		dst := filepath.Join(tmpd, filepath.Clean(hdr.Name))
		if !strings.HasPrefix(dst, tmpd+string(os.PathSeparator)) {
			return "备份文件内容非法"
		}
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return "恢复失败：" + err.Error()
		}
		_, err = io.Copy(out, tr)
		_ = out.Close()
		if err != nil {
			return "恢复失败：" + err.Error()
		}
	}
	move := func(rel, dst string, mode os.FileMode) error {
		src := filepath.Join(tmpd, rel)
		if !fileExists(src) {
			return nil
		}
		nw := dst + ".new"
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(nw, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, in)
		_ = out.Close()
		if err != nil {
			return err
		}
		_ = os.Chmod(nw, mode)
		return os.Rename(nw, dst)
	}
	// 搬文件
	for _, rel := range files {
		if err := move(rel, filepath.Join(base.Base, rel), 0o644); err != nil {
			return "恢复失败：" + err.Error()
		}
	}
	if err := move("data.json", base.DataFile, 0o600); err != nil {
		return "恢复失败：" + err.Error()
	}
	return ""
}
