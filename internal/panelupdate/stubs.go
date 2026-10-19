package panelupdate

// 本文件集中声明 panelupdate 依赖的外部模块 stub。
// 各模块移植完成，stub 已全部接线到真实实现（直接赋值或小适配闭包）；
// `// STUB:<包>.<函数>` 注释保留，标注每个接线的来源。

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"shunt/internal/backup"
	"shunt/internal/errlog"
	"shunt/internal/https"
	"shunt/internal/sysopt"
	"shunt/internal/updateguard"
)

// httpResponse 对应 proxy_opener(...).open(...) 返回的响应对象。
type httpResponse struct {
	Body          io.ReadCloser
	ContentLength int64
	FinalURL      string
}

// opener 是 proxy_opener 返回对象的最小接口（STUB:sysopt.proxy_opener 的边界）。
type opener interface {
	Open(rawurl, ua string, timeoutSec int) (*httpResponse, error)
}

// STUB:sysopt.proxy_opener
// Go 侧对应 sysopt.ProxyClient(proxy) *http.Client（已含 SafeRedirectHandler
// 语义的重定向 SSRF 校验）；这里适配成调用方期望的 opener 接口
// （Open 做一次 GET，带 UA 与超时，返回 Body/ContentLength/FinalURL）。
var proxyOpener = func(proxy bool) opener { return proxyOpenAdapter{proxy: proxy} }

type proxyOpenAdapter struct{ proxy bool }

func (a proxyOpenAdapter) Open(rawurl, ua string, timeoutSec int) (*httpResponse, error) {
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	client := sysopt.ProxyClient(a.proxy)
	client.Timeout = time.Duration(timeoutSec) * time.Second
	req, err := http.NewRequest(http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	finalURL := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	return &httpResponse{Body: resp.Body, ContentLength: resp.ContentLength, FinalURL: finalURL}, nil
}

// STUB:sysopt.sh
var shRun = func(cmd string, timeoutSec int) (int, string) { return sysopt.Sh(cmd, timeoutSec) }

// STUB:https.restart_self
var restartSelf = https.RestartSelf

// STUB:update_guard.start_update_guard
var startUpdateGuard = updateguard.StartUpdateGuard

// STUB:backup.create
// Python 签名 create(version=None, keep=None)：version 缺省取当前 PANEL_VERSION，
// keep 缺省 None；Go 侧 Create("", "") 即按同样的缺省处理。
var backupCreate = func() (bool, string) { return backup.Create("", "") }

// STUB:errlog.log_err
// Python 默认 tb=False，调用处均未传 tb，沿用。
var logErr = func(where string, err error) { errlog.LogErr(where, err, false) }

// logErrSafe 在"Python 会吞掉异常"的路径上调用 log_err：
// stub 未接线时静默跳过，避免二次 panic。
func logErrSafe(where string, err error) {
	defer func() { _ = recover() }()
	logErr(where, err)
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

// copyFile 对应 shutil.copyfile：只复制内容。
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
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

var shellSafeRe = regexp.MustCompile(`^[a-zA-Z0-9_@%+=:,./-]+$`)

// shellQuote 对应 shlex.quote 的常用情形（路径/命令片段）。
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if shellSafeRe.MatchString(s) {
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

func hostOf(rawurl string) string {
	if u, err := url.Parse(rawurl); err == nil {
		return u.Hostname()
	}
	return ""
}
