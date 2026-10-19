// Package https 对应 Python shunt/https.py：HTTPS 证书生成、面板自重启。
package https

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"shunt/internal/base"
	"shunt/internal/data"
	"shunt/internal/sysopt"
)

// LanIP 对应 _lan_ip()：本机局域网 IP（UDP connect 只查路由出口地址，不实际发包）；拿不到返回空串。
func LanIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return ""
}

// GenCert 对应 gen_cert()：生成自签名证书。返回 (成功, 输出)。
func GenCert() (bool, string) {
	if _, out := sysopt.Sh("command -v openssl"); out == "" {
		sysopt.Sh("apk add --no-cache openssl", 120)
	}
	if err := os.MkdirAll(base.PanelDir, 0o755); err != nil {
		return false, err.Error()
	}
	san := "DNS:shunt.lan"
	if ip := LanIP(); ip != "" {
		san += ",IP:" + ip
	}
	code, out := sysopt.Sh(fmt.Sprintf(
		"openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj '/CN=Shunt' "+
			"-addext 'subjectAltName=%s' -keyout %s -out %s",
		san, shellQuote(base.KeyFile), shellQuote(base.CertFile)), 120)
	if code == 0 {
		_ = os.Chmod(base.KeyFile, 0o600)
	}
	return code == 0, out
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\\''`) + "'"
}

// HttpsReady 对应 https_ready(d)：开启 https 且证书存在。
func HttpsReady(d map[string]any) bool {
	return data.Bool(d, "https") && fileExists(base.CertFile) && fileExists(base.KeyFile)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// Server 对应 https.Server：ThreadingHTTPServer 的 Go 等价。
// Python 的 handle_error 对 SSL/连接类错误（浏览器用 http 访问 https 端口、客户端断开等）静默忽略，
// 这里对应丢弃 http.Server 的 ErrorLog。
type Server struct {
	*http.Server
}

// NewServer 创建面板 HTTP(S) 服务器。
func NewServer(addr string, handler http.Handler) *Server {
	return &Server{&http.Server{
		Addr:     addr,
		Handler:  handler,
		ErrorLog: log.New(io.Discard, "", 0),
	}}
}

// defaultRestart 对应 _DEFAULT_RESTART
var defaultRestart = "rc-service " + base.PanelSvc + " restart"

// RestartSelf 对应 restart_self()：延迟 1 秒后重启面板服务（脱离当前进程）。
func RestartSelf() {
	cmd, ok := os.LookupEnv("PANEL_RESTART")
	if !ok {
		cmd = defaultRestart // 可信默认值（含参数，直接拼）
	} else {
		cmd = shellQuote(cmd) // 环境变量来源不可信：整体引用为单个词，防止注入
	}
	sysopt.Sh(fmt.Sprintf("(sleep 1; %s) >/dev/null 2>&1 &", cmd))
}
