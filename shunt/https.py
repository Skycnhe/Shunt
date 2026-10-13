"""HTTPS"""
import os, shlex, socket, ssl, sys
from http.server import ThreadingHTTPServer

from .base import CERT, KEY, PANEL_DIR, PANEL_SVC
from .sysopt import sh


def _lan_ip():
    """本机局域网 IP：UDP connect 只查路由出口地址，不实际发包；拿不到返回空串"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return ""


def gen_cert():
    if not sh("command -v openssl")[1]:
        sh("apk add --no-cache openssl", timeout=120)
    os.makedirs(PANEL_DIR, exist_ok=True)
    san = "DNS:shunt.lan"
    ip = _lan_ip()
    if ip:
        san += f",IP:{ip}"
    code, out = sh(f"openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj '/CN=Shunt' "
                   f"-addext 'subjectAltName={san}' "
                   f"-keyout '{KEY}' -out '{CERT}'", timeout=120)
    if code == 0:
        os.chmod(KEY, 0o600)
    return code == 0, out


def https_ready(d):
    return bool(d.get("https")) and os.path.isfile(CERT) and os.path.isfile(KEY)


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        e = sys.exc_info()[1]
        if isinstance(e, (ssl.SSLError, ConnectionError, socket.timeout, BrokenPipeError)):
            return  # 浏览器用 http 访问 https 端口、客户端断开等，静默忽略
        super().handle_error(request, client_address)


_DEFAULT_RESTART = "rc-service " + PANEL_SVC + " restart"  # 可信默认值（含参数，直接拼）


def restart_self():
    cmd = os.environ.get("PANEL_RESTART")
    if cmd is None:
        cmd = _DEFAULT_RESTART
    else:
        cmd = shlex.quote(cmd)  # 环境变量来源不可信：整体引用为单个词，防止注入
    sh(f"(sleep 1; {cmd}) >/dev/null 2>&1 &")
