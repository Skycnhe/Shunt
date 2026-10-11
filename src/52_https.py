# ---------------------------------------------------------------- HTTPS
def gen_cert():
    if not sh("command -v openssl")[1]:
        sh("apk add --no-cache openssl", timeout=120)
    os.makedirs(PANEL_DIR, exist_ok=True)
    code, out = sh(f"openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj '/CN=Shunt' "
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


def restart_self():
    sh("(sleep 1; %s) >/dev/null 2>&1 &" % os.environ.get("PANEL_RESTART", "rc-service mihomo-panel restart"))


