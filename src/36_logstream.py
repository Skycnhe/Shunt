# ---------------------------------------------------------------- 实时日志 (SSE)
def core_stream(path, sink, stop, idle=None):
    """以原始 socket 读取 mihomo 的 chunked JSON 行流，逐行回调 sink；stop 被置位或连接断开时结束。
    idle: 超过该秒数没有数据视为断线（/traffic /memory 每秒推送，可用来发现半开连接）"""
    d = load()
    s = socket.create_connection((CTRL_HOST, CTRL_PORT), timeout=10)
    stop["sock"] = s
    s.settimeout(idle)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: {CTRL_HOST}\r\nAuthorization: Bearer {d['secret']}\r\nConnection: close\r\n\r\n".encode())
    f = s.makefile("rb")
    status = f.readline().decode("latin1")
    chunked = False
    while True:
        h = f.readline()
        if h in (b"\r\n", b"\n", b""):
            break
        if h.lower().startswith(b"transfer-encoding:") and b"chunked" in h.lower():
            chunked = True
    if " 200" not in status:
        raise IOError("mihomo 返回 " + status.strip())
    buf = b""
    while not stop.get("stop"):
        if chunked:
            size_line = f.readline()
            if not size_line:
                break
            size = int(size_line.split(b";")[0].strip() or b"0", 16)
            if size == 0:
                break
            data = f.read(size)
            f.readline()
        else:
            data = f.readline()
            if not data:
                break
        buf += data
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if line.strip():
                sink(line.decode("utf-8", "ignore"))


