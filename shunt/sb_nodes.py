"""节点：mihomo 字段 → sing-box outbound"""
import re
def _sb_tls(p, sni_key="servername", force=False):
    if not (p.get("tls") or force):
        return None
    t = {"enabled": True}
    sni = p.get(sni_key) or p.get("sni") or p.get("servername")
    if sni:
        t["server_name"] = str(sni)
    if p.get("skip-cert-verify"):
        t["insecure"] = True
    if p.get("alpn"):
        t["alpn"] = [str(a) for a in (p["alpn"] if isinstance(p["alpn"], list) else str(p["alpn"]).split(","))]
    if p.get("disable-sni"):
        t["disable_sni"] = True
    fp = p.get("client-fingerprint")
    ro = p.get("reality-opts")
    if ro:
        t["reality"] = {"enabled": True, "public_key": str(ro.get("public-key") or ""), "short_id": str(ro.get("short-id") or "")}
        fp = fp or "chrome"
    if fp and fp not in ("none",):
        t["utls"] = {"enabled": True, "fingerprint": "chrome" if fp == "random" else str(fp)}
    return t


def _sb_transport(p):
    net = (p.get("network") or "tcp").lower()
    if net == "ws":
        o = p.get("ws-opts") or {}
        path = str(o.get("path") or "/")
        hdr = {k: (v[0] if isinstance(v, list) else str(v)) for k, v in (o.get("headers") or {}).items()}
        if o.get("v2ray-http-upgrade"):
            t = {"type": "httpupgrade", "path": path}
            if hdr.get("Host"):
                t["host"] = hdr.pop("Host")
            if hdr:
                t["headers"] = hdr
            return t
        t = {"type": "ws", "path": path}
        m = re.search(r"[?&]ed=(\d+)", path)
        if m:
            t["path"] = re.sub(r"[?&]ed=\d+", "", path) or "/"
            t["max_early_data"], t["early_data_header_name"] = int(m.group(1)), "Sec-WebSocket-Protocol"
        elif o.get("max-early-data"):
            t["max_early_data"] = int(o["max-early-data"])
            t["early_data_header_name"] = o.get("early-data-header-name") or "Sec-WebSocket-Protocol"
        if hdr:
            t["headers"] = hdr
        return t
    if net == "grpc":
        return {"type": "grpc", "service_name": str((p.get("grpc-opts") or {}).get("grpc-service-name") or "")}
    if net == "h2":
        o = p.get("h2-opts") or {}
        t = {"type": "http", "path": str(o.get("path") or "/")}
        if o.get("host"):
            t["host"] = [str(h) for h in (o["host"] if isinstance(o["host"], list) else [o["host"]])]
        return t
    if net == "http":
        o = p.get("http-opts") or {}
        path = o.get("path") or ["/"]
        t = {"type": "http", "path": str(path[0] if isinstance(path, list) else path), "method": str(o.get("method") or "GET")}
        hosts = (o.get("headers") or {}).get("Host")
        if hosts:
            t["host"] = [str(h) for h in (hosts if isinstance(hosts, list) else [hosts])]
        return t
    if net in ("tcp", ""):
        return None
    raise ValueError(f"sing-box 不支持传输方式 {net}")


def _mbps(v):
    m = re.match(r"\s*(\d+)", str(v or ""))
    return int(m.group(1)) if m else 0


def sb_outbound(p, tag):
    """返回 sing-box outbound；不支持的协议抛 ValueError"""
    if p.get("_sb"):
        o = dict(p["_sb"])
        o["tag"] = tag
        return o
    t = str(p.get("type") or "").lower()
    o = {"tag": tag, "server": str(p.get("server") or ""), "server_port": int(p.get("port") or 0)}
    if not o["server"] or not o["server_port"]:
        raise ValueError("缺少服务器或端口")
    if t == "ss":
        o.update(type="shadowsocks", method=str(p.get("cipher") or ""), password=str(p.get("password") or ""))
        pl, po = p.get("plugin"), p.get("plugin-opts") or {}
        if pl == "obfs":
            o["plugin"], o["plugin_opts"] = "obfs-local", f"obfs={po.get('mode', 'http')};obfs-host={po.get('host', 'bing.com')}"
        elif pl == "v2ray-plugin":
            opts = [f"mode={po.get('mode', 'websocket')}"] + ([f"host={po['host']}"] if po.get("host") else []) + \
                   ([f"path={po['path']}"] if po.get("path") else []) + (["tls"] if po.get("tls") else [])
            o["plugin"], o["plugin_opts"] = "v2ray-plugin", ";".join(opts)
        elif pl:
            raise ValueError(f"sing-box 不支持 ss 插件 {pl}")
        if p.get("udp-over-tcp"):
            o["udp_over_tcp"] = True
    elif t == "vmess":
        o.update(type="vmess", uuid=str(p.get("uuid") or ""), security=str(p.get("cipher") or "auto"), alter_id=int(p.get("alterId") or 0))
    elif t == "vless":
        o.update(type="vless", uuid=str(p.get("uuid") or ""), packet_encoding="xudp")
        if p.get("flow"):
            o["flow"] = str(p["flow"])
    elif t == "trojan":
        o.update(type="trojan", password=str(p.get("password") or ""))
        o["tls"] = _sb_tls(p, "sni", force=True)
    elif t == "hysteria2":
        o.update(type="hysteria2", password=str(p.get("password") or ""))
        if p.get("ports"):
            o["server_ports"] = [x.strip().replace("-", ":") if "-" in x else f"{x.strip()}:{x.strip()}"
                                 for x in str(p["ports"]).replace("/", ",").split(",") if x.strip()]
        if p.get("obfs"):
            o["obfs"] = {"type": str(p["obfs"]), "password": str(p.get("obfs-password") or "")}
        for k, sk in (("up", "up_mbps"), ("down", "down_mbps")):
            if _mbps(p.get(k)):
                o[sk] = _mbps(p.get(k))
        o["tls"] = _sb_tls(p, "sni", force=True)
    elif t == "tuic":
        o.update(type="tuic", uuid=str(p.get("uuid") or ""), password=str(p.get("password") or ""),
                 congestion_control=str(p.get("congestion-controller") or "bbr"),
                 udp_relay_mode=str(p.get("udp-relay-mode") or "native"))
        if p.get("reduce-rtt"):
            o["zero_rtt_handshake"] = True
        o["tls"] = _sb_tls(dict(p, alpn=p.get("alpn") or ["h3"]), "sni", force=True)
    elif t == "hysteria":
        o.update(type="hysteria", up_mbps=_mbps(p.get("up")) or 10, down_mbps=_mbps(p.get("down")) or 50)
        if p.get("auth-str") or p.get("auth_str"):
            o["auth_str"] = str(p.get("auth-str") or p.get("auth_str"))
        if p.get("obfs"):
            o["obfs"] = str(p["obfs"])
        o["tls"] = _sb_tls(p, "sni", force=True)
    elif t == "anytls":
        o.update(type="anytls", password=str(p.get("password") or ""))
        o["tls"] = _sb_tls(p, "sni", force=True)
    elif t in ("http", "socks5"):
        o["type"] = "http" if t == "http" else "socks"
        if t == "socks5":
            o["version"] = "5"
        if p.get("username"):
            o["username"], o["password"] = str(p["username"]), str(p.get("password") or "")
    elif t == "ssh":
        o.update(type="ssh", user=str(p.get("username") or "root"))
        if p.get("password"):
            o["password"] = str(p["password"])
        if p.get("private-key"):
            o["private_key"] = str(p["private-key"])
    else:
        raise ValueError(f"sing-box 不支持 {t or '未知'} 协议")
    if t in ("vmess", "vless", "http", "socks5"):
        tls = _sb_tls(p, "servername")
        if tls:
            o["tls"] = tls
    if t in ("vmess", "vless", "trojan"):
        tr = _sb_transport(p)
        if tr:
            o["transport"] = tr
    if o.get("tls") is None:
        o.pop("tls", None)
    if p.get("udp") is False and t in ("ss",):
        o["network"] = "tcp"
    return o
