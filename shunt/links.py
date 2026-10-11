"""单节点链接解析"""
import base64, json, re
from urllib.parse import parse_qs, unquote, urlsplit

from .base import (
    AUTO_SUFFIX, AUTO_TAIL_OLD, BUILTIN_POLICIES, G_AUTO, G_DIRECT, G_MANUAL, G_OTHER, G_SEL, LB_SUFFIX, LEGACY_AUTO, REGIONS, SIDE_GROUPS
)
from .data import auto_name, lb_dropped_names, lb_names, lb_old_name
def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "ignore")


def q1(qs, *keys, default=""):
    for k in keys:
        if qs.get(k) and qs[k][0] != "":
            return qs[k][0]
    return default


def truthy(v):
    return str(v).lower() in ("1", "true", "yes")


def host_port(netloc):
    """返回 (host, port_spec)，兼容 [IPv6]:port 与 hy2 的多端口 443,2000-3000"""
    hp = netloc.rpartition("@")[2]
    m = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\]:([\d,\-]+)", hp) or re.fullmatch(r"([^:\[\]]+):([\d,\-]+)", hp)
    if not m:
        raise ValueError("服务器地址或端口无效")
    return m.group(1), m.group(2)


def common_tls(p, qs, sni_key="servername"):
    sni = q1(qs, "sni", "peer", "serverName")
    if sni:
        p[sni_key] = sni
    alpn = q1(qs, "alpn")
    if alpn:
        p["alpn"] = [a for a in alpn.split(",") if a]
    fp = q1(qs, "fp")
    if fp:
        p["client-fingerprint"] = fp
    if truthy(q1(qs, "allowInsecure", "insecure", "allow_insecure", "skip-cert-verify")):
        p["skip-cert-verify"] = True


def transport(p, net, qs):
    net = (net or "tcp").lower()
    host, path = q1(qs, "host"), q1(qs, "path")
    if net in ("ws", "httpupgrade"):
        p["network"] = "ws"
        o = {"path": path or "/"}
        if host:
            o["headers"] = {"Host": host}
        if net == "httpupgrade":
            o["v2ray-http-upgrade"] = True
        p["ws-opts"] = o
    elif net == "grpc":
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": q1(qs, "serviceName", "path")}
    elif net in ("h2", "http"):
        p["network"] = "h2"
        o = {"path": path or "/"}
        if host:
            o["host"] = host.split(",")
        p["h2-opts"] = o
    elif net == "tcp":
        if q1(qs, "headerType") == "http":
            p["network"] = "http"
            o = {"path": [path or "/"]}
            if host:
                o["headers"] = {"Host": host.split(",")}
            p["http-opts"] = o
    else:
        raise ValueError(f"不支持的传输方式 {net}")


def parse_link(line):
    line = line.strip()
    scheme = line.split("://", 1)[0].lower()
    if scheme == "vmess":
        j = json.loads(b64d(line[8:].split("#")[0]))
        p = {"name": str(j.get("ps") or ""), "type": "vmess", "server": j["add"], "port": int(j["port"]),
             "uuid": j["id"], "alterId": int(j.get("aid") or 0), "cipher": j.get("scy") or "auto", "udp": True}
        if j.get("tls") in ("tls", True):
            p["tls"] = True
            sni = j.get("sni") or j.get("host")
            if sni:
                p["servername"] = sni
            if j.get("alpn"):
                p["alpn"] = str(j["alpn"]).split(",")
            if j.get("fp"):
                p["client-fingerprint"] = j["fp"]
            if truthy(j.get("allowInsecure") or j.get("skip-cert-verify") or ""):
                p["skip-cert-verify"] = True
        qs = {k: [str(j.get(f) or "")] for k, f in (("path", "path"), ("host", "host"), ("serviceName", "path"), ("headerType", "type"))}
        transport(p, j.get("net") or "tcp", qs)
        return p
    if scheme == "ss":
        body, _, frag = line[5:].partition("#")
        if "@" in body:
            userinfo, _, rest = body.rpartition("@")
            userinfo = unquote(userinfo)
            if ":" not in userinfo:
                userinfo = b64d(userinfo)
        else:  # 旧格式 ss://base64(method:pass@host:port)
            b, sep, qpart = body.partition("?")
            dec = b64d(b.rstrip("/"))
            userinfo, _, hp = dec.rpartition("@")
            rest = hp + (sep + qpart if qpart else "")
        method, _, password = userinfo.partition(":")
        u = urlsplit("ss://x@" + rest)
        host, port = host_port(u.netloc)
        p = {"name": unquote(frag), "type": "ss", "server": host, "port": int(port), "cipher": method,
             "password": password, "udp": True}
        plugin = q1(parse_qs(u.query), "plugin")
        if plugin:
            parts = plugin.split(";")
            opts = dict((x.split("=", 1) + [""])[:2] for x in parts[1:])
            if parts[0] in ("obfs-local", "simple-obfs", "obfs"):
                p["plugin"] = "obfs"
                p["plugin-opts"] = {"mode": opts.get("obfs", "http"), "host": opts.get("obfs-host", "bing.com")}
            elif parts[0] == "v2ray-plugin":
                p["plugin"] = "v2ray-plugin"
                p["plugin-opts"] = {"mode": opts.get("mode", "websocket"), "host": opts.get("host", ""),
                                    "path": opts.get("path", "/"), "tls": "tls" in opts}
            else:
                raise ValueError(f"不支持的 ss 插件 {parts[0]}")
        return p
    if scheme in ("vless", "trojan", "hysteria2", "hy2", "tuic"):
        u = urlsplit(line)
        qs = parse_qs(u.query)
        host, port = host_port(u.netloc)
        name = unquote(u.fragment)
        user = unquote(u.username or "")
        pw = unquote(u.password) if u.password is not None else None
        if scheme == "vless":
            p = {"name": name, "type": "vless", "server": host, "port": int(port), "uuid": user, "udp": True}
            sec = q1(qs, "security")
            if sec in ("tls", "reality", "xtls"):
                p["tls"] = True
                common_tls(p, qs)
            if sec == "reality":
                p["reality-opts"] = {"public-key": q1(qs, "pbk"), "short-id": q1(qs, "sid")}
                p.setdefault("client-fingerprint", "chrome")
            flow = q1(qs, "flow")
            if flow:
                p["flow"] = flow
            enc = q1(qs, "encryption")
            if enc and enc != "none":
                p["encryption"] = enc
            transport(p, q1(qs, "type"), qs)
            return p
        if scheme == "trojan":
            p = {"name": name, "type": "trojan", "server": host, "port": int(port), "password": user, "udp": True}
            common_tls(p, qs, "sni")
            transport(p, q1(qs, "type"), qs)
            return p
        if scheme in ("hysteria2", "hy2"):
            auth = user + (":" + pw if pw is not None else "")
            first = re.split(r"[,\-]", port)[0]
            p = {"name": name, "type": "hysteria2", "server": host, "port": int(first), "password": auth, "udp": True}
            if not port.isdigit():
                p["ports"] = port
            common_tls(p, qs, "sni")
            p.pop("client-fingerprint", None)
            obfs = q1(qs, "obfs")
            if obfs and obfs != "none":
                p["obfs"] = obfs
                p["obfs-password"] = q1(qs, "obfs-password")
            return p
        if scheme == "tuic":
            p = {"name": name, "type": "tuic", "server": host, "port": int(port), "uuid": user, "password": pw or "",
                 "udp": True, "alpn": ["h3"]}
            common_tls(p, qs, "sni")
            p.pop("client-fingerprint", None)
            p["congestion-controller"] = q1(qs, "congestion_control", "congestion-control", default="bbr")
            p["udp-relay-mode"] = q1(qs, "udp_relay_mode", "udp-relay-mode", default="native")
            if truthy(q1(qs, "disable_sni")):
                p["disable-sni"] = True
            return p
    if scheme in ("anytls", "hysteria", "hy", "socks", "socks5", "socks5h"):
        u = urlsplit(line)
        qs = parse_qs(u.query)
        host, port = host_port(u.netloc)
        port = re.split(r"[,\-]", port)[0]
        name = unquote(u.fragment)
        user = unquote(u.username or "")
        pw = unquote(u.password) if u.password is not None else None
        if scheme == "anytls":
            p = {"name": name, "type": "anytls", "server": host, "port": int(port), "password": user, "udp": True}
            common_tls(p, qs, "sni")
            return p
        if scheme in ("hysteria", "hy"):
            p = {"name": name, "type": "hysteria", "server": host, "port": int(port), "udp": True,
                 "up": q1(qs, "upmbps", "up", default="10"), "down": q1(qs, "downmbps", "down", default="50")}
            auth = q1(qs, "auth", "auth_str") or user
            if auth:
                p["auth-str"] = auth
            if q1(qs, "obfsParam", "obfs-password", "obfs"):
                p["obfs"] = q1(qs, "obfsParam", "obfs-password", "obfs")
            common_tls(p, qs, "sni")
            p.pop("client-fingerprint", None)
            return p
        if pw is None and user and ":" not in user:  # socks://base64(user:pass)@host:port
            try:
                user, _, pw = b64d(user).partition(":")
            except Exception:
                pass
        p = {"name": name, "type": "socks5", "server": host, "port": int(port), "udp": True}
        if user:
            p["username"], p["password"] = user, pw or ""
        return p
    raise ValueError(f"不支持的链接类型 {scheme}://")


def add_links(text, existing, d=None):
    """解析多行链接，返回 (新增节点列表, 错误列表)；节点名自动去重"""
    taken = {n["proxy"]["name"] for n in existing} | reserved_names(d)
    out, errs = [], []
    for i, line in enumerate([x.strip() for x in text.splitlines() if x.strip()], 1):
        try:
            p = parse_link(line)
            if not p.get("server") or not p.get("port"):
                raise ValueError("缺少服务器或端口")
            base = (p.get("name") or f"{p['type']}-{p['server']}:{p['port']}").strip()
            name, k = base, 2
            while name in taken:
                name, k = f"{base} ({k})", k + 1
            p["name"] = name
            taken.add(name)
            out.append({"link": line, "proxy": p})
        except Exception as e:
            errs.append(f"第 {i} 行：{e}")
    return out, errs


def reserved_names(d=None):
    regs = [r[0] for r in REGIONS] + [G_OTHER]
    out = {G_SEL, G_AUTO, G_MANUAL, G_DIRECT, LEGACY_AUTO, "GLOBAL"} | set(SIDE_GROUPS) | BUILTIN_POLICIES
    for r in regs:
        out |= {r, r + LB_SUFFIX, r + AUTO_SUFFIX, auto_name(r), auto_name(r, AUTO_TAIL_OLD), lb_old_name(r), *lb_names(r), *lb_dropped_names(r)}
    if d:
        out |= {g["name"] for g in d.get("custom_groups") or []}
    return out
