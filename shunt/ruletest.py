"""规则测试"""
import ipaddress, json, re, socket, threading, time
from urllib.parse import quote

from .base import MIXED
from .corehttp import core_json
from .logstream import core_stream
def clean_target(t):
    t = t.strip()
    t = re.sub(r"^[a-z]+://", "", t, flags=re.I).split("/")[0].split("?")[0]
    if t.startswith("["):
        return t[1:].split("]")[0]
    if t.count(":") == 1:
        t = t.split(":")[0]
    return t.lower()


def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def chain_of(name, proxies):
    out, seen = [name], {name}
    while proxies.get(out[-1], {}).get("now") and proxies[out[-1]]["now"] not in seen:
        out.append(proxies[out[-1]]["now"])
        seen.add(out[-1])
    return out


def live_rule(host):
    """经 mixed 端口对目标发起 CONNECT，同时监听核心日志：
    优先从 /connections 读取命中规则与链路；节点不通时从日志里的 "dial X (match Rule/payload)" 读取"""
    logs, stop = [], {}

    def reader():
        try:
            core_stream("/logs?level=info", logs.append, stop)
        except Exception:
            pass
    threading.Thread(target=reader, daemon=True).start()
    time.sleep(0.3)
    s = socket.create_connection(("127.0.0.1", MIXED), timeout=8)
    try:
        hp = f"[{host}]:443" if ":" in host else f"{host}:443"
        port = str(s.getsockname()[1])
        s.sendall(f"CONNECT {hp} HTTP/1.1\r\nHost: {hp}\r\n\r\n".encode())
        try:
            first = s.recv(256).decode("latin1").split("\r\n")[0]
        except socket.timeout:
            first = "(等待超时)"
        src = re.compile(r"(?:127\.0\.0\.1|\[?::1\]?):" + port + r"\b")
        for _ in range(10):
            c = core_json("/connections") or {}
            for x in c.get("connections") or []:
                m = x.get("metadata") or {}
                if str(m.get("sourcePort")) == port and m.get("sourceIP") in ("127.0.0.1", "::1"):
                    return {"method": "live", "rule": x.get("rule"), "payload": x.get("rulePayload", ""),
                            "chain": list(reversed(x.get("chains") or [])), "note": "连接已建立"}
            for line in list(logs):
                try:
                    msg = json.loads(line).get("payload", "")
                except Exception:
                    continue
                if not src.search(msg):
                    continue
                m = re.search(r"dial (.+?) \(match (\w+)/(.*?)\) .*? error: (.*)", msg)
                if m:
                    proxies = (core_json("/proxies") or {}).get("proxies") or {}
                    return {"method": "live", "rule": m.group(2), "payload": m.group(3),
                            "chain": chain_of(m.group(1), proxies), "note": "节点连接失败：" + m.group(4)[:200]}
                m = re.search(r"match (\w+)\((.*?)\) using (.+)$", msg)
                if m:
                    proxies = (core_json("/proxies") or {}).get("proxies") or {}
                    pol = m.group(3).split("[")[0].strip()
                    return {"method": "live", "rule": m.group(1), "payload": m.group(2),
                            "chain": chain_of(pol, proxies), "note": "连接已结束"}
            time.sleep(0.3)
        return {"error": "未捕获到连接（" + first + "）"}
    finally:
        s.close()
        stop["stop"] = True
        try:
            stop["sock"].shutdown(socket.SHUT_RDWR)
        except (KeyError, OSError):
            pass


def static_rule(host):
    rules = (core_json("/rules") or {}).get("rules") or []
    proxies = (core_json("/proxies") or {}).get("proxies") or {}
    ips, uncertain = None, []

    def get_ips():
        nonlocal ips
        if ips is None:
            if is_ip(host):
                ips = [ipaddress.ip_address(host)]
            else:  # 经 mihomo 的 DNS 解析（按 nameserver-policy 分流），不用本机系统 DNS，避免把国外域名泄露给本机上游
                ips = []
                for qt in ("A", "AAAA"):
                    j = core_json(f"/dns/query?name={quote(host)}&type={qt}", timeout=8) or {}
                    for a in j.get("Answer") or []:
                        if a.get("type") in (1, 28) and is_ip(str(a.get("data"))):
                            ips.append(ipaddress.ip_address(a["data"]))
        return ips

    for r in rules:
        t = re.sub(r"[-_]", "", str(r.get("type", ""))).lower()
        pl = str(r.get("payload", ""))
        hit = None
        if t == "domain":
            hit = host == pl.lower()
        elif t == "domainsuffix":
            hit = host == pl.lower() or host.endswith("." + pl.lower())
        elif t == "domainkeyword":
            hit = pl.lower() in host
        elif t == "domainregex":
            try:
                hit = bool(re.search(pl, host))
            except re.error:
                hit = None
        elif t in ("ipcidr", "ipcidr6"):
            try:
                net = ipaddress.ip_network(pl, strict=False)
                hit = any(i in net for i in get_ips() if i.version == net.version)
            except ValueError:
                hit = None
        elif t == "geoip" and pl.lower() in ("private", "lan"):
            hit = any(i.is_private for i in get_ips())
        elif t == "dstport":
            hit = False
            for seg in re.split(r"[/,]", pl):
                a, _, z = seg.partition("-")
                if a.strip().isdigit() and int(a) <= 443 <= int(z or a):
                    hit = True
        elif t == "match":
            hit = True
        if hit is None or t in ("geosite", "geoip", "ruleset", "and", "or", "not", "srcipcidr", "processname",
                                "processpath", "inport", "intype", "network", "srcport", "inname", "inuser"):
            if len(uncertain) < 8:
                uncertain.append(f"{r.get('type')},{pl} → {r.get('proxy')}")
            continue
        if hit:
            return {"method": "static", "rule": r.get("type"), "payload": pl, "chain": chain_of(r.get("proxy"), proxies),
                    "uncertain": uncertain}
    return {"method": "static", "rule": "-", "payload": "", "chain": [], "uncertain": uncertain}


def rule_test(target):
    host = clean_target(target)
    if not host:
        raise ValueError("请输入域名或 IP")
    res, live_err = None, ""
    try:
        res = live_rule(host)
        if "error" in res:
            live_err, res = res["error"], None
    except Exception as e:
        live_err = str(e)
    if res is None:
        res = static_rule(host)
        res["live_error"] = live_err
    res["host"] = host
    return res

