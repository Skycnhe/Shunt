"""公网 IP 与归属地查询（概览页展示）"""
import json
import re
import shlex
import socket
import subprocess
import threading
import time

from .base import MIXED
from .corehttp import core
from .errlog import log_err
from .sysopt import proxy_opener, sh

IP_ECHO = "https://api.ipify.org"  # 返回纯文本公网 IP
GEO_URL = "http://ip-api.com/json/%s?lang=zh-CN&fields=status,country,regionName,city"

_CACHE = {"t": 0, "v": None, "fail": 0, "next": 0}
_TTL = 600  # 两边都查到才缓存 10 分钟；公网 IP 变化不频繁
_LOCK = threading.Lock()


def _backoff(n):
    """查询失败后的重试间隔：5、10、20、40、60、60… 秒"""
    return min(60, 5 * 2 ** max(0, n - 1))


def reset():
    """核心重启 / 切换后作废缓存：出口可能变了，失败的结果也立刻允许重查"""
    _CACHE.update(t=0, v=None, fail=0, next=0)


def core_ready():
    """代理出口查询的前提：核心控制接口有响应、mixed 端口能连上。重启瞬间两者都不在，此时查只会白等超时"""
    try:
        code, _ = core("GET", "/version", timeout=3)
        if code != 200:
            return False
        with socket.create_connection(("127.0.0.1", MIXED), timeout=2):
            return True
    except Exception:
        return False


def _fetch(url, via_proxy, timeout=10):
    try:
        with proxy_opener(via_proxy).open(url, timeout=timeout) as r:
            return r.read().decode(errors="ignore").strip()
    except Exception:
        return ""


def _phys_iface():
    """物理网卡：优先默认路由的非 TUN dev；TUN 接管默认路由时，退化为第一个 UP 的非 TUN/非 lo 网卡。
    TUN 模式会拦截本机全部流量，直连请求必须绑定物理网卡才能绕过 TUN 拿到真实公网 IP。"""
    try:
        out = subprocess.check_output(["ip", "-4", "route", "show", "default"],
                                      text=True, timeout=5)
        for line in out.splitlines():
            m = re.search(r"\bdev (\S+)", line)
            if m and not _is_tun(m.group(1)):
                return m.group(1)
    except Exception:
        pass
    try:
        out = subprocess.check_output(["ip", "-o", "link", "show"], text=True, timeout=5)
        for line in out.splitlines():
            m = re.search(r"^\d+: (\S+?):.*state UP", line)
            if m and m.group(1) != "lo" and not _is_tun(m.group(1)):
                return m.group(1)
    except Exception:
        pass
    return None


def _is_tun(dev):
    return (dev.startswith("tun") or dev.startswith("utun") or dev == "mihomo"
            or dev.startswith("docker") or dev.startswith("br-") or dev.startswith("veth"))


def _fetch_cn_ip():
    """经代理端口取国内 IP 查询服务。若代理按规则直连中国网站，可拿到真实公网 IP；
    响应自带中文归属地（格式：当前 IP：x.x.x.x  来自于：...），无需再查 geo。"""
    try:
        with proxy_opener(True).open("https://myip.ipip.net", timeout=10) as r:
            txt = r.read().decode(errors="ignore")
        m = re.search(r"当前 IP：([0-9.]+)\s*来自于：(.+)", txt)
        if m:
            return m.group(1).strip(), m.group(2).strip()
    except Exception as e:
        log_err("出口 IP 查询 (myip.ipip.net)", e)
    return "", ""


def _fetch_direct_ip():
    """直连取公网 IP：
    1. 优先 https://1.1.1.1/cdn-cgi/trace（固定 IP 无需 DNS，不受 fake-ip 污染），绑定物理网卡绕过 TUN
    2. 回退 api.ipify.org（DNS 可能被 fake-ip 污染）
    3. 回退普通直连"""
    dev = _phys_iface()
    if dev:
        code, out = sh(f"curl -s --interface {shlex.quote(dev)} --max-time 10 https://1.1.1.1/cdn-cgi/trace",
                       timeout=15)
        if code == 0:
            m = re.search(r"^ip=([0-9a-fA-F:.]+)", out, re.M)
            if m:
                return m.group(1)
        code, out = sh(f"curl -s --interface {shlex.quote(dev)} --max-time 10 {IP_ECHO}", timeout=15)
        out = out.strip()
        if code == 0 and re.fullmatch(r"[0-9a-fA-F:.]+", out):
            return out
    # 不绑网卡、也不走代理：1.1.1.1 是字面 IP，不依赖本机 DNS（核心重启时本机 DNS 可能指向还没起来的核心）
    code, out = sh("curl -s --noproxy '*' --max-time 8 https://1.1.1.1/cdn-cgi/trace", timeout=12)
    m = re.search(r"^ip=([0-9a-fA-F:.]+)", out or "", re.M) if code == 0 else None
    if m:
        return m.group(1)
    return _fetch(IP_ECHO, False)


_LOC_SUFFIX = re.compile(r"(?:省|市|自治区|特别行政区|壮族自治区|回族自治区|维吾尔自治区)$")


def loc_dedup(loc):
    """归属地去掉相邻重复的地名：「中国 重庆 重庆 电信」→「中国 重庆 电信」，「北京市 北京」也算重复"""
    out = []
    for p in (loc or "").split():
        prev = out[-1] if out else ""
        # 完全相同，或只差一个「市 / 省」后缀（重庆市 / 重庆）才算重复；吉林省 / 吉林市 是两级地名，保留
        if out and (p == prev or (_LOC_SUFFIX.sub("", p) == _LOC_SUFFIX.sub("", prev) and (p == _LOC_SUFFIX.sub("", p) or prev == _LOC_SUFFIX.sub("", prev)))):
            if len(p) < len(out[-1]):
                out[-1] = p  # 保留更短的写法（重庆 而不是 重庆市）
            continue
        out.append(p)
    return " ".join(out)


def _geo(ip):
    if not ip:
        return ""
    try:
        j = json.loads(_fetch(GEO_URL % ip, False, timeout=10))
        if j.get("status") == "success":
            return " ".join(p for p in (j.get("country"), j.get("regionName"), j.get("city")) if p)
    except Exception as e:
        log_err("IP 归属地查询", e)
    return ""


def _query():
    """代理出口强制经核心 mixed 端口；本地公网先经代理取国内服务（规则直连中国网站时拿到真实 IP，自带中文归属地），
    拿不到或与出口相同时改为绕过核心直连查询。两边并行，避免串行超时累加到半分钟以上"""
    res = {}

    def proxy_side():
        ip = _fetch(IP_ECHO, True) if core_ready() else ""
        res["proxy"] = {"ip": ip, "loc": loc_dedup(_geo(ip))}

    t = threading.Thread(target=proxy_side, daemon=True)
    t.start()
    direct_ip, direct_loc = _fetch_cn_ip() if core_ready() else ("", "")
    t.join(40)
    proxy_ip = (res.get("proxy") or {}).get("ip", "")
    if not direct_ip or direct_ip == proxy_ip:
        direct_ip = _fetch_direct_ip()
        direct_loc = _geo(direct_ip)
    return {"direct": {"ip": direct_ip, "loc": loc_dedup(direct_loc)},
            "proxy": res.get("proxy") or {"ip": "", "loc": ""}}


def get_ipinfo(query=None):
    """返回 {"direct": {"ip","loc"}, "proxy": {"ip","loc"}, "retry": 秒}；查不到的一边 ip 为空串。
    以前查询失败（核心刚重启、开机网络未就绪）的空结果也缓存 10 分钟，前端又只在进概览时拉一次，于是一直显示「-」。
    现在只有两边都查到才缓存；有失败就按 5→60 秒退避重查，retry 告诉前端多久后再来拉"""
    query = query or _query
    with _LOCK:
        now = time.time()
        v = _CACHE["v"]
        if v is not None:
            if not _CACHE["fail"] and now - _CACHE["t"] < _TTL:
                return v
            if _CACHE["fail"] and now < _CACHE["next"]:
                return dict(v, retry=max(1, int(_CACHE["next"] - now + 0.999)))
        v = query()
        now = time.time()
        if v["direct"]["ip"] and v["proxy"]["ip"]:
            _CACHE.update(t=now, v=v, fail=0, next=0)
            return v
        _CACHE["fail"] += 1
        wait = _backoff(_CACHE["fail"])
        _CACHE.update(t=now, v=v, next=now + wait)
        return dict(v, retry=wait)
