"""公网 IP 与归属地查询（概览页展示）"""
import json
import re
import shlex
import subprocess
import time

from .sysopt import proxy_opener, sh

IP_ECHO = "https://api.ipify.org"  # 返回纯文本公网 IP
GEO_URL = "http://ip-api.com/json/%s?lang=zh-CN&fields=status,country,regionName,city"

_CACHE = {"t": 0, "v": None}
_TTL = 600  # 公网 IP 变化不频繁，缓存 10 分钟


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
    except Exception:
        pass
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
    return _fetch(IP_ECHO, False)


_LOC_SUFFIX = re.compile(r"(?:省|市|自治区|特别行政区|壮族自治区|回族自治区|维吾尔自治区)$")


def loc_dedup(loc):
    """归属地去掉相邻重复的地名：「中国 重庆 重庆 电信」→「中国 重庆 电信」，「北京市 北京」也算重复"""
    out = []
    for p in (loc or "").split():
        if out and _LOC_SUFFIX.sub("", p) == _LOC_SUFFIX.sub("", out[-1]):
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
    except Exception:
        pass
    return ""


def get_ipinfo():
    """返回 {"direct": {"ip","loc"}, "proxy": {"ip","loc"}}；失败时 ip/loc 为空串，前端显示 '-'"""
    now = time.time()
    if _CACHE["v"] is not None and now - _CACHE["t"] < _TTL:
        return _CACHE["v"]
    proxy_ip = _fetch(IP_ECHO, True)
    # 本地公网 IP：优先经代理取国内服务（代理直连中国网站时可拿到真实 IP，自带中文归属地）
    direct_ip, direct_loc = _fetch_cn_ip()
    if not direct_ip or direct_ip == proxy_ip:
        direct_ip = _fetch_direct_ip()
        direct_loc = _geo(direct_ip)
    v = {"direct": {"ip": direct_ip, "loc": loc_dedup(direct_loc)},
         "proxy": {"ip": proxy_ip, "loc": loc_dedup(_geo(proxy_ip))}}
    _CACHE["t"], _CACHE["v"] = now, v
    return v
