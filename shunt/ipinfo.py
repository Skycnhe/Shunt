"""公网 IP 与归属地查询（概览页展示）"""
import json
import time

from .sysopt import proxy_opener

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
    direct_ip = _fetch(IP_ECHO, False)
    proxy_ip = _fetch(IP_ECHO, True)
    v = {"direct": {"ip": direct_ip, "loc": _geo(direct_ip)},
         "proxy": {"ip": proxy_ip, "loc": _geo(proxy_ip)}}
    _CACHE["t"], _CACHE["v"] = now, v
    return v
