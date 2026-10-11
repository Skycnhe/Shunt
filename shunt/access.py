"""访问控制"""
import ipaddress, os, time
from collections import deque

from .data import load
# 面板没有密码：只接受局域网来源，Host 必须是 IP / 局域网名（防 DNS 重绑定），改动类请求必须带自定义头（防跨站请求）
LAN_EXTRA = [ipaddress.ip_network(n) for n in ("100.64.0.0/10",)]  # CGNAT / Tailscale
LAN_SUFFIX = (".lan", ".local", ".home", ".internal", ".home.arpa", ".localdomain", ".router", ".intranet", ".ts.net")
ACL = {"t": 0, "public": False, "hosts": set()}


def acl_cfg():
    if time.time() - ACL["t"] > 5:
        d = load()
        env = {h.strip().lower() for h in os.environ.get("PANEL_ALLOW_HOSTS", "").split(",") if h.strip()}
        ACL.update(t=time.time(), public=bool(d.get("allow_public")) or os.environ.get("PANEL_ALLOW_PUBLIC") == "1",
                   hosts={str(h).strip().lower() for h in d.get("allow_hosts") or [] if str(h).strip()} | env)
    return ACL


def ip_is_lan(ip):
    try:
        a = ipaddress.ip_address(str(ip).split("%")[0])
    except ValueError:
        return False
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    return a.is_private or a.is_loopback or a.is_link_local or any(a in n for n in LAN_EXTRA)


def host_name(host):
    h = (host or "").strip().lower()
    if h.startswith("["):
        return h[1:h.find("]")] if "]" in h else h[1:]
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


def host_ok(host):
    h = host_name(host).rstrip(".")
    if not h:
        return True  # HTTP/1.0 等不带 Host：没有重绑定风险
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    a = acl_cfg()
    return a["public"] or h == "localhost" or "." not in h or h.endswith(LAN_SUFFIX) or h in a["hosts"]


ERRS = deque(maxlen=30)
_ERR_SEEN = {}


def log_err(where, e, tb=False):
    """把原本被吞掉的异常记到面板日志和「诊断」里；同一处同一错误 10 分钟只记一次"""
    msg = f"{type(e).__name__}: {e}"[:300] if isinstance(e, BaseException) else str(e)[:300]
    key = (where, msg)
    now = time.time()
    if now - _ERR_SEEN.get(key, 0) < 600:
        return
    _ERR_SEEN[key] = now
    if len(_ERR_SEEN) > 500:
        _ERR_SEEN.clear()
    ERRS.appendleft({"t": int(now), "where": where, "msg": msg})
    extra = ""
    if tb and isinstance(e, BaseException):
        import traceback
        extra = "\n" + "".join(traceback.format_exception(type(e), e, e.__traceback__))[-1500:]
    print(f"[error] {where}: {msg}{extra}", flush=True)
