"""Cloudflare WARP 代理（WireGuard 协议）。

与 mihomo/sing-box 内核二选一：WARP 连接时可自动停止内核，
内核启动时可自动断开 WARP（互斥开关控制，默认开）。
"""
import ipaddress
import json
import os
import re
import socket
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .base import CORE_SVC
from .notify import WD
from .sysopt import sh

WARP_DIR = "/etc/mihomo-panel/warp"
WARP_CONF = os.path.join(WARP_DIR, "wgcf-profile.conf")
WARP_CONF_BAK = os.path.join(WARP_DIR, "wgcf-profile.conf.bak")
MUTEX_FILE = os.path.join(WARP_DIR, "mutex.json")
SANITIZED_CONF = "/tmp/warp-sanitized.conf"
IFACE = "wgcf"

# Cloudflare WARP 入口 IP 候选池（均为 anycast，同 IP 自动路由到最近 PoP，
# 实际以测速结果为准；用户可在页面添加自定义 IP 加入候选池）
# 范围来源：162.159.192/193/195/204.0/24，188.114.96-99.0/24
WARP_IPS = [
    "162.159.192.1", "162.159.192.10", "162.159.192.100",
    "162.159.193.1", "162.159.193.10", "162.159.193.100",
    "162.159.195.1", "162.159.195.10", "162.159.195.100",
    "162.159.204.1", "162.159.204.10", "162.159.204.50",
    "162.159.204.100", "162.159.204.200",
    "188.114.96.1", "188.114.96.10", "188.114.96.100",
    "188.114.97.1", "188.114.97.10", "188.114.97.100",
    "188.114.98.1", "188.114.98.10", "188.114.99.1",
    "188.114.99.10",
]
WARP_PORT = 2408
WARP_PORTS = [2408, 500, 1701, 4500, 443, 2053, 2083, 2087, 2096, 8443,
              80, 8080, 8880, 2052, 2082, 2086, 2095]
WARP_PORT_GROUPS = {
    "WARP": [2408, 500, 1701, 4500],
    "HTTPS": [443, 2053, 2083, 2087, 2096, 8443],
    "HTTP": [80, 8080, 8880, 2052, 2082, 2086, 2095],
}
CUSTOM_IPS_FILE = os.path.join(WARP_DIR, "custom_ips.json")
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=5000000"
SPEED_TIMEOUT = 12


def _ensure_dir():
    try:
        os.makedirs(WARP_DIR, mode=0o700, exist_ok=True)
    except Exception:
        pass


def get_mutex():
    """互斥开关，默认开。"""
    try:
        with open(MUTEX_FILE) as f:
            return bool(json.load(f).get("mutex", True))
    except Exception:
        return True


def set_mutex(on):
    _ensure_dir()
    try:
        with open(MUTEX_FILE, "w") as f:
            json.dump({"mutex": bool(on)}, f)
        os.chmod(MUTEX_FILE, 0o600)
        return True
    except Exception:
        return False


def _which(cmd):
    code, _ = sh("command -v %s" % cmd, timeout=10)
    return code == 0


def _core_running():
    code, out = sh("rc-service %s status" % CORE_SVC, timeout=10)
    return code == 0 and "started" in out.lower()


def _stop_core():
    return sh("rc-service %s stop" % CORE_SVC, timeout=30)


def is_registered():
    return os.path.isfile(WARP_CONF)


def is_connected():
    code, out = sh("wg show %s 2>/dev/null | head -1" % IFACE, timeout=10)
    return code == 0 and ("interface" in out.lower() or IFACE in out)


def _egress_ip(timeout=15):
    """WARP 连接后的出口 IP（经 Cloudflare trace）。"""
    try:
        req = urllib.request.Request("https://www.cloudflare.com/cdn-cgi/trace",
                                     headers={"User-Agent": "curl"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            for line in r.read().decode(errors="ignore").splitlines():
                if line.startswith("ip="):
                    return line[3:].strip()
    except Exception:
        pass
    return ""


def status():
    installed_wg = _which("wg") and _which("wg-quick")
    installed_wgcf = _which("wgcf")
    registered = is_registered()
    connected = is_connected() if (installed_wg and registered) else False
    ip = _egress_ip() if connected else ""
    return {
        "installed_wg": installed_wg,
        "installed_wgcf": installed_wgcf,
        "registered": registered,
        "connected": connected,
        "ip": ip,
        "mutex": get_mutex(),
        "core_running": _core_running(),
    }


def get_config():
    """读取 WireGuard 配置文件。返回 dict(ok, content/message)。"""
    try:
        with open(WARP_CONF) as f:
            return {"ok": True, "content": f.read()}
    except FileNotFoundError:
        return {"ok": False, "message": "配置文件不存在，请先点「初始化 WARP」"}
    except Exception as e:
        return {"ok": False, "message": "读取配置失败：%s" % e}


def save_config(content):
    """保存用户编辑的 WireGuard 配置。返回 dict(ok, message)。

    保存的是原始内容（含 DNS 行也保留，connect 时的消毒逻辑会自动处理）。
    """
    content = (content or "").strip()
    if not content:
        return {"ok": False, "message": "配置内容为空，未保存"}
    if "[Interface]" not in content or "[Peer]" not in content:
        return {"ok": False, "message": "配置无效：缺少 [Interface] 或 [Peer] 段，未保存"}
    _ensure_dir()
    # 备份原文件（只留一份）
    try:
        if os.path.isfile(WARP_CONF):
            with open(WARP_CONF) as f:
                old = f.read()
            with open(WARP_CONF_BAK, "w") as f:
                f.write(old)
            os.chmod(WARP_CONF_BAK, 0o600)
    except Exception as e:
        return {"ok": False, "message": "备份原配置失败：%s" % e}
    try:
        with open(WARP_CONF, "w") as f:
            f.write(content + "\n")
        os.chmod(WARP_CONF, 0o600)
    except Exception as e:
        return {"ok": False, "message": "保存配置失败：%s" % e}
    return {"ok": True, "message": "配置已保存（原配置已备份为 wgcf-profile.conf.bak）"}


def get_custom_ips():
    """用户自定义 IP 候选池。返回 dict(ok, ips)。"""
    try:
        with open(CUSTOM_IPS_FILE) as f:
            ips = json.load(f).get("ips", [])
        return {"ok": True, "ips": [i for i in ips if isinstance(i, str)]}
    except FileNotFoundError:
        return {"ok": True, "ips": []}
    except Exception as e:
        return {"ok": False, "message": "读取自定义 IP 失败：%s" % e}


def save_custom_ips(ips_text):
    """保存用户自定义 IP（每行一个）。无效行跳过并告知。返回 dict(ok, message)。"""
    valid, skipped = [], 0
    for line in (ips_text or "").splitlines():
        ip = line.strip()
        if not ip:
            continue
        try:
            ipaddress.ip_address(ip)
            valid.append(ip)
        except ValueError:
            skipped += 1
    # 去重（保持顺序）
    seen, dedup = set(), []
    for ip in valid:
        if ip not in seen:
            seen.add(ip)
            dedup.append(ip)
    _ensure_dir()
    try:
        with open(CUSTOM_IPS_FILE, "w") as f:
            json.dump({"ips": dedup}, f)
        os.chmod(CUSTOM_IPS_FILE, 0o600)
    except Exception as e:
        return {"ok": False, "message": "保存自定义 IP 失败：%s" % e}
    msg = "已保存 %d 个自定义 IP" % len(dedup)
    if skipped:
        msg += "（跳过 %d 个无效 IP）" % skipped
    return {"ok": True, "message": msg, "ips": dedup}


def _candidate_ips():
    """内置候选池 + 自定义 IP，合并去重（保持顺序）。"""
    custom = get_custom_ips().get("ips", []) or []
    seen, out = set(), []
    for ip in WARP_IPS + custom:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def _probe_ip(ip, port=WARP_PORT, tries=3, timeout=2):
    """对单个 IP 做 TCP connect 延迟测试，返回 (ok, avg_ms, min_ms)。"""
    """对单个 IP 做 TCP connect 延迟测试，返回 (ok, avg_ms, min_ms)。"""
    results = []
    for _ in range(tries):
        try:
            t0 = time.monotonic()
            s = socket.create_connection((ip, port), timeout=timeout)
            s.close()
            results.append((time.monotonic() - t0) * 1000)
        except Exception:
            pass
    if not results:
        return False, 0, 0
    return True, sum(results) / len(results), min(results)


def _ref_download_speed():
    """当前网络到 Cloudflare 的参考下载速度（curl 官方测速端点，供参考）。

    注意：这是整条路径的参考值，不是每个候选 IP 的独立速度
    （HTTPS 下载的 IP 不可控，无法按候选 IP 单独测速）。返回如 "12.5 MB/s"，失败返回 ""。
    """
    try:
        code, out = sh('curl -o /dev/null -s -w "%%{speed_download}" --max-time %d "%s"'
                       % (SPEED_TIMEOUT, SPEED_URL), timeout=SPEED_TIMEOUT + 3)
        if code != 0:
            return ""
        spd = float((out or "").strip())
        if spd <= 0:
            return ""
        if spd >= 1048576:
            return "%.1f MB/s" % (spd / 1048576)
        if spd >= 1024:
            return "%.0f KB/s" % (spd / 1024)
        return "%.0f B/s" % spd
    except Exception:
        return ""


def preferred_ips(ports=None):
    """对候选池（内置 + 自定义）× 端口组合做延迟测试，按平均延迟排序。

    ports: None 或空表示测全部 WARP_PORTS。返回 {"servers": [{ip, port, avg_ms, min_ms, ok}], "ref_speed": "..."}。
    """
    targets = _candidate_ips()
    sel = [p for p in (ports or []) if isinstance(p, int) and p in WARP_PORTS] or list(WARP_PORTS)
    combos = [(ip, pt) for ip in targets for pt in sel]

    def one(c):
        ip, pt = c
        ok, avg, mn = _probe_ip(ip, port=pt)
        return {"ip": ip, "port": pt, "avg_ms": round(avg, 1),
                "min_ms": round(mn, 1), "ok": ok}

    with ThreadPoolExecutor(max_workers=20) as ex:
        fut_speed = ex.submit(_ref_download_speed)
        results = list(ex.map(one, combos))
        ref_speed = fut_speed.result()
    # 成功的按延迟排前面，失败的排最后
    results.sort(key=lambda r: (0 if r["ok"] else 1, r["avg_ms"] if r["ok"] else 1e9))
    return {"servers": results, "ref_speed": ref_speed}


def apply_ip(ip, port=None):
    """把指定 IP+端口填入 WireGuard 配置的 Endpoint，保存。返回 dict(ok, message)。"""
    ip = (ip or "").strip()
    if ip not in _candidate_ips():
        return {"ok": False, "message": "未知 IP：%s" % ip}
    try:
        port = int(port) if port is not None else WARP_PORT
    except (TypeError, ValueError):
        port = WARP_PORT
    if port not in WARP_PORTS:
        port = WARP_PORT
    r = get_config()
    if not r["ok"]:
        return r
    content = r["content"]
    new_content, n = re.subn(
        r"(?m)^\s*Endpoint\s*=.*$",
        "Endpoint = %s:%d" % (ip, port),
        content,
    )
    if n == 0:
        return {"ok": False, "message": "配置中未找到 Endpoint 行，未修改"}
    return save_config(new_content)


def setup():
    """wgcf 注册并生成 WireGuard 配置。返回 (ok, message)。"""
    if not _which("wgcf"):
        return False, "未安装 wgcf：请先下载（https://github.com/ViRb3/wgcf/releases）放到 /usr/bin/wgcf 并 chmod +x"
    _ensure_dir()
    code, out = sh("cd %s && wgcf register --accept-tos" % WARP_DIR, timeout=60)
    if code != 0:
        return False, "wgcf 注册失败：%s" % (out[-500:] if out else "未知错误")
    code, out = sh("cd %s && wgcf generate" % WARP_DIR, timeout=60)
    if code != 0 or not os.path.isfile(WARP_CONF):
        return False, "wgcf 生成配置失败：%s" % (out[-500:] if out else "未知错误")
    try:
        os.chmod(WARP_CONF, 0o600)
    except Exception:
        pass
    return True, "WARP 配置已生成"


def _lan_subnet():
    """检测局域网段：从 ip route 找默认路由的 dev 上的直连网段。

    例如 `192.168.31.0/24 dev eth0 proto kernel scope link src 192.168.31.20`
    返回 (subnet, iface)，如 ("192.168.31.0/24", "eth0")；失败返回 (None, None)。
    """
    try:
        code, out = sh("ip route show", timeout=10)
        if code != 0:
            return None, None
        default_iface = None
        for line in out.splitlines():
            if line.startswith("default "):
                m = re.search(r"\bdev\s+(\S+)", line)
                if m:
                    default_iface = m.group(1)
                break
        if not default_iface:
            return None, None
        for line in out.splitlines():
            # 直连路由形如: 192.168.31.0/24 dev eth0 proto kernel scope link src 192.168.31.20
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+/\d+)\s+dev\s+(\S+)\s+.*scope\s+link", line)
            if m and m.group(2) == default_iface:
                return m.group(1), m.group(2)
    except Exception:
        pass
    return None, None


def _ensure_lan_bypass():
    """WARP 连接后加一条局域网直连路由（metric 更小优先），保住面板/局域网访问。

    wg-quick 的 AllowedIPs=0.0.0.0/0 会接管全部流量，浏览器访问面板的回包
    进隧道就回不来了。加这条路由让局域网流量不走隧道。幂等，失败只记日志不阻断。
    """
    try:
        subnet, iface = _lan_subnet()
        if not subnet or not iface:
            return
        # 已存在则不重复加
        code, out = sh("ip route show %s 2>/dev/null" % subnet, timeout=10)
        if code == 0 and ("dev %s" % iface) in out:
            return
        sh("ip route add %s dev %s metric 5 2>/dev/null" % (subnet, iface), timeout=10)
    except Exception:
        pass


def _remove_lan_bypass():
    """删除 _ensure_lan_bypass 加的局域网直连路由。"""
    try:
        subnet, iface = _lan_subnet()
        if not subnet:
            return
        sh("ip route del %s dev %s metric 5 2>/dev/null" % (subnet, iface or ""), timeout=10)
    except Exception:
        pass


def _sanitized_conf():
    """去掉配置里的 DNS 行（wg-quick 会用 resolvconf 改系统 DNS，Alpine 上失败且与面板 DNS 冲突）。

    返回消毒后的配置文件路径：有 DNS 行则写临时文件，无则直接返回原路径。
    """
    try:
        with open(WARP_CONF) as f:
            content = f.read()
    except Exception:
        return WARP_CONF
    new_content, n = re.subn(r"(?m)^\s*DNS\s*=.*$", "", content)
    if n == 0:
        return WARP_CONF
    try:
        with open(SANITIZED_CONF, "w") as f:
            f.write(new_content)
        os.chmod(SANITIZED_CONF, 0o600)
        return SANITIZED_CONF
    except Exception:
        return WARP_CONF


def connect():
    """连接 WARP。返回 (ok, message, st)。"""
    if not (_which("wg") and _which("wg-quick")):
        return False, "未安装 wireguard-tools：路由器上执行 apk add wireguard-tools", status()
    if not _which("wgcf"):
        return False, "未安装 wgcf：https://github.com/ViRb3/wgcf/releases 下载对应架构版本", status()
    if not is_registered():
        ok, msg = setup()
        if not ok:
            return False, msg, status()
    if is_connected():
        st = status()
        return True, "WARP 已在连接中", st
    code, out = sh("wg-quick up %s" % _sanitized_conf(), timeout=30)
    if code != 0:
        return False, "WARP 连接失败：%s" % (out[-500:] if out else "未知错误"), status()
    _ensure_lan_bypass()  # 保住局域网/面板访问，不让回包进隧道
    msg = "WARP 已连接"
    if get_mutex():
        WD["manual_stop"] = True  # 告诉看门狗这是人为停止，不要自动重启
        c2, o2 = _stop_core()
        if c2 == 0:
            msg += "，内核已停止"
        else:
            msg += "（停止内核失败，请手动执行 rc-service %s stop）" % CORE_SVC
    st = status()
    return True, msg, st


def disconnect():
    """断开 WARP（不动内核）。返回 (ok, message, st)。"""
    if not is_connected():
        return True, "WARP 未连接", status()
    code, out = sh("wg-quick down %s" % IFACE, timeout=30)
    if code != 0:
        # 兜底：直接删接口
        sh("ip link del %s 2>/dev/null" % IFACE, timeout=10)
    _remove_lan_bypass()  # 清掉我们加的局域网直连路由
    st = status()
    if st["connected"]:
        return False, "WARP 断开失败：%s" % (out[-300:] if out else "未知错误"), st
    try:
        if os.path.isfile(SANITIZED_CONF):
            os.unlink(SANITIZED_CONF)
    except Exception:
        pass
    return True, "WARP 已断开（内核未动，需手动启动）", st
