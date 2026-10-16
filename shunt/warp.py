"""Cloudflare WARP 代理（WireGuard 协议）。

与 mihomo/sing-box 内核二选一：WARP 连接时可自动停止内核，
内核启动时可自动断开 WARP（互斥开关控制，默认开）。
"""
import json
import os
import re
import urllib.request

from .base import CORE_SVC
from .sysopt import sh

WARP_DIR = "/etc/mihomo-panel/warp"
WARP_CONF = os.path.join(WARP_DIR, "wgcf-profile.conf")
WARP_CONF_BAK = os.path.join(WARP_DIR, "wgcf-profile.conf.bak")
MUTEX_FILE = os.path.join(WARP_DIR, "mutex.json")
SANITIZED_CONF = "/tmp/warp-sanitized.conf"
IFACE = "wgcf"


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
    msg = "WARP 已连接"
    if get_mutex():
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
    st = status()
    if st["connected"]:
        return False, "WARP 断开失败：%s" % (out[-300:] if out else "未知错误"), st
    try:
        if os.path.isfile(SANITIZED_CONF):
            os.unlink(SANITIZED_CONF)
    except Exception:
        pass
    return True, "WARP 已断开（内核未动，需手动启动）", st
