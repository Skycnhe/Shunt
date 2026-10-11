"""设备名称"""
import ipaddress, os, re, socket, threading, time
from collections import deque

from .base import LEASE_FILES, MIHOMO_LOG
from .data import load
from .stats import arp_table
from .ruletest import is_ip
RDNS = {}  # ip -> (name, 过期时间)
RDNS_Q = deque()
RDNS_EV = threading.Event()


def read_leases():
    out = {}
    for path in LEASE_FILES:
        try:
            with open(path) as f:
                for line in f:
                    p = line.split()
                    if len(p) >= 4 and is_ip(p[2]):
                        out[p[2]] = (p[1].lower(), "" if p[3] == "*" else p[3])
        except OSError:
            pass
    return out


def read_hosts():
    out = {}
    try:
        with open("/etc/hosts") as f:
            for line in f:
                p = line.split("#", 1)[0].split()
                if len(p) >= 2 and is_ip(p[0]) and not ipaddress.ip_address(p[0]).is_loopback:
                    out.setdefault(p[0], p[1])
    except OSError:
        pass
    return out


def rdns_loop():
    while True:
        RDNS_EV.wait(30)
        RDNS_EV.clear()
        while RDNS_Q:
            ip = RDNS_Q.popleft()
            name = ""
            try:  # 不再改全局 socket 超时：那会让同时建立的订阅下载、核心更新等连接也只剩 2 秒
                name = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass
            if name and (name == ip or name.endswith(".in-addr.arpa")):
                name = ""
            RDNS[ip] = (name.split(".")[0] if name.endswith((".lan", ".local", ".home", ".localdomain")) else name, time.time() + 1800)


def device_map(ips):
    d = load()
    custom = {k.lower(): v for k, v in (d.get("devices") or {}).items()}
    arp, leases, hosts = arp_table(), read_leases(), read_hosts()
    out = {}
    for ip in ips:
        if not ip or ip == "?":
            continue
        mac = (arp.get(ip) or leases.get(ip, ("", ""))[0] or "").lower()
        name, src = custom.get(ip.lower()) or (custom.get(mac) if mac else None), "备注"
        if not name and leases.get(ip, ("", ""))[1]:
            name, src = leases[ip][1], "DHCP"
        if not name and hosts.get(ip):
            name, src = hosts[ip], "hosts"
        if not name:
            r = RDNS.get(ip)
            if r and r[1] > time.time():
                name, src = r[0], "反向解析"
            elif (not r or r[1] <= time.time()) and is_ip(ip) and ipaddress.ip_address(ip).is_private and ip not in RDNS_Q:
                RDNS[ip] = ("", time.time() + 300)
                RDNS_Q.append(ip)
                RDNS_EV.set()
        out[ip] = {"name": name or "", "mac": mac, "src": src if name else ""}
    return out


def tun_runtime_error(dev, wait=4):
    """等待 TUN 网卡出现；失败时从核心日志里找出原因"""
    for _ in range(wait * 2):
        if os.path.exists(f"/sys/class/net/{dev}/tun_flags"):  # 必须是 TUN 网卡，避免与 eth0 等同名网卡误判
            return ""
        time.sleep(0.5)
    try:
        with open(MIHOMO_LOG, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 64 * 1024))
            lines = f.read().decode("utf-8", "ignore").splitlines()
        for line in reversed(lines):
            if "TUN" in line and ("error" in line.lower() or "fatal" in line.lower()):
                m = re.search(r'msg="(.*)"', line)
                return (m.group(1) if m else line)[-240:]
    except OSError:
        pass
    return f"未检测到网卡 {dev}"
