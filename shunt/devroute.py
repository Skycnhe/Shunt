"""按设备分流：把指定设备（IP / 网段 / MAC）的全部流量交给某个策略组、直连或拦截。

data.json 的 device_routes：[{name, ip, mac, target, enabled}]，ip 与 mac 二选一。
生成配置时转换成排在规则前部的 SRC-IP-CIDR 规则（sing-box 由 sb_config 按同一份 mihomo 规则翻译成 source_ip_cidr）；
MAC 在生成时按 ARP 表 / DHCP 租约（开启 IPv6 时再加 IPv6 邻居表）解析成当前 IP。
设备换了 IP 时，定时任务循环（schedule.sched_loop，每分钟）发现解析结果与上次写入配置时不同就重载核心。"""
import ipaddress, json, os, re, subprocess, threading

from .base import PANEL_DIR
from .groups import NAME_BAD

ROUTES_MAX = 500
MAC_RX = re.compile(r"([0-9a-f]{2}:){5}[0-9a-f]{2}")
TARGET_DIRECT, TARGET_REJECT = "DIRECT", "REJECT"
APPLIED_FILE = os.path.join(PANEL_DIR, "devroute_applied.json")
SEEN = {}  # mac -> 上次解析到的 IP 列表：设备暂时不在 ARP 表里（休眠）时沿用，不让规则时有时无、核心反复重载
STATE = {"last": None, "applied": None, "loaded": False}  # last：最近一次生成配置时的 MAC 解析结果；applied：写入正式配置时的
_LOGGED = set()  # 已记过日志的跳过原因（生成配置很频繁，同一原因只记一次）
_LOCK = threading.Lock()


def norm_mac(v):
    v = str(v or "").strip().lower().replace("-", ":")
    return v if MAC_RX.fullmatch(v) else ""


def norm_ip(v):
    """IP / 网段 → 规范写法（单个地址不带前缀）；无效返回空串"""
    try:
        n = ipaddress.ip_network(str(v or "").strip(), strict=False)
    except ValueError:
        return ""
    return str(n.network_address) if n.prefixlen == n.max_prefixlen else str(n)


def clean_device_routes(v):
    """/api/settings、/api/restore 的形状校验：坏条目抛 ValueError（提示可直接给用户看）"""
    if not isinstance(v, list):
        raise ValueError("按设备分流应为列表")
    if len(v) > ROUTES_MAX:
        raise ValueError(f"按设备分流最多 {ROUTES_MAX} 条")
    out, seen = [], set()
    for i, e in enumerate(v):
        if not isinstance(e, dict):
            raise ValueError(f"按设备分流第 {i + 1} 项格式不正确")
        ip_raw, mac_raw = str(e.get("ip") or "").strip(), str(e.get("mac") or "").strip()
        if bool(ip_raw) == bool(mac_raw):
            raise ValueError(f"按设备分流第 {i + 1} 项：IP 和 MAC 填且只填一个")
        ip, mac = norm_ip(ip_raw) if ip_raw else "", norm_mac(mac_raw) if mac_raw else ""
        if ip_raw and not ip:
            raise ValueError(f"按设备分流第 {i + 1} 项的 IP / 网段无效：{ip_raw[:60]}")
        if mac_raw and not mac:
            raise ValueError(f"按设备分流第 {i + 1} 项的 MAC 无效：{mac_raw[:60]}")
        key = ip or mac
        if key in seen:
            raise ValueError(f"按设备分流重复：{key}")
        seen.add(key)
        name = e.get("name")
        if name is not None and not isinstance(name, str):
            raise ValueError(f"按设备分流「{key}」的名称应为文本")
        target = e.get("target")
        if not isinstance(target, str) or not target.strip():
            raise ValueError(f"按设备分流「{key}」没有选择目标")
        target = target.strip()
        if NAME_BAD.search(target) or len(target) > 80:
            raise ValueError(f"按设备分流「{key}」的目标无效：{target[:60]}")
        out.append({"name": (name or "").strip()[:40] or key, "ip": ip, "mac": mac, "target": target,
                    "enabled": bool(e.get("enabled", True))})
    return out


def neigh6():
    """IPv6 邻居表 {ip: mac}（ip -6 neigh）；没有 ip 命令或出错时返回空"""
    out = {}
    try:
        r = subprocess.run(["ip", "-6", "neigh", "show"], capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return out
    for line in r.stdout.splitlines():
        p = line.split()
        if "lladdr" in p and p.index("lladdr") + 1 < len(p) and "FAILED" not in p:
            ip, mac = p[0], p[p.index("lladdr") + 1].lower()
            if not ip.lower().startswith("fe80:"):  # 链路本地地址不会出现在转发流量的源地址里
                out[ip] = mac
    return out


def _tables(d):
    """(ARP {ip: mac}, DHCP 租约 {ip: (mac, 名称)}, IPv6 邻居 {ip: mac})"""
    arp, leases, n6 = {}, {}, {}
    try:
        arp = arp_table()
    except Exception:
        pass
    try:
        leases = read_leases()
    except Exception:
        pass
    if d.get("ipv6"):
        try:
            n6 = neigh6()
        except Exception:
            pass
    return arp, leases, n6


def resolve_mac(mac, arp, leases, n6):
    """MAC 的当前 IP：ARP 表 + DHCP 租约（租约里的 IP 已在 ARP 表中属于别的设备时不算）+ IPv6 邻居表"""
    ips = [ip for ip, m in arp.items() if str(m).lower() == mac]
    for ip, v in leases.items():
        if str(v[0]).lower() == mac and ip not in ips and str(arp.get(ip, mac)).lower() == mac:
            ips.append(ip)
    ips += [ip for ip, m in n6.items() if str(m).lower() == mac and ip not in ips]
    return sorted(ips, key=lambda x: (":" in x, x))


def mac_mapping(d, tables=None):
    """启用的 MAC 条目 → {mac: [IP]}（找不到时沿用上次见到的、仍未被别的设备占用的 IP）"""
    macs = [e["mac"] for e in _entries(d) if e["mac"]]
    if not macs:
        return {}
    arp, leases, n6 = tables or _tables(d)
    owner = {ip: str(m).lower() for ip, m in list(arp.items()) + list(n6.items())}
    out = {}
    for mac in macs:
        ips = resolve_mac(mac, arp, leases, n6)
        with _LOCK:
            if ips:
                SEEN[mac] = ips
            else:
                ips = [ip for ip in SEEN.get(mac, []) if owner.get(ip, mac) == mac]
        out[mac] = ips
    return out


def _entries(d):
    """data.json 里启用的、形状正确的条目（坏条目忽略，不让生成配置失败）"""
    out = []
    for e in d.get("device_routes") or []:
        if not isinstance(e, dict) or not e.get("enabled", True):
            continue
        ip, mac = norm_ip(e.get("ip")) if e.get("ip") else "", norm_mac(e.get("mac"))
        target = str(e.get("target") or "").strip()
        if (ip or mac) and target and not NAME_BAD.search(target):
            out.append({"name": str(e.get("name") or ip or mac), "ip": ip, "mac": mac, "target": target})
    return out


def _log_once(key, msg):
    if key not in _LOGGED:
        _LOGGED.add(key)
        print("[device-route]", msg, flush=True)


def device_route_rules(d, policies, tables=None):
    """按设备分流 → mihomo 规则列表（SRC-IP-CIDR,<ip>/32|/128|网段,<目标>）。
    目标策略组不存在、MAC 解析不到 IP 的条目跳过（记日志），不会生成无法加载的配置。同一地址只取第一条"""
    entries = _entries(d)
    mapping = mac_mapping(d, tables) if any(e["mac"] for e in entries) else {}
    STATE["last"] = _sig(mapping)
    rules, used = [], set()
    for e in entries:
        tgt = e["target"]
        if tgt not in policies:
            _log_once(("tgt", e["name"], tgt), f"「{e['name']}」的目标「{tgt}」不存在，已跳过")
            continue
        if e["ip"]:
            nets = [e["ip"]]
        else:
            nets = mapping.get(e["mac"]) or []
            if not nets:
                _log_once(("mac", e["mac"]), f"「{e['name']}」（{e['mac']}）当前找不到 IP，暂不生效")
                continue
        for x in nets:
            n = ipaddress.ip_network(x, strict=False)
            if n in used:
                continue
            used.add(n)
            rules.append(f"SRC-IP-CIDR,{n},{tgt}")
    return rules


def route_targets(d):
    return [e["target"] for e in _entries(d)]


def _sig(mapping):
    return {m: list(v) for m, v in sorted(mapping.items())}


def mark_applied():
    """写入正式配置后调用：记下这份配置里 MAC → IP 的解析结果（落盘，开机时 --gen 进程写的面板进程也能读到）"""
    sig = STATE["last"]
    STATE.update(applied=sig, loaded=True)
    try:
        if sig or os.path.isfile(APPLIED_FILE):
            os.makedirs(os.path.dirname(APPLIED_FILE), exist_ok=True)
            with open(APPLIED_FILE + ".tmp", "w") as f:
                json.dump(sig or {}, f)
            os.replace(APPLIED_FILE + ".tmp", APPLIED_FILE)
    except OSError:
        pass


def applied_sig():
    if not STATE["loaded"]:
        STATE["loaded"] = True
        try:
            with open(APPLIED_FILE) as f:
                v = json.load(f)
            STATE["applied"] = v if isinstance(v, dict) else None
        except (OSError, ValueError):
            STATE["applied"] = None
    return STATE["applied"]


def mac_changed(d):
    """MAC 条目解析出的 IP 与当前配置里的不同 → 返回新的解析结果 {mac: [IP]}，没变返回 None（定时任务循环据此重载核心）"""
    if not any(e["mac"] for e in _entries(d)):
        return None
    cur = _sig(mac_mapping(d))
    return cur if cur != (applied_sig() or {}) else None


def _link():
    global arp_table, read_leases
    from .stats import arp_table
    from .devices import read_leases
