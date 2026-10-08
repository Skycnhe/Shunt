#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shunt 分流: 零依赖的旁路由透明代理管理后端 (Alpine Linux, mihomo / sing-box)"""
import json, os, sys, signal, time, hashlib, hmac, secrets, subprocess, threading, re, socket, ssl, base64, copy, ipaddress, shutil
import urllib.request, urllib.error, http.client, gzip, io
from collections import deque
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, urlsplit, parse_qs, unquote, quote

BASE = os.path.dirname(os.path.abspath(__file__))
CONF_DIR = os.environ.get("MIHOMO_DIR", "/etc/mihomo")
DATA_FILE = os.environ.get("PANEL_DATA", "/etc/mihomo-panel/data.json")
PANEL_DIR = os.path.dirname(DATA_FILE)
STATS_FILE = os.path.join(PANEL_DIR, "stats.json")
NOTIFY_FILE = os.path.join(PANEL_DIR, "notify.json")
CERT, KEY = os.path.join(PANEL_DIR, "cert.pem"), os.path.join(PANEL_DIR, "key.pem")
PORT = int(os.environ.get("PANEL_PORT", "8080"))
MIHOMO_BIN = os.environ.get("MIHOMO_BIN", "/usr/local/bin/mihomo")
TPROXY_SH = os.environ.get("PANEL_TPROXY", os.path.join(BASE, "tproxy.sh"))
CTRL_HOST, CTRL_PORT = "127.0.0.1", 9090
MAX_BODY = 32 * 2**20  # 请求体上限 32MB（备份恢复可能较大）
CTRL = f"http://{CTRL_HOST}:{CTRL_PORT}"
MIXED = 7890
WD_INTERVAL = int(os.environ.get("PANEL_WD_INTERVAL", "30"))  # 看门狗检查间隔（秒）
LOCK = threading.RLock()  # 可重入：load() 内迁移写盘时可能已在 update() 的锁内

SVC = os.environ.get("PANEL_SVC", "rc-service mihomo")  # 核心服务控制命令（测试环境可覆盖）
LOG_FILES = [x for x in os.environ.get("PANEL_LOGS", "/var/log/mihomo.log,/var/log/mihomo-panel.log").split(",") if x]
MIHOMO_LOG = LOG_FILES[0] if LOG_FILES else "/var/log/mihomo.log"
AB_DIR = os.path.join(CONF_DIR, "adblock")
AB_STATS_FILE = os.path.join(PANEL_DIR, "adblock_stats.json")
LEASE_FILES = ["/var/lib/misc/dnsmasq.leases", "/tmp/dhcp.leases", "/var/lib/dnsmasq/dnsmasq.leases"]

DEFAULT_EXCLUDE = "剩余|到期|官网|流量|过期|Expire|Traffic"
PROXY_MODES = ("tproxy", "tun", "off")
TUN_STACKS = ("system", "gvisor", "mixed")
DEFAULT_FAKE_FILTER = ["*.lan", "+.local", "+.msftconnecttest.com", "+.msftncsi.com", "time.*.com", "ntp.*.com", "+.ntp.org",
                       "+.stun.*.*", "+.market.xiaomi.com", "localhost.ptlogin2.qq.com"]
DNS_DEFAULT = {"direct": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
               "proxy": ["https://1.1.1.1/dns-query#🚀 节点选择", "https://dns.google/dns-query#🚀 节点选择"],
               "default": ["223.5.5.5", "119.29.29.29"], "pserver": [], "mode": "fake-ip", "fake_filter": DEFAULT_FAKE_FILTER,
               "cache": "arc", "policy": True, "respect_rules": True, "block_bypass": False, "hosts": [], "policies": []}
DNS_LISTS = ("direct", "proxy", "default", "pserver", "fake_filter")
# 客户端绕过 mihomo DNS 的常见公共 DoH / DoT 服务器（阻止客户端绕过 DNS 时拒绝 LAN 设备直连它们的 443 / 853）
DOH_IPS = ["1.1.1.1/32", "1.0.0.1/32", "8.8.8.8/32", "8.8.4.4/32", "9.9.9.9/32", "149.112.112.112/32", "208.67.222.222/32",
           "208.67.220.220/32", "94.140.14.14/32", "94.140.15.15/32", "101.101.101.101/32", "185.222.222.222/32", "45.11.45.11/32",
           "223.5.5.5/32", "223.6.6.6/32", "119.29.29.29/32", "1.12.12.12/32", "120.53.53.53/32", "180.76.76.76/32",
           "180.184.1.1/32", "180.184.2.2/32", "2606:4700:4700::1111/128", "2606:4700:4700::1001/128", "2001:4860:4860::8888/128",
           "2001:4860:4860::8844/128", "2620:fe::fe/128", "2400:3200::1/128", "2400:3200:baba::1/128", "2402:4e00::/128"]
DOH_DOMAINS = ["+.dns.google", "+.cloudflare-dns.com", "+.one.one.one.one", "+.dns.quad9.net", "+.doh.opendns.com", "+.dns.adguard-dns.com",
               "+.dns.adguard.com", "+.dns.nextdns.io", "+.doh.pub", "+.dot.pub", "+.dns.alidns.com", "+.doh.360.cn", "+.dns.twnic.tw",
               "+.mozilla.cloudflare-dns.com", "+.chrome.cloudflare-dns.com", "+.dns.sb", "+.doh.dns.sb"]
LAN_IN = "IN-TYPE,TPROXY/TUN/REDIR"  # 只针对透明代理进来的局域网流量；mihomo 自己的 DNS 查询（Inner）与 7890 端口不受影响
# 国内（会看到你查询国外域名就算泄露）的 DNS 服务器特征
CN_DNS = re.compile(r"(?i)(?:^|[/@\[])(?:223\.5\.5\.5|223\.6\.6\.6|2400:3200|119\.29\.29\.29|119\.28\.28\.28|182\.254\.11[68]\.116|"
                    r"1\.12\.12\.12|120\.53\.53\.53|2402:4e00|114\.114\.11[45]\.11[45]|180\.76\.76\.76|180\.184\.[12]\.[12]|"
                    r"101\.226\.4\.6|218\.30\.118\.6|117\.50\.\d+\.\d+|52\.80\.\d+\.\d+|"
                    r"[\w.-]*(?:alidns\.com|doh\.pub|dot\.pub|dnspod\.(?:cn|com)|360\.cn|114dns\.com|onedns\.net|baidu\.com|volces\.com))(?:[:/#\]]|$)")
AB_DEFAULT = {"enabled": False, "lists": [], "black": [], "white": [], "interval": 86400, "dns": False}
AB_PRESETS = [{"name": "AdGuard DNS filter", "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"},
              {"name": "anti-AD", "url": "https://anti-ad.net/easylist.txt"}]
TUN_DEFAULT = {"stack": "mixed", "device": "Meta", "auto_redirect": True, "strict_route": False}
GROUPS_DEFAULT = {"type": "url-test", "lb": True, "auto": True, "strategy": "consistent-hashing", "interval": 300,
                  "tolerance": 50, "url": "https://www.gstatic.com/generate_204", "extra": True, "other": True, "lazy": True}
SCHED_DEFAULT = {"sub_update": "", "core_restart": "", "geo_update": "", "latency": 0}
DEFAULT = {"password": "admin", "pw_hash": "", "pw_default": False, "secret": "", "mode": "rule", "tproxy": True, "subs": [], "rules": [],
           "rulesets": [], "bypass": [], "tests": None, "sub_interval": 86400, "region_groups": True,
           "nodes": [], "ipv6": False, "https": False, "watchdog": True, "tg_token": "", "tg_chat": "",
           "proxy_mode": "", "tun": TUN_DEFAULT, "log_limit": 5, "adblock": AB_DEFAULT, "dns": DNS_DEFAULT,
           "devices": {}, "schedule": SCHED_DEFAULT, "groups_cfg": GROUPS_DEFAULT, "custom_groups": [], "sniffer": True,
           "gh_proxy": "", "core": "mihomo", "schema": 0, "sysopt": [], "sysopt_orig": {}, "sysopt_mods": []}
TESTS = [
    {"name": "Google", "url": "https://www.google.com/generate_204"},
    {"name": "YouTube", "url": "https://www.youtube.com/generate_204"},
    {"name": "Telegram", "url": "https://api.telegram.org"},
    {"name": "GitHub", "url": "https://github.com"},
    {"name": "百度", "url": "https://www.baidu.com"},
]
G_SEL, G_YT, G_GG, G_TG, G_FINAL = "🚀 节点选择", "📹 YouTube", "🔍 Google", "📲 Telegram", "🐟 漏网之鱼"
G_AI, G_NF = "🤖 AI 服务", "🎬 Netflix"
G_MANUAL, G_AUTO, G_DIRECT = "\U0001F590\uFE0F 手动选择", "⚡ 全局自动选择", "🏠 直连"
LB_PREFIX, AUTO_TAIL, LB_TAIL = "\u2696\uFE0F ", "自动优选", "负载均衡"
LEGACY_AUTO = "♻️ 自动选择"  # v5 及以前的名称，读取旧数据时自动迁移
AUTO_ORDER = ["日本", "新加坡", "香港", "美国"]  # 「自动优选」组在节点选择中的顺序，其余地区按识别顺序排在后面
LB_ORDER = ["香港", "日本", "新加坡", "美国"]    # 「负载均衡」组的顺序
SCHEMA = 6
PANEL_VERSION = "6.6.3"
L, R = "(?<![A-Za-z])", "(?![A-Za-z])"  # 英文缩写两侧不能紧挨字母，避免 (?i)US 误匹配 Russia / Plus / Australia
REGIONS = [  # (分组名, 正则)；正则同时在 Python 与 mihomo(regexp2) 中使用，只用两者都支持的语法
    ("🇭🇰 香港", f"🇭🇰|(?i:香港|港|Hong ?Kong)|{L}HKG?{R}"),
    ("🇹🇼 台湾", f"🇹🇼|(?i:台|Taiwan|Taipei)|{L}TWN?{R}"),
    ("🇯🇵 日本", f"🇯🇵|(?i:日本|东京|東京|大阪|埼玉|Japan|Tokyo|Osaka)|{L}JPN?{R}"),
    ("🇸🇬 新加坡", f"🇸🇬|(?i:新加坡|狮城|獅城|Singapore)|{L}SGP?{R}"),
    ("🇺🇸 美国", f"🇺🇸|(?i:美国|美國|洛杉矶|圣何塞|硅谷|纽约|西雅图|芝加哥|达拉斯|凤凰城|United ?States|America|Los ?Angeles|San ?Jose|Seattle|New ?York|Chicago|Dallas)|{L}USA?{R}"),
    # 以下为扩展地区（设置 → 策略组 可关闭），只有确实存在节点时才生成
    ("🇰🇷 韩国", f"🇰🇷|(?i:韩国|韓國|首尔|首爾|春川|Korea|Seoul)|{L}KOR?{R}"),
    ("🇬🇧 英国", f"🇬🇧|(?i:英国|英國|伦敦|倫敦|United ?Kingdom|Britain|London)|{L}(?:UK|GB|GBR){R}"),
    ("🇩🇪 德国", f"🇩🇪|(?i:德国|德國|法兰克福|Germany|Frankfurt)|{L}DEU?{R}"),
    ("🇫🇷 法国", f"🇫🇷|(?i:法国|法國|巴黎|France|Paris)|{L}FRA?{R}"),
    ("🇳🇱 荷兰", f"🇳🇱|(?i:荷兰|荷蘭|阿姆斯特丹|Netherlands|Amsterdam)|{L}NLD?{R}"),
    ("🇨🇦 加拿大", f"🇨🇦|(?i:加拿大|多伦多|温哥华|Canada|Toronto|Vancouver)|{L}CAN?{R}"),
    ("🇦🇺 澳大利亚", f"🇦🇺|(?i:澳大利亚|澳洲|悉尼|墨尔本|Australia|Sydney|Melbourne)|{L}AUS?{R}"),
    ("🇷🇺 俄罗斯", f"🇷🇺|(?i:俄罗斯|俄羅斯|莫斯科|Russia|Moscow)|{L}RUS?{R}"),
    ("🇮🇳 印度", f"🇮🇳|(?i:印度|孟买|India|Mumbai)|{L}IND?{R}"),
    ("🇹🇷 土耳其", f"🇹🇷|(?i:土耳其|伊斯坦布尔|Turkey|Türkiye|Istanbul)|{L}TUR?{R}"),
    ("🇲🇾 马来西亚", f"🇲🇾|(?i:马来|馬來|吉隆坡|Malaysia)|{L}MYS?{R}"),
    ("🇹🇭 泰国", f"🇹🇭|(?i:泰国|泰國|曼谷|Thailand|Bangkok)|{L}THA?{R}"),
    ("🇻🇳 越南", f"🇻🇳|(?i:越南|胡志明|Vietnam)|{L}VNM?{R}"),
    ("🇵🇭 菲律宾", f"🇵🇭|(?i:菲律宾|菲律賓|马尼拉|Philippines)|{L}PHL?{R}"),
    ("🇦🇷 阿根廷", f"🇦🇷|(?i:阿根廷|Argentina)|{L}ARG?{R}"),
    ("🇧🇷 巴西", f"🇧🇷|(?i:巴西|圣保罗|Brazil)|{L}BRA?{R}"),
]
PRIMARY_REGIONS = 5
G_OTHER = "🌐 其他"
LB_SUFFIX, AUTO_SUFFIX = "均衡", "自动"  # 旧版（v5）地区组后缀，仅用于迁移
GROUP_TYPES = ("select", "url-test", "fallback", "load-balance")
LB_STRATEGIES = ("consistent-hashing", "round-robin", "sticky-sessions")
SIDE_GROUPS = [G_YT, G_GG, G_TG, G_AI, G_NF, G_FINAL]
BUILTIN_POLICIES = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}
HC = "https://www.gstatic.com/generate_204"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"


# ---------------------------------------------------------------- 数据
def load():
    try:
        with open(DATA_FILE) as f:
            d = json.load(f)
    except Exception:
        d = {}
    for k, v in DEFAULT.items():
        d.setdefault(k, copy.deepcopy(v))
        if isinstance(v, dict) and isinstance(d[k], dict) and k != "devices":
            for kk, vv in v.items():
                d[k].setdefault(kk, copy.deepcopy(vv))
    if d["proxy_mode"] not in PROXY_MODES:  # 旧版只有 tproxy 布尔值
        d["proxy_mode"] = "tproxy" if d.get("tproxy", True) else "off"
    d["tproxy"] = d["proxy_mode"] == "tproxy"
    if not d["tests"]:
        d["tests"] = [dict(t) for t in TESTS]
    dirty = False
    if d.get("password") and not d.get("pw_hash"):  # 旧版明文密码 → PBKDF2 哈希，明文不再落盘
        d["pw_default"] = d["password"] == "admin"
        d["pw_hash"] = pw_hash(d["password"])
        d["password"] = ""
        dirty = True
    if not d["secret"]:
        d["secret"] = secrets.token_hex(16)
        dirty = True
    if int(d.get("schema") or 0) < SCHEMA:  # v5 → v6：地区组改名（如 🇺🇸 美国 → 🇺🇸 美国自动优选），同步所有引用
        migrate_names(d)
        d["schema"] = SCHEMA
        dirty = True
    if dirty:
        with LOCK:
            save(d)
    return d


def region_label(rname):
    """「🇺🇸 美国」→ (「🇺🇸」, 「美国」)"""
    flag, _, label = rname.partition(" ")
    return flag, label


def auto_name(rname):
    flag, label = region_label(rname)
    return f"{flag} {label}{AUTO_TAIL}"


def lb_name(rname):
    return LB_PREFIX + region_label(rname)[1] + LB_TAIL


def legacy_map():
    """旧版策略组名 → 新名称"""
    m = {LEGACY_AUTO: G_AUTO}
    for rname in [r[0] for r in REGIONS] + [G_OTHER]:
        m[rname] = m[rname + AUTO_SUFFIX] = auto_name(rname)
        m[rname + LB_SUFFIX] = lb_name(rname)
    return m


def map_dns_server(x, mp):
    pol = dns_policy_of(x)
    if pol and pol in mp:
        head, _, tail = x.partition("#")
        return head + "#" + mp[pol] + tail[len(pol):]
    return x


def map_refs(d, mp, drop=()):
    """按 mp {旧名: 新名} 改写自定义规则、规则集、自定义组成员、各 DNS 列表里的策略组引用；drop 中的名字从自定义组成员里删除。返回改动数"""
    n = 0
    rules = []
    for r in d.get("rules") or []:
        parts = r.split(",")
        i = rule_policy_index(parts)
        if not r.startswith("#") and i > 0 and parts[i].strip() in mp:
            parts[i] = mp[parts[i].strip()]
            n += 1
        rules.append(",".join(parts))
    d["rules"] = rules
    for r in d.get("rulesets") or []:
        if r.get("target") in mp:
            r["target"] = mp[r["target"]]
            n += 1
    for g in d.get("custom_groups") or []:
        old = list(g.get("proxies") or [])
        new = []
        for m in old:
            if m in drop:
                continue
            m = mp.get(m, m)
            if m not in new:
                new.append(m)
        if new != old:
            g["proxies"] = new
            n += 1
    dc = d.get("dns") or {}
    for k in ("direct", "proxy", "pserver"):
        out = []
        for x in dc.get(k) or []:
            y = map_dns_server(x, mp)
            n += y != x
            out.append(y)
        if k in dc:
            dc[k] = out
    for pe in dc.get("policies") or []:
        out = [map_dns_server(x, mp) for x in pe.get("servers") or []]
        n += out != pe.get("servers")
        pe["servers"] = out
    return n


def migrate_names(d):
    mp = legacy_map()
    return map_refs(d, {k: v for k, v in mp.items() if k != v})


def save(d):
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, DATA_FILE)


def update(fn):
    """在锁内读-改-写 data.json，返回修改前的副本（用于配置校验失败时回滚）；有实际变化时把旧版本记入配置快照"""
    with LOCK:
        d = load()
        prev = copy.deepcopy(d)
        fn(d)
        save(d)
        try:
            history_push(prev, d)
        except Exception as e:
            print("history error", e, flush=True)
    return prev


HISTORY_FILE = os.path.join(PANEL_DIR, "history.json")
HISTORY_MAX = 10
HISTORY_SKIP = {"core", "password", "pw_hash", "pw_default", "secret", "devices", "https", "schema", "sysopt", "sysopt_orig", "sysopt_mods"}
KEY_LABEL = {"subs": "订阅", "nodes": "节点", "rules": "自定义规则", "rulesets": "规则集", "dns": "DNS", "adblock": "广告拦截",
             "custom_groups": "自定义策略组", "groups_cfg": "地区分组", "region_groups": "地区分组", "proxy_mode": "代理方式",
             "tun": "TUN", "ipv6": "IPv6", "bypass": "绕过设备", "mode": "代理模式", "sniffer": "域名嗅探", "schedule": "定时任务",
             "tests": "延迟站点", "sub_interval": "订阅间隔", "tg_token": "Telegram", "tg_chat": "Telegram", "watchdog": "看门狗",
             "log_limit": "日志上限", "gh_proxy": "GitHub 加速", "tproxy": "代理方式"}


def history_push(prev, cur):
    keys = sorted(k for k in set(prev) | set(cur) if k not in HISTORY_SKIP and prev.get(k) != cur.get(k))
    if not keys:
        return
    h = read_json(HISTORY_FILE, [])
    snap = {k: v for k, v in prev.items() if k not in HISTORY_SKIP}
    if h and h[0].get("data") == snap:
        return
    labels = []
    for k in keys:
        lb = KEY_LABEL.get(k, k)
        if lb not in labels:
            labels.append(lb)
    h.insert(0, {"id": secrets.token_hex(4), "t": int(time.time()), "changed": labels, "data": snap})
    write_json(HISTORY_FILE, h[:HISTORY_MAX])


def read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".tmp", "w") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.replace(path + ".tmp", path)


def safe(name):
    return re.sub(r"[^\w\-]", "_", name) or "sub"


# ---------------------------------------------------------------- 单节点链接解析
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
    raise ValueError("不支持的链接类型")


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
        out |= {r, r + LB_SUFFIX, r + AUTO_SUFFIX, auto_name(r), lb_name(r)}
    if d:
        out |= {g["name"] for g in d.get("custom_groups") or []}
    return out


# ---------------------------------------------------------------- 策略组
PROV_FILE = os.path.join(PANEL_DIR, "provider_nodes.json")
PROV = {"t": 0, "data": None}
RX_CACHE = {}


def rx(pattern):
    """编译正则（缓存）；无效时返回 None"""
    if pattern not in RX_CACHE:
        try:
            RX_CACHE[pattern] = re.compile(pattern)
        except re.error:
            RX_CACHE[pattern] = None
    return RX_CACHE[pattern]


def provider_nodes(fresh=False):
    """订阅（proxy-provider）里的节点名 {订阅名: [节点名]}：优先读运行中的核心，缓存到文件供核心未运行时生成配置"""
    now = time.time()
    if not fresh and PROV["data"] is not None and now - PROV["t"] < 60:
        return PROV["data"]
    data = None
    if active_core() == "singbox":  # sing-box 的订阅由面板下载解析，节点名直接取缓存
        data = sb_provider_nodes(load())
        PROV.update(t=now, data=data)
        return data
    j = None if os.environ.get("PANEL_OFFLINE") else core_json("/providers/proxies", timeout=3)
    if j is not None:
        data = {}
        for name, p in (j.get("providers") or {}).items():
            if p.get("vehicleType") in ("HTTP", "File", "Inline") and p.get("proxies") is not None:
                data[name] = [x.get("name") for x in p["proxies"] if x.get("name")]
        if data != read_json(PROV_FILE, None):
            try:
                write_json(PROV_FILE, data)
            except Exception:
                pass
    if data is None:
        data = read_json(PROV_FILE, {})
    PROV.update(t=now, data=data)
    return data


def gcfg(d):
    gc = dict(GROUPS_DEFAULT)
    gc.update({k: v for k, v in (d.get("groups_cfg") or {}).items() if k in GROUPS_DEFAULT})
    gc["type"] = "url-test"  # v6：地区「自动优选」组固定为 url-test（旧的地区主组类型设置不再使用）
    if gc["strategy"] not in LB_STRATEGIES:
        gc["strategy"] = "consistent-hashing"
    return gc


def group_opts(t, gc, extra=None):
    """各类型策略组的公共参数"""
    e = extra or {}
    g = {"type": t}
    if t != "select":
        g.update({"url": e.get("url") or gc["url"], "interval": int(e.get("interval") or gc["interval"]), "lazy": bool(gc["lazy"])})
        if t == "url-test":
            g["tolerance"] = int(e.get("tolerance") if e.get("tolerance") not in (None, "") else gc["tolerance"])
        if t == "load-balance":
            g["strategy"] = e.get("strategy") if e.get("strategy") in LB_STRATEGIES else gc["strategy"]
    return g


def region_plan(d, names, use):
    """返回 [(地区名, 正则或 None, exclude 正则或 None, 手动节点, 节点总数, 是否未知)]，只保留确实有节点的地区"""
    if not (use or names) or not d.get("region_groups", True):
        return []
    gc = gcfg(d)
    pn = provider_nodes() if use else {}
    subs = [s["name"] for s in d["subs"]]
    unknown = any(s not in pn for s in subs)
    pnames = [n for s in subs for n in pn.get(s, [])]
    regs = REGIONS if gc["extra"] else REGIONS[:PRIMARY_REGIONS]
    out = []
    for i, (rname, flt) in enumerate(regs):
        r = rx(flt)
        matched = [n for n in names if r.search(n)]
        total = len(matched) + sum(1 for n in pnames if r.search(n))
        if total or (unknown and i < PRIMARY_REGIONS):  # 订阅还没加载过：沿用旧行为，先生成 5 个常用地区
            out.append((rname, flt, None, matched, total, unknown))
    if gc["other"]:
        alls = [rx(f) for _, f in regs]
        matched = [n for n in names if not any(r.search(n) for r in alls)]
        total = len(matched) + sum(1 for n in pnames if not any(r.search(n) for r in alls))
        if total:
            out.append((G_OTHER, None, "|".join(f for _, f in regs), matched, total, unknown))
    return out


def all_node_names(d):
    """手动节点 + 已知订阅节点"""
    pn = provider_nodes() if d["subs"] else {}
    return [n["proxy"]["name"] for n in d.get("nodes", [])] + [n for s in d["subs"] for n in pn.get(s["name"], [])]


def find_cycle(groups):
    """策略组之间的循环引用，返回环路径或 None"""
    gmap = {g["name"]: [m for m in g.get("proxies", [])] for g in groups}
    state, stack = {}, []

    def dfs(n):
        state[n] = 1
        stack.append(n)
        for m in gmap.get(n, []):
            if m in gmap:
                if state.get(m) == 1:
                    return stack[stack.index(m):] + [m]
                if not state.get(m):
                    c = dfs(m)
                    if c:
                        return c
        state[n] = 2
        stack.pop()
        return None

    for n in gmap:
        if not state.get(n):
            c = dfs(n)
            if c:
                return c
    return None


NAME_BAD = re.compile(r"[,#\n\r\t\"]")


def clean_custom_group(b):
    """校验并规范化一个自定义策略组（不含引用检查）"""
    name = str(b.get("name") or "").strip()
    if not name or len(name) > 40 or NAME_BAD.search(name):
        raise ValueError("名称不能为空、不超过 40 字，且不能包含逗号、# 或引号")
    t = b.get("type") or "select"
    if t not in GROUP_TYPES:
        raise ValueError("类型只能是 select / url-test / fallback / load-balance")
    members = []
    for m in b.get("proxies") or []:
        m = str(m).strip()
        if m and m not in members:
            members.append(m)
    flt = str(b.get("filter") or "").strip()
    if flt and rx(flt) is None:
        raise ValueError(f"筛选正则无效：{flt}")
    if not members and not flt:
        raise ValueError("请至少选择一个成员，或填写筛选正则")
    icon = str(b.get("icon") or "").strip()
    if icon and not re.match(r"^https?://\S{4,500}$", icon):
        raise ValueError("图标必须是 http(s) 图片地址")
    g = {"name": name, "type": t, "proxies": members, "filter": flt, "subs": bool(b.get("subs", True)),
         "expose": bool(b.get("expose", True)), "icon": icon}
    if t != "select":
        try:
            iv = int(b.get("interval") or 0)
            tol = int(b.get("tolerance") or 0)
        except (TypeError, ValueError):
            raise ValueError("测速间隔 / 容差必须是数字")
        if iv and not 30 <= iv <= 86400:
            raise ValueError("测速间隔应在 30–86400 秒之间")
        if not 0 <= tol <= 1000:
            raise ValueError("容差应在 0–1000 ms 之间")
        g.update(interval=iv, tolerance=tol)
        if t == "load-balance":
            st = b.get("strategy") or "consistent-hashing"
            if st not in LB_STRATEGIES:
                raise ValueError("负载均衡策略无效")
            g["strategy"] = st
    return g


def validate_groups(d):
    """生成配置后检查自定义组：重名、成员不存在、循环引用"""
    errs = []
    nodes = all_node_names(d)
    fixed = reserved_names()
    seen = set()
    for cg in d.get("custom_groups") or []:
        n = cg["name"]
        if n in seen:
            errs.append(f"策略组重名：{n}")
        if n in fixed:
            errs.append(f"「{n}」与内置策略组或策略同名")
        if n in nodes:
            errs.append(f"「{n}」与节点同名")
        seen.add(n)
    cfg = build_config(d, strict=True)
    names = {g["name"] for g in cfg["proxy-groups"]} | BUILTIN_POLICIES | {p["name"] for p in cfg["proxies"]}
    for cg in d.get("custom_groups") or []:
        miss = [m for m in cg["proxies"] if m not in names]
        if miss:
            errs.append(f"「{cg['name']}」的成员不存在：" + "、".join(miss[:5]))
        if cg["name"] in cg["proxies"]:
            errs.append(f"「{cg['name']}」不能包含自己")
    cyc = find_cycle(cfg["proxy-groups"])
    if cyc:
        errs.append("策略组循环引用：" + " → ".join(cyc) + "（加入分流组候选的自定义组不能再引用 YouTube / Google 等分流组，可关闭“加入分流组候选”）")
    return errs


# ---------------------------------------------------------------- 生成配置
def build_config(d, strict=False):
    providers = {}
    for s in d["subs"]:
        pv = {
            "type": "http", "url": s["url"], "path": f"./providers/{safe(s['name'])}.yaml",
            "interval": int(d.get("sub_interval") or 86400),
            "health-check": {"enable": True, "url": HC, "interval": 300},
        }
        if s.get("filter"):
            pv["filter"] = s["filter"]
        exc = s.get("exclude", DEFAULT_EXCLUDE)
        if exc:
            pv["exclude-filter"] = exc
        providers[s["name"]] = pv
    use = list(providers)
    proxies = [n["proxy"] for n in d.get("nodes", [])]
    names = [p["name"] for p in proxies]
    gc = gcfg(d)

    def with_src(g, members, src=True):
        if members:
            g["proxies"] = members
        if use and src:
            g["use"] = list(use)
        if not g.get("proxies") and not g.get("use"):
            g["proxies"] = ["COMPATIBLE"]
        return g

    # 地区分组：「<旗> <地区>自动优选」(url-test) + 「⚖️ <地区>负载均衡」(load-balance，≥2 个节点时)
    autos, lbs = [], []
    for rname, flt, exc, matched, total, unknown in region_plan(d, names, use):
        label = region_label(rname)[1]
        variants = [(auto_name(rname), "url-test", autos)]
        if gc["lb"]:  # 每个有节点的地区都生成「⚖️ <地区>负载均衡」
            variants.append((lb_name(rname), "load-balance", lbs))
        for gname, t, bucket in variants:
            g = with_src(dict({"name": gname}, **group_opts(t, gc)), matched)
            if use:
                if flt:
                    g["filter"] = flt
                if exc:
                    g["exclude-filter"] = exc
            bucket.append((label, g))

    def ordered(items, order):
        rank = {n: i for i, n in enumerate(order)}
        return [g for i, (label, g) in sorted(enumerate(items), key=lambda x: (rank.get(x[1][0], len(order)), x[0]))]
    region_groups = ordered(autos, AUTO_ORDER) + ordered(lbs, LB_ORDER)
    rnames = [g["name"] for g in region_groups]

    # 自定义策略组
    custom_groups, cnames, exposed = [], [], []
    region_set = set(rnames)
    for cg in d.get("custom_groups") or []:
        try:
            cg = clean_custom_group(cg)
        except ValueError:
            continue
        members = list(cg["proxies"])
        if cg["filter"]:
            r = rx(cg["filter"])
            members += [n for n in names if r.search(n) and n not in members]
        g = dict({"name": cg["name"]}, **group_opts(cg["type"], gc, cg))
        g["_members"] = members
        if cg["icon"]:
            g["icon"] = cg["icon"]
        if cg["filter"] and cg["subs"] and use:
            g["use"], g["filter"] = list(use), cg["filter"]
        custom_groups.append(g)
        cnames.append(cg["name"])
        if cg["expose"]:
            exposed.append(cg["name"])

    # 🚀 节点选择 只包含：各地区自动优选 → 各地区负载均衡 → 🖐️ 手动选择 → ⚡ 全局自动选择 → 🏠 直连
    have = bool(use or names)
    direct_g = {"name": G_DIRECT, "type": "select", "proxies": ["DIRECT"]}
    if have:
        groups = [{"name": G_SEL, "type": "select", "proxies": rnames + [G_MANUAL, G_AUTO, G_DIRECT]}] + region_groups + [
            with_src({"name": G_MANUAL, "type": "select"}, names),
            with_src(dict({"name": G_AUTO}, **group_opts("url-test", gc)), names), direct_g]
        side = [G_SEL] + rnames + [G_MANUAL, G_AUTO] + exposed + ["DIRECT"] + names
    else:
        groups = [{"name": G_SEL, "type": "select", "proxies": [G_DIRECT]}, direct_g]
        side = [G_SEL] + exposed + ["DIRECT"]
    for g in SIDE_GROUPS:
        groups.append(with_src({"name": g, "type": "select"}, list(side)))
    known = {g["name"] for g in groups} | region_set | set(cnames) | BUILTIN_POLICIES | set(names)
    for g in custom_groups:
        members = g.pop("_members")
        if not strict:  # 成员已不存在（地区组消失、节点被删）时跳过，避免整份配置无法加载
            members = [m for m in members if m in known]
        if members:
            g["proxies"] = members
        if not g.get("proxies") and not g.get("use"):
            g["proxies"] = ["COMPATIBLE"]
        groups.append(g)
    policies = {g["name"] for g in groups} | BUILTIN_POLICIES | set(names)

    rule_providers = {}
    rs_rules = []
    for r in d.get("rulesets", []):
        ext = {"mrs": "mrs", "text": "list"}.get(r.get("format"), "yaml")
        rule_providers[r["name"]] = {"type": "http", "behavior": r.get("behavior", "domain"), "format": r.get("format", "yaml"),
                                     "url": r["url"], "path": f"./rules/{safe(r['name'])}.{ext}", "interval": 86400}
        tgt = r.get("target", G_SEL) if r.get("target", G_SEL) in policies else G_SEL
        rs_rules.append(f"RULE-SET,{r['name']},{tgt}" + (",no-resolve" if r.get("behavior") == "ipcidr" else ""))
    custom = [fix_rule_policy(x, policies) for x in d["rules"]]
    pre = []
    if d.get("proxy_mode") == "tun":  # TUN 模式下无法在 nftables 里按来源绕过，改用规则让这些设备直连
        for x in d.get("bypass", []):
            try:
                n = ipaddress.ip_network(x.strip(), strict=False)
                pre.append(f"SRC-IP-CIDR,{n},DIRECT")
            except ValueError:
                pass
    ab_prov, ab_rules = adblock_providers(d)
    rule_providers.update(ab_prov)
    dc = dns_cfg(d)
    guard = []
    if dc["block_bypass"]:  # 阻止局域网设备绕过 mihomo DNS：拒绝 DoT/DoQ(853) 与已知公共 DoH 服务器
        rule_providers["dns-bypass-ip"] = {"type": "inline", "behavior": "ipcidr", "payload": list(DOH_IPS)}
        rule_providers["dns-bypass-domain"] = {"type": "inline", "behavior": "domain", "payload": list(DOH_DOMAINS)}
        guard = [f"AND,(({LAN_IN}),(DST-PORT,853)),REJECT",
                 f"AND,(({LAN_IN}),(DST-PORT,443),(RULE-SET,dns-bypass-ip,no-resolve)),REJECT",
                 f"AND,(({LAN_IN}),(RULE-SET,dns-bypass-domain)),REJECT"]
    rules = pre + guard + ab_rules + [x for x in custom if x] + rs_rules + [
        "GEOSITE,private,DIRECT", "GEOIP,private,DIRECT,no-resolve",
        f"GEOSITE,category-ai-!cn,{G_AI}", f"GEOSITE,netflix,{G_NF}", f"GEOIP,netflix,{G_NF},no-resolve",
        f"GEOSITE,youtube,{G_YT}", f"GEOSITE,google,{G_GG}", f"GEOIP,google,{G_GG},no-resolve",
        f"GEOSITE,telegram,{G_TG}", f"GEOIP,telegram,{G_TG},no-resolve",
        f"GEOSITE,geolocation-!cn,{G_SEL}", "GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT", f"MATCH,{G_FINAL}",
    ]
    v6 = bool(d.get("ipv6"))
    fx = lambda xs: [fix_dns_policy(x, policies) for x in xs]
    direct = fx(dc["direct"] or DNS_DEFAULT["direct"])
    proxy_dns = fx(dc["proxy"])
    plain_direct = [x.split("#", 1)[0] for x in direct]
    mode = dc["mode"]
    # 防泄露布局：默认 nameserver = 代理 DNS（经节点发出），只有 geosite:cn / private 用直连 DNS；
    # 节点域名由 proxy-server-nameserver 解析，DIRECT 连接由 direct-nameserver 解析；不使用 fallback
    dns = {
        "enable": True, "listen": "[::]:1053" if v6 else "0.0.0.0:1053", "ipv6": v6, "enhanced-mode": mode,
        "cache-algorithm": dc["cache"], "prefer-h3": False, "use-hosts": True, "use-system-hosts": False,
        "respect-rules": bool(dc["respect_rules"]),
        "default-nameserver": list(dc["default"] or DNS_DEFAULT["default"]),
        "nameserver": proxy_dns or direct,
        "proxy-server-nameserver": [x.split("#", 1)[0] for x in dc["pserver"]] or plain_direct,
        "direct-nameserver": plain_direct, "direct-nameserver-follow-policy": False,
    }
    if mode == "fake-ip":
        dns["fake-ip-range"] = "198.18.0.1/16"
        dns["fake-ip-filter"] = [x for x in dc["fake_filter"] if x.strip()]
        if v6:
            dns["fake-ip-range6"] = "fdfe:dcba:9876::1/64"
    pol = {}
    ab = d.get("adblock") or {}
    if ab.get("enabled") and ab.get("dns"):  # DNS 层拦截：白名单先走直连 DNS，其余命中拦截列表直接返回 NXDOMAIN
        if "ad-allow" in ab_prov:
            pol["rule-set:ad-allow"] = direct
        for k in ab_prov:
            if k != "ad-allow":
                pol["rule-set:" + k] = "rcode://name_error"
    for pe in dc["policies"]:  # 用户自定义的 nameserver-policy（排在内置分流之前，JSON 保序，mihomo 按顺序匹配）
        if pe["match"] not in pol:
            pol[pe["match"]] = fx(pe["servers"])
    if dc["policy"] and proxy_dns:  # 国内域名走直连 DNS，其余（含未知域名）走代理 DNS
        pol.setdefault("geosite:cn,private", direct)
    if pol:
        dns["nameserver-policy"] = pol
    hosts = {}
    for h in dc["hosts"]:
        vals = hosts.setdefault(h["domain"], [])
        vals += [v for v in h["value"] if v not in vals]
    hosts = {k: (v[0] if len(v) == 1 else v) for k, v in hosts.items()}
    tc = d.get("tun") or TUN_DEFAULT
    if d.get("proxy_mode") == "tun":
        tun = {"enable": True, "stack": tc.get("stack") if tc.get("stack") in TUN_STACKS else "mixed",
               "device": safe_dev(tc.get("device")), "auto-route": True, "auto-redirect": bool(tc.get("auto_redirect", True)),
               "auto-detect-interface": True, "dns-hijack": ["any:53", "tcp://any:53"],
               "strict-route": bool(tc.get("strict_route", False))}
    else:
        tun = {"enable": False}
    return {
        "mixed-port": MIXED, "tproxy-port": 7893, "allow-lan": True, "bind-address": "*",
        "mode": d.get("mode", "rule"), "log-level": "info", "ipv6": v6,
        "external-controller": f"{CTRL_HOST}:{CTRL_PORT}", "secret": d["secret"],
        "unified-delay": True, "tcp-concurrent": True, "global-ua": "clash.meta",
        "geodata-mode": True, "geo-auto-update": True, "geo-update-interval": 24,
        "geox-url": {
            "geoip": "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat",
            "geosite": "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
            "mmdb": "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb",
        },
        "profile": {"store-selected": True, "store-fake-ip": True},
        "sniffer": {"enable": bool(d.get("sniffer", True)), "sniff": {
            "HTTP": {"ports": [80, "8080-8880"], "override-destination": True},
            "TLS": {"ports": [443, 8443]}, "QUIC": {"ports": [443, 8443]}}},
        "dns": dns, "tun": tun, "hosts": hosts,
        "proxies": proxies,
        "proxy-providers": providers, "rule-providers": rule_providers, "proxy-groups": groups, "rules": rules,
    }


def rule_policy_index(parts):
    i = len(parts) - 1
    while i > 0 and parts[i].strip().lower() in ("no-resolve", "src"):
        i -= 1
    return i


def fix_rule_policy(rule, policies):
    """自定义规则引用了不存在的策略组时改用节点选择，避免整份配置无法加载"""
    rule = rule.strip()
    if not rule or rule.startswith("#"):
        return None
    parts = rule.split(",")
    i = rule_policy_index(parts)
    if i > 0 and parts[i].strip() not in policies and not parts[i].strip().endswith(")"):
        parts[i] = G_SEL
    return ",".join(parts)


def safe_dev(name):
    name = re.sub(r"[^A-Za-z0-9_\-]", "", str(name or ""))[:15]
    return name or "Meta"


DNS_RX = re.compile(r"^(?:(?:https|tls|quic|udp|tcp|h3)://[^\s#]+|dhcp://[\w.\-]+|system(?:://)?|rcode://\w+|"
                    r"\[?[0-9a-fA-F:.]+\]?(?::\d+)?)(?:#\S.*)?$")
HOST_KEY_RX = re.compile(r"^(?:\+\.|\*\.)?(?:[a-z0-9_*](?:[a-z0-9_\-*]{0,61}[a-z0-9_*])?\.)*[a-z0-9_\-]{1,63}$")
POLICY_DOMAIN_RX = re.compile(r"^(?:\+\.|\*\.|\.)?(?:[a-z0-9_*\-]+\.)*[a-z0-9_*\-]+$", re.I)
POLICY_NAME_RX = re.compile(r"^[\w@!\-.]+$")


def norm_policy_match(m):
    """nameserver-policy 的键：geosite:a,b / rule-set:x,y / 域名1,域名2（mihomo 不支持在一个键里混用）"""
    parts = [x.strip() for x in str(m).split(",") if x.strip()]
    for pre in ("geosite:", "rule-set:"):
        if parts and parts[0].lower().startswith(pre):
            return pre + ",".join(x[len(pre):] if x.lower().startswith(pre) else x for x in parts)
    return ",".join(parts)


def policy_parts(m):
    """返回 (类型, [名称])：类型为 geosite / rule-set / domain"""
    for pre in ("geosite:", "rule-set:"):
        if m.lower().startswith(pre):
            return pre[:-1], m[len(pre):].split(",")
    return "domain", m.split(",")


def is_ip_addr(v):
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def dns_cfg(d):
    """data.json 里的 dns 设置补齐默认值并规范化（旧版数据没有的键用默认值）"""
    dc = dict(DNS_DEFAULT)
    dc.update(d.get("dns") or {})
    for k in DNS_LISTS:
        dc[k] = [str(x).strip() for x in (dc.get(k) if isinstance(dc.get(k), list) else DNS_DEFAULT[k]) if str(x).strip()]
    if dc.get("mode") not in ("fake-ip", "redir-host"):
        dc["mode"] = "fake-ip"
    if dc.get("cache") not in ("arc", "lru"):
        dc["cache"] = "arc"
    for k in ("policy", "respect_rules", "block_bypass"):
        dc[k] = bool(dc.get(k, DNS_DEFAULT[k]))
    hosts = []
    for h in dc.get("hosts") or []:
        if isinstance(h, dict) and h.get("domain") and h.get("value"):
            v = h["value"] if isinstance(h["value"], list) else str(h["value"]).replace(",", " ").split()
            hosts.append({"domain": str(h["domain"]).strip().lower(), "value": [str(x).strip() for x in v if str(x).strip()]})
    dc["hosts"] = hosts
    pols = []
    for pe in dc.get("policies") or []:
        if isinstance(pe, dict) and pe.get("match") and pe.get("servers"):
            sv = pe["servers"] if isinstance(pe["servers"], list) else str(pe["servers"]).split(",")
            pols.append({"match": norm_policy_match(pe["match"]),
                         "servers": [str(x).strip() for x in sv if str(x).strip()]})
    dc["policies"] = pols
    return dc


def dns_policy_of(server):
    _, sep, tail = server.partition("#")
    if not sep:
        return ""
    # "#节点" 或 "#节点&h3=true" 之类的参数
    return tail.split("&")[0] if "=" not in tail.split("&")[0] else ""


def fix_dns_policy(server, policies):
    """DNS 服务器后缀 #策略组 引用了不存在的组时改用节点选择"""
    server = server.strip()
    pol = dns_policy_of(server)
    if pol and pol not in policies:
        server = server.split("#", 1)[0] + "#" + G_SEL
    return server


def check_host_entry(h):
    dom, vals = h.get("domain", ""), h.get("value") or []
    if not HOST_KEY_RX.match(dom):
        return f"hosts 域名格式无效：{dom or '(空)'}（可用 example.com、+.example.com、*.example.com）"
    if not vals:
        return f"hosts「{dom}」没有填写 IP"
    for v in vals:
        if not is_ip_addr(v) and not (DOMAIN_RX.match(v.lower()) and not is_ip_addr(dom)):
            return f"hosts「{dom}」的值无效：{v}（应为 IP，或单个域名作为别名）"
    if len(vals) > 1 and not all(is_ip_addr(v) for v in vals):
        return f"hosts「{dom}」：别名域名只能填一个"
    return ""


def validate_dns(dc, d):
    pol = {g["name"] for g in build_config(dict(d, rules=[]))["proxy-groups"]} | BUILTIN_POLICIES | {n["proxy"]["name"] for n in d["nodes"]}
    errs = []
    for key, label in (("direct", "直连 DNS"), ("proxy", "代理 DNS"), ("default", "默认 DNS"), ("pserver", "节点域名解析 DNS")):
        for s in dc.get(key) or []:
            if not DNS_RX.match(s) or s.startswith("rcode://"):
                errs.append(f"{label} 格式无效：{s}")
            elif key == "default" and not re.match(r"^(?:(?:udp|tcp|tls|https)://)?\[?[0-9a-fA-F:.]+\]?(?::\d+)?(?:/|$)", s):
                errs.append(f"默认 DNS 必须是 IP（用于解析 DoH 域名）：{s}")
            elif key in ("default", "pserver") and dns_policy_of(s):
                errs.append(f"{label} 不能指定 #策略组（解析节点域名本身不能经过节点）：{s}")
            elif dns_policy_of(s) and dns_policy_of(s) not in pol:
                errs.append(f"{label} 引用的策略组不存在：{s}")
    for s in dc.get("fake_filter") or []:
        if not re.match(r"^(?:geosite:|rule-set:)?[\w*+.\-!@:]+$", s):
            errs.append(f"Fake-IP 过滤格式无效：{s}")
    for h in dc.get("hosts") or []:
        e = check_host_entry(h)
        if e:
            errs.append(e)
    seen = set()
    for pe in dc.get("policies") or []:
        m = pe.get("match", "")
        kind, parts = policy_parts(m)
        for part in parts:
            if not (POLICY_NAME_RX if kind != "domain" else POLICY_DOMAIN_RX).match(part) or ":" in part:
                errs.append(f"nameserver-policy 匹配项无效：{part}（一条只能是 geosite:a,b、rule-set:x 或 域名列表 +.example.com,example.com，不能混用）")
        if m in seen:
            errs.append(f"nameserver-policy 重复：{m}")
        seen.add(m)
        if not pe.get("servers"):
            errs.append(f"nameserver-policy「{m}」没有填写 DNS 服务器")
        for s in pe.get("servers") or []:
            if not DNS_RX.match(s):
                errs.append(f"nameserver-policy「{m}」的 DNS 格式无效：{s}")
            elif dns_policy_of(s) and dns_policy_of(s) not in pol:
                errs.append(f"nameserver-policy「{m}」引用的策略组不存在：{s}")
    if not dc.get("direct"):
        errs.append("直连 DNS 不能为空")
    if not dc.get("default"):
        errs.append("默认 DNS 不能为空")
    return errs


def bad_rule_policies(rules, d):
    pol = {g["name"] for g in build_config(dict(d, rules=[]))["proxy-groups"]} | BUILTIN_POLICIES | {n["proxy"]["name"] for n in d["nodes"]}
    bad = []
    for r in rules:
        parts = r.split(",")
        i = rule_policy_index(parts)
        if i <= 0 or parts[i].strip() not in pol:
            bad.append(r)
    return bad


def write_config(d, path=None):
    os.makedirs(os.path.join(CONF_DIR, "providers"), exist_ok=True)
    path = path or os.path.join(CONF_DIR, "config.yaml")
    with open(path, "w") as f:  # JSON 是 YAML 的子集，mihomo 可直接读取
        json.dump(build_config(d), f, ensure_ascii=False, indent=2)
    return path


def check_config(path):
    """用 mihomo -t 校验配置；没有核心程序时跳过"""
    if not os.path.isfile(MIHOMO_BIN):
        return True, ""
    code, out = sh(f"'{MIHOMO_BIN}' -t -d '{CONF_DIR}' -f '{path}'", timeout=90)
    if code == 0:
        return True, ""
    lines = [l for l in out.splitlines() if "level=error" in l or "level=fatal" in l or "test failed" in l.lower() or l.startswith("panic:")]
    return False, "\n".join(lines[-3:]) or out[-400:]


# ---------------------------------------------------------------- 核心交互
DIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # 访问本机控制器绝不走系统代理


_SECRET = [None, ""]


def ctrl_secret():
    """控制器密钥按 data.json 修改时间缓存：每秒的实时请求不再反复读取解析整份配置"""
    try:
        st = os.stat(DATA_FILE)
        key = (st.st_mtime_ns, st.st_size)
    except OSError:
        key = None
    if key is None or _SECRET[0] != key:
        _SECRET[:] = [key, load()["secret"]]
    return _SECRET[1]


def core(method, path, body=None, timeout=10):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(CTRL + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + ctrl_secret(), "Content-Type": "application/json"})
    try:
        with DIRECT_OPENER.open(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 502, json.dumps({"message": "mihomo 未运行或无法连接: %s" % e}).encode()


def core_json(path, timeout=10):
    code, raw = core("GET", path, timeout=timeout)
    if code != 200:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def reload_core(prev=None):
    """写配置 → mihomo -t 校验 → 热重载；校验失败时回滚 data.json"""
    with LOCK:
        d = load()
        sb = active_core(d) == "singbox"
        if sb:
            final = SB_CONF
            tmp = write_sb_config(d, final + ".new")
            ok, err = check_sb_config(tmp)
        else:
            final = os.path.join(CONF_DIR, "config.yaml")
            tmp = write_config(d, final + ".new")
            ok, err = check_config(tmp)
        if not ok:
            os.remove(tmp)
            if prev is not None:
                save(prev)
            return False, "配置校验失败，已撤销本次修改：" + err
        os.replace(tmp, final)
    WD["manual_stop"] = False
    retest_soon()
    if sb:
        return sb_hot_reload()
    code, body = core("PUT", "/configs?force=true", {"path": final}, timeout=30)
    if code == 502:  # 核心没在跑，尝试启动
        sh(SVC + " restart")
        return True, "已写入配置并重启 mihomo"
    return code < 300, body.decode(errors="ignore") or "配置已重载"


def group_sig(cfg):
    return [(g["name"], g["type"], g.get("filter", ""), tuple(g.get("proxies") or [])) for g in cfg.get("proxy-groups") or []]


def refresh_regions():
    """订阅节点变化后，地区分组（存在哪些地区、是否生成均衡组）可能变化：与当前配置不同就重新生成并重载"""
    if not core_alive():  # 核心没在运行（可能是手动停止）时不重载，免得把它拉起来
        return False, "核心未运行"
    provider_nodes(fresh=True)
    if active_core() == "singbox":
        cur = read_json(SB_CONF, None)
        new = build_singbox(load())[0]
        sig = lambda c: [(o["tag"], tuple(o.get("outbounds") or [])) for o in (c or {}).get("outbounds") or [] if o.get("outbounds")]
        if cur and sig(cur) == sig(new):
            return True, "地区分组无变化"
        ok, msg = reload_core()
        return ok, "地区分组已按最新订阅节点更新" if ok else msg
    cur = read_json(os.path.join(CONF_DIR, "config.yaml"), None)
    if not cur:
        return False, "当前配置不存在"
    if group_sig(cur) == group_sig(build_config(load())):
        return True, "地区分组无变化"
    ok, msg = reload_core()
    print(time.strftime("%F %T"), "[groups] 订阅节点变化，已重新生成地区分组：", ok, msg[:120], flush=True)
    return ok, "地区分组已按最新订阅节点更新" if ok else msg


def refresh_after_sub(name, wait=90):
    """新订阅加入后等核心下载完节点，再更新地区分组"""
    def run():
        end = time.time() + wait
        while time.time() < end:
            time.sleep(4)
            if name in provider_nodes(fresh=True):
                break
        try:
            refresh_regions()
        except Exception as e:
            print("refresh regions error", e, flush=True)
    threading.Thread(target=run, daemon=True).start()


# ---------------------------------------------------------------- sing-box 内核
# 面板数据（订阅、节点、规则、DNS、设备）两个内核共用；切换内核时按各自格式生成独立的配置文件：
#   mihomo   → /etc/mihomo/config.yaml
#   sing-box → /etc/sing-box/config.json
# sing-box 没有负载均衡 / 故障转移组：自定义的这两类组降级为 urltest（自动测速），地区「⚖️ 负载均衡」组与
# 「自动优选」完全相同，不再重复生成，引用它的地方自动改指向同地区的「自动优选」。
SB_BIN = os.environ.get("SB_BIN", "/usr/local/bin/sing-box")
SB_DIR = os.environ.get("SB_DIR", "/etc/sing-box")
SB_CONF = os.path.join(SB_DIR, "config.json")
SB_RULE_DIR = os.environ.get("SB_RULES", os.path.join(SB_DIR, "rules"))
SB_SUB_DIR = os.path.join(PANEL_DIR, "sb_subs")
CORE_FILE = os.path.join(PANEL_DIR, "core")  # init.d/mihomo 读取它决定启动哪个内核
CORE_PID = os.environ.get("PANEL_CORE_PID", "/run/mihomo.pid")
CORES = {"mihomo": "mihomo", "singbox": "sing-box"}
SB_GEO = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo"
SB_REPO = os.environ.get("SB_REPO", "https://github.com/SagerNet/sing-box/releases")
SB_API = os.environ.get("SB_API", "https://api.github.com/repos/SagerNet/sing-box/releases")
SB_UA = ("clash.meta", "v2rayN/6.45")
SB_STATE = {"warn": [], "subs": {}}
SB_LOCK = threading.Lock()


def active_core(d=None):
    c = (d or load()).get("core") or "mihomo"
    return c if c in CORES else "mihomo"


def core_bin(kind=None):
    return SB_BIN if (kind or active_core()) == "singbox" else MIHOMO_BIN


def core_conf_path(kind=None):
    return SB_CONF if (kind or active_core()) == "singbox" else os.path.join(CONF_DIR, "config.yaml")


def write_core_file(kind):
    try:
        wfile(CORE_FILE, kind + "\n")
    except Exception:
        pass


# ---- 极简 YAML 读取（只为解析 Clash 订阅里的 proxies 列表；面板保持零依赖）
def _y_strip_comment(s):
    q = None
    for i, ch in enumerate(s):
        if q:
            if ch == q and (q == "'" or s[i - 1] != "\\"):
                q = None
        elif ch in "'\"":
            q = ch
        elif ch == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i].rstrip()
    return s.rstrip()


def _y_scalar(s):
    s = s.strip()
    if not s:
        return None
    if s[0] == '"' and s.endswith('"') and len(s) > 1:
        try:
            return json.loads(s)
        except Exception:
            return s[1:-1]
    if s[0] == "'" and s.endswith("'") and len(s) > 1:
        return s[1:-1].replace("''", "'")
    low = s.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~"):
        return None
    if re.fullmatch(r"[-+]?\d+", s) and not (len(s.lstrip("+-")) > 1 and s.lstrip("+-")[0] == "0"):
        return int(s)
    if re.fullmatch(r"[-+]?\d+\.\d+", s):
        return float(s)
    return s


def _y_flow(s, i=0):
    """解析 {..} / [..] 流式集合，返回 (值, 结束位置)"""
    def ws(i):
        while i < len(s) and s[i] in " \t\r\n":
            i += 1
        return i

    def scalar(i, stops):
        i = ws(i)
        if i < len(s) and s[i] in "'\"":
            q = s[i]
            j = i + 1
            while j < len(s):
                if s[j] == q:
                    if q == "'" and j + 1 < len(s) and s[j + 1] == "'":
                        j += 2
                        continue
                    if q == '"' and s[j - 1] == "\\":
                        j += 1
                        continue
                    break
                j += 1
            return _y_scalar(s[i:j + 1]), j + 1
        j = i
        while j < len(s) and s[j] not in stops:
            if s[j] == ":" and "}" in stops and (j + 1 >= len(s) or s[j + 1] in " ,}"):
                break
            j += 1
        return _y_scalar(s[i:j]), j

    def value(i, stops):
        i = ws(i)
        if i < len(s) and s[i] in "{[":
            return _y_flow(s, i)
        return scalar(i, stops)

    i = ws(i)
    if s[i] == "{":
        out, i = {}, i + 1
        while True:
            i = ws(i)
            if i >= len(s):
                raise ValueError("YAML 花括号未闭合")
            if s[i] == "}":
                return out, i + 1
            k, i = scalar(i, ",}")
            i = ws(i)
            v = None
            if i < len(s) and s[i] == ":":
                v, i = value(i + 1, ",}")
            out[str(k)] = v
            i = ws(i)
            if i < len(s) and s[i] == ",":
                i += 1
    if s[i] == "[":
        out, i = [], i + 1
        while True:
            i = ws(i)
            if i >= len(s):
                raise ValueError("YAML 方括号未闭合")
            if s[i] == "]":
                return out, i + 1
            v, i = value(i, ",]")
            out.append(v)
            i = ws(i)
            if i < len(s) and s[i] == ",":
                i += 1
    return scalar(i, "")


def yaml_lite(text):
    """块状 / 流式映射与列表、引号字符串、注释；不支持锚点等高级语法"""
    raw = []
    for line in text.replace("\t", "  ").splitlines():
        if line.strip() in ("---", "...") or not line.strip() or line.lstrip().startswith("#"):
            continue
        raw.append(line)
    lines, buf = [], ""
    for line in raw:  # 跨行的流式集合合并成一行
        buf = buf + " " + line.strip() if buf else line
        c = _y_strip_comment(buf)
        depth = sum(1 for ch in c if ch in "{[") - sum(1 for ch in c if ch in "}]")
        if depth <= 0:
            lines.append((len(c) - len(c.lstrip(" ")), c.strip()))
            buf = ""
    if buf:
        c = _y_strip_comment(buf)
        lines.append((len(c) - len(c.lstrip(" ")), c.strip()))

    def split_kv(t):
        if t[:1] in "'\"":
            q = t[0]
            j = t.find(q, 1)
            while q == '"' and j > 0 and t[j - 1] == "\\":
                j = t.find(q, j + 1)
            if j > 0 and t[j + 1:j + 2] == ":":
                return _y_scalar(t[:j + 1]), t[j + 2:].strip()
            return None
        m = re.match(r"^([^:{}\[\],]+?)\s*:(?:\s+(.*)|$)", t)
        return (m.group(1).strip(), (m.group(2) or "").strip()) if m else None

    def inline(v):
        if v.startswith(("{", "[")):
            return _y_flow(v)[0]
        if v in ("|", ">", "|-", ">-"):
            return ""
        return _y_scalar(v)

    def block(i, ind):
        if i >= len(lines):
            return None, i
        if lines[i][1].startswith("- ") or lines[i][1] == "-":
            out = []
            while i < len(lines) and lines[i][0] == ind and (lines[i][1].startswith("- ") or lines[i][1] == "-"):
                rest = lines[i][1][1:].strip()
                if not rest:
                    if i + 1 < len(lines) and lines[i + 1][0] > ind:
                        v, i = block(i + 1, lines[i + 1][0])
                    else:
                        v, i = None, i + 1
                    out.append(v)
                    continue
                kv = None if rest.startswith(("{", "[")) else split_kv(rest)
                if kv is None:
                    out.append(inline(rest))
                    i += 1
                    continue
                sub = ind + len(lines[i][1]) - len(rest)
                lines[i] = (sub, rest)  # 「- key: v」等价于下一级映射的第一行
                v, i = block(i, sub)
                out.append(v)
            return out, i
        out = {}
        while i < len(lines) and lines[i][0] == ind and not lines[i][1].startswith("- "):
            kv = split_kv(lines[i][1])
            if kv is None:
                i += 1
                continue
            k, v = kv
            i += 1
            if v and v not in ("|", ">", "|-", ">-"):
                out[str(k)] = inline(v)
            elif i < len(lines) and (lines[i][0] > ind or (lines[i][0] == ind and lines[i][1].startswith("- "))):
                if v in ("|", ">", "|-", ">-"):
                    parts = []
                    while i < len(lines) and lines[i][0] > ind:
                        parts.append(lines[i][1])
                        i += 1
                    out[str(k)] = ("\n" if v.startswith("|") else " ").join(parts)
                else:
                    out[str(k)], i = block(i, lines[i][0])
            else:
                out[str(k)] = None
        return out, i

    if not lines:
        return None
    return block(0, lines[0][0])[0]


# ---- 订阅：sing-box 不能自己拉取订阅，由面板下载、解析成节点后写进配置
def sub_cache_path(name):
    return os.path.join(SB_SUB_DIR, safe(name) + ".json")


def parse_sub_text(text):
    """订阅内容 → mihomo 风格节点列表。支持 Clash YAML、sing-box JSON、Base64 / 明文分享链接"""
    t = text.strip().lstrip("\ufeff")
    if t.startswith("{"):
        try:
            j = json.loads(t)
            if isinstance(j.get("outbounds"), list):
                return [{"_sb": o, "name": o.get("tag"), "type": o.get("type")} for o in j["outbounds"]
                        if o.get("type") not in ("selector", "urltest", "direct", "block", "dns") and o.get("tag") and o.get("server")], []
        except ValueError:
            pass
    if re.search(r"(?m)^proxies\s*:", t):
        y = yaml_lite(t)
        ps = (y or {}).get("proxies") if isinstance(y, dict) else None
        if isinstance(ps, list):
            return [p for p in ps if isinstance(p, dict) and p.get("name") and p.get("type")], []
    body = t
    if "://" not in t:
        try:
            body = b64d(re.sub(r"\s+", "", t))
        except Exception:
            body = ""
    out, errs = [], []
    for i, line in enumerate([x.strip() for x in body.splitlines() if "://" in x], 1):
        try:
            p = parse_link(line)
            p["name"] = (p.get("name") or f"{p['type']}-{p['server']}:{p['port']}").strip()
            out.append(p)
        except Exception as e:
            errs.append(f"第 {i} 条：{e}")
    return out, errs


def sb_fetch_sub(s, gh=""):
    """下载并解析一个订阅，写入缓存；返回 (节点数, 消息)"""
    last = ""
    for ua in SB_UA:
        try:
            req = urllib.request.Request(s["url"], headers={"User-Agent": ua})
            data = None
            for use_proxy in ((True, False) if core_alive() else (False,)):
                try:
                    with proxy_opener(use_proxy).open(req, timeout=30) as r:
                        data = r.read(20 << 20)
                        info = r.headers.get("subscription-userinfo") or ""
                    break
                except Exception as e:
                    last = str(e)[:150]
            if data is None:
                continue
            nodes, errs = parse_sub_text(data.decode("utf-8", "ignore"))
            if not nodes:
                last = "没有解析出节点" + ("：" + errs[0] if errs else "")
                continue
            flt, exc = s.get("filter") or "", s.get("exclude", DEFAULT_EXCLUDE) or ""
            rf, re_ = rx(flt) if flt else None, rx(exc) if exc else None
            nodes = [p for p in nodes if (not rf or rf.search(p["name"])) and not (re_ and re_.search(p["name"]))]
            ui = {}
            for part in info.split(";"):
                k, _, v = part.strip().partition("=")
                if k in ("upload", "download", "total", "expire") and v.strip().isdigit():
                    ui[k.capitalize()] = int(v)
            write_json(sub_cache_path(s["name"]), {"name": s["name"], "updated": int(time.time()), "nodes": nodes,
                                                   "info": ui, "skipped": len(errs), "ua": ua})
            return len(nodes), f"{len(nodes)} 个节点" + (f"（{len(errs)} 条无法识别已跳过）" if errs else "")
        except Exception as e:
            last = str(e)[:150]
    raise IOError(last or "下载失败")


def sb_sub_cache(name):
    return read_json(sub_cache_path(name), {}) or {}


def sb_provider_nodes(d):
    """{订阅名: [节点名]}，名称已按全局去重（与生成的 sing-box 配置一致）"""
    return {k: [n for n, _ in v] for k, v in sb_sub_outbounds(d).items()}


def sb_sub_outbounds(d):
    taken = {n["proxy"]["name"] for n in d.get("nodes", [])} | reserved_names(d)
    out = {}
    for s in d["subs"]:
        lst = []
        for p in sb_sub_cache(s["name"]).get("nodes") or []:
            base = str(p.get("name") or "").strip() or "node"
            name, k = base, 2
            while name in taken:
                name, k = f"{base} ({k})", k + 1
            taken.add(name)
            lst.append((name, p))
        out[s["name"]] = lst
    return out


def sb_update_subs(names=None, d=None):
    d = d or load()
    gh = d.get("gh_proxy") or ""
    ok, bad = [], []
    for s in d["subs"]:
        if names and s["name"] not in names:
            continue
        try:
            n, msg = sb_fetch_sub(s, gh)
            ok.append(f"{s['name']}：{msg}")
        except Exception as e:
            bad.append(f"{s['name']}：{e}")
    PROV.update(t=0, data=None)
    return ok, bad


# ---- 节点：mihomo 字段 → sing-box outbound
def _sb_tls(p, sni_key="servername", force=False):
    if not (p.get("tls") or force):
        return None
    t = {"enabled": True}
    sni = p.get(sni_key) or p.get("sni") or p.get("servername")
    if sni:
        t["server_name"] = str(sni)
    if p.get("skip-cert-verify"):
        t["insecure"] = True
    if p.get("alpn"):
        t["alpn"] = [str(a) for a in (p["alpn"] if isinstance(p["alpn"], list) else str(p["alpn"]).split(","))]
    if p.get("disable-sni"):
        t["disable_sni"] = True
    fp = p.get("client-fingerprint")
    ro = p.get("reality-opts")
    if ro:
        t["reality"] = {"enabled": True, "public_key": str(ro.get("public-key") or ""), "short_id": str(ro.get("short-id") or "")}
        fp = fp or "chrome"
    if fp and fp not in ("none",):
        t["utls"] = {"enabled": True, "fingerprint": "chrome" if fp == "random" else str(fp)}
    return t


def _sb_transport(p):
    net = (p.get("network") or "tcp").lower()
    if net == "ws":
        o = p.get("ws-opts") or {}
        path = str(o.get("path") or "/")
        hdr = {k: (v[0] if isinstance(v, list) else str(v)) for k, v in (o.get("headers") or {}).items()}
        if o.get("v2ray-http-upgrade"):
            t = {"type": "httpupgrade", "path": path}
            if hdr.get("Host"):
                t["host"] = hdr.pop("Host")
            if hdr:
                t["headers"] = hdr
            return t
        t = {"type": "ws", "path": path}
        m = re.search(r"[?&]ed=(\d+)", path)
        if m:
            t["path"] = re.sub(r"[?&]ed=\d+", "", path) or "/"
            t["max_early_data"], t["early_data_header_name"] = int(m.group(1)), "Sec-WebSocket-Protocol"
        elif o.get("max-early-data"):
            t["max_early_data"] = int(o["max-early-data"])
            t["early_data_header_name"] = o.get("early-data-header-name") or "Sec-WebSocket-Protocol"
        if hdr:
            t["headers"] = hdr
        return t
    if net == "grpc":
        return {"type": "grpc", "service_name": str((p.get("grpc-opts") or {}).get("grpc-service-name") or "")}
    if net == "h2":
        o = p.get("h2-opts") or {}
        t = {"type": "http", "path": str(o.get("path") or "/")}
        if o.get("host"):
            t["host"] = [str(h) for h in (o["host"] if isinstance(o["host"], list) else [o["host"]])]
        return t
    if net == "http":
        o = p.get("http-opts") or {}
        path = o.get("path") or ["/"]
        t = {"type": "http", "path": str(path[0] if isinstance(path, list) else path), "method": str(o.get("method") or "GET")}
        hosts = (o.get("headers") or {}).get("Host")
        if hosts:
            t["host"] = [str(h) for h in (hosts if isinstance(hosts, list) else [hosts])]
        return t
    if net in ("tcp", ""):
        return None
    raise ValueError(f"sing-box 不支持传输方式 {net}")


def _mbps(v):
    m = re.match(r"\s*(\d+)", str(v or ""))
    return int(m.group(1)) if m else 0


def sb_outbound(p, tag):
    """返回 sing-box outbound；不支持的协议抛 ValueError"""
    if p.get("_sb"):
        o = dict(p["_sb"])
        o["tag"] = tag
        return o
    t = str(p.get("type") or "").lower()
    o = {"tag": tag, "server": str(p.get("server") or ""), "server_port": int(p.get("port") or 0)}
    if not o["server"] or not o["server_port"]:
        raise ValueError("缺少服务器或端口")
    if t == "ss":
        o.update(type="shadowsocks", method=str(p.get("cipher") or ""), password=str(p.get("password") or ""))
        pl, po = p.get("plugin"), p.get("plugin-opts") or {}
        if pl == "obfs":
            o["plugin"], o["plugin_opts"] = "obfs-local", f"obfs={po.get('mode', 'http')};obfs-host={po.get('host', 'bing.com')}"
        elif pl == "v2ray-plugin":
            opts = [f"mode={po.get('mode', 'websocket')}"] + ([f"host={po['host']}"] if po.get("host") else []) + \
                   ([f"path={po['path']}"] if po.get("path") else []) + (["tls"] if po.get("tls") else [])
            o["plugin"], o["plugin_opts"] = "v2ray-plugin", ";".join(opts)
        elif pl:
            raise ValueError(f"sing-box 不支持 ss 插件 {pl}")
        if p.get("udp-over-tcp"):
            o["udp_over_tcp"] = True
    elif t == "vmess":
        o.update(type="vmess", uuid=str(p.get("uuid") or ""), security=str(p.get("cipher") or "auto"), alter_id=int(p.get("alterId") or 0))
    elif t == "vless":
        o.update(type="vless", uuid=str(p.get("uuid") or ""), packet_encoding="xudp")
        if p.get("flow"):
            o["flow"] = str(p["flow"])
    elif t == "trojan":
        o.update(type="trojan", password=str(p.get("password") or ""))
        o["tls"] = _sb_tls(p, "sni", force=True)
    elif t == "hysteria2":
        o.update(type="hysteria2", password=str(p.get("password") or ""))
        if p.get("ports"):
            o["server_ports"] = [x.strip().replace("-", ":") if "-" in x else f"{x.strip()}:{x.strip()}"
                                 for x in str(p["ports"]).replace("/", ",").split(",") if x.strip()]
        if p.get("obfs"):
            o["obfs"] = {"type": str(p["obfs"]), "password": str(p.get("obfs-password") or "")}
        for k, sk in (("up", "up_mbps"), ("down", "down_mbps")):
            if _mbps(p.get(k)):
                o[sk] = _mbps(p.get(k))
        o["tls"] = _sb_tls(p, "sni", force=True)
    elif t == "tuic":
        o.update(type="tuic", uuid=str(p.get("uuid") or ""), password=str(p.get("password") or ""),
                 congestion_control=str(p.get("congestion-controller") or "bbr"),
                 udp_relay_mode=str(p.get("udp-relay-mode") or "native"))
        if p.get("reduce-rtt"):
            o["zero_rtt_handshake"] = True
        o["tls"] = _sb_tls(dict(p, alpn=p.get("alpn") or ["h3"]), "sni", force=True)
    elif t == "hysteria":
        o.update(type="hysteria", up_mbps=_mbps(p.get("up")) or 10, down_mbps=_mbps(p.get("down")) or 50)
        if p.get("auth-str") or p.get("auth_str"):
            o["auth_str"] = str(p.get("auth-str") or p.get("auth_str"))
        if p.get("obfs"):
            o["obfs"] = str(p["obfs"])
        o["tls"] = _sb_tls(p, "sni", force=True)
    elif t == "anytls":
        o.update(type="anytls", password=str(p.get("password") or ""))
        o["tls"] = _sb_tls(p, "sni", force=True)
    elif t in ("http", "socks5"):
        o["type"] = "http" if t == "http" else "socks"
        if t == "socks5":
            o["version"] = "5"
        if p.get("username"):
            o["username"], o["password"] = str(p["username"]), str(p.get("password") or "")
    elif t == "ssh":
        o.update(type="ssh", user=str(p.get("username") or "root"))
        if p.get("password"):
            o["password"] = str(p["password"])
        if p.get("private-key"):
            o["private_key"] = str(p["private-key"])
    else:
        raise ValueError(f"sing-box 不支持 {t or '未知'} 协议")
    if t in ("vmess", "vless", "http", "socks5"):
        tls = _sb_tls(p, "servername")
        if tls:
            o["tls"] = tls
    if t in ("vmess", "vless", "trojan"):
        tr = _sb_transport(p)
        if tr:
            o["transport"] = tr
    if o.get("tls") is None:
        o.pop("tls", None)
    if p.get("udp") is False and t in ("ss",):
        o["network"] = "tcp"
    return o


# ---- 规则：mihomo 规则字符串 → sing-box 路由规则
def _mh_domain(x):
    """mihomo 域名通配（+.a.com / *.a.com / a.*.com）→ (字段, 值)"""
    x = x.strip().lower()
    if x.startswith("+."):
        return "domain_suffix", x[2:]
    if x.startswith("."):
        return "domain_suffix", x[1:]
    if "*" in x:
        return "domain_regex", "^" + re.escape(x).replace(r"\*", r"[^.]+") + "$"
    return "domain", x


def _rs_tag(kind, name):
    return f"{kind}-{name}".lower() if kind in ("geosite", "geoip") else name


def _split_top(s):
    """「(A,b),(C,d)」按最外层逗号拆分"""
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur:
        out.append(cur)
    return out


class SBRules:
    """收集翻译过程中用到的规则集、入站，以及无法翻译的条目"""

    def __init__(self, cfg, inbounds, alias, rule_sets):
        self.cfg, self.inbounds, self.alias, self.rule_sets = cfg, inbounds, alias, rule_sets
        self.warn = []

    def use_geo(self, kind, name):
        tag = _rs_tag(kind, name)
        if tag not in self.rule_sets:
            self.rule_sets[tag] = {"kind": "geo", "url": f"{SB_GEO}/{kind}/{name.lower()}.srs", "path": f"{kind}-{name.lower()}.srs"}
        return tag

    def cond(self, typ, val):
        """单个匹配条件 → sing-box 规则字段（dict）；不支持时返回 None"""
        typ, val = typ.strip().upper(), val.strip()
        if typ == "DOMAIN":
            return {"domain": [val.lower()]}
        if typ == "DOMAIN-SUFFIX":
            return {"domain_suffix": [val.lower().lstrip(".")]}
        if typ == "DOMAIN-KEYWORD":
            return {"domain_keyword": [val.lower()]}
        if typ == "DOMAIN-REGEX":
            return {"domain_regex": [val]}
        if typ == "DOMAIN-WILDCARD":
            k, v = _mh_domain(val)
            return {k: [v]}
        if typ in ("IP-CIDR", "IP-CIDR6"):
            return {"ip_cidr": [val]}
        if typ in ("SRC-IP-CIDR",):
            return {"source_ip_cidr": [val]}
        if typ in ("DST-PORT", "SRC-PORT", "IN-PORT"):
            key = {"DST-PORT": "port", "SRC-PORT": "source_port", "IN-PORT": "port"}[typ]
            ports, ranges = [], []
            for x in val.replace("/", ",").split(","):
                x = x.strip()
                if re.fullmatch(r"\d+", x):
                    ports.append(int(x))
                elif re.fullmatch(r"\d+-\d+", x):
                    ranges.append(x.replace("-", ":"))
            c = {}
            if ports:
                c[key] = ports
            if ranges:
                c[key + "_range"] = ranges
            if typ == "IN-PORT":
                return None
            return c or None
        if typ == "NETWORK":
            return {"network": [val.lower()]}
        if typ == "GEOSITE":
            return {"rule_set": [self.use_geo("geosite", val)]}
        if typ == "GEOIP":
            if val.lower() in ("private", "lan"):
                return {"ip_is_private": True}
            return {"rule_set": [self.use_geo("geoip", val)]}
        if typ == "RULE-SET":
            return {"rule_set": [val]} if val in self.rule_sets else None
        if typ == "IN-TYPE":
            want = {"TPROXY": "tproxy-in", "TUN": "tun-in", "MIXED": "mixed-in", "HTTP": "mixed-in", "SOCKS5": "mixed-in"}
            tags = sorted({want[x] for x in val.upper().split("/") if want.get(x) in self.inbounds})
            return {"inbound": tags} if tags else False
        if typ in ("PROCESS-NAME", "PROCESS-PATH"):
            return {"process_name" if typ == "PROCESS-NAME" else "process_path": [val]}
        return None

    def logical(self, typ, inner):
        subs = []
        for part in _split_top(inner):
            part = part.strip()
            if part.startswith("(") and part.endswith(")"):
                part = part[1:-1]
            r = self.match(part)
            if r is None or r is False:
                return r
            subs.append(r)
        if not subs:
            return None
        if typ == "NOT":
            r = dict(subs[0]) if len(subs) == 1 else {"type": "logical", "mode": "and", "rules": subs}
            r["invert"] = not r.get("invert", False)
            return r
        return {"type": "logical", "mode": typ.lower(), "rules": subs}

    def match(self, body):
        """不含策略的匹配部分 → 规则 dict / None（不支持）/ False（永不命中）"""
        m = re.match(r"^(AND|OR|NOT)\s*,\s*\((.*)\)$", body.strip(), re.I)
        if m:
            return self.logical(m.group(1).upper(), m.group(2))
        typ, _, val = body.partition(",")
        return self.cond(typ, val.split(",")[0]) if val else None

    def action(self, pol):
        pol = self.alias.get(pol.strip(), pol.strip())
        if pol in ("REJECT",):
            return {"action": "reject"}
        if pol == "REJECT-DROP":
            return {"action": "reject", "method": "drop"}
        if pol in ("DIRECT", "COMPATIBLE"):
            return {"action": "route", "outbound": "DIRECT"}
        if pol == "PASS":
            return None
        return {"action": "route", "outbound": pol}

    def rule(self, line):
        """完整规则「类型,值,策略[,no-resolve]」→ (规则 dict 或 None, 是否需要先解析域名)"""
        parts = line.split(",")
        i = rule_policy_index(parts)
        if line.upper().startswith(("AND,", "OR,", "NOT,")):
            k = line.rfind(")")
            body, pol = line[:k + 1], line[k + 1:].strip(",").split(",")[0]
        else:
            body, pol = ",".join(parts[:i]), parts[i]
        typ = body.split(",")[0].strip().upper()
        if typ == "MATCH":
            return None, False
        act = self.action(pol)
        r = self.match(body)
        if act is None or r is False:
            return None, False
        if r is None:
            self.warn.append(f"规则「{line[:80]}」sing-box 不支持，已跳过")
            return None, False
        r = dict(r, **act)
        needs = typ in ("GEOIP", "IP-CIDR", "IP-CIDR6") and "no-resolve" not in [x.strip().lower() for x in parts[i + 1:]] \
            and not r.get("ip_is_private")
        return r, needs


# ---- DNS
def _sb_dns_server(addr, tag, boot, warn):
    """mihomo DNS 地址（含 #策略组）→ sing-box DNS server"""
    addr = addr.strip()
    pol = dns_policy_of(addr)
    base = addr.split("#", 1)[0]
    s = {"tag": tag}
    if base.startswith("system"):
        s["type"] = "local"
    elif base.startswith("dhcp://"):
        s["type"] = "dhcp"
        ifc = base[7:]
        if ifc and ifc != "system":
            s["interface"] = ifc
    else:
        m = re.match(r"^(https|tls|quic|h3|udp|tcp)://(.+)$", base)
        scheme, rest = (m.group(1), m.group(2)) if m else ("udp", base)
        u = urlsplit("x://" + rest)
        host = u.hostname or rest
        s["type"] = scheme
        s["server"] = host
        if u.port:
            s["server_port"] = u.port
        if scheme in ("https", "h3") and u.path and u.path != "/dns-query":
            s["path"] = u.path
        if not is_ip_addr(host) and boot:
            s["domain_resolver"] = boot
    if pol:
        s["detour"] = pol
    return s


def sb_dns(d, cfg, policies, rs, alias, v6):
    dc = dns_cfg(d)
    warn = rs.warn
    fixd = lambda x: (x.split("#", 1)[0] + "#" + alias[dns_policy_of(x)]) if dns_policy_of(x) in alias else x
    fx = lambda xs: [fix_dns_policy(fixd(x), policies) for x in xs]
    servers, tags = [], {}

    def server(addr, boot="dns-boot"):
        if addr in tags:
            return tags[addr]
        if addr.startswith("rcode://"):
            return addr
        tag = f"dns-{len(tags) + 1}"
        servers.append(_sb_dns_server(addr, tag, boot, warn))
        tags[addr] = tag
        return tag

    boot_list = list(dc["default"] or DNS_DEFAULT["default"])
    servers.append(_sb_dns_server(boot_list[0], "dns-boot", None, warn))
    direct = fx(dc["direct"] or DNS_DEFAULT["direct"])
    proxy = fx(dc["proxy"])
    t_direct = server(direct[0])
    t_proxy = server(proxy[0]) if proxy else None
    t_node = server(dc["pserver"][0].split("#", 1)[0]) if dc["pserver"] else server(direct[0].split("#", 1)[0])
    final = t_proxy or t_direct
    rules = []
    ab = d.get("adblock") or {}
    ab_sets = [k for k in rs.rule_sets if k.startswith("ad-")]
    if ab.get("enabled") and ab.get("dns") and ab_sets:
        if "ad-allow" in ab_sets:
            rules.append({"rule_set": ["ad-allow"], "action": "route", "server": t_direct})
        bl = [k for k in ab_sets if k != "ad-allow"]
        if bl:
            rules.append({"rule_set": bl, "action": "predefined", "rcode": "NXDOMAIN"})

    def policy_cond(match):
        kind, names = policy_parts(match)
        if kind == "geosite":
            return {"rule_set": [rs.use_geo("geosite", n) for n in names]}
        if kind == "rule-set":
            have = [n for n in names if n in rs.rule_sets]
            return {"rule_set": have} if have else None
        c = {}
        for n in names:
            k, v = _mh_domain(n)
            c.setdefault(k, []).append(v)
        return c

    def target(servers_):
        s0 = servers_[0]
        if s0.startswith("rcode://"):
            rc = {"success": "NOERROR", "format_error": "FORMERR", "server_failure": "SERVFAIL", "name_error": "NXDOMAIN",
                  "not_implemented": "NOTIMP", "refused": "REFUSED"}.get(s0[8:], "NXDOMAIN")
            return {"action": "predefined", "rcode": rc}
        return {"action": "route", "server": server(s0)}

    for pe in dc["policies"]:
        c = policy_cond(pe["match"])
        if c:
            rules.append(dict(c, **target(fx(pe["servers"]))))
        else:
            warn.append(f"DNS 策略「{pe['match']}」引用的规则集 sing-box 中不存在，已跳过")
    exact = {}
    for h in dc["hosts"]:
        ips = [v for v in h["value"] if is_ip_addr(v)]
        if h["domain"].startswith(("+.", "*.")) or not ips:
            warn.append(f"hosts「{h['domain']}」sing-box 只支持精确域名 → IP，已跳过")
            continue
        exact[h["domain"]] = ips
    if exact:
        servers.append({"type": "hosts", "tag": "dns-hosts", "predefined": exact})
        rules.append({"domain": sorted(exact), "action": "route", "server": "dns-hosts"})
    cn_cond = {"rule_set": [rs.use_geo("geosite", "cn"), rs.use_geo("geosite", "private")]}
    if dc["mode"] == "fake-ip":
        servers.append({"type": "fakeip", "tag": "dns-fake", "inet4_range": "198.18.0.0/15",
                        **({"inet6_range": "fc00::/18"} if v6 else {})})
        conds = {}
        for x in dc["fake_filter"]:
            if x.lower().startswith("geosite:"):
                conds.setdefault("rule_set", []).append(rs.use_geo("geosite", x[8:]))
            elif x.lower().startswith("rule-set:"):
                if x[9:] in rs.rule_sets:
                    conds.setdefault("rule_set", []).append(x[9:])
            else:
                k, v = _mh_domain(x)
                conds.setdefault(k, []).append(v)
        if conds:  # Fake-IP 过滤名单：按国内 / 国外分流到真实 DNS
            parts = [{k: v} for k, v in conds.items() if k == "rule_set"]
            dom = {k: v for k, v in conds.items() if k != "rule_set"}
            if dom:
                parts.insert(0, dom)
            fc = parts[0] if len(parts) == 1 else {"type": "logical", "mode": "or", "rules": parts}
            if dc["policy"] and t_proxy:
                rules.append({"type": "logical", "mode": "and", "rules": [fc, cn_cond], "action": "route", "server": t_direct})
            rules.append(dict(fc, action="route", server=final))
        rules.append({"query_type": ["A", "AAAA"], "action": "route", "server": "dns-fake"})
    if dc["policy"] and t_proxy:
        rules.append(dict(cn_cond, action="route", server=t_direct))
    out = {"servers": servers, "rules": rules, "final": final, "strategy": "prefer_ipv4" if v6 else "ipv4_only",
           "cache_capacity": 4096}
    return out, t_node, t_direct, t_proxy


# ---- 生成 sing-box 配置
def build_singbox(d):
    """把 build_config 生成的 mihomo 结构翻译成 sing-box 配置；返回 (配置, 警告列表, 需要的规则集文件)"""
    sub_out = sb_sub_outbounds(d)
    PROV.update(t=time.time(), data={k: [n for n, _ in v] for k, v in sub_out.items()})
    cfg = build_config(d)
    v6 = bool(d.get("ipv6"))
    gc = gcfg(d)
    warn = []
    # 节点
    outbounds, node_names, prov_names = [], [], {}
    for p in cfg["proxies"]:
        try:
            outbounds.append(sb_outbound(p, p["name"]))
            node_names.append(p["name"])
        except ValueError as e:
            warn.append(f"节点「{p['name']}」：{e}，已跳过")
    skipped = 0
    for sname, lst in sub_out.items():
        prov_names[sname] = []
        for name, p in lst:
            try:
                outbounds.append(sb_outbound(p, name))
                prov_names[sname].append(name)
            except (ValueError, TypeError):
                skipped += 1
    if skipped:
        warn.append(f"订阅中有 {skipped} 个节点的协议 sing-box 不支持（如 ssr、snell、wireguard），已跳过")
    for s in d["subs"]:
        if not sb_sub_cache(s["name"]).get("updated"):
            warn.append(f"订阅「{s['name']}」还没有下载过节点")
    # 策略组：地区负载均衡与自动优选相同 → 去掉并重定向引用；其余 load-balance / fallback 改为 urltest
    alias = {}
    region_lb = set()
    for r, _ in REGIONS + [(G_OTHER, None)]:
        alias[lb_name(r)] = auto_name(r)
        region_lb.add(lb_name(r))
    groups = [g for g in cfg["proxy-groups"] if g["name"] not in region_lb]
    gnames = {g["name"] for g in groups}
    alias = {k: v for k, v in alias.items() if v in gnames}
    lb_custom = [g["name"] for g in groups if g["type"] in ("load-balance", "fallback")]
    if lb_custom:
        warn.append("sing-box 没有负载均衡 / 故障转移组，已按自动测速运行：" + "、".join(lb_custom[:6]) + ("…" if len(lb_custom) > 6 else ""))
    all_sub = [n for v in prov_names.values() for n in v]
    known = set(node_names) | set(all_sub) | gnames
    for g in groups:
        members = []
        for m in g.get("proxies") or []:
            m = alias.get(m, m)
            if m in ("REJECT", "REJECT-DROP", "PASS"):
                continue
            if m == "COMPATIBLE":
                m = "DIRECT"
            if (m in known or m == "DIRECT") and m != g["name"] and m not in members:
                members.append(m)
        if g.get("use"):
            pool = [n for u in g["use"] for n in prov_names.get(u, [])]
            f, ex = g.get("filter"), g.get("exclude-filter")
            rf, rex = (rx(f) if f else None), (rx(ex) if ex else None)
            members += [n for n in pool if (not rf or rf.search(n)) and not (rex and rex.search(n)) and n not in members]
        if not members:
            members = ["DIRECT"]
        if g["type"] == "select":
            o = {"type": "selector", "tag": g["name"], "outbounds": members, "interrupt_exist_connections": False}
        else:
            o = {"type": "urltest", "tag": g["name"], "outbounds": members, "url": g.get("url") or gc["url"],
                 "interval": f"{max(int(g.get('interval') or gc['interval']), 30)}s",
                 "tolerance": int(g.get("tolerance") if g.get("tolerance") is not None else gc["tolerance"]),
                 "interrupt_exist_connections": False}
            if g["type"] == "url-test" and not g.get("lazy", True):
                o["idle_timeout"] = "720h"
        outbounds.append(o)
    group_out = [o for o in outbounds if o["type"] in ("selector", "urltest")]
    outbounds = group_out + [o for o in outbounds if o["type"] not in ("selector", "urltest")] + [{"type": "direct", "tag": "DIRECT"}]
    policies = {o["tag"] for o in outbounds} | BUILTIN_POLICIES
    # 入站
    lis = "::" if v6 else "0.0.0.0"
    inbounds = [{"type": "mixed", "tag": "mixed-in", "listen": lis, "listen_port": MIXED},
                {"type": "direct", "tag": "dns-in", "listen": lis, "listen_port": 1053}]
    if d.get("proxy_mode") == "tproxy":  # 透明代理（tproxy.sh 把流量转到 7893）
        inbounds.insert(1, {"type": "tproxy", "tag": "tproxy-in", "listen": lis, "listen_port": 7893})
    tc = d.get("tun") or TUN_DEFAULT
    if d.get("proxy_mode") == "tun":
        tun = {"type": "tun", "tag": "tun-in", "interface_name": safe_dev(tc.get("device")), "address": ["172.19.0.1/30"] + (["fdfe:dcba:9876::1/126"] if v6 else []),
               "auto_route": True, "auto_redirect": bool(tc.get("auto_redirect", True)), "strict_route": bool(tc.get("strict_route", False)),
               "stack": tc.get("stack") if tc.get("stack") in TUN_STACKS else "mixed"}
        inbounds.append(tun)
    in_tags = {i["tag"] for i in inbounds}
    # 规则集
    rule_sets = {}
    for name, prov in cfg["rule-providers"].items():
        if prov.get("type") == "inline":
            payload = prov.get("payload") or []
            r = {}
            for x in payload:
                if prov.get("behavior") == "ipcidr":
                    r.setdefault("ip_cidr", []).append(x)
                else:
                    k, v = _mh_domain(x)
                    r.setdefault(k, []).append(v)
            rule_sets[name] = {"kind": "inline", "rules": [r] if r else []}
        elif name.startswith("ad-"):
            rule_sets[name] = {"kind": "adblock", "src": os.path.join(AB_DIR, os.path.basename(prov["path"])), "path": name + ".json"}
        else:
            url = prov.get("url") or ""
            if re.search(r"\.srs(?:\?|$)", url):
                rule_sets[name] = {"kind": "srs", "url": url, "path": f"rs-{safe(name)}.srs"}
            elif prov.get("format") == "mrs" and "meta-rules-dat" in url and "/meta/" in url:
                rule_sets[name] = {"kind": "srs", "url": re.sub(r"\.mrs(\?|$)", r".srs\1", url.replace("/meta/", "/sing/")),
                                   "path": f"rs-{safe(name)}.srs"}
            elif prov.get("format") == "mrs":
                warn.append(f"规则集「{name}」是 mihomo 专用的 .mrs 格式，sing-box 无法使用，已跳过（可改用 .srs 地址）")
            else:
                rule_sets[name] = {"kind": "convert", "url": url, "behavior": prov.get("behavior", "domain"),
                                   "format": prov.get("format", "yaml"), "path": f"rs-{safe(name)}.json"}
    tr = SBRules(cfg, in_tags, alias, rule_sets)
    tr.warn = warn
    # 路由规则
    route_rules = []
    if d.get("sniffer", True) or dns_cfg(d)["mode"] == "fake-ip":
        route_rules.append({"action": "sniff"})
    route_rules += [{"inbound": ["dns-in"], "action": "hijack-dns"}, {"protocol": ["dns"], "action": "hijack-dns"},
                    {"clash_mode": "Direct", "action": "route", "outbound": "DIRECT"},
                    {"clash_mode": "Global", "action": "route", "outbound": G_SEL if G_SEL in policies else "DIRECT"}]
    resolved = False
    final = "DIRECT"
    for line in cfg["rules"]:
        if line.upper().startswith("MATCH,"):
            final = tr.action(line.split(",", 1)[1]).get("outbound", "DIRECT") if tr.action(line.split(",", 1)[1]) else "DIRECT"
            continue
        r, needs = tr.rule(line)
        if r is None:
            continue
        if r.get("action") == "route" and r.get("outbound") not in policies:
            r["outbound"] = G_SEL if G_SEL in policies else "DIRECT"
        if needs and not resolved:  # 与 mihomo 一致：没有 no-resolve 的 IP 规则先解析域名再匹配
            route_rules.append({"action": "resolve"})
            resolved = True
        route_rules.append(r)
    dns, t_node, t_direct, t_proxy = sb_dns(d, cfg, policies, tr, alias, v6)
    if resolved and t_proxy:
        for r in route_rules:
            if r.get("action") == "resolve":
                r["server"] = t_proxy if dns_cfg(d)["mode"] == "fake-ip" else dns["final"]
    elif resolved:
        for r in route_rules:
            if r.get("action") == "resolve":
                r["server"] = t_direct
    # 规则集定义：只保留本地已有文件的（缺失的规则及引用跳过，避免启动失败）
    defs, missing = [], set()
    for tag, rsd in rule_sets.items():
        if rsd["kind"] == "inline":
            defs.append({"type": "inline", "tag": tag, "rules": rsd["rules"] or [{"domain": ["invalid.invalid"]}]})
            continue
        path = os.path.join(SB_RULE_DIR, rsd["path"])
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            defs.append({"type": "local", "tag": tag, "format": "binary" if path.endswith(".srs") else "source", "path": path})
        else:
            missing.add(tag)
    if missing:
        warn.append("以下规则集文件尚未下载，相关规则暂时跳过：" + "、".join(sorted(missing)[:8]) + ("…" if len(missing) > 8 else ""))

    def prune_rules(lst):
        out = []
        for r in lst:
            r = dict(r)
            if r.get("type") == "logical":
                subs = prune_rules(r["rules"])
                if len(subs) != len(r["rules"]):
                    continue
                r["rules"] = subs
            elif "rule_set" in r:
                keep = [x for x in r["rule_set"] if x not in missing]
                if not keep:
                    continue
                r["rule_set"] = keep
            out.append(r)
        return out
    route_rules = prune_rules(route_rules)
    dns["rules"] = prune_rules(dns["rules"])
    mode = {"global": "Global", "direct": "Direct"}.get(d.get("mode"), "Rule")
    conf = {
        "log": {"level": "info", "timestamp": True},
        "dns": dns,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": route_rules, "rule_set": defs, "final": final if final in policies else "DIRECT",
                  "auto_detect_interface": True, "default_domain_resolver": t_node},
        "experimental": {"clash_api": {"external_controller": f"{CTRL_HOST}:{CTRL_PORT}", "secret": d["secret"],
                                       "default_mode": mode},
                         "cache_file": {"enabled": True, "path": os.path.join(SB_DIR, "cache.db"), "store_fakeip": True}},
    }
    need = {tag: rsd for tag, rsd in rule_sets.items() if rsd["kind"] != "inline"}
    return conf, list(dict.fromkeys(warn)), need


def _rule_lines_to_source(text, behavior, fmt):
    """mihomo 规则集文本（yaml payload / text）→ sing-box source 规则集"""
    t = text.strip()
    items = []
    if fmt == "yaml" or re.search(r"(?m)^payload\s*:", t):
        y = yaml_lite(t)
        items = [str(x) for x in ((y or {}).get("payload") or [])] if isinstance(y, dict) else []
    else:
        items = [l.strip() for l in t.splitlines() if l.strip() and not l.strip().startswith(("#", "//"))]
    r = {}
    tr = SBRules({}, set(), {}, {})
    for x in items:
        x = x.strip().strip("'\"")
        if behavior == "ipcidr":
            try:
                r.setdefault("ip_cidr", []).append(str(ipaddress.ip_network(x, strict=False)))
            except ValueError:
                pass
        elif behavior == "domain":
            k, v = _mh_domain(x)
            r.setdefault(k, []).append(v)
        else:
            typ, _, val = x.partition(",")
            c = tr.cond(typ, val.split(",")[0]) if val else None
            if c:
                for k, v in c.items():
                    if isinstance(v, list):
                        r.setdefault(k, []).extend(v)
    return {"version": 3, "rules": [r] if r else []}


def sb_adblock_source(src):
    """面板广告列表（每行 +.a.com 或 a.com）→ sing-box source 规则集"""
    suf, exact = [], []
    with open(src) as f:
        for line in f:
            line = line.strip()
            if line.startswith("+."):
                suf.append(line[2:])
            elif line:
                exact.append(line)
    r = {}
    if suf:
        r["domain_suffix"] = suf
    if exact:
        r["domain"] = exact
    return {"version": 3, "rules": [r] if r else []}


def sb_sync_assets(d, force=False, need=None):
    """下载 / 转换 sing-box 需要的规则集文件；返回失败列表"""
    if need is None:
        need = build_singbox(d)[2]
    gh = (d.get("gh_proxy") or "").rstrip("/")
    os.makedirs(SB_RULE_DIR, exist_ok=True)
    bad = []
    for tag, rsd in need.items():
        path = os.path.join(SB_RULE_DIR, rsd["path"])
        try:
            if rsd["kind"] == "adblock":
                if os.path.isfile(rsd["src"]) and (force or not os.path.isfile(path) or os.path.getmtime(rsd["src"]) > os.path.getmtime(path)):
                    write_json(path, sb_adblock_source(rsd["src"]))
                continue
            if os.path.isfile(path) and os.path.getsize(path) > 0 and not force:
                continue
            urls = ([gh + "/" + rsd["url"]] if gh and "github" in rsd["url"] else []) + [rsd["url"]]
            data, err = None, ""
            for u in urls:
                for use_proxy in ((True, False) if core_alive() else (False,)):
                    try:
                        with proxy_opener(use_proxy).open(urllib.request.Request(u, headers={"User-Agent": UA}), timeout=30) as r:
                            data = r.read(40 << 20)
                        break
                    except Exception as e:
                        err = str(e)[:120]
                if data is not None:
                    break
            if data is None:
                raise IOError(err or "下载失败")
            if rsd["kind"] in ("geo", "srs"):
                if not data.startswith(b"SRS"):
                    raise ValueError("不是有效的 .srs 文件")
                with open(path + ".tmp", "wb") as f:
                    f.write(data)
                os.replace(path + ".tmp", path)
            else:
                src = _rule_lines_to_source(data.decode("utf-8", "ignore"), rsd["behavior"], rsd["format"])
                if not src["rules"]:
                    raise ValueError("没有解析出任何规则")
                write_json(path, src)
        except Exception as e:
            bad.append(f"{tag}：{e}")
    return bad


def write_sb_config(d, path=None):
    os.makedirs(SB_DIR, exist_ok=True)
    conf, warn, _ = build_singbox(d)
    SB_STATE["warn"] = warn
    path = path or SB_CONF
    with open(path, "w") as f:
        json.dump(conf, f, ensure_ascii=False, indent=2)
    return path


def check_sb_config(path, binp=None):
    binp = binp or SB_BIN
    if not os.path.isfile(binp):
        return True, ""
    code, out = sh(f"'{binp}' check -c '{path}' -D '{SB_DIR}'", timeout=90)
    if code == 0:
        return True, ""
    lines = [l for l in out.splitlines() if "FATAL" in l or "ERROR" in l or "error" in l.lower()]
    return False, "\n".join(lines[-3:]) or out[-400:]


def write_active_config(d=None):
    d = d or load()
    if active_core(d) == "singbox":
        return write_sb_config(d)
    return write_config(d)


def core_pid():
    try:
        pid = int(open(CORE_PID).read().strip())
        os.kill(pid, 0)
        return pid
    except Exception:
        return 0


def sb_hot_reload():
    """sing-box 收到 SIGHUP 会重新读取配置（透明代理规则不受影响）；进程不在时重启服务"""
    pid = core_pid()
    if pid:
        try:
            os.kill(pid, signal.SIGHUP)
            for _ in range(20):
                time.sleep(0.5)
                if core_alive():
                    return True, "配置已重载"
            return False, "sing-box 重载后未响应，请查看日志"
        except OSError:
            pass
    sh(SVC + " restart", timeout=90)
    return True, "已写入配置并重启 sing-box"


def sb_version(path=None):
    path = path or SB_BIN
    if not os.path.isfile(path):
        return ""
    code, out = sh(f"'{path}' version", timeout=15)
    m = re.search(r"sing-box version (\S+)", out) if code == 0 else None
    return m.group(1) if m else ""


def iso_utc(t):
    g = time.gmtime(t)
    return "%04d-%02d-%02dT%02d:%02d:%02dZ" % g[:6]


def sb_fake_providers(d):
    """sing-box 没有 proxy-provider：按 mihomo /providers/proxies 的格式拼出订阅节点及其延迟，前端无需区分内核"""
    px = (core_json("/proxies", timeout=5) or {}).get("proxies") or {}
    out = {}
    for s in d["subs"]:
        c = sb_sub_cache(s["name"])
        names = sb_provider_nodes(d).get(s["name"], [])
        upd = c.get("updated")
        out[s["name"]] = {"name": s["name"], "type": "Proxy", "vehicleType": "HTTP",
                          "updatedAt": iso_utc(upd) if upd else "",
                          "subscriptionInfo": c.get("info") or {},
                          "proxies": [dict({"name": n, "type": (px.get(n) or {}).get("type", ""), "history": []}, **(px.get(n) or {}))
                                      for n in names]}
    return {"providers": out}


def sb_fake_rule_providers(d):
    out = {}
    need = build_singbox(d)[2]
    for r in d.get("rulesets") or []:
        rsd = need.get(r["name"])
        path = os.path.join(SB_RULE_DIR, rsd["path"]) if rsd else ""
        mt = os.path.getmtime(path) if path and os.path.isfile(path) else 0
        out[r["name"]] = {"name": r["name"], "type": "Rule", "vehicleType": "HTTP", "behavior": r.get("behavior", "domain").capitalize(),
                          "ruleCount": 0, "updatedAt": iso_utc(mt) if mt else ""}
    return {"providers": out}


# ---- 内核切换
def sb_arch():
    m = os.uname().machine
    return {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64", "armv7l": "armv7", "armv8l": "armv7", "armv6l": "armv6",
            "i686": "386", "i386": "386", "riscv64": "riscv64", "loongarch64": "loong64", "s390x": "s390x"}.get(m, "")


def sb_remote_version(channel, gh):
    """最新正式版 / 预发布版的版本号（不带 v）"""
    try:
        with open_url(SB_API + ("/latest" if channel == "stable" else "?per_page=10"), "", timeout=15) as r:
            j = json.loads(r.read(400000))
        if channel != "stable":
            j = next((x for x in j if x.get("prerelease")), j[0])
        v = str(j.get("tag_name") or "").lstrip("v")
        if v:
            return v
    except Exception:
        if channel != "stable":
            raise
    with open_url(SB_REPO + "/latest", gh, timeout=15) as r:  # API 受限时从跳转地址里取版本号
        m = re.search(r"/tag/v?([\w.\-]+)", r.geturl())
    if not m:
        raise IOError("获取 sing-box 版本号失败")
    return m.group(1)


def sb_install(channel, gh, force=False):
    """下载 sing-box 到 SB_BIN（旧版本备份为 .bak）；返回版本号"""
    import tarfile
    arch = sb_arch()
    if not arch:
        raise ValueError(f"sing-box 不支持当前 CPU 架构：{os.uname().machine}")
    ver = sb_remote_version(channel, gh)
    cur = sb_version()
    if cur == ver and not force:
        return ver, False
    url = f"{SB_REPO}/download/v{ver}/sing-box-{ver}-linux-{arch}.tar.gz"
    _cu("下载", 10, f"下载 sing-box-{ver}-linux-{arch}.tar.gz")
    tmp = SB_BIN + ".new"
    with open_url(url, gh, timeout=60) as r:
        total = int(r.headers.get("Content-Length") or 0)
        buf, n = io.BytesIO(), 0
        while True:
            chunk = r.read(1 << 16)
            if not chunk:
                break
            n += len(chunk)
            if n > 120 * 2**20:
                raise ValueError("下载文件异常过大，已中止")
            buf.write(chunk)
            if total:
                CORE_UPD["pct"] = 10 + int(50 * n / total)
    buf.seek(0)
    with tarfile.open(fileobj=buf, mode="r:gz") as tf:
        mem = next((m for m in tf.getmembers() if m.isfile() and os.path.basename(m.name) == "sing-box"), None)
        if not mem:
            raise ValueError("压缩包里没有 sing-box 程序")
        with tf.extractfile(mem) as src, open(tmp, "wb") as f:
            shutil.copyfileobj(src, f)
    os.chmod(tmp, 0o755)
    nv = sb_version(tmp)
    if not nv:
        os.remove(tmp)
        raise ValueError("下载的 sing-box 无法运行（架构不匹配或文件损坏）")
    if os.path.isfile(SB_BIN):
        shutil.copy2(SB_BIN, SB_BIN + ".bak")
    os.replace(tmp, SB_BIN)
    return nv, True


def core_switch_job(kind, gh):
    """切换内核：准备程序与数据 → 生成并校验配置 → 写入启动选择 → 重启；失败自动换回原内核"""
    prev = active_core()
    try:
        label = CORES[kind]
        if kind == "singbox":
            if not sb_version():
                _cu("安装 sing-box", 5, "设备上还没有 sing-box，正在下载最新正式版")
                nv, _ = sb_install("stable", gh)
                _cu("安装 sing-box", 62, f"已安装 sing-box {nv}")
            d = load()
            if d["subs"]:
                _cu("下载订阅", 65, "sing-box 不能自己拉取订阅，由面板下载并解析节点")
                ok, bad = sb_update_subs(d=d)
                for x in ok + bad:
                    _cu("下载订阅", None, x)
                if not ok:
                    raise ValueError("订阅全部下载失败，未切换：" + "；".join(bad)[:300])
            _cu("规则集", 75, "下载 sing-box 格式的 GEO / 规则集文件")
            bad = sb_sync_assets(d)
            for x in bad[:5]:
                _cu("规则集", None, "✗ " + x)
            tmp = write_sb_config(d, SB_CONF + ".new")
            ok, err = check_sb_config(tmp)
            if not ok:
                os.remove(tmp)
                raise ValueError("sing-box 配置校验失败，未切换：" + err)
            os.replace(tmp, SB_CONF)
        else:
            if not bin_version(MIHOMO_BIN):
                raise ValueError("设备上没有可用的 mihomo 程序，请先在「内核更新」里安装")
            d = load()
            tmp = write_config(d, os.path.join(CONF_DIR, "config.yaml.new"))
            ok, err = check_config(tmp)
            if not ok:
                os.remove(tmp)
                raise ValueError("mihomo 配置校验失败，未切换：" + err)
            os.replace(tmp, os.path.join(CONF_DIR, "config.yaml"))
        snapshot_selections(force=True)
        update(lambda x: x.update(core=kind))
        write_core_file(kind)
        PROV.update(t=0, data=None)
        _cu("重启核心", 88, f"正在以 {label} 重启核心（局域网会断网几秒）")
        WD["manual_stop"] = False
        sh(SVC + " restart", timeout=90)
        for _ in range(30):
            time.sleep(1)
            if core_alive():
                break
        else:
            tail = [l for l in sh(f"tail -n 30 '{MIHOMO_LOG}'")[1].splitlines() if re.search(r"FATAL|ERROR|level=(?:error|fatal)", l)]
            update(lambda x: x.update(core=prev))
            write_core_file(prev)
            sh(SVC + " restart", timeout=90)
            log = re.sub(r"\x1b\[[0-9;]*m", "", "\n".join(tail[-3:]))[-400:]
            raise ValueError(f"{label} 30 秒内未响应，已切回 {CORES[prev]}。" + ("日志：" + log if log else "请查看核心日志"))
        threading.Thread(target=restore_selections, daemon=True).start()
        CORE_UPD.update(ok=True, message=f"已切换到 {label}" + (f"（{len(SB_STATE['warn'])} 条兼容提示见设置 → 核心）" if kind == "singbox" and SB_STATE["warn"] else ""))
        notify(f"🔀 内核已切换：{CORES[prev]} → {label}")
    except Exception as e:
        CORE_UPD.update(ok=False, message=str(e))
    finally:
        CORE_UPD["pct"] = 100
        _cu("完成" if CORE_UPD["ok"] else "失败", 100, CORE_UPD["message"])
        CORE_UPD["busy"] = False


def sb_update_job(channel, gh, force=False):
    try:
        cur = sb_version()
        _cu("获取版本", 3, "正在获取 sing-box 最新版本号")
        nv, changed = sb_install(channel, gh, force)
        if not changed:
            CORE_UPD.update(ok=True, message=f"已是最新版本 {nv}，无需更新")
            return
        _cu("校验", 70, f"用 sing-box {nv} 检查当前配置")
        if active_core() == "singbox":
            ok, err = check_sb_config(SB_CONF)
            if not ok:
                shutil.copy2(SB_BIN + ".bak", SB_BIN)
                raise ValueError("新版 sing-box 不兼容当前配置，已恢复原版本：" + err)
            _cu("重启核心", 85, "正在重启核心")
            sh(SVC + " restart", timeout=90)
            for _ in range(30):
                time.sleep(1)
                if core_alive():
                    break
            else:
                shutil.copy2(SB_BIN + ".bak", SB_BIN)
                sh(SVC + " restart", timeout=90)
                raise ValueError("新版 sing-box 30 秒内未响应，已恢复原版本")
        CORE_UPD.update(ok=True, message=f"sing-box 已从 {cur or '未安装'} 更新到 {nv}" + ("，旧版本已备份" if cur else ""))
    except Exception as e:
        CORE_UPD.update(ok=False, message=str(e))
    finally:
        CORE_UPD["pct"] = 100
        _cu("完成" if CORE_UPD["ok"] else "失败", 100, CORE_UPD["message"])
        CORE_UPD["busy"] = False


# ---------------------------------------------------------------- 面板在线更新
PANEL_RAW = os.environ.get("PANEL_RAW", "https://raw.githubusercontent.com/Skycnhe/Shunt/Hk001")
UPD_FILES = ["server.py", "index.html", "tproxy.sh", "selftest.sh", "init.d/mihomo", "init.d/mihomo-panel"]
UPD_STATE = {"busy": False}


def local_file(f):
    if f.startswith("init.d/"):
        sysf = "/etc/init.d/" + f[7:]
        return sysf if BASE == "/opt/mihomo-panel" and os.path.isfile(sysf) else os.path.join(BASE, f)
    return os.path.join(BASE, f)


def fetch_raw(f, gh):
    url = PANEL_RAW.rstrip("/") + "/" + f
    tries = [(gh.rstrip("/") + "/" + url, False)] if gh else []
    tries += [(url, True), (url, False)]  # 先经 mihomo 代理，再直连
    err = ""
    for u, use_proxy in tries:
        try:
            req = urllib.request.Request(u + ("&" if "?" in u else "?") + "t=" + str(int(time.time())), headers={"User-Agent": UA})
            with proxy_opener(use_proxy).open(req, timeout=20) as r:
                return r.read(4 << 20)
        except Exception as e:
            err = f"{u.split('://')[0]}{'(代理)' if use_proxy else ''}: {str(e)[:120]}"
    raise IOError(f"下载 {f} 失败：{err}")


def remote_version(src):
    m = re.search(rb'^PANEL_VERSION = "([^"]+)"', src, re.M)
    return m.group(1).decode() if m else "?"


def self_update(apply=False, gh=""):
    """检查 / 应用 GitHub 上的新版面板：下载全部文件 → 校验 → 备份 → 替换 → 重启面板"""
    if UPD_STATE["busy"]:
        return False, {"message": "正在更新中"}
    UPD_STATE["busy"] = True
    try:
        files, changed = {}, []
        for f in UPD_FILES:
            data = fetch_raw(f, gh)
            files[f] = data
            try:
                with open(local_file(f), "rb") as fh:
                    same = fh.read() == data
            except OSError:
                same = False
            if not same:
                changed.append(f)
        info = {"current": PANEL_VERSION, "remote": remote_version(files["server.py"]), "changed": changed,
                "source": PANEL_RAW}
        if not apply:
            info["message"] = "已是最新" if not changed else f"有 {len(changed)} 个文件可更新"
            return True, info
        if not changed:
            info["message"] = "已是最新，无需更新"
            return True, info
        try:  # 校验：Python 语法、HTML 完整、shell 语法
            compile(files["server.py"], "server.py", "exec")
        except SyntaxError as e:
            raise ValueError(f"新版 server.py 语法错误：{e}")
        if b"</html>" not in files["index.html"] or b"<script>" not in files["index.html"]:
            raise ValueError("新版 index.html 不完整")
        tmpd = os.path.join(BASE, ".update")
        shutil.rmtree(tmpd, ignore_errors=True)
        os.makedirs(os.path.join(tmpd, "init.d"))
        for f, data in files.items():
            with open(os.path.join(tmpd, f), "wb") as fh:
                fh.write(data)
            if f.endswith(".sh") or f.startswith("init.d/"):
                code, out = sh(f"sh -n '{os.path.join(tmpd, f)}'")
                if code != 0:
                    raise ValueError(f"新版 {f} 语法错误：{out[-200:]}")
        bak = os.path.join(BASE, ".backup")
        shutil.rmtree(bak, ignore_errors=True)
        os.makedirs(os.path.join(bak, "init.d"))
        for f in UPD_FILES:
            if os.path.isfile(local_file(f)):
                shutil.copy2(local_file(f), os.path.join(bak, f))
        for f in changed:
            dst = local_file(f)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(os.path.join(tmpd, f), dst + ".new")
            os.chmod(dst + ".new", 0o755 if (f.endswith(".sh") or f.startswith("init.d/")) else 0o644)
            os.replace(dst + ".new", dst)
        shutil.rmtree(tmpd, ignore_errors=True)
        restart_self()
        info["message"] = f"已更新 {len(changed)} 个文件（{'、'.join(changed)}），面板正在重启；旧版本已备份，可回滚"
        return True, info
    except Exception as e:
        return False, {"message": str(e)}
    finally:
        UPD_STATE["busy"] = False


# ---------------------------------------------------------------- 内核（mihomo）更新
CORE_REPO = os.environ.get("CORE_REPO", "https://github.com/MetaCubeX/mihomo/releases")
CORE_CHANNELS = {"stable": "latest/download", "alpha": "download/Prerelease-Alpha"}
CORE_UPD = {"busy": False, "stage": "", "pct": 0, "ok": None, "message": "", "log": deque(maxlen=30), "t": 0}


def core_arch():
    m = os.uname().machine
    if m == "x86_64":
        try:  # 支持 AVX2 等 x86-64-v3 指令集的 CPU 用 v3 版本更快，否则用兼容版
            flags = open("/proc/cpuinfo").read()
            if all(f in flags for f in (" avx2", " bmi2", " fma", " movbe")):
                return "amd64-v3"
        except OSError:
            pass
        return "amd64-compatible"
    return {"aarch64": "arm64", "arm64": "arm64", "armv7l": "armv7", "armv8l": "armv7", "armv6l": "armv6",
            "i686": "386", "i386": "386", "riscv64": "riscv64", "loongarch64": "loong64-abi2"}.get(m, "")


def bin_version(path):
    """执行 mihomo -v，返回版本号（如 v1.19.32 / alpha-9f053c4）；不能运行时返回空串"""
    if not os.path.isfile(path):
        return ""
    code, out = sh(f"'{path}' -v", timeout=15)
    m = re.search(r"Mihomo\s+Meta\s+(\S+)", out) if code == 0 else None
    return m.group(1) if m else ""


def open_url(url, gh, timeout=20):
    """GitHub 下载：先走加速地址，再经 mihomo 代理，最后直连"""
    tries = [(gh.rstrip("/") + "/" + url, False)] if gh else []
    tries += [(url, True), (url, False)]
    err = ""
    for u, use_proxy in tries:
        try:
            req = urllib.request.Request(u, headers={"User-Agent": UA})
            return proxy_opener(use_proxy and core_alive()).open(req, timeout=timeout)
        except Exception as e:
            err = f"{u.split('/')[2]}{'(代理)' if use_proxy else ''}: {str(e)[:120]}"
    raise IOError(err)


def core_remote_version(channel, gh):
    url = f"{CORE_REPO}/{CORE_CHANNELS[channel]}/version.txt"
    with open_url(url, gh) as r:
        v = r.read(200).decode(errors="ignore").strip()
    if not re.match(r"^[\w.\-]+$", v):
        raise IOError("获取到的版本号无效：" + v[:40])
    return v


def core_check(channel, gh):
    arch = core_arch()
    info = {"current": bin_version(MIHOMO_BIN) or "未安装", "arch": arch or os.uname().machine, "channel": channel,
            "backup": bin_version(MIHOMO_BIN + ".bak"), "remote": ""}
    try:
        info["remote"] = core_remote_version(channel, gh)
    except Exception as e:
        info["message"] = "获取最新版本失败：" + str(e)
        return False, info
    info["latest"] = info["remote"] == info["current"]
    info["message"] = "已是最新" if info["latest"] else f"可更新到 {info['remote']}"
    return True, info


def _cu(stage, pct=None, msg=None):
    CORE_UPD["stage"] = stage
    if pct is not None:
        CORE_UPD["pct"] = pct
    CORE_UPD["log"].appendleft(f"{time.strftime('%H:%M:%S')} {msg or stage}")


def _core_swap_and_restart(src, label):
    """把 src 换成正式核心并重启；30 秒内控制接口没起来就自动换回原来的核心"""
    bak = MIHOMO_BIN + ".bak"
    had_old = os.path.isfile(MIHOMO_BIN)
    if had_old and src != bak:
        shutil.copy2(MIHOMO_BIN, bak)
    if src == bak:  # 回滚：当前核心与备份互换，方便再“回滚”回来
        tmp = MIHOMO_BIN + ".swap"
        shutil.copy2(MIHOMO_BIN, tmp)
        os.replace(bak, MIHOMO_BIN)
        os.replace(tmp, bak)
    else:
        os.replace(src, MIHOMO_BIN)
    if active_core() == "singbox":  # 当前运行的是 sing-box：只替换程序，下次切回 mihomo 时生效
        _cu("完成", 95, f"已替换为 {label}（当前内核是 sing-box，切回 mihomo 时生效）")
        return True, ""
    _cu("重启核心", 90, f"已替换为 {label}，正在重启核心")
    sh(SVC + " restart", timeout=90)
    for _ in range(30):
        time.sleep(1)
        if core_alive():
            return True, ""
    if had_old and src != bak:  # 新核心起不来 → 自动恢复
        _cu("自动回滚", 95, "新核心 30 秒内未响应，正在恢复原核心")
        shutil.copy2(bak, MIHOMO_BIN)
        sh(SVC + " restart", timeout=90)
        return False, "新核心启动失败，已自动恢复为原核心。日志：" + sh(f"tail -n 5 '{MIHOMO_LOG}'")[1][-300:]
    return False, "核心重启后 30 秒内未响应，请查看日志"


def core_update_job(channel, gh, force=False):
    tmp = MIHOMO_BIN + ".new"
    try:
        arch = core_arch()
        if not arch:
            raise ValueError(f"不支持的 CPU 架构：{os.uname().machine}")
        _cu("获取版本", 2, "正在获取最新版本号")
        ver = core_remote_version(channel, gh)
        cur = bin_version(MIHOMO_BIN)
        if ver == cur and not force:
            CORE_UPD.update(ok=True, message=f"已是最新版本 {cur}，无需更新")
            return
        free = shutil.disk_usage(os.path.dirname(MIHOMO_BIN)).free
        if free < 80 * 2**20:
            raise ValueError(f"{os.path.dirname(MIHOMO_BIN)} 剩余空间不足（{free // 2**20} MB，至少需要 80 MB）")
        url = f"{CORE_REPO}/download/{'Prerelease-Alpha' if channel == 'alpha' else ver}/mihomo-linux-{arch}-{ver}.gz"
        _cu("下载", 5, f"下载 mihomo-linux-{arch}-{ver}.gz")
        import gzip
        with open_url(url, gh, timeout=30) as r:
            total = int(r.headers.get("Content-Length") or 0)

            class Counter:
                def __init__(self):
                    self.n = 0

                def read(self, k=-1):
                    b = r.read(k)
                    self.n += len(b)
                    if total:
                        CORE_UPD["pct"] = 5 + int(70 * self.n / total)
                    return b
            with gzip.GzipFile(fileobj=Counter()) as gz, open(tmp, "wb") as f:
                size = 0
                while True:
                    chunk = gz.read(1 << 16)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > 200 * 2**20:
                        raise ValueError("解压后的文件异常过大，已中止")
                    f.write(chunk)
        os.chmod(tmp, 0o755)
        _cu("校验", 78, "校验新核心能否运行")
        nv = bin_version(tmp)
        if not nv:
            raise ValueError("新核心无法运行（架构不匹配或文件损坏），未做任何替换")
        _cu("校验", 84, f"新核心 {nv}，正在用它检查当前配置")
        code, out = sh(f"'{tmp}' -t -d '{CONF_DIR}' -f '{os.path.join(CONF_DIR, 'config.yaml')}'", timeout=90)
        if code != 0:
            raise ValueError("新核心不兼容当前配置，未做任何替换：" + out[-300:])
        ok, err = _core_swap_and_restart(tmp, nv)
        if not ok:
            raise ValueError(err)
        CORE_UPD.update(ok=True, message=f"内核已从 {cur or '无'} 更新到 {nv}，旧版本已备份，可一键回滚")
        tg = load()
        if tg.get("tg_token") and tg.get("tg_chat"):
            notify(f"⬆️ mihomo 内核已更新：{cur or '无'} → {nv}")
    except Exception as e:
        CORE_UPD.update(ok=False, message=str(e))
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
        CORE_UPD["pct"] = 100
        _cu("完成" if CORE_UPD["ok"] else "失败", 100, CORE_UPD["message"])
        CORE_UPD["busy"] = False


def core_rollback_job():
    try:
        old = bin_version(MIHOMO_BIN + ".bak")
        if not old:
            raise ValueError("没有可回滚的内核备份")
        cur = bin_version(MIHOMO_BIN)
        ok, err = _core_swap_and_restart(MIHOMO_BIN + ".bak", old)
        if not ok:
            raise ValueError(err)
        CORE_UPD.update(ok=True, message=f"已回滚：{cur} → {old}（{cur} 保留为备份）")
    except Exception as e:
        CORE_UPD.update(ok=False, message=str(e))
    finally:
        CORE_UPD["pct"] = 100
        _cu("完成" if CORE_UPD["ok"] else "失败", 100, CORE_UPD["message"])
        CORE_UPD["busy"] = False


def core_job_start(fn, *args):
    if CORE_UPD["busy"] or UPD_STATE["busy"]:
        return False, "正在更新中，请稍候"
    CORE_UPD.update(busy=True, stage="开始", pct=0, ok=None, message="", t=int(time.time()))
    CORE_UPD["log"].clear()
    threading.Thread(target=fn, args=args, daemon=True).start()
    return True, "已开始"


def core_upd_status():
    return {k: (list(v) if isinstance(v, deque) else v) for k, v in CORE_UPD.items()}


# ---------------------------------------------------------------- Alpine 系统优化
PROC_SYS = os.environ.get("PANEL_PROC_SYS", "/proc/sys")
SYS_ROOT = os.environ.get("PANEL_SYS_ROOT", "/sys")
ETC = os.environ.get("PANEL_ETC", "/etc")
OPT_SYSCTL = os.path.join(ETC, "sysctl.d", "98-shunt-optimize.conf")
OPT_LOCALD = os.path.join(ETC, "local.d", "shunt-optimize.start")
OPT_CONFD = os.path.join(ETC, "conf.d", "mihomo")
OPT_LOCK = threading.Lock()


def mem_mb():
    try:
        with open("/proc/meminfo") as f:
            return int(re.search(r"MemTotal:\s+(\d+)", f.read()).group(1)) // 1024
    except Exception:
        return 512


def rsys(key):
    try:
        with open(os.path.join(PROC_SYS, key.replace(".", "/"))) as f:
            return " ".join(f.read().split())
    except OSError:
        return None


def wsys(key, val):
    try:
        with open(os.path.join(PROC_SYS, key.replace(".", "/")), "w") as f:
            f.write(str(val))
        return ""
    except OSError as e:
        return f"{key}: {e.strerror or e}"


def rfile(path, default=""):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def wfile(path, val):
    try:
        with open(path, "w") as f:
            f.write(str(val))
        return True
    except OSError:
        return False


def net_ifaces():
    """物理网卡（有 device 链接，排除 lo / 虚拟网卡 / TUN）"""
    base = os.path.join(SYS_ROOT, "class", "net")
    try:
        return sorted(n for n in os.listdir(base) if os.path.exists(os.path.join(base, n, "device")))
    except OSError:
        return []


def cpu_govs():
    return sorted(glob_paths(os.path.join(SYS_ROOT, "devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor")))


def glob_paths(pat):
    import glob
    return glob.glob(pat)


def opt_items():
    """按内存 / CPU 计算推荐值。每项：id、名称、说明、sysctl 目标值、是否支持"""
    mem, ncpu = mem_mb(), os.cpu_count() or 1
    buf = 16 << 20 if mem >= 1024 else 8 << 20  # quic-go（Hysteria2 / TUIC）建议 UDP 缓冲 ≥7.5MB
    ct = max(32768, min(262144, mem * 256))
    bbr_ok = "bbr" in (rsys("net.ipv4.tcp_available_congestion_control") or "") or os.path.exists(
        f"/lib/modules/{os.uname().release}/kernel/net/ipv4/tcp_bbr.ko") or bool(
        glob_paths(f"/lib/modules/{os.uname().release}/kernel/net/ipv4/tcp_bbr.ko*"))
    govs = cpu_govs()
    gov_ok = bool(govs) and "performance" in rfile(os.path.join(os.path.dirname(govs[0]), "scaling_available_governors")) if govs else False
    return [
        {"id": "bbr", "name": "BBR 拥塞控制", "rec": True, "ok": bbr_ok, "why": "" if bbr_ok else "内核没有 tcp_bbr 模块",
         "desc": "TCP 改用 BBR + fq 队列，丢包或长距离线路下的下载速度明显更高",
         "sysctl": {"net.core.default_qdisc": "fq", "net.ipv4.tcp_congestion_control": "bbr"}},
        {"id": "buf", "name": "网络缓冲区", "rec": True, "ok": True,
         "desc": f"加大 TCP/UDP 收发缓冲到 {buf >> 20}MB（按 {mem}MB 内存计算），提升大带宽和 Hysteria2 / TUIC 等 QUIC 协议速度",
         "sysctl": {"net.core.rmem_max": buf, "net.core.wmem_max": buf, "net.core.rmem_default": 262144,
                    "net.core.wmem_default": 262144, "net.ipv4.tcp_rmem": f"4096 131072 {buf}",
                    "net.ipv4.tcp_wmem": f"4096 65536 {buf}", "net.ipv4.udp_rmem_min": 16384, "net.ipv4.udp_wmem_min": 16384,
                    "net.core.netdev_max_backlog": 16384, "net.core.somaxconn": 8192, "net.ipv4.tcp_max_syn_backlog": 8192}},
        {"id": "tcp", "name": "TCP 连接优化", "rec": True, "ok": True,
         "desc": "开启 TCP Fast Open 和 MTU 探测（避免某些线路卡在握手），空闲后不降速，扩大可用端口，快速回收 TIME_WAIT",
         "sysctl": {"net.ipv4.tcp_fastopen": 3, "net.ipv4.tcp_mtu_probing": 1, "net.ipv4.tcp_slow_start_after_idle": 0,
                    "net.ipv4.tcp_tw_reuse": 1, "net.ipv4.tcp_fin_timeout": 15, "net.ipv4.ip_local_port_range": "10000 65535",
                    "net.ipv4.tcp_keepalive_time": 600, "net.ipv4.tcp_notsent_lowat": 131072}},
        {"id": "conntrack", "name": "连接跟踪表", "rec": True, "ok": rsys("net.netfilter.nf_conntrack_max") is not None,
         "why": "nf_conntrack 未加载", "desc": f"连接数上限提高到 {ct}，已建立连接的超时从 5 天缩短到 2 小时，避免设备多时连接表被占满导致断流",
         "sysctl": {"net.netfilter.nf_conntrack_max": ct, "net.netfilter.nf_conntrack_tcp_timeout_established": 7200,
                    "net.netfilter.nf_conntrack_udp_timeout": 60, "net.netfilter.nf_conntrack_udp_timeout_stream": 180}},
        {"id": "fd", "name": "文件句柄上限", "rec": True, "ok": True,
         "desc": "mihomo 可同时打开的连接数从 1024 提高到 1048576，设备多或 BT 下载时不再报 too many open files（下次重启核心生效）",
         "sysctl": {"fs.file-max": 1048576, "fs.nr_open": 1048576}},
        {"id": "rps", "name": "多核网络分流 (RPS)", "rec": ncpu > 1, "ok": ncpu > 1 and bool(net_ifaces()),
         "why": "单核 CPU 无需开启" if ncpu <= 1 else "未找到物理网卡",
         "desc": f"把网卡收包分摊到全部 {ncpu} 个 CPU 核心，单队列网卡（树莓派、多数 ARM 盒子、虚拟机）满速时不再单核 100%",
         "sysctl": {"net.core.rps_sock_flow_entries": 32768}},
        {"id": "gov", "name": "CPU 性能模式", "rec": False, "ok": gov_ok, "why": "CPU 不支持调频或没有 performance 模式",
         "desc": "CPU 一直跑在最高频率，延迟更低更稳定；功耗和发热会增加，散热差的设备慎开", "sysctl": {}},
        {"id": "ntp", "name": "时间同步", "rec": True, "ok": True,
         "desc": "安装并开机启动 chrony 自动校时。系统时间不准会导致 TLS 握手失败、VMess / Trojan 等节点全部不可用",
         "sysctl": {}},
    ]


def ntp_running():
    return sh("pidof chronyd || pidof ntpd")[0] == 0


def opt_status():
    d = load()
    on = set(d.get("sysopt") or [])
    out = []
    for it in opt_items():
        cur, hit = {}, 0
        for k, v in it["sysctl"].items():
            c = rsys(k)
            cur[k] = c
            if c is not None and c == " ".join(str(v).split()):
                hit += 1
        live = bool(it["sysctl"]) and hit == len(it["sysctl"])
        if it["id"] == "fd":
            live = live and 'rc_ulimit="-n 1048576"' in rfile(OPT_CONFD)
        elif it["id"] == "rps":
            live = live and it["ok"] and all(int(rfile(q, "0").replace(",", "") or "0", 16) != 0
                                            for q in glob_paths(os.path.join(SYS_ROOT, "class/net/*/queues/rx-*/rps_cpus"))
                                            if q.split("/class/net/")[1].split("/")[0] in net_ifaces())
        elif it["id"] == "gov":
            live = it["ok"] and all(rfile(g) == "performance" for g in cpu_govs())
        elif it["id"] == "ntp":
            live = ntp_running()
        show = {}
        if it["id"] == "bbr":
            show = {"当前": rsys("net.ipv4.tcp_congestion_control") or "-", "队列": rsys("net.core.default_qdisc") or "-"}
        elif it["id"] == "buf":
            show = {"当前上限": f"{int(rsys('net.core.rmem_max') or 0) >> 10} KB"}
        elif it["id"] == "conntrack":
            show = {"已用 / 上限": f"{rsys('net.netfilter.nf_conntrack_count') or '-'} / {rsys('net.netfilter.nf_conntrack_max') or '-'}"}
        elif it["id"] == "gov" and it["ok"]:
            show = {"当前": rfile(cpu_govs()[0])}
        out.append({k: it[k] for k in ("id", "name", "desc", "rec", "ok")} | {
            "why": "" if it["ok"] else it.get("why", ""), "enabled": it["id"] in on, "active": live, "show": show})
    return {"items": out, "mem": mem_mb(), "cpu": os.cpu_count() or 1, "kernel": os.uname().release}


def _opt_locald(on):
    """开机脚本：RPS 与 CPU 调频不是 sysctl，由 /etc/local.d 在每次启动时重新写入"""
    lines = ["#!/bin/sh", "# 由 Shunt 面板生成：系统优化（开机执行）"]
    if "rps" in on:
        n = os.cpu_count() or 1
        lines += [f"MASK={((1 << n) - 1):x}",
                  "for q in /sys/class/net/*/queues/rx-*; do",
                  '  i=${q#/sys/class/net/}; i=${i%%/*}; [ -e "/sys/class/net/$i/device" ] || continue',
                  '  echo $MASK > "$q/rps_cpus" 2>/dev/null; echo 4096 > "$q/rps_flow_cnt" 2>/dev/null',
                  "done"]
    if "gov" in on:
        lines += ["for g in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do echo performance > \"$g\" 2>/dev/null; done"]
    if "bbr" in on:
        lines += ["modprobe tcp_bbr 2>/dev/null; modprobe sch_fq 2>/dev/null"]
    if "conntrack" in on:
        lines += ["modprobe nf_conntrack 2>/dev/null"]
    # 开机时 sysctl 服务可能早于模块加载（conntrack / bbr 参数会写入失败），这里再应用一次
    lines += ["[ -f " + OPT_SYSCTL + " ] && sysctl -q -p " + OPT_SYSCTL + " 2>/dev/null", "exit 0"]
    return "\n".join(lines) + "\n"


def opt_apply(ids):
    """应用选中的优化项（未选中的恢复原值）；返回 (ok, 消息, 每项错误)"""
    with OPT_LOCK:
        items = {it["id"]: it for it in opt_items()}
        want = [i for i in ids if i in items and items[i]["ok"]]
        d = load()
        prev = set(d.get("sysopt") or [])
        orig = dict(d.get("sysopt_orig") or {})
        mods = list(d.get("sysopt_mods") or [])
        errs = []
        if "bbr" in want:
            sh("modprobe tcp_bbr; modprobe sch_fq")
            mf = os.path.join(ETC, "modules")
            if "tcp_bbr" not in rfile(mf).split():
                try:
                    with open(mf, "a") as f:
                        f.write("tcp_bbr\n")
                    mods.append("tcp_bbr")
                except OSError as e:
                    errs.append(f"写入 /etc/modules 失败：{e}")
        if "conntrack" in want:
            sh("modprobe nf_conntrack")
        # sysctl：先记住原值，再写入；取消的项恢复原值
        conf = ["# 由 Shunt 面板生成：系统优化（取消请在面板「设置 → 系统优化」中关闭）"]
        for iid, it in items.items():
            for k, v in it["sysctl"].items():
                if iid in want:
                    if k not in orig and rsys(k) is not None:
                        orig[k] = rsys(k)
                    e = wsys(k, v)
                    if e:
                        errs.append(e)
                    conf.append(f"{k} = {v}")
                elif iid in prev and k in orig:
                    wsys(k, orig[k])
        try:
            os.makedirs(os.path.dirname(OPT_SYSCTL), exist_ok=True)
            if len(conf) > 1:
                with open(OPT_SYSCTL, "w") as f:
                    f.write("\n".join(conf) + "\n")
            elif os.path.exists(OPT_SYSCTL):
                os.remove(OPT_SYSCTL)
        except OSError as e:
            errs.append(f"写入 {OPT_SYSCTL} 失败：{e}")
        # mihomo 文件句柄
        try:
            txt = rfile(OPT_CONFD)
            txt = "\n".join(l for l in txt.splitlines() if not l.startswith("rc_ulimit=")).strip()
            if "fd" in want:
                txt = (txt + "\n" if txt else "") + 'rc_ulimit="-n 1048576"'
            if txt or os.path.exists(OPT_CONFD):
                os.makedirs(os.path.dirname(OPT_CONFD), exist_ok=True)
                with open(OPT_CONFD, "w") as f:
                    f.write(txt + "\n" if txt else "")
        except OSError as e:
            errs.append(f"写入 {OPT_CONFD} 失败：{e}")
        # RPS
        mask = f"{((1 << (os.cpu_count() or 1)) - 1):x}"
        for ifc in net_ifaces():
            for q in glob_paths(os.path.join(SYS_ROOT, "class/net", ifc, "queues/rx-*")):
                key = "rps:" + q
                if "rps" in want:
                    orig.setdefault(key, rfile(os.path.join(q, "rps_cpus"), "0"))
                    if not (wfile(os.path.join(q, "rps_cpus"), mask) and wfile(os.path.join(q, "rps_flow_cnt"), 4096)):
                        errs.append(f"{ifc} RPS 写入失败")
                elif "rps" in prev and key in orig:
                    wfile(os.path.join(q, "rps_cpus"), orig[key])
                    wfile(os.path.join(q, "rps_flow_cnt"), 0)
        # CPU 调频
        for g in cpu_govs():
            key = "gov:" + g
            if "gov" in want:
                orig.setdefault(key, rfile(g))
                if not wfile(g, "performance"):
                    errs.append("CPU 调频写入失败")
            elif "gov" in prev and key in orig:
                wfile(g, orig[key])
        # 开机脚本
        try:
            if set(want) - {"ntp"}:
                os.makedirs(os.path.dirname(OPT_LOCALD), exist_ok=True)
                with open(OPT_LOCALD, "w") as f:
                    f.write(_opt_locald(set(want)))
                os.chmod(OPT_LOCALD, 0o755)
                sh("rc-update add local default")
            elif os.path.exists(OPT_LOCALD):
                os.remove(OPT_LOCALD)
        except OSError as e:
            errs.append(f"写入开机脚本失败：{e}")
        # 时间同步
        if "ntp" in want and "ntp" not in prev and not ntp_running():
            code, out = sh("apk add --no-cache chrony && rc-update add chronyd default && rc-service chronyd start", timeout=120)
            if code != 0:
                errs.append("安装 chrony 失败：" + out[-150:])
        elif "ntp" in prev and "ntp" not in want:
            sh("rc-service chronyd stop; rc-update del chronyd default")
        if not want:  # 全部关闭：清掉记录，下次重新读取原值
            mf = os.path.join(ETC, "modules")
            if mods:
                ls = [l for l in rfile(mf).splitlines() if l.strip() not in mods]
                wfile(mf, "\n".join(ls) + ("\n" if ls else ""))
            orig, mods = {}, []
        update(lambda x: x.update({"sysopt": want, "sysopt_orig": orig, "sysopt_mods": mods}))
        fd_changed = ("fd" in want) != ("fd" in prev)
        msg = f"已应用 {len(want)} 项优化" if want else "已全部恢复为系统默认值"
        if fd_changed:
            msg += "；文件句柄上限在下次重启核心后生效"
        return not errs, msg + ("" if not errs else "；部分失败：" + "；".join(errs[:4])), errs


def speed_test(proxy):
    """经代理 / 直连下载 Cloudflare 测速文件，返回 Mbps"""
    url = "https://speed.cloudflare.com/__down?bytes=50000000"
    t0 = time.time()
    n = 0
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with proxy_opener(proxy).open(req, timeout=10) as r:
            ttfb = time.time() - t0
            t1 = time.time()
            while time.time() - t1 < 10:
                b = r.read(1 << 16)
                if not b:
                    break
                n += len(b)
            dt = max(time.time() - t1, 0.001)
        return {"ok": True, "mbps": round(n * 8 / dt / 1e6, 1), "mb": round(n / 1e6, 1), "ttfb": int(ttfb * 1000)}
    except Exception as e:
        return {"ok": False, "error": str(e)[:120], "mb": round(n / 1e6, 1)}


def self_rollback():
    bak = os.path.join(BASE, ".backup")
    if not os.path.isfile(os.path.join(bak, "server.py")):
        return False, "没有可回滚的备份"
    for f in UPD_FILES:
        src = os.path.join(bak, f)
        if os.path.isfile(src):
            shutil.copy2(src, local_file(f))
    restart_self()
    return True, "已回滚到更新前的版本，面板正在重启"


def config_view(d=None, masked=True):
    d = d or load()
    if active_core(d) == "singbox":
        cfg = build_singbox(d)[0]
        if masked:
            cfg["experimental"]["clash_api"]["secret"] = "******"
        return json.dumps(cfg, ensure_ascii=False, indent=2)
    cfg = build_config(d)
    if masked:
        cfg["secret"] = "******"
    return json.dumps(cfg, ensure_ascii=False, indent=2)


def sh(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as e:
        return 1, str(e)


def proxy_opener(proxy=True):
    hs = [urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{MIXED}", "https": f"http://127.0.0.1:{MIXED}"} if proxy else {})]
    return urllib.request.build_opener(*hs)


def delay_test():
    tests = load()["tests"] or TESTS
    opener = proxy_opener()
    out = [None] * len(tests)

    def one(i, t):
        st = time.time()
        try:
            req = urllib.request.Request(t["url"], method="HEAD", headers={"User-Agent": "curl/8"})
            try:
                opener.open(req, timeout=6).close()
            except urllib.error.HTTPError:
                pass  # 有响应即可视为可达
            out[i] = {"name": t["name"], "ms": int((time.time() - st) * 1000)}
        except Exception:
            out[i] = {"name": t["name"], "ms": -1}

    ths = [threading.Thread(target=one, args=(i, t)) for i, t in enumerate(tests)]
    [t.start() for t in ths]
    [t.join() for t in ths]
    return out


# ---------------------------------------------------------------- 认证：PBKDF2 密码 + 随机会话
PW_ITER = 60000  # 低端 ARM 上约 0.3 秒，只在登录 / 改密时计算
SESS_FILE = os.path.join(PANEL_DIR, "sessions.json")
SESS_TTL = 30 * 86400  # 会话 30 天无访问即过期（每次访问顺延）
SESS_MAX = 50
SESS, SESS_LOCK, TICKETS = {}, threading.Lock(), {}


def pw_hash(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), PW_ITER).hex()
    return f"pbkdf2_sha256${PW_ITER}${salt}${h}"


def pw_check(pw, d):
    st = d.get("pw_hash") or ""
    if not st:
        return hmac.compare_digest(pw.encode(), (d.get("password") or "admin").encode())
    try:
        _, it, salt, h = st.split("$")
        return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it)).hex(), h)
    except Exception:
        return False


def _tk(tok):
    return hashlib.sha256(str(tok).encode()).hexdigest()


def sess_load():
    try:
        with open(SESS_FILE) as f:
            SESS.update({k: v for k, v in json.load(f).items() if isinstance(v, dict) and v.get("exp", 0) > time.time()})
    except Exception:
        pass


def sess_save():
    try:
        tmp = SESS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(SESS, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, SESS_FILE)
    except Exception as e:
        print("session save error", e, flush=True)


def sess_new(ip="", ua=""):
    tok = secrets.token_urlsafe(32)
    now = time.time()
    with SESS_LOCK:
        for k in [k for k, v in SESS.items() if v.get("exp", 0) <= now]:
            SESS.pop(k)
        while len(SESS) >= SESS_MAX:  # 只保留最近的会话
            SESS.pop(min(SESS, key=lambda k: SESS[k].get("seen", 0)))
        SESS[_tk(tok)] = {"t": int(now), "seen": int(now), "exp": int(now + SESS_TTL), "ip": ip, "ua": ua[:120]}
        sess_save()
    return tok


def sess_ok(tok):
    if not tok:
        return False
    k, now = _tk(tok), time.time()
    with SESS_LOCK:
        e = SESS.get(k)
        if not e or e.get("exp", 0) <= now:
            SESS.pop(k, None)
            return False
        if now - e.get("seen", 0) > 3600:  # 每小时最多落盘一次，避免频繁写闪存
            e["seen"], e["exp"] = int(now), int(now + SESS_TTL)
            sess_save()
    return True


def sess_drop(tok=None, keep=None):
    """tok：注销该会话；tok 为空：注销全部（keep 除外）"""
    with SESS_LOCK:
        if tok:
            SESS.pop(_tk(tok), None)
        else:
            kk = _tk(keep) if keep else None
            for k in [k for k in SESS if k != kk]:
                SESS.pop(k)
        sess_save()


def ticket_new():
    """日志流（EventSource 无法带请求头）用的一次性票据，60 秒有效"""
    now = time.time()
    for k in [k for k, v in TICKETS.items() if v <= now]:
        TICKETS.pop(k, None)
    t = secrets.token_urlsafe(18)
    TICKETS[t] = now + 60
    return t


def ticket_use(t):
    exp = TICKETS.pop(str(t or ""), 0)
    return exp > time.time()


# ---------------------------------------------------------------- Telegram 通知
def tg_send(text, d=None):
    d = d or load()
    if not d.get("tg_token") or not d.get("tg_chat"):
        return False, "未配置 Telegram"
    body = json.dumps({"chat_id": d["tg_chat"], "text": f"[Shunt@{socket.gethostname()}]\n{text}"}).encode()
    url = f"https://api.telegram.org/bot{d['tg_token']}/sendMessage"
    err = ""
    for use_proxy in (True, False):  # 先走代理，核心挂了再直连
        try:
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
            with proxy_opener(use_proxy).open(req, timeout=10) as r:
                if json.loads(r.read()).get("ok"):
                    return True, "已发送"
        except urllib.error.HTTPError as e:
            try:
                return False, json.loads(e.read()).get("description", str(e))
            except Exception:
                return False, str(e)
        except Exception as e:
            err = str(e)
    return False, "发送失败：" + err


def notify(text):
    threading.Thread(target=tg_send, args=(text,), daemon=True).start()


# ---------------------------------------------------------------- 故障自动直连 (watchdog) + 定期告警
WD = {"status": "ok", "fails": 0, "events": deque(maxlen=50), "last_check": 0, "manual_stop": False, "tp_off": False}


def wd_event(msg, push=True):
    WD["events"].appendleft({"t": int(time.time()), "msg": msg})
    print(time.strftime("%F %T"), "[watchdog]", msg, flush=True)
    if push:
        notify(msg)


def core_alive():
    code, _ = core("GET", "/version", timeout=5)
    return code == 200


def watchdog_tick():
    if CORE_UPD["busy"]:  # 内核更新过程中核心会重启，不算故障
        return
    d = load()
    WD["last_check"] = int(time.time())
    if not d.get("watchdog", True):
        WD["status"] = "off"
        return
    redirecting = d["proxy_mode"] != "off"  # TProxy 或 TUN（TUN 模式下 tproxy.sh 仍负责 DNS 重定向）
    if core_alive():
        if WD["status"] in ("restarting", "direct"):
            msg = "mihomo 核心已恢复"
            if WD["tp_off"] and redirecting:
                code, out = sh(TPROXY_SH + " apply")
                msg += "，透明代理已重新开启" if code == 0 else "，但重新开启透明代理失败：" + out[-120:]
            WD["tp_off"] = False
            wd_event(msg)
        WD["status"], WD["fails"] = "ok", 0
        return
    if WD["manual_stop"]:
        WD["status"] = "stopped"
        return
    WD["fails"] += 1
    if WD["fails"] <= 2:
        WD["status"] = "restarting"
        wd_event(f"mihomo 核心无响应，第 {WD['fails']} 次自动重启", push=WD["fails"] == 1)
        sh(SVC + " restart", timeout=60)
        return
    if WD["status"] != "direct":
        WD["status"] = "direct"
        if redirecting:
            sh(TPROXY_SH + " stop")  # TUN 模式下核心退出时 TUN 设备与路由随之消失，这里再撤掉 DNS 重定向
            WD["tp_off"] = True
        wd_event("mihomo 核心重启 2 次仍无响应，已关闭透明代理，局域网暂时直连上网")
    elif WD["fails"] % 10 == 0:  # 直连状态下每 5 分钟再尝试拉起一次
        sh(SVC + " restart", timeout=60)
        if redirecting and core_alive():
            sh(TPROXY_SH + " stop")  # rc 的 start_post 会重新挂上规则，等下一轮确认恢复后再开
            # TUN 模式下核心一启动就接管路由，无法“暂不接管”，下一轮检查会正常恢复


def load_notified():
    return read_json(NOTIFY_FILE, {})


def check_nodes():
    """节点选择里所有节点都超时 → 通知（只在状态变化时发）"""
    d = load()
    if d.get("mode") == "direct" or not (d.get("tg_token") and d.get("tg_chat")):
        return  # 没配置 Telegram 时不必每 10 分钟测一遍全部节点
    # 用「🖐️ 手动选择」（select，含全部节点）测速：对 url-test 组调用 /group/…/delay 会被 mihomo 清除用户的📌固定选择
    pg = core_json("/proxies/" + quote(G_MANUAL))
    if not pg:
        return
    code, raw = core("GET", f"/group/{quote(G_MANUAL)}/delay?url={quote(HC)}&timeout=5000", timeout=30)
    try:
        res = json.loads(raw) if code == 200 else {}
    except Exception:
        res = {}
    all_down = not any(v for v in res.values() if isinstance(v, int) and v > 0)
    st = load_notified()
    if all_down != bool(st.get("allnodes")):
        st["allnodes"] = all_down
        write_json(NOTIFY_FILE, st)
        notify("⚠️ 节点选择中的所有节点均测速超时，请检查订阅或网络" if all_down else "✅ 节点已恢复可用")


# ---------------------------------------------------------------- 节点延迟缓存
# 核心只在内存里保存最近几次测速记录：重载配置、重启、切换内核后全部清空，订阅节点的记录又分散在
# /proxies 与 /providers/proxies 两处，前端轮询时就会「一会有一会没有」。面板把每个节点最近一次的
# 测速结果（任意测速地址中时间最新的一条）缓存到文件，核心暂时没有记录时用缓存补上。
DELAY_FILE = os.path.join(PANEL_DIR, "delays.json")
BG_FILE = os.path.join(PANEL_DIR, "bg.img")  # 外观：自定义背景图（所有设备共用）
BG_MAX = 8 * 2**20
DELAYS = {"data": None, "saved": 0, "dirty": False}
RETEST = {"pending": False, "last": 0}


def _hist_last(p):
    """节点所有测速记录（history 与各地址的 extra.history）里时间最新的一条 → (延迟, 时间串)"""
    best = None
    lists = [p.get("history") or []] + [v.get("history") or [] for v in (p.get("extra") or {}).values() if isinstance(v, dict)]
    for h in lists:
        if h and isinstance(h[-1], dict) and "delay" in h[-1]:
            e = h[-1]
            if best is None or str(e.get("time") or "") > best[1]:
                best = (int(e.get("delay") or 0), str(e.get("time") or ""))
    return best


def delay_merge(px):
    """用核心的最新记录更新缓存，并给每个节点写入 _d（延迟）/ _dt（测速时间）"""
    if DELAYS["data"] is None:
        DELAYS["data"] = read_json(DELAY_FILE, {}) or {}
    data, now = DELAYS["data"], int(time.time())
    for name, p in px.items():
        if p.get("all") is not None:  # 策略组的延迟取当前节点，前端处理
            continue
        r = _hist_last(p)
        if r:
            old = data.get(name)
            if not old or old.get("ts") != r[1]:
                data[name] = {"d": r[0], "ts": r[1], "at": now}
                DELAYS["dirty"] = True
        c = data.get(name)
        if c:
            p["_d"], p["_dt"] = c["d"], c["at"]
    if px:
        for n in [n for n in data if n not in px]:  # 节点已不存在
            data.pop(n)
            DELAYS["dirty"] = True
    if DELAYS["dirty"] and now - DELAYS["saved"] > 30:
        try:
            write_json(DELAY_FILE, data)
            DELAYS.update(saved=now, dirty=False)
        except Exception:
            pass
    return px


def fix_global():
    """mihomo 的「全局」模式走内置 GLOBAL 组，它默认选第一项 DIRECT（全局模式反而不走代理）：没选过代理时指向「🚀 节点选择」"""
    if active_core() == "singbox":  # sing-box 的 Global 已直接指向节点选择
        return
    g = core_json("/proxies/GLOBAL", timeout=5) or {}
    if g.get("now") in (None, "", "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE") and G_SEL in (g.get("all") or []):
        core("PUT", "/proxies/GLOBAL", {"name": G_SEL}, timeout=5)


def retest_soon(wait=6):
    """重载 / 重启后核心的测速记录清空：稍后在后台用「🖐️ 手动选择」（select 组，不会清除 url-test 的固定）测一遍全部节点"""
    if RETEST["pending"] or time.time() - RETEST["last"] < 60:
        return
    RETEST["pending"] = True

    def run():
        try:
            for _ in range(20):
                time.sleep(wait if _ == 0 else 3)
                if core_alive():
                    break
            fix_global()
            if core_json("/proxies/" + quote(G_MANUAL), timeout=5):
                core("GET", f"/group/{quote(G_MANUAL)}/delay?url={quote(HC)}&timeout=5000", timeout=60)
            RETEST["last"] = time.time()
            proxies_merged()
        except Exception:
            pass
        finally:
            RETEST["pending"] = False
    threading.Thread(target=run, daemon=True).start()


def bg_save(data_url):
    """data:image/...;base64,xxx → 保存背景图；只接受 JPEG / PNG / WebP / GIF"""
    m = re.match(r"data:image/[\w.+-]+;base64,(.+)$", str(data_url or ""), re.S)
    if not m:
        return False, "图片格式不正确"
    try:
        raw = base64.b64decode(m.group(1), validate=False)
    except Exception:
        return False, "图片数据无法解析"
    if len(raw) > BG_MAX:
        return False, "图片不能超过 8MB"
    if bg_type(raw[:16]) is None:
        return False, "只支持 JPG / PNG / WebP / GIF"
    tmp = BG_FILE + ".tmp"
    with open(tmp, "wb") as f:
        f.write(raw)
    os.replace(tmp, BG_FILE)
    return True, "背景图已保存"


def bg_type(head):
    if head[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if head[:4] == b"GIF8":
        return "image/gif"
    return None


def proxies_merged():
    """/proxies + 订阅节点（mihomo 在 /providers/proxies，sing-box 由面板拼出）合并成一份，并补上缓存的延迟"""
    a = core_json("/proxies", timeout=8)
    if a is None:
        return None
    px = dict(a.get("proxies") or {})
    try:
        prov = prov_json().get("providers") or {}
    except Exception:
        prov = {}
    for pv in prov.values():
        for n in pv.get("proxies") or []:
            if n and n.get("name"):
                cur = px.get(n["name"])
                if not cur:
                    px[n["name"]] = n
                elif not _hist_last(cur) and _hist_last(n):  # 同名节点：保留有测速记录的那份
                    cur["history"], cur["extra"] = n.get("history") or [], n.get("extra") or {}
    delay_merge(px)
    nodes = [p for p in px.values() if p.get("all") is None and p.get("type") not in ("Direct", "Reject", "RejectDrop", "Pass", "Compatible", "Dns")]
    if nodes and not any("_d" in p for p in nodes):  # 一个延迟都没有（刚启动 / 刚重载）：后台补测
        retest_soon(1)
    return px


def prov_json():
    """订阅节点（mihomo /providers/proxies 格式）；sing-box 由面板按缓存拼出同样的结构"""
    if active_core() == "singbox":
        return sb_fake_providers(load())
    return core_json("/providers/proxies") or {}


def check_subs():
    prov = prov_json().get("providers", {})
    names = {s["name"] for s in load()["subs"]}
    st = load_notified()
    changed = False
    now = time.time()
    for name, p in prov.items():
        si = p.get("subscriptionInfo") or {}
        if name not in names or not si:
            continue
        exp = int(si.get("Expire") or 0)
        k = "exp:" + name
        if exp and 0 < exp - now < 3 * 86400 and st.get(k) != exp:
            st[k] = exp
            changed = True
            notify(f"⏰ 订阅「{name}」将于 {time.strftime('%Y-%m-%d %H:%M', time.localtime(exp))} 到期")
        total, used = int(si.get("Total") or 0), int(si.get("Upload") or 0) + int(si.get("Download") or 0)
        k = "traffic:" + name
        high = total > 0 and used / total > 0.9
        if high and not st.get(k):
            notify(f"📶 订阅「{name}」流量已用 {used / total:.0%}（{used / 2**30:.1f} / {total / 2**30:.1f} GB）")
        if high != bool(st.get(k)):
            st[k] = high
            changed = True
    if changed:
        write_json(NOTIFY_FILE, st)


def monitor_loop():
    n = 0
    while True:
        time.sleep(WD_INTERVAL)
        n += 1
        for fn, every in ((watchdog_tick, 1), (check_nodes, 20), (check_subs, 120), (refresh_regions, 20)):
            if n % every == 0 or (fn is check_subs and n == 2):
                try:
                    if fn is watchdog_tick or WD["status"] in ("ok", "off"):
                        fn()
                except Exception as e:
                    print("monitor error", fn.__name__, e, flush=True)


# ---------------------------------------------------------------- 流量统计
class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.data = read_json(STATS_FILE, {"days": {}})
        self.data.setdefault("days", {})
        self.conns, self.tot, self.saved = {}, None, time.time()

    def bucket(self, day):
        return self.data["days"].setdefault(day, {"up": 0, "down": 0, "dev": {}, "node": {}})

    def poll(self):
        c = core_json("/connections", timeout=5)
        if c is None:
            self.conns, self.tot = {}, None
            return
        ut, dt = int(c.get("uploadTotal") or 0), int(c.get("downloadTotal") or 0)
        cur = {}
        with self.lock:
            b = self.bucket(time.strftime("%Y-%m-%d"))
            first = self.tot is None
            if not first:
                b["up"] += ut - self.tot[0] if ut >= self.tot[0] else ut  # 核心重启后计数归零
                b["down"] += dt - self.tot[1] if dt >= self.tot[1] else dt
            self.tot = (ut, dt)
            for x in c.get("connections") or []:
                up, dn = int(x.get("upload") or 0), int(x.get("download") or 0)
                cur[x["id"]] = (up, dn)
                if first:
                    continue
                pu, pd = self.conns.get(x["id"], (0, 0))
                du, dd = max(0, up - pu), max(0, dn - pd)
                if not du and not dd:
                    continue
                src = (x.get("metadata") or {}).get("sourceIP") or "?"
                node = (x.get("chains") or ["DIRECT"])[0]
                for key, k in (("dev", src), ("node", node)):
                    e = b[key].setdefault(k, [0, 0])
                    e[0] += du
                    e[1] += dd
            self.conns = cur
        if time.time() - self.saved > 60:
            self.flush()

    def flush(self):
        with self.lock:
            keep = sorted(self.data["days"])[-60:]
            self.data["days"] = {k: self.data["days"][k] for k in keep}
            write_json(STATS_FILE, self.data)
        self.saved = time.time()

    def report(self):
        with self.lock:
            days = copy.deepcopy(self.data["days"])
        today, month = time.strftime("%Y-%m-%d"), time.strftime("%Y-%m")

        def agg(keys):
            r = {"up": 0, "down": 0, "dev": {}, "node": {}}
            for k in keys:
                b = days[k]
                r["up"] += b["up"]
                r["down"] += b["down"]
                for key in ("dev", "node"):
                    for n, (u, dn) in b[key].items():
                        e = r[key].setdefault(n, [0, 0])
                        e[0] += u
                        e[1] += dn
            for key in ("dev", "node"):
                r[key] = sorted(([n, u, dn] for n, (u, dn) in r[key].items()), key=lambda x: -(x[1] + x[2]))[:100]
            return r
        return {"today": agg([k for k in days if k == today]), "month": agg([k for k in days if k.startswith(month)]),
                "days": [{"date": k, "up": days[k]["up"], "down": days[k]["down"]} for k in sorted(days)],
                "arp": arp_table()}

    def loop(self):
        while True:
            try:
                self.poll()
            except Exception as e:
                print("stats error", e, flush=True)
            time.sleep(5)


def arp_table():
    out = {}
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                p = line.split()
                if len(p) >= 4 and p[3] != "00:00:00:00:00:00":
                    out[p[0]] = p[3]
    except Exception:
        pass
    return out


STATS = None


# ---------------------------------------------------------------- 流媒体解锁检测
def fetch(url, timeout=10, headers=None):
    h = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}
    h.update(headers or {})
    req = urllib.request.Request(url, headers=h)
    try:
        with proxy_opener().open(req, timeout=timeout) as r:
            try:
                raw = r.read(600000)
            except http.client.IncompleteRead as e:
                raw = e.partial
            return r.status, r.geturl(), raw.decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(200000).decode("utf-8", "ignore")
        except Exception:
            body = ""
        return e.code, e.geturl() if hasattr(e, "geturl") else url, body


def cf_loc(host):
    try:
        _, _, b = fetch(f"https://{host}/cdn-cgi/trace", timeout=8)
        m = re.search(r"^loc=([A-Z]{2})", b, re.M)
        ip = re.search(r"^ip=(\S+)", b, re.M)
        return (m.group(1) if m else ""), (ip.group(1) if ip else "")
    except Exception:
        return "", ""


def ck_egress():
    loc, ip = cf_loc("www.cloudflare.com")
    return {"ok": bool(loc), "text": ip or "无法获取", "region": loc}


def ck_netflix():
    code, url, body = fetch("https://www.netflix.com/title/81280792")
    m = re.search(r'"requestCountry":\{"id":"([A-Z]{2})"', body) or re.search(r'"country":"([A-Z]{2})"', body) \
        or re.search(r"netflix\.com/([a-z]{2})(?:-[a-z]{2})?/title", url)
    region = (m.group(1).upper() if m else "")
    if code == 200:
        return {"ok": True, "text": "完整解锁", "region": region}
    if code == 404:
        return {"ok": "partial", "text": "仅自制剧", "region": region}
    if code == 403:
        return {"ok": False, "text": "不可用（403）"}
    return {"ok": False, "text": f"未知（HTTP {code}）"}


def ck_chatgpt():
    _, _, b1 = fetch("https://ios.chat.openai.com/")
    code2, _, b2 = fetch("https://chatgpt.com/")
    region, _ = cf_loc("chatgpt.com")
    text = b1 + b2
    if "unsupported_country" in text:
        return {"ok": False, "text": "地区不支持", "region": region}
    if re.search(r"VPN|blocked|Access denied", b1, re.I) and "cf-" not in b1[:2000]:
        return {"ok": False, "text": "IP 被封锁", "region": region}
    if code2 in (200, 403) and region:
        return {"ok": True, "text": "可用", "region": region}
    return {"ok": False, "text": f"未知（HTTP {code2}）", "region": region}


def ck_disney():
    code, url, body = fetch("https://www.disneyplus.com/")
    if "unavailable" in url or "not available in your region" in body.lower():
        return {"ok": False, "text": "地区不支持"}
    m = re.search(r'"countryCode"\s*:\s*"([A-Z]{2})"', body) or re.search(r'Region:\s*([A-Z]{2})', body) \
        or re.search(r"disneyplus\.com/(?:[a-z]{2}-)?([a-z]{2})(?:/|$)", url)
    region = m.group(1).upper() if m else ""
    if code == 200:
        return {"ok": True, "text": "可访问" if not region else "可用", "region": region}
    return {"ok": False, "text": f"不可用（HTTP {code}）", "region": region}


def ck_youtube():
    code, url, body = fetch("https://www.youtube.com/premium", headers={"Cookie": "CONSENT=YES+1"})
    if "www.google.cn" in body:
        return {"ok": False, "text": "不可用", "region": "CN"}
    m = re.search(r'"countryCode":"([A-Z]{2})"', body) or re.search(r'"INNERTUBE_CONTEXT_GL":"([A-Z]{2})"', body)
    region = m.group(1) if m else ""
    if "Premium is not available in your country" in body:
        return {"ok": False, "text": "Premium 不可用", "region": region}
    if code == 200 and ("ad-free" in body.lower() or "premium" in body.lower()):
        return {"ok": True, "text": "Premium 可用", "region": region}
    return {"ok": False, "text": f"未知（HTTP {code}）", "region": region}


def ck_gemini():
    code, _, body = fetch("https://gemini.google.com/")
    if re.search(r'45631641(?:,null,true|\\?":true)', body):
        return {"ok": True, "text": "可用"}
    if code == 200:
        return {"ok": False, "text": "地区可能不支持"}
    return {"ok": False, "text": f"不可用（HTTP {code}）"}


UNLOCK = [("出口位置", ck_egress), ("Netflix", ck_netflix), ("ChatGPT", ck_chatgpt), ("Disney+", ck_disney),
          ("YouTube Premium", ck_youtube), ("Gemini", ck_gemini)]


def unlock_test():
    out = [None] * len(UNLOCK)

    def one(i, name, fn):
        try:
            r = fn()
        except Exception as e:
            r = {"ok": False, "text": "检测失败：" + (str(e)[:60] or e.__class__.__name__)}
        r["name"] = name
        out[i] = r
    ths = [threading.Thread(target=one, args=(i, n, f)) for i, (n, f) in enumerate(UNLOCK)]
    [t.start() for t in ths]
    [t.join(30) for t in ths]
    return [o or {"name": UNLOCK[i][0], "ok": False, "text": "超时"} for i, o in enumerate(out)]


# ---------------------------------------------------------------- 规则测试
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
        except Exception:
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


# ---------------------------------------------------------------- 实时日志 (SSE)
def core_stream(path, sink, stop, idle=None):
    """以原始 socket 读取 mihomo 的 chunked JSON 行流，逐行回调 sink；stop 被置位或连接断开时结束。
    idle: 超过该秒数没有数据视为断线（/traffic /memory 每秒推送，可用来发现半开连接）"""
    d = load()
    s = socket.create_connection((CTRL_HOST, CTRL_PORT), timeout=10)
    stop["sock"] = s
    s.settimeout(idle)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: {CTRL_HOST}\r\nAuthorization: Bearer {d['secret']}\r\nConnection: close\r\n\r\n".encode())
    f = s.makefile("rb")
    status = f.readline().decode("latin1")
    chunked = False
    while True:
        h = f.readline()
        if h in (b"\r\n", b"\n", b""):
            break
        if h.lower().startswith(b"transfer-encoding:") and b"chunked" in h.lower():
            chunked = True
    if " 200" not in status:
        raise IOError("mihomo 返回 " + status.strip())
    buf = b""
    while not stop.get("stop"):
        if chunked:
            size_line = f.readline()
            if not size_line:
                break
            size = int(size_line.split(b";")[0].strip() or b"0", 16)
            if size == 0:
                break
            data = f.read(size)
            f.readline()
        else:
            data = f.readline()
            if not data:
                break
        buf += data
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if line.strip():
                sink(line.decode("utf-8", "ignore"))


# ---------------------------------------------------------------- 广告拦截（AdGuard Home 风格的域名过滤）
# 订阅 AdGuard/ABP（||domain^、@@||domain^）、hosts（0.0.0.0 domain）与纯域名列表，转换为 mihomo
# behavior=domain / format=text 的本地 rule-provider 文件：
#   ||a.com^ → "+.a.com"（含子域）；hosts / 纯域名 → "a.com"（仅该域名，与 AdGuard Home 语义一致）
# 规则：AND,((RULE-SET,ad-xxx),(NOT,((RULE-SET,ad-allow)))),REJECT  —— 白名单优先，且被放行的域名继续走正常分流
DOMAIN_RX = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9\-]{1,59})$")
ABP_RX = re.compile(r"^(@@)?\|\|([^\^/|$]+)\^\|?(?:\$(.*))?$")
HOSTS_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1", "0:0:0:0:0:0:0:0", "::0", "0", "255.255.255.255"}
HOSTS_SKIP = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
              "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0"}
AB_STATE = {"updating": False, "msg": "", "last": 0}
AB_LOCK = threading.Lock()


def fmt_size(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def list_id(url):
    return hashlib.md5(url.strip().encode()).hexdigest()[:8]


def norm_domain(s):
    s = s.strip().lower().rstrip(".")
    if not s or "*" in s or not DOMAIN_RX.match(s):
        return None
    return s


def parse_filter(text, plain_suffix=False):
    """解析过滤列表文本。返回 (block_suffix, block_exact, allow_suffix, allow_exact, skipped)"""
    bs, be, as_, ae = set(), set(), set(), set()
    skipped = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "!#[":
            continue
        low = line.lower()
        if low.startswith("||") or low.startswith("@@"):
            m = ABP_RX.match(low)
            if not m:
                # 允许 @@domain / @@|domain^ 之类的简写出现在用户白名单里
                if plain_suffix and low.startswith("@@") and norm_domain(low[2:].strip("|^")):
                    as_.add(norm_domain(low[2:].strip("|^")))
                else:
                    skipped += 1
                continue
            allow, dom, mods = m.group(1), m.group(2), m.group(3)
            if mods and {x.strip() for x in mods.split(",")} - {"important", ""}:
                skipped += 1  # $client= / $dnstype= / $denyallow= 等修饰符无法用域名规则等价表达
                continue
            dom = norm_domain(dom)
            if not dom:
                skipped += 1
                continue
            (as_ if allow else bs).add(dom)
            continue
        if low[0] in "|/" or any(c in low for c in "$^*/\\"):
            skipped += 1  # 正则、URL 规则、通配符等
            continue
        parts = low.split("#", 1)[0].split()
        if len(parts) >= 2 and parts[0] in HOSTS_IPS:
            for h in parts[1:]:
                dom = norm_domain(h)
                if dom and dom not in HOSTS_SKIP:
                    be.add(dom)
                elif h not in HOSTS_SKIP:
                    skipped += 1
        elif len(parts) == 1:
            dom = norm_domain(parts[0].lstrip("+."))
            if not dom:
                skipped += 1
            elif plain_suffix or parts[0].startswith("+.") or parts[0].startswith("."):
                bs.add(dom)
            else:
                be.add(dom)
        else:
            skipped += 1
    return bs, be, as_, ae, skipped


def parents(dom, include_self):
    parts = dom.split(".")
    for i in range(0 if include_self else 1, len(parts)):
        yield ".".join(parts[i:])


def prune(suffix, exact):
    """去掉已被上级 +. 规则覆盖的条目"""
    suffix2 = {s for s in suffix if not any(p in suffix for p in parents(s, False))}
    exact2 = {e for e in exact if not any(p in suffix for p in parents(e, True))}
    return suffix2, exact2


def domain_lines(suffix, exact):
    suffix, exact = prune(suffix, exact)
    return sorted(["+." + x for x in suffix] + list(exact)), len(suffix) + len(exact)


def write_lines(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".tmp", "w") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))
    os.replace(path + ".tmp", path)


def ab_meta():
    return read_json(os.path.join(AB_DIR, "meta.json"), {})


def download(url, timeout=60, limit=40 << 20):
    """先经代理（mixed 端口）下载，失败再直连"""
    err = ""
    for use_proxy in (True, False):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with proxy_opener(use_proxy).open(req, timeout=timeout) as r:
                data = r.read(limit + 1)
                if len(data) > limit:
                    raise ValueError("文件过大（超过 40MB）")
                return data.decode("utf-8", "ignore")
        except Exception as e:
            err = str(e)[:160]
    raise IOError(err or "下载失败")


def ab_fetch(lst):
    """下载并转换一个列表，写入 <id>.txt / <id>.allow.txt，返回 meta"""
    text = download(lst["url"])
    bs, be, as_, ae, skipped = parse_filter(text)
    lines, n = domain_lines(bs, be)
    alines, na = domain_lines(as_, ae)
    if not n and not na:
        raise ValueError("没有解析出任何域名，确认是 AdGuard / hosts / 域名列表格式")
    write_lines(os.path.join(AB_DIR, lst["id"] + ".txt"), lines)
    write_lines(os.path.join(AB_DIR, lst["id"] + ".allow.txt"), alines)
    return {"count": n, "allow": na, "skipped": skipped, "updated": int(time.time()), "error": ""}


def ab_compose(d):
    """根据用户黑/白名单与各列表的 @@ 规则生成 custom.txt / allow.txt"""
    ab = d["adblock"]
    bs, be, _, _, _ = parse_filter("\n".join(ab.get("black") or []), plain_suffix=True)
    write_lines(os.path.join(AB_DIR, "custom.txt"), domain_lines(bs, be)[0])
    ws, we, was, wae, _ = parse_filter("\n".join(ab.get("white") or []), plain_suffix=True)
    suffix, exact = ws | was, we | wae
    for l in ab.get("lists", []):
        if not l.get("enabled", True):
            continue
        try:
            with open(os.path.join(AB_DIR, l["id"] + ".allow.txt")) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("+."):
                        suffix.add(line[2:])
                    elif line:
                        exact.add(line)
        except OSError:
            pass
    write_lines(os.path.join(AB_DIR, "allow.txt"), domain_lines(suffix, exact)[0])


def adblock_providers(d):
    ab = d.get("adblock") or {}
    if not ab.get("enabled"):
        return {}, []
    prov = {}

    def add(name, fn):
        path = os.path.join(AB_DIR, fn)
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            prov[name] = {"type": "file", "behavior": "domain", "format": "text", "path": "./adblock/" + fn}
    add("ad-allow", "allow.txt")
    add("ad-custom", "custom.txt")
    for l in ab.get("lists", []):
        if l.get("enabled", True) and re.fullmatch(r"[0-9a-f]{8}", l.get("id", "")):
            add("ad-" + l["id"], l["id"] + ".txt")
    rules = []
    for k in prov:
        if k == "ad-allow":
            continue
        rules.append(f"AND,((RULE-SET,{k}),(NOT,((RULE-SET,ad-allow)))),REJECT" if "ad-allow" in prov else f"RULE-SET,{k},REJECT")
    return prov, rules


def config_text(d):
    return json.dumps(build_config(d), ensure_ascii=False, indent=2)


def ab_apply():
    """列表文件变化后让核心生效：配置结构没变时只刷新对应 rule-provider，否则走完整的校验 + 重载"""
    d = load()
    if active_core(d) == "singbox":  # 广告列表转换成 sing-box 规则集后重载
        sb_sync_assets(d)
        AB_CACHE.clear()
        return reload_core()
    try:
        with open(os.path.join(CONF_DIR, "config.yaml")) as f:
            same = f.read() == config_text(d)
    except OSError:
        same = False
    if same:
        for name in adblock_providers(d)[0]:
            core("PUT", "/providers/rules/" + quote(name), timeout=60)
        AB_CACHE.clear()
        return True, "规则已刷新"
    AB_CACHE.clear()
    return reload_core()


def adblock_update(ids=None, apply=True):
    """下载全部（或指定）启用的列表；在后台线程里调用"""
    with AB_LOCK:
        if AB_STATE["updating"]:
            return False, "正在更新中"
        AB_STATE.update(updating=True, msg="正在下载规则列表…")
    try:
        d = load()
        lists = [l for l in d["adblock"]["lists"] if l.get("enabled", True) and (not ids or l["id"] in ids)]
        meta = ab_meta()
        res = {}

        def one(l):
            try:
                res[l["id"]] = ab_fetch(l)
            except Exception as e:
                m = dict(meta.get(l["id"]) or {})
                m.update(error=str(e)[:200], checked=int(time.time()))
                res[l["id"]] = m
        ths = [threading.Thread(target=one, args=(l,)) for l in lists]
        [t.start() for t in ths]
        [t.join(150) for t in ths]
        meta.update(res)
        os.makedirs(AB_DIR, exist_ok=True)
        write_json(os.path.join(AB_DIR, "meta.json"), meta)
        ab_compose(load())
        bad = [l["name"] for l in lists if (res.get(l["id"]) or {}).get("error")]
        ok, msg = ab_apply() if apply else (True, "")
        AB_STATE["last"] = int(time.time())
        AB_STATE["msg"] = ("部分列表下载失败：" + "、".join(bad) if bad else "已更新 %d 个列表" % len(lists)) + ("" if ok else "；" + msg)
        return ok and not bad, AB_STATE["msg"]
    finally:
        AB_STATE["updating"] = False


AB_CACHE = {}


def ab_sets(path):
    try:
        mt = os.path.getmtime(path)
    except OSError:
        return set(), set()
    c = AB_CACHE.get(path)
    if c and c[0] == mt:
        return c[1], c[2]
    suf, ex = set(), set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("+."):
                suf.add(line[2:])
            elif line:
                ex.add(line)
    AB_CACHE[path] = (mt, suf, ex)
    return suf, ex


def ab_match(host, sets):
    suf, ex = sets
    if host in ex:
        return host
    for p in parents(host, True):
        if p in suf:
            return "+." + p
    return None


def ab_check(target):
    host = clean_target(target)
    if not norm_domain(host):
        raise ValueError("请输入有效域名")
    d = load()
    ab = d["adblock"]
    names = {l["id"]: l["name"] for l in ab["lists"]}
    blocked, allowed = [], []
    ws, we, was, wae, _ = parse_filter("\n".join(ab.get("white") or []), plain_suffix=True)
    r = ab_match(host, (ws | was, we | wae))
    if r:
        allowed.append({"name": "自定义白名单", "rule": r})
    for l in ab["lists"]:
        if not l.get("enabled", True):
            continue
        r = ab_match(host, ab_sets(os.path.join(AB_DIR, l["id"] + ".allow.txt")))
        if r:
            allowed.append({"name": l["name"] + "（@@ 例外）", "rule": r})
    bs, be, _, _, _ = parse_filter("\n".join(ab.get("black") or []), plain_suffix=True)
    r = ab_match(host, (bs, be))
    if r:
        blocked.append({"name": "自定义黑名单", "rule": r})
    for l in ab["lists"]:
        if not l.get("enabled", True):
            continue
        r = ab_match(host, ab_sets(os.path.join(AB_DIR, l["id"] + ".txt")))
        if r:
            blocked.append({"name": names[l["id"]], "rule": r})
    return {"host": host, "enabled": bool(ab.get("enabled")), "blocked_by": blocked, "allowed_by": allowed,
            "blocked": bool(blocked) and not allowed and bool(ab.get("enabled"))}


class AdStats:
    """订阅 mihomo info 日志，统计命中广告规则 (REJECT) 的连接"""
    RX = re.compile(r"--> (\S+?):\d+ match .*?RuleSet[,(](ad-[0-9a-z]+)\).* using REJECT")

    def __init__(self):
        self.lock = threading.Lock()
        self.data = read_json(AB_STATS_FILE, {"days": {}})
        self.data.setdefault("days", {})
        self.saved = time.time()

    def hit(self, host, prov):
        if host.startswith("["):
            host = host[1:-1]
        with self.lock:
            b = self.data["days"].setdefault(time.strftime("%Y-%m-%d"), {"count": 0, "top": {}, "lists": {}})
            b["count"] += 1
            b["top"][host] = b["top"].get(host, 0) + 1
            key = prov[3:]
            b["lists"][key] = b["lists"].get(key, 0) + 1
            if len(b["top"]) > 5000:  # 防止长尾域名无限增长
                b["top"] = dict(sorted(b["top"].items(), key=lambda x: -x[1])[:2000])

    def sink(self, line):
        try:
            msg = json.loads(line).get("payload", "")
        except Exception:
            return
        if "REJECT" not in msg:
            return
        m = self.RX.search(msg)
        if m:
            self.hit(m.group(1), m.group(2))
        if time.time() - self.saved > 60:
            self.flush()

    def flush(self):
        with self.lock:
            keep = sorted(self.data["days"])[-14:]
            self.data["days"] = {k: self.data["days"][k] for k in keep}
            for b in self.data["days"].values():
                b["top"] = dict(sorted(b["top"].items(), key=lambda x: -x[1])[:500])
            write_json(AB_STATS_FILE, self.data)
        self.saved = time.time()

    def report(self):
        with self.lock:
            days = copy.deepcopy(self.data["days"])
        b = days.get(time.strftime("%Y-%m-%d"), {"count": 0, "top": {}, "lists": {}})
        return {"today": b["count"], "top": sorted(b["top"].items(), key=lambda x: -x[1])[:20], "lists": b["lists"],
                "days": [{"date": k, "count": days[k]["count"]} for k in sorted(days)]}

    def loop(self):
        while True:
            try:
                core_stream("/logs?level=info", self.sink, {})
            except Exception:
                pass
            time.sleep(3)


AD_STATS = None


# ---------------------------------------------------------------- 实时速率 / 内存（订阅 /traffic 与 /memory 流）
LIVE = {"up": 0, "down": 0, "upTotal": 0, "downTotal": 0, "inuse": 0, "oslimit": 0, "t": 0}


def live_loop(path):
    def sink(line):
        try:
            j = json.loads(line)
        except Exception:
            return
        if path == "/memory":
            if j.get("inuse"):  # 首条消息固定为 0
                LIVE["inuse"], LIVE["oslimit"] = j["inuse"], j.get("oslimit", 0)
        else:
            LIVE.update({k: j.get(k, 0) for k in ("up", "down", "upTotal", "downTotal")})
            LIVE["t"] = time.time()
    while True:
        try:
            core_stream(path, sink, {}, idle=15)
        except Exception:
            pass
        LIVE.update(up=0, down=0, t=0) if path == "/traffic" else LIVE.update(inuse=0)
        time.sleep(3)


def memory_once():
    """不依赖后台线程：读取 /memory 流的前两行（首行恒为 0）"""
    got = []
    stop = {}

    def sink(line):
        try:
            j = json.loads(line)
        except Exception:
            return
        got.append(j)
        if j.get("inuse") or len(got) >= 2:
            stop["stop"] = True
            try:
                stop["sock"].shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
    try:
        core_stream("/memory", sink, stop, idle=3)
    except Exception:
        pass
    vals = [g for g in got if g.get("inuse")]
    return vals[-1] if vals else {"inuse": 0, "oslimit": 0}


# ---------------------------------------------------------------- 日志自动清理
LOG_STATE = {"last": 0, "trimmed": []}


def log_sizes():
    out = []
    for p in LOG_FILES:
        try:
            out.append({"path": p, "size": os.path.getsize(p)})
        except OSError:
            out.append({"path": p, "size": -1})
    return out


def trim_log(path, keep=200):
    """原地截断，只保留最后 keep 行。写入方（OpenRC output_log）以 O_APPEND 打开，截断后会继续追加到新末尾"""
    try:
        with open(path, "rb+") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 256 * 1024))
            tail = f.read().splitlines(keepends=True)[-keep:]
            data = b"".join(tail)
            f.seek(0)
            f.write(data)
            f.truncate()
        return size - len(data)
    except OSError:
        return 0


def log_clean(force=False):
    limit = float(load().get("log_limit") or 5) * 1024 * 1024
    freed = 0
    for x in log_sizes():
        if x["size"] > 0 and (force or x["size"] > limit):
            freed += trim_log(x["path"])
    LOG_STATE["last"] = int(time.time())
    return freed


def log_loop():
    while True:
        try:
            freed = log_clean()
            if freed:
                print(time.strftime("%F %T"), f"[log] 日志超过上限，已截断释放 {freed // 1024} KB", flush=True)
        except Exception as e:
            print("log clean error", e, flush=True)
        time.sleep(60)


# ---------------------------------------------------------------- 定时任务
SCHED = {"events": deque(maxlen=30), "done": {}}


def sched_event(msg):
    SCHED["events"].appendleft({"t": int(time.time()), "msg": msg})
    print(time.strftime("%F %T"), "[schedule]", msg, flush=True)


def run_task(name):
    d = load()
    if name == "sub_update" and active_core(d) == "singbox":
        ok, bad = sb_update_subs(d=d)
        try:
            refresh_regions()
        except Exception:
            pass
        return not bad, "订阅已更新" if not bad else "以下订阅更新失败：" + "；".join(bad)
    if name == "geo_update" and active_core(d) == "singbox":
        bad = sb_sync_assets(d, force=True)
        ok, msg = reload_core()
        return not bad and ok, "GEO / 规则集已更新" if not bad else "部分规则集更新失败：" + "；".join(bad)[:200]
    if name == "sub_update":
        bad = []
        for s in d["subs"]:
            code, _ = core("PUT", "/providers/proxies/" + quote(s["name"]), timeout=120)
            if code >= 300:
                bad.append(s["name"])
        try:
            refresh_regions()
        except Exception:
            pass
        return not bad, "订阅已更新" if not bad else "以下订阅更新失败：" + "、".join(bad)
    if name == "core_restart":
        WD["manual_stop"] = False
        code, out = sh(SVC + " restart", timeout=90)
        return code == 0, "核心已重启" if code == 0 else out[-200:]
    if name == "geo_update":
        code, raw = core("POST", "/configs/geo", {}, timeout=180)
        return code < 300, "GEO 数据库已更新" if code < 300 else raw.decode(errors="ignore")[:200]
    if name == "latency":
        # GLOBAL 只含 config 里的节点和策略组，订阅节点要经「🖐️ 手动选择」（含全部节点）测速
        code, raw = core("GET", f"/group/GLOBAL/delay?url={quote(HC)}&timeout=5000", timeout=120)
        n = 0
        if core_json("/proxies/" + quote(G_MANUAL)):
            c2, r2 = core("GET", f"/group/{quote(G_MANUAL)}/delay?url={quote(HC)}&timeout=5000", timeout=120)
            try:
                n = sum(1 for v in json.loads(r2).values() if isinstance(v, int) and v > 0) if c2 == 200 else 0
            except Exception:
                n = 0
            code = 200 if (code == 200 or c2 in (200, 504)) else code
        return code == 200, f"节点测速完成，{n} 个节点可达"
    if name == "adblock":
        return adblock_update()
    return False, "未知任务"


TASK_NAMES = {"sub_update": "定时更新订阅", "core_restart": "定时重启核心", "geo_update": "定时更新 GEO",
              "latency": "自动测速", "adblock": "更新广告规则"}


def sched_loop():
    n = 0
    while True:
        time.sleep(20)
        n += 1
        try:
            d = load()
            sc = d.get("schedule") or {}
            now = time.strftime("%H:%M")
            today = time.strftime("%Y-%m-%d")
            due = [k for k in ("sub_update", "core_restart", "geo_update")
                   if sc.get(k) and sc[k] == now and SCHED["done"].get(k) != today]
            mins = int(sc.get("latency") or 0)
            if mins and time.time() - SCHED["done"].get("latency", 0) >= mins * 60:
                due.append("latency")
            if active_core(d) == "singbox" and d["subs"]:  # mihomo 的订阅由核心按间隔自动更新；sing-box 由面板代劳
                iv = max(int(d.get("sub_interval") or 86400), 600)
                last = min([sb_sub_cache(s["name"]).get("updated", 0) for s in d["subs"]] or [0])
                if time.time() - max(last, SCHED["done"].get("sb_subs", 0)) >= iv:
                    SCHED["done"]["sb_subs"] = time.time()
                    ok_, bad_ = sb_update_subs(d=d)
                    refresh_regions()
                    if bad_:
                        sched_event("订阅自动更新：✗ " + "；".join(bad_)[:200])
            ab = d["adblock"]
            if ab.get("enabled") and ab.get("lists") and int(ab.get("interval") or 0):
                if time.time() - max(AB_STATE["last"], ab_last_update()) >= int(ab["interval"]):
                    due.append("adblock")
            for k in due:
                SCHED["done"][k] = time.time() if k in ("latency",) else today
                if k == "adblock":
                    AB_STATE["last"] = int(time.time())  # 失败也等下一个周期，避免频繁重试
                ok, msg = run_task(k)
                if k != "latency" or not ok:
                    sched_event(f"{TASK_NAMES[k]}：{'✓' if ok else '✗'} {msg}")
        except Exception as e:
            print("schedule error", e, flush=True)


def ab_last_update():
    m = ab_meta()
    return max([v.get("updated", 0) for v in m.values()] or [0])


# ---------------------------------------------------------------- 设备名称
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
            try:
                socket.setdefaulttimeout(2)
                name = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass
            finally:
                socket.setdefaulttimeout(None)
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
        if os.path.isdir("/sys/class/net/" + dev):
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


# ---------------------------------------------------------------- 网络诊断
def dns_probe(server=("127.0.0.1", 1053), name="www.baidu.com"):
    """向 mihomo DNS 端口发一个最小的 A 查询"""
    qid = secrets.randbits(16)
    pkt = qid.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    pkt += b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4)
    try:
        st = time.time()
        s.sendto(pkt, server)
        data = s.recv(1500)
        rcode, an = data[3] & 0x0F, int.from_bytes(data[6:8], "big")
        return rcode == 0 and an > 0, int((time.time() - st) * 1000), rcode
    finally:
        s.close()


def diagnose():
    d = load()
    mode = d["proxy_mode"]
    out = []

    def item(name, ok, detail, fix=""):
        out.append({"name": name, "ok": ok, "detail": detail, "fix": fix if ok is not True else ""})

    code, ver = core("GET", "/version", timeout=5)
    alive = code == 200
    sb = active_core(d) == "singbox"
    item(f"{CORES[active_core(d)]} 核心", alive, json.loads(ver).get("version", "") if alive else "核心未运行或控制器无响应",
         "在顶部点「启动」，或执行 rc-service mihomo restart 并查看 /var/log/mihomo.log")
    if sb:
        if os.path.isfile(SB_BIN) and os.path.isfile(SB_CONF):
            ok, err = check_sb_config(SB_CONF)
            item("配置校验 (sing-box check)", ok, "通过" if ok else err[-200:], "在设置中撤销最近的修改，或切回 mihomo")
        if SB_STATE["warn"]:
            item("sing-box 兼容提示", "warn", "；".join(SB_STATE["warn"])[:300], "详见 设置 → 核心 → 内核切换")
    cfg = os.path.join(CONF_DIR, "config.yaml")
    if not sb and os.path.isfile(MIHOMO_BIN) and os.path.isfile(cfg):
        ok, err = check_config(cfg)
        item("配置校验 (mihomo -t)", ok, "通过" if ok else err[-200:], "在设置中撤销最近的修改，或恢复备份")
    try:
        fwd = open("/proc/sys/net/ipv4/ip_forward").read().strip() == "1"
    except OSError:
        fwd = False
    item("IPv4 转发", fwd if mode != "off" else ("warn" if not fwd else True), "已开启" if fwd else "未开启",
         "sysctl -w net.ipv4.ip_forward=1，并写入 /etc/sysctl.conf")
    _, st = sh(TPROXY_SH + " status", timeout=10)
    st = st.strip().splitlines()[-1] if st.strip() else "off"
    if mode == "tproxy":
        item("TProxy 规则", st == "tproxy", "nftables 规则已加载" if st == "tproxy" else "未检测到 nftables TProxy 规则",
             "在设置里重新选择「TProxy」，或执行 /opt/mihomo-panel/tproxy.sh start；需要 nftables 与 nft_tproxy 模块")
    elif mode == "tun":
        dev = safe_dev((d.get("tun") or {}).get("device"))
        has_tun = os.path.exists("/dev/net/tun")
        item("TUN 模块", has_tun, "/dev/net/tun 存在" if has_tun else "缺少 /dev/net/tun",
             "modprobe tun，并把 tun 加入 /etc/modules（install.sh 会自动处理）")
        up = os.path.isdir("/sys/class/net/" + dev)
        item(f"TUN 网卡 {dev}", up, "已创建" if up else "未找到该网卡",
             "确认核心以 root 运行且日志里没有 TUN 报错；切换协议栈为 gvisor 再试")
        item("DNS 重定向 (53 → 1053)", st == "dns" or "warn", "已加载" if st == "dns" else "未加载，局域网设备需把 DNS 指向本机 1053 或开启后重试",
             "执行 /opt/mihomo-panel/tproxy.sh dns")
    else:
        item("代理方式", "warn", "已关闭透明代理，仅 7890 端口（HTTP/SOCKS）可用", "在设置里选择 TProxy 或 TUN")
    if alive:
        try:
            ok, ms, rc = dns_probe()
            item("DNS 服务 (127.0.0.1:1053)", ok, f"解析 www.baidu.com 用时 {ms} ms" if ok else f"返回码 {rc}",
                 "检查 设置 → DNS 中的直连 DNS 是否可达")
        except Exception as e:
            item("DNS 服务 (127.0.0.1:1053)", False, str(e)[:120], "确认核心 DNS 已监听 1053 端口")
        for host, label in (("www.baidu.com", "国内域名解析"), ("www.google.com", "国外域名解析")):
            c2, raw = core("GET", f"/dns/query?name={host}&type=A", timeout=10)
            try:
                j = json.loads(raw)
                ans = [a["data"] for a in j.get("Answer") or [] if a.get("type") == 1]
                ok = c2 == 200 and j.get("Status") == 0 and bool(ans)
                item(label, ok, ", ".join(ans[:2]) if ok else f"失败（Status {j.get('Status')}）",
                     "检查直连 / 代理 DNS 设置" + ("；代理 DNS 依赖节点可用" if "google" in host else ""))
            except Exception:
                item(label, False, "查询失败", "检查 DNS 设置")

    def reach(url, use_proxy):
        st = time.time()
        try:
            req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "curl/8"})
            try:
                proxy_opener(use_proxy).open(req, timeout=8).close()
            except urllib.error.HTTPError:
                pass
            return True, int((time.time() - st) * 1000)
        except Exception as e:
            return False, str(e)[:100]
    res = {}
    ths = [threading.Thread(target=lambda k=k, a=a: res.__setitem__(k, reach(*a))) for k, a in
           (("direct", ("https://www.baidu.com", False)), ("cn", ("https://www.baidu.com", True)),
            ("proxy", ("https://www.gstatic.com/generate_204", True)))]
    [t.start() for t in ths]
    [t.join(12) for t in ths]
    for k, label, fix in (("direct", "本机直连外网", "检查旁路由的网关 / DNS 设置（应指向主路由）"),
                          ("cn", "经代理访问国内", "核心或 7890 端口异常，查看日志"),
                          ("proxy", "经代理访问国外", "当前节点不可用：去「节点」测速并切换，或更新订阅")):
        ok, v = res.get(k, (False, "超时"))
        item(label, ok, f"{v} ms" if ok else v, fix)
    try:
        du = shutil.disk_usage(CONF_DIR)
        free = du.free / 2**20
        item("磁盘空间", True if free > 100 else "warn" if free > 20 else False, f"剩余 {free:.0f} MB",
             "清理日志（设置 → 日志清理）或扩容")
    except OSError:
        pass
    return out


# ---------------------------------------------------------------- DNS 防泄露
RESOLV_FILE = os.environ.get("PANEL_RESOLV", "/etc/resolv.conf")
CN_GEO = re.compile(r"(?i)^(?:cn|private|.*@cn|.*-cn|tld-cn|geolocation-cn)$")
CN_DOMAIN = re.compile(r"(?i)^[+*.]*[\w.\-]*\.(?:cn|lan|local|arpa|home|localdomain)$")


def is_cn_dns(x):
    x = x.split("#", 1)[0]
    return bool(CN_DNS.search(x)) or x.startswith(("system", "dhcp://"))


def antileak_dns(cur):
    """一键防泄露：fake-ip + respect-rules + 默认上游走代理 DNS + 国内域名走直连 DNS + 阻止客户端绕过"""
    dc = copy.deepcopy(cur)
    dc.update(mode="fake-ip", respect_rules=True, policy=True, block_bypass=True)
    dc["direct"] = [x for x in dc["direct"] if "#" not in x] or list(DNS_DEFAULT["direct"])
    proxy = []
    for x in dc["proxy"]:
        if is_cn_dns(x) or x.startswith("rcode://"):
            continue  # 国内 / 本机 DNS 不能作为代理 DNS
        if not dns_policy_of(x):
            x = x.split("#", 1)[0] + "#" + G_SEL
        proxy.append(x)
    dc["proxy"] = proxy or list(DNS_DEFAULT["proxy"])
    dc["pserver"] = [x for x in dc["pserver"] if "#" not in x and is_cn_dns(x)]
    if not dc["fake_filter"]:
        dc["fake_filter"] = list(DEFAULT_FAKE_FILTER)
    dc["policies"] = [pe for pe in dc["policies"] if not leaky_policy(pe)]
    return dc


def leaky_policy(pe):
    """自定义 nameserver-policy 把非国内域名交给国内 DNS"""
    kind, parts = policy_parts(pe["match"])
    if kind == "rule-set" or all((CN_GEO if kind == "geosite" else CN_DOMAIN).match(p) for p in parts):
        return False
    return any(is_cn_dns(x) for x in pe["servers"]) and not all(x.startswith("rcode://") for x in pe["servers"])


def host_match(pattern, name):
    pattern = pattern.lower()
    if pattern.startswith("+."):
        return name == pattern[2:] or name.endswith(pattern[1:])
    if pattern.startswith("."):
        return name.endswith(pattern)
    if "*" in pattern:
        return bool(re.fullmatch(re.escape(pattern).replace(r"\*", r"[^.]+"), name))
    return name == pattern


def dns_route(name, d):
    """估算一个域名由哪组上游解析（GEOSITE 需要核心数据库，这里按规则顺序给出说明）"""
    dc = dns_cfg(d)
    short = lambda xs: "、".join(x.replace("https://", "").replace("/dns-query", "") for x in xs[:2]) + (" 等" if len(xs) > 2 else "")
    for h in dc["hosts"]:
        if host_match(h["domain"], name):
            return f"hosts 静态记录（{h['domain']} → {', '.join(h['value'][:3])}，不查询上游）"
    for pe in dc["policies"]:
        kind, parts = policy_parts(pe["match"])
        for part in parts if kind == "domain" else []:
            if host_match(part, name):
                return f"自定义策略 {part} → {short(pe['servers'])}"
    geo = [pe["match"] for pe in dc["policies"] if policy_parts(pe["match"])[0] != "domain"]
    head = ("先匹配自定义 " + "、".join(geo[:3]) + "；") if geo else ""
    if not dc["proxy"]:
        return head + f"全部走直连 DNS（{short(dc['direct'])}）——未设置代理 DNS，国外域名会泄露"
    if dc["policy"]:
        return head + f"属于 geosite:cn / private → 直连 DNS（{short(dc['direct'])}）；其他域名 → 代理 DNS（{short(dc['proxy'])}）"
    return head + f"全部走代理 DNS（{short(dc['proxy'])}）"


def dns_probe_ip(name, server=("127.0.0.1", 1053)):
    """向 mihomo DNS 端口查询 A 记录，返回 (rcode, [IP])"""
    qid = secrets.randbits(16)
    pkt = qid.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    pkt += b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4)
    try:
        s.sendto(pkt, server)
        data = s.recv(1500)
    finally:
        s.close()
    rcode, an = data[3] & 0x0F, int.from_bytes(data[6:8], "big")
    i, ips = 12, []
    while data[i]:  # 跳过问题部分
        i += data[i] + 1
    i += 5
    for _ in range(an):
        if data[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while data[i]:
                i += data[i] + 1
            i += 1
        typ, rdlen = int.from_bytes(data[i:i + 2], "big"), int.from_bytes(data[i + 8:i + 10], "big")
        i += 10
        if typ == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in data[i:i + 4]))
        i += rdlen
    return rcode, ips


def resolv_servers():
    try:
        with open(RESOLV_FILE) as f:
            return [l.split()[1] for l in f if l.strip().startswith("nameserver") and len(l.split()) > 1]
    except OSError:
        return []


def leak_live():
    """经代理访问 bash.ws 的 DNS 泄露测试：用 mihomo 的解析器（/dns/query，与客户端走同样的上游分流）
    解析一组随机子域名，再读取 bash.ws 记录到的递归解析器 IP / 国家"""
    out = {"ok": None, "resolvers": [], "egress": [], "error": "", "source": "bash.ws"}
    try:
        code, _, tid = fetch("https://bash.ws/id", timeout=10)
        tid = tid.strip()
        if code != 200 or not re.fullmatch(r"[a-z0-9]{6,40}", tid):
            raise IOError(f"获取测试 ID 失败（HTTP {code}）")
        ths = [threading.Thread(target=core, args=("GET", f"/dns/query?name={i}.{tid}.bash.ws&type=A"), kwargs={"timeout": 10})
               for i in range(1, 9)]
        [t.start() for t in ths]
        [t.join(12) for t in ths]
        time.sleep(1)
        code, _, body = fetch(f"https://bash.ws/dnsleak/test/{tid}?json", timeout=15)
        items = json.loads(body)
        for x in items:
            e = {"ip": x.get("ip"), "country": (x.get("country") or "").upper(), "country_name": x.get("country_name") or "",
                 "org": x.get("asn") or x.get("org") or ""}
            if x.get("type") == "dns":
                e["cn"] = e["country"] == "CN"
                out["resolvers"].append(e)
            elif x.get("type") == "ip":
                out["egress"].append(e)
        if not out["resolvers"]:
            out["error"] = "bash.ws 没有记录到解析请求（代理 DNS 可能不可用）"
        else:
            out["ok"] = not any(r["cn"] for r in out["resolvers"])
    except Exception as e:
        out["error"] = "在线检测失败：" + (str(e)[:160] or e.__class__.__name__)
    return out


def leak_check(live=True):
    d = load()
    dc = dns_cfg(d)
    items = []

    def item(name, ok, detail, fix=""):
        items.append({"name": name, "ok": ok, "detail": detail, "fix": fix if ok is not True else ""})

    item("增强模式", True if dc["mode"] == "fake-ip" else "warn",
         "fake-ip：客户端只拿到 198.18.x.x，域名由 mihomo 按规则处理" if dc["mode"] == "fake-ip" else
         "redir-host：客户端拿到真实 IP，可能绕过按域名分流", "改用 fake-ip")
    ns = dc["proxy"] or dc["direct"]
    bad_ns = [x for x in ns if is_cn_dns(x)]
    unrouted = [x for x in dc["proxy"] if not dns_policy_of(x) and not dc["respect_rules"]]
    if not dc["proxy"]:
        item("默认上游（未知 / 国外域名）", False, "未设置代理 DNS，所有域名都发给直连 DNS：" + "、".join(dc["direct"][:2]),
             "添加代理 DNS，如 https://1.1.1.1/dns-query#🚀 节点选择")
    elif bad_ns:
        item("默认上游（未知 / 国外域名）", False, "代理 DNS 里有国内 / 本机解析器：" + "、".join(bad_ns[:3]), "从代理 DNS 中删除它们，国内 DNS 只放在直连 DNS")
    elif unrouted:
        item("默认上游（未知 / 国外域名）", "warn", "这些代理 DNS 没有指定 #策略组，且未开启 respect-rules，会直连发出：" + "、".join(unrouted[:2]),
             "开启 respect-rules，或在地址后加 #🚀 节点选择")
    else:
        item("默认上游（未知 / 国外域名）", True, "代理 DNS 经节点查询：" + "、".join(dc["proxy"][:2]))
    item("国内域名分流", True if dc["policy"] else "warn",
         "geosite:cn / private → 直连 DNS，其余全部走代理 DNS（不再按 geolocation-!cn 白名单，未知域名也不会发给国内 DNS）"
         if dc["policy"] else "国内域名也走代理 DNS：不泄露，但国内 CDN 解析可能不是最近节点", "开启「国内域名走直连 DNS」")
    item("respect-rules", True if dc["respect_rules"] else "warn",
         "DNS 查询连接遵循分流规则，节点域名用国内 DoH 解析（proxy-server-nameserver）" if dc["respect_rules"] else "未开启",
         "开启 respect-rules")
    item("fallback / 系统 hosts", True, "未使用 fallback（避免同时向国内外 DNS 发同一查询）；use-system-hosts 已关闭；prefer-h3 已关闭")
    lp = [pe["match"] for pe in dc["policies"] if leaky_policy(pe)]
    if lp:
        item("自定义 DNS 策略", False, "以下非国内域名被交给国内 DNS：" + "、".join(lp[:3]), "改为代理 DNS，或删除这些策略")
    item("阻止客户端绕过 DNS", True if dc["block_bypass"] else "warn",
         "已拒绝局域网设备的 DoT / DoQ（853）与常见公共 DoH 服务器" if dc["block_bypass"] else
         "未开启：浏览器 / 手机的“安全 DNS”、私人 DNS 可能直连国内 DoH，绕过 mihomo", "开启「阻止客户端绕过 DNS」")
    mode = d["proxy_mode"]
    if mode == "off":
        item("DNS 劫持", "warn", "透明代理已关闭，客户端 DNS 不经过 mihomo", "在设置里选择 TProxy 或 TUN，并把客户端 DNS 设为旁路由")
    else:
        _, st = sh(TPROXY_SH + " status", timeout=10)
        st = st.strip().splitlines()[-1] if st.strip() else "off"
        okh = st in ("tproxy", "dns") or mode == "tun"
        item("DNS 劫持", True if okh else False, ("TUN dns-hijack any:53" if mode == "tun" else "发往旁路由 53 端口的查询重定向到 1053")
             if okh else "未检测到 53 → 1053 重定向规则", "执行 /opt/mihomo-panel/tproxy.sh apply")
    has6 = bool(re.search(r"inet6 [23]", sh("ip -o -6 addr show scope global 2>/dev/null")[1]))
    if not d.get("ipv6"):
        item("IPv6", "warn" if has6 else True, "本机有公网 IPv6，但 IPv6 透明代理未开启：客户端可能通过主路由下发的 IPv6 DNS（RDNSS）绕过"
             if has6 else "未开启 IPv6，mihomo DNS 不返回 AAAA，与透明代理一致",
             "在主路由关闭 IPv6 DNS 下发 / DHCPv6，或开启 IPv6 透明代理")
    else:
        item("IPv6", True, "IPv6 透明代理已开启，DNS 同时处理 AAAA")
    item("域名嗅探", True if d.get("sniffer", True) else "warn", "已开启：按 IP 发起的连接也能识别域名分流" if d.get("sniffer", True)
         else "未开启：Fake-IP 过滤的域名、直接按 IP 的连接无法按域名分流", "设置 → 核心服务 → 开启域名嗅探")
    rs = resolv_servers()
    item("旁路由本机解析", True if rs else "warn",
         ("/etc/resolv.conf：" + "、".join(rs[:3]) + "。面板自身的外网请求经 mihomo 代理（远端解析），规则测试改用 mihomo DNS，本机只解析国内 / 直连目标")
         if rs else "/etc/resolv.conf 没有 nameserver", "把 /etc/resolv.conf 指向主路由或国内 DNS（如 223.5.5.5）")
    out = {"items": items, "live": None, "fakeip": None}
    if live and core_alive():
        try:
            rc, ips = dns_probe_ip("www.google.com")
            fake = bool(ips) and all(ipaddress.ip_address(i) in ipaddress.ip_network("198.18.0.0/15") for i in ips)
            out["fakeip"] = {"name": "www.google.com", "ips": ips, "rcode": rc, "fake": fake}
            if dc["mode"] == "fake-ip":
                item("客户端查询测试", True if fake else "warn", f"www.google.com → {', '.join(ips) or '无记录'}" +
                     ("（Fake-IP，客户端查询不触发上游解析）" if fake else ""), "检查 Fake-IP 过滤列表是否包含该域名")
        except Exception as e:
            item("客户端查询测试", False, f"向 127.0.0.1:1053 查询失败：{e}", "确认核心 DNS 已监听 1053")
        out["live"] = leak_live()
        lv = out["live"]
        if lv["ok"] is True:
            item("在线泄露检测", True, "上游解析器：" + "、".join(f"{r['ip']}（{r['country'] or '?'} {r['org'][:30]}）" for r in lv["resolvers"][:4]))
        elif lv["ok"] is False:
            cn = [r for r in lv["resolvers"] if r["cn"]]
            item("在线泄露检测", False, "发现国内解析器：" + "、".join(f"{r['ip']}（{r['org'][:30]}）" for r in cn[:4]), "点击「一键应用防泄露设置」")
        else:
            item("在线泄露检测", "warn", lv["error"], "确认节点可用后重试；离线时以上配置检查仍然有效")
    elif live:
        item("在线泄露检测", "warn", "核心未运行，只做了配置检查", "启动核心后重试")
    out["bad"] = sum(1 for x in items if x["ok"] is False)
    out["warn"] = sum(1 for x in items if x["ok"] == "warn")
    return out


# ---------------------------------------------------------------- v5 → v6 升级：保留节点选择
SEL_FILE = os.path.join(PANEL_DIR, "selected.json")


def snapshot_selections(force=False):
    """记录各手动选择组当前选中的节点 / 分组（升级改名前调用）"""
    if os.path.isfile(SEL_FILE) and not force:
        return None
    j = core_json("/proxies", timeout=5)
    if not j:
        return None
    sel = {n: p["now"] for n, p in (j.get("proxies") or {}).items() if p.get("type") == "Selector" and p.get("now") and n != "GLOBAL"}
    write_json(SEL_FILE, sel)
    return sel


def restore_selections():
    """按新名称恢复升级前的选择；返回恢复的组数"""
    sel = read_json(SEL_FILE, None)
    if not sel:
        return 0
    mp = legacy_map()
    proxies = (core_json("/proxies", timeout=5) or {}).get("proxies") or {}
    n = 0
    for g, now in sel.items():
        g2, now2 = mp.get(g, g), mp.get(now, now)
        p = proxies.get(g2) or {}
        if p.get("type") == "Selector" and now2 in (p.get("all") or []) and p.get("now") != now2:
            code, _ = core("PUT", "/proxies/" + quote(g2), {"name": now2})
            n += code < 300
    try:
        os.remove(SEL_FILE)
    except OSError:
        pass
    print(time.strftime("%F %T"), f"[upgrade] 已按新名称恢复 {n} 个策略组的选择", flush=True)
    return n


def startup_migrate():
    """面板升级后首次启动：核心还在跑旧配置（旧组名）时，先记下选择，再生成新配置并恢复选择"""
    for _ in range(30):
        if core_alive():
            break
        time.sleep(2)
    else:
        return
    cur = {} if active_core() == "singbox" else read_json(os.path.join(CONF_DIR, "config.yaml"), None) or {}
    old = set(legacy_map())
    if any(g.get("name") in old for g in cur.get("proxy-groups") or []):
        snapshot_selections()
        ok, msg = reload_core()
        print(time.strftime("%F %T"), "[upgrade] 已按新版策略组重新生成配置：", ok, msg[:120], flush=True)
        time.sleep(1)
    if os.path.isfile(SEL_FILE):
        restore_selections()


# ---------------------------------------------------------------- 登录防爆破
FAILS = {}  # ip -> [失败次数, 解锁时间]


def login_blocked(ip):
    e = FAILS.get(ip)
    if e and e[1] > time.time():
        return int(e[1] - time.time())
    return 0


def login_failed(ip):
    e = FAILS.setdefault(ip, [0, 0])
    if e[1] and e[1] <= time.time():
        e[:] = [0, 0]
    e[0] += 1
    if e[0] >= 5:
        e[1] = time.time() + 600


# ---------------------------------------------------------------- HTTPS
def gen_cert():
    if not sh("command -v openssl")[1]:
        sh("apk add --no-cache openssl", timeout=120)
    os.makedirs(PANEL_DIR, exist_ok=True)
    code, out = sh(f"openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj '/CN=Shunt' "
                   f"-keyout '{KEY}' -out '{CERT}'", timeout=120)
    if code == 0:
        os.chmod(KEY, 0o600)
    return code == 0, out


def https_ready(d):
    return bool(d.get("https")) and os.path.isfile(CERT) and os.path.isfile(KEY)


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        e = sys.exc_info()[1]
        if isinstance(e, (ssl.SSLError, ConnectionError, socket.timeout, BrokenPipeError)):
            return  # 浏览器用 http 访问 https 端口、客户端断开等，静默忽略
        super().handle_error(request, client_address)


def restart_self():
    sh("(sleep 1; %s) >/dev/null 2>&1 &" % os.environ.get("PANEL_RESTART", "rc-service mihomo-panel restart"))


def group_kind(n, custom=()):
    if n in custom:
        return "custom"
    if n == G_SEL:
        return "select"
    if n == G_MANUAL:
        return "manual"
    if n == G_AUTO:
        return "auto"
    if n == G_DIRECT:
        return "direct"
    if n in SIDE_GROUPS:
        return "service"
    if n.startswith(LB_PREFIX) and n.endswith(LB_TAIL):
        return "lb"
    if n.endswith(AUTO_TAIL):
        return "region"
    return "other"


def group_meta(d, cfg):
    cn = {g["name"] for g in d.get("custom_groups") or []}
    meta = {}
    for g in cfg["proxy-groups"]:
        n = g["name"]
        meta[n] = {"kind": group_kind(n, cn), "type": g["type"], "strategy": g.get("strategy", ""), "filter": g.get("filter", ""),
                   "subs": bool(g.get("use")), "icon": g.get("icon", "")}
    return meta


def rename_policy(d, old, new):
    """策略组改名 / 删除（new 为节点选择）时同步更新自定义规则、规则集、其他自定义组、DNS 的引用；返回受影响条目数"""
    return map_refs(d, {old: new}, drop={old} if new == G_SEL else ())


# ---------------------------------------------------------------- 静态资源：gzip + ETag
STATIC = {}
STATIC_TYPES = {"index.html": "text/html", "icon.svg": "image/svg+xml", "icon-180.png": "image/png", "icon-512.png": "image/png"}
MANIFEST = {"name": "Shunt 分流", "short_name": "Shunt", "description": "mihomo 旁路由面板", "start_url": "/", "scope": "/",
            "display": "standalone", "background_color": "#f2f2f7", "theme_color": "#0a84ff",
            "icons": [{"src": "/icon-180.png", "sizes": "180x180", "type": "image/png"},
                      {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"}]}


def static_file(name):
    """返回 (原始, gzip, etag, 类型)；按文件修改时间缓存。图标文件缺失时（旧版面板在线更新上来）从 index.html 内嵌的图标取"""
    path = os.path.join(BASE, name)
    try:
        st = os.stat(path)
        key = (st.st_mtime_ns, st.st_size)
    except OSError:
        if not name.endswith(".png"):
            return None
        idx = static_file("index.html")
        m = re.search(rb'rel="apple-touch-icon" href="data:image/png;base64,([A-Za-z0-9+/=]+)"', idx[0]) if idx else None
        if not m:
            return None
        raw = base64.b64decode(m.group(1))
        return raw, None, '"i%s"' % hashlib.md5(raw).hexdigest()[:16], "image/png"
    c = STATIC.get(name)
    if c and c[0] == key:
        return c[1]
    with open(path, "rb") as f:
        raw = f.read()
    gz = gzip.compress(raw, 6) if not name.endswith(".png") else None
    val = (raw, gz, '"%s"' % hashlib.md5(raw).hexdigest()[:16], STATIC_TYPES.get(name, "application/octet-stream"))
    STATIC[name] = (key, val)
    return val


# ---------------------------------------------------------------- HTTP
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def gzip_ok(self):
        return "gzip" in (self.headers.get("Accept-Encoding") or "")

    def send(self, code, obj, ctype="application/json"):
        body = obj if isinstance(obj, bytes) else json.dumps(obj, ensure_ascii=False).encode()
        zipped = len(body) > 1400 and ctype in ("application/json", "text/html", "text/plain") and self.gzip_ok()
        if zipped:  # 连接列表、节点列表等较大的 JSON 压缩后通常只有 1/5～1/10
            body = gzip.compress(body, 5)
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        if zipped:
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Vary", "Accept-Encoding")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_static(self, name):
        f = static_file(name)
        if not f:
            return self.send(404, {"message": "not found"})
        raw, gz, etag, ctype = f
        if self.headers.get("If-None-Match") == etag:  # 浏览器已有最新版本，不再传输
            self.send_response(304)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            return
        body = gz if gz is not None and self.gzip_ok() else raw
        self.send_response(200)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith("text/") else ""))
        if body is gz:
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Vary", "Accept-Encoding")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("ETag", etag)
        # 页面每次打开都向服务器确认（未变化时只回 304），面板更新后立即生效；图标缓存 1 天
        self.send_header("Cache-Control", "no-cache" if name == "index.html" else "public, max-age=86400")
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0:
            return {}
        if n > MAX_BODY:  # 防止未登录请求（如 /api/login）用超大 body 耗尽路由器内存
            raise ValueError("请求体过大")
        raw = self.rfile.read(n)
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def tok(self):
        return self.headers.get("X-Token") or ""

    def authed(self):
        return sess_ok(self.tok())

    def do_GET(self): self.route("GET")
    def do_POST(self): self.route("POST")
    def do_PUT(self): self.route("PUT")
    def do_DELETE(self): self.route("DELETE")
    def do_PATCH(self): self.route("PATCH")

    def route(self, m):
        u = urlparse(self.path)
        p = u.path
        if m == "GET" and (p in ("/", "/index.html") or p.lstrip("/") in STATIC_TYPES):
            return self.send_static("index.html" if p == "/" else p.lstrip("/"))
        if m == "GET" and p == "/manifest.webmanifest":
            return self.send(200, json.dumps(MANIFEST, ensure_ascii=False).encode(), "application/manifest+json")
        if m == "GET" and p == "/bg":  # 背景图：CSS url() 无法带登录头，只读、不含敏感信息
            try:
                with open(BG_FILE, "rb") as f:
                    raw = f.read()
            except OSError:
                return self.send(404, {"message": "未设置背景图"})
            self.send_response(200)
            self.send_header("Content-Type", bg_type(raw[:16]) or "application/octet-stream")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "public, max-age=31536000, immutable")  # 前端用 ?v=修改时间 刷新
            self.end_headers()
            self.wfile.write(raw)
            return
        if p == "/api/login" and m == "POST":
            ip = self.client_address[0]
            left = login_blocked(ip)
            if left:
                return self.send(429, {"message": f"失败次数过多，请 {left // 60 + 1} 分钟后再试"})
            d = load()
            try:
                bd = self.body()
                pw = str(bd.get("password") or "") if isinstance(bd, dict) else ""
            except ValueError as e:
                return self.send(413, {"message": str(e)})
            if pw_check(pw, d):
                FAILS.pop(ip, None)
                return self.send(200, {"token": sess_new(ip, self.headers.get("User-Agent") or ""),
                                       "must_change": bool(d.get("pw_default"))})
            login_failed(ip)
            n = FAILS[ip][0]
            return self.send(401, {"message": "密码错误" + (f"，还可尝试 {5 - n} 次" if n < 5 else "，已锁定 10 分钟")})
        if not p.startswith("/api/"):
            return self.send(404, {"message": "not found"})
        if p == "/api/logstream" and m == "GET":  # EventSource 无法带自定义头，用 /api/logticket 换来的一次性票据
            qs = parse_qs(u.query)
            if not ticket_use(q1(qs, "ticket")):
                return self.send(401, {"message": "未登录"})
            return self.logstream(q1(qs, "level", default="info"))
        if not self.authed():
            return self.send(401, {"message": "未登录"})
        try:
            return self.api(m, p, u.query)
        except Exception as e:
            return self.send(500, {"message": str(e)})

    def logstream(self, level):
        if level not in ("debug", "info", "warning", "error"):
            level = "info"
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        q, stop = deque(), {}
        ev = threading.Event()

        def sink(line):
            q.append(line)
            ev.set()

        def reader():
            try:
                core_stream(f"/logs?level={level}", sink, stop)
                sink(json.dumps({"type": "warning", "payload": "日志流已结束（mihomo 可能已重启），正在重连…"}))
            except Exception as e:
                sink(json.dumps({"type": "error", "payload": "无法连接 mihomo 日志流：%s" % e}))
            stop["ended"] = True
            ev.set()

        threading.Thread(target=reader, daemon=True).start()
        try:
            while True:
                ev.wait(15)
                ev.clear()
                if not q and not stop.get("ended"):
                    self.wfile.write(b": ping\n\n")  # 心跳，同时探测浏览器是否断开
                while q:
                    self.wfile.write(b"data: " + q.popleft().encode() + b"\n\n")
                self.wfile.flush()
                if stop.get("ended"):
                    break
        except Exception:
            pass
        finally:
            stop["stop"] = True
            try:
                stop["sock"].shutdown(socket.SHUT_RDWR)
            except Exception:
                pass

    def reply(self, ok, msg):
        return self.send(200 if ok else 500, {"message": msg})

    def set_proxy_mode(self, b):
        mode = b.get("mode")
        if mode not in PROXY_MODES:
            return self.send(400, {"message": "代理方式无效"})
        tun_in = b.get("tun") or {}
        if tun_in.get("stack") is not None and tun_in["stack"] not in TUN_STACKS:
            return self.send(400, {"message": "TUN 协议栈只能是 system / gvisor / mixed"})

        def fn(d):
            d["proxy_mode"], d["tproxy"] = mode, mode == "tproxy"
            t = d["tun"]
            for k in ("stack", "auto_redirect", "strict_route"):
                if k in tun_in:
                    t[k] = tun_in[k] if k == "stack" else bool(tun_in[k])
            if "device" in tun_in:
                t["device"] = safe_dev(tun_in["device"])
        prev = update(fn)
        ok, msg = reload_core(prev)  # TUN 开关在配置里，先校验并重载核心
        if not ok:
            return self.send(500, {"message": msg})
        WD["tp_off"] = False
        code, out = sh(TPROXY_SH + " apply")
        label = {"tproxy": "TProxy", "tun": "TUN", "off": "关闭"}[mode]
        note = ""
        if mode == "tun":  # mihomo -t 只做语法校验；TUN 网卡创建失败时核心照常运行，需要单独确认
            err = tun_runtime_error(safe_dev(load()["tun"].get("device")))
            if err and "redirect" in err.lower() and load()["tun"].get("auto_redirect"):
                # auto-redirect 依赖 nftables / iptables，内核不支持时自动关闭后重试一次
                update(lambda d: d["tun"].update(auto_redirect=False))
                ok, msg = reload_core()
                err = tun_runtime_error(safe_dev(load()["tun"].get("device"))) if ok else msg
                note = "（auto-redirect 不可用，已自动关闭）" if not err else ""
            if err:
                return self.send(500, {"message": "配置已生效，但 TUN 启动失败：" + err +
                                       "。可尝试：关闭 auto-redirect、换用 gvisor 协议栈、确认以 root 运行并已加载 tun 模块（modprobe tun）"})
        if code != 0:
            return self.send(500, {"message": f"核心已切换为 {label}，但 nftables 规则处理失败：{out[-200:]}"})
        return self.send(200, {"message": f"代理方式：{label}{note}。" + (out.splitlines()[-1] if out else "")})

    def save_adblock(self, b):
        cur = load()["adblock"]
        lists = []
        seen = set()
        for l in b.get("lists", cur["lists"]):
            url = str(l.get("url") or "").strip()
            name = str(l.get("name") or "").strip()[:40] or (url.split("/")[2] if url.count("/") >= 2 else "")
            if not url.startswith(("http://", "https://")):
                return self.send(400, {"message": f"列表地址无效：{url or '(空)'}"})
            lid = list_id(url)
            if lid in seen:
                continue
            seen.add(lid)
            lists.append({"id": lid, "name": name or lid, "url": url, "enabled": bool(l.get("enabled", True))})
        clean = lambda xs: [x.strip() for x in xs if str(x).strip()][:20000]
        new = {"enabled": bool(b.get("enabled", cur["enabled"])), "lists": lists,
               "black": clean(b.get("black", cur["black"])), "white": clean(b.get("white", cur["white"])),
               "interval": int(b.get("interval", cur["interval"]) or 0), "dns": bool(b.get("dns", cur["dns"]))}
        if new["interval"] not in (0, 21600, 43200, 86400, 259200, 604800):
            return self.send(400, {"message": "更新间隔无效"})
        for key, label in (("black", "黑名单"), ("white", "白名单")):
            bs, be, as_, ae, sk = parse_filter("\n".join(new[key]), plain_suffix=True)
            if sk:
                bad = [x for x in new[key] if not any(parse_filter(x, plain_suffix=True)[:4])]
                return self.send(400, {"message": f"{label}中有无法识别的条目：" + "；".join(bad[:5])})
        prev = update(lambda d: d.update(adblock=new))
        need = [l["id"] for l in lists if l["enabled"] and not os.path.isfile(os.path.join(AB_DIR, l["id"] + ".txt"))]
        ab_compose(load())
        ok, msg = reload_core(prev)
        if not ok:
            ab_compose(load())
            return self.send(500, {"message": msg})
        AB_CACHE.clear()
        if new["enabled"] and need and not AB_STATE["updating"]:
            threading.Thread(target=adblock_update, args=(need,), daemon=True).start()
            return self.send(200, {"message": "已保存，正在下载新增的列表…"})
        return self.send(200, {"message": "已保存并生效"})

    def save_dns(self, b):
        d0 = load()
        cur = dns_cfg(d0)
        if b.get("reset"):
            dc = copy.deepcopy(DNS_DEFAULT)
        elif b.get("preset") == "antileak":
            dc = antileak_dns(cur)
        else:
            dc = dict(cur)
            for k in DNS_LISTS:
                if k in b:
                    if not isinstance(b[k], list):
                        return self.send(400, {"message": f"{k} 应为列表"})
                    dc[k] = [str(x).strip() for x in b[k] if str(x).strip()]
            for k in ("mode", "cache"):
                if k in b:
                    dc[k] = b[k]
            for k in ("policy", "respect_rules", "block_bypass"):
                if k in b:
                    dc[k] = bool(b[k])
            for k in ("hosts", "policies"):
                if k in b:
                    if not isinstance(b[k], list):
                        return self.send(400, {"message": f"{k} 应为列表"})
                    dc[k] = b[k]
        if dc["mode"] not in ("fake-ip", "redir-host"):
            return self.send(400, {"message": "增强模式只能是 fake-ip 或 redir-host"})
        if dc["cache"] not in ("arc", "lru"):
            return self.send(400, {"message": "缓存算法只能是 arc 或 lru"})
        dc = dns_cfg({"dns": dc})
        errs = validate_dns(dc, d0)
        if errs:
            return self.send(400, {"message": "；".join(errs[:5])})
        sniff = b.get("preset") == "antileak" and not d0.get("sniffer", True)

        def fn(d):
            d["dns"] = dc
            if sniff:
                d["sniffer"] = True
        prev = update(fn)
        ok, msg = reload_core(prev)
        if ok and dns_cfg(prev)["block_bypass"] != dc["block_bypass"] and prev.get("proxy_mode") != "off":
            sh(TPROXY_SH + " apply")  # 重新加载 nftables：是否劫持发往任意服务器的 53 端口
        if ok:
            core("POST", "/cache/dns/flush")
            core("POST", "/cache/fakeip/flush") if dc["mode"] == "fake-ip" else None
        done = "已应用防泄露设置" if b.get("preset") == "antileak" else "DNS 设置已生效"
        return self.reply(ok, done if ok else msg)

    def groups_info(self):
        d = load()
        cfg = build_config(d)
        names = [p["name"] for p in cfg["proxies"]]
        plan = region_plan(d, names, list(cfg["proxy-providers"]))
        gnames = [g["name"] for g in cfg["proxy-groups"]]
        meta = group_meta(d, cfg)
        sb = active_core(d) == "singbox"
        if sb:  # sing-box：地区负载均衡并入自动优选，自定义负载均衡 / 故障转移按自动测速运行
            lbs = {lb_name(r) for r, _ in REGIONS + [(G_OTHER, None)]}
            gnames = [g for g in gnames if g not in lbs]
            for n in list(meta):
                if n in lbs:
                    meta.pop(n)
                elif meta[n]["type"] in ("load-balance", "fallback"):
                    meta[n].update(sb_from=meta[n]["type"], type="url-test")
        regions = [{"name": r[0], "total": r[4], "manual": len(r[3]), "unknown": r[5],
                    "groups": [g for g in gnames if g in (auto_name(r[0]), lb_name(r[0]))]} for r in plan]
        sel = next((g.get("proxies") or [] for g in cfg["proxy-groups"] if g["name"] == G_SEL), [])
        if sb:
            sel = [x for x in sel if x in gnames or x in BUILTIN_POLICIES]
        return self.send(200, {"cfg": gcfg(d), "region_groups": d["region_groups"], "custom": d["custom_groups"],
                               "regions": regions, "groups": gnames, "manual": names, "nodes": all_node_names(d),
                               "meta": meta, "core": active_core(d), "types": GROUP_TYPES, "strategies": LB_STRATEGIES,
                               "region_names": [r[0] for r in REGIONS], "primary": PRIMARY_REGIONS, "selector": sel})

    def save_groups_cfg(self, b):
        gc = gcfg(load())
        for k in ("lb", "extra", "other", "lazy"):
            if k in b:
                gc[k] = bool(b[k])
        if "strategy" in b:
            if b["strategy"] not in LB_STRATEGIES:
                return self.send(400, {"message": "负载均衡策略无效"})
            gc["strategy"] = b["strategy"]
        try:
            if "interval" in b:
                gc["interval"] = int(b["interval"])
            if "tolerance" in b:
                gc["tolerance"] = int(b["tolerance"])
        except (TypeError, ValueError):
            return self.send(400, {"message": "测速间隔 / 容差必须是数字"})
        if not 30 <= gc["interval"] <= 86400:
            return self.send(400, {"message": "测速间隔应在 30–86400 秒之间"})
        if not 0 <= gc["tolerance"] <= 1000:
            return self.send(400, {"message": "容差应在 0–1000 ms 之间"})
        if "url" in b:
            u = str(b["url"]).strip()
            if not re.match(r"^https?://\S+$", u):
                return self.send(400, {"message": "测速地址必须是 http(s) 链接"})
            gc["url"] = u

        def fn(d):
            d["groups_cfg"] = gc
            if "region_groups" in b:
                d["region_groups"] = bool(b["region_groups"])
        test = load()
        fn(test)
        errs = validate_groups(test)
        if errs:
            return self.send(400, {"message": "；".join(errs[:3])})
        prev = update(fn)
        ok, msg = reload_core(prev)
        return self.reply(ok, "策略组设置已生效" if ok else msg)

    def save_custom_group(self, b):
        try:
            g = clean_custom_group(b)
        except ValueError as e:
            return self.send(400, {"message": str(e)})
        orig = str(b.get("orig") or "").strip()
        cur = load()
        if orig and not any(x["name"] == orig for x in cur["custom_groups"]):
            return self.send(404, {"message": f"策略组不存在：{orig}"})
        if g["name"] != orig and any(x["name"] == g["name"] for x in cur["custom_groups"]):
            return self.send(400, {"message": f"已存在同名策略组：{g['name']}"})
        info = {"refs": 0}

        def fn(d):
            if orig:
                d["custom_groups"] = [g if x["name"] == orig else x for x in d["custom_groups"]]
                if g["name"] != orig:
                    info["refs"] = rename_policy(d, orig, g["name"])
            else:
                d["custom_groups"].append(g)
        test = copy.deepcopy(cur)
        fn(test)
        errs = validate_groups(test)
        if errs:
            return self.send(400, {"message": "；".join(errs[:3])})
        prev = update(fn)
        ok, msg = reload_core(prev)
        if not ok:
            return self.send(500, {"message": msg})
        extra = f"，已同步更新 {info['refs']} 处引用" if info["refs"] else ""
        return self.send(200, {"message": ("已保存策略组 " if orig else "已创建策略组 ") + g["name"] + extra})

    def delete_custom_group(self, b):
        name = str(b.get("name") or "")
        cur = load()
        if not any(x["name"] == name for x in cur["custom_groups"]):
            return self.send(404, {"message": f"策略组不存在：{name}"})
        users = [x["name"] for x in cur["custom_groups"] if name in x.get("proxies", [])]
        if users and not b.get("force"):
            return self.send(409, {"message": f"「{name}」被其他策略组引用：{'、'.join(users)}。确认删除会同时从这些组中移除它", "users": users})
        info = {"refs": 0}

        def fn(d):
            d["custom_groups"] = [x for x in d["custom_groups"] if x["name"] != name]
            info["refs"] = rename_policy(d, name, G_SEL)
        prev = update(fn)
        ok, msg = reload_core(prev)
        if not ok:
            return self.send(500, {"message": msg})
        extra = f"，{info['refs']} 处引用已改为「{G_SEL}」" if info["refs"] else ""
        return self.send(200, {"message": f"已删除 {name}{extra}"})

    def api(self, m, p, q):
        b = self.body() if m in ("POST", "PUT", "PATCH", "DELETE") else {}
        # 透传到 mihomo external-controller
        if p.startswith("/api/core/") and active_core() == "singbox":
            sub = p[len("/api/core"):]
            if sub == "/providers/proxies" and m == "GET":
                return self.send(200, sb_fake_providers(load()))
            if sub == "/providers/rules" and m == "GET":
                return self.send(200, sb_fake_rule_providers(load()))
            if sub.startswith("/providers/proxies/") and m == "PUT":
                okl, bad = sb_update_subs([unquote(sub.rsplit("/", 1)[1])])
                if not bad:
                    refresh_regions()
                return self.send(204 if not bad else 502, b"" if not bad else {"message": "；".join(bad)})
            if sub.startswith("/providers/proxies/") and sub.endswith("/healthcheck"):
                code, raw = core("GET", f"/group/{quote(G_MANUAL)}/delay?url={quote(HC)}&timeout=5000", timeout=60)
                return self.send(204 if code < 300 else code, b"")
            if (sub.startswith("/providers/rules/") and m == "PUT") or sub == "/configs/geo":
                d = load()
                need = build_singbox(d)[2]
                if sub.startswith("/providers/rules/"):
                    nm = unquote(sub.rsplit("/", 1)[1])
                    need = {k: v for k, v in need.items() if k == nm}
                bad = sb_sync_assets(d, force=True, need=need)
                ok, msg = reload_core()
                return self.send(204 if not bad and ok else 502, b"" if not bad and ok else {"message": "；".join(bad) or msg})
            if sub.startswith("/configs") and m == "PUT":
                return self.reply(*reload_core())
            if sub == "/upgrade":
                return self.send(400, {"message": "请在 设置 → 核心 → 内核更新 里更新 sing-box"})
        if p.startswith("/api/core/"):
            slow = p.endswith("/delay") or p.endswith("/healthcheck")  # 测速可能超过默认 10 秒
            code, raw = core(m, p[len("/api/core"):] + ("?" + q if q else ""), b if b else None, timeout=60 if slow else 10)
            return self.send(code, raw or b"{}")
        if p == "/api/state" and m == "GET":
            d = load()
            _, st = sh(SVC + " status")
            code, ver = core("GET", "/version")
            try:
                version = json.loads(ver).get("version", "-") if code == 200 else "-"
            except Exception:
                version = "-"
            has = bool(d["subs"] or d["nodes"])
            cfg = build_config(d)
            groups = [g["name"] for g in cfg["proxy-groups"]]
            gmeta = group_meta(d, cfg)
            if active_core(d) == "singbox":  # 地区负载均衡并入自动优选；负载均衡 / 故障转移按自动测速运行
                lbs = {lb_name(r) for r, _ in REGIONS + [(G_OTHER, None)]}
                groups = [g for g in groups if g not in lbs]
                for n, mt in list(gmeta.items()):
                    if n in lbs:
                        gmeta.pop(n)
                    elif mt["type"] in ("load-balance", "fallback"):
                        mt.update(sb_from=mt["type"], type="url-test")
            return self.send(200, {"pw_default": bool(d.get("pw_default")), "mode": d["mode"], "tproxy": d["tproxy"], "subs": d["subs"], "rules": d["rules"],
                                   "running": "started" in st or code == 200, "version": version, "groups": groups,
                                   "has_nodes": has, "nodes": [{"name": n["proxy"]["name"], "type": n["proxy"]["type"],
                                                                "server": n["proxy"]["server"], "port": n["proxy"]["port"]} for n in d["nodes"]],
                                   "rulesets": d["rulesets"], "bypass": d["bypass"], "tests": d["tests"],
                                   "sub_interval": d["sub_interval"], "region_groups": d["region_groups"],
                                   "ipv6": d["ipv6"], "https": d["https"], "https_active": isinstance(self.connection, ssl.SSLSocket),
                                   "watchdog": d["watchdog"], "tg_token": d["tg_token"], "tg_chat": d["tg_chat"],
                                   "default_exclude": DEFAULT_EXCLUDE, "proxy_mode": d["proxy_mode"], "tun": d["tun"],
                                   "log_limit": d["log_limit"], "dns": dns_cfg(d), "dns_default": DNS_DEFAULT,
                                   "schedule": d["schedule"], "devices": d["devices"], "adblock_on": d["adblock"]["enabled"],
                                   "sched_events": list(SCHED["events"])[:20], "group_meta": gmeta,
                                   "custom_groups": d["custom_groups"], "groups_cfg": gcfg(d), "sniffer": d["sniffer"],
                                   "gh_proxy": d["gh_proxy"], "panel_version": PANEL_VERSION, "core": active_core(d),
                                   "wd": {"status": WD["status"], "fails": WD["fails"], "last_check": WD["last_check"],
                                          "events": list(WD["events"])[:20]}})
        if p == "/api/groups" and m == "GET":
            return self.groups_info()
        if p == "/api/groups/cfg" and m == "PUT":
            return self.save_groups_cfg(b)
        if p == "/api/groups" and m == "POST":
            return self.save_custom_group(b)
        if p == "/api/groups" and m == "DELETE":
            return self.delete_custom_group(b)
        if p == "/api/groups/preview" and m == "POST":
            flt = str(b.get("filter") or "").strip()
            if not flt:
                return self.send(200, {"matched": [], "total": 0})
            r = rx(flt)
            if r is None:
                return self.send(400, {"message": "正则无效"})
            d = load()
            manual = [n["proxy"]["name"] for n in d["nodes"]]
            allnodes = all_node_names(d) if b.get("subs", True) else manual
            hit = [n for n in allnodes if r.search(n)]
            return self.send(200, {"matched": hit[:200], "total": len(hit), "of": len(allnodes)})
        if p == "/api/groups/refresh" and m == "POST":
            return self.reply(*refresh_regions())
        if p == "/api/config" and m == "GET":
            txt = config_view(load(), masked=True)
            sbm = active_core() == "singbox"
            if "download" in parse_qs(q):
                return self.send(200, txt.encode(), "application/json" if sbm else "application/x-yaml")
            return self.send(200, {"text": txt, "path": core_conf_path(), "size": len(txt.encode()), "core": active_core()})
        if p == "/api/sysopt" and m == "GET":
            return self.send(200, opt_status())
        if p == "/api/sysopt" and m == "POST":
            ids = b.get("ids")
            if not isinstance(ids, list):
                return self.send(400, {"message": "参数错误"})
            ok, msg, errs = opt_apply([str(i) for i in ids])
            return self.send(200, {"ok": ok, "message": msg, "errors": errs} | opt_status())
        if p == "/api/speedtest" and m == "GET":
            via = q1(parse_qs(q), "via", default="proxy")
            return self.send(200, speed_test(via == "proxy"))
        if p == "/api/bg" and m == "GET":
            try:
                return self.send(200, {"exists": True, "v": int(os.path.getmtime(BG_FILE)), "size": os.path.getsize(BG_FILE)})
            except OSError:
                return self.send(200, {"exists": False})
        if p == "/api/bg" and m == "POST":
            ok, msg = bg_save(b.get("data"))
            if not ok:
                return self.send(400, {"message": msg})
            return self.send(200, {"message": msg, "v": int(os.path.getmtime(BG_FILE))})
        if p == "/api/bg" and m == "DELETE":
            try:
                os.remove(BG_FILE)
            except OSError:
                pass
            return self.send(200, {"message": "已移除背景图"})
        if p == "/api/px" and m == "GET":
            px = proxies_merged()
            if px is None:
                return self.send(502, {"message": "核心未运行或无法连接"})
            return self.send(200, {"proxies": px, "retesting": RETEST["pending"]})
        if p == "/api/coreswitch" and m == "GET":
            d = load()
            if active_core(d) == "singbox" and not SB_STATE["warn"]:
                SB_STATE["warn"] = build_singbox(d)[1]
            return self.send(200, {"core": active_core(d), "versions": {"mihomo": bin_version(MIHOMO_BIN), "singbox": sb_version()},
                                   "warn": SB_STATE["warn"] if active_core(d) == "singbox" else [], "busy": CORE_UPD["busy"]})
        if p == "/api/coreswitch" and m == "POST":
            kind = b.get("core")
            if kind not in CORES:
                return self.send(400, {"message": "未知的内核"})
            if kind == active_core():
                return self.send(400, {"message": f"当前已经是 {CORES[kind]}"})
            ok, msg = core_job_start(core_switch_job, kind, load().get("gh_proxy") or "")
            return self.send(200 if ok else 409, {"message": msg})
        if p == "/api/coreupdate" and m == "GET" and (q1(parse_qs(q), "core") or active_core()) == "singbox":
            ch = q1(parse_qs(q), "channel", default="stable")
            info = {"current": sb_version() or "未安装", "arch": sb_arch() or os.uname().machine, "channel": ch,
                    "backup": sb_version(SB_BIN + ".bak"), "remote": "", "busy": CORE_UPD["busy"], "core": "singbox"}
            try:
                info["remote"] = sb_remote_version(ch, load().get("gh_proxy") or "")
            except Exception as e:
                info["message"] = "获取最新版本失败：" + str(e)
                return self.send(502, info)
            info["latest"] = info["remote"] == sb_version()
            return self.send(200, info)
        if p == "/api/coreupdate" and m == "POST" and (b.get("core") or active_core()) == "singbox":
            if b.get("action") == "rollback":
                if not sb_version(SB_BIN + ".bak"):
                    return self.send(400, {"message": "没有可回滚的 sing-box 备份"})
                tmp = SB_BIN + ".swap"
                shutil.copy2(SB_BIN, tmp)
                os.replace(SB_BIN + ".bak", SB_BIN)
                os.replace(tmp, SB_BIN + ".bak")
                if active_core() == "singbox":
                    sh(SVC + " restart", timeout=90)
                return self.reply(True, f"已回滚到 sing-box {sb_version()}")
            ch = b.get("channel") or "stable"
            ok, msg = core_job_start(sb_update_job, ch, load().get("gh_proxy") or "", bool(b.get("force")))
            return self.send(200 if ok else 409, {"message": msg})
        if p == "/api/coreupdate" and m == "GET":
            ch = q1(parse_qs(q), "channel", default="stable")
            if ch not in CORE_CHANNELS:
                return self.send(400, {"message": "未知的更新通道"})
            ok, info = core_check(ch, load().get("gh_proxy") or "")
            info["busy"] = CORE_UPD["busy"]
            return self.send(200 if ok else 502, info)
        if p == "/api/coreupdate/status" and m == "GET":
            return self.send(200, core_upd_status())
        if p == "/api/coreupdate" and m == "POST":
            if b.get("action") == "rollback":
                ok, msg = core_job_start(core_rollback_job)
            else:
                ch = b.get("channel") or "stable"
                if ch not in CORE_CHANNELS:
                    return self.send(400, {"message": "未知的更新通道"})
                ok, msg = core_job_start(core_update_job, ch, load().get("gh_proxy") or "", bool(b.get("force")))
            return self.send(200 if ok else 409, {"message": msg})
        if p == "/api/selfupdate" and m == "GET":
            ok, info = self_update(False, load().get("gh_proxy") or "")
            return self.send(200 if ok else 502, info)
        if p == "/api/selfupdate" and m == "POST":
            if b.get("action") == "rollback":
                return self.reply(*self_rollback())
            ok, info = self_update(True, load().get("gh_proxy") or "")
            return self.send(200 if ok else 500, info)
        if p == "/api/subs/update" and m == "POST":
            name = b.get("name") or ""
            names = [s["name"] for s in load()["subs"]] if not name else [name]
            if active_core() == "singbox":
                okl, bad = sb_update_subs(names)
                ok2, msg2 = refresh_regions()
                msg = ("已更新：" + "；".join(okl) if not bad else "更新失败：" + "；".join(bad)) + ("；" + msg2 if msg2 and "无变化" not in msg2 else "")
                return self.reply(not bad, msg)
            bad = []
            for nm in names:
                code, raw = core("PUT", "/providers/proxies/" + quote(nm), timeout=120)
                if code >= 300:
                    bad.append(nm + "：" + raw.decode(errors="ignore")[:100])
            ok2, msg2 = refresh_regions()
            msg = ("已更新" if not bad else "更新失败：" + "；".join(bad)) + ("；" + msg2 if msg2 and "无变化" not in msg2 else "")
            return self.reply(not bad, msg)
        if p == "/api/delay":
            return self.send(200, delay_test())
        if p == "/api/unlock":
            return self.send(200, unlock_test())
        if p == "/api/stats" and m == "GET":
            return self.send(200, STATS.report() if STATS else {"today": {}, "month": {}, "days": [], "arp": {}})
        if p == "/api/ruletest" and m == "POST":
            return self.send(200, rule_test(b.get("target") or ""))
        if p == "/api/subs" and m == "POST":
            name, url = (b.get("name") or "").strip(), (b.get("url") or "").strip()
            if not name or not url.startswith("http"):
                return self.send(400, {"message": "名称或订阅链接无效"})
            flt, exc = (b.get("filter") or "").strip(), (b["exclude"] if "exclude" in b else DEFAULT_EXCLUDE).strip()
            for pat in (flt, exc):
                try:
                    re.compile(pat)
                except re.error as e:
                    return self.send(400, {"message": f"正则表达式无效：{pat}（{e}）"})
            prev = update(lambda d: d.update(subs=[s for s in d["subs"] if s["name"] != name] +
                                              [{"name": name, "url": url, "filter": flt, "exclude": exc}]))
            if active_core() == "singbox":  # 先由面板下载节点，再生成配置
                okl, bad = sb_update_subs([name])
                ok, msg = reload_core(prev)
                if ok and bad:
                    ok, msg = False, "订阅已保存，但下载失败：" + "；".join(bad)
                return self.reply(ok, msg if not ok else "已添加：" + "；".join(okl))
            ok, msg = reload_core(prev)
            if ok:
                refresh_after_sub(name)  # 订阅下载完成后按实际节点生成地区 / 均衡分组
            return self.reply(ok, msg)
        if p == "/api/subs" and m == "DELETE":
            prev = update(lambda d: d.update(subs=[s for s in d["subs"] if s["name"] != b.get("name")]))
            return self.reply(*reload_core(prev))
        if p == "/api/nodes" and m == "POST":
            d = load()
            added, errs = add_links(b.get("links") or "", d["nodes"], d)
            if not added:
                return self.send(400, {"message": "没有可导入的节点" + ("：\n" + "\n".join(errs) if errs else "")})
            prev = update(lambda d: d["nodes"].extend(added))
            ok, msg = reload_core(prev)
            msg = (f"已导入 {len(added)} 个节点" if ok else msg) + ("；忽略：" + "；".join(errs) if errs else "")
            return self.reply(ok, msg)
        if p == "/api/nodes" and m == "DELETE":
            names = set(b.get("names") or [b.get("name")])
            prev = update(lambda d: d.update(nodes=[n for n in d["nodes"] if n["proxy"]["name"] not in names]))
            return self.reply(*reload_core(prev))
        if p == "/api/rules" and m == "PUT":
            rules = [r.strip() for r in b.get("rules", []) if r.strip()]
            bad = bad_rule_policies([r for r in rules if not r.startswith("#")], load())
            if bad:
                return self.send(400, {"message": "以下规则的策略不存在：" + "；".join(bad[:5])})
            prev = update(lambda d: d.update(rules=rules))
            return self.reply(*reload_core(prev))
        if p == "/api/mode" and m == "PUT":
            mode = b.get("mode")
            if mode not in ("rule", "global", "direct"):
                return self.send(400, {"message": "模式无效"})
            with LOCK:
                d = load()
                d["mode"] = mode
                save(d)
                sb = active_core(d) == "singbox"
                write_active_config(d)
            core("PATCH", "/configs", {"mode": mode.capitalize() if sb else mode})
            if mode == "global":
                fix_global()
            return self.send(200, {"message": "ok"})
        if p == "/api/tproxy" and m == "PUT":  # 兼容旧接口
            return self.set_proxy_mode({"mode": "tproxy" if b.get("enable") else "off"})
        if p == "/api/proxymode" and m == "PUT":
            return self.set_proxy_mode(b)
        if p == "/api/conns" and m == "GET":  # 精简后的连接列表：只保留前端用到的字段
            c = core_json("/connections", timeout=5)
            if c is None:
                return self.send(502, {"message": "mihomo 未运行或无法连接"})
            keep = ("sourceIP", "host", "sniffHost", "destinationIP", "destinationPort", "network")
            out = [{"id": x.get("id"), "start": x.get("start"), "upload": x.get("upload", 0), "download": x.get("download", 0),
                    "rule": x.get("rule"), "rulePayload": x.get("rulePayload"), "chains": x.get("chains"),
                    "metadata": {k: (x.get("metadata") or {}).get(k) for k in keep}} for x in c.get("connections") or []]
            return self.send(200, {"connections": out})
        if p == "/api/live" and m == "GET":
            out = dict(LIVE)
            if time.time() - out["t"] > 5:  # 后台 /traffic 流未就绪（核心刚启动或已停止）时退回连接快照
                c = core_json("/connections", timeout=3)
                out.update(up=0, down=0, upTotal=(c or {}).get("uploadTotal", 0), downTotal=(c or {}).get("downloadTotal", 0))
                out["stale"] = True
            if not out["inuse"]:
                out.update(memory_once())
            out["running"] = time.time() - LIVE["t"] < 5 or bool(out.get("inuse"))
            return self.send(200, out)
        if p == "/api/memory" and m == "GET":
            return self.send(200, {"inuse": LIVE["inuse"], "oslimit": LIVE["oslimit"]} if LIVE["inuse"] else memory_once())
        if p == "/api/logs/info" and m == "GET":
            return self.send(200, {"files": log_sizes(), "limit": load()["log_limit"], "last": LOG_STATE["last"]})
        if p == "/api/logs/clean" and m == "POST":
            freed = log_clean(force=True)
            return self.send(200, {"message": f"已清理，释放 {fmt_size(freed)}", "files": log_sizes()})
        if p == "/api/adblock" and m == "GET":
            d = load()
            meta = ab_meta()
            rep = AD_STATS.report() if AD_STATS else {"today": 0, "top": [], "lists": {}, "days": []}
            lists = [dict(l, **{k: v for k, v in (meta.get(l["id"]) or {}).items()}, hits=rep["lists"].get(l["id"], 0)) for l in d["adblock"]["lists"]]
            prov = (core_json("/providers/rules") or {}).get("providers") or {}
            return self.send(200, {**{k: v for k, v in d["adblock"].items() if k != "lists"}, "lists": lists,
                                   "presets": AB_PRESETS, "stats": rep, "updating": AB_STATE["updating"], "msg": AB_STATE["msg"],
                                   "custom_hits": rep["lists"].get("custom", 0),
                                   "loaded": {k: v.get("ruleCount") for k, v in prov.items() if k.startswith("ad-")}})
        if p == "/api/adblock" and m == "PUT":
            return self.save_adblock(b)
        if p == "/api/adblock/update" and m == "POST":
            if AB_STATE["updating"]:
                return self.send(409, {"message": "正在更新中，请稍候"})
            threading.Thread(target=adblock_update, args=(b.get("ids"),), daemon=True).start()
            return self.send(200, {"message": "已开始下载，完成后自动生效"})
        if p == "/api/adblock/check" and m == "POST":
            return self.send(200, ab_check(b.get("domain") or ""))
        if p == "/api/dns" and m == "PUT":
            return self.save_dns(b)
        if p == "/api/dnsleak" and m == "GET":
            return self.send(200, leak_check(live="nolive" not in parse_qs(q)))
        if p == "/api/history" and m == "GET":
            h = read_json(HISTORY_FILE, [])
            return self.send(200, [{"id": x["id"], "t": x["t"], "changed": x["changed"]} for x in h])
        if p == "/api/history" and m == "POST":
            h = {x["id"]: x for x in read_json(HISTORY_FILE, [])}
            snap = h.get(str(b.get("id") or ""))
            if not snap:
                return self.send(404, {"message": "快照不存在"})

            def apply_snap(d):
                d.update({k: v for k, v in snap["data"].items() if k not in HISTORY_SKIP})
                migrate_names(d)
            prev = update(apply_snap)
            ab_compose(load())
            ok, msg = reload_core(prev)
            if ok:
                sh(TPROXY_SH + " apply")
            return self.reply(ok, ("已恢复到 " + time.strftime("%m-%d %H:%M", time.localtime(snap["t"])) + " 的配置") if ok else msg)
        if p == "/api/dnsquery" and m == "POST":
            name = clean_target(b.get("name") or "")
            qtype = (b.get("type") or "A").upper()
            if not name or qtype not in ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "HTTPS", "SRV", "PTR"):
                return self.send(400, {"message": "请输入域名并选择记录类型"})
            st = time.time()
            code, raw = core("GET", f"/dns/query?name={quote(name)}&type={qtype}", timeout=15)
            ms = int((time.time() - st) * 1000)
            try:
                j = json.loads(raw)
            except Exception:
                j = {"message": raw.decode(errors="ignore")}
            if code != 200:
                return self.send(502 if code == 502 else code, {"message": j.get("message") or "查询失败"})
            return self.send(200, {"name": name, "type": qtype, "ms": ms, "status": j.get("Status"),
                                   "answer": j.get("Answer") or [], "policy": dns_route(name, load())})
        if p == "/api/devices" and m == "GET":
            ips = set(arp_table()) | set(read_leases())
            if STATS:
                with STATS.lock:
                    for b2 in STATS.data["days"].values():
                        ips |= set(b2.get("dev", {}))
            c = core_json("/connections", timeout=5) or {}
            ips |= {(x.get("metadata") or {}).get("sourceIP") for x in c.get("connections") or []}
            return self.send(200, {"map": device_map(sorted(i for i in ips if i)), "custom": load()["devices"]})
        if p == "/api/devices" and m == "PUT":
            devs = {}
            for k, v in (b.get("devices") or {}).items():
                k, v = str(k).strip().lower().replace("-", ":"), str(v).strip()[:40]
                if k and v and (is_ip(k) or re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", k)):
                    devs[k] = v
            update(lambda d: d.update(devices=devs))
            return self.send(200, {"message": f"已保存 {len(devs)} 个设备备注"})
        if p == "/api/diag" and m == "GET":
            return self.send(200, diagnose())
        if p == "/api/schedule" and m == "PUT":
            sc = {}
            for k in ("sub_update", "core_restart", "geo_update"):
                v = str(b.get(k) or "").strip()
                if v and not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", v):
                    return self.send(400, {"message": f"时间格式应为 HH:MM：{v}"})
                sc[k] = v
            sc["latency"] = int(b.get("latency") or 0) if int(b.get("latency") or 0) in (0, 10, 30, 60, 180) else 0
            update(lambda d: d.update(schedule=sc))
            return self.send(200, {"message": "定时任务已保存"})
        if p == "/api/schedule/run" and m == "POST":
            k = b.get("task")
            if k not in TASK_NAMES:
                return self.send(400, {"message": "未知任务"})
            ok, msg = run_task(k)
            sched_event(f"手动执行 {TASK_NAMES[k]}：{'✓' if ok else '✗'} {msg}")
            return self.reply(ok, msg)
        if p == "/api/service" and m == "POST":
            act = b.get("action")
            if act == "reload":
                return self.reply(*reload_core())
            if act in ("restart", "stop", "start"):
                WD["manual_stop"] = act == "stop"
                code, out = sh(SVC + " " + act, timeout=90)
                if act != "stop":
                    retest_soon()
                return self.reply(code == 0, out)
            if act == "upgrade" and active_core() == "singbox":
                return self.send(400, {"message": "请在 设置 → 核心 → 内核更新 里更新 sing-box"})
            if act == "upgrade":
                code, raw = core("POST", "/upgrade", {}, timeout=300)
                return self.send(code if code != 502 else 500, raw or b'{"message":"ok"}')
            if act == "geo" and active_core() == "singbox":
                return self.reply(*run_task("geo_update"))
            if act == "geo":
                code, raw = core("POST", "/configs/geo", {}, timeout=120)
                return self.send(code, raw or b'{"message":"ok"}')
            return self.send(400, {"message": "未知操作"})
        if p == "/api/logs":
            _, out = sh(f"tail -n 300 '{MIHOMO_LOG}'")
            return self.send(200, {"log": out})
        if p == "/api/settings" and m == "PUT":
            allowed = {"rulesets", "bypass", "tests", "sub_interval", "region_groups", "ipv6", "watchdog", "tg_token", "tg_chat",
                       "log_limit", "sniffer", "gh_proxy"}
            if "gh_proxy" in b:
                b["gh_proxy"] = str(b["gh_proxy"] or "").strip()
                if b["gh_proxy"] and not re.match(r"^https?://[\w.\-:]+/?$", b["gh_proxy"]):
                    return self.send(400, {"message": "GitHub 加速地址格式应为 https://ghfast.top/"})
                if b["gh_proxy"] and not b["gh_proxy"].endswith("/"):
                    b["gh_proxy"] += "/"
            if "sniffer" in b:
                b["sniffer"] = bool(b["sniffer"])
            if "log_limit" in b and b["log_limit"] not in (1, 2, 5, 10, 20):
                return self.send(400, {"message": "日志上限只能是 1 / 2 / 5 / 10 / 20 MB"})
            prev = update(lambda d: d.update({k: v for k, v in b.items() if k in allowed}))
            d = load()
            msg = "已保存"
            if set(b) & {"rulesets", "sub_interval", "region_groups", "ipv6", "sniffer"} or ("bypass" in b and d["proxy_mode"] == "tun"):
                ok, msg = reload_core(prev)
                if not ok:
                    return self.send(500, {"message": msg})
            if set(b) & {"bypass", "ipv6"} and d["proxy_mode"] != "off":
                sh(TPROXY_SH + " apply")
            if "watchdog" in b and not b["watchdog"]:
                WD["status"] = "off"
            return self.send(200, {"message": msg})
        if p == "/api/https" and m == "PUT":
            on = bool(b.get("enable"))
            if on and not (os.path.isfile(CERT) and os.path.isfile(KEY)):
                ok, out = gen_cert()
                if not ok:
                    return self.send(500, {"message": "生成证书失败（需要 openssl）：" + out[-200:]})
            update(lambda d: d.update(https=on))
            restart_self()
            return self.send(200, {"message": "面板将以 " + ("HTTPS" if on else "HTTP") + " 重启", "scheme": "https" if on else "http"})
        if p == "/api/tg/test" and m == "POST":
            d = load()
            if "tg_token" in b:
                d.update(tg_token=b.get("tg_token", ""), tg_chat=b.get("tg_chat", ""))
            return self.reply(*tg_send("✅ 测试消息：通知已配置成功", d))
        if p == "/api/backup" and m == "GET":
            d = load()
            return self.send(200, {k: v for k, v in d.items() if k not in ("password", "pw_hash", "pw_default", "secret")})
        if p == "/api/restore" and m == "POST":
            keys = ("mode", "tproxy", "subs", "rules", "rulesets", "bypass", "tests", "sub_interval", "region_groups",
                    "nodes", "ipv6", "watchdog", "tg_token", "tg_chat", "proxy_mode", "tun", "log_limit", "adblock", "dns",
                    "devices", "schedule", "groups_cfg", "custom_groups", "sniffer", "gh_proxy")

            def apply_backup(d):
                d.update({k: b[k] for k in keys if k in b})
                if "proxy_mode" not in b and "tproxy" in b:
                    d["proxy_mode"] = "tproxy" if b["tproxy"] else "off"
                migrate_names(d)  # 旧版备份里的地区组名自动换成新名称
            prev = update(apply_backup)
            ab_compose(load())
            ok, msg = reload_core(prev)
            if ok:
                sh(TPROXY_SH + " apply")
            return self.reply(ok, ("已恢复，" if ok else "") + msg)
        if p == "/api/password" and m == "PUT":
            pw = b.get("password") or ""
            if len(pw) < 4:
                return self.send(400, {"message": "密码至少 4 位"})
            if pw == "admin":
                return self.send(400, {"message": "不能使用默认密码 admin"})
            h = pw_hash(pw)
            update(lambda d: d.update(password="", pw_hash=h, pw_default=False))
            sess_drop(keep=self.tok())  # 改密后其他设备全部下线
            return self.send(200, {"token": self.tok(), "message": "密码已修改，其他设备已退出登录"})
        if p == "/api/logout" and m == "POST":
            if b.get("all"):
                sess_drop()
                return self.send(200, {"message": "所有设备已退出登录"})
            sess_drop(self.tok())
            return self.send(200, {"message": "已退出登录"})
        if p == "/api/logticket" and m == "POST":
            return self.send(200, {"ticket": ticket_new()})
        return self.send(404, {"message": "not found"})


def tp_env():
    """供 tproxy.sh eval：绕过列表、IPv6 开关、本机 IPv6 网段（值均经过正则过滤）"""
    d = load()
    items = [x.strip() for x in d["bypass"] if x.strip()]
    macs = [x.lower().replace("-", ":") for x in items if re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", x)]
    ips, ip6s = [], []
    for x in items:
        try:
            n = ipaddress.ip_network(x, strict=False)
            (ips if n.version == 4 else ip6s).append(str(n))
        except ValueError:
            pass
    local6 = []
    _, out = sh("ip -o -6 addr show scope global 2>/dev/null")
    for m in re.finditer(r"inet6 ([0-9a-fA-F:]+/\d+)", out):
        try:
            local6.append(str(ipaddress.ip_interface(m.group(1)).network))
        except ValueError:
            pass
    return (f"B_IP='{','.join(ips)}'\nB_MAC='{','.join(macs)}'\nB_IP6='{','.join(ip6s)}'\n"
            f"LOCAL6='{','.join(sorted(set(local6)))}'\nIPV6={1 if d.get('ipv6') else 0}\nTPROXY={1 if d.get('tproxy') else 0}\n"
            f"MODE={d['proxy_mode']}\nDNS_ALL={1 if dns_cfg(d)['block_bypass'] else 0}")


if __name__ == "__main__":
    if "--bypass" in sys.argv:  # 兼容旧版 tproxy.sh
        env = dict(l.split("=", 1) for l in tp_env().splitlines())
        print(env["B_IP"].strip("'") + "|" + env["B_MAC"].strip("'"))
        sys.exit(0)
    if "--tpenv" in sys.argv:
        print(tp_env())
        sys.exit(0)
    if "--gen" in sys.argv:  # init.d/mihomo 启动前调用：按当前内核生成配置
        dd = load()
        write_core_file(active_core(dd))
        print(write_active_config(dd))
        sys.exit(0)
    if "--snapshot" in sys.argv:  # install.sh 升级前调用：记下各组当前选择，新配置生效后由面板恢复
        print("saved" if snapshot_selections() is not None else "skip")
        sys.exit(0)
    if "--gen-cert" in sys.argv:
        ok, out = gen_cert()
        print(out)
        sys.exit(0 if ok else 1)
    d = load()
    sess_load()
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))  # 让 finally 有机会保存统计
    STATS = Stats()
    AD_STATS = AdStats()
    for target, args in ((STATS.loop, ()), (monitor_loop, ()), (AD_STATS.loop, ()), (live_loop, ("/traffic",)),
                         (live_loop, ("/memory",)), (log_loop, ()), (sched_loop, ()), (rdns_loop, ()), (startup_migrate, ())):
        threading.Thread(target=target, args=args, daemon=True).start()
    srv = Server(("0.0.0.0", PORT), H)
    scheme = "http"
    if https_ready(d):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT, KEY)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
        scheme = "https"
    print(f"Shunt listening on {scheme}://0.0.0.0:{PORT}", flush=True)
    try:
        srv.serve_forever()
    finally:
        STATS.flush()
        AD_STATS.flush()
