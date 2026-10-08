#!/usr/bin/env python3
"""mihomo-panel: 零依赖的 mihomo 旁路由管理后端 (Alpine Linux)"""
import json, os, sys, signal, time, hashlib, hmac, secrets, subprocess, threading, re, socket, ssl, base64, copy, ipaddress, shutil
import urllib.request, urllib.error, http.client
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
CTRL = f"http://{CTRL_HOST}:{CTRL_PORT}"
MIXED = 7890
WD_INTERVAL = int(os.environ.get("PANEL_WD_INTERVAL", "30"))  # 看门狗检查间隔（秒）
LOCK = threading.Lock()

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
DEFAULT = {"password": "admin", "secret": "", "mode": "rule", "tproxy": True, "subs": [], "rules": [],
           "rulesets": [], "bypass": [], "tests": None, "sub_interval": 86400, "region_groups": True,
           "nodes": [], "ipv6": False, "https": False, "watchdog": True, "tg_token": "", "tg_chat": "",
           "proxy_mode": "", "tun": TUN_DEFAULT, "log_limit": 5, "adblock": AB_DEFAULT, "dns": DNS_DEFAULT,
           "devices": {}, "schedule": SCHED_DEFAULT, "groups_cfg": GROUPS_DEFAULT, "custom_groups": [], "sniffer": True,
           "gh_proxy": "", "schema": 0}
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
PANEL_VERSION = "6.0"
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
    if not d["secret"]:
        d["secret"] = secrets.token_hex(16)
        dirty = True
    if int(d.get("schema") or 0) < SCHEMA:  # v5 → v6：地区组改名（如 🇺🇸 美国 → 🇺🇸 美国自动优选），同步所有引用
        migrate_names(d)
        d["schema"] = SCHEMA
        dirty = True
    if dirty:
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
HISTORY_SKIP = {"password", "secret", "devices", "https", "schema"}
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


def core(method, path, body=None, timeout=10):
    d = load()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(CTRL + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + d["secret"], "Content-Type": "application/json"})
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


# ---------------------------------------------------------------- 面板在线更新
PANEL_RAW = os.environ.get("PANEL_RAW", "https://raw.githubusercontent.com/Skycnhe/mihomo-panel/Hk001")
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
    cfg = build_config(d or load())
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


def token(d):
    return hashlib.sha256((d["password"] + d["secret"]).encode()).hexdigest()


# ---------------------------------------------------------------- Telegram 通知
def tg_send(text, d=None):
    d = d or load()
    if not d.get("tg_token") or not d.get("tg_chat"):
        return False, "未配置 Telegram"
    body = json.dumps({"chat_id": d["tg_chat"], "text": f"[mihomo-panel@{socket.gethostname()}]\n{text}"}).encode()
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
    if load().get("mode") == "direct":
        return
    pg = core_json("/proxies/" + quote(G_AUTO))
    if not pg:
        return
    code, raw = core("GET", f"/group/{quote(G_AUTO)}/delay?url={quote(HC)}&timeout=5000", timeout=30)
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


def check_subs():
    prov = (core_json("/providers/proxies") or {}).get("providers", {})
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
    item("mihomo 核心", alive, json.loads(ver).get("version", "") if alive else "核心未运行或控制器无响应",
         "在顶部点「启动」，或执行 rc-service mihomo restart 并查看 /var/log/mihomo.log")
    cfg = os.path.join(CONF_DIR, "config.yaml")
    if os.path.isfile(MIHOMO_BIN) and os.path.isfile(cfg):
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
    cur = read_json(os.path.join(CONF_DIR, "config.yaml"), None) or {}
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
    code, out = sh(f"openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj '/CN=mihomo-panel' "
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


# ---------------------------------------------------------------- HTTP
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, obj, ctype="application/json"):
        body = obj if isinstance(obj, bytes) else json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        raw = self.rfile.read(n)
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def authed(self, tok=None):
        return hmac.compare_digest(str(tok if tok is not None else self.headers.get("X-Token") or ""), token(load()))

    def do_GET(self): self.route("GET")
    def do_POST(self): self.route("POST")
    def do_PUT(self): self.route("PUT")
    def do_DELETE(self): self.route("DELETE")
    def do_PATCH(self): self.route("PATCH")

    def route(self, m):
        u = urlparse(self.path)
        p = u.path
        if m == "GET" and (p == "/" or p == "/index.html"):
            with open(os.path.join(BASE, "index.html"), "rb") as f:
                return self.send(200, f.read(), "text/html")
        if p == "/api/login" and m == "POST":
            ip = self.client_address[0]
            left = login_blocked(ip)
            if left:
                return self.send(429, {"message": f"失败次数过多，请 {left // 60 + 1} 分钟后再试"})
            d = load()
            if hmac.compare_digest(str(self.body().get("password") or ""), d["password"]):
                FAILS.pop(ip, None)
                return self.send(200, {"token": token(d)})
            login_failed(ip)
            n = FAILS[ip][0]
            return self.send(401, {"message": "密码错误" + (f"，还可尝试 {5 - n} 次" if n < 5 else "，已锁定 10 分钟")})
        if not p.startswith("/api/"):
            return self.send(404, {"message": "not found"})
        if p == "/api/logstream" and m == "GET":  # EventSource 无法带自定义头，此接口单独允许 ?token=
            qs = parse_qs(u.query)
            if not self.authed(q1(qs, "token")):
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
        regions = [{"name": r[0], "total": r[4], "manual": len(r[3]), "unknown": r[5],
                    "groups": [g for g in gnames if g in (auto_name(r[0]), lb_name(r[0]))]} for r in plan]
        sel = next((g.get("proxies") or [] for g in cfg["proxy-groups"] if g["name"] == G_SEL), [])
        return self.send(200, {"cfg": gcfg(d), "region_groups": d["region_groups"], "custom": d["custom_groups"],
                               "regions": regions, "groups": gnames, "manual": names, "nodes": all_node_names(d),
                               "meta": group_meta(d, cfg), "types": GROUP_TYPES, "strategies": LB_STRATEGIES,
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
            return self.send(200, {"mode": d["mode"], "tproxy": d["tproxy"], "subs": d["subs"], "rules": d["rules"],
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
                                   "sched_events": list(SCHED["events"])[:20], "group_meta": group_meta(d, cfg),
                                   "custom_groups": d["custom_groups"], "groups_cfg": gcfg(d), "sniffer": d["sniffer"],
                                   "gh_proxy": d["gh_proxy"], "panel_version": PANEL_VERSION,
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
            if "download" in parse_qs(q):
                return self.send(200, txt.encode(), "application/x-yaml")
            return self.send(200, {"text": txt, "path": os.path.join(CONF_DIR, "config.yaml"), "size": len(txt.encode())})
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
                write_config(d)
            core("PATCH", "/configs", {"mode": mode})
            return self.send(200, {"message": "ok"})
        if p == "/api/tproxy" and m == "PUT":  # 兼容旧接口
            return self.set_proxy_mode({"mode": "tproxy" if b.get("enable") else "off"})
        if p == "/api/proxymode" and m == "PUT":
            return self.set_proxy_mode(b)
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
                return self.reply(code == 0, out)
            if act == "upgrade":
                code, raw = core("POST", "/upgrade", {}, timeout=300)
                return self.send(code if code != 502 else 500, raw or b'{"message":"ok"}')
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
            return self.send(200, {k: v for k, v in d.items() if k not in ("password", "secret")})
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
            update(lambda d: d.update(password=pw))
            return self.send(200, {"token": token(load())})
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
    if "--gen" in sys.argv:
        print(write_config(load()))
        sys.exit(0)
    if "--snapshot" in sys.argv:  # install.sh 升级前调用：记下各组当前选择，新配置生效后由面板恢复
        print("saved" if snapshot_selections() is not None else "skip")
        sys.exit(0)
    if "--gen-cert" in sys.argv:
        ok, out = gen_cert()
        print(out)
        sys.exit(0 if ok else 1)
    d = load()
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
    print(f"mihomo-panel listening on {scheme}://0.0.0.0:{PORT}", flush=True)
    try:
        srv.serve_forever()
    finally:
        STATS.flush()
        AD_STATS.flush()
