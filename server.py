#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shunt 分流: 零依赖的旁路由透明代理管理后端 (Alpine Linux, mihomo / sing-box)

本文件由 tools/build.py 生成，内嵌了 shunt/ 目录下全部模块的源码。请修改 shunt/ 下的文件后重新生成，不要直接改这里。
"""
PANEL_VERSION = "7.4.2"
import importlib.abc, importlib.util, linecache, os, sys, types

_SRC = {}
_SRC['shunt'] = '''"""Shunt 分流面板后端。

设备上运行的是仓库根目录的 server.py：它由 tools/build.py 生成，内嵌了本目录全部模块的源码，所以部署时仍然只有一个文件。
模块之间：引用前面模块的名字直接 from-import；引用后面模块的名字写在各模块末尾的 _link() 里，由 load() 在全部模块加载后调用。
"""
import importlib
import os

# 加载顺序：模块顶层代码只用到排在前面的模块
MODULES = [
    "base",
    "errlog",
    "data",
    "links",
    "groups",
    "mihomo",
    "core",
    "sb_common",
    "sb_yaml",
    "sb_subs",
    "sb_nodes",
    "sb_rules",
    "sb_dns",
    "sb_config",
    "sb_switch",
    "panel_update",
    "core_update",
    "sysopt",
    "notify",
    "latency",
    "stats",
    "unlock",
    "ruletest",
    "logstream",
    "adblock",
    "live",
    "logclean",
    "schedule",
    "devices",
    "diag",
    "dnsleak",
    "migrate",
    "https",
    "access",
    "update_guard",
    "static",
    "webapi",
    "cli",
]
SERVER_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server.py")
_loaded = []


def load(server_file=None):
    """按顺序加载全部模块并绑定模块间的引用；返回模块列表（重复调用直接返回）"""
    global SERVER_FILE
    if _loaded:
        return _loaded
    if server_file:
        SERVER_FILE = server_file
    mods = [importlib.import_module(__name__ + "." + n) for n in MODULES]
    for m in mods:
        if hasattr(m, "_link"):
            m._link()
    _loaded.extend(mods)
    return _loaded


def setvar(name, value):
    """测试 / 调试用：把所有模块里同名的全局变量一起改掉（from-import 让每个模块都有自己的一份引用）"""
    for m in _loaded:
        if name in vars(m):
            setattr(m, name, value)
'''
_SRC['shunt.base'] = '''"""基础常量与通用工具"""
import shunt
import ipaddress
import os, threading, re
import socket
import urllib.error
import urllib.request
from urllib.parse import urlsplit

BASE = os.path.dirname(os.path.abspath(shunt.SERVER_FILE))  # 面板文件所在目录（index.html、tproxy.sh 等）
CONF_DIR = os.environ.get("MIHOMO_DIR", "/etc/mihomo")
DATA_FILE = os.environ.get("PANEL_DATA", "/etc/mihomo-panel/data.json")
PANEL_DIR = os.path.dirname(DATA_FILE)
STATS_FILE = os.path.join(PANEL_DIR, "stats.json")
NOTIFY_FILE = os.path.join(PANEL_DIR, "notify.json")
CERT, KEY = os.path.join(PANEL_DIR, "cert.pem"), os.path.join(PANEL_DIR, "key.pem")
PORT = int(os.environ.get("PANEL_PORT", "8080"))
MIHOMO_BIN = os.environ.get("MIHOMO_BIN", "/usr/local/bin/mihomo")
SMART_BIN = os.environ.get("SMART_BIN", "/usr/local/bin/mihomo-smart")  # vernesong/mihomo：带 Smart 策略组的 mihomo
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
CN_DNS = re.compile(r"(?i)(?:^|[/@\\[])(?:223\\.5\\.5\\.5|223\\.6\\.6\\.6|2400:3200|119\\.29\\.29\\.29|119\\.28\\.28\\.28|182\\.254\\.11[68]\\.116|"
                    r"1\\.12\\.12\\.12|120\\.53\\.53\\.53|2402:4e00|114\\.114\\.11[45]\\.11[45]|180\\.76\\.76\\.76|180\\.184\\.[12]\\.[12]|"
                    r"101\\.226\\.4\\.6|218\\.30\\.118\\.6|117\\.50\\.\\d+\\.\\d+|52\\.80\\.\\d+\\.\\d+|"
                    r"[\\w.-]*(?:alidns\\.com|doh\\.pub|dot\\.pub|dnspod\\.(?:cn|com)|360\\.cn|114dns\\.com|onedns\\.net|baidu\\.com|volces\\.com))(?:[:/#\\]]|$)")
AB_DEFAULT = {"enabled": False, "lists": [], "black": [], "white": [], "interval": 86400, "dns": False}
# 内置预设：按「国内 / 国外 × 视频 / 网页 / 隐私」分组，前端按 cat 分行显示
BM = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/"
AB_PRESETS = [
    {"cat": "国内 · 视频 / App", "name": "秋风广告规则", "url": "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
     "dsc": "国内 App 开屏、视频贴片、广告 SDK"},
    {"cat": "国内 · 视频 / App", "name": "小米电视广告", "url": BM + "AdvertisingMiTV/AdvertisingMiTV.list", "dsc": "小米电视 / 盒子开机与界面广告"},
    {"cat": "国内 · 网页", "name": "anti-AD", "url": "https://anti-ad.net/easylist.txt", "dsc": "国内网页、App 广告综合"},
    {"cat": "国内 · 网页", "name": "AdGuard 中文", "url": "https://filters.adtidy.org/extension/ublock/filters/224.txt", "dsc": "中文网站广告"},
    {"cat": "国内 · 隐私", "name": "隐私追踪 (blackmatrix7)", "url": BM + "Privacy/Privacy.list", "dsc": "统计、埋点、行为追踪"},
    {"cat": "国外 · 视频 / 电视", "name": "Smart-TV", "url": "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt",
     "dsc": "三星 / LG / 索尼等电视界面广告与回传"},
    {"cat": "国外 · 网页", "name": "AdGuard DNS filter", "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
     "dsc": "国外网站、App 广告综合"},
    {"cat": "国外 · 网页", "name": "HaGeZi Multi", "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt",
     "dsc": "广告 + 追踪 + 恶意域名，覆盖更广"},
    {"cat": "国外 · 隐私", "name": "EasyPrivacy", "url": "https://easylist.to/easylist/easyprivacy.txt", "dsc": "国外统计与追踪"},
    {"cat": "国外 · 隐私", "name": "Frogeye 一方追踪", "url": "https://hostfiles.frogeye.fr/firstparty-trackers.txt",
     "dsc": "伪装成网站子域名的追踪器"}]
TUN_DEFAULT = {"stack": "mixed", "device": "Meta", "auto_redirect": True, "strict_route": False}
GROUPS_DEFAULT = {"type": "url-test", "lb": True, "auto": True, "strategy": "consistent-hashing", "interval": 60,
                  "tolerance": 0, "url": "https://www.gstatic.com/generate_204", "extra": True, "other": True, "lazy": True,
                  "lgbm": False}
SCHED_DEFAULT = {"sub_update": "", "core_restart": "", "geo_update": "", "latency": 0}
DEFAULT = {"secret": "", "mode": "rule", "tproxy": True, "subs": [], "rules": [],
           "rulesets": [], "bypass": [], "tests": None, "sub_interval": 86400, "region_groups": True,
           "nodes": [], "ipv6": False, "https": False, "allow_public": False, "allow_hosts": [], "watchdog": True, "tg_token": "", "tg_chat": "",
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
G_MANUAL, G_AUTO, G_DIRECT = "\\U0001F590\\uFE0F 手动选择", "⚡ 全局自动选择", "🏠 直连"
LB_PREFIX, AUTO_TAIL, LB_TAIL = "\\u2696\\uFE0F ", "竞技", "负载均衡"
AUTO_TAIL_OLD = "自动优选"  # v6–v6.7.2 的地区组后缀，v6.7.3 改为「竞技」，仅用于迁移
LEGACY_AUTO = "♻️ 自动选择"  # v5 及以前的名称，读取旧数据时自动迁移
AUTO_ORDER = ["日本", "新加坡", "香港", "美国"]  # 「自动优选」组在节点选择中的顺序，其余地区按识别顺序排在后面
LB_ORDER = ["香港", "日本", "新加坡", "美国"]    # 「负载均衡」组的顺序
SCHEMA = 9
PANEL_VERSION = "7.4.2"
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
LB_STRATEGIES = ("consistent-hashing",)  # v6.7.1 起负载均衡只保留一致性哈希
SIDE_GROUPS = [G_YT, G_GG, G_TG, G_AI, G_NF, G_FINAL]
BUILTIN_POLICIES = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}
HC = "https://www.gstatic.com/generate_204"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"


def url_host_forbidden(url):
    """SSRF 防护：下载类 URL 的目标主机必须解析到公网地址。

    命中以下任一情况返回 True（禁止）：无主机名 / localhost / DNS 解析失败 /
    解析出的任一 IP 不是公网地址（内网、回环、链路本地、保留、组播等）。
    注意：检查与实际建连之间存在 DNS TOCTOU 窗口，这里只防住直接的内网目标。"""
    try:
        host = (urlsplit(url).hostname or "").strip().lower().rstrip(".")
    except Exception:
        return True
    if not host or host == "localhost":
        return True
    try:
        addrs = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return True
    for _, _, _, _, sa in addrs:
        try:
            ip = ipaddress.ip_address(sa[0])
        except ValueError:
            return True
        if not ip.is_global:
            return True
    return False


def dl_check(url):
    """下载入口统一校验：目标非公网地址时抛 IOError（调用方已有通用异常处理）"""
    if url_host_forbidden(url):
        raise IOError(f"目标地址非公网，已拦截（SSRF 防护）：{urlsplit(url).hostname}")


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """跟随重定向前校验目标主机，防止 302 跳到内网（urllib 默认无条件跟随）"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if url_host_forbidden(newurl):
            raise urllib.error.HTTPError(newurl, 403, "重定向目标非公网地址，已拦截（SSRF 防护）", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)
'''
_SRC['shunt.errlog'] = '''"""错误记录：原本被吞掉的异常记到面板日志和「诊断」页"""
import time
from collections import deque

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
        extra = "\\n" + "".join(traceback.format_exception(type(e), e, e.__traceback__))[-1500:]
    print(f"[error] {where}: {msg}{extra}", flush=True)
'''
_SRC['shunt.data'] = '''"""数据"""
import copy, json, os, re, secrets, time

from .base import (
    AUTO_SUFFIX, AUTO_TAIL, AUTO_TAIL_OLD, DATA_FILE, DEFAULT, G_AUTO, G_OTHER, LB_PREFIX, LB_SUFFIX, LB_TAIL, LEGACY_AUTO, LOCK,
    PANEL_DIR, PROXY_MODES, REGIONS, SCHEMA, TESTS
)
OLD_PW_KEYS = ("password", "pw_hash", "pw_default")


def load():
    _fix_legacy_perms()
    key = _data_key()
    if key is not None and _DATA_CACHE.get("key") == key and _DATA_CACHE.get("data") is not None:
        return copy.deepcopy(_DATA_CACHE["data"])
    d = _load_uncached()
    _DATA_CACHE["key"] = key
    _DATA_CACHE["data"] = copy.deepcopy(d)
    return d


def _data_key():
    """data.json 的缓存键：路径 + mtime + 大小。save() 必改 mtime，写后缓存自动失效"""
    try:
        st = os.stat(DATA_FILE)
        return (DATA_FILE, st.st_mtime_ns, st.st_size)
    except OSError:
        return None


_DATA_CACHE = {}


def _fix_legacy_perms():
    """一次性收紧旧版留下的 644 敏感文件（含订阅/节点密码）：只跑一次"""
    global _PERMS_FIXED
    if _PERMS_FIXED:
        return
    _PERMS_FIXED = True
    paths = [HISTORY_FILE, os.path.join(PANEL_DIR, "sub-debug.txt")]
    try:
        paths += [os.path.join(PANEL_DIR, "sb_subs", n) for n in os.listdir(os.path.join(PANEL_DIR, "sb_subs"))
                  if n.endswith(".json")]
    except OSError:
        pass
    for p in paths:
        try:
            if os.path.isfile(p):
                os.chmod(p, 0o600)
        except OSError:
            pass


_PERMS_FIXED = False


def _load_uncached():
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
    if any(k in d for k in OLD_PW_KEYS):  # v6.8.2 起面板不再有密码：清掉旧版留下的密码字段
        for k in OLD_PW_KEYS:
            d.pop(k, None)
        dirty = True
    if not d["secret"]:
        d["secret"] = secrets.token_hex(16)
        dirty = True
    if int(d.get("schema") or 0) < SCHEMA:  # v5 → v6：地区组改名（如 🇺🇸 美国 → 🇺🇸 美国自动优选），同步所有引用
        # 旧版地区负载均衡与未写策略的自定义负载均衡组用的是 groups_cfg.strategy（没保存过 = 当时默认的一致性哈希），保留下来，行为不变
        d["groups_cfg"]["strategy"] = "consistent-hashing"
        gc0 = d["groups_cfg"]  # v6.7.3 竞技：仍是旧默认值（300 秒 / 50 ms）的改为 60 秒 / 0 ms，自己改过的保留
        if int(d.get("schema") or 0) < 9:
            if gc0.get("interval") in (None, 300):
                gc0["interval"] = 60
            if gc0.get("tolerance") in (None, 50):
                gc0["tolerance"] = 0
        migrate_names(d)  # 旧「⚖️ X负载均衡」与 v6.6.9 的「⚖️ X轮询 / 粘性」都改指「⚖️ X哈希」
        for g in d.get("custom_groups") or []:  # 自定义负载均衡组的轮询 / 粘性会话也改为一致性哈希
            if isinstance(g, dict) and g.get("type") == "load-balance":
                g["strategy"] = "consistent-hashing"
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


def auto_name(rname, tail=AUTO_TAIL):
    """「🇯🇵 日本竞技」：url-test，始终选延迟最低的节点"""
    flag, label = region_label(rname)
    return f"{flag} {label}{tail}"


LB_KINDS = (("consistent-hashing", "哈希"),)  # 每个地区一个负载均衡组「⚖️ 日本哈希」
LB_DROPPED = (("round-robin", "轮询"), ("sticky-sessions", "粘性"))  # v6.6.9–v6.7.0 的轮询 / 粘性组，v6.7.1 移除，仅用于迁移
LB_ALL = dict(LB_KINDS + LB_DROPPED)


def lb_name(rname, strategy="consistent-hashing"):
    """「⚖️ 日本哈希」（旧版还有「⚖️ 日本轮询」「⚖️ 日本粘性」）"""
    return LB_PREFIX + region_label(rname)[1] + LB_ALL[strategy]


def lb_names(rname):
    return [lb_name(rname, st) for st, _ in LB_KINDS]


def lb_dropped_names(rname):
    return [lb_name(rname, st) for st, _ in LB_DROPPED]


def lb_old_name(rname):
    """v6.6.8 及以前的单个「⚖️ 日本负载均衡」组"""
    return LB_PREFIX + region_label(rname)[1] + LB_TAIL


def region_lb_set():
    return {n for r, _ in REGIONS + [(G_OTHER, None)] for n in lb_names(r)}


def legacy_map(st=None):
    """旧版策略组名 → 新名称。st：旧版「⚖️ X负载均衡」实际用的策略（存在 groups_cfg.strategy，没保存过就是当时的默认一致性哈希），
    迁移到同策略的组，行为与升级前一致"""
    m = {LEGACY_AUTO: G_AUTO}
    for rname in [r[0] for r in REGIONS] + [G_OTHER]:
        m[rname] = m[rname + AUTO_SUFFIX] = m[auto_name(rname, AUTO_TAIL_OLD)] = auto_name(rname)
        m[rname + LB_SUFFIX] = m[lb_old_name(rname)] = lb_name(rname)  # 只剩一致性哈希
        for n in lb_dropped_names(rname):
            m[n] = lb_name(rname)
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


def migrate_names(d, st=None):
    mp = legacy_map(st if st else (d.get("groups_cfg") or {}).get("strategy"))
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
HISTORY_SKIP = {"core", "secret", "devices", "https", "schema", "sysopt", "sysopt_orig", "sysopt_mods"}
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


def write_json(path, obj, mode=0o600):
    """原子写 JSON。默认 600：经此函数落盘的文件多含订阅/节点等敏感信息，路由器本地非 root 用户不应可读"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".tmp", "w") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.chmod(path + ".tmp", mode)
    os.replace(path + ".tmp", path)


def safe(name):
    return re.sub(r"[^\\w\\-]", "_", name) or "sub"


def _link():
    """全部模块加载后由 shunt.load() 调用：绑定后面模块里定义的名字（模块之间互相调用，放在这里避免循环导入）"""
    global dns_policy_of, rule_policy_index
    from .mihomo import dns_policy_of, rule_policy_index
'''
_SRC['shunt.links'] = '''"""单节点链接解析"""
import base64, json, re
from urllib.parse import parse_qs, unquote, urlsplit

from .base import (
    AUTO_SUFFIX, AUTO_TAIL_OLD, BUILTIN_POLICIES, G_AUTO, G_DIRECT, G_MANUAL, G_OTHER, G_SEL, LB_SUFFIX, LEGACY_AUTO, REGIONS, SIDE_GROUPS
)
from .data import auto_name, lb_dropped_names, lb_names, lb_old_name
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
    m = re.fullmatch(r"\\[([0-9A-Fa-f:.]+)\\]:([\\d,\\-]+)", hp) or re.fullmatch(r"([^:\\[\\]]+):([\\d,\\-]+)", hp)
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


def link_parts(line, first_port=False):
    """URL 形式的链接 → (查询参数, 主机, 端口, 名称, 用户名, 密码)；first_port：端口范围只取第一个"""
    u = urlsplit(line)
    host, port = host_port(u.netloc)
    if first_port:
        port = re.split(r"[,\\-]", port)[0]
    pw = unquote(u.password) if u.password is not None else None
    return parse_qs(u.query), host, port, unquote(u.fragment), unquote(u.username or ""), pw


def parse_vmess(line):
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


def parse_ss(line):
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


def parse_vless(line):
    qs, host, port, name, user, pw = link_parts(line)
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


def parse_trojan(line):
    qs, host, port, name, user, pw = link_parts(line)
    p = {"name": name, "type": "trojan", "server": host, "port": int(port), "password": user, "udp": True}
    common_tls(p, qs, "sni")
    transport(p, q1(qs, "type"), qs)
    return p


def parse_hysteria2(line):
    qs, host, port, name, user, pw = link_parts(line)
    auth = user + (":" + pw if pw is not None else "")
    first = re.split(r"[,\\-]", port)[0]
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


def parse_tuic(line):
    qs, host, port, name, user, pw = link_parts(line)
    p = {"name": name, "type": "tuic", "server": host, "port": int(port), "uuid": user, "password": pw or "",
         "udp": True, "alpn": ["h3"]}
    common_tls(p, qs, "sni")
    p.pop("client-fingerprint", None)
    p["congestion-controller"] = q1(qs, "congestion_control", "congestion-control", default="bbr")
    p["udp-relay-mode"] = q1(qs, "udp_relay_mode", "udp-relay-mode", default="native")
    if truthy(q1(qs, "disable_sni")):
        p["disable-sni"] = True
    return p


def parse_anytls(line):
    qs, host, port, name, user, pw = link_parts(line, first_port=True)
    p = {"name": name, "type": "anytls", "server": host, "port": int(port), "password": user, "udp": True}
    common_tls(p, qs, "sni")
    return p


def parse_hysteria(line):
    qs, host, port, name, user, pw = link_parts(line, first_port=True)
    p = {"name": name, "type": "hysteria", "server": host, "port": int(port), "udp": True,
         "up": q1(qs, "upmbps", "up", default="10"), "down": q1(qs, "downmbps", "down", default="50")}
    auth = q1(qs, "auth", "auth_str") or user
    if auth:
        p["auth-str"] = auth
    if q1(qs, "obfsParam", "obfs-password", "obfs"):
        p["obfs"] = q1(qs, "obfsParam", "obfs-password", "obfs")
    common_tls(p, qs, "sni")
    p.pop("client-fingerprint", None)
    return p


def parse_socks(line):
    qs, host, port, name, user, pw = link_parts(line, first_port=True)
    if pw is None and user and ":" not in user:  # socks://base64(user:pass)@host:port
        try:
            user, _, pw = b64d(user).partition(":")
        except ValueError:
            pass
    p = {"name": name, "type": "socks5", "server": host, "port": int(port), "udp": True}
    if user:
        p["username"], p["password"] = user, pw or ""
    return p


LINK_PARSERS = {"vmess": parse_vmess, "ss": parse_ss, "vless": parse_vless, "trojan": parse_trojan, "hysteria2": parse_hysteria2,
                "hy2": parse_hysteria2, "tuic": parse_tuic, "anytls": parse_anytls, "hysteria": parse_hysteria, "hy": parse_hysteria,
                "socks": parse_socks, "socks5": parse_socks, "socks5h": parse_socks}


def parse_link(line):
    line = line.strip()
    scheme = line.split("://", 1)[0].lower()
    if scheme not in LINK_PARSERS:
        raise ValueError(f"不支持的链接类型 {scheme}://")
    return LINK_PARSERS[scheme](line)


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
        out |= {r, r + LB_SUFFIX, r + AUTO_SUFFIX, auto_name(r), auto_name(r, AUTO_TAIL_OLD), lb_old_name(r), *lb_names(r), *lb_dropped_names(r)}
    if d:
        out |= {g["name"] for g in d.get("custom_groups") or []}
    return out
'''
_SRC['shunt.groups'] = '''"""策略组"""
import os, re, time

from .errlog import log_err
from .base import BUILTIN_POLICIES, GROUPS_DEFAULT, GROUP_TYPES, G_OTHER, PANEL_DIR, PRIMARY_REGIONS, REGIONS
from .data import load, read_json, write_json
from .links import reserved_names
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
            except OSError as e:
                log_err("保存订阅节点列表", e)
    if data is None:
        data = read_json(PROV_FILE, {})
    PROV.update(t=now, data=data)
    return data


def gcfg(d):
    gc = dict(GROUPS_DEFAULT)
    gc.update({k: v for k, v in (d.get("groups_cfg") or {}).items() if k in GROUPS_DEFAULT})
    gc["type"] = "url-test"  # v6：地区「自动优选」组固定为 url-test（旧的地区主组类型设置不再使用）
    gc["strategy"] = "consistent-hashing"  # 只支持一致性哈希
    return gc


def group_opts(t, gc, extra=None):
    """各类型策略组的公共参数"""
    e = extra or {}
    g = {"type": t}
    if t != "select":
        g.update({"url": e.get("url") or gc["url"], "interval": int(e.get("interval") or gc["interval"]), "lazy": bool(gc["lazy"])})
        if t in ("url-test", "smart"):
            g["tolerance"] = int(e.get("tolerance") if e.get("tolerance") not in (None, "") else gc["tolerance"])
        if t == "load-balance":
            g["strategy"] = "consistent-hashing"
        if t == "smart":  # Smart 内核：按延迟 / 丢包 / 速度综合打分，可用 LightGBM 模型预测权重
            g.update({"uselightgbm": bool(gc.get("lgbm")), "collectdata": False})
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


NAME_BAD = re.compile(r"[,#\\n\\r\\t\\"]")


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
    if icon and not re.match(r"^https?://\\S{4,500}$", icon):
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
            g["strategy"] = "consistent-hashing"  # 只支持一致性哈希
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


def _link():
    """全部模块加载后由 shunt.load() 调用：绑定后面模块里定义的名字（模块之间互相调用，放在这里避免循环导入）"""
    global build_config, core_json, active_core, sb_provider_nodes
    from .mihomo import build_config
    from .core import core_json
    from .sb_common import active_core
    from .sb_subs import sb_provider_nodes
'''
_SRC['shunt.mihomo'] = '''"""生成配置"""
import ipaddress, json, os, re

from .base import (
    AUTO_ORDER, BUILTIN_POLICIES, CONF_DIR, CTRL_HOST, CTRL_PORT, DEFAULT_EXCLUDE, DNS_DEFAULT, DNS_LISTS, DOH_DOMAINS, DOH_IPS, G_AI,
    G_AUTO, G_DIRECT, G_FINAL, G_GG, G_MANUAL, G_NF, G_SEL, G_TG, G_YT, HC, LAN_IN, LB_ORDER, MIHOMO_BIN, MIXED, SIDE_GROUPS, SMART_BIN,
    TUN_DEFAULT, TUN_STACKS
)
from .data import LB_KINDS, auto_name, lb_name, region_label, safe
from .groups import clean_custom_group, gcfg, group_opts, region_plan, rx
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
    race = "smart" if active_core(d) == "smart" else "url-test"  # 竞技组：mihomo 用 url-test，Smart 内核用 smart

    def with_src(g, members, src=True):
        if members:
            g["proxies"] = members
        if use and src:
            g["use"] = list(use)
        if not g.get("proxies") and not g.get("use"):
            g["proxies"] = ["COMPATIBLE"]
        return g

    # 地区分组：「<旗> <地区>竞技」(url-test，选延迟最低) + 「⚖️ <地区>哈希」(load-balance，一致性哈希)
    autos, lbs = [], []
    for rname, flt, exc, matched, total, unknown in region_plan(d, names, use):
        label = region_label(rname)[1]
        variants = [(auto_name(rname), race, autos, None)]
        if gc["lb"] and (total >= 2 or unknown):  # 地区有 ≥2 个节点时生成负载均衡组（一致性哈希）
            variants += [(lb_name(rname, st), "load-balance", lbs, {"strategy": st}) for st, _ in LB_KINDS]
        for gname, t, bucket, ex in variants:
            g = with_src(dict({"name": gname}, **group_opts(t, gc, ex)), matched)
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

    # 🚀 节点选择 只包含：各地区竞技 → 各地区负载均衡 → 🖐️ 手动选择 → ⚡ 全局自动选择 → 🏠 直连
    have = bool(use or names)
    direct_g = {"name": G_DIRECT, "type": "select", "proxies": ["DIRECT"]}
    if have:
        groups = [{"name": G_SEL, "type": "select", "proxies": rnames + [G_MANUAL, G_AUTO, G_DIRECT]}] + region_groups + [
            with_src({"name": G_MANUAL, "type": "select"}, names),
            with_src(dict({"name": G_AUTO}, **group_opts(race, gc)), names), direct_g]
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

    dc = dns_cfg(d)
    rule_providers, rules, ab_prov = mihomo_rules(d, policies, dc)
    v6 = bool(d.get("ipv6"))
    dns = mihomo_dns(d, dc, policies, ab_prov)
    hosts = mihomo_hosts(dc)
    tun = mihomo_tun(d)
    extra = {}
    if active_core(d) == "smart" and gcfg(d).get("lgbm"):  # 模型放在 -d 目录（/etc/mihomo/Model.bin），内核每 72 小时自动更新
        gh = (d.get("gh_proxy") or "").rstrip("/")
        extra = {"lgbm-auto-update": True, "lgbm-update-interval": 72, "lgbm-url": (gh + "/" if gh else "") + LGBM_URL}
    return dict(extra, **{
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
    })

def mihomo_rules(d, policies, dc):
    """规则集、TUN 绕过、广告拦截、防绕过 DNS、自定义规则与内置分流规则 → (rule-providers, rules, 广告拦截 providers)"""
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
    return rule_providers, rules, ab_prov


def mihomo_dns(d, dc, policies, ab_prov):
    """dns 段：防泄露布局 + nameserver-policy"""
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
    return dns


def mihomo_hosts(dc):
    hosts = {}
    for h in dc["hosts"]:
        vals = hosts.setdefault(h["domain"], [])
        vals += [v for v in h["value"] if v not in vals]
    hosts = {k: (v[0] if len(v) == 1 else v) for k, v in hosts.items()}
    return hosts


def mihomo_tun(d):
    tc = d.get("tun") or TUN_DEFAULT
    if d.get("proxy_mode") == "tun":
        tun = {"enable": True, "stack": tc.get("stack") if tc.get("stack") in TUN_STACKS else "mixed",
               "device": safe_dev(tc.get("device")), "auto-route": True, "auto-redirect": bool(tc.get("auto_redirect", True)),
               "auto-detect-interface": True, "dns-hijack": ["any:53", "tcp://any:53"],
               "strict-route": bool(tc.get("strict_route", False))}
    else:
        tun = {"enable": False}
    return tun



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
    name = re.sub(r"[^A-Za-z0-9_\\-]", "", str(name or ""))[:15]
    return name or "Meta"


DNS_RX = re.compile(r"^(?:(?:https|tls|quic|udp|tcp|h3)://[^\\s#]+|dhcp://[\\w.\\-]+|system(?:://)?|rcode://\\w+|"
                    r"\\[?[0-9a-fA-F:.]+\\]?(?::\\d+)?)(?:#\\S.*)?$")
HOST_KEY_RX = re.compile(r"^(?:\\+\\.|\\*\\.)?(?:[a-z0-9_*](?:[a-z0-9_\\-*]{0,61}[a-z0-9_*])?\\.)*[a-z0-9_\\-]{1,63}$")
POLICY_DOMAIN_RX = re.compile(r"^(?:\\+\\.|\\*\\.|\\.)?(?:[a-z0-9_*\\-]+\\.)*[a-z0-9_*\\-]+$", re.I)
POLICY_NAME_RX = re.compile(r"^[\\w@!\\-.]+$")


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
            elif key == "default" and not re.match(r"^(?:(?:udp|tcp|tls|https)://)?\\[?[0-9a-fA-F:.]+\\]?(?::\\d+)?(?:/|$)", s):
                errs.append(f"默认 DNS 必须是 IP（用于解析 DoH 域名）：{s}")
            elif key in ("default", "pserver") and dns_policy_of(s):
                errs.append(f"{label} 不能指定 #策略组（解析节点域名本身不能经过节点）：{s}")
            elif dns_policy_of(s) and dns_policy_of(s) not in pol:
                errs.append(f"{label} 引用的策略组不存在：{s}")
    for s in dc.get("fake_filter") or []:
        if not re.match(r"^(?:geosite:|rule-set:)?[\\w*+.\\-!@:]+$", s):
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


def mh_bin(kind=None):
    """mihomo 系内核的程序路径：smart → mihomo-smart，其余 → mihomo"""
    return SMART_BIN if (kind or active_core()) == "smart" else MIHOMO_BIN


def check_config(path, kind=None):
    """用 mihomo -t 校验配置；没有核心程序时跳过"""
    b = mh_bin(kind)
    if not os.path.isfile(b):
        return True, ""
    code, out = sh(f"'{b}' -t -d '{CONF_DIR}' -f '{path}'", timeout=90)
    if code == 0:
        return True, ""
    lines = [l for l in out.splitlines() if "level=error" in l or "level=fatal" in l or "test failed" in l.lower() or l.startswith("panic:")]
    return False, "\\n".join(lines[-3:]) or out[-400:]


def _link():
    """全部模块加载后由 shunt.load() 调用：绑定后面模块里定义的名字（模块之间互相调用，放在这里避免循环导入）"""
    global active_core, LGBM_URL, sh, DOMAIN_RX, adblock_providers
    from .sb_common import active_core
    from .core_update import LGBM_URL
    from .sysopt import sh
    from .adblock import DOMAIN_RX, adblock_providers
'''
_SRC['shunt.core'] = '''"""核心交互"""
import json, os, threading, time, urllib.request, urllib.error

from .base import CONF_DIR, CTRL, DATA_FILE, LOCK, SVC
from .data import load, read_json, save
from .groups import provider_nodes
from .mihomo import build_config, check_config, write_config
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
            try:  # 广告 / 白名单列表改动后，先把对应的 sing-box 规则集文件转换好，否则这些规则会被跳过
                need = {k: v for k, v in build_singbox(d)[2].items() if v.get("kind") == "adblock"}
                if need:
                    sb_sync_assets(d, need=need)
            except Exception as e:
                print("sb adblock sync", e, flush=True)
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
        ok, msg = sb_hot_reload()
        if not ok and prev is not None:  # 配置能通过 sing-box check 但运行时启动失败（如内核缺少模块）：撤销并恢复
            tail = sb_log_error()
            with LOCK:
                save(prev)
                write_sb_config(load(), SB_CONF)
            sh(SVC + " restart", timeout=90)
            return False, "sing-box 启动失败，已撤销本次修改" + ("：" + tail if tail else "")
        return ok, msg
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


def _link():
    """全部模块加载后由 shunt.load() 调用：绑定后面模块里定义的名字（模块之间互相调用，放在这里避免循环导入）"""
    global SB_CONF, active_core, build_singbox, check_sb_config, sb_hot_reload, sb_log_error, sb_sync_assets, write_sb_config
    global sh, WD, core_alive, retest_soon
    from .sb_common import SB_CONF, active_core
    from .sb_config import build_singbox, check_sb_config, sb_hot_reload, sb_log_error, sb_sync_assets, write_sb_config
    from .sysopt import sh
    from .notify import WD, core_alive
    from .latency import retest_soon
'''
_SRC['shunt.sb_common'] = '''"""sing-box 内核"""
import os

from .errlog import log_err
from .base import CONF_DIR, PANEL_DIR
from .data import load
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
CORES = {"mihomo": "mihomo", "smart": "mihomo Smart", "singbox": "sing-box"}
SB_GEO = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo"
SB_REPO = os.environ.get("SB_REPO", "https://github.com/SagerNet/sing-box/releases")
SB_API = os.environ.get("SB_API", "https://api.github.com/repos/SagerNet/sing-box/releases")
SB_UA = ("clash.meta", "v2rayN/6.45")
SB_STATE = {"warn": [], "subs": {}}


def active_core(d=None):
    c = (d or load()).get("core") or "mihomo"
    return c if c in CORES else "mihomo"


def core_conf_path(kind=None):
    return SB_CONF if (kind or active_core()) == "singbox" else os.path.join(CONF_DIR, "config.yaml")


def write_core_file(kind):
    try:
        wfile(CORE_FILE, kind + "\\n")
    except OSError as e:
        log_err("记录当前内核", e)


def _link():
    """全部模块加载后由 shunt.load() 调用：绑定后面模块里定义的名字（模块之间互相调用，放在这里避免循环导入）"""
    global wfile
    from .sysopt import wfile
'''
_SRC['shunt.sb_yaml'] = '''"""极简 YAML 读取（只为解析 Clash 订阅里的 proxies 列表；面板保持零依赖）"""
import json, re
def _y_strip_comment(s):
    q = None
    for i, ch in enumerate(s):
        if q:
            if ch == q and (q == "'" or s[i - 1] != "\\\\"):
                q = None
        elif ch in "'\\"":
            q = ch
        elif ch == "#" and (i == 0 or s[i - 1] in " \\t"):
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
    if re.fullmatch(r"[-+]?\\d+", s) and not (len(s.lstrip("+-")) > 1 and s.lstrip("+-")[0] == "0"):
        return int(s)
    if re.fullmatch(r"[-+]?\\d+\\.\\d+", s):
        return float(s)
    return s


def _y_flow(s, i=0):
    """解析 {..} / [..] 流式集合，返回 (值, 结束位置)"""
    def ws(i):
        while i < len(s) and s[i] in " \\t\\r\\n":
            i += 1
        return i

    def scalar(i, stops):
        i = ws(i)
        if i < len(s) and s[i] in "'\\"":
            q = s[i]
            j = i + 1
            while j < len(s):
                if s[j] == q:
                    if q == "'" and j + 1 < len(s) and s[j + 1] == "'":
                        j += 2
                        continue
                    if q == '"' and s[j - 1] == "\\\\":
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
    for line in text.replace("\\t", "  ").splitlines():
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
        if t[:1] in "'\\"":
            q = t[0]
            j = t.find(q, 1)
            while q == '"' and j > 0 and t[j - 1] == "\\\\":
                j = t.find(q, j + 1)
            if j > 0 and t[j + 1:j + 2] == ":":
                return _y_scalar(t[:j + 1]), t[j + 2:].strip()
            return None
        m = re.match(r"^([^:{}\\[\\],]+?)\\s*:(?:\\s+(.*)|$)", t)
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
                    out[str(k)] = ("\\n" if v.startswith("|") else " ").join(parts)
                else:
                    out[str(k)], i = block(i, lines[i][0])
            else:
                out[str(k)] = None
        return out, i

    if not lines:
        return None
    return block(0, lines[0][0])[0]
'''
_SRC['shunt.sb_subs'] = '''"""订阅：sing-box 不能自己拉取订阅，由面板下载、解析成节点后写进配置"""
import json, os, re, threading, time, urllib.request, urllib.error

from .base import CONF_DIR, DEFAULT_EXCLUDE, PANEL_DIR, dl_check
from .data import load, read_json, safe, write_json
from .links import b64d, parse_link, reserved_names
from .groups import PROV, rx
from .sb_common import SB_SUB_DIR, SB_UA
from .sb_yaml import yaml_lite

_DEBUG_LOCK = threading.Lock()  # sub-debug.txt 并发写保护
def sub_cache_path(name):
    return os.path.join(SB_SUB_DIR, safe(name) + ".json")


def _yaml_full(text):
    try:
        import yaml  # 设备装了 py3-yaml 就用完整解析器
        y = yaml.safe_load(text)
        return y if isinstance(y, dict) else None
    except ImportError:
        return None
    except Exception:
        return None


def _yaml_section(text, key):
    """取出顶层 key: 段落原文（到下一个顶层键为止）"""
    lines = text.replace("\\t", "  ").splitlines()
    out, on = [], False
    for ln in lines:
        top = ln[:1] not in ("", " ", "-", "#")
        if top:
            m = re.match(r"^[\\"']?([^:\\"']+)[\\"']?\\s*:", ln)
            on = bool(m and m.group(1).strip() == key)
            if on:
                out.append(f"{key}:" + ln.split(":", 1)[1])
            continue
        if on:
            out.append(ln)
    return "\\n".join(out) if out else ""


def _yaml_items(sec):
    """整段解析失败时，按列表项逐条解析，坏的跳过"""
    lines = sec.splitlines()[1:]
    ind = next((len(x) - len(x.lstrip(" ")) for x in lines if x.strip().startswith("-")), None)
    if ind is None:
        return []
    items, cur = [], []
    for ln in lines:
        if ln.strip().startswith("-") and len(ln) - len(ln.lstrip(" ")) == ind:
            if cur:
                items.append(cur)
            cur = [ln]
        elif cur:
            cur.append(ln)
    if cur:
        items.append(cur)
    out = []
    for it in items:
        try:
            v = yaml_lite("x:\\n" + "\\n".join(it))
            v = (v or {}).get("x")
            if isinstance(v, list) and v and isinstance(v[0], dict):
                out.append(v[0])
        except Exception:
            pass
    return out


def sub_yaml(text):
    """Clash/mihomo 订阅 → {"proxies": [...], "proxy-providers": {...}}，尽量容错"""
    y = _yaml_full(text)
    if y is not None:
        return {"proxies": y.get("proxies") or [], "proxy-providers": y.get("proxy-providers") or {}}
    res = {"proxies": [], "proxy-providers": {}}
    for key in ("proxies", "proxy-providers"):
        sec = _yaml_section(text, key)
        if not sec:
            continue
        v = None
        try:
            v = (yaml_lite(sec) or {}).get(key)
        except Exception:
            v = None
        if key == "proxies":
            n_items = sum(1 for x in sec.splitlines() if re.match(r"^\\s*-\\s", x))
            if not isinstance(v, list) or len(v) < n_items:
                alt = _yaml_items(sec)
                if len(alt) > len(v if isinstance(v, list) else []):
                    v = alt
            res[key] = v if isinstance(v, list) else []
        else:
            res[key] = v if isinstance(v, dict) else {}
    return res


def parse_sub_text(text, fetch=None, depth=0):
    """订阅内容 → mihomo 风格节点列表。支持 Clash YAML、sing-box JSON、Base64 / 明文分享链接"""
    t = text.strip().lstrip("\\ufeff")
    if t.startswith("{"):
        try:
            j = json.loads(t)
            if isinstance(j.get("outbounds"), list):
                return [{"_sb": o, "name": o.get("tag"), "type": o.get("type")} for o in j["outbounds"]
                        if o.get("type") not in ("selector", "urltest", "direct", "block", "dns") and o.get("tag") and o.get("server")], []
        except ValueError:
            pass
    if re.search(r"(?m)^[\\"']?(proxies|proxy-providers)[\\"']?\\s*:", t):
        y = sub_yaml(t)
        ps = y.get("proxies") if isinstance(y.get("proxies"), list) else []
        out = [p for p in ps if isinstance(p, dict) and p.get("name") and p.get("type")]
        errs = []
        pv = y.get("proxy-providers") if isinstance(y.get("proxy-providers"), dict) else {}
        # 聚合配置：mihomo 自己会去拉 proxy-providers，sing-box 不会，这里由面板逐个下载展开
        for pname, prov in pv.items():
            if not isinstance(prov, dict) or not prov.get("url") or depth > 1 or fetch is None:
                continue
            try:
                sub, e2 = parse_sub_text(fetch(str(prov["url"])), fetch, depth + 1)
                names = {x["name"] for x in out}
                for x in sub:
                    if x["name"] in names:
                        x["name"] = f"{x['name']} [{pname}]"
                    out.append(x)
                errs += e2
            except Exception as e:
                errs.append(f"{pname}：{str(e)[:80]}")
        if out or ps or pv:
            return out, errs
        return [], errs or ["订阅是 mihomo 配置，但没读到 proxies 节点"]
    body = t
    if "://" not in t:
        try:
            body = b64d(re.sub(r"\\s+", "", t))
        except Exception:
            body = ""
    out, errs = [], []
    for i, line in enumerate([x.strip() for x in body.splitlines() if re.match(r"^\\s*[A-Za-z][\\w+.\\-]*://", x)], 1):
        try:
            p = parse_link(line)
            p["name"] = (p.get("name") or f"{p['type']}-{p['server']}:{p['port']}").strip()
            out.append(p)
        except Exception as e:
            errs.append(f"第 {i} 条：{e}")
    return out, errs


def _sub_get(url, ua):
    """下载订阅里嵌套的 proxy-providers 地址：先代理后直连"""
    dl_check(url)  # SSRF 防护：禁止内网目标
    last = None
    for use_proxy in ((True, False) if core_alive() else (False,)):
        req = urllib.request.Request(url, headers={"User-Agent": ua})
        try:
            with proxy_opener(use_proxy).open(req, timeout=30) as r:
                return r.read(20 << 20).decode("utf-8", "ignore")
        except Exception as e:
            last = e
    raise IOError(str(last)[:120])


def sb_fetch_sub(s, gh=""):
    """下载并解析一个订阅，写入缓存；返回 (节点数, 消息)"""
    dl_check(s["url"])  # SSRF 防护：禁止内网目标
    last = ""
    for ua in SB_UA:
        try:
            data = None
            for use_proxy in ((True, False) if core_alive() else (False,)):
                # 每次新建 Request：走代理失败后 urllib 已把代理地址写进 Request，复用会让「直连重试」仍然连到代理
                req = urllib.request.Request(s["url"], headers={"User-Agent": ua})
                try:
                    with proxy_opener(use_proxy).open(req, timeout=30) as r:
                        data = r.read(20 << 20)
                        info = r.headers.get("subscription-userinfo") or ""
                    break
                except Exception as e:
                    last = str(e)[:150]
            if data is None:
                continue
            nodes, errs = parse_sub_text(data.decode("utf-8", "ignore"), lambda u, _ua=ua: _sub_get(u, _ua))
            if not nodes:
                last = "没有解析出节点" + ("：" + errs[0] if errs else "")
                try:  # 留一份原文方便排查（只保留最近一次）；原文含节点密码，600 权限
                    with _DEBUG_LOCK:
                        dbg = os.path.join(PANEL_DIR, "sub-debug.txt")
                        with open(dbg, "wb") as f:
                            f.write(data[:2 << 20])
                        os.chmod(dbg, 0o600)
                except OSError:
                    pass
                # mihomo 已下载过这个订阅时，用它的缓存兜底
                cache = os.path.join(CONF_DIR, "providers", safe(s["name"]) + ".yaml")
                if os.path.isfile(cache):
                    with open(cache, encoding="utf-8", errors="ignore") as f:
                        nodes, errs = parse_sub_text(f.read(), lambda u, _ua=ua: _sub_get(u, _ua))
                if not nodes:
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
    """并发更新订阅：每个订阅一个线程（单个订阅仍串行走 UA/代理/直连回退），整体耗时取决于最慢的一个"""
    d = d or load()
    gh = d.get("gh_proxy") or ""
    subs = [s for s in d["subs"] if not names or s["name"] in names]
    ok, bad = [], []
    res_lock = threading.Lock()

    def one(s):
        try:
            n, msg = sb_fetch_sub(s, gh)
            with res_lock:
                ok.append(f"{s['name']}：{msg}")
        except Exception as e:
            with res_lock:
                bad.append(f"{s['name']}：{e}")

    ths = [threading.Thread(target=one, args=(s,)) for s in subs]
    for t in ths:
        t.start()
    for t in ths:
        t.join(180)
    PROV.update(t=0, data=None)
    return ok, bad


def _link():
    """全部模块加载后由 shunt.load() 调用：绑定后面模块里定义的名字（模块之间互相调用，放在这里避免循环导入）"""
    global proxy_opener, core_alive, fetch
    from .sysopt import proxy_opener
    from .notify import core_alive
    from .unlock import fetch
'''
_SRC['shunt.sb_nodes'] = '''"""节点：mihomo 字段 → sing-box outbound"""
import re
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
        m = re.search(r"[?&]ed=(\\d+)", path)
        if m:
            t["path"] = re.sub(r"[?&]ed=\\d+", "", path) or "/"
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
    m = re.match(r"\\s*(\\d+)", str(v or ""))
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
            opts = [f"mode={po.get('mode', 'websocket')}"] + ([f"host={po['host']}"] if po.get("host") else []) + \\
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
'''
_SRC['shunt.sb_rules'] = '''"""规则：mihomo 规则字符串 → sing-box 路由规则"""
import re

from .mihomo import rule_policy_index
from .sb_common import SB_GEO
def _mh_domain(x):
    """mihomo 域名通配（+.a.com / *.a.com / a.*.com）→ (字段, 值)"""
    x = x.strip().lower()
    if x.startswith("+."):
        return "domain_suffix", x[2:]
    if x.startswith("."):
        return "domain_suffix", x[1:]
    if "*" in x:
        return "domain_regex", "^" + re.escape(x).replace(r"\\*", r"[^.]+") + "$"
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
                if re.fullmatch(r"\\d+", x):
                    ports.append(int(x))
                elif re.fullmatch(r"\\d+-\\d+", x):
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
        m = re.match(r"^(AND|OR|NOT)\\s*,\\s*\\((.*)\\)$", body.strip(), re.I)
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
        needs = typ in ("GEOIP", "IP-CIDR", "IP-CIDR6") and "no-resolve" not in [x.strip().lower() for x in parts[i + 1:]] \\
            and not r.get("ip_is_private")
        return r, needs
'''
_SRC['shunt.sb_dns'] = '''"""DNS"""
import re
from urllib.parse import urlsplit

from .base import DNS_DEFAULT
from .mihomo import dns_cfg, dns_policy_of, fix_dns_policy, is_ip_addr, policy_parts
from .sb_rules import _mh_domain
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


def _link():
    """全部模块加载后由 shunt.load() 调用：绑定后面模块里定义的名字（模块之间互相调用，放在这里避免循环导入）"""
    global ab_sets
    from .adblock import ab_sets
'''
_SRC['shunt.sb_config'] = '''"""生成 sing-box 配置"""
import ipaddress, json, os, re, signal, time, urllib.request, urllib.error

from .base import (
    AB_DIR, BUILTIN_POLICIES, CTRL_HOST, CTRL_PORT, G_OTHER, G_SEL, MIHOMO_LOG, MIXED, REGIONS, SVC, TUN_DEFAULT, TUN_STACKS, UA,
    dl_check,
)
from .data import auto_name, lb_dropped_names, lb_names, lb_old_name, load, safe, write_json
from .groups import PROV, gcfg, rx
from .mihomo import build_config, dns_cfg, safe_dev, write_config
from .core import core_json
from .sb_common import CORE_PID, SB_BIN, SB_CONF, SB_DIR, SB_RULE_DIR, SB_STATE, active_core
from .sb_yaml import yaml_lite
from .sb_subs import sb_provider_nodes, sb_sub_cache, sb_sub_outbounds
from .sb_nodes import sb_outbound
from .sb_rules import SBRules, _mh_domain
from .sb_dns import sb_dns
def build_singbox(d):
    """把 build_config 生成的 mihomo 结构翻译成 sing-box 配置；返回 (配置, 警告列表, 需要的规则集文件)"""
    sub_out = sb_sub_outbounds(d)
    PROV.update(t=time.time(), data={k: [n for n, _ in v] for k, v in sub_out.items()})
    cfg = build_config(d)
    v6 = bool(d.get("ipv6"))
    gc = gcfg(d)
    warn = []
    outbounds, node_names, prov_names = sb_node_outbounds(d, cfg, sub_out, warn)
    alias, group_outs = sb_group_outbounds(cfg, gc, node_names, prov_names, warn)
    outbounds += group_outs
    group_out = [o for o in outbounds if o["type"] in ("selector", "urltest")]
    outbounds = group_out + [o for o in outbounds if o["type"] not in ("selector", "urltest")] + [{"type": "direct", "tag": "DIRECT"}]
    policies = {o["tag"] for o in outbounds} | BUILTIN_POLICIES
    inbounds = sb_inbounds(d, v6)
    in_tags = {i["tag"] for i in inbounds}
    rule_sets = sb_rule_sets(cfg, warn)
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
    defs, missing = sb_rule_set_defs(rule_sets, warn)
    route_rules = sb_prune_rules(route_rules, missing)
    dns["rules"] = sb_prune_rules(dns["rules"], missing)
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


def sb_node_outbounds(d, cfg, sub_out, warn):
    """手动节点与订阅节点 → (outbounds, 手动节点名, {订阅名: 节点名列表})"""
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
    return outbounds, node_names, prov_names


def sb_group_outbounds(cfg, gc, node_names, prov_names, warn):
    """策略组：地区负载均衡与自动优选相同 → 去掉并重定向引用；其余 load-balance / fallback 改为 urltest。返回 (别名表, 组 outbounds)"""
    outbounds = []
    alias = {}
    region_lb = set()
    for r, _ in REGIONS + [(G_OTHER, None)]:
        for n in lb_names(r) + lb_dropped_names(r) + [lb_old_name(r)]:
            alias[n] = auto_name(r)
            region_lb.add(n)
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
    return alias, outbounds


def sb_inbounds(d, v6):
    lis = "::" if v6 else "0.0.0.0"
    inbounds = [{"type": "mixed", "tag": "mixed-in", "listen": lis, "listen_port": MIXED},
                {"type": "direct", "tag": "dns-in", "listen": lis, "listen_port": 1053}]
    if d.get("proxy_mode") == "tproxy":  # 透明代理（tproxy.sh 把流量转到 7893）
        inbounds.insert(1, {"type": "tproxy", "tag": "tproxy-in", "listen": lis, "listen_port": 7893})
    tc = d.get("tun") or TUN_DEFAULT
    if d.get("proxy_mode") == "tun":
        tun = {"type": "tun", "tag": "tun-in", "interface_name": safe_dev(tc.get("device")), "address": ["172.19.0.1/30"] + (["fdfe:dcba:9876::1/126"] if v6 else []),
               "auto_route": True, "auto_redirect": bool(tc.get("auto_redirect", True)) and nft_ok(), "strict_route": bool(tc.get("strict_route", False)),
               "stack": tc.get("stack") if tc.get("stack") in TUN_STACKS else "mixed"}
        inbounds.append(tun)
    return inbounds


def sb_rule_sets(cfg, warn):
    """mihomo rule-providers → sing-box 规则集描述（inline / 广告拦截 / srs / 需要转换）"""
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
            if re.search(r"\\.srs(?:\\?|$)", url):
                rule_sets[name] = {"kind": "srs", "url": url, "path": f"rs-{safe(name)}.srs"}
            elif prov.get("format") == "mrs" and "meta-rules-dat" in url and "/meta/" in url:
                rule_sets[name] = {"kind": "srs", "url": re.sub(r"\\.mrs(\\?|$)", r".srs\\1", url.replace("/meta/", "/sing/")),
                                   "path": f"rs-{safe(name)}.srs"}
            elif prov.get("format") == "mrs":
                warn.append(f"规则集「{name}」是 mihomo 专用的 .mrs 格式，sing-box 无法使用，已跳过（可改用 .srs 地址）")
            else:
                rule_sets[name] = {"kind": "convert", "url": url, "behavior": prov.get("behavior", "domain"),
                                   "format": prov.get("format", "yaml"), "path": f"rs-{safe(name)}.json"}
    return rule_sets


def sb_rule_set_defs(rule_sets, warn):
    """规则集定义：只保留本地已有文件的（缺失的规则及引用跳过，避免启动失败）"""
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
    return defs, missing


def sb_prune_rules(lst, missing):
    """去掉引用了缺失规则集的规则（逻辑规则里有一条缺失就整条去掉）"""
    out = []
    for r in lst:
        r = dict(r)
        if r.get("type") == "logical":
            subs = sb_prune_rules(r["rules"], missing)
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


def _rule_lines_to_source(text, behavior, fmt):
    """mihomo 规则集文本（yaml payload / text）→ sing-box source 规则集"""
    t = text.strip()
    items = []
    if fmt == "yaml" or re.search(r"(?m)^payload\\s*:", t):
        y = yaml_lite(t)
        items = [str(x) for x in ((y or {}).get("payload") or [])] if isinstance(y, dict) else []
    else:
        items = [l.strip() for l in t.splitlines() if l.strip() and not l.strip().startswith(("#", "//"))]
    r = {}
    tr = SBRules({}, set(), {}, {})
    for x in items:
        x = x.strip().strip("'\\"")
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


def sb_rule_count(path):
    """sing-box source 规则集里的条目数（广告拦截页显示「已加载」用；sing-box 的 clash_api 不提供规则集信息）"""
    try:
        with open(path) as f:
            j = json.load(f)
    except (OSError, ValueError):
        return None
    return sum(len(v) for r in j.get("rules") or [] if isinstance(r, dict) for v in r.values() if isinstance(v, list))


def sb_ab_loaded(d):
    """{"ad-xxx": 条目数}：只统计配置里实际引用、且已转换好的广告拦截规则集"""
    out = {}
    for tag, rsd in build_singbox(d)[2].items():
        if rsd.get("kind") == "adblock":
            path = os.path.join(SB_RULE_DIR, rsd["path"])
            if os.path.isfile(path) and os.path.getsize(path) > 0:
                out[tag] = sb_rule_count(path)
    return out


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
                try:
                    dl_check(u)  # SSRF 防护：禁止内网目标
                except IOError as e:
                    err = str(e)[:120]
                    continue
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
    return False, "\\n".join(lines[-3:]) or out[-400:]


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


def sb_log_error():
    """sing-box 日志里最后一条 FATAL / ERROR"""
    try:
        with open(MIHOMO_LOG, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 16 * 1024))
            lines = f.read().decode("utf-8", "ignore").splitlines()
    except OSError:
        return ""
    for line in reversed(lines):
        if "FATAL" in line or " ERROR " in line:
            return re.sub(r"^(\\S+\\s+){0,3}(FATAL|ERROR)(\\[\\d+\\])?\\s*", "", line.strip())[-200:]
    return ""


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
    m = re.search(r"sing-box version (\\S+)", out) if code == 0 else None
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


def _link():
    """全部模块加载后由 shunt.load() 调用：绑定后面模块里定义的名字（模块之间互相调用，放在这里避免循环导入）"""
    global nft_ok, proxy_opener, sh, core_alive
    from .sysopt import nft_ok, proxy_opener, sh
    from .notify import core_alive
'''
_SRC['shunt.sb_switch'] = '''"""内核切换"""
import hashlib, io, json, os, re, shutil, threading, time

from .base import CONF_DIR, MIHOMO_LOG, SMART_BIN, SVC
from .data import load, update
from .groups import PROV, gcfg
from .mihomo import check_config, mh_bin, write_config
from .sb_common import CORES, SB_API, SB_BIN, SB_CONF, SB_REPO, SB_STATE, active_core, write_core_file
from .sb_subs import sb_update_subs
from .sb_config import check_sb_config, sb_sync_assets, sb_version, write_sb_config
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
        m = re.search(r"/tag/v?([\\w.\\-]+)", r.geturl())
    if not m:
        raise IOError("获取 sing-box 版本号失败")
    return m.group(1)


def is_musl():
    import glob
    return bool(glob.glob("/lib/ld-musl-*")) or os.path.isfile("/etc/alpine-release")


def sb_fetch(url, gh, digest=""):
    if not digest:
        gh = ""  # 没有校验值时不走第三方镜像
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
    if total and n < total:
        raise ValueError(f"下载不完整 {n}/{total}")
    if digest and hashlib.sha256(buf.getbuffer()).hexdigest() != digest:
        raise ValueError("SHA256 与 GitHub 不一致（可能被加速镜像篡改）")
    buf.seek(0)
    return buf


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
    # 1.14 起普通 linux 包依赖 glibc，Alpine(musl) 上跑不起来，优先下 -musl 版
    variants = ["-musl", "", "-glibc"] if is_musl() else ["", "-glibc", "-musl"]
    tmp, errs, nv = SB_BIN + ".new", [], ""
    for v in variants:
        name = f"sing-box-{ver}-linux-{arch}{v}.tar.gz"
        _cu("下载", 10, f"下载 {name}")
        try:
            buf = sb_fetch(f"{SB_REPO}/download/v{ver}/{name}", gh, release_digest(SB_REPO, "v" + ver, name))
            with tarfile.open(fileobj=buf, mode="r:gz") as tf:
                mem = next((m for m in tf.getmembers() if m.isfile() and os.path.basename(m.name) == "sing-box"), None)
                if not mem:
                    raise ValueError("压缩包里没有 sing-box 程序")
                with tf.extractfile(mem) as src, open(tmp, "wb") as f:
                    shutil.copyfileobj(src, f)
        except Exception as e:
            errs.append(f"{name}: {str(e)[:100]}")
            continue
        os.chmod(tmp, 0o755)
        nv = sb_version(tmp)
        if nv:
            break
        _, out = sh(f"'{tmp}' version", timeout=15)
        errs.append(f"{name}: 无法运行 {out.strip()[:100]}")
        os.remove(tmp)
    if not nv:
        raise ValueError("下载的 sing-box 无法运行（架构不匹配或文件损坏）：" + "；".join(errs))
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
            if kind == "smart" and not bin_version(SMART_BIN):
                _cu("安装 Smart 内核", 5, "设备上还没有 mihomo Smart，正在从 vernesong/mihomo 下载")
                tmp = mh_fetch("smart", "alpha", gh, lambda pc: CORE_UPD.update(pct=5 + int(55 * pc)))[0]
                os.replace(tmp, SMART_BIN)
                _cu("安装 Smart 内核", 62, f"已安装 {bin_version(SMART_BIN)}")
            if not bin_version(mh_bin(kind)):
                raise ValueError(f"设备上没有可用的 {label} 程序，请先在「内核更新」里安装")
            d = dict(load(), core=kind)  # 按目标内核生成（Smart：竞技组改为 smart 类型）
            if kind == "smart" and gcfg(d)["lgbm"] and not os.path.isfile(LGBM_FILE):
                _cu("LightGBM 模型", 64, "下载 LightGBM 模型 Model.bin")
                try:
                    lgbm_fetch(gh)
                except Exception as e:
                    _cu("LightGBM 模型", None, "✗ 模型下载失败，Smart 组先用内置算法：" + str(e)[:120])
            tmp = write_config(d, os.path.join(CONF_DIR, "config.yaml.new"))
            ok, err = check_config(tmp, kind)
            if not ok:
                os.remove(tmp)
                raise ValueError(f"{label} 配置校验失败，未切换：" + err)
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
            log = re.sub(r"\\x1b\\[[0-9;]*m", "", "\\n".join(tail[-3:]))[-400:]
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


def _link():
    """全部模块加载后由 shunt.load() 调用：绑定后面模块里定义的名字（模块之间互相调用，放在这里避免循环导入）"""
    global CORE_UPD, LGBM_FILE, _cu, bin_version, lgbm_fetch, mh_fetch, open_url, release_digest
    global sh, WD, core_alive, notify, restore_selections, snapshot_selections
    from .core_update import CORE_UPD, LGBM_FILE, _cu, bin_version, lgbm_fetch, mh_fetch, open_url, release_digest
    from .sysopt import sh
    from .notify import WD, core_alive, notify
    from .migrate import restore_selections, snapshot_selections
'''
_SRC['shunt.panel_update'] = '''"""面板在线更新"""
import hashlib, json, os, re, shutil, time, urllib.request, urllib.error

from .errlog import log_err
from .base import BASE, PANEL_VERSION, UA, dl_check
PANEL_RAW = os.environ.get("PANEL_RAW", "https://raw.githubusercontent.com/Skycnhe/Shunt/Hk001")
UPD_FILES = ["server.py", "index.html", "tproxy.sh", "selftest.sh", "init.d/mihomo", "init.d/mihomo-panel"]
UPD_STATE = {"busy": False}
UPD_LIST = "update-files.txt"  # 仓库里的部署文件清单：以后增减文件只改清单，不用再改更新程序


def remote_file_list(gh, commit, shas):
    """读取仓库里的部署文件清单（必须通过 GitHub 校验）；没有或拿不到校验值时用内置列表"""
    if not shas or UPD_LIST not in shas:
        return list(UPD_FILES)
    raw = fetch_raw(UPD_LIST, gh, commit, shas[UPD_LIST]).decode("utf-8", "replace")
    out = []
    for ln in raw.splitlines():
        f = ln.split("#", 1)[0].strip()
        if not f:
            continue
        if not re.fullmatch(r"[\\w.\\-]+(/[\\w.\\-]+)*", f) or ".." in f.split("/") or f.startswith("."):
            raise ValueError(f"部署清单里有不安全的路径：{f}")
        if f not in shas:
            raise ValueError(f"部署清单里的 {f} 在仓库中不存在")
        out.append(f)
    for need in ("server.py", "index.html"):
        if need not in out:
            raise ValueError(f"部署清单缺少 {need}")
    return out


def local_file(f):
    if f.startswith("init.d/"):
        sysf = "/etc/init.d/" + f[7:]
        return sysf if BASE == "/opt/mihomo-panel" and os.path.isfile(sysf) else os.path.join(BASE, f)
    return os.path.join(BASE, f)


def gh_api(path, timeout=15):
    """直连或经 mihomo 代理访问 GitHub API（绝不走第三方加速镜像：校验值必须来自 GitHub 本身）"""
    with open_url("https://api.github.com" + path, "", timeout=timeout) as r:
        return json.loads(r.read(8 << 20))


def panel_manifest():
    """返回 (commit, {路径: git blob sha1})；失败返回 (None, {})"""
    m = re.match(r"https://raw\\.githubusercontent\\.com/([^/]+/[^/]+)/(.+?)/?$", PANEL_RAW)
    if not m:
        return None, {}
    try:
        c = gh_api(f"/repos/{m.group(1)}/commits/{m.group(2)}")
        t = gh_api(f"/repos/{m.group(1)}/git/trees/{c['commit']['tree']['sha']}?recursive=1")
        return c["sha"], {x["path"]: x["sha"] for x in t.get("tree", []) if x.get("type") == "blob"}
    except Exception as e:
        log_err("获取面板校验值", e)
        return None, {}


def git_blob_sha(data):
    return hashlib.sha1(b"blob %d\\0" % len(data) + data).hexdigest()


def fetch_raw(f, gh, commit=None, sha=None):
    """下载面板文件。有 GitHub 给的校验值时可以走加速镜像，下载后逐个比对；没有校验值时不走镜像"""
    base = PANEL_RAW.rstrip("/")
    if commit:
        base = base.rsplit("/", 1)[0] + "/" + commit
    url = base + "/" + f
    if not sha:
        gh = ""
    tries = [(gh.rstrip("/") + "/" + url, False)] if gh else []
    tries += [(url, True), (url, False)]  # 先经 mihomo 代理，再直连
    err = ""
    for u, use_proxy in tries:
        try:
            dl_check(u)  # SSRF 防护：禁止内网目标
            req = urllib.request.Request(u + ("&" if "?" in u else "?") + "t=" + str(int(time.time())), headers={"User-Agent": UA})
            with proxy_opener(use_proxy).open(req, timeout=20) as r:
                data = r.read(4 << 20)
            if sha and git_blob_sha(data) != sha:
                raise ValueError("文件校验失败（与 GitHub 上的不一致，可能被加速镜像篡改）")
            return data
        except Exception as e:
            err = f"{u.split('/')[2]}{'(代理)' if use_proxy else ''}: {str(e)[:120]}"
    raise IOError(f"下载 {f} 失败：{err}")


def self_rollback():
    """把 .backup 里的文件（上次更新前的版本）全部放回去"""
    bak = os.path.join(BASE, ".backup")
    if not os.path.isfile(os.path.join(bak, "server.py")):
        return False, "没有可回滚的备份"
    for root, _, names in os.walk(bak):
        for n in names:
            src = os.path.join(root, n)
            shutil.copy2(src, local_file(os.path.relpath(src, bak)))
    restart_self()
    return True, "已回滚到更新前的版本，面板正在重启"


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
        commit, shas = panel_manifest()
        flist = remote_file_list(gh, commit, shas)
        for f in flist:
            data = fetch_raw(f, gh, commit, shas.get(f))
            files[f] = data
            try:
                with open(local_file(f), "rb") as fh:
                    same = fh.read() == data
            except OSError:
                same = False
            if not same:
                changed.append(f)
        info = {"current": PANEL_VERSION, "remote": remote_version(files["server.py"]), "changed": changed,
                "source": PANEL_RAW, "verified": bool(shas), "commit": (commit or "")[:10]}
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
        for f, data in files.items():
            os.makedirs(os.path.dirname(os.path.join(tmpd, f)), exist_ok=True)
            with open(os.path.join(tmpd, f), "wb") as fh:
                fh.write(data)
            if f.endswith(".sh") or f.startswith("init.d/"):
                code, out = sh(f"sh -n '{os.path.join(tmpd, f)}'")
                if code != 0:
                    raise ValueError(f"新版 {f} 语法错误：{out[-200:]}")
        bak = os.path.join(BASE, ".backup")
        shutil.rmtree(bak, ignore_errors=True)
        os.makedirs(bak)
        for f in flist:
            if os.path.isfile(local_file(f)):
                os.makedirs(os.path.dirname(os.path.join(bak, f)), exist_ok=True)
                shutil.copy2(local_file(f), os.path.join(bak, f))
        for f in changed:
            dst = local_file(f)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(os.path.join(tmpd, f), dst + ".new")
            os.chmod(dst + ".new", 0o755 if (f.endswith(".sh") or f.startswith("init.d/")) else 0o644)
            os.replace(dst + ".new", dst)
        shutil.rmtree(tmpd, ignore_errors=True)
        start_update_guard(flist)
        restart_self()
        info["message"] = (f"已更新 {len(changed)} 个文件（{'、'.join(changed)}）" + ("，已通过 GitHub 校验" if shas else "")
                           + "，面板正在重启；新版启动失败会在 90 秒内自动回滚")
        return True, info
    except Exception as e:
        return False, {"message": str(e)}
    finally:
        UPD_STATE["busy"] = False


def _link():
    """全部模块加载后由 shunt.load() 调用：绑定后面模块里定义的名字（模块之间互相调用，放在这里避免循环导入）"""
    global open_url, proxy_opener, sh, restart_self, start_update_guard
    from .core_update import open_url
    from .sysopt import proxy_opener, sh
    from .https import restart_self
    from .update_guard import start_update_guard
'''
_SRC['shunt.core_update'] = '''"""内核（mihomo）更新"""
import hashlib, os, re, shutil, sys, threading, time, urllib.request, urllib.error
from collections import deque
from urllib.parse import quote

from .errlog import log_err
from .base import CONF_DIR, MIHOMO_LOG, SVC, UA, dl_check
from .data import load
from .mihomo import mh_bin, write_config
from .core import reload_core
from .sb_common import CORES, active_core
from .panel_update import UPD_STATE, gh_api
CORE_REPO = os.environ.get("CORE_REPO", "https://github.com/MetaCubeX/mihomo/releases")
CORE_CHANNELS = {"stable": "latest/download", "alpha": "download/Prerelease-Alpha"}
SMART_REPO = os.environ.get("SMART_REPO", "https://github.com/vernesong/mihomo/releases")  # 只发布 Alpha 预览版
LGBM_URL = SMART_REPO + "/download/LightGBM-Model/Model.bin"
LGBM_FILE = os.path.join(CONF_DIR, "Model.bin")
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
    m = re.search(r"Mihomo\\s+Meta\\s+(\\S+)", out) if code == 0 else None
    return m.group(1) if m else ""


def open_url(url, gh, timeout=20):
    """GitHub 下载：先走加速地址，再经 mihomo 代理，最后直连"""
    tries = [(gh.rstrip("/") + "/" + url, False)] if gh else []
    tries += [(url, True), (url, False)]
    err = ""
    for u, use_proxy in tries:
        try:
            dl_check(u)  # SSRF 防护：禁止内网目标
            req = urllib.request.Request(u, headers={"User-Agent": UA})
            return proxy_opener(use_proxy and core_alive()).open(req, timeout=timeout)
        except Exception as e:
            err = f"{u.split('/')[2]}{'(代理)' if use_proxy else ''}: {str(e)[:120]}"
    raise IOError(err)


def release_digest(repo_url, tag, name):
    """GitHub Release 资产的 SHA256（GitHub 自动计算，API 的 digest 字段）；拿不到返回空串"""
    m = re.match(r"https://github\\.com/([^/]+/[^/]+)/releases", repo_url)
    if not m:
        return ""
    try:
        j = gh_api(f"/repos/{m.group(1)}/releases/tags/{quote(tag)}")
        for a in j.get("assets") or []:
            if a.get("name") == name and str(a.get("digest") or "").startswith("sha256:"):
                return a["digest"][7:]
    except Exception as e:
        log_err("获取内核校验值", e)
    return ""


class HashReader:
    """边读边算 SHA256 的包装（流式解压时用）"""
    def __init__(self, r, prog=None, total=0):
        self.r, self.h, self.n, self.prog, self.total = r, hashlib.sha256(), 0, prog, total

    def read(self, k=-1):
        b = self.r.read(k)
        self.h.update(b)
        self.n += len(b)
        if self.total and self.prog:
            self.prog(min(1.0, self.n / self.total))
        return b


def core_remote_version(channel, gh, kind="mihomo"):
    url = f"{SMART_REPO}/download/Prerelease-Alpha/version.txt" if kind == "smart" else f"{CORE_REPO}/{CORE_CHANNELS[channel]}/version.txt"
    with open_url(url, gh) as r:
        v = r.read(200).decode(errors="ignore").strip()
    if not re.match(r"^[\\w.\\-]+$", v):
        raise IOError("获取到的版本号无效：" + v[:40])
    return v


def core_check(channel, gh, kind="mihomo"):
    arch, b = core_arch(), mh_bin(kind)
    if kind == "smart":
        channel = "alpha"
    info = {"current": bin_version(b) or "未安装", "arch": arch or os.uname().machine, "channel": channel,
            "backup": bin_version(b + ".bak"), "remote": "", "core": kind}
    try:
        info["remote"] = core_remote_version(channel, gh, kind)
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


def _core_swap_and_restart(src, label, kind="mihomo"):
    """把 src 换成正式核心并重启；30 秒内控制接口没起来就自动换回原来的核心"""
    B = mh_bin(kind)
    bak = B + ".bak"
    had_old = os.path.isfile(B)
    if had_old and src != bak:
        shutil.copy2(B, bak)
    if src == bak:  # 回滚：当前核心与备份互换，方便再“回滚”回来
        tmp = B + ".swap"
        shutil.copy2(B, tmp)
        os.replace(bak, B)
        os.replace(tmp, bak)
    else:
        os.replace(src, B)
    if active_core() != kind:  # 这个内核没在运行：只替换程序，切换过去时生效
        _cu("完成", 95, f"已替换为 {label}（当前内核是 {CORES[active_core()]}，切到 {CORES[kind]} 时生效）")
        return True, ""
    _cu("重启核心", 90, f"已替换为 {label}，正在重启核心")
    sh(SVC + " restart", timeout=90)
    for _ in range(30):
        time.sleep(1)
        if core_alive():
            return True, ""
    if had_old and src != bak:  # 新核心起不来 → 自动恢复
        _cu("自动回滚", 95, "新核心 30 秒内未响应，正在恢复原核心")
        shutil.copy2(bak, B)
        sh(SVC + " restart", timeout=90)
        return False, "新核心启动失败，已自动恢复为原核心。日志：" + sh(f"tail -n 5 '{MIHOMO_LOG}'")[1][-300:]
    return False, "核心重启后 30 秒内未响应，请查看日志"


def mh_fetch(kind, channel, gh, prog=None):
    """下载 mihomo / mihomo Smart 到 <程序>.new 并校验能运行；返回 (临时文件, 版本号)"""
    import gzip
    B = mh_bin(kind)
    arch = core_arch()
    if not arch:
        raise ValueError(f"不支持的 CPU 架构：{os.uname().machine}")
    ver = core_remote_version(channel, gh, kind)
    free = shutil.disk_usage(os.path.dirname(B)).free
    if free < 80 * 2**20:
        raise ValueError(f"{os.path.dirname(B)} 剩余空间不足（{free // 2**20} MB，至少需要 80 MB）")
    tag = "Prerelease-Alpha" if kind == "smart" or channel == "alpha" else ver
    url = f"{SMART_REPO if kind == 'smart' else CORE_REPO}/download/{tag}/mihomo-linux-{arch}-{ver}.gz"
    name = url.rsplit('/', 1)[-1]
    digest = release_digest(SMART_REPO if kind == "smart" else CORE_REPO, tag, name)
    if not digest and gh:
        _cu("下载", None, "拿不到 GitHub 校验值，不使用加速镜像（避免下载到被篡改的文件）")
        gh = ""
    _cu("下载", None, f"下载 {name}")
    tmp = B + ".new"
    try:
        with open_url(url, gh, timeout=30) as r:
            hr = HashReader(r, prog, int(r.headers.get("Content-Length") or 0))
            with gzip.GzipFile(fileobj=hr) as gz, open(tmp, "wb") as f:
                size = 0
                while True:
                    chunk = gz.read(1 << 16)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > 200 * 2**20:
                        raise ValueError("解压后的文件异常过大，已中止")
                    f.write(chunk)
            while hr.read(1 << 16):  # gzip 尾部之后若还有数据也计入校验
                pass
        if digest and hr.h.hexdigest() != digest:
            raise ValueError("内核文件 SHA256 与 GitHub 不一致（可能被加速镜像篡改），未做任何替换")
        _cu("下载", None, "SHA256 校验通过" if digest else "未能获取 GitHub 校验值，已改为直连 / 代理下载")
        os.chmod(tmp, 0o755)
        nv = bin_version(tmp)
        if not nv:
            raise ValueError("新核心无法运行（架构不匹配或文件损坏），未做任何替换")
        return tmp, nv
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def core_update_job(channel, gh, force=False, kind="mihomo"):
    B = mh_bin(kind)
    tmp = B + ".new"
    try:
        _cu("获取版本", 2, "正在获取最新版本号")
        ver = core_remote_version(channel, gh, kind)
        cur = bin_version(B)
        if ver == cur and not force:
            CORE_UPD.update(ok=True, message=f"已是最新版本 {cur}，无需更新")
            return
        CORE_UPD["pct"] = 5
        tmp, nv = mh_fetch(kind, channel, gh, lambda pc: CORE_UPD.update(pct=5 + int(70 * pc)))
        _cu("校验", 84, f"新核心 {nv}，正在用它检查配置")
        if active_core() == kind:  # 正在用：拿当前配置校验；没在用：按它的格式生成一份再校验
            cfg = os.path.join(CONF_DIR, "config.yaml")
        else:
            cfg = write_config(dict(load(), core=kind), os.path.join(CONF_DIR, "config.yaml.chk"))
        code, out = sh(f"'{tmp}' -t -d '{CONF_DIR}' -f '{cfg}'", timeout=90)
        if cfg.endswith(".chk"):
            os.remove(cfg)
        if code != 0:
            raise ValueError("新核心不兼容当前配置，未做任何替换：" + out[-300:])
        ok, err = _core_swap_and_restart(tmp, nv, kind)
        if not ok:
            raise ValueError(err)
        CORE_UPD.update(ok=True, message=f"{CORES[kind]} 已从 {cur or '无'} 更新到 {nv}" + ("，旧版本已备份，可一键回滚" if cur else ""))
        tg = load()
        if tg.get("tg_token") and tg.get("tg_chat"):
            notify(f"⬆️ {CORES[kind]} 内核已更新：{cur or '无'} → {nv}")
    except Exception as e:
        CORE_UPD.update(ok=False, message=str(e))
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
        CORE_UPD["pct"] = 100
        _cu("完成" if CORE_UPD["ok"] else "失败", 100, CORE_UPD["message"])
        CORE_UPD["busy"] = False


def lgbm_fetch(gh):
    """下载 LightGBM 模型到 /etc/mihomo/Model.bin（约 9 MB，Smart 组 uselightgbm 用）"""
    tmp = LGBM_FILE + ".new"
    try:
        digest = release_digest(SMART_REPO, "LightGBM-Model", "Model.bin")
        with open_url(LGBM_URL, gh if digest else "", timeout=60) as r0, open(tmp, "wb") as f:
            r = HashReader(r0)
            n = 0
            while True:
                chunk = r.read(1 << 16)
                if not chunk:
                    break
                n += len(chunk)
                if n > 64 * 2**20:
                    raise ValueError("模型文件异常过大，已中止")
                f.write(chunk)
        if n < 1 << 20:
            raise ValueError("下载的模型文件不完整")
        if digest and r.h.hexdigest() != digest:
            raise ValueError("模型文件 SHA256 与 GitHub 不一致")
        os.replace(tmp, LGBM_FILE)
        return n
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def lgbm_fetch_reload():
    try:
        lgbm_fetch(load().get("gh_proxy") or "")
        if active_core() == "smart":
            reload_core()
    except Exception as e:
        print(f"LightGBM 模型下载失败：{e}", file=sys.stderr)


def core_rollback_job(kind="mihomo"):
    try:
        B = mh_bin(kind)
        old = bin_version(B + ".bak")
        if not old:
            raise ValueError("没有可回滚的内核备份")
        cur = bin_version(B)
        ok, err = _core_swap_and_restart(B + ".bak", old, kind)
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


def _link():
    """全部模块加载后由 shunt.load() 调用：绑定后面模块里定义的名字（模块之间互相调用，放在这里避免循环导入）"""
    global proxy_opener, sh, core_alive, notify
    from .sysopt import proxy_opener, sh
    from .notify import core_alive, notify
'''
_SRC['shunt.sysopt'] = '''"""Alpine 系统优化"""
import http.client, json, os, re, ssl, subprocess, threading, time, urllib.request, urllib.error
from collections import deque
from urllib.parse import urlsplit

from .base import MIXED, PANEL_DIR, TESTS, UA, SafeRedirectHandler
from .data import load, update
from .mihomo import build_config
from .sb_common import active_core
from .sb_config import build_singbox
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
            return int(re.search(r"MemTotal:\\s+(\\d+)", f.read()).group(1)) // 1024
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


_CT = {}


def in_container():
    """LXC / Docker 等容器：内核由宿主机共用，大部分全局参数、/sys、系统时间都无权修改"""
    if "v" not in _CT:
        v = rfile("/run/systemd/container")
        if not v and (os.path.exists("/dev/.lxc-boot-id") or " lxcfs " in rfile("/proc/self/mountinfo")
                      or re.search(r"/lxc", rfile("/proc/1/cgroup"))):
            v = "lxc"
        if not v and (os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")
                      or re.search(r"/(docker|kubepods)", rfile("/proc/1/cgroup"))):
            v = "docker"
        _CT["v"] = v
    return _CT["v"]


def path_writable(path):
    """把当前值原样写回，判断是否有权修改（容器里 /proc/sys、/sys 多数只读）"""
    try:
        with open(path) as f:
            cur = f.read().strip()
        with open(path, "w") as f:
            f.write(cur)
        return True
    except OSError:
        return False


_SYSW = {}


def sys_writable(key):
    if key not in _SYSW:
        path = os.path.join(PROC_SYS, key.replace(".", "/"))
        if not os.path.exists(path):
            return False  # 模块未加载时参数不存在，不缓存，加载后再判断
        _SYSW[key] = path_writable(path)
    return _SYSW[key]


def nofile_target():
    """mihomo 文件句柄目标值：不能超过本机（容器）的硬上限，否则 rc_ulimit 会让核心启动失败"""
    try:
        import resource
        hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    except Exception:
        hard = -1
    return 1048576 if hard < 0 or hard >= 1048576 else hard


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
    ct_name = in_container()
    if ct_name:  # 容器里没有自己的内核：模块要在宿主机上加载
        bbr_ok = "bbr" in (rsys("net.ipv4.tcp_available_congestion_control") or "")
    gov_ok = gov_ok and path_writable(govs[0])
    nof = nofile_target()
    rpsq = [q for q in glob_paths(os.path.join(SYS_ROOT, "class/net/*/queues/rx-*/rps_cpus"))
            if q.split("/class/net/")[1].split("/")[0] in net_ifaces()]
    rps_ok = ncpu > 1 and bool(rpsq) and path_writable(rpsq[0])
    host = "宿主机" + ("（PVE / LXC）" if ct_name == "lxc" else "")
    items = [
        {"id": "bbr", "name": "BBR 拥塞控制", "rec": True, "ok": bbr_ok,
         "why": "" if bbr_ok else f"宿主机内核未加载 tcp_bbr，请在{host}上执行 modprobe tcp_bbr" if ct_name else "内核没有 tcp_bbr 模块",
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
        {"id": "fd", "name": "文件句柄上限", "rec": True, "ok": nof > 1024, "why": "本机文件句柄硬上限只有 1024，需在宿主机上调高",
         "desc": f"mihomo 可同时打开的连接数从 1024 提高到 {nof}，设备多或 BT 下载时不再报 too many open files（下次重启核心生效）",
         "sysctl": {"fs.file-max": 1048576, "fs.nr_open": 1048576}},
        {"id": "rps", "name": "多核网络分流 (RPS)", "rec": ncpu > 1, "ok": rps_ok,
         "why": "单核 CPU 无需开启" if ncpu <= 1 else "未找到物理网卡" if not rpsq else f"网卡参数只读，请在{host}上设置",
         "desc": f"把网卡收包分摊到全部 {ncpu} 个 CPU 核心，单队列网卡（树莓派、多数 ARM 盒子、虚拟机）满速时不再单核 100%",
         "sysctl": {"net.core.rps_sock_flow_entries": 32768}},
        {"id": "gov", "name": "CPU 性能模式", "rec": False, "ok": gov_ok,
         "why": f"CPU 调频由{host}控制" if govs and ct_name else "CPU 不支持调频或没有 performance 模式",
         "desc": "CPU 一直跑在最高频率，延迟更低更稳定；功耗和发热会增加，散热差的设备慎开", "sysctl": {}},
        {"id": "ntp", "name": "时间同步", "rec": True, "ok": not ct_name, "why": "容器和宿主机共用系统时钟，请在宿主机上校时",
         "desc": "安装并开机启动 chrony 自动校时。系统时间不准会导致 TLS 握手失败、VMess / Trojan 等节点全部不可用",
         "sysctl": {}},
    ]
    for it in items:  # 只保留有权修改的参数；容器里 net.core.*、fs.* 等全局参数由宿主机决定
        allk = it["sysctl"]
        if not allk or not it["ok"]:
            continue
        w = {k: v for k, v in allk.items() if sys_writable(k)}
        it["skipped"] = [k for k in allk if k not in w]
        it["sysctl"] = w
        if not w and it["id"] != "fd":
            it["ok"] = False
            it["why"] = f"这些内核参数在容器里只读，由{host}决定" if ct_name else "内核参数只读"
        elif it["skipped"]:
            it["part"] = f"有 {len(it['skipped'])}/{len(allk)} 个参数只读（{'由' + host + '决定' if ct_name else '内核不允许修改'}），已跳过"
    return items


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
            live = (live or not it["sysctl"]) and f'rc_ulimit="-n {nofile_target()}"' in rfile(OPT_CONFD)
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
            "why": "" if it["ok"] else it.get("why", ""), "enabled": it["id"] in on, "active": live, "show": show,
            "part": it.get("part", "") if it["ok"] else ""})
    return {"items": out, "mem": mem_mb(), "cpu": os.cpu_count() or 1, "kernel": os.uname().release, "container": in_container()}


def opt_fix_ulimit():
    """旧版写死 rc_ulimit="-n 1048576"：在硬上限更低的 LXC 容器里会让核心启动失败，按实际上限改小"""
    txt = rfile(OPT_CONFD)
    m = re.search(r'^rc_ulimit="-n (\\d+)"', txt, re.M)
    if m and int(m.group(1)) > nofile_target():
        wfile(OPT_CONFD, txt.replace(m.group(0), f'rc_ulimit="-n {nofile_target()}"') + ("" if txt.endswith("\\n") else "\\n"))


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
        lines += ["for g in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do echo performance > \\"$g\\" 2>/dev/null; done"]
    if "bbr" in on:
        lines += ["modprobe tcp_bbr 2>/dev/null; modprobe sch_fq 2>/dev/null"]
    if "conntrack" in on:
        lines += ["modprobe nf_conntrack 2>/dev/null"]
    # 开机时 sysctl 服务可能早于模块加载（conntrack / bbr 参数会写入失败），这里再应用一次
    lines += ["[ -f " + OPT_SYSCTL + " ] && sysctl -q -p " + OPT_SYSCTL + " 2>/dev/null", "exit 0"]
    return "\\n".join(lines) + "\\n"


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
        if "bbr" in want and not in_container():
            sh("modprobe tcp_bbr; modprobe sch_fq")
            mf = os.path.join(ETC, "modules")
            if "tcp_bbr" not in rfile(mf).split():
                try:
                    with open(mf, "a") as f:
                        f.write("tcp_bbr\\n")
                    mods.append("tcp_bbr")
                except OSError as e:
                    errs.append(f"写入 /etc/modules 失败：{e}")
        if "conntrack" in want and not in_container():
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
                    f.write("\\n".join(conf) + "\\n")
            elif os.path.exists(OPT_SYSCTL):
                os.remove(OPT_SYSCTL)
        except OSError as e:
            errs.append(f"写入 {OPT_SYSCTL} 失败：{e}")
        # mihomo 文件句柄
        try:
            txt = rfile(OPT_CONFD)
            txt = "\\n".join(l for l in txt.splitlines() if not l.startswith("rc_ulimit=")).strip()
            if "fd" in want:
                txt = (txt + "\\n" if txt else "") + f'rc_ulimit="-n {nofile_target()}"'
            if txt or os.path.exists(OPT_CONFD):
                os.makedirs(os.path.dirname(OPT_CONFD), exist_ok=True)
                with open(OPT_CONFD, "w") as f:
                    f.write(txt + "\\n" if txt else "")
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
                wfile(mf, "\\n".join(ls) + ("\\n" if ls else ""))
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


_NFT = {"ok": None, "t": 0}


def nft_ok():
    """内核是否支持 nftables（sing-box 的 TUN auto_redirect 依赖它，不支持时 sing-box 直接退出）"""
    if _NFT["ok"] is None or (not _NFT["ok"] and time.time() - _NFT["t"] > 60):
        try:
            p = subprocess.run(["nft", "list", "tables"], capture_output=True, timeout=5)
            _NFT["ok"] = p.returncode == 0
        except Exception:
            _NFT["ok"] = False
        _NFT["t"] = time.time()
    return _NFT["ok"]


def sh(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as e:
        return 1, str(e)


def proxy_opener(proxy=True):
    hs = [urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{MIXED}", "https": f"http://127.0.0.1:{MIXED}"} if proxy else {})]
    # SafeRedirectHandler 替换默认的重定向处理器：跟随 302 前校验目标为公网地址（SSRF 防护）
    return urllib.request.build_opener(*hs, SafeRedirectHandler())


def site_rtt(url, timeout=6):
    """经 mixed 端口建立一条连接（DNS、TCP、TLS 握手不计时），在同一连接上再请求一次，只计这一次的往返。
    与核心 unified-delay 的测法一致，也和浏览器复用连接时的实际体验一致；第二次请求失败时退回第一次的总耗时"""
    u = urlsplit(url)
    https = u.scheme == "https"
    port = u.port or (443 if https else 80)
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    hdr = {"User-Agent": "curl/8", "Accept": "*/*"}
    if https:
        c = http.client.HTTPSConnection("127.0.0.1", MIXED, timeout=timeout, context=ssl.create_default_context())
        c.set_tunnel(u.hostname, port)
    else:  # 普通 HTTP 走代理时请求行用完整 URL
        c = http.client.HTTPConnection("127.0.0.1", MIXED, timeout=timeout)
        path = f"http://{u.hostname}:{port}{path}"
    try:
        st = time.time()
        c.request("HEAD", path, headers=hdr)
        r = c.getresponse()
        r.read()
        first = int((time.time() - st) * 1000)
        if r.will_close:
            return first
        try:
            st = time.time()
            c.request("HEAD", path, headers=hdr)
            c.getresponse().read()
            return max(1, int((time.time() - st) * 1000))
        except Exception:
            return first
    finally:
        c.close()


SITE_HIST, SITE_LOCK, SITE_LAST = {}, threading.Lock(), {"t": 0, "r": None}
SITE_HIST_N = 30  # 每个站点保留最近 30 次（约 30 分钟）


def delay_test(force=False):
    """多个浏览器同时打开概览时 20 秒内复用同一次结果，历史只记一次"""
    with SITE_LOCK:
        if not force and SITE_LAST["r"] is not None and time.time() - SITE_LAST["t"] < 20:
            return SITE_LAST["r"]
        tests = load()["tests"] or TESTS
        out = [None] * len(tests)

        def one(i, t):
            try:
                out[i] = {"name": t["name"], "url": t["url"], "ms": site_rtt(t["url"])}
            except Exception:
                out[i] = {"name": t["name"], "url": t["url"], "ms": -1}

        ths = [threading.Thread(target=one, args=(i, t)) for i, t in enumerate(tests)]
        [t.start() for t in ths]
        [t.join() for t in ths]
        names = {o["name"] for o in out}
        for k in list(SITE_HIST):
            if k not in names:
                del SITE_HIST[k]
        for o in out:
            h = SITE_HIST.setdefault(o["name"], deque(maxlen=SITE_HIST_N))
            h.append(o["ms"])
            o["hist"] = list(h)
        SITE_LAST.update(t=time.time(), r=out)
        return out


# 站点图标：经代理下载 https://<host>/favicon.ico，失败再试 Google favicon 服务；缓存 7 天，失败的 1 小时内不重试
FAV_DIR = os.path.join(PANEL_DIR, "favicons")
FAV_FAIL = {}


def _is_img(b):
    return b[:4] in (b"\\x00\\x00\\x01\\x00", b"\\x89PNG") or b[:3] == b"GIF" or b[:2] == b"\\xff\\xd8" or b[:4] == b"RIFF" or b.lstrip()[:4] == b"<svg"


def favicon(url):
    host = (urlsplit(url).hostname or "").lower()
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", host):
        return None, None
    path = os.path.join(FAV_DIR, host)
    try:
        if time.time() - os.path.getmtime(path) < 7 * 86400:
            with open(path, "rb") as f:
                b = f.read()
            return b, ("image/svg+xml" if b.lstrip()[:4] == b"<svg" else "image/x-icon" if b[:4] == b"\\x00\\x00\\x01\\x00" else "image/png")
    except OSError:
        pass
    if time.time() - FAV_FAIL.get(host, 0) < 3600:
        return None, None
    op = proxy_opener()
    root = ".".join(host.split(".")[-2:])  # api.telegram.org 没有图标时用 telegram.org 的
    tries = [f"https://{host}/favicon.ico"] + ([f"https://{root}/favicon.ico", f"https://www.{root}/favicon.ico"] if root != host else [])
    for u in tries + [f"https://www.google.com/s2/favicons?domain={host}&sz=64"]:
        try:
            with op.open(urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"}), timeout=8) as r:
                b = r.read(256 * 1024)
            if len(b) > 60 and _is_img(b):
                os.makedirs(FAV_DIR, exist_ok=True)
                with open(path, "wb") as f:
                    f.write(b)
                return favicon(url)
        except Exception:
            pass
    FAV_FAIL[host] = time.time()
    return None, None
'''
_SRC['shunt.notify'] = '''"""Telegram 通知"""
import json, socket, threading, time, urllib.request, urllib.error
from collections import deque
from urllib.parse import quote

from .base import G_MANUAL, HC, NOTIFY_FILE, SVC, TPROXY_SH
from .data import load, read_json, write_json
from .core import core, core_json
from .core_update import CORE_UPD
from .sysopt import proxy_opener, sh
def tg_send(text, d=None):
    d = d or load()
    if not d.get("tg_token") or not d.get("tg_chat"):
        return False, "未配置 Telegram"
    body = json.dumps({"chat_id": d["tg_chat"], "text": f"[Shunt@{socket.gethostname()}]\\n{text}"}).encode()
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
'''
_SRC['shunt.latency'] = '''"""节点延迟缓存"""
import base64, json, os, re, threading, time, urllib.request, urllib.error
from urllib.parse import quote

from .errlog import log_err
from .base import G_MANUAL, G_SEL, HC, NOTIFY_FILE, PANEL_DIR, UA, WD_INTERVAL, dl_check
from .data import load, read_json, write_json
from .core import core, core_json, refresh_regions
from .sb_common import active_core
from .sb_config import sb_fake_providers
from .sysopt import proxy_opener
from .notify import WD, check_nodes, core_alive, load_notified, notify, watchdog_tick
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
        except OSError as e:
            log_err("保存延迟缓存", e)
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
        except Exception as e:
            log_err("定时测速", e)
        finally:
            RETEST["pending"] = False
    threading.Thread(target=run, daemon=True).start()


def bg_save(data_url):
    """data:image/...;base64,xxx → 保存背景图；只接受 JPEG / PNG / WebP / GIF"""
    m = re.match(r"data:image/[\\w.+-]+;base64,(.+)$", str(data_url or ""), re.S)
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


BG_META = BG_FILE + ".json"  # 链接背景图：{"url": 链接, "daily": 每天刷新, "t": 上次下载时间}


def bg_meta():
    try:
        with open(BG_META) as f:
            m = json.load(f)
        return m if isinstance(m, dict) else {}
    except Exception:
        return {}


def bg_meta_save(m):
    try:
        if m:
            tmp = BG_META + ".tmp"
            with open(tmp, "w") as f:
                json.dump(m, f, ensure_ascii=False)
            os.replace(tmp, BG_META)
        elif os.path.exists(BG_META):
            os.remove(BG_META)
    except OSError as e:
        print("bg meta save error", e, flush=True)


def bg_fetch(url):
    """由路由器下载图片链接保存为背景图（先走代理，失败再直连）。必应每日壁纸这类接口会 302 跳到真实图片，urllib 自动跟随"""
    url = str(url or "").strip()
    if not re.match(r"https?://\\S+$", url):
        return False, "请输入 http(s) 开头的图片链接"
    try:
        dl_check(url)  # SSRF 防护：禁止内网目标
    except IOError as e:
        return False, str(e)
    raw, err = None, ""
    for proxy in (True, False):
        # 每次新建 Request：走代理时 urllib 会把代理地址写进 Request，复用会让直连也连到代理端口
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "image/avif,image/webp,image/*,*/*;q=0.8"})
        try:
            with proxy_opener(proxy).open(req, timeout=20) as r:
                raw = r.read(BG_MAX + 1)
            break
        except urllib.error.HTTPError as e:
            err = f"HTTP {e.code}"
        except Exception as e:
            err = str(e)[:120]
    if raw is None:
        return False, "下载失败：" + (err or "无法连接")
    if len(raw) > BG_MAX:
        return False, "图片不能超过 8MB"
    if bg_type(raw[:16]) is None:
        return False, "链接返回的不是 JPG / PNG / WebP / GIF 图片"
    tmp = BG_FILE + ".tmp"
    with open(tmp, "wb") as f:
        f.write(raw)
    os.replace(tmp, BG_FILE)
    return True, "背景图已下载到路由器"


def bg_type(head):
    if head[:3] == b"\\xff\\xd8\\xff":
        return "image/jpeg"
    if head[:8] == b"\\x89PNG\\r\\n\\x1a\\n":
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
'''
_SRC['shunt.stats'] = '''"""流量统计"""
import copy, threading, time

from .base import STATS_FILE
from .data import read_json, write_json
from .core import core_json
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
    except OSError:
        pass
    return out


STATS = None
'''
_SRC['shunt.unlock'] = '''"""流媒体解锁检测"""
import http.client, re, threading, urllib.request, urllib.error

from .base import UA
from .sysopt import proxy_opener
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
        ip = re.search(r"^ip=(\\S+)", b, re.M)
        return (m.group(1) if m else ""), (ip.group(1) if ip else "")
    except Exception:
        return "", ""


def ck_egress():
    loc, ip = cf_loc("www.cloudflare.com")
    return {"ok": bool(loc), "text": ip or "无法获取", "region": loc}


def ck_netflix():
    code, url, body = fetch("https://www.netflix.com/title/81280792")
    m = re.search(r'"requestCountry":\\{"id":"([A-Z]{2})"', body) or re.search(r'"country":"([A-Z]{2})"', body) \\
        or re.search(r"netflix\\.com/([a-z]{2})(?:-[a-z]{2})?/title", url)
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
    m = re.search(r'"countryCode"\\s*:\\s*"([A-Z]{2})"', body) or re.search(r'Region:\\s*([A-Z]{2})', body) \\
        or re.search(r"disneyplus\\.com/(?:[a-z]{2}-)?([a-z]{2})(?:/|$)", url)
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
    if re.search(r'45631641(?:,null,true|\\\\?":true)', body):
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
'''
_SRC['shunt.ruletest'] = '''"""规则测试"""
import ipaddress, json, re, socket, threading, time
from urllib.parse import quote

from .base import MIXED
from .core import core_json
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
        s.sendall(f"CONNECT {hp} HTTP/1.1\\r\\nHost: {hp}\\r\\n\\r\\n".encode())
        try:
            first = s.recv(256).decode("latin1").split("\\r\\n")[0]
        except socket.timeout:
            first = "(等待超时)"
        src = re.compile(r"(?:127\\.0\\.0\\.1|\\[?::1\\]?):" + port + r"\\b")
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
                m = re.search(r"dial (.+?) \\(match (\\w+)/(.*?)\\) .*? error: (.*)", msg)
                if m:
                    proxies = (core_json("/proxies") or {}).get("proxies") or {}
                    return {"method": "live", "rule": m.group(2), "payload": m.group(3),
                            "chain": chain_of(m.group(1), proxies), "note": "节点连接失败：" + m.group(4)[:200]}
                m = re.search(r"match (\\w+)\\((.*?)\\) using (.+)$", msg)
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
        except (KeyError, OSError):
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


def _link():
    """全部模块加载后由 shunt.load() 调用：绑定后面模块里定义的名字（模块之间互相调用，放在这里避免循环导入）"""
    global core_stream
    from .logstream import core_stream
'''
_SRC['shunt.logstream'] = '''"""实时日志 (SSE)"""
import secrets, socket, time

from .base import CTRL_HOST, CTRL_PORT
from .data import load

TICKETS = {}  # 日志流（EventSource 无法带请求头）用的一次性票据


def core_stream(path, sink, stop, idle=None):
    """以原始 socket 读取 mihomo 的 chunked JSON 行流，逐行回调 sink；stop 被置位或连接断开时结束。
    idle: 超过该秒数没有数据视为断线（/traffic /memory 每秒推送，可用来发现半开连接）"""
    d = load()
    s = socket.create_connection((CTRL_HOST, CTRL_PORT), timeout=10)
    stop["sock"] = s
    s.settimeout(idle)
    s.sendall(f"GET {path} HTTP/1.1\\r\\nHost: {CTRL_HOST}\\r\\nAuthorization: Bearer {d['secret']}\\r\\nConnection: close\\r\\n\\r\\n".encode())
    f = s.makefile("rb")
    status = f.readline().decode("latin1")
    chunked = False
    while True:
        h = f.readline()
        if h in (b"\\r\\n", b"\\n", b""):
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
        while b"\\n" in buf:
            line, buf = buf.split(b"\\n", 1)
            if line.strip():
                sink(line.decode("utf-8", "ignore"))


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
'''
_SRC['shunt.adblock'] = '''"""广告拦截（AdGuard Home 风格的域名过滤）"""
import copy, hashlib, json, os, re, secrets, threading, time, urllib.request, urllib.error
from collections import deque
from urllib.parse import quote

from .errlog import log_err
from .base import AB_DIR, AB_STATS_FILE, CONF_DIR, UA, dl_check
from .data import load, read_json, write_json
from .mihomo import build_config
from .core import core, reload_core
from .sb_common import active_core
from .sb_config import sb_sync_assets
from .sysopt import proxy_opener
from .ruletest import clean_target
from .logstream import core_stream
# 订阅 AdGuard/ABP（||domain^、@@||domain^）、hosts（0.0.0.0 domain）与纯域名列表，转换为 mihomo
# behavior=domain / format=text 的本地 rule-provider 文件：
#   ||a.com^ → "+.a.com"（含子域）；hosts / 纯域名 → "a.com"（仅该域名，与 AdGuard Home 语义一致）
# 规则：AND,((RULE-SET,ad-xxx),(NOT,((RULE-SET,ad-allow)))),REJECT  —— 白名单优先，且被放行的域名继续走正常分流
DOMAIN_RX = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_\\-]{0,61}[a-z0-9_])?\\.)+(?:[a-z]{2,63}|xn--[a-z0-9\\-]{1,59})$")
CLASH_RX = re.compile(r"^(domain|domain-suffix),([^,\\s]+)(?:,.*)?$")
ABP_RX = re.compile(r"^(@@)?\\|\\|([^\\^/|$]+)\\^\\|?(?:\\$(.*))?$")
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
        if low.startswith("payload:"):
            continue
        if low.startswith("- "):  # Clash YAML payload：  - DOMAIN-SUFFIX,a.com / - '+.a.com'
            low = low[2:].strip().strip("'\\"")
            if not low:
                continue
        cm = CLASH_RX.match(low)
        if cm:  # Clash 规则列表：DOMAIN / DOMAIN-SUFFIX 可用，KEYWORD / IP 类无法用域名列表表达
            dom = norm_domain(cm.group(2))
            if dom:
                (bs if cm.group(1) == "domain-suffix" else be).add(dom)
            else:
                skipped += 1
            continue
        if re.match(r"^(?:domain-keyword|domain-regex|ip-cidr6?|ip-asn|geoip|geosite|process-name|user-agent|url-regex|dst-port|src-ip-cidr),", low):
            skipped += 1
            continue
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
        if low[0] in "|/" or any(c in low for c in "$^*/\\\\"):
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
        f.write("\\n".join(lines) + ("\\n" if lines else ""))
    os.replace(path + ".tmp", path)


def ab_meta():
    return read_json(os.path.join(AB_DIR, "meta.json"), {})


def download(url, timeout=60, limit=40 << 20):
    """先经代理（mixed 端口）下载，失败再直连"""
    dl_check(url)  # SSRF 防护：禁止内网目标
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
    bs, be, _, _, _ = parse_filter("\\n".join(ab.get("black") or []), plain_suffix=True)
    write_lines(os.path.join(AB_DIR, "custom.txt"), domain_lines(bs, be)[0])
    ws, we, was, wae, _ = parse_filter("\\n".join(ab.get("white") or []), plain_suffix=True)
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
    ws, we, was, wae, _ = parse_filter("\\n".join(ab.get("white") or []), plain_suffix=True)
    r = ab_match(host, (ws | was, we | wae))
    if r:
        allowed.append({"name": "自定义白名单", "rule": r})
    for l in ab["lists"]:
        if not l.get("enabled", True):
            continue
        r = ab_match(host, ab_sets(os.path.join(AB_DIR, l["id"] + ".allow.txt")))
        if r:
            allowed.append({"name": l["name"] + "（@@ 例外）", "rule": r})
    bs, be, _, _, _ = parse_filter("\\n".join(ab.get("black") or []), plain_suffix=True)
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
    """订阅 mihomo info 日志，统计命中广告规则 (REJECT) 的连接；另按小时统计全部连接请求数、拦截数和 DNS 解析耗时（概览「域名过滤」）"""
    RX = re.compile(r"--> (\\S+?):\\d+ match .*?RuleSet[,(](ad-[0-9a-z]+)\\).* using REJECT")
    RX_ALL = re.compile(r"--> \\S+ (?:match|doesn't match)")

    def __init__(self):
        self.lock = threading.Lock()
        self.data = read_json(AB_STATS_FILE, {"days": {}})
        self.data.setdefault("days", {})
        self.data.setdefault("hours", {})
        self.data.setdefault("dns5", {})
        self.dns_recent = deque(self.data.get("dns_recent") or [], maxlen=60)  # 最近 60 次原始耗时，刚启动时画曲线用
        self.saved = time.time()

    def hour(self):
        return self.data["hours"].setdefault(time.strftime("%Y-%m-%d %H"), {"req": 0, "blk": 0, "dns": [0, 0]})

    def dns_sample(self, ms):
        with self.lock:
            h = self.hour()
            h["dns"][0] += ms
            h["dns"][1] += 1
            t = time.localtime()
            k = time.strftime("%Y-%m-%d %H:", t) + "%02d" % (t.tm_min // 5 * 5)  # 5 分钟一段，24 小时 288 段
            b = self.data["dns5"].setdefault(k, [0, 0])
            b[0] += ms
            b[1] += 1
            self.dns_recent.append(ms)

    def hit(self, host, prov):
        if host.startswith("["):
            host = host[1:-1]
        with self.lock:
            b = self.data["days"].setdefault(time.strftime("%Y-%m-%d"), {"count": 0, "top": {}, "lists": {}})
            b["count"] += 1
            b["top"][host] = b["top"].get(host, 0) + 1
            key = prov[3:]
            b["lists"][key] = b["lists"].get(key, 0) + 1
            self.hour()["blk"] += 1
            if len(b["top"]) > 5000:  # 防止长尾域名无限增长
                b["top"] = dict(sorted(b["top"].items(), key=lambda x: -x[1])[:2000])

    def sink(self, line):
        try:
            msg = json.loads(line).get("payload", "")
        except Exception:
            return
        if self.RX_ALL.search(msg):
            with self.lock:
                self.hour()["req"] += 1
        if "REJECT" in msg:
            m = self.RX.search(msg)
            if m:
                self.hit(m.group(1), m.group(2))
        if time.time() - self.saved > 60:
            self.flush()

    SB_LINE = re.compile(r"^\\[(\\d+) \\d+ms\\] (.*)$")
    SB_TO = re.compile(r"inbound/(\\w+)\\[([^\\]]+)\\]: inbound (?:packet )?connection to (\\S+?):\\d+$")
    SB_SNIFF = re.compile(r"router: sniffed (?:packet )?protocol: \\w+, domain: (\\S+)")
    SB_REJ = re.compile(r"router: match\\[\\d+\\] .*?\\brule_set=(ad-[0-9a-z]+).*=> reject")
    SB_QN = re.compile(r"dns: exchange (\\S+?)\\.? IN ")
    SB_DREJ = re.compile(r"dns: match\\[\\d+\\] .*?\\brule_set=(ad-[0-9a-z]+).*=> (?:predefined|reject)")

    def sink_sb(self, line):
        """sing-box debug 日志：按连接 ID 记住目标域名，命中 ad- 规则集的 reject / DNS 拦截记为一次拦截"""
        try:
            msg = json.loads(line).get("payload", "")
        except Exception:
            return
        m = self.SB_LINE.match(msg)
        if not m:
            return
        cid, body = m.group(1), m.group(2)
        hosts = self.__dict__.setdefault("_sb_hosts", {})
        if len(hosts) > 5000:
            hosts.clear()
        m = self.SB_TO.search(body)
        if m:
            if m.group(2) != "dns-in":
                hosts[cid] = m.group(3)
                with self.lock:
                    self.hour()["req"] += 1
        elif "sniffed" in body:
            m = self.SB_SNIFF.search(body)
            if m:
                hosts[cid] = m.group(1)
        elif "=> reject" in body:
            m = self.SB_REJ.search(body)
            if m:
                self.hit(hosts.pop(cid, "?"), m.group(1))
        elif body.startswith("dns: "):
            m = self.SB_QN.search(body)
            if m:
                hosts["q" + cid] = m.group(1)
            else:
                m = self.SB_DREJ.search(body)
                if m:
                    self.hit(hosts.pop("q" + cid, "?"), m.group(1))
        if time.time() - self.saved > 60:
            self.flush()

    def flush(self):
        with self.lock:
            keep = sorted(self.data["days"])[-14:]
            self.data["days"] = {k: self.data["days"][k] for k in keep}
            hk = sorted(self.data["hours"])[-48:]
            self.data["hours"] = {k: self.data["hours"][k] for k in hk}
            dk = sorted(self.data["dns5"])[-288:]
            self.data["dns5"] = {k: self.data["dns5"][k] for k in dk}
            self.data["dns_recent"] = list(self.dns_recent)
            for b in self.data["days"].values():
                b["top"] = dict(sorted(b["top"].items(), key=lambda x: -x[1])[:500])
            write_json(AB_STATS_FILE, self.data)
        self.saved = time.time()

    def report(self):
        with self.lock:
            days = copy.deepcopy(self.data["days"])
            hours = copy.deepcopy(self.data["hours"])
            d5 = dict(self.data["dns5"])
            recent = list(self.dns_recent)
        b = days.get(time.strftime("%Y-%m-%d"), {"count": 0, "top": {}, "lists": {}})
        now = int(time.time() // 3600 * 3600)
        h24 = []
        for i in range(23, -1, -1):  # 最近 24 个小时段，缺的补 0
            k = time.strftime("%Y-%m-%d %H", time.localtime(now - i * 3600))
            e = hours.get(k) or {"req": 0, "blk": 0, "dns": [0, 0]}
            h24.append({"h": k[-2:], "req": e["req"], "blk": e["blk"], "dns": round(e["dns"][0] / e["dns"][1], 1) if e["dns"][1] else None})
        return {"today": b["count"], "top": sorted(b["top"].items(), key=lambda x: -x[1])[:20], "lists": b["lists"],
                "days": [{"date": k, "count": days[k]["count"]} for k in sorted(days)], "hours": h24,
                "dns": self.dns_report(d5, recent)}

    @staticmethod
    def dns_report(d5, recent):
        """解析耗时：24 小时 288 个 5 分钟段（null = 该段没采样）；有效段不足 2 个时（刚安装 / 刚重启）用最近的原始采样画曲线"""
        now = int(time.time() // 300 * 300)
        seg = []
        for i in range(287, -1, -1):
            t = time.localtime(now - i * 300)
            b = d5.get(time.strftime("%Y-%m-%d %H:", t) + "%02d" % (t.tm_min // 5 * 5))
            seg.append(round(b[0] / b[1], 1) if b and b[1] else None)
        vals = [v for v in seg if v is not None]
        tot = sum(b[0] for b in d5.values() if b[1])
        cnt = sum(b[1] for b in d5.values() if b[1])
        return {"avg": round(tot / cnt, 1) if cnt else None, "last": recent[-1] if recent else None, "samples": cnt,
                "series": seg if len(vals) >= 2 else recent[-30:], "mode": "5min" if len(vals) >= 2 else "recent",
                "core": active_core()}

    def dns_probe(self):
        """经核心解析器查随机子域名（绕过缓存）：国内域名走直连 DNS、国外域名走代理 DNS，记录平均耗时"""
        sb = active_core() == "singbox"  # sing-box 的 Clash API 没有 /dns/query，改为直接向 dns-in(1053) 发 UDP 查询
        ms = []
        for base in ("baidu.com", "google.com"):
            name = "shunt-%s.%s" % (secrets.token_hex(4), base)
            st = time.time()
            if sb:
                ok = udp_dns_query(name, 1053, timeout=8)
            else:
                code, _ = core("GET", f"/dns/query?name={name}&type=A", timeout=8)
                ok = code == 200
            if ok:
                ms.append(max(1, int((time.time() - st) * 1000)))
        if ms:
            self.dns_sample(round(sum(ms) / len(ms)))

    def dns_loop(self):
        """启动后先连测 3 次（每 10 秒）让曲线马上有数据，之后每 60 秒一次"""
        time.sleep(8)
        n = 0
        while True:
            try:
                self.dns_probe()
            except Exception as e:
                log_err("广告拦截 DNS 统计", e)
            n += 1
            time.sleep(10 if n < 3 else 60)

    def loop(self):
        while True:
            try:
                sb = active_core() == "singbox"  # sing-box 的规则命中只在 debug 级别日志里
                core_stream("/logs?level=debug" if sb else "/logs?level=info", self.sink_sb if sb else self.sink, {})
            except OSError:  # 内核未运行 / 断线，稍后重连
                pass
            except Exception as e:
                log_err("广告拦截统计", e)
            time.sleep(3)


AD_STATS = None


def _link():
    """全部模块加载后由 shunt.load() 调用：绑定后面模块里定义的名字（模块之间互相调用，放在这里避免循环导入）"""
    global udp_dns_query
    from .live import udp_dns_query
'''
_SRC['shunt.live'] = '''"""实时速率 / 内存（订阅 /traffic 与 /memory 流）"""
import json, secrets, socket, time

from .errlog import log_err
from .core import core_json
from .logstream import core_stream
def udp_dns_query(name, port=1053, host="127.0.0.1", timeout=8):
    """向本机 DNS 端口发一个 A 记录查询；收到同 ID 的应答（含 NXDOMAIN）即视为成功"""
    qid = secrets.randbits(16)
    pkt = qid.to_bytes(2, "big") + b"\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00"
    for lab in name.strip(".").split("."):
        b = lab.encode("idna") if lab else b""
        pkt += bytes([len(b)]) + b
    pkt += b"\\x00\\x00\\x01\\x00\\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (host, port))
        end = time.time() + timeout
        while time.time() < end:
            data = s.recv(1500)
            if len(data) >= 12 and int.from_bytes(data[:2], "big") == qid and data[2] & 0x80:
                return True
    except Exception:
        return False
    finally:
        s.close()
    return False


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
            LIVE.update({k: j.get(k, 0) for k in ("up", "down")})
            if "upTotal" in j or "downTotal" in j:
                LIVE.update(upTotal=j.get("upTotal", 0), downTotal=j.get("downTotal", 0))
            elif time.time() - LIVE.get("_tt", 0) > 2:  # sing-box 的 /traffic 不带累计值，从 /connections 取
                LIVE["_tt"] = time.time()
                c = core_json("/connections", timeout=3) or {}
                LIVE.update(upTotal=int(c.get("uploadTotal") or 0), downTotal=int(c.get("downloadTotal") or 0))
            LIVE["t"] = time.time()
    while True:
        try:
            core_stream(path, sink, {}, idle=15)
        except OSError:  # 内核未运行 / 断线，稍后重连
            pass
        except Exception as e:
            log_err("实时速率", e)
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
            except (KeyError, OSError):
                pass
    try:
        core_stream("/memory", sink, stop, idle=3)
    except Exception:
        pass
    vals = [g for g in got if g.get("inuse")]
    return vals[-1] if vals else {"inuse": 0, "oslimit": 0}
'''
_SRC['shunt.logclean'] = '''"""日志自动清理"""
import os, time

from .base import LOG_FILES
from .data import load
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
'''
_SRC['shunt.schedule'] = '''"""定时任务"""
import json, time
from collections import deque
from urllib.parse import quote

from .errlog import log_err
from .base import G_MANUAL, HC, SVC
from .data import load
from .core import core, core_json, refresh_regions, reload_core
from .sb_common import active_core
from .sb_subs import sb_sub_cache, sb_update_subs
from .sb_config import sb_sync_assets
from .sysopt import sh
from .notify import WD
from .latency import bg_fetch, bg_meta, bg_meta_save
from .adblock import AB_STATE, ab_meta, adblock_update
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
        except Exception as e:
            log_err("定时任务：刷新地区分组", e)
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
        except Exception as e:
            log_err("定时任务：刷新地区分组", e)
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
            bm = bg_meta()
            if bm.get("daily") and bm.get("url") and time.time() - max(int(bm.get("t") or 0), SCHED["done"].get("bg", 0)) >= 86400:
                SCHED["done"]["bg"] = time.time()  # 失败也等一天，避免反复重试
                if bg_fetch(bm["url"])[0]:
                    bm["t"] = int(time.time())
                    bg_meta_save(bm)
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
'''
_SRC['shunt.devices'] = '''"""设备名称"""
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
            except OSError:
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
'''
_SRC['shunt.diag'] = '''"""网络诊断"""
import json, os, secrets, shutil, socket, threading, time, urllib.request, urllib.error

from .errlog import ERRS
from .base import CONF_DIR, TPROXY_SH
from .data import load
from .mihomo import check_config, mh_bin, safe_dev
from .core import core
from .sb_common import CORES, SB_BIN, SB_CONF, SB_STATE, active_core
from .sb_config import check_sb_config
from .sysopt import proxy_opener, sh
def dns_probe(server=("127.0.0.1", 1053), name="www.baidu.com"):
    """向 mihomo DNS 端口发一个最小的 A 查询"""
    qid = secrets.randbits(16)
    pkt = qid.to_bytes(2, "big") + b"\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00"
    pkt += b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\\x00\\x00\\x01\\x00\\x01"
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

    recent = [e for e in ERRS if time.time() - e["t"] < 86400]
    if recent:
        item(f"面板内部错误（24 小时内 {len(recent)} 条）", "warn",
             "；".join(f"{time.strftime('%m-%d %H:%M', time.localtime(e['t']))} {e['where']}：{e['msg']}" for e in recent[:5])[:600],
             "完整记录在 /var/log/mihomo-panel.log，反馈问题时请附上")

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
    if not sb and os.path.isfile(mh_bin(active_core(d))) and os.path.isfile(cfg):
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
'''
_SRC['shunt.dnsleak'] = '''"""DNS 防泄露"""
import copy, ipaddress, json, os, re, secrets, socket, threading, time

from .base import CN_DNS, DEFAULT_FAKE_FILTER, DNS_DEFAULT, G_SEL, TPROXY_SH
from .data import load
from .mihomo import dns_cfg, dns_policy_of, policy_parts
from .core import core
from .sysopt import sh
from .notify import core_alive
from .unlock import fetch
RESOLV_FILE = os.environ.get("PANEL_RESOLV", "/etc/resolv.conf")
CN_GEO = re.compile(r"(?i)^(?:cn|private|.*@cn|.*-cn|tld-cn|geolocation-cn)$")
CN_DOMAIN = re.compile(r"(?i)^[+*.]*[\\w.\\-]*\\.(?:cn|lan|local|arpa|home|localdomain)$")


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
        return bool(re.fullmatch(re.escape(pattern).replace(r"\\*", r"[^.]+"), name))
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
    pkt = qid.to_bytes(2, "big") + b"\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00"
    pkt += b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\\x00\\x00\\x01\\x00\\x01"
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
'''
_SRC['shunt.migrate'] = '''"""v5 → v6 升级：保留节点选择"""
import os, time
from urllib.parse import quote

from .base import CONF_DIR, PANEL_DIR
from .data import legacy_map, load, read_json, write_json
from .core import core, core_json, reload_core
from .sb_common import active_core
from .notify import core_alive
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
    mp = legacy_map(load()["groups_cfg"].get("strategy"))
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
'''
_SRC['shunt.https'] = '''"""HTTPS"""
import os, socket, ssl, sys
from http.server import ThreadingHTTPServer

from .base import CERT, KEY, PANEL_DIR
from .sysopt import sh
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
'''
_SRC['shunt.access'] = '''"""访问控制"""
import ipaddress, os, time

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
'''
_SRC['shunt.update_guard'] = '''"""面板更新失败自动回滚"""
import os

from .errlog import log_err
from .base import AUTO_TAIL, BASE, G_AUTO, G_DIRECT, G_MANUAL, G_SEL, LB_PREFIX, LB_TAIL, PANEL_VERSION, PORT, SIDE_GROUPS
from .data import LB_ALL, map_refs
from .panel_update import local_file
from .sysopt import sh
GUARD = os.path.join(BASE, ".update-guard.sh")
ROLLBACK_NOTE = os.path.join(BASE, ".rollback-note")


def update_guard_script(files):
    """更新后由独立的 shell 脚本检查新面板：90 秒内一直打不开就把 .backup 里的旧版本放回去并重启"""
    bak = os.path.join(BASE, ".backup")
    cps = "\\n".join(f"  [ -f '{bak}/{f}' ] && cp '{bak}/{f}' '{local_file(f)}'" for f in files)
    restart = os.environ.get("PANEL_RESTART", "rc-service mihomo-panel restart")
    return f"""#!/bin/sh
# 由 Shunt 面板生成：在线更新后自动检查，新版启动失败时回滚
sleep 30
i=0
while [ $i -lt 6 ]; do
  python3 - <<'PY' && {{ rm -f "$0"; exit 0; }}
import ssl, sys, urllib.request
ctx = ssl._create_unverified_context()
op = urllib.request.build_opener(urllib.request.ProxyHandler({{}}), urllib.request.HTTPSHandler(context=ctx))
for u in ("http://127.0.0.1:{PORT}/manifest.webmanifest", "https://127.0.0.1:{PORT}/manifest.webmanifest"):
    try:
        op.open(u, timeout=5)
        sys.exit(0)
    except Exception:
        pass
sys.exit(1)
PY
  i=$((i+1)); sleep 10
done
{cps}
echo "新版面板 90 秒内没有启动成功，已自动恢复为 v{PANEL_VERSION}" > '{ROLLBACK_NOTE}'
echo "[update-guard] 新版面板启动失败，已回滚到 v{PANEL_VERSION}" >> /var/log/mihomo-panel.log
{restart} >/dev/null 2>&1
rm -f "$0"
"""


def start_update_guard(files):
    try:
        with open(GUARD, "w") as f:
            f.write(update_guard_script(files))
        os.chmod(GUARD, 0o755)
        sh(f"(command -v setsid >/dev/null && setsid sh '{GUARD}' || sh '{GUARD}') >/dev/null 2>&1 &")
    except OSError as e:
        log_err("更新回滚守护", e)


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
    if n.startswith(LB_PREFIX) and n.endswith((LB_TAIL,) + tuple(LB_ALL.values())):
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
'''
_SRC['shunt.static'] = '''"""静态资源：gzip + ETag"""
import base64, gzip, hashlib, os, re

from .base import BASE
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
'''
_SRC['shunt.webapi'] = '''"""HTTP"""
import copy, gzip, json, os, re, shutil, socket, threading, time
from http.server import BaseHTTPRequestHandler
from collections import deque
from urllib.parse import parse_qs, quote, unquote, urlparse

from .errlog import log_err
from . import adblock, stats
from .base import (
    AB_DIR, AB_PRESETS, BUILTIN_POLICIES, CERT, DEFAULT_EXCLUDE, DNS_DEFAULT, DNS_LISTS, GROUP_TYPES, G_MANUAL, G_SEL, HC, KEY,
    LB_STRATEGIES, LOCK, MAX_BODY, MIHOMO_BIN, MIHOMO_LOG, PANEL_VERSION, PRIMARY_REGIONS, PROXY_MODES, REGIONS, SMART_BIN, SVC, TPROXY_SH,
    TUN_STACKS
)
from .data import HISTORY_FILE, HISTORY_SKIP, auto_name, lb_names, load, migrate_names, read_json, region_lb_set, save, update
from .links import add_links, q1
from .groups import all_node_names, clean_custom_group, gcfg, region_plan, rx, validate_groups
from .mihomo import bad_rule_policies, build_config, dns_cfg, safe_dev, validate_dns
from .core import core, core_json, refresh_after_sub, refresh_regions, reload_core
from .sb_common import CORES, SB_BIN, SB_STATE, active_core, core_conf_path
from .sb_subs import sb_update_subs
from .sb_config import build_singbox, sb_ab_loaded, sb_fake_providers, sb_fake_rule_providers, sb_sync_assets, sb_version, write_active_config
from .sb_switch import core_switch_job, sb_arch, sb_remote_version, sb_update_job
from .panel_update import self_rollback, self_update
from .core_update import (
    CORE_CHANNELS, CORE_UPD, LGBM_FILE, bin_version, core_check, core_job_start, core_rollback_job, core_upd_status, core_update_job,
    lgbm_fetch, lgbm_fetch_reload
)
from .sysopt import config_view, delay_test, favicon, nft_ok, opt_apply, opt_status, sh, speed_test
from .notify import WD, tg_send
from .latency import BG_FILE, RETEST, bg_fetch, bg_meta, bg_meta_save, bg_save, bg_type, fix_global, proxies_merged, retest_soon
from .stats import arp_table
from .unlock import unlock_test
from .ruletest import clean_target, is_ip, rule_test
from .logstream import core_stream, ticket_new, ticket_use
from .adblock import AB_CACHE, AB_STATE, ab_check, ab_compose, ab_meta, adblock_update, fmt_size, list_id, parse_filter
from .live import LIVE, memory_once
from .logclean import LOG_STATE, log_clean, log_sizes
from .schedule import SCHED, TASK_NAMES, run_task, sched_event
from .devices import device_map, read_leases, tun_runtime_error
from .diag import diagnose
from .dnsleak import antileak_dns, dns_route, leak_check
from .https import gen_cert, restart_self
from .access import acl_cfg, host_name, host_ok, ip_is_lan
from .update_guard import group_meta, rename_policy
from .static import MANIFEST, STATIC_TYPES, static_file
ROUTES = {}  # (方法, 路径) → H 的处理函数；api() 先处理前缀 / 条件路由，再查这张表

# GET 也要求 X-Shunt 头的机密接口：返回内容含订阅 URL / 节点密码 / TG token 等机密，局域网零凭证可拖库
SENSITIVE_GET = ("/api/backup", "/api/config", "/api/history")


def api_route(path, *methods):
    def deco(fn):
        for m in methods:
            assert (m, path) not in ROUTES, (m, path)
            ROUTES[(m, path)] = fn
        return fn
    return deco


class H(BaseHTTPRequestHandler):
    timeout = 30  # 读请求/TLS 握手的超时：卡住不发数据的连接不再永久占用线程（日志流只写不读，不受影响）

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
        if n > MAX_BODY:  # 防止超大 body 耗尽路由器内存
            raise ValueError("请求体过大")
        raw = self.rfile.read(n)
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def do_GET(self): self.route("GET")
    def do_POST(self): self.route("POST")
    def do_PUT(self): self.route("PUT")
    def do_DELETE(self): self.route("DELETE")
    def do_PATCH(self): self.route("PATCH")

    def deny(self, why):
        if self.path.startswith("/api/"):
            return self.send(403, {"message": why})
        from html import escape as html_escape
        html = ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>"
                "<title>Shunt</title><div style='font:15px/1.7 system-ui;max-width:640px;margin:40px auto;padding:0 16px'>"
                f"<h3>访问被拒绝</h3><p>{html_escape(why)}</p></div>")
        return self.send(403, html.encode(), "text/html")

    def guard(self, m, p):
        """返回拒绝原因；空串表示放行"""
        a = acl_cfg()
        ip = self.client_address[0]
        if not a["public"] and not ip_is_lan(ip):
            return (f"面板默认只允许局域网访问，你的地址 {ip} 不是局域网地址。确实需要从外网访问时，"
                    "在路由器上执行：python3 /opt/mihomo-panel/server.py --allow-public on（面板没有密码，请自行做好防护）")
        host = self.headers.get("Host") or ""
        if not host_ok(host):
            h = host_name(host)
            return (f"域名 {h} 不在允许列表（防止 DNS 重绑定攻击）。用 IP 访问，或在路由器上执行："
                    f"python3 /opt/mihomo-panel/server.py --allow-host {h}")
        if m not in ("GET", "HEAD") and p.startswith("/api/"):
            origin = self.headers.get("Origin")
            if origin and origin != "null" and urlparse(origin).netloc.lower() != host.lower():
                return "跨站请求已拒绝"
            if "X-Shunt" not in self.headers and "X-Token" not in self.headers:  # X-Token：兼容旧版脚本
                return "缺少 X-Shunt 请求头，跨站请求已拒绝（脚本调用接口请加上 -H 'X-Shunt: 1'）"
        if m in ("GET", "HEAD") and p in SENSITIVE_GET:
            # 机密类 GET：/api/backup、/api/config（含 ?download）、/api/history 返回订阅/节点密码等机密，同样要求请求头
            if "X-Shunt" not in self.headers and "X-Token" not in self.headers:
                return "缺少 X-Shunt 请求头，机密接口拒绝访问（脚本调用请加上 -H 'X-Shunt: 1'）"
        return ""

    def route(self, m):
        u = urlparse(self.path)
        p = u.path
        why = self.guard(m, p)
        if why:
            return self.deny(why)
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
        if not p.startswith("/api/"):
            return self.send(404, {"message": "not found"})
        if p == "/api/logstream" and m == "GET":  # EventSource 无法带自定义头，用 /api/logticket 换来的一次性票据
            qs = parse_qs(u.query)
            if not ticket_use(q1(qs, "ticket")):
                return self.send(401, {"message": "未登录"})
            return self.logstream(q1(qs, "level", default="info"))
        try:
            return self.api(m, p, u.query)
        except (BrokenPipeError, ConnectionResetError):
            raise
        except Exception as e:
            log_err(f"{m} {p}", e, tb=True)
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
                    self.wfile.write(b": ping\\n\\n")  # 心跳，同时探测浏览器是否断开
                while q:
                    self.wfile.write(b"data: " + q.popleft().encode() + b"\\n\\n")
                self.wfile.flush()
                if stop.get("ended"):
                    break
        except Exception:
            pass
        finally:
            stop["stop"] = True
            try:
                stop["sock"].shutdown(socket.SHUT_RDWR)
            except (KeyError, OSError):
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
            if active_core() == "singbox" and load()["tun"].get("auto_redirect", True) and not nft_ok():
                note = "（内核不支持 nftables，auto-redirect 未启用）"
            if err and "redirect" in err.lower() and load()["tun"].get("auto_redirect"):
                # auto-redirect 依赖 nftables / iptables，内核不支持时自动关闭后重试一次
                update(lambda d: d["tun"].update(auto_redirect=False))
                ok, msg = reload_core()
                err = tun_runtime_error(safe_dev(load()["tun"].get("device"))) if ok else msg
                note = "（auto-redirect 不可用，已自动关闭）" if not err else ""
            if err:  # TUN 起不来时局域网会断网：恢复为原来的代理方式
                save(prev)
                reload_core()
                sh(TPROXY_SH + " apply")
                return self.send(500, {"message": "TUN 启动失败，已恢复原来的代理方式：" + err +
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
            bs, be, as_, ae, sk = parse_filter("\\n".join(new[key]), plain_suffix=True)
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
            lbs = region_lb_set()
            gnames = [g for g in gnames if g not in lbs]
            for n in list(meta):
                if n in lbs:
                    meta.pop(n)
                elif meta[n]["type"] in ("load-balance", "fallback"):
                    meta[n].update(sb_from=meta[n]["type"], type="url-test")
        regions = [{"name": r[0], "total": r[4], "manual": len(r[3]), "unknown": r[5],
                    "groups": [g for g in gnames if g in [auto_name(r[0])] + lb_names(r[0])]} for r in plan]
        sel = next((g.get("proxies") or [] for g in cfg["proxy-groups"] if g["name"] == G_SEL), [])
        if sb:
            sel = [x for x in sel if x in gnames or x in BUILTIN_POLICIES]
        return self.send(200, {"cfg": gcfg(d), "region_groups": d["region_groups"], "custom": d["custom_groups"],
                               "regions": regions, "groups": gnames, "manual": names, "nodes": all_node_names(d),
                               "meta": meta, "core": active_core(d), "types": GROUP_TYPES, "strategies": LB_STRATEGIES,
                               "region_names": [r[0] for r in REGIONS], "primary": PRIMARY_REGIONS, "selector": sel})

    def save_groups_cfg(self, b):
        gc = gcfg(load())
        for k in ("lb", "extra", "other", "lazy", "lgbm"):
            if k in b:
                gc[k] = bool(b[k])
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
            if not re.match(r"^https?://\\S+$", u):
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
        if ok and gc["lgbm"] and active_core() == "smart" and not os.path.isfile(LGBM_FILE):
            threading.Thread(target=lgbm_fetch_reload, daemon=True).start()
            msg = "策略组设置已生效，LightGBM 模型正在后台下载，下载完会自动重载"
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
        if p == "/api/delay":
            return self.send(200, delay_test(force=q1(parse_qs(q), "force") == "1"))
        if p == "/api/favicon":
            b, ct = favicon(q1(parse_qs(q), "u", default=""))
            if not b:
                return self.send(404, {"message": "无图标"})
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "max-age=86400")
            self.end_headers()
            return self.wfile.write(b)
        if p == "/api/unlock":
            return self.send(200, unlock_test())
        if p == "/api/logs":
            _, out = sh(f"tail -n 300 '{MIHOMO_LOG}'")
            return self.send(200, {"log": out})
        fn = ROUTES.get((m, p))
        if fn:
            return fn(self, m, p, b, q)
        return self.send(404, {"message": "not found"})

    @api_route("/api/state", "GET")
    def api_state_get(self, m, p, b, q):
        d = load()
        _, st = sh(SVC + " status")
        code, ver = core("GET", "/version")
        try:
            version = json.loads(ver).get("version", "-") if code == 200 else "-"
        except Exception:
            version = "-"
        cfg = build_config(d)
        groups = [g["name"] for g in cfg["proxy-groups"]]
        gmeta = group_meta(d, cfg)
        if active_core(d) == "singbox":  # 地区负载均衡并入自动优选；负载均衡 / 故障转移按自动测速运行
            lbs = region_lb_set()
            groups = [g for g in groups if g not in lbs]
            for n, mt in list(gmeta.items()):
                if n in lbs:
                    gmeta.pop(n)
                elif mt["type"] in ("load-balance", "fallback"):
                    mt.update(sb_from=mt["type"], type="url-test")
        return self.send(200, {"mode": d["mode"], "subs": d["subs"], "rules": d["rules"],
                               "running": "started" in st or code == 200, "version": version, "groups": groups,
                               "nodes": [{"name": n["proxy"]["name"], "type": n["proxy"]["type"],
                                                            "server": n["proxy"]["server"], "port": n["proxy"]["port"]} for n in d["nodes"]],
                               "rulesets": d["rulesets"], "bypass": d["bypass"], "tests": d["tests"],
                               "sub_interval": d["sub_interval"],
                               "ipv6": d["ipv6"], "https": d["https"],
                               "watchdog": d["watchdog"], "tg_token": d["tg_token"], "tg_chat": d["tg_chat"],
                               "default_exclude": DEFAULT_EXCLUDE, "proxy_mode": d["proxy_mode"], "tun": d["tun"],
                               "log_limit": d["log_limit"], "dns": dns_cfg(d),
                               "schedule": d["schedule"], "devices": d["devices"], "adblock_on": d["adblock"]["enabled"],
                               "sched_events": list(SCHED["events"])[:20], "group_meta": gmeta,
                               "sniffer": d["sniffer"],
                               "gh_proxy": d["gh_proxy"], "panel_version": PANEL_VERSION, "core": active_core(d),
                               "wd": {"status": WD["status"], "last_check": WD["last_check"],
                                      "events": list(WD["events"])[:20]}})

    @api_route("/api/groups", "GET")
    def api_groups_get(self, m, p, b, q):
        return self.groups_info()

    @api_route("/api/groups/cfg", "PUT")
    def api_groups_cfg_put(self, m, p, b, q):
        return self.save_groups_cfg(b)

    @api_route("/api/groups", "POST")
    def api_groups_post(self, m, p, b, q):
        return self.save_custom_group(b)

    @api_route("/api/groups", "DELETE")
    def api_groups_delete(self, m, p, b, q):
        return self.delete_custom_group(b)

    @api_route("/api/groups/preview", "POST")
    def api_groups_preview_post(self, m, p, b, q):
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

    @api_route("/api/groups/refresh", "POST")
    def api_groups_refresh_post(self, m, p, b, q):
        return self.reply(*refresh_regions())

    @api_route("/api/config", "GET")
    def api_config_get(self, m, p, b, q):
        txt = config_view(load(), masked=True)
        sbm = active_core() == "singbox"
        if "download" in parse_qs(q):
            return self.send(200, txt.encode(), "application/json" if sbm else "application/x-yaml")
        return self.send(200, {"text": txt, "path": core_conf_path(), "size": len(txt.encode()), "core": active_core()})

    @api_route("/api/sysopt", "GET")
    def api_sysopt_get(self, m, p, b, q):
        return self.send(200, opt_status())

    @api_route("/api/sysopt", "POST")
    def api_sysopt_post(self, m, p, b, q):
        ids = b.get("ids")
        if not isinstance(ids, list):
            return self.send(400, {"message": "参数错误"})
        ok, msg, errs = opt_apply([str(i) for i in ids])
        return self.send(200, {"ok": ok, "message": msg, "errors": errs} | opt_status())

    @api_route("/api/speedtest", "GET")
    def api_speedtest_get(self, m, p, b, q):
        via = q1(parse_qs(q), "via", default="proxy")
        return self.send(200, speed_test(via == "proxy"))

    @api_route("/api/bg", "GET")
    def api_bg_get(self, m, p, b, q):
        bm = bg_meta()
        try:
            return self.send(200, {"exists": True, "v": int(os.path.getmtime(BG_FILE)), "size": os.path.getsize(BG_FILE),
                                   "url": bm.get("url", ""), "daily": bool(bm.get("daily"))})
        except OSError:
            return self.send(200, {"exists": False})

    @api_route("/api/bg", "POST")
    def api_bg_post(self, m, p, b, q):
        ok, msg = bg_save(b.get("data"))
        if not ok:
            return self.send(400, {"message": msg})
        bg_meta_save({})  # 改为上传的图片：不再按链接刷新
        return self.send(200, {"message": msg, "v": int(os.path.getmtime(BG_FILE))})

    @api_route("/api/bg/url", "POST")
    def api_bg_url_post(self, m, p, b, q):
        url = str(b.get("url") or "").strip() or bg_meta().get("url", "")
        ok, msg = bg_fetch(url)
        if not ok:
            return self.send(400, {"message": msg})
        bg_meta_save({"url": url, "daily": bool(b.get("daily")), "t": int(time.time())})
        return self.send(200, {"message": msg, "v": int(os.path.getmtime(BG_FILE))})

    @api_route("/api/bg/daily", "POST")
    def api_bg_daily_post(self, m, p, b, q):
        bm = bg_meta()
        if not bm.get("url"):
            return self.send(400, {"message": "当前背景图不是链接图片"})
        bm["daily"] = bool(b.get("daily"))
        bg_meta_save(bm)
        return self.send(200, {"message": "已开启每天自动更新" if bm["daily"] else "已关闭每天自动更新"})

    @api_route("/api/bg", "DELETE")
    def api_bg_delete(self, m, p, b, q):
        try:
            os.remove(BG_FILE)
        except OSError:
            pass
        bg_meta_save({})
        return self.send(200, {"message": "已移除背景图"})

    @api_route("/api/px", "GET")
    def api_px_get(self, m, p, b, q):
        px = proxies_merged()
        if px is None:
            return self.send(502, {"message": "核心未运行或无法连接"})
        return self.send(200, {"proxies": px, "retesting": RETEST["pending"]})

    @api_route("/api/coreswitch", "GET")
    def api_coreswitch_get(self, m, p, b, q):
        d = load()
        if active_core(d) == "singbox" and not SB_STATE["warn"]:
            SB_STATE["warn"] = build_singbox(d)[1]
        return self.send(200, {"core": active_core(d), "versions": {"mihomo": bin_version(MIHOMO_BIN), "smart": bin_version(SMART_BIN), "singbox": sb_version()},
                               "lgbm": os.path.isfile(LGBM_FILE),
                               "warn": SB_STATE["warn"] if active_core(d) == "singbox" else [], "busy": CORE_UPD["busy"]})

    @api_route("/api/coreswitch", "POST")
    def api_coreswitch_post(self, m, p, b, q):
        kind = b.get("core")
        if kind not in CORES:
            return self.send(400, {"message": "未知的内核"})
        if kind == active_core():
            return self.send(400, {"message": f"当前已经是 {CORES[kind]}"})
        ok, msg = core_job_start(core_switch_job, kind, load().get("gh_proxy") or "")
        return self.send(200 if ok else 409, {"message": msg})

    @api_route("/api/coreupdate", "GET")
    def api_coreupdate_get(self, m, p, b, q):
        ch = q1(parse_qs(q), "channel", default="stable")
        kind = "smart" if (q1(parse_qs(q), "core") or active_core()) == "smart" else "mihomo"
        if ch not in CORE_CHANNELS:
            return self.send(400, {"message": "未知的更新通道"})
        ok, info = core_check(ch, load().get("gh_proxy") or "", kind)
        info["busy"] = CORE_UPD["busy"]
        return self.send(200 if ok else 502, info)

    @api_route("/api/coreupdate/status", "GET")
    def api_coreupdate_status_get(self, m, p, b, q):
        return self.send(200, core_upd_status())

    @api_route("/api/coreupdate", "POST")
    def api_coreupdate_post(self, m, p, b, q):
        kind = "smart" if (b.get("core") or active_core()) == "smart" else "mihomo"
        if b.get("action") == "lgbm":
            try:
                n = lgbm_fetch(load().get("gh_proxy") or "")
            except Exception as e:
                return self.send(502, {"message": "模型下载失败：" + str(e)[:200]})
            if active_core() == "smart":
                reload_core()
            return self.reply(True, f"LightGBM 模型已更新（{n // 2**20} MB）")
        if b.get("action") == "rollback":
            ok, msg = core_job_start(core_rollback_job, kind)
        else:
            ch = "alpha" if kind == "smart" else (b.get("channel") or "stable")
            if ch not in CORE_CHANNELS:
                return self.send(400, {"message": "未知的更新通道"})
            ok, msg = core_job_start(core_update_job, ch, load().get("gh_proxy") or "", bool(b.get("force")), kind)
        return self.send(200 if ok else 409, {"message": msg})

    @api_route("/api/selfupdate", "GET")
    def api_selfupdate_get(self, m, p, b, q):
        ok, info = self_update(False, load().get("gh_proxy") or "")
        return self.send(200 if ok else 502, info)

    @api_route("/api/selfupdate", "POST")
    def api_selfupdate_post(self, m, p, b, q):
        if b.get("action") == "rollback":
            return self.reply(*self_rollback())
        ok, info = self_update(True, load().get("gh_proxy") or "")
        return self.send(200 if ok else 500, info)

    @api_route("/api/subs/update", "POST")
    def api_subs_update_post(self, m, p, b, q):
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

    @api_route("/api/stats", "GET")
    def api_stats_get(self, m, p, b, q):
        return self.send(200, stats.STATS.report() if stats.STATS else {"today": {}, "month": {}, "days": [], "arp": {}})

    @api_route("/api/ruletest", "POST")
    def api_ruletest_post(self, m, p, b, q):
        return self.send(200, rule_test(b.get("target") or ""))

    @api_route("/api/subs", "POST")
    def api_subs_post(self, m, p, b, q):
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

    @api_route("/api/subs", "DELETE")
    def api_subs_delete(self, m, p, b, q):
        prev = update(lambda d: d.update(subs=[s for s in d["subs"] if s["name"] != b.get("name")]))
        return self.reply(*reload_core(prev))

    @api_route("/api/nodes", "POST")
    def api_nodes_post(self, m, p, b, q):
        d = load()
        added, errs = add_links(b.get("links") or "", d["nodes"], d)
        if not added:
            return self.send(400, {"message": "没有可导入的节点" + ("：\\n" + "\\n".join(errs) if errs else "")})
        prev = update(lambda d: d["nodes"].extend(added))
        ok, msg = reload_core(prev)
        msg = (f"已导入 {len(added)} 个节点" if ok else msg) + ("；忽略：" + "；".join(errs) if errs else "")
        return self.reply(ok, msg)

    @api_route("/api/nodes", "DELETE")
    def api_nodes_delete(self, m, p, b, q):
        names = set(b.get("names") or [b.get("name")])
        prev = update(lambda d: d.update(nodes=[n for n in d["nodes"] if n["proxy"]["name"] not in names]))
        return self.reply(*reload_core(prev))

    @api_route("/api/rules", "PUT")
    def api_rules_put(self, m, p, b, q):
        rules = [r.strip() for r in b.get("rules", []) if r.strip()]
        bad = bad_rule_policies([r for r in rules if not r.startswith("#")], load())
        if bad:
            return self.send(400, {"message": "以下规则的策略不存在：" + "；".join(bad[:5])})
        prev = update(lambda d: d.update(rules=rules))
        return self.reply(*reload_core(prev))

    @api_route("/api/mode", "PUT")
    def api_mode_put(self, m, p, b, q):
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

    @api_route("/api/proxymode", "PUT")
    def api_proxymode_put(self, m, p, b, q):
        return self.set_proxy_mode(b)

    @api_route("/api/conns", "GET")
    def api_conns_get(self, m, p, b, q):
        # 精简后的连接列表：只保留前端用到的字段
        c = core_json("/connections", timeout=5)
        if c is None:
            return self.send(502, {"message": "mihomo 未运行或无法连接"})
        keep = ("sourceIP", "host", "sniffHost", "destinationIP", "destinationPort", "network")
        out = [{"id": x.get("id"), "start": x.get("start"), "upload": x.get("upload", 0), "download": x.get("download", 0),
                "rule": x.get("rule"), "rulePayload": x.get("rulePayload"), "chains": x.get("chains"),
                "metadata": {k: (x.get("metadata") or {}).get(k) for k in keep}} for x in c.get("connections") or []]
        return self.send(200, {"connections": out})

    @api_route("/api/live", "GET")
    def api_live_get(self, m, p, b, q):
        out = dict(LIVE)
        if time.time() - out["t"] > 5:  # 后台 /traffic 流未就绪（核心刚启动或已停止）时退回连接快照
            c = core_json("/connections", timeout=3)
            out.update(up=0, down=0, upTotal=(c or {}).get("uploadTotal", 0), downTotal=(c or {}).get("downloadTotal", 0))
            out["stale"] = True
        if not out["inuse"]:
            out.update(memory_once())
        out["running"] = time.time() - LIVE["t"] < 5 or bool(out.get("inuse"))
        return self.send(200, out)

    @api_route("/api/logs/info", "GET")
    def api_logs_info_get(self, m, p, b, q):
        return self.send(200, {"files": log_sizes(), "limit": load()["log_limit"], "last": LOG_STATE["last"]})

    @api_route("/api/logs/clean", "POST")
    def api_logs_clean_post(self, m, p, b, q):
        freed = log_clean(force=True)
        return self.send(200, {"message": f"已清理，释放 {fmt_size(freed)}", "files": log_sizes()})

    @api_route("/api/adblock", "GET")
    def api_adblock_get(self, m, p, b, q):
        d = load()
        meta = ab_meta()
        rep = adblock.AD_STATS.report() if adblock.AD_STATS else {"today": 0, "top": [], "lists": {}, "days": []}
        lists = [dict(l, **{k: v for k, v in (meta.get(l["id"]) or {}).items()}, hits=rep["lists"].get(l["id"], 0)) for l in d["adblock"]["lists"]]
        if active_core(d) == "singbox":  # sing-box 的 clash_api 没有规则集信息：按已转换好的规则集文件统计
            loaded = sb_ab_loaded(d) if d["adblock"].get("enabled") else {}
        else:
            prov = (core_json("/providers/rules") or {}).get("providers") or {}
            loaded = {k: v.get("ruleCount") for k, v in prov.items() if k.startswith("ad-")}
        return self.send(200, {**{k: v for k, v in d["adblock"].items() if k != "lists"}, "lists": lists,
                               "presets": AB_PRESETS, "stats": rep, "updating": AB_STATE["updating"], "msg": AB_STATE["msg"],
                               "custom_hits": rep["lists"].get("custom", 0),
                               "loaded": loaded})

    @api_route("/api/adblock", "PUT")
    def api_adblock_put(self, m, p, b, q):
        return self.save_adblock(b)

    @api_route("/api/adblock/update", "POST")
    def api_adblock_update_post(self, m, p, b, q):
        if AB_STATE["updating"]:
            return self.send(409, {"message": "正在更新中，请稍候"})
        threading.Thread(target=adblock_update, args=(b.get("ids"),), daemon=True).start()
        return self.send(200, {"message": "已开始下载，完成后自动生效"})

    @api_route("/api/adblock/check", "POST")
    def api_adblock_check_post(self, m, p, b, q):
        return self.send(200, ab_check(b.get("domain") or ""))

    @api_route("/api/dns", "PUT")
    def api_dns_put(self, m, p, b, q):
        return self.save_dns(b)

    @api_route("/api/dnsleak", "GET")
    def api_dnsleak_get(self, m, p, b, q):
        return self.send(200, leak_check(live="nolive" not in parse_qs(q)))

    @api_route("/api/history", "GET")
    def api_history_get(self, m, p, b, q):
        h = read_json(HISTORY_FILE, [])
        return self.send(200, [{"id": x["id"], "t": x["t"], "changed": x["changed"]} for x in h])

    @api_route("/api/history", "POST")
    def api_history_post(self, m, p, b, q):
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

    @api_route("/api/dnsquery", "POST")
    def api_dnsquery_post(self, m, p, b, q):
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

    @api_route("/api/devices", "GET")
    def api_devices_get(self, m, p, b, q):
        ips = set(arp_table()) | set(read_leases())
        if stats.STATS:
            with stats.STATS.lock:
                for b2 in stats.STATS.data["days"].values():
                    ips |= set(b2.get("dev", {}))
        c = core_json("/connections", timeout=5) or {}
        ips |= {(x.get("metadata") or {}).get("sourceIP") for x in c.get("connections") or []}
        return self.send(200, {"map": device_map(sorted(i for i in ips if i)), "custom": load()["devices"]})

    @api_route("/api/devices", "PUT")
    def api_devices_put(self, m, p, b, q):
        devs = {}
        for k, v in (b.get("devices") or {}).items():
            k, v = str(k).strip().lower().replace("-", ":"), str(v).strip()[:40]
            if k and v and (is_ip(k) or re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", k)):
                devs[k] = v
        update(lambda d: d.update(devices=devs))
        return self.send(200, {"message": f"已保存 {len(devs)} 个设备备注"})

    @api_route("/api/diag", "GET")
    def api_diag_get(self, m, p, b, q):
        return self.send(200, diagnose())

    @api_route("/api/schedule", "PUT")
    def api_schedule_put(self, m, p, b, q):
        sc = {}
        for k in ("sub_update", "core_restart", "geo_update"):
            v = str(b.get(k) or "").strip()
            if v and not re.fullmatch(r"([01]\\d|2[0-3]):[0-5]\\d", v):
                return self.send(400, {"message": f"时间格式应为 HH:MM：{v}"})
            sc[k] = v
        sc["latency"] = int(b.get("latency") or 0) if int(b.get("latency") or 0) in (0, 10, 30, 60, 180) else 0
        update(lambda d: d.update(schedule=sc))
        return self.send(200, {"message": "定时任务已保存"})

    @api_route("/api/schedule/run", "POST")
    def api_schedule_run_post(self, m, p, b, q):
        k = b.get("task")
        if k not in TASK_NAMES:
            return self.send(400, {"message": "未知任务"})
        ok, msg = run_task(k)
        sched_event(f"手动执行 {TASK_NAMES[k]}：{'✓' if ok else '✗'} {msg}")
        return self.reply(ok, msg)

    @api_route("/api/service", "POST")
    def api_service_post(self, m, p, b, q):
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

    @api_route("/api/settings", "PUT")
    def api_settings_put(self, m, p, b, q):
        allowed = {"rulesets", "bypass", "tests", "sub_interval", "region_groups", "ipv6", "watchdog", "tg_token", "tg_chat",
                   "log_limit", "sniffer", "gh_proxy"}
        if "gh_proxy" in b:
            b["gh_proxy"] = str(b["gh_proxy"] or "").strip()
            if b["gh_proxy"] and not re.match(r"^https?://[\\w.\\-:]+/?$", b["gh_proxy"]):
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

    @api_route("/api/https", "PUT")
    def api_https_put(self, m, p, b, q):
        on = bool(b.get("enable"))
        if on and not (os.path.isfile(CERT) and os.path.isfile(KEY)):
            ok, out = gen_cert()
            if not ok:
                return self.send(500, {"message": "生成证书失败（需要 openssl）：" + out[-200:]})
        update(lambda d: d.update(https=on))
        restart_self()
        return self.send(200, {"message": "面板将以 " + ("HTTPS" if on else "HTTP") + " 重启", "scheme": "https" if on else "http"})

    @api_route("/api/tg/test", "POST")
    def api_tg_test_post(self, m, p, b, q):
        d = load()
        if "tg_token" in b:
            d.update(tg_token=b.get("tg_token", ""), tg_chat=b.get("tg_chat", ""))
        return self.reply(*tg_send("✅ 测试消息：通知已配置成功", d))

    @api_route("/api/backup", "GET")
    def api_backup_get(self, m, p, b, q):
        d = load()
        return self.send(200, {k: v for k, v in d.items() if k != "secret"})

    @api_route("/api/restore", "POST")
    def api_restore_post(self, m, p, b, q):
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

    @api_route("/api/logticket", "POST")
    def api_logticket_post(self, m, p, b, q):
        return self.send(200, {"ticket": ticket_new()})
'''
_SRC['shunt.cli'] = '''""""""
import ipaddress, os, re, signal, ssl, sys, threading

from .errlog import log_err
from . import adblock, stats
from .base import CERT, KEY, PANEL_DIR, PORT
from .data import load, update
from .mihomo import dns_cfg
from .sb_common import active_core, write_core_file
from .sb_config import write_active_config
from .sysopt import opt_fix_ulimit, rfile, sh
from .latency import monitor_loop
from .stats import Stats
from .adblock import AdStats
from .live import live_loop
from .logclean import log_loop
from .schedule import sched_loop
from .devices import rdns_loop
from .migrate import snapshot_selections, startup_migrate
from .https import Server, gen_cert, https_ready
from .update_guard import ROLLBACK_NOTE
from .webapi import H
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
    for m in re.finditer(r"inet6 ([0-9a-fA-F:]+/\\d+)", out):
        try:
            local6.append(str(ipaddress.ip_interface(m.group(1)).network))
        except ValueError:
            pass
    return (f"B_IP='{','.join(ips)}'\\nB_MAC='{','.join(macs)}'\\nB_IP6='{','.join(ip6s)}'\\n"
            f"LOCAL6='{','.join(sorted(set(local6)))}'\\nIPV6={1 if d.get('ipv6') else 0}\\nTPROXY={1 if d.get('tproxy') else 0}\\n"
            f"MODE={d['proxy_mode']}\\nDNS_ALL={1 if dns_cfg(d)['block_bypass'] else 0}")


def main():
    """命令行入口：带参数时执行一次性命令，否则启动面板"""
    if "--bypass" in sys.argv:  # 兼容旧版 tproxy.sh
        env = dict(l.split("=", 1) for l in tp_env().splitlines())
        print(env["B_IP"].strip("'") + "|" + env["B_MAC"].strip("'"))
        sys.exit(0)
    if "--tpenv" in sys.argv:
        print(tp_env())
        sys.exit(0)
    if "--gen" in sys.argv:  # init.d/mihomo 启动前调用：按当前内核生成配置
        try:
            opt_fix_ulimit()
        except Exception as e:
            print("文件句柄修正失败：", e, file=sys.stderr)
        dd = load()
        write_core_file(active_core(dd))
        print(write_active_config(dd))
        sys.exit(0)
    if "--allow-public" in sys.argv:  # 允许 / 禁止从外网（非局域网地址）访问面板
        on = (sys.argv[sys.argv.index("--allow-public") + 1:] or ["on"])[0] in ("on", "1", "yes", "true")
        update(lambda x: x.update(allow_public=on))
        print("已允许外网访问面板（面板没有密码，请用防火墙或反向代理自行加访问控制）" if on else "已恢复为只允许局域网访问")
        sys.exit(0)
    if "--allow-host" in sys.argv:  # 允许用这个域名访问面板（DDNS、反向代理等）；--allow-host -x 删除
        args = sys.argv[sys.argv.index("--allow-host") + 1:]
        if not args:
            print("当前允许的域名：", ", ".join(load().get("allow_hosts") or []) or "（无，IP 和 .lan/.local 等局域网域名始终允许）")
            sys.exit(0)
        h = args[0].strip().lower()

        def _ah(x):
            cur = [y for y in x.get("allow_hosts") or [] if y != h.lstrip("-")]
            x["allow_hosts"] = cur if h.startswith("-") else cur + [h]
        update(_ah)
        print(("已删除 " if h.startswith("-") else "已允许 ") + h.lstrip("-"))
        sys.exit(0)
    if "--snapshot" in sys.argv:  # install.sh 升级前调用：记下各组当前选择，新配置生效后由面板恢复
        print("saved" if snapshot_selections() is not None else "skip")
        sys.exit(0)
    if "--gen-cert" in sys.argv:
        ok, out = gen_cert()
        print(out)
        sys.exit(0 if ok else 1)
    d = load()
    try:  # v6.8.2 起没有登录会话，删掉旧版留下的会话文件
        os.remove(os.path.join(PANEL_DIR, "sessions.json"))
    except FileNotFoundError:
        pass
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))  # 让 finally 有机会保存统计
    STATS = stats.STATS = Stats()
    AD_STATS = adblock.AD_STATS = AdStats()
    for target, args in ((STATS.loop, ()), (monitor_loop, ()), (AD_STATS.loop, ()), (AD_STATS.dns_loop, ()), (live_loop, ("/traffic",)),
                         (live_loop, ("/memory",)), (log_loop, ()), (sched_loop, ()), (rdns_loop, ()), (startup_migrate, ())):
        threading.Thread(target=target, args=args, daemon=True).start()
    try:
        opt_fix_ulimit()
    except Exception as e:
        log_err("文件句柄修正", e)
    if os.path.isfile(ROLLBACK_NOTE):
        log_err("面板在线更新", rfile(ROLLBACK_NOTE))
        os.remove(ROLLBACK_NOTE)
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
'''


class _Importer(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """从 _SRC 加载 shunt 包；把源码登记到 linecache，异常堆栈能显示出错的那一行"""

    @staticmethod
    def path(name):
        return name.replace(".", "/") + ("/__init__.py" if name == "shunt" else ".py")

    def find_spec(self, name, path=None, target=None):
        if name in _SRC:
            return importlib.util.spec_from_loader(name, self, origin=self.path(name), is_package=name == "shunt")
        return None

    def create_module(self, spec):
        return None

    def exec_module(self, mod):
        fn, src = self.path(mod.__name__), _SRC[mod.__name__]
        mod.__file__ = fn
        linecache.cache[fn] = (len(src), None, src.splitlines(True), fn)
        exec(compile(src, fn, "exec"), mod.__dict__)


sys.meta_path.insert(0, _Importer())
import shunt  # noqa: E402

shunt.load(os.path.abspath(__file__))
for _m in shunt._loaded:  # 兼容 `import server` / runpy 的脚本（selftest.sh、离线包构建）：所有名字在这里都能拿到
    globals().update((k, v) for k, v in vars(_m).items() if not k.startswith("__") and k != "_link")


class _Facade(types.ModuleType):
    """`server.X = ...`（测试打桩）同时改掉各模块里的同名变量"""

    def __setattr__(self, k, v):
        super().__setattr__(k, v)
        shunt.setvar(k, v)


if __name__ != "__main__" and isinstance(sys.modules.get(__name__), types.ModuleType):
    sys.modules[__name__].__class__ = _Facade

if __name__ == "__main__":
    shunt.cli.main()
