"""基础常量与通用工具"""
import shunt
import ipaddress
import os, threading, re
import secrets
import socket
import time
import urllib.error
import urllib.request
from collections import deque
from urllib.parse import urlsplit

BASE = os.path.dirname(os.path.abspath(shunt.SERVER_FILE))  # 面板文件所在目录（index.html、tproxy.sh 等）
CONF_DIR = os.environ.get("MIHOMO_DIR", "/etc/mihomo")
DATA_FILE = os.environ.get("PANEL_DATA", "/etc/mihomo-panel/data.json")
LGBM_URL = os.environ.get("SMART_REPO", "https://github.com/vernesong/mihomo/releases") + "/download/LightGBM-Model/Model.bin"
UPD_STATE = {"busy": False}  # 面板在线更新忙标志：panel_update 与 core_update 共用，避免循环导入
WD_HOLD = {"until": 0.0, "why": ""}  # 面板自己在重启 / 重载核心：这段时间内看门狗不判定故障（sysopt.svc_restart、sb_hot_reload 置位）


def wd_hold(sec, why="", reset=False):
    """reset=True：直接改成「从现在起 sec 秒」，用于重启命令返回后缩短暂停期"""
    import time as _t
    t = _t.time() + sec
    WD_HOLD["until"] = t if reset else max(WD_HOLD["until"], t)
    WD_HOLD["why"] = why


CORE_UPD = {"busy": False, "stage": "", "pct": 0, "ok": None, "message": "", "log": deque(maxlen=30), "t": 0}  # 内核更新状态：core_update 与 notify 共用
MASS_TEST = {"n": 0}  # 进行中的全节点测速（/group/*/delay）计数：corehttp 置位，notify 看门狗据此暂停故障判定，避免高负载误判


def local_file(f):
    """部署文件 f 的本地路径（init.d/ 下的优先用 /etc/init.d/ 的系统版本）"""
    if f.startswith("init.d/"):
        sysf = "/etc/init.d/" + f[7:]
        return sysf if BASE == "/opt/mihomo-panel" and os.path.isfile(sysf) else os.path.join(BASE, f)
    return os.path.join(BASE, f)


def udp_dns_query(name, port=1053, host="127.0.0.1", timeout=8):
    """向本机 DNS 端口发一个 A 记录查询；收到同 ID 的应答（含 NXDOMAIN）即视为成功"""
    qid = secrets.randbits(16)
    pkt = qid.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for lab in name.strip(".").split("."):
        b = lab.encode("idna") if lab else b""
        pkt += bytes([len(b)]) + b
    pkt += b"\x00\x00\x01\x00\x01"
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

# v7.7.6 起服务名为 shunt（面板）/ shunt-core（核心）；还没迁移的旧设备仍是 mihomo-panel / mihomo（svcmigrate.py 负责迁移）
SVC_NEW = os.path.isfile("/etc/init.d/shunt-core")
CORE_SVC = "shunt-core" if SVC_NEW else "mihomo"
PANEL_SVC = "shunt" if os.path.isfile("/etc/init.d/shunt") else "mihomo-panel"
SVC = os.environ.get("PANEL_SVC", "rc-service " + CORE_SVC)  # 核心服务控制命令（测试环境可覆盖）
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
    {"name": "淘宝", "url": "https://www.taobao.com"},
]
G_SEL, G_YT, G_GG, G_TG, G_FINAL = "🚀 节点选择", "📹 YouTube", "🔍 Google", "📲 Telegram", "🐟 漏网之鱼"
G_AI, G_NF = "🤖 AI 服务", "🎬 Netflix"
G_MANUAL, G_AUTO, G_DIRECT = "\U0001F590\uFE0F 手动选择", "⚡ 全局自动选择", "🏠 直连"
LB_PREFIX, AUTO_TAIL, LB_TAIL = "\u2696\uFE0F ", "竞技", "负载均衡"
AUTO_TAIL_OLD = "自动优选"  # v6–v6.7.2 的地区组后缀，v6.7.3 改为「竞技」，仅用于迁移
LEGACY_AUTO = "♻️ 自动选择"  # v5 及以前的名称，读取旧数据时自动迁移
AUTO_ORDER = ["日本", "新加坡", "香港", "美国"]  # 「自动优选」组在节点选择中的顺序，其余地区按识别顺序排在后面
LB_ORDER = ["香港", "日本", "新加坡", "美国"]    # 「负载均衡」组的顺序
SCHEMA = 9
PANEL_VERSION = "7.9.3"
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
# 直连测速用国内地址（DIRECT 是国内直连，测谷歌没有意义）；第一个不可用时试下一个
# 直连测速地址：与概览「百度」卡片同一个地址、同一种测法，两处数字才可比
DIRECT_HC = "https://www.baidu.com"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"


# Fake-IP 网段：路由器自己用本机 DNS 时，公网域名会解析成这些地址，连接由 mihomo / sing-box 接管并按真实域名转发，
# 不是内网目标，SSRF 校验放行（否则开着 Fake-IP 时在线更新、订阅下载直连全被误拦）
FAKEIP_NETS = (ipaddress.ip_network("198.18.0.0/15"), ipaddress.ip_network("fc00::/18"), ipaddress.ip_network("fdfe:dcba:9876::/64"))


def url_host_forbidden(url, via_proxy=False):
    """SSRF 防护：下载类 URL 的目标主机必须解析到公网地址。

    命中以下任一情况返回 True（禁止）：无主机名 / localhost / 字面内网 IP /
    （直连时）DNS 解析失败或解析出的任一 IP 不是公网地址（内网、回环、链路本地、保留、组播等；Fake-IP 网段除外）。
    via_proxy=True（经 mihomo 代理下载）时跳过 DNS 校验：DNS 由代理自己解析，
    本地校验无意义，且在 DNS 受干扰的环境（如国内）会误伤合法下载；字面 IP 仍拦截。
    注意：检查与实际建连之间存在 DNS TOCTOU 窗口，这里只防住直接的内网目标。"""
    try:
        host = (urlsplit(url).hostname or "").strip().lower().rstrip(".")
    except Exception:
        return True
    if not host or host == "localhost":
        return True
    try:
        return not ipaddress.ip_address(host).is_global  # 字面 IP：无需 DNS，直接判定
    except ValueError:
        pass
    if via_proxy:
        return False
    try:
        addrs = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return True
    for _, _, _, _, sa in addrs:
        try:
            ip = ipaddress.ip_address(sa[0])
        except ValueError:
            return True
        if not ip.is_global and not any(ip in n for n in FAKEIP_NETS):
            return True
    return False


def dl_check(url, via_proxy=False):
    """下载入口统一校验：目标非公网地址时抛 IOError（调用方已有通用异常处理）"""
    if url_host_forbidden(url, via_proxy=via_proxy):
        raise IOError(f"目标地址非公网，已拦截（SSRF 防护）：{urlsplit(url).hostname}")


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """跟随重定向前校验目标主机，防止 302 跳到内网（urllib 默认无条件跟随）"""

    def __init__(self, via_proxy=False):
        self._via_proxy = via_proxy

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if url_host_forbidden(newurl, via_proxy=self._via_proxy):
            raise urllib.error.HTTPError(newurl, 403, "重定向目标非公网地址，已拦截（SSRF 防护）", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)
