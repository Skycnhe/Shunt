"""规则工具（叶子模块）：从 mihomo.py / adblock.py 抽出的纯函数与常量。

只依赖 base、os、re；data.py、mihomo.py、adblock.py 都从这里导入，
打破 data→mihomo、mihomo→adblock 的循环。
"""
import ipaddress
import os
import re

from .base import AB_DIR

DOMAIN_RX = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9\-]{1,59})$")


def rule_policy_index(parts):
    i = len(parts) - 1
    while i > 0 and parts[i].strip().lower() in ("no-resolve", "src"):
        i -= 1
    return i


# 「类型,值,策略」中值后面必须跟策略的规则类型（MATCH / 逻辑规则除外）
RULE_TYPES = frozenset("""DOMAIN DOMAIN-SUFFIX DOMAIN-KEYWORD DOMAIN-REGEX DOMAIN-WILDCARD GEOSITE GEOIP IP-CIDR IP-CIDR6 IP-SUFFIX
IP-ASN SRC-GEOIP SRC-IP-ASN SRC-IP-CIDR SRC-IP-SUFFIX DST-PORT SRC-PORT IN-PORT IN-TYPE IN-USER IN-NAME PROCESS-NAME
PROCESS-PATH PROCESS-NAME-REGEX PROCESS-PATH-REGEX UID NETWORK DSCP RULE-SET USER-AGENT URL-REGEX""".split())


def complete_rule(rule, default):
    """「DOMAIN-SUFFIX,a.com」「IP-CIDR,1.2.3.4/32,no-resolve」这类没写目标策略的规则补上 default。
    以前会把值（a.com）当成策略名：保存时报「策略不存在」，备份恢复 / 手改 data.json 的则被换成节点选择、值丢失"""
    s = rule.strip()
    if not s or s.startswith("#"):
        return rule
    parts = s.split(",")
    if parts[0].strip().upper() in RULE_TYPES and rule_policy_index(parts) <= 1 and len(parts) >= 2 and parts[1].strip():
        parts.insert(2, default)
        return ",".join(parts)
    return rule


def norm_rule(rule):
    """规范化自定义规则里两种内核都会「静默不生效」的写法（v8.4.15）：
    - DOMAIN-SUFFIX 的值带前导「.」「+.」「*.」：mihomo 按字面匹配，永远命中不了（sing-box 只去掉了「.」，「+.」「*.」同样失效）
      → 去掉前缀（后缀规则本来就含域名自身及所有子域）
    - DOMAIN 的值以「+.」「.」开头：同样永不命中 → 改成 DOMAIN-SUFFIX
    - IP-CIDR / IP-CIDR6 / SRC-IP-CIDR 只写了单个 IP（没有 /前缀）：mihomo 整份配置校验失败（payloadRule error）
      → 补 /32 或 /128
    逻辑规则（AND / OR / NOT）、注释、空行原样返回"""
    s = rule.strip()
    if not s or s.startswith("#"):
        return rule
    parts = s.split(",")
    if len(parts) < 2:
        return rule
    typ, val = parts[0].strip().upper(), parts[1].strip()
    if typ == "DOMAIN" and val.startswith(("+.", ".")) and val.lstrip("+.").strip():
        parts[0], typ = "DOMAIN-SUFFIX", "DOMAIN-SUFFIX"
    if typ == "DOMAIN-SUFFIX":
        v = val
        while v.startswith(("+.", "*.", ".")):
            v = v[2:] if v[:2] in ("+.", "*.") else v[1:]
        if v and v != val:
            parts[1] = v
    elif typ in ("IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR") and "/" not in val:
        try:
            ip = ipaddress.ip_address(val.strip("[]"))
            parts[1] = f"{ip}/{32 if ip.version == 4 else 128}"
        except ValueError:
            pass
    return ",".join(parts)


def dns_policy_of(server):
    _, sep, tail = server.partition("#")
    if not sep:
        return ""
    # "#节点" 或 "#节点&h3=true" 之类的参数
    return tail.split("&")[0] if "=" not in tail.split("&")[0] else ""


def _mh_domain(x):
    """mihomo 域名通配（+.a.com / *.a.com / a.*.com）→ (sing-box 字段, 值)"""
    x = x.strip().lower()
    pre = ""
    if x.startswith("+."):  # 自身及所有子域
        x, pre = x[2:], r"(?:[^.]+\.)*"
    elif x.startswith("."):  # 只匹配子域（mihomo 语义，不含自身）
        x, pre = x[1:], r"(?:[^.]+\.)+"
    if "*" in x:  # 含通配：只能用正则，否则 domain_suffix 会把「stun.*.*」当成字面量，永远匹配不到
        return "domain_regex", "^" + pre + re.escape(x).replace(r"\*", r"[^.]+") + "$"
    if pre:
        return "domain_suffix", x if pre.endswith("*") else "." + x
    return "domain", x


def _rs_tag(kind, name):
    return f"{kind}-{name}".lower() if kind in ("geosite", "geoip") else name


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
