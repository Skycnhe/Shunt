"""规则工具（叶子模块）：从 mihomo.py / adblock.py 抽出的纯函数与常量。

只依赖 base、os、re；data.py、mihomo.py、adblock.py 都从这里导入，
打破 data→mihomo、mihomo→adblock 的循环。
"""
import os
import re

from .base import AB_DIR

DOMAIN_RX = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9\-]{1,59})$")


def rule_policy_index(parts):
    i = len(parts) - 1
    while i > 0 and parts[i].strip().lower() in ("no-resolve", "src"):
        i -= 1
    return i


def dns_policy_of(server):
    _, sep, tail = server.partition("#")
    if not sep:
        return ""
    # "#节点" 或 "#节点&h3=true" 之类的参数
    return tail.split("&")[0] if "=" not in tail.split("&")[0] else ""


def _mh_domain(x):
    """mihomo 域名通配（+.a.com / *.a.com / a.*.com）→ (sing-box 字段, 值)"""
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
