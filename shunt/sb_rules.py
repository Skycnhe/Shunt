"""规则：mihomo 规则字符串 → sing-box 路由规则"""
import re

from .ruleutil import _mh_domain, _rs_tag, rule_policy_index
from .sb_common import SB_GEO


def geo_srs_entry(kind, name):
    """GEOIP/GEOSITE → (tag, 规则集条目)。SBRules.use_geo 与 sb_geo_rule_sets 共用，避免两处硬编码同一 URL 格式。"""
    tag = _rs_tag(kind, name)
    return tag, {"kind": "geo", "url": f"{SB_GEO}/{kind}/{name.lower()}.srs", "path": f"{kind}-{name.lower()}.srs"}


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
        tag, entry = geo_srs_entry(kind, name)
        if tag not in self.rule_sets:
            self.rule_sets[tag] = entry
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
