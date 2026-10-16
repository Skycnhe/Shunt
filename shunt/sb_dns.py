"""DNS"""
import re
from urllib.parse import urlsplit

from .base import DNS_DEFAULT
from .mihomo import dns_cfg, fix_dns_policy, is_ip_addr, policy_parts
from .ruleutil import _mh_domain, dns_policy_of
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
        # v7.5.9 曾把范围从 198.18.0.0/15 缩小到 /16，导致老版本分配的 198.19.x.x 映射变孤儿
        # （sing-box 不认识 → missing fakeip record）。/15 是 /16 的超集，含 198.18.x 和 198.19.x
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
        # TTL 改成 1（与 mihomo 的 fake-ip 一致）：sing-box 默认 600 秒，内核被强制结束或切换内核后映射丢失时，
        # 客户端还会拿缓存的 198.18.x 连 10 分钟，日志刷「missing fakeip record」，期间这些网站都打不开
        rules.append({"query_type": ["A", "AAAA"], "action": "route", "server": "dns-fake", "rewrite_ttl": 1})
    if dc["policy"] and t_proxy:
        rules.append(dict(cn_cond, action="route", server=t_direct))
    out = {"servers": servers, "rules": rules, "final": final, "strategy": "prefer_ipv4" if v6 else "ipv4_only",
           "cache_capacity": 4096}
    return out, t_node, t_direct, t_proxy

