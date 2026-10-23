"""生成配置"""
import ipaddress, json, os, re, threading

from .base import (
    AUTO_ORDER, BUILTIN_POLICIES, CN_APP_DOMAINS, CONF_DIR, CTRL_HOST, CTRL_PORT, DEFAULT_EXCLUDE, DNS_DEFAULT, DNS_LISTS, DOH_DOMAINS, DOH_IPS, G_AI,
    G_AUTO, G_DIRECT, G_FINAL, G_GG, G_MANUAL, G_NF, G_SEL, G_TG, G_YT, HC, LAN_IN, LB_ORDER, LGBM_URL, MIHOMO_BIN, MIXED, SIDE_GROUPS, SMART_BIN,
    TUN_DEFAULT, TUN_STACKS
)
from .data import LB_KINDS, auto_name, lb_name, region_label, safe
from .devroute import device_route_rules, note_written
from .groups import clean_custom_group, gcfg, group_opts, names_rx, pick_plan, region_plan, rx, rx_or, sub_orig_nodes, sub_removed
from .ruleutil import DOMAIN_RX, adblock_providers, complete_rule, dns_policy_of, rule_policy_index
from .sb_common import active_core
from .sysopt import sh


def drop_provider_cache(name):
    """删掉订阅在 mihomo 里的本地缓存 ./providers/<名>.yaml。
    mihomo 加载 provider 时只要本地文件存在就先用它，按文件修改时间等满一个更新间隔才去下载，不看地址变没变：
    改了订阅链接（换机场 / 重置 token）或删掉后用同名重新添加，以前要等到间隔（默认 24 小时）才换成新链接的节点"""
    try:
        os.remove(os.path.join(CONF_DIR, "providers", safe(name) + ".yaml"))
        return True
    except OSError:
        return False


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
        gone = sub_removed(s)
        if gone:  # 用户从订阅里删除的节点：按原名精确排除，与订阅自己的排除正则取并集
            exc = rx_or(exc, names_rx(gone))
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
    orig = None
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
        uflt = cg["filter"] if cg["filter"] and cg["subs"] and use else ""
        picks = {}
        if cg["sub_nodes"] and use:
            if orig is None:
                orig = sub_orig_nodes(d)
            picks = pick_plan(d, cg, orig)
        if uflt or picks:
            # mihomo 的 proxies 里不能写订阅节点名：勾选的订阅节点用 use（只引用涉及的订阅）+ 精确匹配的 filter 表达；
            # filter 只作用于 use 引用的订阅，手动节点照常写在 proxies 里。同时有用户正则时两者取并集，用户正则原有的语义不变
            g["use"] = list(use) if uflt else [s for s in use if s in picks]
            g["filter"] = rx_or(uflt, names_rx([n for v in picks.values() for n in v]) if picks else "")
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
        # store-fake-ip 关闭：开启时 mihomo 每次热重载（PUT /configs）都会丢掉旧的 fake-ip 映射，客户端还在用缓存的旧 fake IP
        # 时（系统 / 浏览器 DNS 缓存、长连接重连）连接被丢弃，非嗅探端口直到重新解析前都不通；Hk002 的保存设置、订阅变化、
        # 按设备分流 MAC 变化都会热重载。关闭后（mihomo v1.19.33 起）热重载保留映射，代价是核心重启后映射清空、从头分配
        "profile": {"store-selected": True, "store-fake-ip": False},
        # skip-domain：米家设备连云端的 TLS 握手里 SNI 是「Mijia Cloud」，嗅探后按这个假域名改写目标会连不上，设备频繁离线；
        # Apple 推送长连接被嗅探改写后会断开重连，消息推送延迟。两者都是 mihomo 官方示例里的跳过项
        "sniffer": {"enable": bool(d.get("sniffer", True)), "skip-domain": ["Mijia Cloud", "+.push.apple.com"], "sniff": {
            "HTTP": {"ports": [80, "8080-8880"], "override-destination": True},
            "TLS": {"ports": [443, 8443]}, "QUIC": {"ports": [443, 8443]}}},
        "dns": dns, "tun": tun, "hosts": hosts,
        "proxies": proxies,
        "proxy-providers": providers, "rule-providers": rule_providers, "proxy-groups": groups, "rules": rules,
    })

def build_rule_providers(d, dc):
    """rule-providers 段：规则集 + 广告拦截 + DNS 防绕过 → (rule-providers, 广告拦截 providers, 广告拦截 rules)。
    mihomo_rules 与 sing-box 轻量路径（sb_rule_need）共用，后者不再为取规则集需求表而跑完整 build_config。"""
    rule_providers = {}
    for r in d.get("rulesets", []):
        ext = {"mrs": "mrs", "text": "list"}.get(r.get("format"), "yaml")
        rule_providers[r["name"]] = {"type": "http", "behavior": r.get("behavior", "domain"), "format": r.get("format", "yaml"),
                                     "url": r["url"], "path": f"./rules/{safe(r['name'])}.{ext}", "interval": 86400}
    ab_prov, ab_rules = adblock_providers(d)
    rule_providers.update(ab_prov)
    rule_providers["cn-apps"] = {"type": "inline", "behavior": "domain", "payload": list(CN_APP_DOMAINS)}
    if dc["block_bypass"]:  # 阻止局域网设备绕过 mihomo DNS：拒绝 DoT/DoQ(853) 与已知公共 DoH 服务器
        rule_providers["dns-bypass-ip"] = {"type": "inline", "behavior": "ipcidr", "payload": list(DOH_IPS)}
        rule_providers["dns-bypass-domain"] = {"type": "inline", "behavior": "domain", "payload": list(DOH_DOMAINS)}
    return rule_providers, ab_prov, ab_rules


# 内置规则里的 GEOSITE/GEOIP（kind, 值）：sing-box 需为它们下载 .srs。
# 与下面 mihomo_rules 末尾硬编码列表保持一致；SBRules.use_geo 在翻译时把它们加入 [2]，sb_geo_rule_sets 显式计算供轻量路径使用。
# 注意 GEOIP,private 不会产生条目（翻译成 ip_is_private），这里保留仅作对照。
BUILTIN_GEO = (
    ("geosite", "private"), ("geoip", "private"),
    ("geosite", "category-ai-!cn"),
    ("geosite", "netflix"), ("geoip", "netflix"),
    ("geosite", "youtube"), ("geosite", "google"), ("geoip", "google"),
    ("geosite", "telegram"), ("geoip", "telegram"),
    ("geosite", "geolocation-!cn"), ("geosite", "cn"), ("geoip", "CN"),
)


def mihomo_rules(d, policies, dc):
    """规则集、TUN 绕过、广告拦截、防绕过 DNS、自定义规则与内置分流规则 → (rule-providers, rules, 广告拦截 providers)"""
    rule_providers, ab_prov, ab_rules = build_rule_providers(d, dc)
    rs_rules = []
    for r in d.get("rulesets", []):
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
    guard = []
    if dc["block_bypass"]:
        guard = [f"AND,(({LAN_IN}),(DST-PORT,853)),REJECT",
                 f"AND,(({LAN_IN}),(DST-PORT,443),(RULE-SET,dns-bypass-ip,no-resolve)),REJECT",
                 f"AND,(({LAN_IN}),(RULE-SET,dns-bypass-domain)),REJECT"]
    # 按设备分流：排在 TUN 绕过、DNS 防绕过、广告拦截之后，其余规则之前；前面先放局域网直连，
    # 被分流到代理 / 拦截的设备仍能访问局域网（TUN 模式下局域网流量也会进核心）
    dev = device_route_rules(d, policies)
    lan = ["GEOSITE,private,DIRECT", "GEOIP,private,DIRECT,no-resolve"] if dev else []
    rules = pre + guard + lan + ab_rules + dev + [x for x in custom if x] + rs_rules + [
        "GEOSITE,private,DIRECT", "GEOIP,private,DIRECT,no-resolve", "RULE-SET,cn-apps,DIRECT",
        f"GEOSITE,category-ai-!cn,{G_AI}", f"GEOSITE,netflix,{G_NF}", f"GEOIP,netflix,{G_NF},no-resolve",
        f"GEOSITE,youtube,{G_YT}", f"GEOSITE,google,{G_GG}", f"GEOIP,google,{G_GG},no-resolve",
        f"GEOSITE,telegram,{G_TG}", f"GEOIP,telegram,{G_TG},no-resolve",
        f"GEOSITE,geolocation-!cn,{G_SEL}", "DOMAIN-SUFFIX,dangbei.com,DIRECT",
        "GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT", f"MATCH,{G_FINAL}",
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
        pol.setdefault("rule-set:cn-apps", direct)
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


def tun_params(d):
    """TUN 参数归一化：mihomo_tun 与 sing-box sb_inbounds 共用同一决策（是否启用、协议栈回退、设备名、开关量）。"""
    tc = d.get("tun") or TUN_DEFAULT
    return {
        "enable": d.get("proxy_mode") == "tun",
        "stack": tc.get("stack") if tc.get("stack") in TUN_STACKS else "mixed",
        "device": safe_dev(tc.get("device")),
        "auto_redirect": bool(tc.get("auto_redirect", True)),
        "strict_route": bool(tc.get("strict_route", False)),
    }


def mihomo_tun(d):
    p = tun_params(d)
    if not p["enable"]:
        return {"enable": False}
    return {"enable": True, "stack": p["stack"], "device": p["device"], "auto-route": True,
            "auto-redirect": p["auto_redirect"], "auto-detect-interface": True, "dns-hijack": ["any:53", "tcp://any:53"],
            "strict-route": p["strict_route"]}



def fix_rule_policy(rule, policies):
    """自定义规则引用了不存在的策略组时改用节点选择，避免整份配置无法加载"""
    rule = complete_rule(rule.strip(), G_SEL)
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
    final = os.path.join(CONF_DIR, "config.yaml")
    path = path or final
    write_atomic(path, build_config(d))  # JSON 是 YAML 的子集，mihomo 可直接读取
    note_written(path, final)
    return path


def write_atomic(path, obj):
    """先生成内容、写临时文件再改名：生成配置抛异常或写到一半断电时，原来的配置文件保持完整。
    以前先 open(path, "w") 截断再生成，build 一出错（坏数据 / 回滚时旧数据也生成不了）正式配置就变成空文件，核心起不来"""
    text = json.dumps(obj, ensure_ascii=False, indent=2)
    tmp = f"{path}.tmp{os.getpid()}-{threading.get_ident()}"
    try:
        with open(tmp, "w") as f:
            f.write(text)
        try:  # 沿用原文件权限（以前是原地覆盖，权限不变）
            os.chmod(tmp, os.stat(path).st_mode & 0o777)
        except OSError:
            pass
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


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
    return False, "\n".join(lines[-3:]) or out[-400:]

