"""生成 sing-box 配置"""
import ipaddress, json, os, re, signal, threading, time, urllib.request, urllib.error

from .base import (
    AB_DIR, BUILTIN_POLICIES, CTRL_HOST, CTRL_PORT, G_OTHER, G_SEL, MIHOMO_LOG, MIXED, REGIONS, SVC, UA,
    dl_check,
)
from .data import auto_name, lb_dropped_names, lb_names, lb_old_name, load, safe, write_json
from .groups import PROV, gcfg, rx
from .mihomo import BUILTIN_GEO, build_config, build_rule_providers, dns_cfg, policy_parts, tun_params, write_config
from .corehttp import core_json
from .sb_common import CORE_PID, SB_BIN, SB_CONF, SB_DIR, SB_RULE_DIR, SB_STATE, active_core
from .sb_yaml import yaml_lite
from .groups import sb_provider_nodes, sb_sub_cache, sb_sub_outbounds
from .sb_nodes import sb_outbound
from .sb_rules import SBRules, geo_srs_entry
from .ruleutil import _mh_domain
from .sb_dns import sb_dns
from .sysopt import nft_ok, proxy_opener, sh
from .notify import core_alive
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
            act = tr.action(line.split(",", 1)[1])
            final = act.get("outbound", "DIRECT") if act else "DIRECT"
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
    tp = tun_params(d)  # TUN 决策与 mihomo_tun 共用；auto_redirect 另需 nftables 可用
    if tp["enable"]:
        tun = {"type": "tun", "tag": "tun-in", "interface_name": tp["device"], "address": ["172.19.0.1/30"] + (["fdfe:dcba:9876::1/126"] if v6 else []),
               "auto_route": True, "auto_redirect": tp["auto_redirect"] and nft_ok(), "strict_route": tp["strict_route"],
               "stack": tp["stack"]}
        inbounds.append(tun)
    return inbounds


def sb_geo_rule_sets(d, dc=None):
    """显式计算 sing-box 需要的 GEO 规则集条目（{tag: {kind:url:path}}）。

    之前这些条目靠完整 build_singbox 的副作用产生：SBRules.use_geo 在翻译 GEOSITE/GEOIP 规则、
    sb_dns 在生成 DNS 策略时把它们塞进共用的 rule_sets 字典。这里逐条复刻那两个地方的逻辑，
    供轻量路径（sb_rule_need）使用，避免为取 [2] 而重跑整个构建。
    """
    dc = dc or dns_cfg(d)
    geos = {}

    def add(kind, name):
        if kind == "geoip" and name.lower() in ("private", "lan"):
            return  # 翻译成 ip_is_private，不产生规则集条目
        tag, entry = geo_srs_entry(kind, name)
        if tag not in geos:
            geos[tag] = entry

    for kind, name in BUILTIN_GEO:  # mihomo_rules 末尾硬编码分流规则
        add(kind, name)
    for line in d.get("rules") or []:  # 用户自定义规则里的 GEOSITE/GEOIP（fix_rule_policy 只换 target，不过滤）
        parts = str(line).split(",")
        if len(parts) >= 2 and parts[0].strip().upper() in ("GEOSITE", "GEOIP"):
            add(parts[0].strip().lower(), parts[1].strip())
    for pe in dc.get("policies") or []:  # sb_dns.policy_cond：DNS 策略里的 geosite 匹配
        kind, names = policy_parts(pe["match"])
        if kind == "geosite":
            for n in names:
                add("geosite", n)
    add("geosite", "cn")  # sb_dns.cn_cond：固定加入
    add("geosite", "private")
    for x in dc.get("fake_filter") or []:  # sb_dns：fake-ip 过滤里的 geosite:
        if x.lower().startswith("geosite:"):
            add("geosite", x[8:])
    return geos


def sb_rule_need(d):
    """轻量计算 sing-box 规则集需求表（等价于 build_singbox(d)[2]）：只依赖 d，不跑完整构建。
    之前多处为取 [2] 而重跑整个 build_singbox（含 build_config、节点/策略组/outbound 全量计算）。
    由 rule-providers 条目 + 显式计算的 GEO 条目组成，与完整构建的 [2] 逐项一致
    （含 SBRules.use_geo / sb_dns 副作用加入的 geo 条目；同完整构建一样过滤掉 kind=="inline"，内嵌规则集无需下载）。"""
    dc = dns_cfg(d)
    need = sb_rule_sets({"rule-providers": build_rule_providers(d, dc)[0]}, [])
    need.update(sb_geo_rule_sets(d, dc))
    return {tag: rsd for tag, rsd in need.items() if rsd["kind"] != "inline"}


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
    for tag, rsd in sb_rule_need(d).items():
        if rsd.get("kind") == "adblock":
            path = os.path.join(SB_RULE_DIR, rsd["path"])
            if os.path.isfile(path) and os.path.getsize(path) > 0:
                out[tag] = sb_rule_count(path)
    return out


def sb_sync_assets(d, force=False, need=None):
    """下载 / 转换 sing-box 需要的规则集文件；返回失败列表"""
    if need is None:
        need = sb_rule_need(d)
    gh = (d.get("gh_proxy") or "").rstrip("/")
    os.makedirs(SB_RULE_DIR, exist_ok=True)
    bad = []
    bad_lock = threading.Lock()

    def one(tag, rsd):
        """单个规则集：下载 / 转换 / 写文件（每个规则集独立文件，线程间无冲突）"""
        path = os.path.join(SB_RULE_DIR, rsd["path"])
        try:
            if rsd["kind"] == "adblock":
                if os.path.isfile(rsd["src"]) and (force or not os.path.isfile(path) or os.path.getmtime(rsd["src"]) > os.path.getmtime(path)):
                    write_json(path, sb_adblock_source(rsd["src"]))
                return
            if os.path.isfile(path) and os.path.getsize(path) > 0 and not force:
                return
            urls = ([gh + "/" + rsd["url"]] if gh and "github" in rsd["url"] else []) + [rsd["url"]]
            data, err = None, ""
            for u in urls:
                for use_proxy in ((True, False) if core_alive() else (False,)):
                    try:
                        dl_check(u, via_proxy=use_proxy)  # SSRF 防护：直连时校验 DNS，走代理时由代理解析（字面内网 IP 永远拦截）
                    except IOError as e:
                        err = str(e)[:120]
                        continue
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
            with bad_lock:
                bad.append(f"{tag}：{e}")

    ths = [threading.Thread(target=one, args=(tag, rsd)) for tag, rsd in need.items()]
    for t in ths:
        t.start()
    for t in ths:
        t.join(150)
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
            return re.sub(r"^(\S+\s+){0,3}(FATAL|ERROR)(\[\d+\])?\s*", "", line.strip())[-200:]
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
    need = sb_rule_need(d)
    for r in d.get("rulesets") or []:
        rsd = need.get(r["name"])
        path = os.path.join(SB_RULE_DIR, rsd["path"]) if rsd else ""
        mt = os.path.getmtime(path) if path and os.path.isfile(path) else 0
        out[r["name"]] = {"name": r["name"], "type": "Rule", "vehicleType": "HTTP", "behavior": r.get("behavior", "domain").capitalize(),
                          "ruleCount": 0, "updatedAt": iso_utc(mt) if mt else ""}
    return {"providers": out}

