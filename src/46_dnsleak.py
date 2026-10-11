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


