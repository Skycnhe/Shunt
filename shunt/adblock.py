"""广告拦截（AdGuard Home 风格的域名过滤）"""
import copy, hashlib, ipaddress, json, os, re, secrets, threading, time, urllib.request, urllib.error
from collections import deque
from urllib.parse import quote

from .errlog import log_err
from .base import AB_DIR, AB_STATS_FILE, CONF_DIR, FAKEIP_NETS, UA, dl_check, udp_dns_query
from .data import load, read_json, write_json
from .mihomo import build_config
from .core import reload_core
from .corehttp import core
from .sb_common import active_core
from .sb_config import sb_sync_assets
from .sysopt import proxy_opener
from .ruletest import clean_target
from .logstream import core_stream
from .ruleutil import DOMAIN_RX, adblock_providers
# 订阅 AdGuard/ABP（||domain^、@@||domain^）、hosts（0.0.0.0 domain）与纯域名列表，转换为 mihomo
# behavior=domain / format=text 的本地 rule-provider 文件：
#   ||a.com^ → "+.a.com"（含子域）；hosts / 纯域名 → "a.com"（仅该域名，与 AdGuard Home 语义一致）
# 规则：AND,((RULE-SET,ad-xxx),(NOT,((RULE-SET,ad-allow)))),REJECT  —— 白名单优先，且被放行的域名继续走正常分流
CLASH_RX = re.compile(r"^(domain|domain-suffix),([^,\s]+)(?:,.*)?$")
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
        if low.startswith("payload:"):
            continue
        if low.startswith("- "):  # Clash YAML payload：  - DOMAIN-SUFFIX,a.com / - '+.a.com'
            low = low[2:].strip().strip("'\"")
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
            dl_check(url, via_proxy=use_proxy)  # SSRF 防护：直连时校验 DNS，走代理时由代理解析（字面内网 IP 永远拦截）
        except IOError as e:
            err = str(e)[:160]
            continue
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


def ab_fetch(lst, late=None):
    """下载并转换一个列表，写入 <id>.txt / <id>.allow.txt，返回 meta。late 置位（整体超时）后不再写文件"""
    text = download(lst["url"])
    bs, be, as_, ae, skipped = parse_filter(text)
    lines, n = domain_lines(bs, be)
    alines, na = domain_lines(as_, ae)
    if not n and not na:
        raise ValueError("没有解析出任何域名，确认是 AdGuard / hosts / 域名列表格式")
    if late is not None and late.is_set():
        raise IOError("下载超时")
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


AB_WAIT = 150  # 并发下载广告列表整体最多等这么多秒


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
        res_lock = threading.Lock()
        late = threading.Event()

        def fail(l, err):
            m = dict(meta.get(l["id"]) or {})
            m.update(error=err, checked=int(time.time()))
            return m

        def one(l):
            try:
                r = ab_fetch(l, late)
            except Exception as e:
                r = fail(l, str(e)[:200])
            with res_lock:
                if not late.is_set():
                    res[l["id"]] = r
        ths = [threading.Thread(target=one, args=(l,), daemon=True) for l in lists]
        [t.start() for t in ths]
        end = time.time() + AB_WAIT  # 整体最多等 AB_WAIT 秒（以前逐个 join(150)，几个列表都卡住时要等 N×150 秒）
        [t.join(max(0.1, end - time.time())) for t in ths]
        with res_lock:  # 之后迟到的线程既不写列表文件也不改结果，meta 与磁盘上的文件一致
            late.set()
            res = dict(res)
            for l in lists:
                if l["id"] not in res:
                    res[l["id"]] = fail(l, "下载超时")
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


AB_CACHE = {}  # 列表路径 → (mtime, 后缀集合, 精确集合)：只给「查询域名」用，空闲 AB_IDLE 秒后整体释放
AB_IDLE = 300
_AB_GC = {"last": 0.0, "timer": None}
_AB_GC_LOCK = threading.Lock()


def _ab_touch():
    """记一次使用；没有待执行的释放定时器就起一个。几十万条的 HaGeZi / anti-AD 列表转成 set 要占几十 MB，
    以前查一次就常驻到下次更新，现在 5 分钟没人查就释放"""
    with _AB_GC_LOCK:
        _AB_GC["last"] = time.time()
        if _AB_GC["timer"] is None:
            _ab_arm(AB_IDLE)


def _ab_arm(delay):
    t = threading.Timer(delay, _ab_gc)
    t.daemon = True
    _AB_GC["timer"] = t
    t.start()


def _ab_gc():
    with _AB_GC_LOCK:
        left = _AB_GC["last"] + AB_IDLE - time.time()
        if left > 1:
            _ab_arm(left)
            return
        _AB_GC["timer"] = None
        AB_CACHE.clear()


def ab_sets(path):
    try:
        mt = os.path.getmtime(path)
    except OSError:
        return set(), set()
    _ab_touch()
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
    if not isinstance(target, str):
        raise ValueError("请输入有效域名")
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


def is_fake_ip(host):
    """Fake-IP 网段（198.18.0.0/15 等）的地址：没反查到域名的连接，不能当成「被拦截的域名」进排行"""
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return any(ip in n for n in FAKEIP_NETS)


class AdStats:
    """订阅 mihomo info 日志，统计命中广告规则 (REJECT) 的连接；另按小时统计全部连接请求数、拦截数和 DNS 解析耗时（概览「域名过滤」）"""
    RX = re.compile(r"--> (\S+?):\d+ match .*?RuleSet[,(](ad-[0-9a-z]+)\).* using REJECT")
    RX_ALL = re.compile(r"--> \S+ (?:match|doesn't match)")
    REQ_BATCH = 100  # req 计数攒批：攒够这么多行或持锁时一次性合并，减少逐行加锁

    def __init__(self):
        self.lock = threading.Lock()
        self.data = read_json(AB_STATS_FILE, {"days": {}})
        self.data.setdefault("days", {})
        self.data.setdefault("hours", {})
        self.data.setdefault("dns5", {})
        self.dns_recent = deque(self.data.get("dns_recent") or [], maxlen=60)  # 最近 60 次原始耗时，刚启动时画曲线用
        self.saved = time.time()
        self._req_batch = 0  # 未持锁攒批的 req 增量（sink 系单线程调用，无竞争）

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

    def _merge_req_locked(self):
        """调用方已持锁：把攒批的 req 增量一次性合并"""
        if self._req_batch:
            self.hour()["req"] += self._req_batch
            self._req_batch = 0

    def hit(self, host, prov):
        if host.startswith("["):
            host = host[1:-1]
        with self.lock:
            self._merge_req_locked()
            b = self.data["days"].setdefault(time.strftime("%Y-%m-%d"), {"count": 0, "top": {}, "lists": {}})
            b["count"] += 1
            if host != "?" and not is_fake_ip(host):  # 反查不到域名的 Fake-IP / 未知连接只计总数，不进排行
                b["top"][host] = b["top"].get(host, 0) + 1
            key = prov[3:]
            b["lists"][key] = b["lists"].get(key, 0) + 1
            self.hour()["blk"] += 1
            if len(b["top"]) > 5000:  # 防止长尾域名无限增长
                b["top"] = dict(sorted(b["top"].items(), key=lambda x: -x[1])[:2000])

    def sink(self, line):
        # 子串预过滤：两个正则都要求 payload 含 "-->"，绝大多数日志行直接跳过 json 解析
        if "-->" not in line:
            return
        try:
            msg = json.loads(line).get("payload", "")
        except Exception:
            return
        if self.RX_ALL.search(msg):
            self._req_batch += 1
            if self._req_batch >= self.REQ_BATCH:
                with self.lock:
                    self._merge_req_locked()
        if "REJECT" in msg:
            m = self.RX.search(msg)
            if m:
                self.hit(m.group(1), m.group(2))
        if time.time() - self.saved > 60:
            self.flush()

    SB_LINE = re.compile(r"^\[(\d+) \d+ms\] (.*)$")
    SB_TO = re.compile(r"inbound/(\w+)\[([^\]]+)\]: inbound (?:packet )?connection to (\S+?):\d+$")
    SB_SNIFF = re.compile(r"router: sniffed (?:packet )?protocol: \w+, domain: (\S+)")
    SB_FAKE = re.compile(r"router: found fakeip domain: (\S+)")
    SB_REJ = re.compile(r"router: match\[\d+\] .*?\brule_set=(ad-[0-9a-z]+).*=> reject")
    SB_QN = re.compile(r"dns: exchange (\S+?)\.? IN ")
    SB_DREJ = re.compile(r"dns: match\[\d+\] .*?\brule_set=(ad-[0-9a-z]+).*=> (?:predefined|reject)")

    def sink_sb(self, line):
        """sing-box debug 日志：按连接 ID 记住目标域名，命中 ad- 规则集的 reject / DNS 拦截记为一次拦截"""
        # 子串预过滤：各分支的 body 关键字，绝大多数 debug 行直接跳过 json 解析
        if "inbound/" not in line and "sniffed" not in line and "reject" not in line and "dns: " not in line and "fakeip" not in line:
            return
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
                self._req_batch += 1
                if self._req_batch >= self.REQ_BATCH:
                    with self.lock:
                        self._merge_req_locked()
        elif "sniffed" in body:
            m = self.SB_SNIFF.search(body)
            if m:
                hosts[cid] = m.group(1)
        elif "found fakeip domain" in body:
            # 透明代理进来的目标是 198.18.x.x，sing-box 按 Fake-IP 映射还原出域名再匹配规则；
            # 以前只记了入站的 IP，嗅探不到域名（QUIC、非 TLS 等）时排行里就出现 198.18.0.11 这样的地址
            m = self.SB_FAKE.search(body)
            if m and (cid not in hosts or is_fake_ip(hosts[cid])):
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
            self._merge_req_locked()
            keep = sorted(self.data["days"])[-2:]
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

    def today(self):
        with self.lock:
            return int((self.data["days"].get(time.strftime("%Y-%m-%d")) or {}).get("count", 0))

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
        top = [(k, v) for k, v in b["top"].items() if k != "?" and not is_fake_ip(k)]  # 旧版本记下的 Fake-IP 也不显示
        return {"today": b["count"], "top": sorted(top, key=lambda x: -x[1])[:20], "lists": b["lists"],
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

