"""数据"""
import copy, json, os, re, secrets, threading, time

from .base import (
    AUTO_SUFFIX, AUTO_TAIL, AUTO_TAIL_OLD, DATA_FILE, DEFAULT, G_AUTO, G_OTHER, LB_PREFIX, LB_SUFFIX, LB_TAIL, LEGACY_AUTO, LOCK,
    PANEL_DIR, PROXY_MODES, REGIONS, SCHEMA, TESTS
)
from .ruleutil import dns_policy_of, rule_policy_index
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


_CONFIG_VERSION = [0]  # data.json 每次 save() 自增：/api/ping 用它判断配置是否变化


def config_version():
    return _CONFIG_VERSION[0]


def save(d):
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, DATA_FILE)
    with LOCK:  # RLock 可重入：调用方可能已持有
        _CONFIG_VERSION[0] += 1


def update(fn):
    """在锁内读-改-写 data.json，返回修改前的副本（用于配置校验失败时回滚）；有实际变化时把旧版本记入配置快照。
    history.json 的全量读+写移到 LOCK 外（另用 _HISTORY_LOCK 保证原子），避免大快照拖慢写配置并阻塞其他 API。"""
    with LOCK:
        d = load()
        prev = copy.deepcopy(d)
        fn(d)
        save(d)
    try:
        with _HISTORY_LOCK:
            history_push(prev, d)
    except Exception as e:
        print("history error", e, flush=True)
    return prev


_HISTORY_LOCK = threading.Lock()  # history.json 读-改-写原子性（update 的全局 LOCK 之外）


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
    return re.sub(r"[^\w\-]", "_", name) or "sub"

