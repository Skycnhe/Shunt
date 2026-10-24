"""策略组"""
import json, os, re, time

from .errlog import log_err
from .base import GROUPS_DEFAULT, GROUP_TYPES, G_OTHER, PANEL_DIR, PRIMARY_REGIONS, REGIONS
from .corehttp import core_json
from .data import load, read_json, safe, write_json
from .links import reserved_names
from .sb_common import SB_SUB_DIR, active_core
PROV_FILE = os.path.join(PANEL_DIR, "provider_nodes.json")
PROV = {"t": 0, "data": None, "rev": 0}  # rev：订阅节点名单每变化一次加一（/api/state 的策略组缓存键、/api/ping 版本号用）
RX_CACHE = {}


def rx(pattern):
    """编译正则（缓存）；无效时返回 None"""
    if pattern not in RX_CACHE:
        try:
            RX_CACHE[pattern] = re.compile(pattern)
        except re.error:
            RX_CACHE[pattern] = None
    return RX_CACHE[pattern]


def sub_cache_path(name):
    return os.path.join(SB_SUB_DIR, safe(name) + ".json")


def sb_sub_cache(name):
    return read_json(sub_cache_path(name), {}) or {}


def _file_sig(path):
    try:
        st = os.stat(path)
        return st.st_mtime_ns, st.st_size, st.st_ino
    except OSError:
        return None


_SUB_META = {}   # {订阅名: (文件签名, {"updated", "info"})}
_PN_CACHE = {}   # {"v": (键, {订阅名: [节点名]})}


def sb_sub_meta(name):
    """订阅缓存里的更新时间与流量信息（按文件修改时间缓存）：sing-box 下每次 /api/px 都要，不必每次解析整份节点缓存"""
    path = sub_cache_path(name)
    sig = _file_sig(path)
    c = _SUB_META.get(name)
    if c and sig is not None and c[0] == sig:
        return c[1]
    j = sb_sub_cache(name)
    meta = {"updated": j.get("updated"), "info": j.get("info") or {}}
    if sig is not None:
        _SUB_META[name] = (sig, meta)
    return meta


def sb_provider_nodes(d):
    """{订阅名: [节点名]}，名称已按全局去重（与生成的 sing-box 配置一致）。
    结果按「各订阅缓存文件签名 + 订阅名 / 已删节点 + 本地节点名 + 保留名」缓存：sing-box 下每次 /api/px、/api/subs/nodes
    都要算一遍，以前每次都把全部订阅缓存（常有几百 KB～数 MB）重新读取解析"""
    try:
        key = json.dumps([[s["name"], sorted(sub_removed(s)), _file_sig(sub_cache_path(s["name"]))] for s in d["subs"]]
                         + [sorted(n["proxy"]["name"] for n in d.get("nodes", [])), sorted(reserved_names(d))], ensure_ascii=False, default=str)
    except Exception:
        key = None
    c = _PN_CACHE.get("v")
    if key is not None and c and c[0] == key:
        return {k: list(v) for k, v in c[1].items()}
    out = {k: [n for n, _ in v] for k, v in sb_sub_outbounds(d).items()}
    if key is not None:
        _PN_CACHE["v"] = (key, out)
    return {k: list(v) for k, v in out.items()}


def sb_sub_outbounds(d):
    """{订阅名: [(去重后的名称, 节点)]}；用户从订阅里删除的节点（removed，按原名精确匹配）在这里跳过，不用重新下载就生效"""
    taken = {n["proxy"]["name"] for n in d.get("nodes", [])} | reserved_names(d)
    out = {}
    for s in d["subs"]:
        lst = []
        gone = set(sub_removed(s))
        for p in sb_sub_cache(s["name"]).get("nodes") or []:
            if str(p.get("name") or "") in gone:
                continue
            base = str(p.get("name") or "").strip() or "node"
            name, k = base, 2
            while name in taken:
                name, k = f"{base} ({k})", k + 1
            taken.add(name)
            lst.append((name, p))
        out[s["name"]] = lst
    return out


def provider_nodes(fresh=False):
    """订阅（proxy-provider）里的节点名 {订阅名: [节点名]}：优先读运行中的核心，缓存到文件供核心未运行时生成配置"""
    now = time.time()
    if not fresh and PROV["data"] is not None and now - PROV["t"] < 60:
        return PROV["data"]
    data = None
    if active_core() == "singbox":  # sing-box 的订阅由面板下载解析，节点名直接取缓存
        data = sb_provider_nodes(load())
        prov_set(now, data)
        return data
    j = None if os.environ.get("PANEL_OFFLINE") else core_json("/providers/proxies", timeout=3)
    if j is not None:
        data = {}
        for name, p in (j.get("providers") or {}).items():
            if p.get("vehicleType") in ("HTTP", "File", "Inline") and p.get("proxies") is not None:
                data[name] = [x.get("name") for x in p["proxies"] if x.get("name")]
        if data != read_json(PROV_FILE, None):
            try:
                write_json(PROV_FILE, data)
            except OSError as e:
                log_err("保存订阅节点列表", e)
    if data is None:
        data = read_json(PROV_FILE, {})
    prov_set(now, data)
    return data


def prov_set(now, data):
    """更新订阅节点名单缓存；名单有变化时 rev 加一。直接 PROV.update 不会推进 rev（以前 sing-box 更新订阅后策略组名单一直是旧的）"""
    if PROV["data"] is not None and data != PROV["data"]:
        PROV["rev"] += 1
    PROV.update(t=now, data=data)


def provider_rev():
    """订阅节点名单的版本：节点增删 / 改名后变化"""
    return PROV["rev"]


def gcfg(d):
    gc = dict(GROUPS_DEFAULT)
    gc.update({k: v for k, v in (d.get("groups_cfg") or {}).items() if k in GROUPS_DEFAULT})
    gc["type"] = "url-test"  # v6：地区「自动优选」组固定为 url-test（旧的地区主组类型设置不再使用）
    gc["strategy"] = "consistent-hashing"  # 只支持一致性哈希
    return gc


def group_opts(t, gc, extra=None):
    """各类型策略组的公共参数"""
    e = extra or {}
    g = {"type": t}
    if t != "select":
        g.update({"url": e.get("url") or gc["url"], "interval": int(e.get("interval") or gc["interval"]), "lazy": bool(gc["lazy"])})
        if t in ("url-test", "smart"):
            g["tolerance"] = int(e.get("tolerance") if e.get("tolerance") not in (None, "") else gc["tolerance"])
        if t == "load-balance":
            g["strategy"] = "consistent-hashing"
        if t == "smart":  # Smart 内核：按延迟 / 丢包 / 速度综合打分，可用 LightGBM 模型预测权重
            g.update({"uselightgbm": bool(gc.get("lgbm")), "collectdata": False})
    return g


def region_plan(d, names, use):
    """返回 [(地区名, 正则或 None, exclude 正则或 None, 手动节点, 节点总数, 是否未知)]，只保留确实有节点的地区"""
    if not (use or names) or not d.get("region_groups", True):
        return []
    gc = gcfg(d)
    pn = provider_nodes() if use else {}
    subs = [s["name"] for s in d["subs"]]
    unknown = any(s not in pn for s in subs)
    pnames = [n for s in subs for n in pn.get(s, [])]
    regs = REGIONS if gc["extra"] else REGIONS[:PRIMARY_REGIONS]
    out = []
    for i, (rname, flt) in enumerate(regs):
        r = rx(flt)
        matched = [n for n in names if r.search(n)]
        total = len(matched) + sum(1 for n in pnames if r.search(n))
        if total or (unknown and i < PRIMARY_REGIONS):  # 订阅还没加载过：沿用旧行为，先生成 5 个常用地区
            out.append((rname, flt, None, matched, total, unknown))
    if gc["other"]:
        alls = [rx(f) for _, f in regs]
        matched = [n for n in names if not any(r.search(n) for r in alls)]
        total = len(matched) + sum(1 for n in pnames if not any(r.search(n) for r in alls))
        if total:
            out.append((G_OTHER, None, "|".join(f for _, f in regs), matched, total, unknown))
    return out


def all_node_names(d):
    """手动节点 + 已知订阅节点"""
    pn = provider_nodes() if d["subs"] else {}
    return [n["proxy"]["name"] for n in d.get("nodes", [])] + [n for s in d["subs"] for n in pn.get(s["name"], [])]


NAME_BAD = re.compile(r"[,#\n\r\t\"]")
NODE_NAME_MAX = 300  # 订阅节点名长度上限（removed / sub_nodes 校验）
NODE_LIST_MAX = 5000  # 一个订阅的已删节点 / 一个策略组勾选的订阅节点最多这么多条


def sub_removed(s):
    """订阅里被用户删除的节点名（原名，精确匹配）；字段缺失或格式不对时为空（兼容旧 data.json）"""
    v = s.get("removed") if isinstance(s, dict) else None
    return [x for x in v if isinstance(x, str) and x] if isinstance(v, list) else []


def node_name_ok(n):
    return isinstance(n, str) and 0 < len(n) <= NODE_NAME_MAX and "\n" not in n and "\r" not in n


def clean_removed(v, label="已删除节点"):
    """校验并规范化订阅的 removed：文本列表，去重，保持顺序"""
    if v is None:
        return []
    if not isinstance(v, list):
        raise ValueError(f"{label}应为列表")
    out = []
    for x in v:
        if not node_name_ok(x):
            raise ValueError(f"{label}里有无效的节点名（应为 1–{NODE_NAME_MAX} 字的文本）")
        if x not in out:
            out.append(x)
    if len(out) > NODE_LIST_MAX:
        raise ValueError(f"{label}过多（最多 {NODE_LIST_MAX} 个）")
    return out


def clean_sub_nodes(v):
    """自定义组勾选的订阅节点 [{sub, name}]：校验、去重、保持顺序"""
    if v is None:
        return []
    if not isinstance(v, list):
        raise ValueError("勾选的订阅节点应为列表")
    out, seen = [], set()
    for x in v:
        if not isinstance(x, dict) or not isinstance(x.get("sub"), str) or not x["sub"].strip() or not node_name_ok(x.get("name")):
            raise ValueError("勾选的订阅节点格式不正确（需要订阅名和节点名）")
        k = (x["sub"].strip(), x["name"])
        if k not in seen:
            seen.add(k)
            out.append({"sub": k[0], "name": k[1]})
    if len(out) > NODE_LIST_MAX:
        raise ValueError(f"勾选的订阅节点过多（最多 {NODE_LIST_MAX} 个）")
    return out


def names_rx(names):
    """精确匹配这些节点名的正则 ^(?:a|b)$：名字里的 [ ] ( ) | . + 空格等全部转义；
    反引号写成 \\x60（mihomo 把 filter / exclude-filter 里的反引号当作多条正则的分隔符）"""
    return "^(?:" + "|".join(re.escape(n).replace("`", r"\x60") for n in names) + ")$"


def rx_or(a, b):
    """两条正则取并集（命中任一条即可）。含反引号的是 mihomo 的多条正则写法，用反引号连接，语义同样是并集"""
    if not a:
        return b or ""
    if not b:
        return a
    if "`" in a or "`" in b:
        return f"{a}`{b}"
    return f"(?:{a})|{b}"


def sub_orig_nodes(d):
    """{订阅名: 节点原名集合}，只含当前确实可用的节点（已删除的不算）；某订阅还不知道节点（没下载过 / 核心没加载）时不在结果里。
    sing-box：面板缓存里的原名；mihomo：核心 / 文件缓存里的 provider 节点名（provider 不改名，就是原名）"""
    out = {}
    if active_core(d) == "singbox":
        for s in d["subs"]:
            c = sb_sub_cache(s["name"])
            if c.get("updated") or c.get("nodes"):
                gone = set(sub_removed(s))
                out[s["name"]] = {str(p.get("name") or "") for p in c.get("nodes") or []} - gone
        return out
    pn = provider_nodes()
    for s in d["subs"]:
        if s["name"] in pn:
            out[s["name"]] = set(pn[s["name"]] or []) - set(sub_removed(s))
    return out


def pick_plan(d, cg, orig=None):
    """自定义组勾选的订阅节点里还有效的部分 → {订阅名: [节点原名]}（按订阅顺序）。
    订阅已删除、节点已从订阅删除、或订阅里已经没有这个节点（已知节点名单时）都跳过，不让整份配置加载失败"""
    sn = cg.get("sub_nodes") or []
    if not sn:
        return {}
    if orig is None:
        orig = sub_orig_nodes(d)
    subs = {s["name"]: s for s in d["subs"]}
    want = {}
    for x in sn:
        s = subs.get(x["sub"])
        if not s or x["name"] in sub_removed(s):
            continue
        if x["sub"] in orig and x["name"] not in orig[x["sub"]]:
            continue
        lst = want.setdefault(x["sub"], [])
        if x["name"] not in lst:
            lst.append(x["name"])
    return {s["name"]: want[s["name"]] for s in d["subs"] if s["name"] in want}


def clean_custom_group(b):
    """校验并规范化一个自定义策略组（不含引用检查）"""
    name = str(b.get("name") or "").strip()
    if not name or len(name) > 40 or NAME_BAD.search(name):
        raise ValueError("名称不能为空、不超过 40 字，且不能包含逗号、# 或引号")
    t = b.get("type") or "select"
    if t not in GROUP_TYPES:
        raise ValueError("类型只能是 select / url-test / fallback / load-balance")
    members = []
    for m in b.get("proxies") or []:
        m = str(m).strip()
        if m and m not in members:
            members.append(m)
    flt = str(b.get("filter") or "").strip()
    if flt and rx(flt) is None:
        raise ValueError(f"筛选正则无效：{flt}")
    sub_nodes = clean_sub_nodes(b.get("sub_nodes"))
    if not members and not flt and not sub_nodes:
        raise ValueError("请至少选择一个成员（策略组 / 手动节点 / 订阅节点），或填写筛选正则")
    icon = str(b.get("icon") or "").strip()
    if icon and not re.match(r"^https?://\S{4,500}$", icon):
        raise ValueError("图标必须是 http(s) 图片地址")
    g = {"name": name, "type": t, "proxies": members, "filter": flt, "subs": bool(b.get("subs", True)),
         "expose": bool(b.get("expose", True)), "icon": icon, "sub_nodes": sub_nodes}
    if t != "select":
        try:
            iv = int(b.get("interval") or 0)
            # 容差留空 = 跟随全局（策略组设置里的容差）；以前留空存成 0，全局改成 50 后自定义组仍按 0 频繁切换节点
            tol = None if b.get("tolerance") in (None, "") else int(b.get("tolerance"))
        except (TypeError, ValueError):
            raise ValueError("测速间隔 / 容差必须是数字")
        if iv and not 30 <= iv <= 86400:
            raise ValueError("测速间隔应在 30–86400 秒之间")
        if tol is not None and not 0 <= tol <= 1000:
            raise ValueError("容差应在 0–1000 ms 之间")
        g.update(interval=iv, tolerance=tol)
        if t == "load-balance":
            g["strategy"] = "consistent-hashing"  # 只支持一致性哈希
    return g
