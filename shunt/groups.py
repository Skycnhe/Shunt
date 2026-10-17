"""策略组"""
import os, re, time

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


def sb_provider_nodes(d):
    """{订阅名: [节点名]}，名称已按全局去重（与生成的 sing-box 配置一致）"""
    return {k: [n for n, _ in v] for k, v in sb_sub_outbounds(d).items()}


def sb_sub_outbounds(d):
    taken = {n["proxy"]["name"] for n in d.get("nodes", [])} | reserved_names(d)
    out = {}
    for s in d["subs"]:
        lst = []
        for p in sb_sub_cache(s["name"]).get("nodes") or []:
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
        _prov_set(now, data)
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
    _prov_set(now, data)
    return data


def _prov_set(now, data):
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
    if not members and not flt:
        raise ValueError("请至少选择一个成员，或填写筛选正则")
    icon = str(b.get("icon") or "").strip()
    if icon and not re.match(r"^https?://\S{4,500}$", icon):
        raise ValueError("图标必须是 http(s) 图片地址")
    g = {"name": name, "type": t, "proxies": members, "filter": flt, "subs": bool(b.get("subs", True)),
         "expose": bool(b.get("expose", True)), "icon": icon}
    if t != "select":
        try:
            iv = int(b.get("interval") or 0)
            tol = int(b.get("tolerance") or 0)
        except (TypeError, ValueError):
            raise ValueError("测速间隔 / 容差必须是数字")
        if iv and not 30 <= iv <= 86400:
            raise ValueError("测速间隔应在 30–86400 秒之间")
        if not 0 <= tol <= 1000:
            raise ValueError("容差应在 0–1000 ms 之间")
        g.update(interval=iv, tolerance=tol)
        if t == "load-balance":
            g["strategy"] = "consistent-hashing"  # 只支持一致性哈希
    return g
