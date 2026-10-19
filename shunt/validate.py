"""/api/settings、/api/restore 的数据形状校验：残缺或类型不对的条目返回 400，不写进 data.json。

data.json 里一条坏数据（规则集缺 url、节点缺 proxy、绕过列表混入数字……）会让生成配置抛异常，
之后每次 /api/state 都 500，面板等于「变砖」。这里只查形状与取值范围，策略组引用等语义检查仍在各接口里做。"""
import ipaddress, re

from .base import DNS_LISTS, G_SEL, PROXY_MODES
from .data import safe
from .groups import NAME_BAD, clean_custom_group, clean_removed

RS_BEHAVIORS = ("domain", "ipcidr", "classical")
RS_FORMATS = ("yaml", "text", "mrs")
MAC_RX = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
URL_RX = re.compile(r"^https?://\S+$")
LIST_MAX = 20000


def _list(v, label):
    if not isinstance(v, list):
        raise ValueError(f"{label}应为列表")
    if len(v) > LIST_MAX:
        raise ValueError(f"{label}条目过多")
    return v


def _str(v, label, empty=False):
    if not isinstance(v, str):
        raise ValueError(f"{label}应为文本")
    v = v.strip()
    if not v and not empty:
        raise ValueError(f"{label}不能为空")
    return v


def _url(v, label):
    v = _str(v, label)
    if not URL_RX.match(v):
        raise ValueError(f"{label}应为 http(s) 地址：{v[:80]}")
    return v


def clean_rulesets(v):
    out, seen = [], set()
    for i, r in enumerate(_list(v, "规则集")):
        if not isinstance(r, dict):
            raise ValueError(f"规则集第 {i + 1} 项格式不正确")
        name = _str(r.get("name"), f"规则集第 {i + 1} 项的名称")
        if NAME_BAD.search(name) or len(name) > 60:
            raise ValueError(f"规则集名称不能含逗号、# 或引号，且不超过 60 字：{name}")
        if name in seen:
            raise ValueError(f"规则集重名：{name}")
        seen.add(name)
        rs = {"name": name, "url": _url(r.get("url"), f"规则集「{name}」的地址")}
        beh, fmt = r.get("behavior", "domain"), r.get("format", "yaml")
        if beh not in RS_BEHAVIORS:
            raise ValueError(f"规则集「{name}」的类型只能是 " + " / ".join(RS_BEHAVIORS))
        if fmt not in RS_FORMATS:
            raise ValueError(f"规则集「{name}」的格式只能是 " + " / ".join(RS_FORMATS))
        rs.update(behavior=beh, format=fmt, target=_str(r.get("target") or G_SEL, f"规则集「{name}」的目标策略"))
        out.append(rs)
    return out


def bypass_ok(x):
    if MAC_RX.fullmatch(x):
        return True
    try:
        ipaddress.ip_network(x, strict=False)
        return True
    except ValueError:
        return False


def clean_bypass(v):
    out = []
    for x in _list(v, "绕过设备"):
        x = _str(x, "绕过设备的条目", empty=True)
        if not x:
            continue
        if not bypass_ok(x):
            raise ValueError(f"绕过设备只能填 IP、网段或 MAC 地址：{x[:60]}")
        out.append(x)
    return out


def clean_tests(v):
    out = []
    for i, t in enumerate(_list(v, "延迟站点")):
        if not isinstance(t, dict):
            raise ValueError(f"延迟站点第 {i + 1} 项格式不正确")
        name = _str(t.get("name"), f"延迟站点第 {i + 1} 项的名称")
        out.append({"name": name[:40], "url": _url(t.get("url"), f"延迟站点「{name}」的网址")})
    if not out:
        raise ValueError("延迟站点不能为空")
    return out


def clean_rules(v):
    out = []
    for x in _list(v, "自定义规则"):
        x = _str(x, "自定义规则", empty=True)
        if "\n" in x or "\r" in x:
            raise ValueError("自定义规则不能含换行")
        if x:
            out.append(x)
    return out


def sub_name_clash(name, others):
    """订阅名只差符号（「机场 A」和「机场_A」）时会共用同一个节点缓存文件，互相覆盖：返回冲突的那个名字"""
    k = safe(name)
    return next((o for o in others if o != name and safe(o) == k), None)


def rename_sub_clashes(subs):
    """恢复备份时订阅名只差符号（会共用同一个节点缓存文件）：后出现的自动加 _2、_3… 改名。返回 (新列表, [(原名, 新名)])"""
    out, renames, keys, names = [], [], set(), {s["name"] for s in subs}
    for s in subs:
        name = s["name"]
        if safe(name) in keys:
            k = 2
            while f"{name}_{k}" in names or safe(f"{name}_{k}") in keys:
                k += 1
            new = f"{name}_{k}"
            renames.append((name, new))
            names.add(new)
            s = dict(s, name=new)
        keys.add(safe(s["name"]))
        out.append(s)
    return out, renames


def rename_sub_refs(groups, renames):
    """恢复时订阅被自动改名：自定义组里勾选的订阅节点 {sub, name} 跟着改指新名字（订阅自己的 removed 名单在订阅对象里，自然随它走）"""
    m = dict(renames or [])
    if not m:
        return groups
    out = []
    for g in groups or []:
        if isinstance(g, dict) and isinstance(g.get("sub_nodes"), list):
            g = dict(g, sub_nodes=[dict(x, sub=m.get(x.get("sub"), x.get("sub"))) if isinstance(x, dict) else x for x in g["sub_nodes"]])
        out.append(g)
    return out


def clean_subs(v):
    seen = set()
    out = []
    for i, s in enumerate(_list(v, "订阅")):
        if not isinstance(s, dict):
            raise ValueError(f"订阅第 {i + 1} 项格式不正确")
        name = _str(s.get("name"), f"订阅第 {i + 1} 项的名称")
        if name in seen:
            raise ValueError(f"订阅重名：{name}")
        seen.add(name)
        _url(s.get("url"), f"订阅「{name}」的地址")
        for k in ("filter", "exclude"):
            if s.get(k) is not None and not isinstance(s[k], str):
                raise ValueError(f"订阅「{name}」的 {k} 应为文本")
        if "removed" in s:  # 从订阅里删除的节点（v8.4.0）；旧备份没有这个字段
            s = dict(s, removed=clean_removed(s["removed"], f"订阅「{name}」的已删除节点"))
        out.append(s)
    return out


def clean_nodes(v):
    for i, n in enumerate(_list(v, "节点")):
        p = n.get("proxy") if isinstance(n, dict) else None
        if not isinstance(p, dict):
            raise ValueError(f"节点第 {i + 1} 项缺少 proxy")
        name = _str(p.get("name"), f"节点第 {i + 1} 项的名称")
        _str(p.get("type"), f"节点「{name}」的类型")
        _str(p.get("server"), f"节点「{name}」的服务器")
        port = p.get("port")
        try:
            ok = not isinstance(port, bool) and 0 < int(port) < 65536
        except (TypeError, ValueError):
            ok = False
        if not ok:
            raise ValueError(f"节点「{name}」的端口无效")
    return v


def clean_custom_groups(v):
    out, seen = [], set()
    for i, g in enumerate(_list(v, "自定义策略组")):
        if not isinstance(g, dict):
            raise ValueError(f"自定义策略组第 {i + 1} 项格式不正确")
        g = clean_custom_group(g)
        if g["name"] in seen:
            raise ValueError(f"策略组重名：{g['name']}")
        seen.add(g["name"])
        out.append(g)
    return out


def clean_adblock(v):
    if not isinstance(v, dict):
        raise ValueError("广告拦截设置应为对象")
    for i, l in enumerate(_list(v.get("lists", []), "广告拦截列表")):
        if not isinstance(l, dict) or not isinstance(l.get("id"), str) or not l["id"].strip():
            raise ValueError(f"广告拦截列表第 {i + 1} 项格式不正确")
        _url(l.get("url"), f"广告拦截列表「{l['id']}」的地址")
    for k, label in (("black", "黑名单"), ("white", "白名单")):
        for x in _list(v.get(k, []), label):
            _str(x, label, empty=True)
    return v


def clean_devices(v):
    if not isinstance(v, dict) or not all(isinstance(k, str) and isinstance(x, str) for k, x in v.items()):
        raise ValueError("设备备注格式不正确")
    return v


def clean_schedule(v):
    if not isinstance(v, dict):
        raise ValueError("定时任务应为对象")
    for k in ("sub_update", "core_restart", "geo_update"):
        x = v.get(k) or ""
        if not isinstance(x, str) or (x and not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", x)):
            raise ValueError(f"定时任务时间格式应为 HH:MM：{x}")
    try:
        int(v.get("latency") or 0)
    except (TypeError, ValueError):
        raise ValueError("自动测速间隔应为数字")
    return v


def _dict(label):
    def f(v):
        if not isinstance(v, dict):
            raise ValueError(f"{label}应为对象")
        return v
    return f


def _int(label, lo=0, hi=10**9):
    def f(v):
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
            raise ValueError(f"{label}应为 {lo}–{hi} 的数字")
        return int(v)
    return f


def _bool(v):
    return bool(v)


def _text(label):
    def f(v):
        if v is None:
            return ""
        if not isinstance(v, (str, int)) or isinstance(v, bool):
            raise ValueError(f"{label}应为文本")
        return str(v).strip()
    return f


def _choice(label, opts):
    def f(v):
        if v not in opts:
            raise ValueError(f"{label}只能是 " + " / ".join(opts))
        return v
    return f


def _dns(v):
    if not isinstance(v, dict):
        raise ValueError("DNS 设置应为对象")
    for k in DNS_LISTS + ("hosts", "policies"):
        if k in v and not isinstance(v[k], list):
            raise ValueError(f"DNS 的 {k} 应为列表")
    for pe in v.get("policies") or []:
        if not isinstance(pe, dict) or not isinstance(pe.get("servers", []), list):
            raise ValueError("DNS 分流策略格式不正确")
    return v


CLEANERS = {
    "rulesets": clean_rulesets, "bypass": clean_bypass, "tests": clean_tests, "rules": clean_rules, "subs": clean_subs,
    "nodes": clean_nodes, "custom_groups": clean_custom_groups, "adblock": clean_adblock, "devices": clean_devices,
    "schedule": clean_schedule, "dns": _dns, "tun": _dict("TUN 设置"), "groups_cfg": _dict("地区分组设置"),
    "sub_interval": _int("订阅更新间隔", 0, 10**8), "log_limit": _int("日志上限", 1, 100),
    "region_groups": _bool, "ipv6": _bool, "watchdog": _bool, "sniffer": _bool, "tproxy": _bool,
    "tg_token": _text("Telegram Token"), "tg_chat": _text("Telegram Chat ID"), "gh_proxy": _text("GitHub 加速地址"),
    "mode": _choice("代理模式", ("rule", "global", "direct")), "proxy_mode": _choice("代理方式", tuple(PROXY_MODES) + ("",)),
}


def clean_fields(b, keys):
    """按 CLEANERS 校验并规范化 b 中出现在 keys 里的字段，返回新 dict；有问题抛 ValueError（提示可直接给用户看）"""
    if not isinstance(b, dict):
        raise ValueError("请求内容应为 JSON 对象")
    out = {}
    for k in keys:
        if k in b:
            fn = CLEANERS.get(k)
            out[k] = fn(b[k]) if fn else b[k]
    return out
