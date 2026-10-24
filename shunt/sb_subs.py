"""订阅：sing-box 不能自己拉取订阅，由面板下载、解析成节点后写进配置"""
import json, os, re, threading, time, urllib.request, urllib.error

from .errlog import log_err
from .base import CONF_DIR, DEFAULT_EXCLUDE, PANEL_DIR, dl_check, read_full
from .data import load, safe, write_json
from .links import b64d, parse_link
from .groups import PROV, rx, sub_cache_path
from .sb_common import SB_UA
from .sb_yaml import yaml_lite
from .sysopt import proxy_opener
from .notify import core_alive

_DEBUG_LOCK = threading.Lock()  # sub-debug.txt 并发写保护
SUBS_WAIT = 180  # 并发更新订阅整体最多等这么多秒


def _yaml_full(text):
    try:
        import yaml  # 设备装了 py3-yaml 就用完整解析器
        y = yaml.safe_load(text)
        return y if isinstance(y, dict) else None
    except ImportError:
        return None
    except Exception:
        return None


def _yaml_section(text, key):
    """取出顶层 key: 段落原文（到下一个顶层键为止）"""
    lines = text.replace("\t", "  ").splitlines()
    out, on = [], False
    for ln in lines:
        top = ln[:1] not in ("", " ", "-", "#")
        if top:
            m = re.match(r"^[\"']?([^:\"']+)[\"']?\s*:", ln)
            on = bool(m and m.group(1).strip() == key)
            if on:
                out.append(f"{key}:" + ln.split(":", 1)[1])
            continue
        if on:
            out.append(ln)
    return "\n".join(out) if out else ""


def _yaml_items(sec):
    """整段解析失败时，按列表项逐条解析，坏的跳过"""
    lines = sec.splitlines()[1:]
    ind = next((len(x) - len(x.lstrip(" ")) for x in lines if x.strip().startswith("-")), None)
    if ind is None:
        return []
    items, cur = [], []
    for ln in lines:
        if ln.strip().startswith("-") and len(ln) - len(ln.lstrip(" ")) == ind:
            if cur:
                items.append(cur)
            cur = [ln]
        elif cur:
            cur.append(ln)
    if cur:
        items.append(cur)
    out = []
    for it in items:
        try:
            v = yaml_lite("x:\n" + "\n".join(it))
            v = (v or {}).get("x")
            if isinstance(v, list) and v and isinstance(v[0], dict):
                out.append(v[0])
        except Exception as e:
            log_err("订阅节点解析（跳过一条）", e)
    return out


def sub_yaml(text):
    """Clash/mihomo 订阅 → {"proxies": [...], "proxy-providers": {...}}，尽量容错"""
    y = _yaml_full(text)
    if y is not None:
        return {"proxies": y.get("proxies") or [], "proxy-providers": y.get("proxy-providers") or {}}
    res = {"proxies": [], "proxy-providers": {}}
    for key in ("proxies", "proxy-providers"):
        sec = _yaml_section(text, key)
        if not sec:
            continue
        v = None
        try:
            v = (yaml_lite(sec) or {}).get(key)
        except Exception:
            v = None
        if key == "proxies":
            n_items = sum(1 for x in sec.splitlines() if re.match(r"^\s*-\s", x))
            if not isinstance(v, list) or len(v) < n_items:
                alt = _yaml_items(sec)
                if len(alt) > len(v if isinstance(v, list) else []):
                    v = alt
            res[key] = v if isinstance(v, list) else []
        else:
            res[key] = v if isinstance(v, dict) else {}
    return res


def parse_sub_text(text, fetch=None, depth=0):
    """订阅内容 → mihomo 风格节点列表。支持 Clash YAML、sing-box JSON、Base64 / 明文分享链接"""
    t = text.strip().lstrip("\ufeff")
    if t.startswith("{"):
        try:
            j = json.loads(t)
            if isinstance(j, dict) and isinstance(j.get("outbounds"), list):
                # outbounds 里混了非对象元素时以前 o.get 抛 AttributeError（只捕获了 ValueError），整个订阅更新失败；tag 统一成文本
                return [{"_sb": o, "name": str(o["tag"]), "type": o.get("type")} for o in j["outbounds"]
                        if isinstance(o, dict) and o.get("type") not in ("selector", "urltest", "direct", "block", "dns")
                        and o.get("tag") and o.get("server")], []
        except ValueError:
            pass
    if re.search(r"(?m)^[\"']?(proxies|proxy-providers)[\"']?\s*:", t):
        y = sub_yaml(t)
        ps = y.get("proxies") if isinstance(y.get("proxies"), list) else []
        # 名称统一成文本：YAML 里 name: 2024 会解析成数字，后面的筛选正则 / 去重遇到数字会抛 TypeError，整个订阅更新失败
        out = [dict(p, name=str(p["name"]).strip()) for p in ps
               if isinstance(p, dict) and p.get("name") not in (None, "") and p.get("type") and str(p["name"]).strip()]
        # 读不出来的条目计入「无法识别已跳过」：以前静默丢弃，节点少了也没有任何提示
        errs = [f"第 {i} 个节点无法识别" for i, p in enumerate(ps, 1)
                if not (isinstance(p, dict) and p.get("name") not in (None, "") and p.get("type") and str(p["name"]).strip())]
        pv = y.get("proxy-providers") if isinstance(y.get("proxy-providers"), dict) else {}
        # 聚合配置：mihomo 自己会去拉 proxy-providers，sing-box 不会，这里由面板逐个下载展开
        for pname, prov in pv.items():
            if not isinstance(prov, dict) or not prov.get("url") or depth > 1 or fetch is None:
                continue
            try:
                sub, e2 = parse_sub_text(fetch(str(prov["url"])), fetch, depth + 1)
                names = {x["name"] for x in out}
                for x in sub:
                    if x["name"] in names:
                        x["name"] = f"{x['name']} [{pname}]"
                    out.append(x)
                errs += e2
            except Exception as e:
                errs.append(f"{pname}：{str(e)[:80]}")
        if out or ps or pv:
            return out, errs
        return [], errs or ["订阅是 mihomo 配置，但没读到 proxies 节点"]
    body = t
    if "://" not in t:
        try:
            body = b64d(re.sub(r"\s+", "", t))
        except Exception:
            body = ""
    out, errs = [], []
    for i, line in enumerate([x.strip() for x in body.splitlines() if re.match(r"^\s*[A-Za-z][\w+.\-]*://", x)], 1):
        try:
            p = parse_link(line)
            p["name"] = (p.get("name") or f"{p['type']}-{p['server']}:{p['port']}").strip()
            out.append(p)
        except Exception as e:
            errs.append(f"第 {i} 条：{e}")
    return out, errs


def _sub_get(url, ua):
    """下载订阅里嵌套的 proxy-providers 地址：先代理后直连"""
    last = None
    for use_proxy in ((True, False) if core_alive() else (False,)):
        try:
            dl_check(url, via_proxy=use_proxy)  # SSRF 防护：直连时校验 DNS，走代理时由代理解析（字面内网 IP 永远拦截）
        except IOError as e:
            last = e
            continue
        req = urllib.request.Request(url, headers={"User-Agent": ua})
        try:
            with proxy_opener(use_proxy).open(req, timeout=30) as r:
                return read_full(r, 20 << 20).decode("utf-8", "ignore")
        except Exception as e:
            last = e
    raise IOError(str(last)[:120])


def _sub_nodes_save(s, nodes, errs, info, ua, note=""):
    """按订阅的筛选 / 排除过滤后写入面板缓存；返回 (节点数, 消息)"""
    flt, exc = s.get("filter") or "", s.get("exclude", DEFAULT_EXCLUDE) or ""
    rf, re_ = rx(flt) if flt else None, rx(exc) if exc else None
    nodes = [p for p in nodes if (not rf or rf.search(p["name"])) and not (re_ and re_.search(p["name"]))]
    ui = {}
    for part in info.split(";"):
        k, _, v = part.strip().partition("=")
        if k in ("upload", "download", "total", "expire") and v.strip().isdigit():
            ui[k.capitalize()] = int(v)
    write_json(sub_cache_path(s["name"]), {"name": s["name"], "updated": int(time.time()), "nodes": nodes,
                                           "info": ui, "skipped": len(errs), "ua": ua})
    return len(nodes), note + f"{len(nodes)} 个节点" + (f"（{len(errs)} 条无法识别已跳过）" if errs else "")


def _mihomo_cache_fallback(s, ua):
    """所有 UA 都没解析出节点时，用 mihomo 以前下载的 ./providers/<名>.yaml 兜底（刚从 mihomo 切到 sing-box 时用得上）。
    只在面板还没有这个订阅的缓存、或 mihomo 的缓存比面板缓存新时才用：以前只要第一个 UA 没解析出节点就直接读它，
    不再试下一个 UA，并照常报「N 个节点」——mihomo 缓存往往是切换内核前的旧文件，订阅明明换了节点，
    「更新」一直显示成功、节点却一直是旧的。返回 (节点, 错误) 或 None"""
    cache = os.path.join(CONF_DIR, "providers", safe(s["name"]) + ".yaml")
    try:
        mt = os.path.getmtime(cache)
    except OSError:
        return None
    try:
        if os.path.getmtime(sub_cache_path(s["name"])) >= mt:
            return None
    except OSError:
        pass
    try:
        with open(cache, encoding="utf-8", errors="ignore") as f:
            nodes, errs = parse_sub_text(f.read(), lambda u, _ua=ua: _sub_get(u, _ua))
    except (OSError, ValueError):
        return None
    return (nodes, errs) if nodes else None


def sb_fetch_sub(s, gh=""):
    """下载并解析一个订阅，写入缓存；返回 (节点数, 消息)。
    依次试 SB_UA 里的每个 UA（每个 UA 先代理后直连），第一个解析出节点的结果写入缓存；
    全部失败时抛 IOError，面板缓存里上次的节点保持不变（不会把旧节点当成这次更新的结果报成功）"""
    last = ""
    for ua in SB_UA:
        try:
            data = None
            for use_proxy in ((True, False) if core_alive() else (False,)):
                try:
                    dl_check(s["url"], via_proxy=use_proxy)  # SSRF 防护：直连时校验 DNS，走代理时由代理解析（字面内网 IP 永远拦截）
                except IOError as e:
                    last = str(e)[:150]
                    continue
                # 每次新建 Request：走代理失败后 urllib 已把代理地址写进 Request，复用会让「直连重试」仍然连到代理
                req = urllib.request.Request(s["url"], headers={"User-Agent": ua})
                try:
                    with proxy_opener(use_proxy).open(req, timeout=30) as r:
                        data = read_full(r, 20 << 20)
                        info = r.headers.get("subscription-userinfo") or ""
                    break
                except Exception as e:
                    last = str(e)[:150]
            if data is None:
                continue
            nodes, errs = parse_sub_text(data.decode("utf-8", "ignore"), lambda u, _ua=ua: _sub_get(u, _ua))
            if not nodes:
                last = "没有解析出节点" + ("：" + errs[0] if errs else "")
                try:  # 留一份原文方便排查（只保留最近一次）；原文含节点密码，600 权限
                    with _DEBUG_LOCK:
                        dbg = os.path.join(PANEL_DIR, "sub-debug.txt")
                        with open(dbg, "wb") as f:
                            f.write(data[:2 << 20])
                        os.chmod(dbg, 0o600)
                except OSError:
                    pass
                continue  # 换下一个 UA 再试（机场常按 UA 返回不同格式）
            return _sub_nodes_save(s, nodes, errs, info, ua)
        except Exception as e:
            last = str(e)[:150]
    fb = _mihomo_cache_fallback(s, SB_UA[0])
    if fb is not None:
        return _sub_nodes_save(s, fb[0], fb[1], "", "", f"订阅这次没有解析出节点（{(last or '下载失败')[:80]}），暂用 mihomo 之前下载的缓存：")
    raise IOError((last or "下载失败") + ("（已保留上次的节点）" if os.path.isfile(sub_cache_path(s["name"])) else ""))


def _cached_names(name):
    """面板缓存里某订阅的节点名列表（没有缓存时 None）：更新前后对比，节点没变时在结果里注明"""
    try:
        with open(sub_cache_path(name)) as f:
            return [str(p.get("name") or "") for p in json.load(f).get("nodes") or [] if isinstance(p, dict)]
    except (OSError, ValueError, AttributeError):
        return None


def sb_update_subs(names=None, d=None):
    """并发更新订阅：每个订阅一个线程（单个订阅仍串行走 UA/代理/直连回退），整体耗时取决于最慢的一个"""
    d = d or load()
    gh = d.get("gh_proxy") or ""
    subs = [s for s in d["subs"] if not names or s["name"] in names]
    ok, bad = [], []
    res_lock = threading.Lock()

    def one(s):
        try:
            before = _cached_names(s["name"])
            n, msg = sb_fetch_sub(s, gh)
            if before and before == _cached_names(s["name"]):
                msg += "（节点与上次相同）"
            with res_lock:
                ok.append(f"{s['name']}：{msg}")
        except Exception as e:
            with res_lock:
                bad.append(f"{s['name']}：{e}")

    ths = [threading.Thread(target=one, args=(s,)) for s in subs]
    for t in ths:
        t.start()
    end = time.time() + SUBS_WAIT  # 整体最多等 SUBS_WAIT 秒（以前逐个 join(180)，几个订阅都卡住时要等 N×180 秒）
    for t in ths:
        t.join(max(0.1, end - time.time()))
    with res_lock:  # 超时还没结束的线程之后再写结果也不影响这里返回的快照
        ok_out = list(ok)
        bad_out = list(bad) + [f"{s['name']}：下载超时" for s, t in zip(subs, ths) if t.is_alive()]
    # 只让缓存过期、保留旧名单：下次 provider_nodes 拿新名单与它比较，有变化才能推进 provider_rev()。
    # 以前把 data 清成 None，比较时没有旧名单，rev 永远不变：sing-box 下订阅更新出新地区后，/api/state 的策略组名单
    # （策略下拉框、按设备分流目标）一直按旧缓存返回，直到下次改设置
    PROV["t"] = 0
    return ok_out, bad_out


