"""订阅：sing-box 不能自己拉取订阅，由面板下载、解析成节点后写进配置"""
import json, os, re, threading, time, urllib.request, urllib.error

from .errlog import log_err
from .base import CONF_DIR, DEFAULT_EXCLUDE, PANEL_DIR, dl_check
from .data import load, safe, write_json
from .links import b64d, parse_link
from .groups import PROV, rx, sub_cache_path
from .sb_common import SB_UA
from .sb_yaml import yaml_lite
from .sysopt import proxy_opener
from .notify import core_alive

_DEBUG_LOCK = threading.Lock()  # sub-debug.txt 并发写保护


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
            if isinstance(j.get("outbounds"), list):
                return [{"_sb": o, "name": o.get("tag"), "type": o.get("type")} for o in j["outbounds"]
                        if o.get("type") not in ("selector", "urltest", "direct", "block", "dns") and o.get("tag") and o.get("server")], []
        except ValueError:
            pass
    if re.search(r"(?m)^[\"']?(proxies|proxy-providers)[\"']?\s*:", t):
        y = sub_yaml(t)
        ps = y.get("proxies") if isinstance(y.get("proxies"), list) else []
        out = [p for p in ps if isinstance(p, dict) and p.get("name") and p.get("type")]
        errs = []
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
                return r.read(20 << 20).decode("utf-8", "ignore")
        except Exception as e:
            last = e
    raise IOError(str(last)[:120])


def sb_fetch_sub(s, gh=""):
    """下载并解析一个订阅，写入缓存；返回 (节点数, 消息)"""
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
                        data = r.read(20 << 20)
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
                # mihomo 已下载过这个订阅时，用它的缓存兜底
                cache = os.path.join(CONF_DIR, "providers", safe(s["name"]) + ".yaml")
                if os.path.isfile(cache):
                    with open(cache, encoding="utf-8", errors="ignore") as f:
                        nodes, errs = parse_sub_text(f.read(), lambda u, _ua=ua: _sub_get(u, _ua))
                if not nodes:
                    continue
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
            return len(nodes), f"{len(nodes)} 个节点" + (f"（{len(errs)} 条无法识别已跳过）" if errs else "")
        except Exception as e:
            last = str(e)[:150]
    raise IOError(last or "下载失败")


def sb_update_subs(names=None, d=None):
    """并发更新订阅：每个订阅一个线程（单个订阅仍串行走 UA/代理/直连回退），整体耗时取决于最慢的一个"""
    d = d or load()
    gh = d.get("gh_proxy") or ""
    subs = [s for s in d["subs"] if not names or s["name"] in names]
    ok, bad = [], []
    res_lock = threading.Lock()

    def one(s):
        try:
            n, msg = sb_fetch_sub(s, gh)
            with res_lock:
                ok.append(f"{s['name']}：{msg}")
        except Exception as e:
            with res_lock:
                bad.append(f"{s['name']}：{e}")

    ths = [threading.Thread(target=one, args=(s,)) for s in subs]
    for t in ths:
        t.start()
    for t in ths:
        t.join(180)
    PROV.update(t=0, data=None)
    return ok, bad


