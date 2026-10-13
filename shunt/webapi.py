"""HTTP"""
import copy, gzip, json, os, re, shutil, socket, ssl, threading, time
from http.server import BaseHTTPRequestHandler
from collections import deque
from urllib.parse import parse_qs, quote, unquote, urlparse

from .errlog import log_err
from . import adblock, stats
from .base import (
    AB_DIR, AB_PRESETS, BUILTIN_POLICIES, CERT, DEFAULT_EXCLUDE, DNS_DEFAULT, DNS_LISTS, GROUP_TYPES, G_MANUAL, G_SEL, HC, KEY,
    LB_STRATEGIES, LOCK, MAX_BODY, MIHOMO_BIN, MIHOMO_LOG, PANEL_VERSION, PRIMARY_REGIONS, PROXY_MODES, REGIONS, SMART_BIN, SVC, TPROXY_SH,
    TUN_STACKS, wd_hold
)
from .data import HISTORY_FILE, HISTORY_SKIP, auto_name, config_version, lb_names, load, migrate_names, read_json, region_lb_set, save, update
from .links import add_links, q1, reserved_names
from .groups import all_node_names, clean_custom_group, gcfg, region_plan, rx
from .mihomo import bad_rule_policies, build_config, dns_cfg, safe_dev, validate_dns
from .core import conns_snapshot, refresh_after_sub, refresh_regions, reload_core
from .corehttp import core, core_json
from .sb_common import CORES, SB_BIN, SB_STATE, active_core, core_conf_path
from .sb_subs import sb_update_subs
from .sb_config import build_singbox, sb_ab_loaded, sb_fake_providers, sb_fake_rule_providers, sb_rule_need, sb_sync_assets, sb_version, write_active_config
from .sb_switch import core_switch_job, sb_arch, sb_remote_version, sb_update_job
from .panel_update import self_rollback, self_update
from .core_update import (
    CORE_CHANNELS, CORE_UPD, LGBM_FILE, bin_version, core_check, core_job_start, core_rollback_job, core_upd_status, core_update_job,
    lgbm_fetch, lgbm_fetch_reload
)
from .sysopt import delay_test, favicon, nft_ok, opt_apply, opt_status, sh, speed_test, svc_restart
from .notify import WD, tg_send
from .latency import BG_FILE, RETEST, bg_fetch, bg_meta, bg_meta_save, bg_save, bg_type, fix_global, proxies_merged, retest_soon
from .stats import arp_table
from .unlock import unlock_test
from .ruletest import clean_target, is_ip, rule_test
from .logstream import core_stream, ticket_new, ticket_use
from .adblock import AB_CACHE, AB_STATE, ab_check, ab_compose, ab_meta, adblock_update, fmt_size, list_id, parse_filter
from .live import LIVE, memory_once
from .logclean import LOG_STATE, log_clean, log_sizes
from .schedule import SCHED, TASK_NAMES, run_task, sched_event
from .devices import device_map, read_leases, tun_runtime_error
from .diag import diagnose
from .dnsleak import antileak_dns, dns_route, leak_check
from .https import gen_cert, restart_self
from .access import acl_cfg, host_name, host_ok, ip_is_lan
from .update_guard import group_meta, rename_policy
from .static import MANIFEST, STATIC_TYPES, static_file
ROUTES = {}  # (方法, 路径) → H 的处理函数；api() 先处理前缀 / 条件路由，再查这张表

# GET 也要求 X-Shunt 头的机密接口：返回内容含订阅 URL / 节点密码 / TG token 等机密，局域网零凭证可拖库
SENSITIVE_GET = ("/api/backup", "/api/config", "/api/history")

_SVC_CACHE = {}  # {"v": (t, st, code, version)}：rc-service 状态 + 核心 /version 缓存 10 秒
_GRP_CACHE = {}  # {"v": (cfgver, groups, gmeta)}：策略组名单按配置版本缓存，避免每次完整 build_config


def _svc_status():
    """/api/state 每 15 秒/标签页轮询：起 shell 查服务状态 + 调核心 /version，10 秒内复用缓存"""
    now = time.time()
    v = _SVC_CACHE.get("v")
    if v is not None and now - v[0] < 10:
        return v[1], v[2], v[3]
    _, st = sh(SVC + " status")
    code, ver = core("GET", "/version")
    try:
        version = json.loads(ver).get("version", "-") if code == 200 else "-"
    except Exception:
        version = "-"
    _SVC_CACHE["v"] = (now, st, code, version)
    return st, code, version


def api_route(path, *methods):
    def deco(fn):
        for m in methods:
            assert (m, path) not in ROUTES, (m, path)
            ROUTES[(m, path)] = fn
        return fn
    return deco


_MASK_WORDS = ("password", "passwd", "uuid", "token", "psk", "secret", "privatekey")


def _mask_val(v):
    """敏感值掩盖中间：长值露头 3 + 尾 2，短值全打码"""
    s = str(v)
    return f"{s[:3]}******{s[-2:]}" if len(s) > 6 else "******"


def _mask_cfg(o):
    """递归掩盖配置里的敏感字段（key 含 password/uuid/token/psk/secret/privatekey 等，去掉 -_ 后匹配）"""
    if isinstance(o, dict):
        return {k: (_mask_val(v) if isinstance(v, str) and any(w in k.lower().replace("-", "").replace("_", "")
                                                              for w in _MASK_WORDS) else _mask_cfg(v))
                for k, v in o.items()}
    if isinstance(o, list):
        return [_mask_cfg(x) for x in o]
    return o


def config_view(d=None, masked=True):
    """配置文本视图（/api/config）：masked=True 时递归掩盖节点 password/uuid 等敏感字段"""
    d = d or load()
    if active_core(d) == "singbox":
        cfg = build_singbox(d)[0]
    else:
        cfg = build_config(d)
    if masked:
        cfg = _mask_cfg(cfg)
    return json.dumps(cfg, ensure_ascii=False, indent=2)


def find_cycle(groups):
    """策略组之间的循环引用，返回环路径或 None"""
    gmap = {g["name"]: [m for m in g.get("proxies", [])] for g in groups}
    state, stack = {}, []

    def dfs(n):
        state[n] = 1
        stack.append(n)
        for m in gmap.get(n, []):
            if m in gmap:
                if state.get(m) == 1:
                    return stack[stack.index(m):] + [m]
                if not state.get(m):
                    c = dfs(m)
                    if c:
                        return c
        state[n] = 2
        stack.pop()
        return None

    for n in gmap:
        if not state.get(n):
            c = dfs(n)
            if c:
                return c
    return None


def validate_groups(d):
    """生成配置后检查自定义组：重名、成员不存在、循环引用"""
    errs = []
    nodes = all_node_names(d)
    fixed = reserved_names()
    seen = set()
    for cg in d.get("custom_groups") or []:
        n = cg["name"]
        if n in seen:
            errs.append(f"策略组重名：{n}")
        if n in fixed:
            errs.append(f"「{n}」与内置策略组或策略同名")
        if n in nodes:
            errs.append(f"「{n}」与节点同名")
        seen.add(n)
    cfg = build_config(d, strict=True)
    names = {g["name"] for g in cfg["proxy-groups"]} | BUILTIN_POLICIES | {p["name"] for p in cfg["proxies"]}
    for cg in d.get("custom_groups") or []:
        miss = [m for m in cg["proxies"] if m not in names]
        if miss:
            errs.append(f"「{cg['name']}」的成员不存在：" + "、".join(miss[:5]))
        if cg["name"] in cg["proxies"]:
            errs.append(f"「{cg['name']}」不能包含自己")
    cyc = find_cycle(cfg["proxy-groups"])
    if cyc:
        errs.append("策略组循环引用：" + " → ".join(cyc) + "（加入分流组候选的自定义组不能再引用 YouTube / Google 等分流组，可关闭“加入分流组候选”）")
    return errs


def ad_today():
    """顶栏「广告拦截」：今天（本地自然日）拦截数，与概览「今日拦截广告」同一口径"""
    return adblock.AD_STATS.today() if adblock.AD_STATS else 0


class H(BaseHTTPRequestHandler):
    timeout = 30  # 读请求/TLS 握手的超时：卡住不发数据的连接不再永久占用线程（日志流只写不读，不受影响）

    def log_message(self, *a):
        pass

    def gzip_ok(self):
        return "gzip" in (self.headers.get("Accept-Encoding") or "")

    def sec_headers(self):
        self.send_header("X-Frame-Options", "SAMEORIGIN")  # 防点击劫持
        if isinstance(self.connection, ssl.SSLSocket):  # 启用 HTTPS 后才有意义
            self.send_header("Strict-Transport-Security", "max-age=31536000")

    def send(self, code, obj, ctype="application/json"):
        body = obj if isinstance(obj, bytes) else json.dumps(obj, ensure_ascii=False).encode()
        zipped = len(body) > 1400 and ctype in ("application/json", "text/html", "text/plain") and self.gzip_ok()
        if zipped:  # 连接列表、节点列表等较大的 JSON 压缩后通常只有 1/5～1/10
            body = gzip.compress(body, 5)
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        if zipped:
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Vary", "Accept-Encoding")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.sec_headers()
        self.end_headers()
        self.wfile.write(body)

    def send_static(self, name):
        f = static_file(name)
        if not f:
            return self.send(404, {"message": "not found"})
        raw, gz, etag, ctype = f
        if self.headers.get("If-None-Match") == etag:  # 浏览器已有最新版本，不再传输
            self.send_response(304)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "no-cache")
            self.sec_headers()
            self.end_headers()
            return
        body = gz if gz is not None and self.gzip_ok() else raw
        self.send_response(200)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith("text/") else ""))
        if body is gz:
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Vary", "Accept-Encoding")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("ETag", etag)
        # 页面每次打开都向服务器确认（未变化时只回 304），面板更新后立即生效；图标缓存 1 天
        self.send_header("Cache-Control", "no-cache" if name == "index.html" else "public, max-age=86400")
        self.sec_headers()
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0:
            return {}
        if n > MAX_BODY:  # 防止超大 body 耗尽路由器内存
            raise ValueError("请求体过大")
        raw = self.rfile.read(n)
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def do_GET(self): self.route("GET")
    def do_POST(self): self.route("POST")
    def do_PUT(self): self.route("PUT")
    def do_DELETE(self): self.route("DELETE")
    def do_PATCH(self): self.route("PATCH")

    def deny(self, why):
        if self.path.startswith("/api/"):
            return self.send(403, {"message": why})
        from html import escape as html_escape
        html = ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>"
                "<title>Shunt</title><div style='font:15px/1.7 system-ui;max-width:640px;margin:40px auto;padding:0 16px'>"
                f"<h3>访问被拒绝</h3><p>{html_escape(why)}</p></div>")
        return self.send(403, html.encode(), "text/html")

    def guard(self, m, p):
        """返回拒绝原因；空串表示放行"""
        a = acl_cfg()
        ip = self.client_address[0]
        if not a["public"] and not ip_is_lan(ip):
            return (f"面板默认只允许局域网访问，你的地址 {ip} 不是局域网地址。确实需要从外网访问时，"
                    "在路由器上执行：python3 /opt/mihomo-panel/server.py --allow-public on（面板没有密码，请自行做好防护）")
        host = self.headers.get("Host") or ""
        if not host_ok(host):
            h = host_name(host)
            return (f"域名 {h} 不在允许列表（防止 DNS 重绑定攻击）。用 IP 访问，或在路由器上执行："
                    f"python3 /opt/mihomo-panel/server.py --allow-host {h}")
        if m not in ("GET", "HEAD") and p.startswith("/api/"):
            origin = self.headers.get("Origin")
            if origin and origin != "null" and urlparse(origin).netloc.lower() != host.lower():
                return "跨站请求已拒绝"
            if "X-Shunt" not in self.headers and "X-Token" not in self.headers:  # X-Token：兼容旧版脚本
                return "缺少 X-Shunt 请求头，跨站请求已拒绝（脚本调用接口请加上 -H 'X-Shunt: 1'）"
        if m in ("GET", "HEAD") and p in SENSITIVE_GET:
            # 机密类 GET：/api/backup、/api/config（含 ?download）、/api/history 返回订阅/节点密码等机密，同样要求请求头
            if "X-Shunt" not in self.headers and "X-Token" not in self.headers:
                return "缺少 X-Shunt 请求头，机密接口拒绝访问（脚本调用请加上 -H 'X-Shunt: 1'）"
        return ""

    def route(self, m):
        u = urlparse(self.path)
        p = u.path
        why = self.guard(m, p)
        if why:
            return self.deny(why)
        if m == "GET" and (p in ("/", "/index.html") or p.lstrip("/") in STATIC_TYPES):
            return self.send_static("index.html" if p == "/" else p.lstrip("/"))
        if m == "GET" and p == "/manifest.webmanifest":
            return self.send(200, json.dumps(MANIFEST, ensure_ascii=False).encode(), "application/manifest+json")
        if m == "GET" and p == "/bg":  # 背景图：CSS url() 无法带登录头，只读、不含敏感信息
            try:
                with open(BG_FILE, "rb") as f:
                    raw = f.read()
            except OSError:
                return self.send(404, {"message": "未设置背景图"})
            self.send_response(200)
            self.send_header("Content-Type", bg_type(raw[:16]) or "application/octet-stream")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "public, max-age=31536000, immutable")  # 前端用 ?v=修改时间 刷新
            self.end_headers()
            self.wfile.write(raw)
            return
        if not p.startswith("/api/"):
            return self.send(404, {"message": "not found"})
        if p == "/api/logstream" and m == "GET":  # EventSource 无法带自定义头，用 /api/logticket 换来的一次性票据
            qs = parse_qs(u.query)
            if not ticket_use(q1(qs, "ticket")):
                return self.send(401, {"message": "未登录"})
            return self.logstream(q1(qs, "level", default="info"))
        try:
            return self.api(m, p, u.query)
        except (BrokenPipeError, ConnectionResetError):
            raise
        except Exception as e:
            log_err(f"{m} {p}", e, tb=True)  # 堆栈只写服务端日志
            return self.send(500, {"message": "内部错误"})

    def logstream(self, level):
        if level not in ("debug", "info", "warning", "error"):
            level = "info"
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        q, stop = deque(), {}
        ev = threading.Event()

        def sink(line):
            q.append(line)
            ev.set()

        cname = CORES.get(active_core(load()), "mihomo")

        def reader():
            try:
                core_stream(f"/logs?level={level}", sink, stop)
                sink(json.dumps({"type": "warning", "payload": "日志流已结束（%s 可能已重启），正在重连…" % cname}))
            except ConnectionRefusedError:  # 核心进程不在（重启中 / 已停止 / 崩溃）：控制端口没人监听
                sink(json.dumps({"type": "warning", "payload": "%s 内核未运行或正在重启，等待恢复…" % cname, "retry": 1}))
            except Exception as e:
                sink(json.dumps({"type": "error", "payload": "无法连接 %s 日志流：%s" % (cname, e)}))
            stop["ended"] = True
            ev.set()

        threading.Thread(target=reader, daemon=True).start()
        try:
            while True:
                ev.wait(15)
                ev.clear()
                if not q and not stop.get("ended"):
                    self.wfile.write(b": ping\n\n")  # 心跳，同时探测浏览器是否断开
                while q:
                    self.wfile.write(b"data: " + q.popleft().encode() + b"\n\n")
                self.wfile.flush()
                if stop.get("ended"):
                    break
        except Exception:
            pass
        finally:
            stop["stop"] = True
            try:
                stop["sock"].shutdown(socket.SHUT_RDWR)
            except (KeyError, OSError):
                pass

    def reply(self, ok, msg):
        return self.send(200 if ok else 500, {"message": msg})

    def set_proxy_mode(self, b):
        mode = b.get("mode")
        if mode not in PROXY_MODES:
            return self.send(400, {"message": "代理方式无效"})
        tun_in = b.get("tun") or {}
        if tun_in.get("stack") is not None and tun_in["stack"] not in TUN_STACKS:
            return self.send(400, {"message": "TUN 协议栈只能是 system / gvisor / mixed"})

        def fn(d):
            d["proxy_mode"], d["tproxy"] = mode, mode == "tproxy"
            t = d["tun"]
            for k in ("stack", "auto_redirect", "strict_route"):
                if k in tun_in:
                    t[k] = tun_in[k] if k == "stack" else bool(tun_in[k])
            if "device" in tun_in:
                t["device"] = safe_dev(tun_in["device"])
        prev = update(fn)
        ok, msg = reload_core(prev)  # TUN 开关在配置里，先校验并重载核心
        if not ok:
            return self.send(500, {"message": msg})
        WD["tp_off"] = False
        code, out = sh(TPROXY_SH + " apply")
        label = {"tproxy": "TProxy", "tun": "TUN", "off": "关闭"}[mode]
        note = ""
        if mode == "tun":  # mihomo -t 只做语法校验；TUN 网卡创建失败时核心照常运行，需要单独确认
            err = tun_runtime_error(safe_dev(load()["tun"].get("device")))
            if active_core() == "singbox" and load()["tun"].get("auto_redirect", True) and not nft_ok():
                note = "（内核不支持 nftables，auto-redirect 未启用）"
            if err and "redirect" in err.lower() and load()["tun"].get("auto_redirect"):
                # auto-redirect 依赖 nftables / iptables，内核不支持时自动关闭后重试一次
                update(lambda d: d["tun"].update(auto_redirect=False))
                ok, msg = reload_core()
                err = tun_runtime_error(safe_dev(load()["tun"].get("device"))) if ok else msg
                note = "（auto-redirect 不可用，已自动关闭）" if not err else ""
            if err:  # TUN 起不来时局域网会断网：恢复为原来的代理方式
                save(prev)
                reload_core()
                sh(TPROXY_SH + " apply")
                return self.send(500, {"message": "TUN 启动失败，已恢复原来的代理方式：" + err +
                                       "。可尝试：关闭 auto-redirect、换用 gvisor 协议栈、确认以 root 运行并已加载 tun 模块（modprobe tun）"})
        if code != 0:
            return self.send(500, {"message": f"核心已切换为 {label}，但 nftables 规则处理失败：{out[-200:]}"})
        return self.send(200, {"message": f"代理方式：{label}{note}。" + (out.splitlines()[-1] if out else "")})

    def save_adblock(self, b):
        cur = load()["adblock"]
        lists = []
        seen = set()
        for l in b.get("lists", cur["lists"]):
            url = str(l.get("url") or "").strip()
            name = str(l.get("name") or "").strip()[:40] or (url.split("/")[2] if url.count("/") >= 2 else "")
            if not url.startswith(("http://", "https://")):
                return self.send(400, {"message": f"列表地址无效：{url or '(空)'}"})
            lid = list_id(url)
            if lid in seen:
                continue
            seen.add(lid)
            lists.append({"id": lid, "name": name or lid, "url": url, "enabled": bool(l.get("enabled", True))})
        clean = lambda xs: [x.strip() for x in xs if str(x).strip()][:20000]
        new = {"enabled": bool(b.get("enabled", cur["enabled"])), "lists": lists,
               "black": clean(b.get("black", cur["black"])), "white": clean(b.get("white", cur["white"])),
               "interval": int(b.get("interval", cur["interval"]) or 0), "dns": bool(b.get("dns", cur["dns"]))}
        if new["interval"] not in (0, 21600, 43200, 86400, 259200, 604800):
            return self.send(400, {"message": "更新间隔无效"})
        for key, label in (("black", "黑名单"), ("white", "白名单")):
            bs, be, as_, ae, sk = parse_filter("\n".join(new[key]), plain_suffix=True)
            if sk:
                bad = [x for x in new[key] if not any(parse_filter(x, plain_suffix=True)[:4])]
                return self.send(400, {"message": f"{label}中有无法识别的条目：" + "；".join(bad[:5])})
        prev = update(lambda d: d.update(adblock=new))
        need = [l["id"] for l in lists if l["enabled"] and not os.path.isfile(os.path.join(AB_DIR, l["id"] + ".txt"))]
        ab_compose(load())
        ok, msg = reload_core(prev)
        if not ok:
            ab_compose(load())
            return self.send(500, {"message": msg})
        AB_CACHE.clear()
        if new["enabled"] and need and not AB_STATE["updating"]:
            threading.Thread(target=adblock_update, args=(need,), daemon=True).start()
            return self.send(200, {"message": "已保存，正在下载新增的列表…"})
        return self.send(200, {"message": "已保存并生效"})

    def save_dns(self, b):
        d0 = load()
        cur = dns_cfg(d0)
        if b.get("reset"):
            dc = copy.deepcopy(DNS_DEFAULT)
        elif b.get("preset") == "antileak":
            dc = antileak_dns(cur)
        else:
            dc = dict(cur)
            for k in DNS_LISTS:
                if k in b:
                    if not isinstance(b[k], list):
                        return self.send(400, {"message": f"{k} 应为列表"})
                    dc[k] = [str(x).strip() for x in b[k] if str(x).strip()]
            for k in ("mode", "cache"):
                if k in b:
                    dc[k] = b[k]
            for k in ("policy", "respect_rules", "block_bypass"):
                if k in b:
                    dc[k] = bool(b[k])
            for k in ("hosts", "policies"):
                if k in b:
                    if not isinstance(b[k], list):
                        return self.send(400, {"message": f"{k} 应为列表"})
                    dc[k] = b[k]
        if dc["mode"] not in ("fake-ip", "redir-host"):
            return self.send(400, {"message": "增强模式只能是 fake-ip 或 redir-host"})
        if dc["cache"] not in ("arc", "lru"):
            return self.send(400, {"message": "缓存算法只能是 arc 或 lru"})
        dc = dns_cfg({"dns": dc})
        errs = validate_dns(dc, d0)
        if errs:
            return self.send(400, {"message": "；".join(errs[:5])})
        sniff = b.get("preset") == "antileak" and not d0.get("sniffer", True)

        def fn(d):
            d["dns"] = dc
            if sniff:
                d["sniffer"] = True
        prev = update(fn)
        ok, msg = reload_core(prev)
        if ok and dns_cfg(prev)["block_bypass"] != dc["block_bypass"] and prev.get("proxy_mode") != "off":
            sh(TPROXY_SH + " apply")  # 重新加载 nftables：是否劫持发往任意服务器的 53 端口
        if ok:
            core("POST", "/cache/dns/flush")
            core("POST", "/cache/fakeip/flush") if dc["mode"] == "fake-ip" else None
        done = "已应用防泄露设置" if b.get("preset") == "antileak" else "DNS 设置已生效"
        return self.reply(ok, done if ok else msg)

    def groups_info(self):
        d = load()
        cfg = build_config(d)
        names = [p["name"] for p in cfg["proxies"]]
        plan = region_plan(d, names, list(cfg["proxy-providers"]))
        gnames = [g["name"] for g in cfg["proxy-groups"]]
        meta = group_meta(d, cfg)
        sb = active_core(d) == "singbox"
        if sb:  # sing-box：地区负载均衡并入自动优选，自定义负载均衡 / 故障转移按自动测速运行
            lbs = region_lb_set()
            gnames = [g for g in gnames if g not in lbs]
            for n in list(meta):
                if n in lbs:
                    meta.pop(n)
                elif meta[n]["type"] in ("load-balance", "fallback"):
                    meta[n].update(sb_from=meta[n]["type"], type="url-test")
        regions = [{"name": r[0], "total": r[4], "manual": len(r[3]), "unknown": r[5],
                    "groups": [g for g in gnames if g in [auto_name(r[0])] + lb_names(r[0])]} for r in plan]
        sel = next((g.get("proxies") or [] for g in cfg["proxy-groups"] if g["name"] == G_SEL), [])
        if sb:
            sel = [x for x in sel if x in gnames or x in BUILTIN_POLICIES]
        return self.send(200, {"cfg": gcfg(d), "region_groups": d["region_groups"], "custom": d["custom_groups"],
                               "regions": regions, "groups": gnames, "manual": names, "nodes": all_node_names(d),
                               "meta": meta, "core": active_core(d), "types": GROUP_TYPES, "strategies": LB_STRATEGIES,
                               "region_names": [r[0] for r in REGIONS], "primary": PRIMARY_REGIONS, "selector": sel})

    def save_groups_cfg(self, b):
        gc = gcfg(load())
        for k in ("lb", "extra", "other", "lazy", "lgbm"):
            if k in b:
                gc[k] = bool(b[k])
        try:
            if "interval" in b:
                gc["interval"] = int(b["interval"])
            if "tolerance" in b:
                gc["tolerance"] = int(b["tolerance"])
        except (TypeError, ValueError):
            return self.send(400, {"message": "测速间隔 / 容差必须是数字"})
        if not 30 <= gc["interval"] <= 86400:
            return self.send(400, {"message": "测速间隔应在 30–86400 秒之间"})
        if not 0 <= gc["tolerance"] <= 1000:
            return self.send(400, {"message": "容差应在 0–1000 ms 之间"})
        if "url" in b:
            u = str(b["url"]).strip()
            if not re.match(r"^https?://\S+$", u):
                return self.send(400, {"message": "测速地址必须是 http(s) 链接"})
            gc["url"] = u

        def fn(d):
            d["groups_cfg"] = gc
            if "region_groups" in b:
                d["region_groups"] = bool(b["region_groups"])
        test = load()
        fn(test)
        errs = validate_groups(test)
        if errs:
            return self.send(400, {"message": "；".join(errs[:3])})
        prev = update(fn)
        ok, msg = reload_core(prev)
        if ok and gc["lgbm"] and active_core() == "smart" and not os.path.isfile(LGBM_FILE):
            threading.Thread(target=lgbm_fetch_reload, daemon=True).start()
            msg = "策略组设置已生效，LightGBM 模型正在后台下载，下载完会自动重载"
        return self.reply(ok, "策略组设置已生效" if ok else msg)

    def save_custom_group(self, b):
        try:
            g = clean_custom_group(b)
        except ValueError as e:
            return self.send(400, {"message": str(e)})
        orig = str(b.get("orig") or "").strip()
        cur = load()
        if orig and not any(x["name"] == orig for x in cur["custom_groups"]):
            return self.send(404, {"message": f"策略组不存在：{orig}"})
        if g["name"] != orig and any(x["name"] == g["name"] for x in cur["custom_groups"]):
            return self.send(400, {"message": f"已存在同名策略组：{g['name']}"})
        info = {"refs": 0}

        def fn(d):
            if orig:
                d["custom_groups"] = [g if x["name"] == orig else x for x in d["custom_groups"]]
                if g["name"] != orig:
                    info["refs"] = rename_policy(d, orig, g["name"])
            else:
                d["custom_groups"].append(g)
        test = copy.deepcopy(cur)
        fn(test)
        errs = validate_groups(test)
        if errs:
            return self.send(400, {"message": "；".join(errs[:3])})
        prev = update(fn)
        ok, msg = reload_core(prev)
        if not ok:
            return self.send(500, {"message": msg})
        extra = f"，已同步更新 {info['refs']} 处引用" if info["refs"] else ""
        return self.send(200, {"message": ("已保存策略组 " if orig else "已创建策略组 ") + g["name"] + extra})

    def delete_custom_group(self, b):
        name = str(b.get("name") or "")
        cur = load()
        if not any(x["name"] == name for x in cur["custom_groups"]):
            return self.send(404, {"message": f"策略组不存在：{name}"})
        users = [x["name"] for x in cur["custom_groups"] if name in x.get("proxies", [])]
        if users and not b.get("force"):
            return self.send(409, {"message": f"「{name}」被其他策略组引用：{'、'.join(users)}。确认删除会同时从这些组中移除它", "users": users})
        info = {"refs": 0}

        def fn(d):
            d["custom_groups"] = [x for x in d["custom_groups"] if x["name"] != name]
            info["refs"] = rename_policy(d, name, G_SEL)
        prev = update(fn)
        ok, msg = reload_core(prev)
        if not ok:
            return self.send(500, {"message": msg})
        extra = f"，{info['refs']} 处引用已改为「{G_SEL}」" if info["refs"] else ""
        return self.send(200, {"message": f"已删除 {name}{extra}"})

    def api(self, m, p, q):
        b = self.body() if m in ("POST", "PUT", "PATCH", "DELETE") else {}
        # 透传到 mihomo external-controller
        if p.startswith("/api/core/") and active_core() == "singbox":
            sub = p[len("/api/core"):]
            if sub == "/providers/proxies" and m == "GET":
                return self.send(200, sb_fake_providers(load()))
            if sub == "/providers/rules" and m == "GET":
                return self.send(200, sb_fake_rule_providers(load()))
            if sub.startswith("/providers/proxies/") and m == "PUT":
                okl, bad = sb_update_subs([unquote(sub.rsplit("/", 1)[1])])
                if not bad:
                    refresh_regions()
                return self.send(204 if not bad else 502, b"" if not bad else {"message": "；".join(bad)})
            if sub.startswith("/providers/proxies/") and sub.endswith("/healthcheck"):
                code, raw = core("GET", f"/group/{quote(G_MANUAL)}/delay?url={quote(HC)}&timeout=5000", timeout=60)
                return self.send(204 if code < 300 else code, b"")
            if (sub.startswith("/providers/rules/") and m == "PUT") or sub == "/configs/geo":
                d = load()
                need = sb_rule_need(d)
                if sub.startswith("/providers/rules/"):
                    nm = unquote(sub.rsplit("/", 1)[1])
                    need = {k: v for k, v in need.items() if k == nm}
                bad = sb_sync_assets(d, force=True, need=need)
                ok, msg = reload_core()
                return self.send(204 if not bad and ok else 502, b"" if not bad and ok else {"message": "；".join(bad) or msg})
            if sub.startswith("/configs") and m == "PUT":
                return self.reply(*reload_core())
            if sub == "/upgrade":
                return self.send(400, {"message": "请在 设置 → 核心 → 内核更新 里更新 sing-box"})
        if p.startswith("/api/core/"):
            slow = p.endswith("/delay") or p.endswith("/healthcheck")  # 测速可能超过默认 10 秒
            code, raw = core(m, p[len("/api/core"):] + ("?" + q if q else ""), b if b else None, timeout=60 if slow else 10)
            return self.send(code, raw or b"{}")
        if p == "/api/coreupdate" and m == "GET" and (q1(parse_qs(q), "core") or active_core()) == "singbox":
            ch = q1(parse_qs(q), "channel", default="stable")
            info = {"current": sb_version() or "未安装", "arch": sb_arch() or os.uname().machine, "channel": ch,
                    "backup": sb_version(SB_BIN + ".bak"), "remote": "", "busy": CORE_UPD["busy"], "core": "singbox"}
            try:
                info["remote"] = sb_remote_version(ch, load().get("gh_proxy") or "")
            except Exception as e:
                info["message"] = "获取最新版本失败：" + str(e)
                return self.send(502, info)
            info["latest"] = info["remote"] == sb_version()
            return self.send(200, info)
        if p == "/api/coreupdate" and m == "POST" and (b.get("core") or active_core()) == "singbox":
            if b.get("action") == "rollback":
                if not sb_version(SB_BIN + ".bak"):
                    return self.send(400, {"message": "没有可回滚的 sing-box 备份"})
                tmp = SB_BIN + ".swap"
                shutil.copy2(SB_BIN, tmp)
                os.replace(SB_BIN + ".bak", SB_BIN)
                os.replace(tmp, SB_BIN + ".bak")
                if active_core() == "singbox":
                    svc_restart(timeout=90)
                return self.reply(True, f"已回滚到 sing-box {sb_version()}")
            ch = b.get("channel") or "stable"
            ok, msg = core_job_start(sb_update_job, ch, load().get("gh_proxy") or "", bool(b.get("force")))
            return self.send(200 if ok else 409, {"message": msg})
        if p == "/api/delay":
            return self.send(200, delay_test(force=q1(parse_qs(q), "force") == "1"))
        if p == "/api/favicon":
            b, ct = favicon(q1(parse_qs(q), "u", default=""))
            if not b:
                return self.send(404, {"message": "无图标"})
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "max-age=86400")
            self.end_headers()
            return self.wfile.write(b)
        if p == "/api/unlock":
            return self.send(200, unlock_test())
        if p == "/api/logs":
            _, out = sh(f"tail -n 300 '{MIHOMO_LOG}'")
            return self.send(200, {"log": out})
        fn = ROUTES.get((m, p))
        if fn:
            return fn(self, m, p, b, q)
        return self.send(404, {"message": "not found"})

    @api_route("/api/state", "GET")
    def api_state_get(self, m, p, b, q):
        d = load()
        st, code, version = _svc_status()
        cfgver = config_version()
        gv = _GRP_CACHE.get("v")
        if gv is None or gv[0] != cfgver:  # 配置未变时复用策略组名单，不再完整 build_config
            cfg = build_config(d)
            groups = [g["name"] for g in cfg["proxy-groups"]]
            gmeta = group_meta(d, cfg)
            if active_core(d) == "singbox":  # 地区负载均衡并入自动优选；负载均衡 / 故障转移按自动测速运行
                lbs = region_lb_set()
                groups = [g for g in groups if g not in lbs]
                for n, mt in list(gmeta.items()):
                    if n in lbs:
                        gmeta.pop(n)
                    elif mt["type"] in ("load-balance", "fallback"):
                        mt.update(sb_from=mt["type"], type="url-test")
            _GRP_CACHE["v"] = (cfgver, groups, gmeta)
        else:
            _, groups, gmeta = gv
        return self.send(200, {"mode": d["mode"], "subs": d["subs"], "rules": d["rules"],
                               "running": "started" in st or code == 200, "version": version, "groups": groups,
                               "nodes": [{"name": n["proxy"]["name"], "type": n["proxy"]["type"],
                                                            "server": n["proxy"]["server"], "port": n["proxy"]["port"]} for n in d["nodes"]],
                               "rulesets": d["rulesets"], "bypass": d["bypass"], "tests": d["tests"],
                               "sub_interval": d["sub_interval"],
                               "ipv6": d["ipv6"], "https": d["https"],
                               "watchdog": d["watchdog"], "tg_token": d["tg_token"], "tg_chat": d["tg_chat"],
                               "default_exclude": DEFAULT_EXCLUDE, "proxy_mode": d["proxy_mode"], "tun": d["tun"],
                               "log_limit": d["log_limit"], "dns": dns_cfg(d),
                               "schedule": d["schedule"], "devices": d["devices"], "adblock_on": d["adblock"]["enabled"],
                               "sched_events": list(SCHED["events"])[:20], "group_meta": gmeta,
                               "sniffer": d["sniffer"],
                               "gh_proxy": d["gh_proxy"], "panel_version": PANEL_VERSION, "core": active_core(d),
                               "wd": {"status": WD["status"], "last_check": WD["last_check"],
                                      "events": list(WD["events"])[:20]}})

    @api_route("/api/ping", "GET")
    def api_ping_get(self, m, p, b, q):
        """轻量心跳：前端 15 秒轮询，version（data.json 每次 save 自增）变化时才拉全量 /api/state"""
        return self.send(200, {"ok": True, "core": active_core(), "version": config_version(), "ad_today": ad_today()})

    @api_route("/api/groups", "GET")
    def api_groups_get(self, m, p, b, q):
        return self.groups_info()

    @api_route("/api/groups/cfg", "PUT")
    def api_groups_cfg_put(self, m, p, b, q):
        return self.save_groups_cfg(b)

    @api_route("/api/groups", "POST")
    def api_groups_post(self, m, p, b, q):
        return self.save_custom_group(b)

    @api_route("/api/groups", "DELETE")
    def api_groups_delete(self, m, p, b, q):
        return self.delete_custom_group(b)

    @api_route("/api/groups/preview", "POST")
    def api_groups_preview_post(self, m, p, b, q):
        flt = str(b.get("filter") or "").strip()
        if not flt:
            return self.send(200, {"matched": [], "total": 0})
        r = rx(flt)
        if r is None:
            return self.send(400, {"message": "正则无效"})
        d = load()
        manual = [n["proxy"]["name"] for n in d["nodes"]]
        allnodes = all_node_names(d) if b.get("subs", True) else manual
        hit = [n for n in allnodes if r.search(n)]
        return self.send(200, {"matched": hit[:200], "total": len(hit), "of": len(allnodes)})

    @api_route("/api/groups/refresh", "POST")
    def api_groups_refresh_post(self, m, p, b, q):
        return self.reply(*refresh_regions())

    @api_route("/api/config", "GET")
    def api_config_get(self, m, p, b, q):
        txt = config_view(load(), masked=True)
        sbm = active_core() == "singbox"
        if "download" in parse_qs(q):
            return self.send(200, txt.encode(), "application/json" if sbm else "application/x-yaml")
        return self.send(200, {"text": txt, "path": core_conf_path(), "size": len(txt.encode()), "core": active_core()})

    @api_route("/api/sysopt", "GET")
    def api_sysopt_get(self, m, p, b, q):
        return self.send(200, opt_status())

    @api_route("/api/sysopt", "POST")
    def api_sysopt_post(self, m, p, b, q):
        ids = b.get("ids")
        if not isinstance(ids, list):
            return self.send(400, {"message": "参数错误"})
        ok, msg, errs = opt_apply([str(i) for i in ids])
        return self.send(200, {"ok": ok, "message": msg, "errors": errs} | opt_status())

    @api_route("/api/speedtest", "GET")
    def api_speedtest_get(self, m, p, b, q):
        via = q1(parse_qs(q), "via", default="proxy")
        return self.send(200, speed_test(via == "proxy"))

    @api_route("/api/direct_delay", "GET")
    def api_direct_delay_get(self, m, p, b, q):
        """直连国内延迟：DIRECT 是国内直连，单独测百度"""
        from .sysopt import direct_rtt
        return self.send(200, {"ms": direct_rtt()})

    @api_route("/api/bg", "GET")
    def api_bg_get(self, m, p, b, q):
        bm = bg_meta()
        try:
            return self.send(200, {"exists": True, "v": int(os.path.getmtime(BG_FILE)), "size": os.path.getsize(BG_FILE),
                                   "url": bm.get("url", ""), "daily": bool(bm.get("daily"))})
        except OSError:
            return self.send(200, {"exists": False})

    @api_route("/api/bg", "POST")
    def api_bg_post(self, m, p, b, q):
        ok, msg = bg_save(b.get("data"))
        if not ok:
            return self.send(400, {"message": msg})
        bg_meta_save({})  # 改为上传的图片：不再按链接刷新
        return self.send(200, {"message": msg, "v": int(os.path.getmtime(BG_FILE))})

    @api_route("/api/bg/url", "POST")
    def api_bg_url_post(self, m, p, b, q):
        url = str(b.get("url") or "").strip() or bg_meta().get("url", "")
        ok, msg = bg_fetch(url)
        if not ok:
            return self.send(400, {"message": msg})
        bg_meta_save({"url": url, "daily": bool(b.get("daily")), "t": int(time.time())})
        return self.send(200, {"message": msg, "v": int(os.path.getmtime(BG_FILE))})

    @api_route("/api/bg/daily", "POST")
    def api_bg_daily_post(self, m, p, b, q):
        bm = bg_meta()
        if not bm.get("url"):
            return self.send(400, {"message": "当前背景图不是链接图片"})
        bm["daily"] = bool(b.get("daily"))
        bg_meta_save(bm)
        return self.send(200, {"message": "已开启每天自动更新" if bm["daily"] else "已关闭每天自动更新"})

    @api_route("/api/bg", "DELETE")
    def api_bg_delete(self, m, p, b, q):
        try:
            os.remove(BG_FILE)
        except OSError:
            pass
        bg_meta_save({})
        return self.send(200, {"message": "已移除背景图"})

    @api_route("/api/px", "GET")
    def api_px_get(self, m, p, b, q):
        px = proxies_merged()
        if px is None:
            return self.send(502, {"message": "核心未运行或无法连接"})
        return self.send(200, {"proxies": px, "retesting": RETEST["pending"]})

    @api_route("/api/coreswitch", "GET")
    def api_coreswitch_get(self, m, p, b, q):
        d = load()
        if active_core(d) == "singbox" and not SB_STATE["warn"]:
            SB_STATE["warn"] = build_singbox(d)[1]
        return self.send(200, {"core": active_core(d), "versions": {"mihomo": bin_version(MIHOMO_BIN), "smart": bin_version(SMART_BIN), "singbox": sb_version()},
                               "lgbm": os.path.isfile(LGBM_FILE),
                               "warn": SB_STATE["warn"] if active_core(d) == "singbox" else [], "busy": CORE_UPD["busy"]})

    @api_route("/api/coreswitch", "POST")
    def api_coreswitch_post(self, m, p, b, q):
        kind = b.get("core")
        if kind not in CORES:
            return self.send(400, {"message": "未知的内核"})
        if kind == active_core():
            return self.send(400, {"message": f"当前已经是 {CORES[kind]}"})
        ok, msg = core_job_start(core_switch_job, kind, load().get("gh_proxy") or "")
        return self.send(200 if ok else 409, {"message": msg})

    @api_route("/api/coreupdate", "GET")
    def api_coreupdate_get(self, m, p, b, q):
        ch = q1(parse_qs(q), "channel", default="stable")
        kind = "smart" if (q1(parse_qs(q), "core") or active_core()) == "smart" else "mihomo"
        if ch not in CORE_CHANNELS:
            return self.send(400, {"message": "未知的更新通道"})
        ok, info = core_check(ch, load().get("gh_proxy") or "", kind)
        info["busy"] = CORE_UPD["busy"]
        return self.send(200 if ok else 502, info)

    @api_route("/api/coreupdate/status", "GET")
    def api_coreupdate_status_get(self, m, p, b, q):
        return self.send(200, core_upd_status())

    @api_route("/api/coreupdate", "POST")
    def api_coreupdate_post(self, m, p, b, q):
        kind = "smart" if (b.get("core") or active_core()) == "smart" else "mihomo"
        if b.get("action") == "lgbm":
            try:
                n = lgbm_fetch(load().get("gh_proxy") or "")
            except Exception as e:
                return self.send(502, {"message": "模型下载失败：" + str(e)[:200]})
            if active_core() == "smart":
                reload_core()
            return self.reply(True, f"LightGBM 模型已更新（{n // 2**20} MB）")
        if b.get("action") == "rollback":
            ok, msg = core_job_start(core_rollback_job, kind)
        else:
            ch = "alpha" if kind == "smart" else (b.get("channel") or "stable")
            if ch not in CORE_CHANNELS:
                return self.send(400, {"message": "未知的更新通道"})
            ok, msg = core_job_start(core_update_job, ch, load().get("gh_proxy") or "", bool(b.get("force")), kind)
        return self.send(200 if ok else 409, {"message": msg})

    @api_route("/api/selfupdate", "GET")
    def api_selfupdate_get(self, m, p, b, q):
        ok, info = self_update(False, load().get("gh_proxy") or "")
        return self.send(200 if ok else 502, info)

    @api_route("/api/selfupdate", "POST")
    def api_selfupdate_post(self, m, p, b, q):
        if b.get("action") == "rollback":
            return self.reply(*self_rollback())
        ok, info = self_update(True, load().get("gh_proxy") or "")
        return self.send(200 if ok else 500, info)

    @api_route("/api/subs/update", "POST")
    def api_subs_update_post(self, m, p, b, q):
        name = b.get("name") or ""
        names = [s["name"] for s in load()["subs"]] if not name else [name]
        if active_core() == "singbox":
            okl, bad = sb_update_subs(names)
            ok2, msg2 = refresh_regions()
            msg = ("已更新：" + "；".join(okl) if not bad else "更新失败：" + "；".join(bad)) + ("；" + msg2 if msg2 and "无变化" not in msg2 else "")
            return self.reply(not bad, msg)
        bad = []
        for nm in names:
            code, raw = core("PUT", "/providers/proxies/" + quote(nm), timeout=120)
            if code >= 300:
                bad.append(nm + "：" + raw.decode(errors="ignore")[:100])
        ok2, msg2 = refresh_regions()
        msg = ("已更新" if not bad else "更新失败：" + "；".join(bad)) + ("；" + msg2 if msg2 and "无变化" not in msg2 else "")
        return self.reply(not bad, msg)

    @api_route("/api/stats", "GET")
    def api_stats_get(self, m, p, b, q):
        return self.send(200, stats.STATS.report() if stats.STATS else {"today": {}, "month": {}, "days": [], "arp": {}})

    @api_route("/api/ruletest", "POST")
    def api_ruletest_post(self, m, p, b, q):
        return self.send(200, rule_test(b.get("target") or ""))

    @api_route("/api/subs", "POST")
    def api_subs_post(self, m, p, b, q):
        name, url = (b.get("name") or "").strip(), (b.get("url") or "").strip()
        if not name or not url.startswith("http"):
            return self.send(400, {"message": "名称或订阅链接无效"})
        flt, exc = (b.get("filter") or "").strip(), (b["exclude"] if "exclude" in b else DEFAULT_EXCLUDE).strip()
        for pat in (flt, exc):
            try:
                re.compile(pat)
            except re.error as e:
                return self.send(400, {"message": f"正则表达式无效：{pat}（{e}）"})
        prev = update(lambda d: d.update(subs=[s for s in d["subs"] if s["name"] != name] +
                                          [{"name": name, "url": url, "filter": flt, "exclude": exc}]))
        if active_core() == "singbox":  # 先由面板下载节点，再生成配置
            okl, bad = sb_update_subs([name])
            ok, msg = reload_core(prev)
            if ok and bad:
                ok, msg = False, "订阅已保存，但下载失败：" + "；".join(bad)
            return self.reply(ok, msg if not ok else "已添加：" + "；".join(okl))
        ok, msg = reload_core(prev)
        if ok:
            refresh_after_sub(name)  # 订阅下载完成后按实际节点生成地区 / 均衡分组
        return self.reply(ok, msg)

    @api_route("/api/subs", "DELETE")
    def api_subs_delete(self, m, p, b, q):
        prev = update(lambda d: d.update(subs=[s for s in d["subs"] if s["name"] != b.get("name")]))
        return self.reply(*reload_core(prev))

    @api_route("/api/nodes", "POST")
    def api_nodes_post(self, m, p, b, q):
        d = load()
        added, errs = add_links(b.get("links") or "", d["nodes"], d)
        if not added:
            return self.send(400, {"message": "没有可导入的节点" + ("：\n" + "\n".join(errs) if errs else "")})
        prev = update(lambda d: d["nodes"].extend(added))
        ok, msg = reload_core(prev)
        msg = (f"已导入 {len(added)} 个节点" if ok else msg) + ("；忽略：" + "；".join(errs) if errs else "")
        return self.reply(ok, msg)

    @api_route("/api/nodes", "DELETE")
    def api_nodes_delete(self, m, p, b, q):
        names = set(b.get("names") or [b.get("name")])
        prev = update(lambda d: d.update(nodes=[n for n in d["nodes"] if n["proxy"]["name"] not in names]))
        return self.reply(*reload_core(prev))

    @api_route("/api/rules", "PUT")
    def api_rules_put(self, m, p, b, q):
        rules = [r.strip() for r in b.get("rules", []) if r.strip()]
        bad = bad_rule_policies([r for r in rules if not r.startswith("#")], load())
        if bad:
            return self.send(400, {"message": "以下规则的策略不存在：" + "；".join(bad[:5])})
        prev = update(lambda d: d.update(rules=rules))
        return self.reply(*reload_core(prev))

    @api_route("/api/mode", "PUT")
    def api_mode_put(self, m, p, b, q):
        mode = b.get("mode")
        if mode not in ("rule", "global", "direct"):
            return self.send(400, {"message": "模式无效"})
        with LOCK:
            d = load()
            d["mode"] = mode
            save(d)
            sb = active_core(d) == "singbox"
            write_active_config(d)
        core("PATCH", "/configs", {"mode": mode.capitalize() if sb else mode})
        if mode == "global":
            fix_global()
        return self.send(200, {"message": "ok"})

    @api_route("/api/proxymode", "PUT")
    def api_proxymode_put(self, m, p, b, q):
        return self.set_proxy_mode(b)

    @api_route("/api/conns", "GET")
    def api_conns_get(self, m, p, b, q):
        # 精简后的连接列表：只保留前端用到的字段（/connections 走 2 秒共享快照）
        c = conns_snapshot(timeout=5)
        if c is None:
            return self.send(502, {"message": "mihomo 未运行或无法连接"})
        keep = ("sourceIP", "host", "sniffHost", "destinationIP", "destinationPort", "network")
        out = [{"id": x.get("id"), "start": x.get("start"), "upload": x.get("upload", 0), "download": x.get("download", 0),
                "rule": x.get("rule"), "rulePayload": x.get("rulePayload"), "chains": x.get("chains"),
                "metadata": {k: (x.get("metadata") or {}).get(k) for k in keep}} for x in c.get("connections") or []]
        return self.send(200, {"connections": out})

    @api_route("/api/live", "GET")
    def api_live_get(self, m, p, b, q):
        out = dict(LIVE)
        if time.time() - out["t"] > 5:  # 后台 /traffic 流未就绪（核心刚启动或已停止）时退回连接快照
            c = conns_snapshot(timeout=3)
            out.update(up=0, down=0, upTotal=(c or {}).get("uploadTotal", 0), downTotal=(c or {}).get("downloadTotal", 0))
            out["stale"] = True
        if not out["inuse"]:
            out.update(memory_once())
        out["running"] = time.time() - LIVE["t"] < 5 or bool(out.get("inuse"))
        return self.send(200, out)

    @api_route("/api/logs/info", "GET")
    def api_logs_info_get(self, m, p, b, q):
        return self.send(200, {"files": log_sizes(), "limit": load()["log_limit"], "last": LOG_STATE["last"]})

    @api_route("/api/logs/clean", "POST")
    def api_logs_clean_post(self, m, p, b, q):
        freed = log_clean(force=True)
        return self.send(200, {"message": f"已清理，释放 {fmt_size(freed)}", "files": log_sizes()})

    @api_route("/api/adblock", "GET")
    def api_adblock_get(self, m, p, b, q):
        d = load()
        meta = ab_meta()
        rep = adblock.AD_STATS.report() if adblock.AD_STATS else {"today": 0, "top": [], "lists": {}, "days": []}
        lists = [dict(l, **{k: v for k, v in (meta.get(l["id"]) or {}).items()}, hits=rep["lists"].get(l["id"], 0)) for l in d["adblock"]["lists"]]
        if active_core(d) == "singbox":  # sing-box 的 clash_api 没有规则集信息：按已转换好的规则集文件统计
            loaded = sb_ab_loaded(d) if d["adblock"].get("enabled") else {}
        else:
            prov = (core_json("/providers/rules") or {}).get("providers") or {}
            loaded = {k: v.get("ruleCount") for k, v in prov.items() if k.startswith("ad-")}
        return self.send(200, {**{k: v for k, v in d["adblock"].items() if k != "lists"}, "lists": lists,
                               "presets": AB_PRESETS, "stats": rep, "updating": AB_STATE["updating"], "msg": AB_STATE["msg"],
                               "custom_hits": rep["lists"].get("custom", 0),
                               "loaded": loaded})

    @api_route("/api/adblock", "PUT")
    def api_adblock_put(self, m, p, b, q):
        return self.save_adblock(b)

    @api_route("/api/adblock/update", "POST")
    def api_adblock_update_post(self, m, p, b, q):
        if AB_STATE["updating"]:
            return self.send(409, {"message": "正在更新中，请稍候"})
        threading.Thread(target=adblock_update, args=(b.get("ids"),), daemon=True).start()
        return self.send(200, {"message": "已开始下载，完成后自动生效"})

    @api_route("/api/adblock/check", "POST")
    def api_adblock_check_post(self, m, p, b, q):
        return self.send(200, ab_check(b.get("domain") or ""))

    @api_route("/api/dns", "PUT")
    def api_dns_put(self, m, p, b, q):
        return self.save_dns(b)

    @api_route("/api/dnsleak", "GET")
    def api_dnsleak_get(self, m, p, b, q):
        return self.send(200, leak_check(live="nolive" not in parse_qs(q)))

    @api_route("/api/history", "GET")
    def api_history_get(self, m, p, b, q):
        h = read_json(HISTORY_FILE, [])
        return self.send(200, [{"id": x["id"], "t": x["t"], "changed": x["changed"]} for x in h])

    @api_route("/api/history", "POST")
    def api_history_post(self, m, p, b, q):
        h = {x["id"]: x for x in read_json(HISTORY_FILE, [])}
        snap = h.get(str(b.get("id") or ""))
        if not snap:
            return self.send(404, {"message": "快照不存在"})

        def apply_snap(d):
            d.update({k: v for k, v in snap["data"].items() if k not in HISTORY_SKIP})
            migrate_names(d)
        prev = update(apply_snap)
        ab_compose(load())
        ok, msg = reload_core(prev)
        if ok:
            sh(TPROXY_SH + " apply")
        return self.reply(ok, ("已恢复到 " + time.strftime("%m-%d %H:%M", time.localtime(snap["t"])) + " 的配置") if ok else msg)

    @api_route("/api/dnsquery", "POST")
    def api_dnsquery_post(self, m, p, b, q):
        name = clean_target(b.get("name") or "")
        qtype = (b.get("type") or "A").upper()
        if not name or qtype not in ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "HTTPS", "SRV", "PTR"):
            return self.send(400, {"message": "请输入域名并选择记录类型"})
        st = time.time()
        code, raw = core("GET", f"/dns/query?name={quote(name)}&type={qtype}", timeout=15)
        ms = int((time.time() - st) * 1000)
        try:
            j = json.loads(raw)
        except Exception:
            j = {"message": raw.decode(errors="ignore")}
        if code != 200:
            return self.send(502 if code == 502 else code, {"message": j.get("message") or "查询失败"})
        return self.send(200, {"name": name, "type": qtype, "ms": ms, "status": j.get("Status"),
                               "answer": j.get("Answer") or [], "policy": dns_route(name, load())})

    @api_route("/api/devices", "GET")
    def api_devices_get(self, m, p, b, q):
        ips = set(arp_table()) | set(read_leases())
        if stats.STATS:
            with stats.STATS.lock:
                for b2 in stats.STATS.data["days"].values():
                    ips |= set(b2.get("dev", {}))
        c = core_json("/connections", timeout=5) or {}
        ips |= {(x.get("metadata") or {}).get("sourceIP") for x in c.get("connections") or []}
        return self.send(200, {"map": device_map(sorted(i for i in ips if i)), "custom": load()["devices"]})

    @api_route("/api/devices", "PUT")
    def api_devices_put(self, m, p, b, q):
        devs = {}
        for k, v in (b.get("devices") or {}).items():
            k, v = str(k).strip().lower().replace("-", ":"), str(v).strip()[:40]
            if k and v and (is_ip(k) or re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", k)):
                devs[k] = v
        update(lambda d: d.update(devices=devs))
        return self.send(200, {"message": f"已保存 {len(devs)} 个设备备注"})

    @api_route("/api/diag", "GET")
    def api_diag_get(self, m, p, b, q):
        return self.send(200, diagnose())

    @api_route("/api/ipinfo", "GET")
    def api_ipinfo_get(self, m, p, b, q):
        from .ipinfo import get_ipinfo
        return self.send(200, get_ipinfo())

    @api_route("/api/schedule", "PUT")
    def api_schedule_put(self, m, p, b, q):
        sc = {}
        for k in ("sub_update", "core_restart", "geo_update"):
            v = str(b.get(k) or "").strip()
            if v and not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", v):
                return self.send(400, {"message": f"时间格式应为 HH:MM：{v}"})
            sc[k] = v
        sc["latency"] = int(b.get("latency") or 0) if int(b.get("latency") or 0) in (0, 10, 30, 60, 180) else 0
        update(lambda d: d.update(schedule=sc))
        return self.send(200, {"message": "定时任务已保存"})

    @api_route("/api/schedule/run", "POST")
    def api_schedule_run_post(self, m, p, b, q):
        k = b.get("task")
        if k not in TASK_NAMES:
            return self.send(400, {"message": "未知任务"})
        ok, msg = run_task(k)
        sched_event(f"手动执行 {TASK_NAMES[k]}：{'✓' if ok else '✗'} {msg}")
        return self.reply(ok, msg)

    @api_route("/api/service", "POST")
    def api_service_post(self, m, p, b, q):
        act = b.get("action")
        if act == "reload":
            return self.reply(*reload_core())
        if act in ("restart", "stop", "start"):
            WD["manual_stop"] = act == "stop"
            if act == "stop":
                code, out = sh(SVC + " stop", timeout=90)
            else:  # 启动 / 重启：同样让看门狗等内核加载完
                wd_hold(150, "手动" + act)
                code, out = sh(SVC + " " + act, timeout=90)
                wd_hold(60, "手动" + act, reset=True)
            if act != "stop":
                retest_soon()
            return self.reply(code == 0, out)
        if act == "upgrade" and active_core() == "singbox":
            return self.send(400, {"message": "请在 设置 → 核心 → 内核更新 里更新 sing-box"})
        if act == "upgrade":
            code, raw = core("POST", "/upgrade", {}, timeout=300)
            return self.send(code if code != 502 else 500, raw or b'{"message":"ok"}')
        if act == "geo" and active_core() == "singbox":
            return self.reply(*run_task("geo_update"))
        if act == "geo":
            code, raw = core("POST", "/configs/geo", {}, timeout=120)
            return self.send(code, raw or b'{"message":"ok"}')
        return self.send(400, {"message": "未知操作"})

    @api_route("/api/settings", "PUT")
    def api_settings_put(self, m, p, b, q):
        allowed = {"rulesets", "bypass", "tests", "sub_interval", "region_groups", "ipv6", "watchdog", "tg_token", "tg_chat",
                   "log_limit", "sniffer", "gh_proxy"}
        if "gh_proxy" in b:
            b["gh_proxy"] = str(b["gh_proxy"] or "").strip()
            if b["gh_proxy"] and not re.match(r"^https?://[\w.\-:]+/?$", b["gh_proxy"]):
                return self.send(400, {"message": "GitHub 加速地址格式应为 https://ghfast.top/"})
            if b["gh_proxy"] and not b["gh_proxy"].endswith("/"):
                b["gh_proxy"] += "/"
        if "sniffer" in b:
            b["sniffer"] = bool(b["sniffer"])
        if "log_limit" in b and b["log_limit"] not in (1, 2, 5, 10, 20):
            return self.send(400, {"message": "日志上限只能是 1 / 2 / 5 / 10 / 20 MB"})
        prev = update(lambda d: d.update({k: v for k, v in b.items() if k in allowed}))
        d = load()
        msg = "已保存"
        if set(b) & {"rulesets", "sub_interval", "region_groups", "ipv6", "sniffer"} or ("bypass" in b and d["proxy_mode"] == "tun"):
            ok, msg = reload_core(prev)
            if not ok:
                return self.send(500, {"message": msg})
        if set(b) & {"bypass", "ipv6"} and d["proxy_mode"] != "off":
            sh(TPROXY_SH + " apply")
        if "watchdog" in b and not b["watchdog"]:
            WD["status"] = "off"
        return self.send(200, {"message": msg})

    @api_route("/api/https", "PUT")
    def api_https_put(self, m, p, b, q):
        on = bool(b.get("enable"))
        if on and not (os.path.isfile(CERT) and os.path.isfile(KEY)):
            ok, out = gen_cert()
            if not ok:
                return self.send(500, {"message": "生成证书失败（需要 openssl）：" + out[-200:]})
        update(lambda d: d.update(https=on))
        restart_self()
        return self.send(200, {"message": "面板将以 " + ("HTTPS" if on else "HTTP") + " 重启", "scheme": "https" if on else "http"})

    @api_route("/api/tg/test", "POST")
    def api_tg_test_post(self, m, p, b, q):
        d = load()
        if "tg_token" in b:
            d.update(tg_token=b.get("tg_token", ""), tg_chat=b.get("tg_chat", ""))
        return self.reply(*tg_send("✅ 测试消息：通知已配置成功", d))

    @api_route("/api/backup", "GET")
    def api_backup_get(self, m, p, b, q):
        d = load()
        return self.send(200, {k: v for k, v in d.items() if k != "secret"})

    @api_route("/api/restore", "POST")
    def api_restore_post(self, m, p, b, q):
        keys = ("mode", "tproxy", "subs", "rules", "rulesets", "bypass", "tests", "sub_interval", "region_groups",
                "nodes", "ipv6", "watchdog", "tg_token", "tg_chat", "proxy_mode", "tun", "log_limit", "adblock", "dns",
                "devices", "schedule", "groups_cfg", "custom_groups", "sniffer", "gh_proxy")

        def apply_backup(d):
            d.update({k: b[k] for k in keys if k in b})
            if "proxy_mode" not in b and "tproxy" in b:
                d["proxy_mode"] = "tproxy" if b["tproxy"] else "off"
            migrate_names(d)  # 旧版备份里的地区组名自动换成新名称
        prev = update(apply_backup)
        ab_compose(load())
        ok, msg = reload_core(prev)
        if ok:
            sh(TPROXY_SH + " apply")
        return self.reply(ok, ("已恢复，" if ok else "") + msg)

    @api_route("/api/logticket", "POST")
    def api_logticket_post(self, m, p, b, q):
        return self.send(200, {"ticket": ticket_new()})
