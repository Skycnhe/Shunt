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
    TUN_STACKS, upd_begin, upd_busy_msg, wd_hold
)
from .data import HISTORY_FILE, HISTORY_SKIP, auto_name, config_version, lb_names, load, migrate_names, normalize, read_json, region_lb_set, save, update
from .links import add_links, q1, reserved_names
from .groups import (
    NODE_LIST_MAX, all_node_names, clean_custom_group, gcfg, node_name_ok, provider_nodes, provider_rev, region_plan, rx, sb_sub_outbounds,
    sub_orig_nodes, sub_removed
)
from .ruleutil import complete_rule
from .mihomo import bad_rule_policies, build_config, dns_cfg, safe_dev, validate_dns
from .core import conns_snapshot, refresh_after_sub, refresh_later, refresh_regions, reload_core
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
from .sysopt import SVC_OP, core_procs, delay_test, favicon, kill_core_procs, nft_ok, opt_apply, opt_status, rc_run, sh, speed_test, svc_restart
from .notify import WD, WD_EVENTS_MAX, core_alive, core_proc_alive, set_manual_stop, tg_send, wd_counts
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
from .validate import clean_fields, rename_sub_clashes, rename_sub_refs, sub_name_clash
from .static import MANIFEST, STATIC_TYPES, static_file
ROUTES = {}  # (方法, 路径) → H 的处理函数；api() 先处理前缀 / 条件路由，再查这张表

# GET 也要求 X-Shunt 头的机密接口：返回内容含订阅 URL / 节点密码 / TG token 等机密，局域网零凭证可拖库
SENSITIVE_GET = ("/api/backup", "/api/backup/list", "/api/config", "/api/history")

_SVC_CACHE = {}  # {"v": (t, st, code, version)}：rc-service 状态 + 核心 /version 缓存 10 秒
_SVC_LOCK = threading.Lock()  # 启动 / 停止 / 重启同一时间只允许一个
SVC_JOB = {"busy": False, "act": "", "ok": None, "message": "", "t": 0}  # 最近一次启停操作，GET /api/service 返回给前端轮询
SVC_NAMES = {"start": "启动", "stop": "停止", "restart": "重启"}


def tp_apply():
    """按当前代理方式重载 nftables 规则。核心被手动停止时不挂规则：否则局域网流量会被导向不存在的核心端口
    （init.d 的 start_post 会在下次启动核心时自动加载）。
    看门狗因核心无响应已撤掉规则、让局域网直连（WD.tp_off）时同样不挂：以前这时保存绕过设备 / IPv6 / DNS 防绕过、
    恢复设置或快照都会把规则重新挂上，流量导向卡死的核心，局域网断网直到看门狗下一次重试（最长约 5 分钟）。
    核心恢复后看门狗按当时的设置重新开启规则"""
    if WD["manual_stop"] or WD["tp_off"]:
        return 0, ""
    return sh(TPROXY_SH + " apply")


def _svc_do(act):
    """执行启停并确认结果，返回 (成功?, 提示)"""
    if act == "stop":
        with SVC_OP:  # 看门狗 / 定时任务正在重启核心时，等它做完再停，不并发跑两个 rc-service
            set_manual_stop(True)  # 拿到锁后置位（并落盘）：之后看门狗不会再把它拉起来，面板重启后也记得
            wd_hold(150, "手动停止")
            try:
                code, out = rc_run("stop", timeout=90)
                for _ in range(40):  # rc-service 的返回值不可靠，以 pid 为准，每 0.2 秒查一次，最多等 8 秒
                    if not core_proc_alive():
                        break
                    time.sleep(0.2)
                # pid 文件之外还有核心进程（OpenRC 被 zap 过、旧服务名留下的、SSH 手动运行的）：rc-service 管不到，
                # 以前这里直接报「已停止」，实际核心还占着端口在跑，顶栏一直显示运行中
                stray = kill_core_procs() if not core_proc_alive() else 0
                if not core_proc_alive() and not core_procs():
                    if stray:
                        log_err("api/service stop", Exception(f"结束了 {stray} 个不在 pid 文件里的残留核心进程"))
                    return True, "核心已停止" + (f"（另外结束了 {stray} 个不受服务管理的残留核心进程）" if stray else "")
            finally:
                wd_hold(0, "手动停止", reset=True)
        set_manual_stop(False)  # 没停下来：交还给看门狗，避免核心卡死后再也没人拉起
        log_err("api/service stop", Exception(f"停止后核心进程仍在（rc 返回 {code}）：{out[-200:]}"))
        return False, "核心进程仍在运行，停止失败：" + (out[-200:] or "无输出")
    set_manual_stop(False)
    with SVC_OP:
        if not core_proc_alive() and core_procs():  # 服务没在跑却有核心进程：残留孤儿占着端口，新核心会起不来
            n = kill_core_procs()
            log_err("api/service " + act, Exception(f"启动前结束了 {n} 个不受服务管理的残留核心进程"))
    if act == "restart":
        code, out = svc_restart(timeout=90, why="手动重启")  # 与看门狗、切换内核同一入口：含看门狗暂停和 IP 信息重查
    else:
        with SVC_OP:
            wd_hold(150, "手动启动")
            code, out = rc_run("start", timeout=90)
            wd_hold(60, "手动启动", reset=True)
    if code == 124:
        return False, f"核心{SVC_NAMES[act]}超时，请 SSH 检查 `{SVC} status` 和核心日志"
    # 后台启动的服务 rc 总返回 0，要自己确认：控制接口一应答就算成功（通常 1 秒内）；
    # 进程在但接口还没起来（加载大规则集）最多等 8 秒，期间进程退出立即判失败
    for i in range(40):
        if not core_proc_alive():
            if i >= 3:  # 前 0.6 秒 pid 文件可能还没写好
                break
        elif core_alive():
            retest_soon()
            return True, f"核心已{SVC_NAMES[act]}"
        time.sleep(0.2)
    else:
        if core_proc_alive():
            retest_soon()
            return True, f"核心已{SVC_NAMES[act]}（控制接口仍在加载）"
    return False, "核心没有运行起来，请查看核心日志：" + (out[-200:] or "无输出")


def _svc_job(act):
    try:
        ok, msg = _svc_do(act)
    except Exception as e:
        log_err("api/service " + act, e)
        ok, msg = False, f"{SVC_NAMES[act]}失败：{e}"
    finally:
        _SVC_CACHE.pop("v", None)  # 状态缓存作废，前端马上拿到真实运行状态
    SVC_JOB.update(busy=False, ok=ok, message=msg, t=time.time())
    _SVC_LOCK.release()
_GRP_CACHE = {}  # {"v": ((配置版本, 订阅节点名单版本), groups, gmeta)}：避免每次 /api/state 完整 build_config


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


def mask_secret(v):
    """/api/state 里的 TG token：空值保持空（前端据此显示「未配置」），非空打码"""
    return _mask_val(v) if isinstance(v, str) and v else (v or "")


def mask_url(u):
    """订阅 URL 打码：保留协议和主机（去掉 user:pass@），路径与查询串（通常带 token）打码"""
    if not isinstance(u, str) or not u:
        return u or ""
    try:
        sp = urlparse(u)
    except ValueError:
        return _mask_val(u)
    head = f"{sp.scheme}://{sp.netloc}"
    if not sp.scheme or not sp.netloc or not u.startswith(head):
        return _mask_val(u)
    rest = u[len(head):]
    host = f"{sp.scheme}://{sp.netloc.rpartition('@')[2]}"
    return host + ("/" + _mask_val(rest.lstrip("/")) if rest.strip("/") else rest)


def unmask(new, cur, masker):
    """前端把打码后的占位值原样提交回来 = 没改：换回服务端保存的原值"""
    if isinstance(new, str) and isinstance(cur, str) and cur and new.strip() == masker(cur):
        return cur
    return new


def state_subs(subs):
    return [dict(s, url=mask_url(s.get("url"))) if isinstance(s, dict) else s for s in subs or []]


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


def state_groups(d):
    """/api/state 的策略组名单与元数据。按（配置版本, 订阅节点名单版本）缓存：订阅下载完成、节点增删后地区组会变，
    只按配置版本缓存会让「目标策略」下拉框一直缺新地区组。生成失败时返回空名单（记日志），不让整个面板 500"""
    provider_nodes()  # 先刷新订阅节点名单（60 秒内存缓存），名单变化会推进 provider_rev()
    key = (config_version(), provider_rev())
    gv = _GRP_CACHE.get("v")
    if gv is not None and gv[0] == key:
        return gv[1], gv[2]
    try:
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
    except Exception as e:
        log_err("/api/state：生成策略组", e, tb=True)
        return [], {}
    _GRP_CACHE["v"] = (key, groups, gmeta)
    return groups, gmeta


def state_nodes(d):
    """手动节点的摘要；残缺的条目跳过，不让整个 /api/state 500"""
    out = []
    for n in d.get("nodes") or []:
        try:
            px = n["proxy"]
            out.append({"name": px["name"], "type": px["type"], "server": px["server"], "port": px["port"]})
        except (KeyError, TypeError):
            continue
    return out


def parse_node_items(b):
    """{items: [{sub, name}]} → ([(订阅名, 节点原名)], 错误提示)"""
    items = b.get("items") if isinstance(b, dict) else None
    if not isinstance(items, list) or not items:
        return [], "请选择要删除的节点"
    if len(items) > NODE_LIST_MAX:
        return [], f"一次最多删除 {NODE_LIST_MAX} 个节点"
    out = []
    for x in items:
        if not isinstance(x, dict) or not isinstance(x.get("sub"), str) or not x["sub"] or not node_name_ok(x.get("name")):
            return [], "节点格式不正确（需要订阅名和节点名）"
        k = (x["sub"], x["name"])
        if k not in out:
            out.append(k)
    return out, ""


def sub_nodes_view(d):
    """/api/subs/nodes：[{name, known, nodes: [{name, orig, groups}], removed}]"""
    refs = {}
    for g in d.get("custom_groups") or []:
        for x in (g.get("sub_nodes") or []) if isinstance(g, dict) else []:
            if isinstance(x, dict):
                refs.setdefault((x.get("sub"), x.get("name")), []).append(g.get("name"))
    if active_core(d) == "singbox":
        lists = {k: [(tag, str(p.get("name") or "")) for tag, p in v] for k, v in sb_sub_outbounds(d).items()}
    else:
        pn = provider_nodes()
        lists = {k: [(n, n) for n in v or [] if isinstance(n, str)] for k, v in pn.items()}
    known = sub_orig_nodes(d)
    out = []
    for s in d["subs"]:
        gone = sub_removed(s)
        nodes = [{"name": disp, "orig": o, "groups": refs.get((s["name"], o), [])} for disp, o in lists.get(s["name"], []) if o not in gone]
        out.append({"name": s["name"], "known": s["name"] in known, "nodes": nodes, "removed": gone})
    return {"subs": out, "core": active_core(d)}


RESTORE_KEYS = ("mode", "tproxy", "subs", "rules", "rulesets", "bypass", "tests", "sub_interval", "region_groups",
                "nodes", "ipv6", "watchdog", "tg_token", "tg_chat", "proxy_mode", "tun", "log_limit", "adblock", "dns",
                "devices", "schedule", "groups_cfg", "custom_groups", "sniffer", "gh_proxy")


def renames_note(renames):
    """「；已自动改名：A → A_2、B → B_2」，没有改名时为空"""
    return ("；已自动改名：" + "、".join(f"{a} → {b}" for a, b in renames)) if renames else ""


def probe_data(d):
    """按生成配置与 /api/state 的方式完整走一遍：会抛异常的数据不让写进 data.json。返回错误提示或 None"""
    try:
        cfg = build_config(d)
        group_meta(d, cfg)
        dns_cfg(d)
        for n in d.get("nodes") or []:
            n["proxy"]["name"], n["proxy"]["type"], n["proxy"]["server"], n["proxy"]["port"]
        if active_core(d) == "singbox":
            build_singbox(d)
    except Exception as e:
        log_err("保存前检查配置", e)
        return f"数据格式不正确，未保存：{type(e).__name__}: {e}"[:300]
    return None


class H(BaseHTTPRequestHandler):
    # HTTP/1.1 长连接：每秒的 /api/live 等轮询复用同一条 TCP / TLS 连接，不再每次握手。
    # 约定：每个响应都带准确的 Content-Length（204 / 304 无 body），流式响应发 Connection: close；
    # 请求体在路由前完整读掉，读不了的（超限、chunked）回应后关闭连接，避免残留字节被当成下一个请求
    protocol_version = "HTTP/1.1"
    timeout = 30  # 读请求/TLS 握手的超时：空闲的长连接 30 秒后关闭，卡住不发数据的连接不再永久占用线程（日志流只写不读，不受影响）
    _want_close = False  # 本次响应后关闭连接（end_headers 时补发 Connection: close）
    _started = False  # 本次响应的状态行是否已发出
    _raw = b""  # 本次请求已读入的请求体

    def send_response(self, code, message=None):
        self._started = True
        super().send_response(code, message)

    def end_headers(self):
        if self._want_close and not self.close_connection:
            self.send_header("Connection", "close")  # send_header 会同时置 close_connection
        super().end_headers()

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
        if code < 200 or code in (204, 304):  # 这些状态码不允许带 body：写了会污染长连接上的下一个响应
            self.send_response(code)
            self.send_header("Cache-Control", "no-store")
            self.sec_headers()
            self.end_headers()
            return
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

    def pending_body(self):
        """请求声明的 body 长度；无法按长度读取（chunked 等）返回 -1，Content-Length 非法返回 -2"""
        te = (self.headers.get("Transfer-Encoding") or "").strip().lower()
        if te and te != "identity":
            return -1
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return -2
        return n if n >= 0 else -2

    def read_body(self):
        """把请求体完整读掉（长连接上不能留下未读字节）。返回错误响应已发出时为 False"""
        self._raw = b""
        n = self.pending_body()
        if n == 0:
            return True
        self._want_close = True  # 下面任何一条错误路径都不再复用这条连接
        if n == -1:
            self.send(411, {"message": "不支持分块传输的请求体，请带上 Content-Length"})
            return False
        if n == -2:
            self.send(400, {"message": "Content-Length 无效"})
            return False
        if n > MAX_BODY:  # 防止超大 body 耗尽路由器内存
            self.send(413, {"message": "请求体过大"})
            return False
        raw = self.rfile.read(n)
        if len(raw) < n:  # 客户端中途断开
            self.close_connection = True
            return False
        self._raw = raw
        self._want_close = False
        return True

    def body(self):
        if not self._raw:
            return {}
        try:
            return json.loads(self._raw)
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
            # 机密类 GET：/api/backup、/api/backup/list、/api/config（含 ?download）、/api/history 返回订阅/节点密码等机密，同样要求请求头
            if "X-Shunt" not in self.headers and "X-Token" not in self.headers:
                return "缺少 X-Shunt 请求头，机密接口拒绝访问（脚本调用请加上 -H 'X-Shunt: 1'）"
        return ""

    def route(self, m):
        self._want_close, self._started, self._raw = False, False, b""
        u = urlparse(self.path)
        p = u.path
        why = self.guard(m, p)
        if why:
            if self.pending_body():  # 被拒绝的请求不读它的 body，回应后直接关闭连接
                self._want_close = True
            return self.deny(why)
        if not self.read_body():
            return
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
            if self._started:  # 响应头已发出一半：无法再回 500，关闭连接让客户端知道响应不完整
                self.close_connection = True
                return
            return self.send(500, {"message": "内部错误"})

    def logstream(self, level):
        if level not in ("debug", "info", "warning", "error"):
            level = "info"
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self._want_close = True  # 事件流没有长度，结束即关闭连接
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
        code, out = tp_apply()
        label = {"tproxy": "TProxy", "tun": "TUN", "off": "关闭"}[mode]
        note = ""
        if mode == "tun" and not WD["manual_stop"]:  # 核心手动停止时不检查（TUN 网卡要等核心启动才创建）；mihomo -t 只做语法校验；TUN 网卡创建失败时核心照常运行，需要单独确认
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
                with LOCK:  # 与 update() 一样在锁内写：data.json.tmp 是共用的临时文件名，并发写会互相截断 / 改名失败
                    save(prev)
                reload_core()
                tp_apply()
                return self.send(500, {"message": "TUN 启动失败，已恢复原来的代理方式：" + err +
                                       "。可尝试：关闭 auto-redirect、换用 gvisor 协议栈、确认以 root 运行并已加载 tun 模块（modprobe tun）"})
        if WD["manual_stop"]:
            note += "（核心已手动停止，启动后生效）"
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
            tp_apply()  # 重新加载 nftables：是否劫持发往任意服务器的 53 端口
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
        b = self.body() if m in ("POST", "PUT", "PATCH", "DELETE") else {}  # 请求体已在 route() 里完整读入
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
            # 与 mihomo 一致只认 POST /configs/geo：以前任何方法都执行，GET 不要求 X-Shunt 头，
            # 局域网里打开的恶意网页用一个 <img src=…/api/core/configs/geo> 就能让面板强制重下全部规则集并重载核心
            if (sub.startswith("/providers/rules/") and m == "PUT") or (sub == "/configs/geo" and m == "POST"):
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
            if sub == "/configs/geo":
                return self.send(405, {"message": "请用 POST"})
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
                if not upd_begin("core"):
                    return self.send(409, {"message": upd_busy_msg()})
                try:
                    tmp = SB_BIN + ".swap"
                    shutil.copy2(SB_BIN, tmp)
                    os.replace(SB_BIN + ".bak", SB_BIN)
                    os.replace(tmp, SB_BIN + ".bak")
                    if active_core() == "singbox":
                        svc_restart(timeout=90)
                finally:
                    CORE_UPD["busy"] = False
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
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; sandbox")  # 远端内容：即使被当作文档打开也不能执行脚本
            self.sec_headers()
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
        groups, gmeta = state_groups(d)
        out = {"running": "started" in st or code == 200, "version": version, "groups": groups, "group_meta": gmeta,
               "nodes": state_nodes(d), "default_exclude": DEFAULT_EXCLUDE, "sched_events": list(SCHED["events"])[:20],
               "panel_version": PANEL_VERSION, "core": active_core(d),
               "wd": {"status": WD["status"], "last_check": WD["last_check"], "events": list(WD["events"]),
                      "counts": wd_counts(), "max": WD_EVENTS_MAX}}
        for k in ("mode", "subs", "rules", "rulesets", "bypass", "tests", "sub_interval", "ipv6", "https", "watchdog", "tg_token",
                  "tg_chat", "proxy_mode", "tun", "log_limit", "schedule", "devices", "sniffer", "gh_proxy"):
            out[k] = d.get(k)
        # 与 /api/config 一致：订阅 URL（常带 token）和 TG token 打码；前端原样提交回来时由 unmask() 换回原值
        out["subs"] = state_subs(d.get("subs"))
        out["tg_token"] = mask_secret(d.get("tg_token"))
        try:
            out["dns"] = dns_cfg(d)
        except Exception as e:
            log_err("/api/state：DNS 设置", e)
            out["dns"] = copy.deepcopy(DNS_DEFAULT)
        out["adblock_on"] = bool((d.get("adblock") or {}).get("enabled")) if isinstance(d.get("adblock"), dict) else False
        return self.send(200, out)

    @api_route("/api/ping", "GET")
    def api_ping_get(self, m, p, b, q):
        """轻量心跳：前端 15 秒轮询，version 变化时才拉全量 /api/state。
        version = 配置版本（data.json 每次 save 自增）+ 订阅节点名单版本（新订阅下载完、节点增删时地区组会变）"""
        return self.send(200, {"ok": True, "core": active_core(), "version": f"{config_version()}.{provider_rev()}",
                               "ad_today": ad_today()})

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
            code, raw = core("PUT", "/providers/proxies/" + quote(nm, safe=""), timeout=120)
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
        cur = next((s for s in load()["subs"] if isinstance(s, dict) and s.get("name") == name), None)
        if cur:  # 编辑订阅时表单里是打码后的 URL：没改就沿用原链接
            url = unmask(url, cur.get("url"), mask_url)
        if not name or not url.startswith("http"):
            return self.send(400, {"message": "名称或订阅链接无效"})
        other = sub_name_clash(name, [s.get("name") for s in load()["subs"] if isinstance(s, dict) and s.get("name")])
        if other:  # 「机场 A」和「机场_A」会共用 ./providers/<名>.yaml 和 sing-box 节点缓存，互相覆盖
            return self.send(400, {"message": f"与已有订阅「{other}」只差符号，会共用同一个缓存文件，请改个名字"})
        flt, exc = (b.get("filter") or "").strip(), (b["exclude"] if "exclude" in b else DEFAULT_EXCLUDE).strip()
        for pat in (flt, exc):
            try:
                re.compile(pat)
            except re.error as e:
                return self.send(400, {"message": f"正则表达式无效：{pat}（{e}）"})
        def save_sub(d):
            old = next((s for s in d["subs"] if s["name"] == name), None)
            new = {"name": name, "url": url, "filter": flt, "exclude": exc}
            if old and sub_removed(old):  # 编辑订阅时保留「从订阅删除」的节点名单
                new["removed"] = sub_removed(old)
            d["subs"] = [s for s in d["subs"] if s["name"] != name] + [new]
        prev = update(save_sub)
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

    @api_route("/api/subs/nodes", "GET")
    def api_subs_nodes_get(self, m, p, b, q):
        """订阅节点清单（节点页「从订阅删除」、策略组编辑器勾选订阅节点用）：
        每个节点给出显示名（sing-box 为去重改名后的名字）与原名（存进 data.json 的就是原名），以及引用它的自定义组"""
        return self.send(200, sub_nodes_view(load()))

    @api_route("/api/subs/nodes/remove", "POST")
    def api_subs_nodes_remove(self, m, p, b, q):
        items, err = parse_node_items(b)
        if err:
            return self.send(400, {"message": err})
        subs = {s["name"]: s for s in load()["subs"]}
        miss = sorted({x[0] for x in items if x[0] not in subs})
        if miss:
            return self.send(404, {"message": "订阅不存在：" + "、".join(miss[:3])})
        for sname in {x[0] for x in items}:
            if len(set(sub_removed(subs[sname])) | {n for s2, n in items if s2 == sname}) > NODE_LIST_MAX:
                return self.send(400, {"message": f"订阅「{sname}」删除的节点过多（最多 {NODE_LIST_MAX} 个）"})
        # 不能把一个订阅的节点全部删掉：mihomo 的 provider 过滤后一个节点都没有会解析失败（file doesn't have any proxy），
        # 订阅加载出错、之后每次更新也都失败，订阅新增的节点永远进不来，还会按退避间隔反复重新下载。不要这个订阅应直接删除订阅
        left = sub_orig_nodes(load())
        for sname in {x[0] for x in items}:
            if left.get(sname) and left[sname] <= {n for s2, n in items if s2 == sname}:
                return self.send(400, {"message": f"不能删除订阅「{sname}」的全部节点（至少保留一个）；不需要这个订阅可以在「订阅」页直接删除"})
        info = {"n": 0}

        def fn(d):
            for s in d["subs"]:
                add = [n for s2, n in items if s2 == s["name"]]
                if not add:
                    continue
                cur = sub_removed(s)
                new = [n for n in add if n not in cur]
                info["n"] += len(new)
                s["removed"] = cur + new
        return self.sub_nodes_apply(fn, info, lambda n: f"已从订阅删除 {n} 个节点")

    @api_route("/api/subs/nodes/restore", "POST")
    def api_subs_nodes_restore(self, m, p, b, q):
        sname = b.get("sub")
        if not isinstance(sname, str) or not sname:
            return self.send(400, {"message": "缺少订阅名"})
        if not any(s["name"] == sname for s in load()["subs"]):
            return self.send(404, {"message": f"订阅不存在：{sname}"})
        allx = bool(b.get("all"))
        names = b.get("names")
        if not allx:
            if not isinstance(names, list) or not names or len(names) > NODE_LIST_MAX or not all(node_name_ok(x) for x in names):
                return self.send(400, {"message": "请选择要恢复的节点"})
            names = set(names)
        info = {"n": 0}

        def fn(d):
            for s in d["subs"]:
                if s["name"] != sname:
                    continue
                cur = sub_removed(s)
                keep = [] if allx else [n for n in cur if n not in names]
                info["n"] = len(cur) - len(keep)
                if keep:
                    s["removed"] = keep
                else:
                    s.pop("removed", None)
        return self.sub_nodes_apply(fn, info, lambda n: f"已恢复 {n} 个节点")

    def sub_nodes_apply(self, fn, info, done):
        """删除 / 恢复订阅节点：锁内改 data.json → 与其他订阅修改一样重载核心（失败回滚；手动停止时只写配置）"""
        prev = update(fn)
        if not info["n"]:
            return self.send(200, {"message": done(0)})
        ok, msg = reload_core(prev)
        if ok and active_core() != "singbox":
            # mihomo 的订阅节点名单要等核心按新 exclude-filter 重新加载 provider 后才变：稍后按新名单再核对一次策略组
            # （刚恢复的节点被策略组勾选过时补进去）；核心没在运行时 refresh_regions 不会把它拉起来
            refresh_later(8)
        return self.reply(ok, done(info["n"]) + ("；" + msg if "手动停止" in msg else "") if ok else msg)

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
        rules = [complete_rule(r.strip(), G_SEL) for r in b.get("rules", []) if isinstance(r, str) and r.strip()]
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

    @api_route("/api/conns/stats", "GET")
    def api_conns_stats_get(self, m, p, b, q):
        """概览只要两个数字：连接数和来源设备数，不必把整份连接列表（几十到几百 KB）传给前端"""
        c = conns_snapshot(timeout=5)
        if c is None:
            return self.send(502, {"message": "mihomo 未运行或无法连接"})
        conns = c.get("connections") or []
        devs = {(x.get("metadata") or {}).get("sourceIP") for x in conns}
        devs.discard(None)
        devs.discard("")
        return self.send(200, {"count": len(conns), "devices": len(devs)})

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
        try:
            return self.send(200, ab_check(b.get("domain") or ""))
        except ValueError as e:  # 无效域名：给出原因，不再 500「内部错误」
            return self.send(400, {"message": str(e)})

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
            tp_apply()
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
        c = conns_snapshot(timeout=5) or {}  # 与连接页 / 统计共用 2 秒快照，不再单独全量抓取
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

    @api_route("/api/service", "GET")
    def api_service_get(self, m, p, b, q):
        return self.send(200, dict(SVC_JOB, alive=core_proc_alive()))

    @api_route("/api/service", "POST")
    def api_service_post(self, m, p, b, q):
        act = b.get("action")
        if act == "reload":
            return self.reply(*reload_core())
        if act in ("restart", "stop", "start"):
            if not _SVC_LOCK.acquire(blocking=False):  # 防连点 / 多标签页同时操作：两个 rc-service 并发会互相打断
                return self.send(409, {**SVC_JOB, "message": f"正在{SVC_NAMES.get(SVC_JOB['act'], '')}核心，请稍候"})
            SVC_JOB.update(busy=True, act=act, ok=None, message="", t=time.time())
            threading.Thread(target=_svc_job, args=(act,), daemon=True).start()  # 后台执行：请求立即返回，前端轮询结果
            return self.send(202, {**SVC_JOB, "message": f"正在{SVC_NAMES[act]}核心…"})
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
        if "tg_token" in b:  # 打码的 token 原样提交回来 = 没改
            b["tg_token"] = unmask(b["tg_token"], load().get("tg_token"), mask_secret)
        if "sniffer" in b:
            b["sniffer"] = bool(b["sniffer"])
        if "log_limit" in b and b["log_limit"] not in (1, 2, 5, 10, 20):
            return self.send(400, {"message": "日志上限只能是 1 / 2 / 5 / 10 / 20 MB"})
        try:  # 形状校验：残缺的规则集 / 绕过设备 / 延迟站点直接 400，不写进 data.json
            new = clean_fields(b, allowed)
        except ValueError as e:
            return self.send(400, {"message": str(e)})
        test = load()
        test.update(new)
        err = probe_data(test)
        if err:
            return self.send(400, {"message": err})
        prev = update(lambda d: d.update(new))
        d = load()
        msg = "已保存"
        if set(b) & {"rulesets", "sub_interval", "region_groups", "ipv6", "sniffer"} or ("bypass" in b and d["proxy_mode"] == "tun"):
            ok, msg = reload_core(prev)
            if not ok:
                return self.send(500, {"message": msg})
        if set(b) & {"bypass", "ipv6"} and d["proxy_mode"] != "off":
            tp_apply()
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
            d.update(tg_token=unmask(b.get("tg_token", ""), d.get("tg_token"), mask_secret), tg_chat=b.get("tg_chat", ""))
        return self.reply(*tg_send("✅ 测试消息：通知已配置成功", d))

    @api_route("/api/backup", "GET")
    def api_backup_get(self, m, p, b, q):
        d = load()
        return self.send(200, {k: v for k, v in d.items() if k != "secret"})

    @api_route("/api/backup/list", "GET")
    def api_backup_list(self, m, p, b, q):
        from . import backup as backup_mod
        return self.send(200, {"backups": backup_mod.list()})

    @api_route("/api/backup/create", "POST")
    def api_backup_create(self, m, p, b, q):
        from . import backup as backup_mod
        ok, name = backup_mod.create()
        return self.send(200 if ok else 500, {"ok": ok, "name": name if ok else "",
                                              "message": name if ok else "备份失败：%s" % name})

    @api_route("/api/backup/restore", "POST")
    def api_backup_restore(self, m, p, b, q):
        from . import backup as backup_mod
        st = {}

        def check(raw):
            """与「恢复设置」相同的校验：CLEANERS 形状校验 → 订阅名冲突自动改名 → 补默认值 / 迁移 → 试生成配置。
            当前的 core / secret 保留（切换内核与控制密钥不随备份回退）"""
            if not isinstance(raw, dict):
                raise ValueError("data.json 不是 JSON 对象")
            vals = clean_fields(raw, RESTORE_KEYS)
            d = copy.deepcopy(raw)
            d.update(vals)
            if "subs" in vals:
                d["subs"], st["renames"] = rename_sub_clashes(vals["subs"])
                d["custom_groups"] = rename_sub_refs(d.get("custom_groups"), st["renames"])
            try:
                normalize(d)
            except Exception as e:
                raise ValueError(f"{type(e).__name__}: {e}"[:300])
            cur = load()
            for k in ("core", "secret"):
                d[k] = cur[k]
            err = probe_data(d)
            if err:
                raise ValueError(err)
            return d

        def apply(new):
            def fn(d):
                keep = {k: d[k] for k in ("core", "secret") if k in d}
                d.clear()
                d.update(copy.deepcopy(new))
                d.update(keep)
            st["prev"] = update(fn)

        ok, msg = backup_mod.restore((b.get("name") or "").strip(), check_data=check, apply_data=apply)
        if ok and "prev" in st:
            ab_compose(load())
            rok, rmsg = reload_core(st["prev"])
            if rok:
                tp_apply()
            msg += ("核心已重载：" if rok else "设置已撤销：") + rmsg
            ok = rok
        return self.reply(ok, msg + renames_note(st.get("renames")))

    @api_route("/api/backup/delete", "POST")
    def api_backup_delete(self, m, p, b, q):
        from . import backup as backup_mod
        ok, msg = backup_mod.delete((b.get("name") or "").strip())
        return self.reply(ok, msg)

    @api_route("/api/health/status", "GET")
    def api_health_status(self, m, p, b, q):
        from . import health as health_mod
        return self.send(200, {"running": health_mod.HEALTH_STATE["running"],
                               "last_run": health_mod.HEALTH_STATE["last_run"],
                               "total": health_mod.HEALTH_STATE["total"],
                               "checked": health_mod.HEALTH_STATE["checked"],
                               "cfg": health_mod.health_cfg(),
                               "records": health_mod.get_records()})

    @api_route("/api/health/check", "POST")
    def api_health_check(self, m, p, b, q):
        from . import health as health_mod
        ok = health_mod.run_check_bg()
        return self.send(200, {"ok": ok, "message": "已开始检查" if ok else "检查正在进行中"})

    @api_route("/api/health/unhide", "POST")
    def api_health_unhide(self, m, p, b, q):
        from . import health as health_mod
        name = (b.get("node_id") or "").strip()
        ok = health_mod.unhide(name) if name else False
        return self.reply(ok, "已取消隐藏" if ok else "节点不存在")

    @api_route("/api/health/cfg", "PUT")
    def api_health_cfg(self, m, p, b, q):
        from . import health as health_mod
        cfg = health_mod.health_cfg()
        if "enabled" in b:
            cfg["enabled"] = bool(b["enabled"])
        if "time" in b:
            t = str(b["time"]).strip()
            if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", t):
                return self.send(400, {"ok": False, "message": "时间格式应为 HH:MM"})
            cfg["time"] = t
        for k in ("warn_days", "hide_days"):
            if k in b:
                try:
                    v = int(b[k])
                    if v < 1 or v > 30:
                        raise ValueError
                    cfg[k] = v
                except (ValueError, TypeError):
                    return self.send(400, {"ok": False, "message": f"{k} 应为 1-30 的整数"})
        if cfg["warn_days"] >= cfg["hide_days"]:
            return self.send(400, {"ok": False, "message": "标红天数应小于隐藏天数"})
        health_mod.save_health_cfg(cfg)
        return self.send(200, {"ok": True, "cfg": cfg})

    @api_route("/api/restore", "POST")
    def api_restore_post(self, m, p, b, q):
        try:  # 恢复残缺 / 旧格式的备份：任何一项形状不对都整体拒绝，不写进 data.json
            vals = clean_fields(b, RESTORE_KEYS)
        except ValueError as e:
            return self.send(400, {"message": "备份内容无效：" + str(e)})
        if not vals:
            return self.send(400, {"message": "备份内容无效：没有可恢复的设置"})
        renames = []
        if "subs" in vals:  # 订阅名只差符号会共用同一个节点缓存文件：自动改名
            vals["subs"], renames = rename_sub_clashes(vals["subs"])
            if "custom_groups" in vals:  # 自定义组勾选的订阅节点跟着改指新订阅名
                vals["custom_groups"] = rename_sub_refs(vals["custom_groups"], renames)

        def apply_backup(d):
            d.update(copy.deepcopy(vals))
            if renames and "custom_groups" not in vals:  # 备份里没有自定义组：沿用的现有组里勾选的订阅节点也跟着改指新订阅名
                d["custom_groups"] = rename_sub_refs(d.get("custom_groups"), renames)
            if "proxy_mode" not in vals and "tproxy" in vals:
                d["proxy_mode"] = "tproxy" if vals["tproxy"] else "off"
            if d.get("proxy_mode") not in PROXY_MODES:
                d["proxy_mode"] = "tproxy" if d.get("tproxy", True) else "off"
            migrate_names(d)  # 旧版备份里的地区组名自动换成新名称
        test = load()
        apply_backup(test)
        err = probe_data(test)
        if err:
            return self.send(400, {"message": "备份内容无效：" + err})
        prev = update(apply_backup)
        ab_compose(load())
        ok, msg = reload_core(prev)
        if ok:
            tp_apply()
        return self.reply(ok, ("已恢复，" if ok else "") + msg + renames_note(renames))

    @api_route("/api/logticket", "POST")
    def api_logticket_post(self, m, p, b, q):
        return self.send(200, {"ticket": ticket_new()})
