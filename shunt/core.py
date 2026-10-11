"""核心交互"""
import json, os, threading, time, urllib.request, urllib.error

from .base import CONF_DIR, CTRL, DATA_FILE, LOCK, SVC
from .data import load, read_json, save
from .groups import provider_nodes
from .mihomo import build_config, check_config, write_config
DIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # 访问本机控制器绝不走系统代理


_SECRET = [None, ""]


def ctrl_secret():
    """控制器密钥按 data.json 修改时间缓存：每秒的实时请求不再反复读取解析整份配置"""
    try:
        st = os.stat(DATA_FILE)
        key = (st.st_mtime_ns, st.st_size)
    except OSError:
        key = None
    if key is None or _SECRET[0] != key:
        _SECRET[:] = [key, load()["secret"]]
    return _SECRET[1]


def core(method, path, body=None, timeout=10):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(CTRL + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + ctrl_secret(), "Content-Type": "application/json"})
    try:
        with DIRECT_OPENER.open(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 502, json.dumps({"message": "mihomo 未运行或无法连接: %s" % e}).encode()


def core_json(path, timeout=10):
    code, raw = core("GET", path, timeout=timeout)
    if code != 200:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


_CONN_SNAP = {}
_CONN_LOCK = threading.Lock()


def conns_snapshot(timeout=5, ttl=2):
    """1~2 秒 TTL 的 /connections 进程内共享快照。

    stats（5 秒）、连接页（1 秒）、live（2 秒）三处原来各自全量抓取解析
    （300 连接时 100~300KB JSON），现在复用同一份快照。返回的 dict 三处只读不改。
    抓取失败返回 None（与原来语义一致），不缓存失败结果。"""
    now = time.time()
    v = _CONN_SNAP.get("v")
    if v is not None and now - v[0] < ttl:
        return v[1]
    c = core_json("/connections", timeout=timeout)
    if c is None:
        return None
    with _CONN_LOCK:
        _CONN_SNAP["v"] = (time.time(), c)
    return c


def reload_core(prev=None):
    """写配置 → mihomo -t 校验 → 热重载；校验失败时回滚 data.json"""
    with LOCK:
        d = load()
        sb = active_core(d) == "singbox"
        if sb:
            final = SB_CONF
            try:  # 广告 / 白名单列表改动后，先把对应的 sing-box 规则集文件转换好，否则这些规则会被跳过
                need = {k: v for k, v in sb_rule_need(d).items() if v.get("kind") == "adblock"}
                if need:
                    sb_sync_assets(d, need=need)
            except Exception as e:
                print("sb adblock sync", e, flush=True)
            tmp = write_sb_config(d, final + ".new")
            ok, err = check_sb_config(tmp)
        else:
            final = os.path.join(CONF_DIR, "config.yaml")
            tmp = write_config(d, final + ".new")
            ok, err = check_config(tmp)
        if not ok:
            os.remove(tmp)
            if prev is not None:
                save(prev)
            return False, "配置校验失败，已撤销本次修改：" + err
        os.replace(tmp, final)
    WD["manual_stop"] = False
    retest_soon()
    if sb:
        ok, msg = sb_hot_reload()
        if not ok and prev is not None:  # 配置能通过 sing-box check 但运行时启动失败（如内核缺少模块）：撤销并恢复
            tail = sb_log_error()
            with LOCK:
                save(prev)
                write_sb_config(load(), SB_CONF)
            sh(SVC + " restart", timeout=90)
            return False, "sing-box 启动失败，已撤销本次修改" + ("：" + tail if tail else "")
        return ok, msg
    code, body = core("PUT", "/configs?force=true", {"path": final}, timeout=30)
    if code == 502:  # 核心没在跑，尝试启动
        sh(SVC + " restart")
        return True, "已写入配置并重启 mihomo"
    return code < 300, body.decode(errors="ignore") or "配置已重载"


def group_sig(cfg):
    return [(g["name"], g["type"], g.get("filter", ""), tuple(g.get("proxies") or [])) for g in cfg.get("proxy-groups") or []]


def refresh_regions():
    """订阅节点变化后，地区分组（存在哪些地区、是否生成均衡组）可能变化：与当前配置不同就重新生成并重载"""
    if not core_alive():  # 核心没在运行（可能是手动停止）时不重载，免得把它拉起来
        return False, "核心未运行"
    provider_nodes(fresh=True)
    if active_core() == "singbox":
        cur = read_json(SB_CONF, None)
        new = build_singbox(load())[0]
        sig = lambda c: [(o["tag"], tuple(o.get("outbounds") or [])) for o in (c or {}).get("outbounds") or [] if o.get("outbounds")]
        if cur and sig(cur) == sig(new):
            return True, "地区分组无变化"
        ok, msg = reload_core()
        return ok, "地区分组已按最新订阅节点更新" if ok else msg
    cur = read_json(os.path.join(CONF_DIR, "config.yaml"), None)
    if not cur:
        return False, "当前配置不存在"
    if group_sig(cur) == group_sig(build_config(load())):
        return True, "地区分组无变化"
    ok, msg = reload_core()
    print(time.strftime("%F %T"), "[groups] 订阅节点变化，已重新生成地区分组：", ok, msg[:120], flush=True)
    return ok, "地区分组已按最新订阅节点更新" if ok else msg


def refresh_after_sub(name, wait=90):
    """新订阅加入后等核心下载完节点，再更新地区分组"""
    def run():
        end = time.time() + wait
        while time.time() < end:
            time.sleep(10)
            if name in provider_nodes(fresh=True):
                break
        try:
            refresh_regions()
        except Exception as e:
            print("refresh regions error", e, flush=True)
    threading.Thread(target=run, daemon=True).start()


def _link():
    """全部模块加载后由 shunt.load() 调用：绑定后面模块里定义的名字（模块之间互相调用，放在这里避免循环导入）"""
    global SB_CONF, active_core, build_singbox, check_sb_config, sb_hot_reload, sb_log_error, sb_sync_assets, write_sb_config
    global sh, WD, core_alive, retest_soon
    from .sb_common import SB_CONF, active_core
    from .sb_config import build_singbox, check_sb_config, sb_hot_reload, sb_log_error, sb_rule_need, sb_sync_assets, write_sb_config
    from .sysopt import sh
    from .notify import WD, core_alive
    from .latency import retest_soon
