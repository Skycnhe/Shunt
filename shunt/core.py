"""核心交互"""
import os, threading, time

from .base import CONF_DIR, LOCK, wd_hold
from .errlog import log_err
from .corehttp import core, core_json
from .data import load, read_json, save
from .groups import provider_nodes
from .mihomo import build_config, check_config, write_config
from .sb_common import SB_CONF, active_core
from .sb_config import build_singbox, check_sb_config, sb_hot_reload, sb_log_error, sb_rule_need, sb_sync_assets, write_sb_config
from .sysopt import svc_restart
from .notify import core_alive, set_manual_stop


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
    """写配置 → mihomo -t / sing-box check 校验 → 热重载。

    prev（修改前的 data.json）给出时，任何一步失败都回滚到它：校验失败、生成配置抛异常（如残缺的规则集）、
    mihomo 热重载被拒、sing-box 重载后起不来。坏数据不会留在 data.json 里让 /api/state 一直 500"""
    try:
        return _reload_core(prev)
    except Exception as e:
        log_err("重载核心配置", e, tb=True)
        for p in (os.path.join(CONF_DIR, "config.yaml.new"), SB_CONF + ".new"):
            try:
                os.remove(p)
            except OSError:
                pass
        if prev is None:
            return False, "生成配置失败：" + str(e)[:300]
        _rollback(prev)
        return False, "生成配置失败，已撤销本次修改：" + str(e)[:300]


def _rollback(prev, sb=None):
    """data.json 恢复为 prev，并按它重写当前内核的配置文件；返回 (内核是否 sing-box, 配置路径)"""
    with LOCK:
        save(prev)
        d = load()
        if sb is None:
            sb = active_core(d) == "singbox"
        final = SB_CONF if sb else os.path.join(CONF_DIR, "config.yaml")
        try:
            (write_sb_config if sb else write_config)(d, final)
        except Exception as e:  # 旧数据本身也生成不了：保留磁盘上原来的配置文件
            log_err("回滚后重写配置", e)
    return sb, final


def _reload_core(prev):
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
    set_manual_stop(False)
    retest_soon()
    if sb:
        ok, msg = sb_hot_reload()
        if not ok and prev is not None:  # 配置能通过 sing-box check 但运行时启动失败（如内核缺少模块）：撤销并恢复
            tail = sb_log_error()
            _rollback(prev, sb=True)
            svc_restart(timeout=90)
            return False, "sing-box 启动失败，已撤销本次修改" + ("：" + tail if tail else "")
        return ok, msg
    wd_hold(45, "mihomo 重载配置")
    code, body = core("PUT", "/configs?force=true", {"path": final}, timeout=30)
    if code == 502:  # 核心没在跑，尝试启动
        svc_restart()
        return True, "已写入配置并重启 mihomo"
    text = body.decode(errors="ignore") if isinstance(body, (bytes, bytearray)) else str(body or "")
    if code >= 300:
        if prev is None:
            return False, text or f"mihomo 重载失败（{code}）"
        # 核心拒绝了新配置、还在跑旧配置：data.json 和 config.yaml 也退回去，界面与实际生效的配置保持一致
        _, final = _rollback(prev, sb=False)
        core("PUT", "/configs?force=true", {"path": final}, timeout=30)
        return False, "mihomo 重载失败，已撤销本次修改：" + (text[:300] or str(code))
    return True, text or "配置已重载"


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
    # 唯一的延迟绑定：core.reload_core() 在重载后调用 latency.retest_soon() 触发补测，
    # 而 latency 的定时调度器又需要 core.refresh_regions() —— 真互递归，无法通过移动代码破环。
    # latency 侧已改为顶层导入 core，这里只延迟绑定 retest_soon 这一个名字。
    global retest_soon
    from .latency import retest_soon
