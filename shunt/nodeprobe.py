"""逐个节点测速（/proxies/{节点}/delay），给整组测速结果不可靠的场合补测。

sing-box（实测 1.14.3）的 /group/{组}/delay 同时只测 10 个节点、整组共用一个 timeout，应答里只列测通的节点：
排在前面的失效节点占满并发等到超时，后面的可用节点根本没轮到测，也不会出现在结果里（全部没测到时照样 200 {}）。
所以 sing-box 下「组结果里缺席」不等于「测速失败」，要逐个节点再测一次才能下结论。mihomo 的整组测速会测完全部节点，
缺席就是失败（全部失败回 504），不需要补测。

notify.check_nodes（全部超时告警前复核）、health.run_check（节点健康检查）、schedule 的定时测速共用这里的逻辑。
"""
import json
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from urllib.parse import quote

from .base import HC, mass_begin, mass_end
from .corehttp import core

PROBE_WORKERS = 32   # 逐个节点测速的并发数
PROBE_BUDGET = 90    # 默认最多用多少秒（期间按「全节点测速中」登记，看门狗暂停判定）；必须小于 base.MASS_MAX_AGE


def node_delay(name):
    """单节点测速：延迟毫秒（>0 可用）/ 0 超时或失败（两个内核都是 504 超时、503 测速出错）/
    None 没有结论（核心没应答 502、节点已不在 404、应答解析不了等）"""
    code, raw = core("GET", f"/proxies/{quote(name, safe='')}/delay?url={quote(HC)}&timeout=5000", timeout=20)
    if code in (503, 504):
        return 0
    if code != 200:
        return None
    try:
        v = json.loads(raw).get("delay")
    except Exception:
        return None
    return v if isinstance(v, int) and not isinstance(v, bool) and v > 0 else 0


def node_alive(name):
    """True 可用 / False 超时或失败 / None 没有结论"""
    v = node_delay(name)
    return None if v is None else v > 0


def probe_nodes(names, budget=PROBE_BUDGET, stop=None, progress=None):
    """并发逐个测速，返回 {节点: 延迟 | 0 | None}；预算内没测完的节点记 None（没有结论）。
    stop(节点, 结果) 返回真时提前结束（其余节点记 None）；progress(已完成数) 每测完一个调用一次"""
    names = list(dict.fromkeys(n for n in names if isinstance(n, str) and n))
    out = dict.fromkeys(names)
    if not names:
        return out
    tok = mass_begin()  # 测速期间核心负载高，看门狗暂停判定
    ex = ThreadPoolExecutor(min(PROBE_WORKERS, len(names)))
    try:
        futs = {ex.submit(node_delay, n): n for n in names}
        done = 0
        try:
            for f in as_completed(futs, timeout=budget):
                n = futs[f]
                try:
                    out[n] = f.result()
                except Exception:
                    out[n] = None
                done += 1
                if progress:
                    progress(done)
                if stop and stop(n, out[n]):
                    break
        except FuturesTimeout:
            pass  # 节点太多，预算内没测完：剩下的保持 None
        return out
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
        mass_end(tok)


def confirm_all_down(members, budget=PROBE_BUDGET):
    """「全部超时」告警前逐个节点复核：True 全部失败 / False 有节点可用 / None 没有结论（核心重载中、预算内没测完）"""
    names = [m for m in members if isinstance(m, str) and m]
    if not names:
        return True
    res = probe_nodes(names, budget, stop=lambda n, v: bool(v))
    vals = list(res.values())
    if any(vals):
        return False
    return True if all(v == 0 for v in vals) else None


def fill_absent(results, budget=PROBE_BUDGET, progress=None):
    """sing-box 整组测速的结果 {节点: 延迟(0=缺席/失败)} → 缺席的逐个补测。
    返回新的 {节点: 延迟}：测通的写延迟、确认失败的写 0，没有结论的节点不出现（本轮不记失败也不记成功）"""
    miss = [n for n, v in results.items() if not v]
    out = dict(results)
    if not miss:
        return out
    for n, v in probe_nodes(miss, budget, progress=progress).items():
        if v is None:
            out.pop(n, None)
        else:
            out[n] = v
    return out
