"""逐个节点测速（/proxies/{节点}/delay），给整组测速结果不可靠的场合补测。

sing-box（实测 1.14.3）的 /group/{组}/delay 同时只测 10 个节点、整组共用一个 timeout，应答里只列测通的节点：
排在前面的失效节点占满并发等到超时，后面的可用节点根本没轮到测，也不会出现在结果里（全部没测到时照样 200 {}）。
所以 sing-box 下「组结果里缺席」不等于「测速失败」，要逐个节点再测一次才能下结论。mihomo 的整组测速会测完全部节点，
缺席就是失败（全部失败回 504），不需要补测。

notify.check_nodes（全部超时告警前复核）、health.run_check（节点健康检查）、schedule 的定时测速、retest_soon（重载后补测）、
前端经 /api/core/group/…/delay 发起的整组测速（「全部测速」、组测速、概览测速）、订阅 healthcheck 共用这里的逻辑。

并发控制：所有调用方共用一个信号量（同时最多 PROBE_WORKERS 个单节点测速），同一节点同时只测一次（后到的等先到的结果）。
以前每个调用方各开 32 个线程：前端「全部测速」同时测 GLOBAL 与手动选择两个组、再赶上重载后补测，路由器上会叠到上百个并发测速。
"""
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from urllib.parse import quote

from .base import BUILTIN_POLICIES, HC, mass_begin, mass_end
from .corehttp import core, core_json

PROBE_WORKERS = 16   # 逐个节点测速的全局并发上限（所有调用方合计）
PROBE_BUDGET = 90    # 默认最多用多少秒（期间按「全节点测速中」登记，看门狗暂停判定）；必须小于 base.MASS_MAX_AGE
UI_BUDGET = 60       # 前端发起的整组测速 / 订阅 healthcheck 的补测上限（加上整组测速本身最多约 2 分钟）
_SEM = threading.BoundedSemaphore(PROBE_WORKERS)
_INFLIGHT = {}       # {节点: [Event, 结果]}：正在测的节点，后到的调用方等同一个结果
_INFLIGHT_LOCK = threading.Lock()
NON_NODE_TYPES = {"Direct", "Reject", "RejectDrop", "Pass", "Compatible", "Dns", "Block"}


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


def _probe_shared(name, deadline):
    """受全局信号量限制的单节点测速；同一节点正在被别的调用方测时直接等它的结果。到 deadline 还没轮到 / 没测完返回 None"""
    with _INFLIGHT_LOCK:
        slot = _INFLIGHT.get(name)
        owner = slot is None
        if owner:
            slot = _INFLIGHT[name] = [threading.Event(), None]
    if not owner:
        slot[0].wait(max(0.0, deadline - time.monotonic()))
        return slot[1]
    try:
        left = deadline - time.monotonic()
        if left <= 0 or not _SEM.acquire(timeout=left):
            return None
        try:
            slot[1] = node_delay(name)
        finally:
            _SEM.release()
        return slot[1]
    finally:
        with _INFLIGHT_LOCK:
            _INFLIGHT.pop(name, None)
        slot[0].set()


def probe_nodes(names, budget=PROBE_BUDGET, stop=None, progress=None):
    """并发逐个测速，返回 {节点: 延迟 | 0 | None}；预算内没测完的节点记 None（没有结论）。
    stop(节点, 结果) 返回真时提前结束（其余节点记 None）；progress(已完成数) 每测完一个调用一次"""
    names = list(dict.fromkeys(n for n in names if isinstance(n, str) and n))
    out = dict.fromkeys(names)
    if not names:
        return out
    tok = mass_begin()  # 测速期间核心负载高，看门狗暂停判定
    ex = ThreadPoolExecutor(min(PROBE_WORKERS, len(names)))
    deadline = time.monotonic() + budget
    try:
        futs = {ex.submit(_probe_shared, n, deadline): n for n in names}
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


def group_nodes(group):
    """组的直接成员里的节点（不含策略组、DIRECT / REJECT 等内置出站）；核心没应答或组不存在返回 None"""
    px = (core_json("/proxies", timeout=8) or {}).get("proxies")
    if not isinstance(px, dict) or not isinstance(px.get(group), dict):
        return None
    out = []
    for m in px[group].get("all") or []:
        p = px.get(m)
        if not isinstance(m, str) or m in BUILTIN_POLICIES or not isinstance(p, dict):
            continue
        if p.get("all") is not None or p.get("type") in NON_NODE_TYPES:
            continue
        out.append(m)
    return out


def fill_group(group, code, raw, budget=UI_BUDGET):
    """sing-box 整组测速（/group/{组}/delay）的应答 → 缺席的节点逐个补测后，按同样格式（只列测通的）返回 (状态码, 应答)。
    整组测速本身失败（非 200）、组成员取不到时原样返回；补测后仍全部不通时与原来一样回 200 {}"""
    if code != 200:
        return code, raw
    try:
        data = json.loads(raw or b"{}")
    except Exception:
        return code, raw
    if not isinstance(data, dict):
        return code, raw
    nodes = group_nodes(group)
    if not nodes:
        return code, raw
    res = fill_absent({n: (data.get(n) if isinstance(data.get(n), int) and not isinstance(data.get(n), bool) else 0) for n in nodes}, budget)
    out = {k: v for k, v in data.items() if k not in res}  # 组成员里的策略组等：保留核心原来的结果
    out.update({k: v for k, v in res.items() if v and v > 0})
    return 200, json.dumps(out, ensure_ascii=False).encode()
