"""节点延迟缓存"""
import base64, json, os, re, threading, time, urllib.request, urllib.error
from urllib.parse import quote

from .errlog import log_err
from .base import G_MANUAL, G_SEL, HC, NOTIFY_FILE, PANEL_DIR, UA, WD_INTERVAL
from .data import load, read_json, write_json
from .core import core, core_json, refresh_regions
from .sb_common import active_core
from .sb_config import sb_fake_providers
from .sysopt import proxy_opener
from .notify import WD, check_nodes, core_alive, load_notified, notify, watchdog_tick
# 核心只在内存里保存最近几次测速记录：重载配置、重启、切换内核后全部清空，订阅节点的记录又分散在
# /proxies 与 /providers/proxies 两处，前端轮询时就会「一会有一会没有」。面板把每个节点最近一次的
# 测速结果（任意测速地址中时间最新的一条）缓存到文件，核心暂时没有记录时用缓存补上。
DELAY_FILE = os.path.join(PANEL_DIR, "delays.json")
BG_FILE = os.path.join(PANEL_DIR, "bg.img")  # 外观：自定义背景图（所有设备共用）
BG_MAX = 8 * 2**20
DELAYS = {"data": None, "saved": 0, "dirty": False}
RETEST = {"pending": False, "last": 0}


def _hist_last(p):
    """节点所有测速记录（history 与各地址的 extra.history）里时间最新的一条 → (延迟, 时间串)"""
    best = None
    lists = [p.get("history") or []] + [v.get("history") or [] for v in (p.get("extra") or {}).values() if isinstance(v, dict)]
    for h in lists:
        if h and isinstance(h[-1], dict) and "delay" in h[-1]:
            e = h[-1]
            if best is None or str(e.get("time") or "") > best[1]:
                best = (int(e.get("delay") or 0), str(e.get("time") or ""))
    return best


def delay_merge(px):
    """用核心的最新记录更新缓存，并给每个节点写入 _d（延迟）/ _dt（测速时间）"""
    if DELAYS["data"] is None:
        DELAYS["data"] = read_json(DELAY_FILE, {}) or {}
    data, now = DELAYS["data"], int(time.time())
    for name, p in px.items():
        if p.get("all") is not None:  # 策略组的延迟取当前节点，前端处理
            continue
        r = _hist_last(p)
        if r:
            old = data.get(name)
            if not old or old.get("ts") != r[1]:
                data[name] = {"d": r[0], "ts": r[1], "at": now}
                DELAYS["dirty"] = True
        c = data.get(name)
        if c:
            p["_d"], p["_dt"] = c["d"], c["at"]
    if px:
        for n in [n for n in data if n not in px]:  # 节点已不存在
            data.pop(n)
            DELAYS["dirty"] = True
    if DELAYS["dirty"] and now - DELAYS["saved"] > 30:
        try:
            write_json(DELAY_FILE, data)
            DELAYS.update(saved=now, dirty=False)
        except OSError as e:
            log_err("保存延迟缓存", e)
    return px


def fix_global():
    """mihomo 的「全局」模式走内置 GLOBAL 组，它默认选第一项 DIRECT（全局模式反而不走代理）：没选过代理时指向「🚀 节点选择」"""
    if active_core() == "singbox":  # sing-box 的 Global 已直接指向节点选择
        return
    g = core_json("/proxies/GLOBAL", timeout=5) or {}
    if g.get("now") in (None, "", "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE") and G_SEL in (g.get("all") or []):
        core("PUT", "/proxies/GLOBAL", {"name": G_SEL}, timeout=5)


def retest_soon(wait=6):
    """重载 / 重启后核心的测速记录清空：稍后在后台用「🖐️ 手动选择」（select 组，不会清除 url-test 的固定）测一遍全部节点"""
    if RETEST["pending"] or time.time() - RETEST["last"] < 60:
        return
    RETEST["pending"] = True

    def run():
        try:
            for _ in range(20):
                time.sleep(wait if _ == 0 else 3)
                if core_alive():
                    break
            fix_global()
            if core_json("/proxies/" + quote(G_MANUAL), timeout=5):
                core("GET", f"/group/{quote(G_MANUAL)}/delay?url={quote(HC)}&timeout=5000", timeout=60)
            RETEST["last"] = time.time()
            proxies_merged()
        except Exception as e:
            log_err("定时测速", e)
        finally:
            RETEST["pending"] = False
    threading.Thread(target=run, daemon=True).start()


def bg_save(data_url):
    """data:image/...;base64,xxx → 保存背景图；只接受 JPEG / PNG / WebP / GIF"""
    m = re.match(r"data:image/[\w.+-]+;base64,(.+)$", str(data_url or ""), re.S)
    if not m:
        return False, "图片格式不正确"
    try:
        raw = base64.b64decode(m.group(1), validate=False)
    except Exception:
        return False, "图片数据无法解析"
    if len(raw) > BG_MAX:
        return False, "图片不能超过 8MB"
    if bg_type(raw[:16]) is None:
        return False, "只支持 JPG / PNG / WebP / GIF"
    tmp = BG_FILE + ".tmp"
    with open(tmp, "wb") as f:
        f.write(raw)
    os.replace(tmp, BG_FILE)
    return True, "背景图已保存"


BG_META = BG_FILE + ".json"  # 链接背景图：{"url": 链接, "daily": 每天刷新, "t": 上次下载时间}


def bg_meta():
    try:
        with open(BG_META) as f:
            m = json.load(f)
        return m if isinstance(m, dict) else {}
    except Exception:
        return {}


def bg_meta_save(m):
    try:
        if m:
            tmp = BG_META + ".tmp"
            with open(tmp, "w") as f:
                json.dump(m, f, ensure_ascii=False)
            os.replace(tmp, BG_META)
        elif os.path.exists(BG_META):
            os.remove(BG_META)
    except OSError as e:
        print("bg meta save error", e, flush=True)


def bg_fetch(url):
    """由路由器下载图片链接保存为背景图（先走代理，失败再直连）。必应每日壁纸这类接口会 302 跳到真实图片，urllib 自动跟随"""
    url = str(url or "").strip()
    if not re.match(r"https?://\S+$", url):
        return False, "请输入 http(s) 开头的图片链接"
    raw, err = None, ""
    for proxy in (True, False):
        # 每次新建 Request：走代理时 urllib 会把代理地址写进 Request，复用会让直连也连到代理端口
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "image/avif,image/webp,image/*,*/*;q=0.8"})
        try:
            with proxy_opener(proxy).open(req, timeout=20) as r:
                raw = r.read(BG_MAX + 1)
            break
        except urllib.error.HTTPError as e:
            err = f"HTTP {e.code}"
        except Exception as e:
            err = str(e)[:120]
    if raw is None:
        return False, "下载失败：" + (err or "无法连接")
    if len(raw) > BG_MAX:
        return False, "图片不能超过 8MB"
    if bg_type(raw[:16]) is None:
        return False, "链接返回的不是 JPG / PNG / WebP / GIF 图片"
    tmp = BG_FILE + ".tmp"
    with open(tmp, "wb") as f:
        f.write(raw)
    os.replace(tmp, BG_FILE)
    return True, "背景图已下载到路由器"


def bg_type(head):
    if head[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if head[:4] == b"GIF8":
        return "image/gif"
    return None


def proxies_merged():
    """/proxies + 订阅节点（mihomo 在 /providers/proxies，sing-box 由面板拼出）合并成一份，并补上缓存的延迟"""
    a = core_json("/proxies", timeout=8)
    if a is None:
        return None
    px = dict(a.get("proxies") or {})
    try:
        prov = prov_json().get("providers") or {}
    except Exception:
        prov = {}
    for pv in prov.values():
        for n in pv.get("proxies") or []:
            if n and n.get("name"):
                cur = px.get(n["name"])
                if not cur:
                    px[n["name"]] = n
                elif not _hist_last(cur) and _hist_last(n):  # 同名节点：保留有测速记录的那份
                    cur["history"], cur["extra"] = n.get("history") or [], n.get("extra") or {}
    delay_merge(px)
    nodes = [p for p in px.values() if p.get("all") is None and p.get("type") not in ("Direct", "Reject", "RejectDrop", "Pass", "Compatible", "Dns")]
    if nodes and not any("_d" in p for p in nodes):  # 一个延迟都没有（刚启动 / 刚重载）：后台补测
        retest_soon(1)
    return px


def prov_json():
    """订阅节点（mihomo /providers/proxies 格式）；sing-box 由面板按缓存拼出同样的结构"""
    if active_core() == "singbox":
        return sb_fake_providers(load())
    return core_json("/providers/proxies") or {}


def check_subs():
    prov = prov_json().get("providers", {})
    names = {s["name"] for s in load()["subs"]}
    st = load_notified()
    changed = False
    now = time.time()
    for name, p in prov.items():
        si = p.get("subscriptionInfo") or {}
        if name not in names or not si:
            continue
        exp = int(si.get("Expire") or 0)
        k = "exp:" + name
        if exp and 0 < exp - now < 3 * 86400 and st.get(k) != exp:
            st[k] = exp
            changed = True
            notify(f"⏰ 订阅「{name}」将于 {time.strftime('%Y-%m-%d %H:%M', time.localtime(exp))} 到期")
        total, used = int(si.get("Total") or 0), int(si.get("Upload") or 0) + int(si.get("Download") or 0)
        k = "traffic:" + name
        high = total > 0 and used / total > 0.9
        if high and not st.get(k):
            notify(f"📶 订阅「{name}」流量已用 {used / total:.0%}（{used / 2**30:.1f} / {total / 2**30:.1f} GB）")
        if high != bool(st.get(k)):
            st[k] = high
            changed = True
    if changed:
        write_json(NOTIFY_FILE, st)


def monitor_loop():
    n = 0
    while True:
        time.sleep(WD_INTERVAL)
        n += 1
        for fn, every in ((watchdog_tick, 1), (check_nodes, 20), (check_subs, 120), (refresh_regions, 20)):
            if n % every == 0 or (fn is check_subs and n == 2):
                try:
                    if fn is watchdog_tick or WD["status"] in ("ok", "off"):
                        fn()
                except Exception as e:
                    print("monitor error", fn.__name__, e, flush=True)
