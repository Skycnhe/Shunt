"""实时速率 / 内存（订阅 /traffic 与 /memory 流）"""
import json, socket, time

from .errlog import log_err
from .core import conns_snapshot
from .logstream import core_stream


LIVE = {"up": 0, "down": 0, "upTotal": 0, "downTotal": 0, "inuse": 0, "oslimit": 0, "t": 0}


def live_loop(path):
    def sink(line):
        try:
            j = json.loads(line)
        except Exception:
            return
        if path == "/memory":
            if j.get("inuse"):  # 首条消息固定为 0
                LIVE["inuse"], LIVE["oslimit"] = j["inuse"], j.get("oslimit", 0)
        else:
            LIVE.update({k: j.get(k, 0) for k in ("up", "down")})
            if "upTotal" in j or "downTotal" in j:
                LIVE.update(upTotal=j.get("upTotal", 0), downTotal=j.get("downTotal", 0))
            elif time.time() - LIVE.get("_tt", 0) > 2:  # sing-box 的 /traffic 不带累计值，从 /connections 取
                LIVE["_tt"] = time.time()
                c = conns_snapshot(timeout=3) or {}
                LIVE.update(upTotal=int(c.get("uploadTotal") or 0), downTotal=int(c.get("downloadTotal") or 0))
            LIVE["t"] = time.time()
    while True:
        try:
            core_stream(path, sink, {}, idle=15)
        except OSError:  # 内核未运行 / 断线，稍后重连
            pass
        except Exception as e:
            log_err("实时速率", e)
        LIVE.update(up=0, down=0, t=0) if path == "/traffic" else LIVE.update(inuse=0)
        time.sleep(3)


def memory_once():
    """不依赖后台线程：读取 /memory 流的前两行（首行恒为 0）"""
    got = []
    stop = {}

    def sink(line):
        try:
            j = json.loads(line)
        except Exception:
            return
        got.append(j)
        if j.get("inuse") or len(got) >= 2:
            stop["stop"] = True
            try:
                stop["sock"].shutdown(socket.SHUT_RDWR)
            except (KeyError, OSError):
                pass
    try:
        core_stream("/memory", sink, stop, idle=3)
    except Exception:
        pass
    vals = [g for g in got if g.get("inuse")]
    return vals[-1] if vals else {"inuse": 0, "oslimit": 0}
