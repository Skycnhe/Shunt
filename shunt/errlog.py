"""错误记录：原本被吞掉的异常记到面板日志和「诊断」页"""
import time
from collections import deque

ERRS = deque(maxlen=30)
_ERR_SEEN = {}


def log_err(where, e, tb=False):
    """把原本被吞掉的异常记到面板日志和「诊断」里；同一处同一错误 10 分钟只记一次"""
    msg = f"{type(e).__name__}: {e}"[:300] if isinstance(e, BaseException) else str(e)[:300]
    key = (where, msg)
    now = time.time()
    if now - _ERR_SEEN.get(key, 0) < 600:
        return
    _ERR_SEEN[key] = now
    if len(_ERR_SEEN) > 500:
        _ERR_SEEN.clear()
    ERRS.appendleft({"t": int(now), "where": where, "msg": msg})
    extra = ""
    if tb and isinstance(e, BaseException):
        import traceback
        extra = "\n" + "".join(traceback.format_exception(type(e), e, e.__traceback__))[-1500:]
    print(f"[error] {where}: {msg}{extra}", flush=True)
