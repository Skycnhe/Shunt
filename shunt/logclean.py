"""日志自动清理"""
import os, time

from .base import LOG_FILES
from .data import load
LOG_STATE = {"last": 0, "trimmed": []}


def log_sizes():
    out = []
    for p in LOG_FILES:
        try:
            out.append({"path": p, "size": os.path.getsize(p)})
        except OSError:
            out.append({"path": p, "size": -1})
    return out


def trim_log(path, keep=200):
    """原地截断，只保留最后 keep 行。写入方（OpenRC output_log）以 O_APPEND 打开，截断后会继续追加到新末尾"""
    try:
        with open(path, "rb+") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 256 * 1024))
            tail = f.read().splitlines(keepends=True)[-keep:]
            data = b"".join(tail)
            f.seek(0)
            f.write(data)
            f.truncate()
        return size - len(data)
    except OSError:
        return 0


def log_clean(force=False):
    limit = float(load().get("log_limit") or 5) * 1024 * 1024
    freed = 0
    for x in log_sizes():
        if x["size"] > 0 and (force or x["size"] > limit):
            freed += trim_log(x["path"])
    LOG_STATE["last"] = int(time.time())
    return freed


def log_loop():
    while True:
        try:
            freed = log_clean()
            if freed:
                print(time.strftime("%F %T"), f"[log] 日志超过上限，已截断释放 {freed // 1024} KB", flush=True)
        except Exception as e:
            print("log clean error", e, flush=True)
        time.sleep(60)
