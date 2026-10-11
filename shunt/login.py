"""登录防爆破"""
import time
FAILS = {}  # ip -> [失败次数, 解锁时间]


def login_blocked(ip):
    e = FAILS.get(ip)
    if e and e[1] > time.time():
        return int(e[1] - time.time())
    return 0


def login_failed(ip):
    if len(FAILS) > 256:  # 清掉已过期的记录，防止字典无限增长
        now = time.time()
        for k in [k for k, v in FAILS.items() if v[1] and v[1] <= now]:
            FAILS.pop(k, None)
    e = FAILS.setdefault(ip, [0, 0])
    if e[1] and e[1] <= time.time():
        e[:] = [0, 0]
    e[0] += 1
    if e[0] >= 5:
        e[1] = time.time() + 600
