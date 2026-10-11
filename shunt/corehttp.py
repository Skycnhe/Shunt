"""核心控制器 HTTP（叶子模块）：与 mihomo/sing-box 控制器 API 对话。

从 core.py 拆出：只依赖 base、data，无环；core.py 及其他模块从这里导入。
"""
import json
import os
import urllib.request
import urllib.error

from .base import CTRL, DATA_FILE
from .data import load

DIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # 访问本机控制器绝不走系统代理


_SECRET=[None, ""]


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
