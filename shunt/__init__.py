"""Shunt 分流面板后端。

设备上运行的是仓库根目录的 server.py：它由 tools/build.py 生成，内嵌了本目录全部模块的源码，所以部署时仍然只有一个文件。
模块之间直接 from-import，依赖无环（tools/build.py 生成前可用文末的 SCC 脚本验证）。
唯一的例外是 core.py 末尾的 _link()：core.reload_core() 需要 latency.retest_soon()，
而 latency 的定时器又需要 core.refresh_regions()，真互递归，只能延迟绑定这一个名字。
"""
import importlib
import os

# 加载顺序：模块顶层代码只用到排在前面的模块
MODULES = [
    "base",
    "wgcrypto",
    "errlog",
    "data",
    "links",
    "ruleutil",
    "groups",
    "mihomo",
    "core",
    "corehttp",
    "sb_common",
    "sb_yaml",
    "sb_subs",
    "sb_nodes",
    "sb_rules",
    "sb_dns",
    "sb_config",
    "sb_switch",
    "panel_update",
    "backup",
    "health",
    "core_update",
    "sysopt",
    "notify",
    "warp",
    "latency",
    "stats",
    "unlock",
    "ruletest",
    "logstream",
    "adblock",
    "live",
    "logclean",
    "schedule",
    "devices",
    "diag",
    "dnsleak",
    "ipinfo",
    "migrate",
    "https",
    "access",
    "update_guard",
    "svcmigrate",
    "static",
    "webapi",
    "cli",
]
SERVER_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server.py")
_loaded = []


def load(server_file=None):
    """按顺序加载全部模块并绑定模块间的引用；返回模块列表（重复调用直接返回）"""
    global SERVER_FILE
    if _loaded:
        return _loaded
    if server_file:
        SERVER_FILE = server_file
    mods = [importlib.import_module(__name__ + "." + n) for n in MODULES]
    for m in mods:
        if hasattr(m, "_link"):
            m._link()
    _loaded.extend(mods)
    return _loaded


def setvar(name, value):
    """测试 / 调试用：把所有模块里同名的全局变量一起改掉（from-import 让每个模块都有自己的一份引用）"""
    for m in _loaded:
        if name in vars(m):
            setattr(m, name, value)
