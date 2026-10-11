#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""生成设备上部署的两个单文件：
- server.py：内嵌 shunt/ 包的全部模块源码
- index.html：由 web/index.html 模板把 web/style.css、web/js/*.js 按 @include 标记拼进去

    python3 tools/build.py          # 改完 shunt/ 或 web/ 后重新生成 server.py 和 index.html
    python3 tools/build.py --check  # 检查两者是否与源码一致（CI 用），不一致返回 1
    python3 tools/build.py --split  # 反向：从 server.py 里取出内嵌源码写回 shunt/（直接改了 server.py 时用）

server.py 运行时注册一个导入器，从内嵌源码加载 shunt 包；异常堆栈里显示的是 shunt/xxx.py 的文件名和行号。
旧版面板的在线更新只下载 server.py 等固定文件，所以必须保持单文件部署。
"""
import ast, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG, OUT = os.path.join(ROOT, "shunt"), os.path.join(ROOT, "server.py")
WEB, HTML = os.path.join(ROOT, "web"), os.path.join(ROOT, "index.html")
INC = re.compile(r"^(?:/\*@include (\S+)\*/|//@include (\S+))$")

HEAD = '''#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shunt 分流: 零依赖的旁路由透明代理管理后端 (Alpine Linux, mihomo / sing-box)

本文件由 tools/build.py 生成，内嵌了 shunt/ 目录下全部模块的源码。请修改 shunt/ 下的文件后重新生成，不要直接改这里。
"""
PANEL_VERSION = "{ver}"
import importlib.abc, importlib.util, linecache, os, sys, types

_SRC = {{}}
'''

TAIL = '''

class _Importer(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """从 _SRC 加载 shunt 包；把源码登记到 linecache，异常堆栈能显示出错的那一行"""

    @staticmethod
    def path(name):
        return name.replace(".", "/") + ("/__init__.py" if name == "shunt" else ".py")

    def find_spec(self, name, path=None, target=None):
        if name in _SRC:
            return importlib.util.spec_from_loader(name, self, origin=self.path(name), is_package=name == "shunt")
        return None

    def create_module(self, spec):
        return None

    def exec_module(self, mod):
        fn, src = self.path(mod.__name__), _SRC[mod.__name__]
        mod.__file__ = fn
        linecache.cache[fn] = (len(src), None, src.splitlines(True), fn)
        exec(compile(src, fn, "exec"), mod.__dict__)


sys.meta_path.insert(0, _Importer())
import shunt  # noqa: E402

shunt.load(os.path.abspath(__file__))
for _m in shunt._loaded:  # 兼容 `import server` / runpy 的脚本（selftest.sh、离线包构建）：所有名字在这里都能拿到
    globals().update((k, v) for k, v in vars(_m).items() if not k.startswith("__") and k != "_link")


class _Facade(types.ModuleType):
    """`server.X = ...`（测试打桩）同时改掉各模块里的同名变量"""

    def __setattr__(self, k, v):
        super().__setattr__(k, v)
        shunt.setvar(k, v)


if __name__ != "__main__" and isinstance(sys.modules.get(__name__), types.ModuleType):
    sys.modules[__name__].__class__ = _Facade

if __name__ == "__main__":
    shunt.cli.main()
'''


def modules():
    init = open(os.path.join(PKG, "__init__.py"), encoding="utf-8").read()
    names = ast.literal_eval(re.search(r"^MODULES = (\[.*?\])", init, re.M | re.S).group(1))
    return ["shunt"] + ["shunt." + n for n in names]


def file_of(mod):
    return os.path.join(PKG, "__init__.py" if mod == "shunt" else mod.split(".", 1)[1] + ".py")


def quote(s):
    return "'''" + s.replace("\\", "\\\\").replace("'''", "\\'\\'\\'") + "'''"


def build():
    srcs = {m: open(file_of(m), encoding="utf-8").read() for m in modules()}
    for m, s in srcs.items():
        compile(s, file_of(m), "exec")
    ver = re.search(r'^PANEL_VERSION = "([^"]+)"', srcs["shunt.base"], re.M).group(1)
    out = [HEAD.format(ver=ver)]
    for m, s in srcs.items():
        out.append(f"_SRC[{m!r}] = {quote(s)}\n")
    out.append(TAIL)
    res = "".join(out)
    tree = ast.parse(res)
    got = {ast.literal_eval(n.targets[0].slice): ast.literal_eval(n.value) for n in tree.body
           if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Subscript)}
    assert got == srcs, "内嵌源码往返不一致"
    return res


def build_web():
    out = []
    for line in open(os.path.join(WEB, "index.html"), encoding="utf-8").read().split("\n"):
        m = INC.match(line)
        if m:
            with open(os.path.join(WEB, m.group(1) or m.group(2)), encoding="utf-8") as f:
                out.append(f.read()[:-1])  # 去掉拆分时补的最后一个换行
        else:
            out.append(line)
    return "\n".join(out)


def split():
    tree = ast.parse(open(OUT, encoding="utf-8").read())
    n = 0
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Subscript):
            m = ast.literal_eval(node.targets[0].slice)
            with open(file_of(m), "w", encoding="utf-8") as f:
                f.write(ast.literal_eval(node.value))
            n += 1
    print(f"已写回 {n} 个模块")


if __name__ == "__main__":
    if "--split" in sys.argv:
        split()
        sys.exit(0)
    targets = [(OUT, build(), "shunt/"), (HTML, build_web(), "web/")]
    if "--check" in sys.argv:
        bad = [f"{os.path.basename(f)} 与 {src} 不一致" for f, txt, src in targets
               if (open(f, encoding="utf-8").read() if os.path.exists(f) else "") != txt]
        if bad:
            sys.exit("；".join(bad) + "：改完源码后请运行 python3 tools/build.py")
        print(f"server.py 与 shunt/（{len(modules())} 个模块）、index.html 与 web/ 一致")
        sys.exit(0)
    for f, txt, _ in targets:
        with open(f, "w", encoding="utf-8") as fh:
            fh.write(txt)
    print(f"已生成 server.py（{len(modules())} 个模块）和 index.html")
