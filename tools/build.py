#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""把 src/ 下按编号排列的源码片段合并成设备上运行的单文件 server.py。

src/*.py 不是独立模块：它们按文件名顺序首尾相接，共用同一个全局命名空间（和拆分前的 server.py 完全一样）。
设备上只部署合并后的 server.py，所以旧版面板的在线更新、install.sh、离线包都不受影响。

    python3 tools/build.py          # 重新生成 server.py
    python3 tools/build.py --check  # 只检查 server.py 是否与 src/ 一致（CI 用），不一致返回 1
    python3 tools/build.py --split  # 反向：把直接改过的 server.py 按片段标记拆回 src/
"""
import glob, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC, OUT = os.path.join(ROOT, "src"), os.path.join(ROOT, "server.py")
MARK = "# ==== src/{} ====\n"
MARK_RE = re.compile(r"^# ==== src/([\w.\-]+\.py) ====\n", re.M)


def parts():
    fs = sorted(glob.glob(os.path.join(SRC, "*.py")))
    if not fs:
        sys.exit("src/ 下没有源码片段")
    return fs


def build():
    out = []
    for f in parts():
        body = open(f, encoding="utf-8").read()
        if not body.endswith("\n"):
            body += "\n"
        name = os.path.basename(f)
        out.append(body if name.startswith("00") else MARK.format(name) + body)  # 00 开头的片段含 shebang，不加标记
    return "".join(out)


def split():
    s = open(OUT, encoding="utf-8").read()
    ms = list(MARK_RE.finditer(s))
    if not ms:
        sys.exit("server.py 里没有片段标记，无法拆分")
    first = os.path.basename(parts()[0])
    chunks = [(first, s[:ms[0].start()])]
    for i, m in enumerate(ms):
        chunks.append((m.group(1), s[m.end():ms[i + 1].start() if i + 1 < len(ms) else len(s)]))
    for name, body in chunks:
        with open(os.path.join(SRC, name), "w", encoding="utf-8") as f:
            f.write(body)
    print(f"已拆回 {len(chunks)} 个片段")


if __name__ == "__main__":
    if "--split" in sys.argv:
        split()
        sys.exit(0)
    s = build()
    compile(s, "server.py", "exec")
    if "--check" in sys.argv:
        cur = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else ""
        if cur != s:
            sys.exit("server.py 与 src/ 不一致：改 src/ 后请运行 python3 tools/build.py")
        print(f"server.py 与 src/ 一致（{len(parts())} 个片段，{s.count(chr(10))} 行）")
        sys.exit(0)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(s)
    print(f"已生成 server.py（{len(parts())} 个片段，{s.count(chr(10))} 行）")
