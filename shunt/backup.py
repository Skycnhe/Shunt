# SPDX-License-Identifier: GPL-3.0-or-later
"""版本备份/恢复：把面板文件打包成带版本号的 tar.gz，支持一键回滚。"""
import os
import re
import tarfile
import time

from .base import BASE, DATA_FILE, PANEL_VERSION

# 备份目录：跟 data.json 同级
BACKUP_DIR = os.path.join(os.path.dirname(os.path.abspath(DATA_FILE)), "backups")
# 保留最近多少个备份
KEEP_N = 10

# 打包进备份的文件（相对于 BASE / DATA_FILE 所在目录）
_FILES = [
    ("base", "server.py"),
    ("base", "index.html"),
    ("base", "CHANGELOG.md"),
]


def _ensure_dir():
    os.makedirs(BACKUP_DIR, exist_ok=True)


def _backup_name(version, ts=None):
    ts = ts or time.strftime("%Y%m%d-%H%M%S")
    # 版本号里的非法字符替换掉，保证文件名安全
    safe_ver = re.sub(r"[^0-9A-Za-z.\-]", "_", version or "unknown")
    return "shunt-backup-v%s-%s.tar.gz" % (safe_ver, ts)


def _parse_name(name):
    """从文件名解析出 version。返回 version 或 None。"""
    m = re.match(r"^shunt-backup-v(.+)-(\d{8}-\d{6})(-\d+)?\.tar\.gz$", name)
    return m.group(1) if m else None


def create(version=None, auto=False):
    """创建备份。返回 (ok, name_or_message)。

    version: 打上的版本号，默认当前 PANEL_VERSION。
    auto: 是否自动备份（更新前调用），失败不抛异常。
    """
    version = version or PANEL_VERSION
    try:
        _ensure_dir()
        name = _backup_name(version)
        path = os.path.join(BACKUP_DIR, name)
        # 同名极小概率冲突（同一秒两次），加后缀
        i = 1
        while os.path.exists(path):
            name = _backup_name(version)[:-7] + "-%d.tar.gz" % i
            path = os.path.join(BACKUP_DIR, name)
            i += 1
        with tarfile.open(path, "w:gz") as tf:
            for kind, rel in _FILES:
                src = os.path.join(BASE, rel) if kind == "base" else rel
                if os.path.isfile(src):
                    tf.add(src, arcname=rel)
            if os.path.isfile(DATA_FILE):
                tf.add(DATA_FILE, arcname="data.json")
        cleanup()
        return True, name
    except Exception as e:
        # 自动备份失败不阻断调用方
        return False, str(e)


def list():
    """返回备份列表 [{name, version, size, mtime}]，按时间倒序。"""
    _ensure_dir()
    out = []
    try:
        for fn in os.listdir(BACKUP_DIR):
            if not fn.endswith(".tar.gz"):
                continue
            ver = _parse_name(fn)
            if not ver:
                continue
            fp = os.path.join(BACKUP_DIR, fn)
            try:
                st = os.stat(fp)
            except OSError:
                continue
            out.append({"name": fn, "version": ver, "size": st.st_size,
                        "mtime": int(st.st_mtime)})
    except OSError:
        pass
    out.sort(key=lambda x: x["mtime"], reverse=True)
    return out


def delete(name):
    """删除指定备份。返回 (ok, message)。"""
    if not name or "/" in name or "\\" in name or ".." in name:
        return False, "非法文件名"
    if not _parse_name(name):
        return False, "不是有效的备份文件"
    fp = os.path.join(BACKUP_DIR, name)
    if not os.path.isfile(fp):
        return False, "备份不存在"
    try:
        os.unlink(fp)
        return True, "已删除"
    except OSError as e:
        return False, str(e)


def cleanup(keep=KEEP_N):
    """只保留最近 keep 个，删除最旧的。"""
    items = list()
    for it in items[keep:]:
        try:
            os.unlink(os.path.join(BACKUP_DIR, it["name"]))
        except OSError:
            pass


def restore(name):
    """恢复指定备份。返回 (ok, message)。

    流程：先自动备份当前版本（防呆）→ 解压覆盖 server.py/index.html/data.json。
    恢复 server.py 后需重启面板进程才生效。
    """
    if not name or "/" in name or "\\" in name or ".." in name:
        return False, "非法文件名"
    if not _parse_name(name):
        return False, "不是有效的备份文件"
    fp = os.path.join(BACKUP_DIR, name)
    if not os.path.isfile(fp):
        return False, "备份不存在"
    # 防呆：先备份当前
    ok, cur = create()
    if not ok:
        return False, "备份当前版本失败，中止恢复：%s" % cur
    try:
        with tarfile.open(fp, "r:gz") as tf:
            members = tf.getnames()
            # 安全检查：不允许绝对路径和 .. 
            for m in members:
                if m.startswith("/") or ".." in m:
                    return False, "备份文件内容非法"
            # 解压到临时目录再搬，避免半截覆盖
            tmpd = os.path.join(BACKUP_DIR, ".restore_tmp")
            import shutil
            shutil.rmtree(tmpd, ignore_errors=True)
            os.makedirs(tmpd)
            tf.extractall(tmpd)
            # 搬文件
            for rel in ("server.py", "index.html", "CHANGELOG.md"):
                src = os.path.join(tmpd, rel)
                if os.path.isfile(src):
                    dst = os.path.join(BASE, rel)
                    shutil.copyfile(src, dst + ".new")
                    os.chmod(dst + ".new", 0o644)
                    os.replace(dst + ".new", dst)
            src_data = os.path.join(tmpd, "data.json")
            if os.path.isfile(src_data):
                shutil.copyfile(src_data, DATA_FILE + ".new")
                os.chmod(DATA_FILE + ".new", 0o600)
                os.replace(DATA_FILE + ".new", DATA_FILE)
            shutil.rmtree(tmpd, ignore_errors=True)
        return True, "已恢复到 %s（已自动备份当前版本 %s）。恢复 server.py 后需重启面板生效。" % (name, cur)
    except Exception as e:
        return False, "恢复失败：%s" % e
