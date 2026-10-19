# SPDX-License-Identifier: GPL-3.0-or-later
"""版本备份/恢复：把面板文件打包成带版本号的 tar.gz，支持一键回滚。"""
import json
import os
import re
import shutil
import tarfile
import tempfile
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
    os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)


def _fix_perms():
    """备份里有 data.json（订阅 URL、节点密码、TG token）：旧版按默认 umask 建成 644 的收紧为 600"""
    try:
        os.chmod(BACKUP_DIR, 0o700)
        for fn in os.listdir(BACKUP_DIR):
            fp = os.path.join(BACKUP_DIR, fn)
            if fn.endswith(".tar.gz") and os.path.isfile(fp) and os.stat(fp).st_mode & 0o077:
                os.chmod(fp, 0o600)
    except OSError:
        pass


def _backup_name(version, ts=None):
    ts = ts or time.strftime("%Y%m%d-%H%M%S")
    # 版本号里的非法字符替换掉，保证文件名安全
    safe_ver = re.sub(r"[^0-9A-Za-z.\-]", "_", version or "unknown")
    return "shunt-backup-v%s-%s.tar.gz" % (safe_ver, ts)


def _parse_name(name):
    """从文件名解析出 version。返回 version 或 None。"""
    m = re.match(r"^shunt-backup-v(.+?)-(\d{8}-\d{6})(-\d+)?\.tar\.gz$", name)
    return m.group(1) if m else None


def create(version=None, keep=None):
    """创建备份，失败不抛异常。返回 (ok, name_or_message)。

    version: 打上的版本号，默认当前 PANEL_VERSION。
    keep: 清理旧备份时必须保留的文件名（恢复时保住正要恢复的那个）。
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
        # 一开始就以 600 创建（不经过默认 umask 的 644 窗口）；O_EXCL 防止同名覆盖
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as fo, tarfile.open(fileobj=fo, mode="w:gz") as tf:
                for kind, rel in _FILES:
                    src = os.path.join(BASE, rel) if kind == "base" else rel
                    if os.path.isfile(src):
                        tf.add(src, arcname=rel)
                if os.path.isfile(DATA_FILE):
                    tf.add(DATA_FILE, arcname="data.json")
        except BaseException:
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
        cleanup(protect=keep)
        return True, name
    except Exception as e:
        # 自动备份失败不阻断调用方
        return False, str(e)


def list():
    """返回备份列表 [{name, version, size, mtime}]，按时间倒序。"""
    _ensure_dir()
    _fix_perms()
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


def _backup_path(name):
    """校验备份文件名并返回 (路径, 错误)：拒绝路径穿越、不是备份格式的名字和不存在的文件"""
    if not name or "/" in name or "\\" in name or ".." in name:
        return None, "非法文件名"
    if not _parse_name(name):
        return None, "不是有效的备份文件"
    fp = os.path.join(BACKUP_DIR, name)
    if not os.path.isfile(fp):
        return None, "备份不存在"
    return fp, ""


def delete(name):
    """删除指定备份。返回 (ok, message)。"""
    fp, err = _backup_path(name)
    if err:
        return False, err
    try:
        os.unlink(fp)
        return True, "已删除"
    except OSError as e:
        return False, str(e)


def cleanup(keep=KEEP_N, protect=None):
    """只保留最近 keep 个，删除最旧的（protect 指定的文件不删）。"""
    allb = list()
    items = [it for it in allb if it["name"] != protect]
    for it in items[keep - (len(allb) - len(items)):]:
        try:
            os.unlink(os.path.join(BACKUP_DIR, it["name"]))
        except OSError:
            pass


def restore(name, check_data=None, apply_data=None):
    """恢复指定备份。返回 (ok, message)。

    流程：解压到临时目录 → check_data 校验备份里的 data.json（不通过则什么都不改）→ 自动备份当前版本（防呆）
    → 覆盖 server.py/index.html，data.json 交给 apply_data 写入（没给时原样覆盖）。恢复 server.py 后需重启面板进程才生效。
    check_data(dict) 返回要写入的 dict，数据无效时抛 ValueError（提示直接给用户看）。
    """
    fp, err = _backup_path(name)
    if err:
        return False, err
    try:
        with tarfile.open(fp, "r:gz") as tf:
            members = tf.getmembers()
            # 安全检查：不允许绝对路径、..、symlink/hardlink
            for m in members:
                if m.name.startswith("/") or ".." in m.name:
                    return False, "备份文件内容非法"
                if m.issym() or m.islnk():
                    return False, "备份文件含非法链接"
            # 解压到唯一临时目录再搬，避免半截覆盖和并发冲突
            _ensure_dir()
            tmpd = tempfile.mkdtemp(prefix="restore_", dir=BACKUP_DIR)
            try:
                try:
                    tf.extractall(tmpd, filter="data")
                except TypeError:  # Python < 3.12 且没有安全补丁的版本没有 filter 参数；上面已逐项检查过成员
                    tf.extractall(tmpd)
                src_data = os.path.join(tmpd, "data.json")
                new_data = None
                if os.path.isfile(src_data) and check_data is not None:
                    # 与「恢复设置」相同的校验：形状不对 / 生成不了配置的数据不写进 data.json，当前数据保持不变
                    try:
                        with open(src_data, encoding="utf-8") as f:
                            raw = json.load(f)
                        new_data = check_data(raw)
                    except ValueError as e:
                        return False, "备份里的设置无效，未恢复（当前设置未改动）：%s" % e
                # 防呆：先备份当前。已有 10 个备份时，新备份会挤掉最旧的一个——恰好是要恢复的这个时以前会把它删掉再报「恢复失败」
                ok, cur = create(keep=name)
                if not ok:
                    return False, "备份当前版本失败，中止恢复：%s" % cur
                # 搬文件
                for rel in ("server.py", "index.html", "CHANGELOG.md"):
                    src = os.path.join(tmpd, rel)
                    if os.path.isfile(src):
                        dst = os.path.join(BASE, rel)
                        shutil.copyfile(src, dst + ".new")
                        os.chmod(dst + ".new", 0o644)
                        os.replace(dst + ".new", dst)
                if new_data is not None and apply_data is not None:
                    apply_data(new_data)
                elif os.path.isfile(src_data):
                    shutil.copyfile(src_data, DATA_FILE + ".new")
                    os.chmod(DATA_FILE + ".new", 0o600)
                    os.replace(DATA_FILE + ".new", DATA_FILE)
            finally:
                shutil.rmtree(tmpd, ignore_errors=True)
        return True, "已恢复到 %s（已自动备份当前版本 %s）。恢复 server.py 后需重启面板生效。" % (name, cur)
    except Exception as e:
        return False, "恢复失败：%s" % e
