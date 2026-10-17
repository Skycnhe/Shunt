"""面板在线更新"""
import hashlib, os, re, shlex, shutil, time, urllib.request, urllib.error

from .errlog import log_err
from .base import BASE, PANEL_VERSION, UA, UPD_STATE, dl_check, local_file, upd_begin, upd_busy_msg
from .core_update import gh_api
from .sysopt import proxy_opener, sh
from .https import restart_self
from .update_guard import start_update_guard
PANEL_RAW = os.environ.get("PANEL_RAW", "https://raw.githubusercontent.com/Skycnhe/Shunt/Hk002")
UPD_FILES = ["server.py", "index.html", "tproxy.sh", "selftest.sh", "init.d/shunt", "init.d/shunt-core"]
UPD_LIST = "update-files.txt"  # 仓库里的部署文件清单：以后增减文件只改清单，不用再改更新程序


def remote_file_list(gh, commit, shas):
    """读取仓库里的部署文件清单（必须通过 GitHub 校验）；没有或拿不到校验值时用内置列表"""
    if not shas or UPD_LIST not in shas:
        return list(UPD_FILES)
    raw = fetch_raw(UPD_LIST, gh, commit, shas[UPD_LIST]).decode("utf-8", "replace")
    out = []
    for ln in raw.splitlines():
        f = ln.split("#", 1)[0].strip()
        if not f:
            continue
        if not re.fullmatch(r"[\w.\-]+(/[\w.\-]+)*", f) or ".." in f.split("/") or f.startswith("."):
            raise ValueError(f"部署清单里有不安全的路径：{f}")
        if f not in shas:
            raise ValueError(f"部署清单里的 {f} 在仓库中不存在")
        out.append(f)
    for need in ("server.py", "index.html"):
        if need not in out:
            raise ValueError(f"部署清单缺少 {need}")
    return out


def panel_manifest():
    """返回 (commit, {路径: git blob sha1})；失败返回 (None, {})"""
    m = re.match(r"https://raw\.githubusercontent\.com/([^/]+/[^/]+)/(.+?)/?$", PANEL_RAW)
    if not m:
        return None, {}
    try:
        c = gh_api(f"/repos/{m.group(1)}/commits/{m.group(2)}")
        t = gh_api(f"/repos/{m.group(1)}/git/trees/{c['commit']['tree']['sha']}?recursive=1")
        return c["sha"], {x["path"]: x["sha"] for x in t.get("tree", []) if x.get("type") == "blob"}
    except Exception as e:
        log_err("获取面板校验值", e)
        return None, {}


def git_blob_sha(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def fetch_raw(f, gh, commit=None, sha=None):
    """下载面板文件。有 GitHub 给的校验值时可以走加速镜像，下载后逐个比对；没有校验值时不走镜像"""
    base = PANEL_RAW.rstrip("/")
    if commit:
        base = base.rsplit("/", 1)[0] + "/" + commit
    url = base + "/" + f
    if not sha:
        gh = ""
    tries = [(gh.rstrip("/") + "/" + url, False)] if gh else []
    tries += [(url, True), (url, False)]  # 先经 mihomo 代理，再直连
    errs = []
    for u, use_proxy in tries:
        try:
            dl_check(u, via_proxy=use_proxy)  # SSRF 防护：直连时校验 DNS，走代理时由代理解析（字面内网 IP 永远拦截）
            req = urllib.request.Request(u + ("&" if "?" in u else "?") + "t=" + str(int(time.time())), headers={"User-Agent": UA})
            with proxy_opener(use_proxy).open(req, timeout=20) as r:
                data = r.read(4 << 20)
            if sha and git_blob_sha(data) != sha:
                raise ValueError("文件校验失败（与 GitHub 上的不一致，可能被加速镜像篡改）")
            return data
        except Exception as e:
            errs.append(f"{u.split('/')[2]}{'(代理)' if use_proxy else '(直连)'}: {str(e)[:120]}")
    raise IOError(f"下载 {f} 失败：" + "；".join(errs))  # 每条线路的失败原因都列出，便于判断是代理还是直连的问题


def self_rollback():
    """把 .backup 里的文件（上次更新前的版本）全部放回去"""
    bak = os.path.join(BASE, ".backup")
    if not os.path.isfile(os.path.join(bak, "server.py")):
        return False, "没有可回滚的备份"
    if not upd_begin("panel"):
        return False, upd_busy_msg()
    try:
        for root, _, names in os.walk(bak):
            for n in names:
                src = os.path.join(root, n)
                shutil.copy2(src, local_file(os.path.relpath(src, bak)))
        restart_self()
    finally:
        UPD_STATE["busy"] = False
    return True, "已回滚到更新前的版本，面板正在重启"


def _undo_replace(done, bak):
    for f in done:
        dst, src = local_file(f), os.path.join(bak, f)
        try:
            if os.path.isfile(src):
                shutil.copy2(src, dst + ".new")
                os.replace(dst + ".new", dst)
            else:  # 新增的文件：删掉
                os.remove(dst)
        except OSError as e:
            log_err("面板更新失败后恢复 " + f, e)


def remote_version(src):
    m = re.search(rb'^PANEL_VERSION = "([^"]+)"', src, re.M)
    return m.group(1).decode() if m else "?"


def self_update(apply=False, gh=""):
    """检查 / 应用 GitHub 上的新版面板：下载全部文件 → 校验 → 备份 → 替换 → 重启面板"""
    # 只检查不替换时不占用忙标志；真正更新时与内核更新 / 切换 / 回滚互斥（内核替换到一半时重启面板会留下半截二进制）
    if apply and not upd_begin("panel"):
        return False, {"message": upd_busy_msg()}
    try:
        files, changed = {}, []
        commit, shas = panel_manifest()
        flist = remote_file_list(gh, commit, shas)
        for f in flist:
            data = fetch_raw(f, gh, commit, shas.get(f))
            files[f] = data
            try:
                with open(local_file(f), "rb") as fh:
                    same = fh.read() == data
            except OSError:
                same = False
            if not same:
                changed.append(f)
        info = {"current": PANEL_VERSION, "remote": remote_version(files["server.py"]), "changed": changed,
                "source": PANEL_RAW, "verified": bool(shas), "commit": (commit or "")[:10]}
        if not apply:
            info["message"] = "已是最新" if not changed else f"有 {len(changed)} 个文件可更新"
            return True, info
        if not changed:
            info["message"] = "已是最新，无需更新"
            return True, info
        try:  # 校验：Python 语法、HTML 完整、shell 语法
            compile(files["server.py"], "server.py", "exec")
        except SyntaxError as e:
            raise ValueError(f"新版 server.py 语法错误：{e}")
        if b"</html>" not in files["index.html"] or b"<script>" not in files["index.html"]:
            raise ValueError("新版 index.html 不完整")
        tmpd = os.path.join(BASE, ".update")
        shutil.rmtree(tmpd, ignore_errors=True)
        for f, data in files.items():
            os.makedirs(os.path.dirname(os.path.join(tmpd, f)), exist_ok=True)
            with open(os.path.join(tmpd, f), "wb") as fh:
                fh.write(data)
            if f.endswith(".sh") or f.startswith("init.d/"):
                code, out = sh("sh -n " + shlex.quote(os.path.join(tmpd, f)))  # f 来自远端清单：引用防注入
                if code != 0:
                    raise ValueError(f"新版 {f} 语法错误：{out[-200:]}")
        bak = os.path.join(BASE, ".backup")
        shutil.rmtree(bak, ignore_errors=True)
        os.makedirs(bak)
        for f in flist:
            if os.path.isfile(local_file(f)):
                os.makedirs(os.path.dirname(os.path.join(bak, f)), exist_ok=True)
                shutil.copy2(local_file(f), os.path.join(bak, f))
        # 版本备份：更新前自动打一个带版本号的 tar.gz（失败不阻断更新）
        try:
            from . import backup as backup_mod
            ok, name = backup_mod.create()
            if not ok:
                log_err("面板在线更新", "更新前自动备份失败：%s" % name)
        except Exception as e:
            log_err("面板在线更新：更新前自动备份异常", e)
        done = []
        try:
            for f in changed:
                dst = local_file(f)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copyfile(os.path.join(tmpd, f), dst + ".new")
                os.chmod(dst + ".new", 0o755 if (f.endswith(".sh") or f.startswith("init.d/")) else 0o644)
                os.replace(dst + ".new", dst)
                done.append(f)
        except Exception as e:
            # 替换到一半失败（磁盘满等）：已替换的文件放回旧版，不留下新 server.py + 旧 index.html 这样的混合版本
            _undo_replace(done, bak)
            raise ValueError(f"替换文件失败，已恢复原文件：{e}")
        shutil.rmtree(tmpd, ignore_errors=True)
        start_update_guard(flist)
        restart_self()
        info["message"] = (f"已更新 {len(changed)} 个文件（{'、'.join(changed)}）" + ("，已通过 GitHub 校验" if shas else "")
                           + "，面板正在重启；新版启动失败会在 90 秒内自动回滚")
        return True, info
    except Exception as e:
        return False, {"message": str(e)}
    finally:
        if apply:
            UPD_STATE["busy"] = False

