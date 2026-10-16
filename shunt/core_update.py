"""内核（mihomo）更新"""
import hashlib, json, os, re, shutil, shlex, sys, threading, time, urllib.request, urllib.error
from collections import deque
from urllib.parse import quote

from .errlog import log_err
from .base import CONF_DIR, CORE_UPD, LGBM_URL, MIHOMO_LOG, UA, UPD_STATE, dl_check
from .data import load
from .mihomo import mh_bin, write_config
from .core import reload_core
from .sb_common import CORES, active_core
from .sysopt import proxy_opener, sh, svc_restart
from .notify import core_alive, notify
CORE_REPO = os.environ.get("CORE_REPO", "https://github.com/MetaCubeX/mihomo/releases")
CORE_CHANNELS = {"stable": "latest/download", "alpha": "download/Prerelease-Alpha"}
SMART_REPO = os.environ.get("SMART_REPO", "https://github.com/vernesong/mihomo/releases")  # 只发布 Alpha 预览版
LGBM_FILE = os.path.join(CONF_DIR, "Model.bin")


def core_arch():
    m = os.uname().machine
    if m == "x86_64":
        try:  # 支持 AVX2 等 x86-64-v3 指令集的 CPU 用 v3 版本更快，否则用兼容版
            flags = open("/proc/cpuinfo").read()
            if all(f in flags for f in (" avx2", " bmi2", " fma", " movbe")):
                return "amd64-v3"
        except OSError:
            pass
        return "amd64-compatible"
    return {"aarch64": "arm64", "arm64": "arm64", "armv7l": "armv7", "armv8l": "armv7", "armv6l": "armv6",
            "i686": "386", "i386": "386", "riscv64": "riscv64", "loongarch64": "loong64-abi2"}.get(m, "")


def bin_version(path):
    """执行 mihomo -v，返回版本号（如 v1.19.32 / alpha-9f053c4）；不能运行时返回空串"""
    if not os.path.isfile(path):
        return ""
    code, out = sh(f"{shlex.quote(path)} -v", timeout=15)
    m = re.search(r"Mihomo\s+Meta\s+(\S+)", out) if code == 0 else None
    return m.group(1) if m else ""


def open_url(url, gh, timeout=20):
    """GitHub 下载：先走加速地址，再经 mihomo 代理，最后直连"""
    tries = [(gh.rstrip("/") + "/" + url, False)] if gh else []
    tries += [(url, True), (url, False)]
    err = ""
    for u, use_proxy in tries:
        try:
            eff_proxy = use_proxy and core_alive()
            dl_check(u, via_proxy=eff_proxy)  # SSRF 防护：直连时校验 DNS，走代理时由代理解析（字面内网 IP 永远拦截）
            req = urllib.request.Request(u, headers={"User-Agent": UA})
            return proxy_opener(eff_proxy).open(req, timeout=timeout)
        except Exception as e:
            err = f"{u.split('/')[2]}{'(代理)' if use_proxy else ''}: {str(e)[:120]}"
    raise IOError(err)


def gh_api(path, timeout=15):
    """直连或经 mihomo 代理访问 GitHub API（绝不走第三方加速镜像：校验值必须来自 GitHub 本身）"""
    with open_url("https://api.github.com" + path, "", timeout=timeout) as r:
        return json.loads(r.read(8 << 20))


def release_digest(repo_url, tag, name):
    """GitHub Release 资产的 SHA256（GitHub 自动计算，API 的 digest 字段）；拿不到返回空串"""
    m = re.match(r"https://github\.com/([^/]+/[^/]+)/releases", repo_url)
    if not m:
        return ""
    try:
        j = gh_api(f"/repos/{m.group(1)}/releases/tags/{quote(tag)}")
        for a in j.get("assets") or []:
            if a.get("name") == name and str(a.get("digest") or "").startswith("sha256:"):
                return a["digest"][7:]
    except Exception as e:
        log_err("获取内核校验值", e)
    return ""


class HashReader:
    """边读边算 SHA256 的包装（流式解压时用）"""
    def __init__(self, r, prog=None, total=0):
        self.r, self.h, self.n, self.prog, self.total = r, hashlib.sha256(), 0, prog, total

    def read(self, k=-1):
        b = self.r.read(k)
        self.h.update(b)
        self.n += len(b)
        if self.total and self.prog:
            self.prog(min(1.0, self.n / self.total))
        return b


def core_remote_version(channel, gh, kind="mihomo"):
    url = f"{SMART_REPO}/download/Prerelease-Alpha/version.txt" if kind == "smart" else f"{CORE_REPO}/{CORE_CHANNELS[channel]}/version.txt"
    with open_url(url, gh) as r:
        v = r.read(200).decode(errors="ignore").strip()
    if not re.match(r"^[\w.\-]+$", v):
        raise IOError("获取到的版本号无效：" + v[:40])
    return v


def core_check(channel, gh, kind="mihomo"):
    arch, b = core_arch(), mh_bin(kind)
    if kind == "smart":
        channel = "alpha"
    info = {"current": bin_version(b) or "未安装", "arch": arch or os.uname().machine, "channel": channel,
            "backup": bin_version(b + ".bak"), "remote": "", "core": kind}
    try:
        info["remote"] = core_remote_version(channel, gh, kind)
    except Exception as e:
        info["message"] = "获取最新版本失败：" + str(e)
        return False, info
    info["latest"] = info["remote"] == info["current"]
    info["message"] = "已是最新" if info["latest"] else f"可更新到 {info['remote']}"
    return True, info


def _cu(stage, pct=None, msg=None):
    CORE_UPD["stage"] = stage
    if pct is not None:
        CORE_UPD["pct"] = pct
    CORE_UPD["log"].appendleft(f"{time.strftime('%H:%M:%S')} {msg or stage}")


def _core_swap_and_restart(src, label, kind="mihomo"):
    """把 src 换成正式核心并重启；30 秒内控制接口没起来就自动换回原来的核心"""
    B = mh_bin(kind)
    bak = B + ".bak"
    had_old = os.path.isfile(B)
    if had_old and src != bak:
        shutil.copy2(B, bak)
    if src == bak:  # 回滚：当前核心与备份互换，方便再“回滚”回来
        tmp = B + ".swap"
        shutil.copy2(B, tmp)
        os.replace(bak, B)
        os.replace(tmp, bak)
    else:
        os.replace(src, B)
    if active_core() != kind:  # 这个内核没在运行：只替换程序，切换过去时生效
        _cu("完成", 95, f"已替换为 {label}（当前内核是 {CORES[active_core()]}，切到 {CORES[kind]} 时生效）")
        return True, ""
    _cu("重启核心", 90, f"已替换为 {label}，正在重启核心")
    svc_restart(timeout=30)
    for _ in range(30):
        time.sleep(1)
        if core_alive():
            return True, ""
    if had_old and src != bak:  # 新核心起不来 → 自动恢复
        _cu("自动回滚", 95, "新核心 30 秒内未响应，正在恢复原核心")
        shutil.copy2(bak, B)
        svc_restart(timeout=30)
        return False, "新核心启动失败，已自动恢复为原核心。日志：" + sh(f"tail -n 5 '{MIHOMO_LOG}'")[1][-300:]
    return False, "核心重启后 30 秒内未响应，请查看日志"


def mh_fetch(kind, channel, gh, prog=None):
    """下载 mihomo / mihomo Smart 到 <程序>.new 并校验能运行；返回 (临时文件, 版本号)"""
    import gzip
    B = mh_bin(kind)
    arch = core_arch()
    if not arch:
        raise ValueError(f"不支持的 CPU 架构：{os.uname().machine}")
    ver = core_remote_version(channel, gh, kind)
    free = shutil.disk_usage(os.path.dirname(B)).free
    if free < 80 * 2**20:
        raise ValueError(f"{os.path.dirname(B)} 剩余空间不足（{free // 2**20} MB，至少需要 80 MB）")
    tag = "Prerelease-Alpha" if kind == "smart" or channel == "alpha" else ver
    url = f"{SMART_REPO if kind == 'smart' else CORE_REPO}/download/{tag}/mihomo-linux-{arch}-{ver}.gz"
    name = url.rsplit('/', 1)[-1]
    digest = release_digest(SMART_REPO if kind == "smart" else CORE_REPO, tag, name)
    if not digest and gh:
        _cu("下载", None, "拿不到 GitHub 校验值，不使用加速镜像（避免下载到被篡改的文件）")
        gh = ""
    _cu("下载", None, f"下载 {name}")
    tmp = B + ".new"
    try:
        with open_url(url, gh, timeout=30) as r:
            hr = HashReader(r, prog, int(r.headers.get("Content-Length") or 0))
            with gzip.GzipFile(fileobj=hr) as gz, open(tmp, "wb") as f:
                size = 0
                while True:
                    chunk = gz.read(1 << 16)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > 200 * 2**20:
                        raise ValueError("解压后的文件异常过大，已中止")
                    f.write(chunk)
            while hr.read(1 << 16):  # gzip 尾部之后若还有数据也计入校验
                pass
        if digest and hr.h.hexdigest() != digest:
            raise ValueError("内核文件 SHA256 与 GitHub 不一致（可能被加速镜像篡改），未做任何替换")
        _cu("下载", None, "SHA256 校验通过" if digest else "未能获取 GitHub 校验值，已改为直连 / 代理下载")
        os.chmod(tmp, 0o755)
        nv = bin_version(tmp)
        if not nv:
            raise ValueError("新核心无法运行（架构不匹配或文件损坏），未做任何替换")
        return tmp, nv
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def core_update_job(channel, gh, force=False, kind="mihomo"):
    B = mh_bin(kind)
    tmp = B + ".new"
    try:
        _cu("获取版本", 2, "正在获取最新版本号")
        ver = core_remote_version(channel, gh, kind)
        cur = bin_version(B)
        if ver == cur and not force:
            CORE_UPD.update(ok=True, message=f"已是最新版本 {cur}，无需更新")
            return
        CORE_UPD["pct"] = 5
        tmp, nv = mh_fetch(kind, channel, gh, lambda pc: CORE_UPD.update(pct=5 + int(70 * pc)))
        _cu("校验", 84, f"新核心 {nv}，正在用它检查配置")
        if active_core() == kind:  # 正在用：拿当前配置校验；没在用：按它的格式生成一份再校验
            cfg = os.path.join(CONF_DIR, "config.yaml")
        else:
            cfg = write_config(dict(load(), core=kind), os.path.join(CONF_DIR, "config.yaml.chk"))
        code, out = sh(f"'{tmp}' -t -d '{CONF_DIR}' -f '{cfg}'", timeout=90)
        if cfg.endswith(".chk"):
            os.remove(cfg)
        if code != 0:
            raise ValueError("新核心不兼容当前配置，未做任何替换：" + out[-300:])
        ok, err = _core_swap_and_restart(tmp, nv, kind)
        if not ok:
            raise ValueError(err)
        CORE_UPD.update(ok=True, message=f"{CORES[kind]} 已从 {cur or '无'} 更新到 {nv}" + ("，旧版本已备份，可一键回滚" if cur else ""))
        tg = load()
        if tg.get("tg_token") and tg.get("tg_chat"):
            notify(f"⬆️ {CORES[kind]} 内核已更新：{cur or '无'} → {nv}")
    except Exception as e:
        CORE_UPD.update(ok=False, message=str(e))
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
        CORE_UPD["pct"] = 100
        _cu("完成" if CORE_UPD["ok"] else "失败", 100, CORE_UPD["message"])
        CORE_UPD["busy"] = False


def lgbm_fetch(gh):
    """下载 LightGBM 模型到 /etc/mihomo/Model.bin（约 9 MB，Smart 组 uselightgbm 用）"""
    tmp = LGBM_FILE + ".new"
    try:
        digest = release_digest(SMART_REPO, "LightGBM-Model", "Model.bin")
        with open_url(LGBM_URL, gh if digest else "", timeout=60) as r0, open(tmp, "wb") as f:
            r = HashReader(r0)
            n = 0
            while True:
                chunk = r.read(1 << 16)
                if not chunk:
                    break
                n += len(chunk)
                if n > 64 * 2**20:
                    raise ValueError("模型文件异常过大，已中止")
                f.write(chunk)
        if n < 1 << 20:
            raise ValueError("下载的模型文件不完整")
        if digest and r.h.hexdigest() != digest:
            raise ValueError("模型文件 SHA256 与 GitHub 不一致")
        os.replace(tmp, LGBM_FILE)
        return n
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def lgbm_fetch_reload():
    try:
        lgbm_fetch(load().get("gh_proxy") or "")
        if active_core() == "smart":
            reload_core()
    except Exception as e:
        print(f"LightGBM 模型下载失败：{e}", file=sys.stderr)


def core_rollback_job(kind="mihomo"):
    try:
        B = mh_bin(kind)
        old = bin_version(B + ".bak")
        if not old:
            raise ValueError("没有可回滚的内核备份")
        cur = bin_version(B)
        ok, err = _core_swap_and_restart(B + ".bak", old, kind)
        if not ok:
            raise ValueError(err)
        CORE_UPD.update(ok=True, message=f"已回滚：{cur} → {old}（{cur} 保留为备份）")
    except Exception as e:
        CORE_UPD.update(ok=False, message=str(e))
    finally:
        CORE_UPD["pct"] = 100
        _cu("完成" if CORE_UPD["ok"] else "失败", 100, CORE_UPD["message"])
        CORE_UPD["busy"] = False


def core_job_start(fn, *args):
    if CORE_UPD["busy"] or UPD_STATE["busy"]:
        return False, "正在更新中，请稍候"
    CORE_UPD.update(busy=True, stage="开始", pct=0, ok=None, message="", t=int(time.time()))
    CORE_UPD["log"].clear()
    threading.Thread(target=fn, args=args, daemon=True).start()
    return True, "已开始"


def core_upd_status():
    return {k: (list(v) if isinstance(v, deque) else v) for k, v in CORE_UPD.items()}

