"""内核切换"""
import hashlib, io, json, os, re, shutil, shlex, threading, time

from .base import CONF_DIR, CORE_UPD, MIHOMO_LOG, SMART_BIN, TPROXY_SH
from .data import load, update
from .groups import PROV, gcfg
from .mihomo import check_config, dns_cfg, mh_bin, write_config
from .sb_common import CORES, SB_API, SB_BIN, SB_CONF, SB_REPO, SB_STATE, active_core, write_core_file
from .sb_subs import sb_update_subs
from .sb_config import check_sb_config, sb_sync_assets, sb_version, write_sb_config
from .core_update import LGBM_FILE, MANUAL_NOTE, _cu, bin_version, copy_replace, lgbm_fetch, mh_fetch, open_url, release_digest
from .sysopt import sh, svc_restart
from .notify import WD, core_alive, notify, set_manual_stop
from .migrate import restore_selections, snapshot_selections
def sb_arch():
    m = os.uname().machine
    return {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64", "armv7l": "armv7", "armv8l": "armv7", "armv6l": "armv6",
            "i686": "386", "i386": "386", "riscv64": "riscv64", "loongarch64": "loong64", "s390x": "s390x"}.get(m, "")


def sb_remote_version(channel, gh):
    """最新正式版 / 预发布版的版本号（不带 v）"""
    try:
        with open_url(SB_API + ("/latest" if channel == "stable" else "?per_page=10"), "", timeout=15) as r:
            j = json.loads(r.read(400000))
        if channel != "stable":
            j = next((x for x in j if x.get("prerelease")), j[0])
        v = str(j.get("tag_name") or "").lstrip("v")
        if v:
            return v
    except Exception:
        if channel != "stable":
            raise
    with open_url(SB_REPO + "/latest", gh, timeout=15) as r:  # API 受限时从跳转地址里取版本号
        m = re.search(r"/tag/v?([\w.\-]+)", r.geturl())
    if not m:
        raise IOError("获取 sing-box 版本号失败")
    return m.group(1)


def is_musl():
    import glob
    return bool(glob.glob("/lib/ld-musl-*")) or os.path.isfile("/etc/alpine-release")


def sb_fetch(url, gh, digest=""):
    if not digest:
        gh = ""  # 没有校验值时不走第三方镜像
    with open_url(url, gh, timeout=60) as r:
        total = int(r.headers.get("Content-Length") or 0)
        buf, n = io.BytesIO(), 0
        while True:
            chunk = r.read(1 << 16)
            if not chunk:
                break
            n += len(chunk)
            if n > 120 * 2**20:
                raise ValueError("下载文件异常过大，已中止")
            buf.write(chunk)
            if total:
                CORE_UPD["pct"] = 10 + int(50 * n / total)
    if total and n < total:
        raise ValueError(f"下载不完整 {n}/{total}")
    if digest and hashlib.sha256(buf.getbuffer()).hexdigest() != digest:
        raise ValueError("SHA256 与 GitHub 不一致（可能被加速镜像篡改）")
    buf.seek(0)
    return buf


def sb_install(channel, gh, force=False):
    """下载 sing-box 到 SB_BIN（旧版本备份为 .bak）；返回版本号"""
    import tarfile
    arch = sb_arch()
    if not arch:
        raise ValueError(f"sing-box 不支持当前 CPU 架构：{os.uname().machine}")
    ver = sb_remote_version(channel, gh)
    cur = sb_version()
    if cur == ver and not force:
        return ver, False
    # 1.14 起普通 linux 包依赖 glibc，Alpine(musl) 上跑不起来，优先下 -musl 版
    variants = ["-musl", "", "-glibc"] if is_musl() else ["", "-glibc", "-musl"]
    tmp, errs, nv = SB_BIN + ".new", [], ""
    for v in variants:
        name = f"sing-box-{ver}-linux-{arch}{v}.tar.gz"
        _cu("下载", 10, f"下载 {name}")
        try:
            buf = sb_fetch(f"{SB_REPO}/download/v{ver}/{name}", gh, release_digest(SB_REPO, "v" + ver, name))
            with tarfile.open(fileobj=buf, mode="r:gz") as tf:
                mem = next((m for m in tf.getmembers() if m.isfile() and os.path.basename(m.name) == "sing-box"), None)
                if not mem:
                    raise ValueError("压缩包里没有 sing-box 程序")
                with tf.extractfile(mem) as src, open(tmp, "wb") as f:
                    shutil.copyfileobj(src, f)
        except Exception as e:
            errs.append(f"{name}: {str(e)[:100]}")
            continue
        os.chmod(tmp, 0o755)
        nv = sb_version(tmp)
        if nv:
            break
        _, out = sh(f"{shlex.quote(tmp)} version", timeout=15)
        errs.append(f"{name}: 无法运行 {out.strip()[:100]}")
        os.remove(tmp)
    if not nv:
        raise ValueError("下载的 sing-box 无法运行（架构不匹配或文件损坏）：" + "；".join(errs))
    if os.path.isfile(SB_BIN):
        shutil.copy2(SB_BIN, SB_BIN + ".bak")
    os.replace(tmp, SB_BIN)
    return nv, True


_UNSET = object()


def core_switch_job(kind, gh):
    """切换内核：准备程序与数据 → 生成并校验配置 → 写入启动选择 → 重启；失败自动换回原内核"""
    prev = active_core()
    dns_auto_fix = False  # 切到 sing-box 时是否自动开启了「阻止客户端绕过 DNS」
    bb_prev = _UNSET
    try:
        label = CORES[kind]
        if kind == "singbox":
            if not sb_version():
                _cu("安装 sing-box", 5, "设备上还没有 sing-box，正在下载最新正式版")
                nv, _ = sb_install("stable", gh)
                _cu("安装 sing-box", 62, f"已安装 sing-box {nv}")
            d = load()
            bb_prev = (d.get("dns") or {}).get("block_bypass", _UNSET)  # 回滚时恢复原值（原来没有这一项就删掉）
            if not dns_cfg(d)["block_bypass"]:
                # sing-box 1.13+ 移除了 sniff_override_destination，设备 DNS 绕过面板时拿到污染 IP 必死；
                # mihomo 的 sniffer 默认改写目标地址所以不受影响。切到 sing-box 时自动开启防绕过。
                d.setdefault("dns", {})["block_bypass"] = True
                dns_auto_fix = True
            if d["subs"]:
                _cu("下载订阅", 65, "sing-box 不能自己拉取订阅，由面板下载并解析节点")
                ok, bad = sb_update_subs(d=d)
                for x in ok + bad:
                    _cu("下载订阅", None, x)
                if not ok:
                    raise ValueError("订阅全部下载失败，未切换：" + "；".join(bad)[:300])
            _cu("规则集", 75, "下载 sing-box 格式的 GEO / 规则集文件")
            bad = sb_sync_assets(d)
            for x in bad[:5]:
                _cu("规则集", None, "✗ " + x)
            crit = [x for x in bad if x.split("：", 1)[0] in ("geosite-cn", "geoip-cn", "geosite-private")]
            if crit:  # 缺了国内 / 私有地址规则集，相关规则会被裁掉，国内流量全部走「漏网之鱼」代理，宁可不切
                raise ValueError("国内分流规则集下载失败，未切换（可在 设置 里填 GitHub 加速地址后重试）：" + "；".join(crit)[:300])
            tmp = write_sb_config(d, SB_CONF + ".new")
            ok, err = check_sb_config(tmp)
            if not ok:
                os.remove(tmp)
                raise ValueError("sing-box 配置校验失败，未切换：" + err)
            os.replace(tmp, SB_CONF)
        else:
            if kind == "smart" and not bin_version(SMART_BIN):
                _cu("安装 Smart 内核", 5, "设备上还没有 mihomo Smart，正在从 vernesong/mihomo 下载")
                tmp = mh_fetch("smart", "alpha", gh, lambda pc: CORE_UPD.update(pct=5 + int(55 * pc)))[0]
                os.replace(tmp, SMART_BIN)
                _cu("安装 Smart 内核", 62, f"已安装 {bin_version(SMART_BIN)}")
            if not bin_version(mh_bin(kind)):
                raise ValueError(f"设备上没有可用的 {label} 程序，请先在「内核更新」里安装")
            d = dict(load(), core=kind)  # 按目标内核生成（Smart：竞技组改为 smart 类型）
            if kind == "smart" and gcfg(d)["lgbm"] and not os.path.isfile(LGBM_FILE):
                _cu("LightGBM 模型", 64, "下载 LightGBM 模型 Model.bin")
                try:
                    lgbm_fetch(gh)
                except Exception as e:
                    _cu("LightGBM 模型", None, "✗ 模型下载失败，Smart 组先用内置算法：" + str(e)[:120])
            tmp = write_config(d, os.path.join(CONF_DIR, "config.yaml.new"))
            ok, err = check_config(tmp, kind)
            if not ok:
                os.remove(tmp)
                raise ValueError(f"{label} 配置校验失败，未切换：" + err)
            os.replace(tmp, os.path.join(CONF_DIR, "config.yaml"))
        snapshot_selections(force=True)

        def _apply_switch(x):
            x["core"] = kind
            if dns_auto_fix:
                x.setdefault("dns", {})["block_bypass"] = True

        update(_apply_switch)
        write_core_file(kind)
        PROV.update(t=0, data=None)
        _cu("重启核心", 88, f"正在以 {label} 重启核心（局域网会断网几秒）")
        set_manual_stop(False)
        svc_restart(timeout=90)
        for _ in range(30):
            time.sleep(1)
            if core_alive():
                break
        else:
            tail = [l for l in sh(f"tail -n 30 '{MIHOMO_LOG}'")[1].splitlines() if re.search(r"FATAL|ERROR|level=(?:error|fatal)", l)]
            def _undo(x):
                x["core"] = prev
                if dns_auto_fix:  # 切换时自动打开的「阻止客户端绕过 DNS」一并关回去
                    if bb_prev is _UNSET:
                        (x.get("dns") or {}).pop("block_bypass", None)
                    else:
                        x.setdefault("dns", {})["block_bypass"] = bb_prev

            update(_undo)
            write_core_file(prev)
            svc_restart(timeout=90)
            log = re.sub(r"\x1b\[[0-9;]*m", "", "\n".join(tail[-3:]))[-400:]
            raise ValueError(f"{label} 30 秒内未响应，已切回 {CORES[prev]}。" + ("日志：" + log if log else "请查看核心日志"))
        threading.Thread(target=restore_selections, daemon=True).start()
        if dns_auto_fix and d.get("proxy_mode") != "off":
            sh(TPROXY_SH + " apply", timeout=15)  # block_bypass 变化：重载 nftables 劫持任意目标的 53 端口
        msg = f"已切换到 {label}"
        if kind == "singbox" and SB_STATE["warn"]:
            msg += f"（{len(SB_STATE['warn'])} 条兼容提示见设置 → 核心）"
        if dns_auto_fix:
            msg += "；已自动开启「阻止客户端绕过 DNS」（sing-box 要求设备 DNS 经过面板，如不需要可在 设置→DNS 关闭）"
        CORE_UPD.update(ok=True, message=msg)
        notify(f"🔀 内核已切换：{CORES[prev]} → {label}")
    except Exception as e:
        CORE_UPD.update(ok=False, message=str(e))
    finally:
        CORE_UPD["pct"] = 100
        _cu("完成" if CORE_UPD["ok"] else "失败", 100, CORE_UPD["message"])
        CORE_UPD["busy"] = False


def sb_update_job(channel, gh, force=False):
    try:
        cur = sb_version()
        _cu("获取版本", 3, "正在获取 sing-box 最新版本号")
        nv, changed = sb_install(channel, gh, force)
        if not changed:
            CORE_UPD.update(ok=True, message=f"已是最新版本 {nv}，无需更新")
            return
        _cu("校验", 70, f"用 sing-box {nv} 检查当前配置")
        if active_core() == "singbox":
            ok, err = check_sb_config(SB_CONF)
            if not ok:
                copy_replace(SB_BIN + ".bak", SB_BIN)
                raise ValueError("新版 sing-box 不兼容当前配置，已恢复原版本：" + err)
        note = ""
        if active_core() == "singbox" and WD["manual_stop"]:  # 手动停止了核心：只替换程序，不替用户拉起来
            note = f"（{MANUAL_NOTE}）"
        elif active_core() == "singbox":
            _cu("重启核心", 85, "正在重启核心")
            svc_restart(timeout=90)
            for _ in range(30):
                time.sleep(1)
                if core_alive():
                    break
            else:
                copy_replace(SB_BIN + ".bak", SB_BIN)
                svc_restart(timeout=90)
                raise ValueError("新版 sing-box 30 秒内未响应，已恢复原版本")
        CORE_UPD.update(ok=True, message=f"sing-box 已从 {cur or '未安装'} 更新到 {nv}" + ("，旧版本已备份" if cur else "") + note)
    except Exception as e:
        CORE_UPD.update(ok=False, message=str(e))
    finally:
        CORE_UPD["pct"] = 100
        _cu("完成" if CORE_UPD["ok"] else "失败", 100, CORE_UPD["message"])
        CORE_UPD["busy"] = False


