"""Alpine 系统优化"""
import http.client, json, os, re, ssl, subprocess, threading, time, urllib.request, urllib.error
from collections import deque
from urllib.parse import urlsplit

from .base import MIXED, PANEL_DIR, TESTS, UA, SafeRedirectHandler, dl_check
from .data import load, update
from .mihomo import build_config
from .sb_common import active_core
from .sb_config import build_singbox
PROC_SYS = os.environ.get("PANEL_PROC_SYS", "/proc/sys")
SYS_ROOT = os.environ.get("PANEL_SYS_ROOT", "/sys")
ETC = os.environ.get("PANEL_ETC", "/etc")
OPT_SYSCTL = os.path.join(ETC, "sysctl.d", "98-shunt-optimize.conf")
OPT_LOCALD = os.path.join(ETC, "local.d", "shunt-optimize.start")
OPT_CONFD = os.path.join(ETC, "conf.d", "mihomo")
OPT_LOCK = threading.Lock()


def mem_mb():
    try:
        with open("/proc/meminfo") as f:
            return int(re.search(r"MemTotal:\s+(\d+)", f.read()).group(1)) // 1024
    except Exception:
        return 512


def rsys(key):
    try:
        with open(os.path.join(PROC_SYS, key.replace(".", "/"))) as f:
            return " ".join(f.read().split())
    except OSError:
        return None


def wsys(key, val):
    try:
        with open(os.path.join(PROC_SYS, key.replace(".", "/")), "w") as f:
            f.write(str(val))
        return ""
    except OSError as e:
        return f"{key}: {e.strerror or e}"


def rfile(path, default=""):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def wfile(path, val):
    try:
        with open(path, "w") as f:
            f.write(str(val))
        return True
    except OSError:
        return False


def net_ifaces():
    """物理网卡（有 device 链接，排除 lo / 虚拟网卡 / TUN）"""
    base = os.path.join(SYS_ROOT, "class", "net")
    try:
        return sorted(n for n in os.listdir(base) if os.path.exists(os.path.join(base, n, "device")))
    except OSError:
        return []


def cpu_govs():
    return sorted(glob_paths(os.path.join(SYS_ROOT, "devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor")))


_CT = {}


def in_container():
    """LXC / Docker 等容器：内核由宿主机共用，大部分全局参数、/sys、系统时间都无权修改"""
    if "v" not in _CT:
        v = rfile("/run/systemd/container")
        if not v and (os.path.exists("/dev/.lxc-boot-id") or " lxcfs " in rfile("/proc/self/mountinfo")
                      or re.search(r"/lxc", rfile("/proc/1/cgroup"))):
            v = "lxc"
        if not v and (os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")
                      or re.search(r"/(docker|kubepods)", rfile("/proc/1/cgroup"))):
            v = "docker"
        _CT["v"] = v
    return _CT["v"]


def path_writable(path):
    """把当前值原样写回，判断是否有权修改（容器里 /proc/sys、/sys 多数只读）"""
    try:
        with open(path) as f:
            cur = f.read().strip()
        with open(path, "w") as f:
            f.write(cur)
        return True
    except OSError:
        return False


_SYSW = {}


def sys_writable(key):
    if key not in _SYSW:
        path = os.path.join(PROC_SYS, key.replace(".", "/"))
        if not os.path.exists(path):
            return False  # 模块未加载时参数不存在，不缓存，加载后再判断
        _SYSW[key] = path_writable(path)
    return _SYSW[key]


def nofile_target():
    """mihomo 文件句柄目标值：不能超过本机（容器）的硬上限，否则 rc_ulimit 会让核心启动失败"""
    try:
        import resource
        hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    except Exception:
        hard = -1
    return 1048576 if hard < 0 or hard >= 1048576 else hard


def glob_paths(pat):
    import glob
    return glob.glob(pat)


def opt_items():
    """按内存 / CPU 计算推荐值。每项：id、名称、说明、sysctl 目标值、是否支持"""
    mem, ncpu = mem_mb(), os.cpu_count() or 1
    buf = 16 << 20 if mem >= 1024 else 8 << 20  # quic-go（Hysteria2 / TUIC）建议 UDP 缓冲 ≥7.5MB
    ct = max(32768, min(262144, mem * 256))
    bbr_ok = "bbr" in (rsys("net.ipv4.tcp_available_congestion_control") or "") or os.path.exists(
        f"/lib/modules/{os.uname().release}/kernel/net/ipv4/tcp_bbr.ko") or bool(
        glob_paths(f"/lib/modules/{os.uname().release}/kernel/net/ipv4/tcp_bbr.ko*"))
    govs = cpu_govs()
    gov_ok = bool(govs) and "performance" in rfile(os.path.join(os.path.dirname(govs[0]), "scaling_available_governors")) if govs else False
    ct_name = in_container()
    if ct_name:  # 容器里没有自己的内核：模块要在宿主机上加载
        bbr_ok = "bbr" in (rsys("net.ipv4.tcp_available_congestion_control") or "")
    gov_ok = gov_ok and path_writable(govs[0])
    nof = nofile_target()
    rpsq = [q for q in glob_paths(os.path.join(SYS_ROOT, "class/net/*/queues/rx-*/rps_cpus"))
            if q.split("/class/net/")[1].split("/")[0] in net_ifaces()]
    rps_ok = ncpu > 1 and bool(rpsq) and path_writable(rpsq[0])
    host = "宿主机" + ("（PVE / LXC）" if ct_name == "lxc" else "")
    items = [
        {"id": "bbr", "name": "BBR 拥塞控制", "rec": True, "ok": bbr_ok,
         "why": "" if bbr_ok else f"宿主机内核未加载 tcp_bbr，请在{host}上执行 modprobe tcp_bbr" if ct_name else "内核没有 tcp_bbr 模块",
         "desc": "TCP 改用 BBR + fq 队列，丢包或长距离线路下的下载速度明显更高",
         "sysctl": {"net.core.default_qdisc": "fq", "net.ipv4.tcp_congestion_control": "bbr"}},
        {"id": "buf", "name": "网络缓冲区", "rec": True, "ok": True,
         "desc": f"加大 TCP/UDP 收发缓冲到 {buf >> 20}MB（按 {mem}MB 内存计算），提升大带宽和 Hysteria2 / TUIC 等 QUIC 协议速度",
         "sysctl": {"net.core.rmem_max": buf, "net.core.wmem_max": buf, "net.core.rmem_default": 262144,
                    "net.core.wmem_default": 262144, "net.ipv4.tcp_rmem": f"4096 131072 {buf}",
                    "net.ipv4.tcp_wmem": f"4096 65536 {buf}", "net.ipv4.udp_rmem_min": 16384, "net.ipv4.udp_wmem_min": 16384,
                    "net.core.netdev_max_backlog": 16384, "net.core.somaxconn": 8192, "net.ipv4.tcp_max_syn_backlog": 8192}},
        {"id": "tcp", "name": "TCP 连接优化", "rec": True, "ok": True,
         "desc": "开启 TCP Fast Open 和 MTU 探测（避免某些线路卡在握手），空闲后不降速，扩大可用端口，快速回收 TIME_WAIT",
         "sysctl": {"net.ipv4.tcp_fastopen": 3, "net.ipv4.tcp_mtu_probing": 1, "net.ipv4.tcp_slow_start_after_idle": 0,
                    "net.ipv4.tcp_tw_reuse": 1, "net.ipv4.tcp_fin_timeout": 15, "net.ipv4.ip_local_port_range": "10000 65535",
                    "net.ipv4.tcp_keepalive_time": 600, "net.ipv4.tcp_notsent_lowat": 131072}},
        {"id": "conntrack", "name": "连接跟踪表", "rec": True, "ok": rsys("net.netfilter.nf_conntrack_max") is not None,
         "why": "nf_conntrack 未加载", "desc": f"连接数上限提高到 {ct}，已建立连接的超时从 5 天缩短到 2 小时，避免设备多时连接表被占满导致断流",
         "sysctl": {"net.netfilter.nf_conntrack_max": ct, "net.netfilter.nf_conntrack_tcp_timeout_established": 7200,
                    "net.netfilter.nf_conntrack_udp_timeout": 60, "net.netfilter.nf_conntrack_udp_timeout_stream": 180}},
        {"id": "fd", "name": "文件句柄上限", "rec": True, "ok": nof > 1024, "why": "本机文件句柄硬上限只有 1024，需在宿主机上调高",
         "desc": f"mihomo 可同时打开的连接数从 1024 提高到 {nof}，设备多或 BT 下载时不再报 too many open files（下次重启核心生效）",
         "sysctl": {"fs.file-max": 1048576, "fs.nr_open": 1048576}},
        {"id": "rps", "name": "多核网络分流 (RPS)", "rec": ncpu > 1, "ok": rps_ok,
         "why": "单核 CPU 无需开启" if ncpu <= 1 else "未找到物理网卡" if not rpsq else f"网卡参数只读，请在{host}上设置",
         "desc": f"把网卡收包分摊到全部 {ncpu} 个 CPU 核心，单队列网卡（树莓派、多数 ARM 盒子、虚拟机）满速时不再单核 100%",
         "sysctl": {"net.core.rps_sock_flow_entries": 32768}},
        {"id": "gov", "name": "CPU 性能模式", "rec": False, "ok": gov_ok,
         "why": f"CPU 调频由{host}控制" if govs and ct_name else "CPU 不支持调频或没有 performance 模式",
         "desc": "CPU 一直跑在最高频率，延迟更低更稳定；功耗和发热会增加，散热差的设备慎开", "sysctl": {}},
        {"id": "ntp", "name": "时间同步", "rec": True, "ok": not ct_name, "why": "容器和宿主机共用系统时钟，请在宿主机上校时",
         "desc": "安装并开机启动 chrony 自动校时。系统时间不准会导致 TLS 握手失败、VMess / Trojan 等节点全部不可用",
         "sysctl": {}},
    ]
    for it in items:  # 只保留有权修改的参数；容器里 net.core.*、fs.* 等全局参数由宿主机决定
        allk = it["sysctl"]
        if not allk or not it["ok"]:
            continue
        w = {k: v for k, v in allk.items() if sys_writable(k)}
        it["skipped"] = [k for k in allk if k not in w]
        it["sysctl"] = w
        if not w and it["id"] != "fd":
            it["ok"] = False
            it["why"] = f"这些内核参数在容器里只读，由{host}决定" if ct_name else "内核参数只读"
        elif it["skipped"]:
            it["part"] = f"有 {len(it['skipped'])}/{len(allk)} 个参数只读（{'由' + host + '决定' if ct_name else '内核不允许修改'}），已跳过"
    return items


def ntp_running():
    return sh("pidof chronyd || pidof ntpd")[0] == 0


def opt_status():
    d = load()
    on = set(d.get("sysopt") or [])
    out = []
    for it in opt_items():
        cur, hit = {}, 0
        for k, v in it["sysctl"].items():
            c = rsys(k)
            cur[k] = c
            if c is not None and c == " ".join(str(v).split()):
                hit += 1
        live = bool(it["sysctl"]) and hit == len(it["sysctl"])
        if it["id"] == "fd":
            live = (live or not it["sysctl"]) and f'rc_ulimit="-n {nofile_target()}"' in rfile(OPT_CONFD)
        elif it["id"] == "rps":
            live = live and it["ok"] and all(int(rfile(q, "0").replace(",", "") or "0", 16) != 0
                                            for q in glob_paths(os.path.join(SYS_ROOT, "class/net/*/queues/rx-*/rps_cpus"))
                                            if q.split("/class/net/")[1].split("/")[0] in net_ifaces())
        elif it["id"] == "gov":
            live = it["ok"] and all(rfile(g) == "performance" for g in cpu_govs())
        elif it["id"] == "ntp":
            live = ntp_running()
        show = {}
        if it["id"] == "bbr":
            show = {"当前": rsys("net.ipv4.tcp_congestion_control") or "-", "队列": rsys("net.core.default_qdisc") or "-"}
        elif it["id"] == "buf":
            show = {"当前上限": f"{int(rsys('net.core.rmem_max') or 0) >> 10} KB"}
        elif it["id"] == "conntrack":
            show = {"已用 / 上限": f"{rsys('net.netfilter.nf_conntrack_count') or '-'} / {rsys('net.netfilter.nf_conntrack_max') or '-'}"}
        elif it["id"] == "gov" and it["ok"]:
            show = {"当前": rfile(cpu_govs()[0])}
        out.append({k: it[k] for k in ("id", "name", "desc", "rec", "ok")} | {
            "why": "" if it["ok"] else it.get("why", ""), "enabled": it["id"] in on, "active": live, "show": show,
            "part": it.get("part", "") if it["ok"] else ""})
    return {"items": out, "mem": mem_mb(), "cpu": os.cpu_count() or 1, "kernel": os.uname().release, "container": in_container()}


def opt_fix_ulimit():
    """旧版写死 rc_ulimit="-n 1048576"：在硬上限更低的 LXC 容器里会让核心启动失败，按实际上限改小"""
    txt = rfile(OPT_CONFD)
    m = re.search(r'^rc_ulimit="-n (\d+)"', txt, re.M)
    if m and int(m.group(1)) > nofile_target():
        wfile(OPT_CONFD, txt.replace(m.group(0), f'rc_ulimit="-n {nofile_target()}"') + ("" if txt.endswith("\n") else "\n"))


def _opt_locald(on):
    """开机脚本：RPS 与 CPU 调频不是 sysctl，由 /etc/local.d 在每次启动时重新写入"""
    lines = ["#!/bin/sh", "# 由 Shunt 面板生成：系统优化（开机执行）"]
    if "rps" in on:
        n = os.cpu_count() or 1
        lines += [f"MASK={((1 << n) - 1):x}",
                  "for q in /sys/class/net/*/queues/rx-*; do",
                  '  i=${q#/sys/class/net/}; i=${i%%/*}; [ -e "/sys/class/net/$i/device" ] || continue',
                  '  echo $MASK > "$q/rps_cpus" 2>/dev/null; echo 4096 > "$q/rps_flow_cnt" 2>/dev/null',
                  "done"]
    if "gov" in on:
        lines += ["for g in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do echo performance > \"$g\" 2>/dev/null; done"]
    if "bbr" in on:
        lines += ["modprobe tcp_bbr 2>/dev/null; modprobe sch_fq 2>/dev/null"]
    if "conntrack" in on:
        lines += ["modprobe nf_conntrack 2>/dev/null"]
    # 开机时 sysctl 服务可能早于模块加载（conntrack / bbr 参数会写入失败），这里再应用一次
    lines += ["[ -f " + OPT_SYSCTL + " ] && sysctl -q -p " + OPT_SYSCTL + " 2>/dev/null", "exit 0"]
    return "\n".join(lines) + "\n"


def opt_apply(ids):
    """应用选中的优化项（未选中的恢复原值）；返回 (ok, 消息, 每项错误)"""
    with OPT_LOCK:
        items = {it["id"]: it for it in opt_items()}
        want = [i for i in ids if i in items and items[i]["ok"]]
        d = load()
        prev = set(d.get("sysopt") or [])
        orig = dict(d.get("sysopt_orig") or {})
        mods = list(d.get("sysopt_mods") or [])
        errs = []
        if "bbr" in want and not in_container():
            sh("modprobe tcp_bbr; modprobe sch_fq")
            mf = os.path.join(ETC, "modules")
            if "tcp_bbr" not in rfile(mf).split():
                try:
                    with open(mf, "a") as f:
                        f.write("tcp_bbr\n")
                    mods.append("tcp_bbr")
                except OSError as e:
                    errs.append(f"写入 /etc/modules 失败：{e}")
        if "conntrack" in want and not in_container():
            sh("modprobe nf_conntrack")
        # sysctl：先记住原值，再写入；取消的项恢复原值
        conf = ["# 由 Shunt 面板生成：系统优化（取消请在面板「设置 → 系统优化」中关闭）"]
        for iid, it in items.items():
            for k, v in it["sysctl"].items():
                if iid in want:
                    if k not in orig and rsys(k) is not None:
                        orig[k] = rsys(k)
                    e = wsys(k, v)
                    if e:
                        errs.append(e)
                    conf.append(f"{k} = {v}")
                elif iid in prev and k in orig:
                    wsys(k, orig[k])
        try:
            os.makedirs(os.path.dirname(OPT_SYSCTL), exist_ok=True)
            if len(conf) > 1:
                with open(OPT_SYSCTL, "w") as f:
                    f.write("\n".join(conf) + "\n")
            elif os.path.exists(OPT_SYSCTL):
                os.remove(OPT_SYSCTL)
        except OSError as e:
            errs.append(f"写入 {OPT_SYSCTL} 失败：{e}")
        # mihomo 文件句柄
        try:
            txt = rfile(OPT_CONFD)
            txt = "\n".join(l for l in txt.splitlines() if not l.startswith("rc_ulimit=")).strip()
            if "fd" in want:
                txt = (txt + "\n" if txt else "") + f'rc_ulimit="-n {nofile_target()}"'
            if txt or os.path.exists(OPT_CONFD):
                os.makedirs(os.path.dirname(OPT_CONFD), exist_ok=True)
                with open(OPT_CONFD, "w") as f:
                    f.write(txt + "\n" if txt else "")
        except OSError as e:
            errs.append(f"写入 {OPT_CONFD} 失败：{e}")
        # RPS
        mask = f"{((1 << (os.cpu_count() or 1)) - 1):x}"
        for ifc in net_ifaces():
            for q in glob_paths(os.path.join(SYS_ROOT, "class/net", ifc, "queues/rx-*")):
                key = "rps:" + q
                if "rps" in want:
                    orig.setdefault(key, rfile(os.path.join(q, "rps_cpus"), "0"))
                    if not (wfile(os.path.join(q, "rps_cpus"), mask) and wfile(os.path.join(q, "rps_flow_cnt"), 4096)):
                        errs.append(f"{ifc} RPS 写入失败")
                elif "rps" in prev and key in orig:
                    wfile(os.path.join(q, "rps_cpus"), orig[key])
                    wfile(os.path.join(q, "rps_flow_cnt"), 0)
        # CPU 调频
        for g in cpu_govs():
            key = "gov:" + g
            if "gov" in want:
                orig.setdefault(key, rfile(g))
                if not wfile(g, "performance"):
                    errs.append("CPU 调频写入失败")
            elif "gov" in prev and key in orig:
                wfile(g, orig[key])
        # 开机脚本
        try:
            if set(want) - {"ntp"}:
                os.makedirs(os.path.dirname(OPT_LOCALD), exist_ok=True)
                with open(OPT_LOCALD, "w") as f:
                    f.write(_opt_locald(set(want)))
                os.chmod(OPT_LOCALD, 0o755)
                sh("rc-update add local default")
            elif os.path.exists(OPT_LOCALD):
                os.remove(OPT_LOCALD)
        except OSError as e:
            errs.append(f"写入开机脚本失败：{e}")
        # 时间同步
        if "ntp" in want and "ntp" not in prev and not ntp_running():
            code, out = sh("apk add --no-cache chrony && rc-update add chronyd default && rc-service chronyd start", timeout=120)
            if code != 0:
                errs.append("安装 chrony 失败：" + out[-150:])
        elif "ntp" in prev and "ntp" not in want:
            sh("rc-service chronyd stop; rc-update del chronyd default")
        if not want:  # 全部关闭：清掉记录，下次重新读取原值
            mf = os.path.join(ETC, "modules")
            if mods:
                ls = [l for l in rfile(mf).splitlines() if l.strip() not in mods]
                wfile(mf, "\n".join(ls) + ("\n" if ls else ""))
            orig, mods = {}, []
        update(lambda x: x.update({"sysopt": want, "sysopt_orig": orig, "sysopt_mods": mods}))
        fd_changed = ("fd" in want) != ("fd" in prev)
        msg = f"已应用 {len(want)} 项优化" if want else "已全部恢复为系统默认值"
        if fd_changed:
            msg += "；文件句柄上限在下次重启核心后生效"
        return not errs, msg + ("" if not errs else "；部分失败：" + "；".join(errs[:4])), errs


def speed_test(proxy):
    """经代理 / 直连下载 Cloudflare 测速文件，返回 Mbps"""
    url = "https://speed.cloudflare.com/__down?bytes=50000000"
    t0 = time.time()
    n = 0
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with proxy_opener(proxy).open(req, timeout=10) as r:
            ttfb = time.time() - t0
            t1 = time.time()
            while time.time() - t1 < 10:
                b = r.read(1 << 16)
                if not b:
                    break
                n += len(b)
            dt = max(time.time() - t1, 0.001)
        return {"ok": True, "mbps": round(n * 8 / dt / 1e6, 1), "mb": round(n / 1e6, 1), "ttfb": int(ttfb * 1000)}
    except Exception as e:
        return {"ok": False, "error": str(e)[:120], "mb": round(n / 1e6, 1)}


_MASK_WORDS = ("password", "passwd", "uuid", "token", "psk", "secret", "privatekey")


def _mask_val(v):
    """敏感值掩盖中间：长值露头 3 + 尾 2，短值全打码"""
    s = str(v)
    return f"{s[:3]}******{s[-2:]}" if len(s) > 6 else "******"


def _mask_cfg(o):
    """递归掩盖配置里的敏感字段（key 含 password/uuid/token/psk/secret/privatekey 等，去掉 -_ 后匹配）"""
    if isinstance(o, dict):
        return {k: (_mask_val(v) if isinstance(v, str) and any(w in k.lower().replace("-", "").replace("_", "")
                                                              for w in _MASK_WORDS) else _mask_cfg(v))
                for k, v in o.items()}
    if isinstance(o, list):
        return [_mask_cfg(x) for x in o]
    return o


def config_view(d=None, masked=True):
    d = d or load()
    if active_core(d) == "singbox":
        cfg = build_singbox(d)[0]
    else:
        cfg = build_config(d)
    if masked:
        cfg = _mask_cfg(cfg)  # 原来只掩 secret，节点 password/uuid 等明文：名不副实，改为递归掩盖
    return json.dumps(cfg, ensure_ascii=False, indent=2)


_NFT = {"ok": None, "t": 0}


def nft_ok():
    """内核是否支持 nftables（sing-box 的 TUN auto_redirect 依赖它，不支持时 sing-box 直接退出）"""
    if _NFT["ok"] is None or (not _NFT["ok"] and time.time() - _NFT["t"] > 60):
        try:
            p = subprocess.run(["nft", "list", "tables"], capture_output=True, timeout=5)
            _NFT["ok"] = p.returncode == 0
        except Exception:
            _NFT["ok"] = False
        _NFT["t"] = time.time()
    return _NFT["ok"]


def sh(cmd, timeout=60):
    """shell=True 是有意的：大量调用方依赖 shell 特性（管道、重定向、&& 等），不要改成 shell=False。
    约定：拼进 cmd 的不可信输入（远端文件名、环境变量、用户输入）调用方必须先用 shlex.quote() 包裹。"""
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as e:
        return 1, str(e)


def proxy_opener(proxy=True):
    hs = [urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{MIXED}", "https": f"http://127.0.0.1:{MIXED}"} if proxy else {})]
    # SafeRedirectHandler 替换默认的重定向处理器：跟随 302 前校验目标为公网地址（SSRF 防护）；
    # 走代理时跳过本地 DNS 校验（由代理自己解析），字面内网 IP 仍拦截
    return urllib.request.build_opener(*hs, SafeRedirectHandler(via_proxy=proxy))


_RTT_CTX = None  # site_rtt 复用：SSL context 创建含 CA 加载，约几十 ms；context 本身线程安全


def _rtt_ctx():
    global _RTT_CTX
    if _RTT_CTX is None:
        _RTT_CTX = ssl.create_default_context()
    return _RTT_CTX


def site_rtt(url, timeout=6):
    """经 mixed 端口建立一条连接（DNS、TCP、TLS 握手不计时），在同一连接上再请求一次，只计这一次的往返。
    与核心 unified-delay 的测法一致，也和浏览器复用连接时的实际体验一致；第二次请求失败时退回第一次的总耗时"""
    u = urlsplit(url)
    https = u.scheme == "https"
    port = u.port or (443 if https else 80)
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    hdr = {"User-Agent": "curl/8", "Accept": "*/*"}
    if https:
        c = http.client.HTTPSConnection("127.0.0.1", MIXED, timeout=timeout, context=_rtt_ctx())
        c.set_tunnel(u.hostname, port)
    else:  # 普通 HTTP 走代理时请求行用完整 URL
        c = http.client.HTTPConnection("127.0.0.1", MIXED, timeout=timeout)
        path = f"http://{u.hostname}:{port}{path}"
    try:
        st = time.time()
        c.request("HEAD", path, headers=hdr)
        r = c.getresponse()
        r.read()
        first = int((time.time() - st) * 1000)
        if r.will_close:
            return first
        try:
            st = time.time()
            c.request("HEAD", path, headers=hdr)
            c.getresponse().read()
            return max(1, int((time.time() - st) * 1000))
        except Exception:
            return first
    finally:
        c.close()


SITE_HIST, SITE_LOCK, SITE_LAST = {}, threading.Lock(), {"t": 0, "r": None}
SITE_HIST_N = 30  # 每个站点保留最近 30 次（约 30 分钟）


def delay_test(force=False):
    """多个浏览器同时打开概览时 20 秒内复用同一次结果，历史只记一次。
    double-checked locking：缓存检查在锁内，整个多线程测速在锁外，写回前再检查一次"""
    if not force:
        with SITE_LOCK:
            if SITE_LAST["r"] is not None and time.time() - SITE_LAST["t"] < 20:
                return SITE_LAST["r"]
    tests = load()["tests"] or TESTS
    out = [None] * len(tests)

    def one(i, t):
        try:
            out[i] = {"name": t["name"], "url": t["url"], "ms": site_rtt(t["url"])}
        except Exception:
            out[i] = {"name": t["name"], "url": t["url"], "ms": -1}

    ths = [threading.Thread(target=one, args=(i, t)) for i, t in enumerate(tests)]
    [t.start() for t in ths]
    [t.join() for t in ths]
    with SITE_LOCK:
        if not force and SITE_LAST["r"] is not None and time.time() - SITE_LAST["t"] < 20:
            return SITE_LAST["r"]  # 测速期间已有更新鲜的结果，直接复用，丢弃本次结果
        names = {o["name"] for o in out}
        for k in list(SITE_HIST):
            if k not in names:
                del SITE_HIST[k]
        for o in out:
            h = SITE_HIST.setdefault(o["name"], deque(maxlen=SITE_HIST_N))
            h.append(o["ms"])
            o["hist"] = list(h)
        SITE_LAST.update(t=time.time(), r=out)
        return out


# 站点图标：经代理下载 https://<host>/favicon.ico，失败再试 Google favicon 服务；缓存 7 天，失败的 1 小时内不重试
FAV_DIR = os.path.join(PANEL_DIR, "favicons")
FAV_FAIL = {}
FAV_FAIL_MAX = 2000  # 失败记录上限：超限淘汰最旧的，防止无界增长


def _is_img(b):
    return b[:4] in (b"\x00\x00\x01\x00", b"\x89PNG") or b[:3] == b"GIF" or b[:2] == b"\xff\xd8" or b[:4] == b"RIFF" or b.lstrip()[:4] == b"<svg"


def favicon(url):
    host = (urlsplit(url).hostname or "").lower()
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", host):
        return None, None
    path = os.path.join(FAV_DIR, host)
    try:
        if time.time() - os.path.getmtime(path) < 7 * 86400:
            with open(path, "rb") as f:
                b = f.read()
            return b, ("image/svg+xml" if b.lstrip()[:4] == b"<svg" else "image/x-icon" if b[:4] == b"\x00\x00\x01\x00" else "image/png")
    except OSError:
        pass
    if time.time() - FAV_FAIL.get(host, 0) < 3600:
        return None, None
    op = proxy_opener()
    root = ".".join(host.split(".")[-2:])  # api.telegram.org 没有图标时用 telegram.org 的
    tries = [f"https://{host}/favicon.ico"] + ([f"https://{root}/favicon.ico", f"https://www.{root}/favicon.ico"] if root != host else [])
    for u in tries + [f"https://www.google.com/s2/favicons?domain={host}&sz=64"]:
        try:
            dl_check(u, via_proxy=True)  # SSRF 防护：走代理下载，跳过本地 DNS 校验（字面内网 IP 仍拦截）
            with op.open(urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"}), timeout=8) as r:
                b = r.read(256 * 1024)
            if len(b) > 60 and _is_img(b):
                os.makedirs(FAV_DIR, exist_ok=True)
                with open(path, "wb") as f:
                    f.write(b)
                return favicon(url)
        except Exception:
            pass
    if len(FAV_FAIL) >= FAV_FAIL_MAX:
        del FAV_FAIL[min(FAV_FAIL, key=FAV_FAIL.get)]  # 淘汰最旧的一条
    FAV_FAIL[host] = time.time()
    return None, None
