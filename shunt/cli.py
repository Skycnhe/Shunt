""""""
import ipaddress, os, re, signal, ssl, sys, threading, time

from .svcmigrate import svc_migrate
from .errlog import log_err
from . import adblock, stats
from .base import CERT, KEY, PANEL_DIR, PORT
from .data import load, update
from .mihomo import dns_cfg
from .sb_common import active_core, write_core_file
from .sb_config import write_active_config
from .sysopt import opt_fix_ulimit, rfile, sh
from .latency import monitor_loop
from .stats import Stats
from .adblock import AdStats
from .live import live_loop
from .logclean import log_loop
from .schedule import sched_loop
from .devices import rdns_loop
from .migrate import snapshot_selections, startup_migrate
from .https import Server, gen_cert, https_ready
from .update_guard import ROLLBACK_NOTE
from .webapi import H
from . import warp
def tp_env():
    """供 tproxy.sh eval：绕过列表、IPv6 开关、本机 IPv6 网段（值均经过正则过滤）"""
    d = load()
    items = [x.strip() for x in d["bypass"] if x.strip()]
    macs = [x.lower().replace("-", ":") for x in items if re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", x)]
    ips, ip6s = [], []
    for x in items:
        try:
            n = ipaddress.ip_network(x, strict=False)
            (ips if n.version == 4 else ip6s).append(str(n))
        except ValueError:
            pass
    local6 = []
    _, out = sh("ip -o -6 addr show scope global 2>/dev/null")
    for m in re.finditer(r"inet6 ([0-9a-fA-F:]+/\d+)", out):
        try:
            local6.append(str(ipaddress.ip_interface(m.group(1)).network))
        except ValueError:
            pass
    return (f"B_IP='{','.join(ips)}'\nB_MAC='{','.join(macs)}'\nB_IP6='{','.join(ip6s)}'\n"
            f"LOCAL6='{','.join(sorted(set(local6)))}'\nIPV6={1 if d.get('ipv6') else 0}\nTPROXY={1 if d.get('tproxy') else 0}\n"
            f"MODE={d['proxy_mode']}\nDNS_ALL={1 if dns_cfg(d)['block_bypass'] else 0}")


def default_tz():
    """设备没设时区（无 /etc/localtime 也无 TZ，Alpine 默认即 UTC）时按北京时间算「今天」：
    广告拦截 / 流量的今日统计在本地 0 点清零，定时任务的时刻也按北京时间。设备自己设了时区则以设备为准"""
    if os.environ.get("TZ") or os.path.exists("/etc/localtime"):
        return False
    os.environ["TZ"] = "CST-8"
    time.tzset()
    return True


def main():
    """命令行入口：带参数时执行一次性命令，否则启动面板"""
    default_tz()
    if "--bypass" in sys.argv:  # 兼容旧版 tproxy.sh
        env = dict(l.split("=", 1) for l in tp_env().splitlines())
        print(env["B_IP"].strip("'") + "|" + env["B_MAC"].strip("'"))
        sys.exit(0)
    if "--tpenv" in sys.argv:
        print(tp_env())
        sys.exit(0)
    if "--gen" in sys.argv:  # init.d/shunt-core 启动前调用：按当前内核生成配置
        try:
            opt_fix_ulimit()
        except Exception as e:
            print("文件句柄修正失败：", e, file=sys.stderr)
        dd = load()
        write_core_file(active_core(dd))
        print(write_active_config(dd))
        sys.exit(0)
    if "--allow-public" in sys.argv:  # 允许 / 禁止从外网（非局域网地址）访问面板
        on = (sys.argv[sys.argv.index("--allow-public") + 1:] or ["on"])[0] in ("on", "1", "yes", "true")
        update(lambda x: x.update(allow_public=on))
        print("已允许外网访问面板（面板没有密码，请用防火墙或反向代理自行加访问控制）" if on else "已恢复为只允许局域网访问")
        sys.exit(0)
    if "--allow-host" in sys.argv:  # 允许用这个域名访问面板（DDNS、反向代理等）；--allow-host -x 删除
        args = sys.argv[sys.argv.index("--allow-host") + 1:]
        if not args:
            print("当前允许的域名：", ", ".join(load().get("allow_hosts") or []) or "（无，IP 和 .lan/.local 等局域网域名始终允许）")
            sys.exit(0)
        h = args[0].strip().lower()

        def _ah(x):
            cur = [y for y in x.get("allow_hosts") or [] if y != h.lstrip("-")]
            x["allow_hosts"] = cur if h.startswith("-") else cur + [h]
        update(_ah)
        print(("已删除 " if h.startswith("-") else "已允许 ") + h.lstrip("-"))
        sys.exit(0)
    if "--snapshot" in sys.argv:  # install.sh 升级前调用：记下各组当前选择，新配置生效后由面板恢复
        print("saved" if snapshot_selections() is not None else "skip")
        sys.exit(0)
    if "--gen-cert" in sys.argv:
        ok, out = gen_cert()
        print(out)
        sys.exit(0 if ok else 1)
    d = load()
    try:  # v6.8.2 起没有登录会话，删掉旧版留下的会话文件
        os.remove(os.path.join(PANEL_DIR, "sessions.json"))
    except FileNotFoundError:
        pass
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))  # 让 finally 有机会保存统计
    STATS = stats.STATS = Stats()
    AD_STATS = adblock.AD_STATS = AdStats()
    for target, args in ((STATS.loop, ()), (monitor_loop, ()), (AD_STATS.loop, ()), (AD_STATS.dns_loop, ()), (live_loop, ("/traffic",)),
                         (live_loop, ("/memory",)), (log_loop, ()), (sched_loop, ()), (rdns_loop, ()), (startup_migrate, ()), (warp.loop, ())):
        threading.Thread(target=target, args=args, daemon=True).start()
    try:
        opt_fix_ulimit()
    except Exception as e:
        log_err("文件句柄修正", e)
    svc_migrate()  # v7.7.6 服务改名：旧设备在线更新后自动迁移到 shunt / shunt-core
    if os.path.isfile(ROLLBACK_NOTE):
        log_err("面板在线更新", rfile(ROLLBACK_NOTE))
        os.remove(ROLLBACK_NOTE)
    srv = Server(("0.0.0.0", PORT), H)
    scheme = "http"
    if https_ready(d):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # 禁用 TLS 1.0/1.1
        ctx.load_cert_chain(CERT, KEY)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
        scheme = "https"
    print(f"Shunt listening on {scheme}://0.0.0.0:{PORT}", flush=True)
    try:
        srv.serve_forever()
    finally:
        STATS.flush()
        AD_STATS.flush()
