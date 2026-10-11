"""网络诊断"""
import json, os, secrets, shutil, socket, threading, time, urllib.request, urllib.error

from .errlog import ERRS
from .base import CONF_DIR, TPROXY_SH
from .data import load
from .mihomo import check_config, mh_bin, safe_dev
from .core import core
from .sb_common import CORES, SB_BIN, SB_CONF, SB_STATE, active_core
from .sb_config import check_sb_config
from .sysopt import proxy_opener, sh
def dns_probe(server=("127.0.0.1", 1053), name="www.baidu.com"):
    """向 mihomo DNS 端口发一个最小的 A 查询"""
    qid = secrets.randbits(16)
    pkt = qid.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    pkt += b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4)
    try:
        st = time.time()
        s.sendto(pkt, server)
        data = s.recv(1500)
        rcode, an = data[3] & 0x0F, int.from_bytes(data[6:8], "big")
        return rcode == 0 and an > 0, int((time.time() - st) * 1000), rcode
    finally:
        s.close()


def diagnose():
    d = load()
    mode = d["proxy_mode"]
    out = []

    def item(name, ok, detail, fix=""):
        out.append({"name": name, "ok": ok, "detail": detail, "fix": fix if ok is not True else ""})

    recent = [e for e in ERRS if time.time() - e["t"] < 86400]
    if recent:
        item(f"面板内部错误（24 小时内 {len(recent)} 条）", "warn",
             "；".join(f"{time.strftime('%m-%d %H:%M', time.localtime(e['t']))} {e['where']}：{e['msg']}" for e in recent[:5])[:600],
             "完整记录在 /var/log/mihomo-panel.log，反馈问题时请附上")

    code, ver = core("GET", "/version", timeout=5)
    alive = code == 200
    sb = active_core(d) == "singbox"
    item(f"{CORES[active_core(d)]} 核心", alive, json.loads(ver).get("version", "") if alive else "核心未运行或控制器无响应",
         "在顶部点「启动」，或执行 rc-service mihomo restart 并查看 /var/log/mihomo.log")
    if sb:
        if os.path.isfile(SB_BIN) and os.path.isfile(SB_CONF):
            ok, err = check_sb_config(SB_CONF)
            item("配置校验 (sing-box check)", ok, "通过" if ok else err[-200:], "在设置中撤销最近的修改，或切回 mihomo")
        if SB_STATE["warn"]:
            item("sing-box 兼容提示", "warn", "；".join(SB_STATE["warn"])[:300], "详见 设置 → 核心 → 内核切换")
    cfg = os.path.join(CONF_DIR, "config.yaml")
    if not sb and os.path.isfile(mh_bin(active_core(d))) and os.path.isfile(cfg):
        ok, err = check_config(cfg)
        item("配置校验 (mihomo -t)", ok, "通过" if ok else err[-200:], "在设置中撤销最近的修改，或恢复备份")
    try:
        fwd = open("/proc/sys/net/ipv4/ip_forward").read().strip() == "1"
    except OSError:
        fwd = False
    item("IPv4 转发", fwd if mode != "off" else ("warn" if not fwd else True), "已开启" if fwd else "未开启",
         "sysctl -w net.ipv4.ip_forward=1，并写入 /etc/sysctl.conf")
    _, st = sh(TPROXY_SH + " status", timeout=10)
    st = st.strip().splitlines()[-1] if st.strip() else "off"
    if mode == "tproxy":
        item("TProxy 规则", st == "tproxy", "nftables 规则已加载" if st == "tproxy" else "未检测到 nftables TProxy 规则",
             "在设置里重新选择「TProxy」，或执行 /opt/mihomo-panel/tproxy.sh start；需要 nftables 与 nft_tproxy 模块")
    elif mode == "tun":
        dev = safe_dev((d.get("tun") or {}).get("device"))
        has_tun = os.path.exists("/dev/net/tun")
        item("TUN 模块", has_tun, "/dev/net/tun 存在" if has_tun else "缺少 /dev/net/tun",
             "modprobe tun，并把 tun 加入 /etc/modules（install.sh 会自动处理）")
        up = os.path.isdir("/sys/class/net/" + dev)
        item(f"TUN 网卡 {dev}", up, "已创建" if up else "未找到该网卡",
             "确认核心以 root 运行且日志里没有 TUN 报错；切换协议栈为 gvisor 再试")
        item("DNS 重定向 (53 → 1053)", st == "dns" or "warn", "已加载" if st == "dns" else "未加载，局域网设备需把 DNS 指向本机 1053 或开启后重试",
             "执行 /opt/mihomo-panel/tproxy.sh dns")
    else:
        item("代理方式", "warn", "已关闭透明代理，仅 7890 端口（HTTP/SOCKS）可用", "在设置里选择 TProxy 或 TUN")
    if alive:
        try:
            ok, ms, rc = dns_probe()
            item("DNS 服务 (127.0.0.1:1053)", ok, f"解析 www.baidu.com 用时 {ms} ms" if ok else f"返回码 {rc}",
                 "检查 设置 → DNS 中的直连 DNS 是否可达")
        except Exception as e:
            item("DNS 服务 (127.0.0.1:1053)", False, str(e)[:120], "确认核心 DNS 已监听 1053 端口")
        for host, label in (("www.baidu.com", "国内域名解析"), ("www.google.com", "国外域名解析")):
            c2, raw = core("GET", f"/dns/query?name={host}&type=A", timeout=10)
            try:
                j = json.loads(raw)
                ans = [a["data"] for a in j.get("Answer") or [] if a.get("type") == 1]
                ok = c2 == 200 and j.get("Status") == 0 and bool(ans)
                item(label, ok, ", ".join(ans[:2]) if ok else f"失败（Status {j.get('Status')}）",
                     "检查直连 / 代理 DNS 设置" + ("；代理 DNS 依赖节点可用" if "google" in host else ""))
            except Exception:
                item(label, False, "查询失败", "检查 DNS 设置")

    def reach(url, use_proxy):
        st = time.time()
        try:
            req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "curl/8"})
            try:
                proxy_opener(use_proxy).open(req, timeout=8).close()
            except urllib.error.HTTPError:
                pass
            return True, int((time.time() - st) * 1000)
        except Exception as e:
            return False, str(e)[:100]
    res = {}
    ths = [threading.Thread(target=lambda k=k, a=a: res.__setitem__(k, reach(*a))) for k, a in
           (("direct", ("https://www.baidu.com", False)), ("cn", ("https://www.baidu.com", True)),
            ("proxy", ("https://www.gstatic.com/generate_204", True)))]
    [t.start() for t in ths]
    [t.join(12) for t in ths]
    for k, label, fix in (("direct", "本机直连外网", "检查旁路由的网关 / DNS 设置（应指向主路由）"),
                          ("cn", "经代理访问国内", "核心或 7890 端口异常，查看日志"),
                          ("proxy", "经代理访问国外", "当前节点不可用：去「节点」测速并切换，或更新订阅")):
        ok, v = res.get(k, (False, "超时"))
        item(label, ok, f"{v} ms" if ok else v, fix)
    try:
        du = shutil.disk_usage(CONF_DIR)
        free = du.free / 2**20
        item("磁盘空间", True if free > 100 else "warn" if free > 20 else False, f"剩余 {free:.0f} MB",
             "清理日志（设置 → 日志清理）或扩容")
    except OSError:
        pass
    return out
