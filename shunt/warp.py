"""Cloudflare WARP 透明代理（面板「WARP」页）

WARP 与 mihomo / sing-box 核心二选一接管局域网流量：
- 启动 WARP：先停止核心（记为手动停止，看门狗不会拉起），再用已安装的 mihomo（没有则用 sing-box）程序
  单独起一个 WARP 实例：WireGuard 出站 + 7893 TProxy 入站 + 1053 DNS，tproxy.sh start 挂上同一套透明代理规则
- 停止 WARP：结束 WARP 实例并撤掉透明代理规则，局域网直连
- 启动 / 重启核心（面板按钮、切换 / 更新内核等）：rc_run 前先让 WARP 退出（PRE_START 钩子），两者不会同时抢 7893 / 1053
WARP 实例不是 OpenRC 服务，由面板直接管理：pid 文件 /run/shunt-warp.pid，面板启动后按上次状态恢复，掉线自动重启。

优选 IP：用当前 WARP 账户的密钥向候选 Endpoint 发 WireGuard 握手包（wgcrypto），收到握手应答即可用，
往返时间即延迟；网速用临时 WARP 实例（只开本地 mixed 端口）经该 Endpoint 下载 Cloudflare 测速文件。"""
import base64, ipaddress, json, os, random, re, shlex, signal, socket, subprocess, threading, time, urllib.request
from collections import deque

from . import wgcrypto as wg
from .base import CONF_DIR, MIHOMO_BIN, SMART_BIN, TPROXY_SH, UA, WARP_DIR, wd_hold
from .data import load, read_json, write_json
from .errlog import log_err
from .sb_common import SB_BIN, SB_RULE_DIR
from .sysopt import PRE_START, SVC_OP, core_procs, kill_core_procs, proxy_opener, rc_run, sh
from .notify import core_proc_alive, set_manual_stop

WARP_CONF = os.path.join(WARP_DIR, "wgcf.conf")  # 标准 WireGuard 配置（wgcf / warp-go 导出的可直接粘贴）
WARP_ACC = os.path.join(WARP_DIR, "account.json")  # 注册得到的账户 id / token（升级 WARP+ 用）
WARP_STATE = os.path.join(WARP_DIR, "state.json")
WARP_PID = os.environ.get("PANEL_WARP_PID", "/run/shunt-warp.pid")
WARP_LOG = os.environ.get("PANEL_WARP_LOG", "/var/log/shunt-warp.log")
WARP_MIXED = 40000  # WARP 实例的本地 HTTP / SOCKS5 端口（仅 127.0.0.1），用于出口检测
SPEED_PORT = 40001  # 测速用临时实例
REG_API = "https://api.cloudflareclient.com/v0a2158/reg"
REG_HDR = {"User-Agent": "okhttp/3.12.1", "CF-Client-Version": "a-6.10-2158", "Content-Type": "application/json"}
CF_PEER = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
DEFAULT_RANGES = ["162.159.192.0/24", "162.159.193.0/24", "162.159.195.0/24", "188.114.96.0/24", "188.114.97.0/24",
                  "188.114.98.0/24", "188.114.99.0/24"]
COMMON_PORTS = [2408, 500, 1701, 4500, 878, 894, 7559, 8854]
ALL_PORTS = [500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968, 987, 988,
             1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177,
             4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886]
STATE_DEFAULT = {"on": False, "cn_direct": True, "scan": [], "scan_t": 0}

WARP = {"busy": False, "act": "", "ok": None, "message": "", "t": 0, "fails": 0, "events": deque(maxlen=30), "started": 0}
SCAN = {"busy": False, "stage": "", "done": 0, "total": 0, "message": "", "t": 0}
_JOB = threading.Lock()  # 启动 / 停止 / 重启 WARP 同一时间只允许一个
_SPEED = threading.Lock()


def _state():
    st = dict(STATE_DEFAULT)
    st.update(read_json(WARP_STATE, {}) or {})
    return st


def _save_state(**kw):
    st = _state()
    st.update(kw)
    write_json(WARP_STATE, st)
    return st


def event(msg):
    WARP["events"].appendleft({"t": int(time.time()), "msg": msg})
    print(time.strftime("%F %T"), "[warp]", msg, flush=True)


# ---------------- 配置文件 ----------------
def parse_conf(text):
    """解析 WireGuard 配置；返回 dict，格式错误抛 ValueError（中文提示）"""
    sec, iface, peer = None, {}, {}
    for raw in str(text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.fullmatch(r"\[(\w+)\]", line)
        if m:
            sec = m.group(1).lower()
            continue
        if "=" not in line or sec not in ("interface", "peer"):
            continue
        k, v = (x.strip() for x in line.split("=", 1))
        (iface if sec == "interface" else peer)[k.lower()] = v
    if not iface.get("privatekey"):
        raise ValueError("缺少 [Interface] PrivateKey")
    priv = wg.unb64(iface["privatekey"])
    pub = wg.unb64(peer.get("publickey") or CF_PEER)
    v4, v6 = "", ""
    for a in re.split(r"[,\s]+", iface.get("address", "")):
        if not a:
            continue
        try:
            ip = ipaddress.ip_interface(a if "/" in a else a + ("/128" if ":" in a else "/32")).ip
        except ValueError:
            raise ValueError(f"Address 格式不对：{a}")
        if ip.version == 4 and not v4:
            v4 = str(ip)
        elif ip.version == 6 and not v6:
            v6 = str(ip)
    if not v4 and not v6:
        raise ValueError("缺少 [Interface] Address")
    ep = peer.get("endpoint") or "engage.cloudflareclient.com:2408"
    m = re.fullmatch(r"\[?([0-9A-Za-z.:\-]+?)\]?:(\d{1,5})", ep)
    if not m or not 0 < int(m.group(2)) < 65536:
        raise ValueError(f"Endpoint 格式不对：{ep}（应为 IP:端口）")
    reserved = [0, 0, 0]
    rv = peer.get("reserved", "")
    if rv:
        try:
            nums = [int(x) for x in re.split(r"[,\s\[\]]+", rv) if x]
            if len(nums) != 3:
                raise ValueError
        except ValueError:
            try:
                nums = list(base64.b64decode(rv))
            except Exception:
                nums = []
        if len(nums) != 3 or any(not 0 <= n < 256 for n in nums):
            raise ValueError("Reserved 应为 3 个 0~255 的数字，例如 12,34,56")
        reserved = nums
    try:
        mtu = int(iface.get("mtu") or 1280)
    except ValueError:
        raise ValueError("MTU 应为数字")
    return {"priv": priv, "pub": pub, "v4": v4, "v6": v6, "host": m.group(1), "port": int(m.group(2)),
            "reserved": reserved, "mtu": max(1000, min(mtu, 1500))}


def read_conf():
    try:
        with open(WARP_CONF) as f:
            return f.read()
    except OSError:
        return ""


def write_conf(text):
    os.makedirs(WARP_DIR, exist_ok=True)
    tmp = WARP_CONF + ".tmp"
    with open(tmp, "w") as f:
        f.write(text.strip() + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, WARP_CONF)


def conf_text(priv, v4, v6, reserved, endpoint="engage.cloudflareclient.com:2408", pub=CF_PEER, mtu=1280):
    addr = ", ".join([f"{v4}/32"] + ([f"{v6}/128"] if v6 else []))
    return (f"[Interface]\nPrivateKey = {priv}\nAddress = {addr}\nDNS = 1.1.1.1\nMTU = {mtu}\n\n"
            f"[Peer]\nPublicKey = {pub}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {endpoint}\n"
            f"Reserved = {','.join(str(x) for x in reserved)}\n")


def set_endpoint(text, ep):
    """把配置里的 Endpoint 换成 ep（没有这一行就加到 [Peer] 末尾）"""
    if re.search(r"(?im)^\s*Endpoint\s*=", text):
        return re.sub(r"(?im)^(\s*Endpoint\s*=\s*).*$", lambda m: m.group(1) + ep, text, count=1)
    if re.search(r"(?im)^\s*\[Peer\]", text):
        return re.sub(r"(?im)^(\s*\[Peer\][^\n]*)$", lambda m: m.group(1) + "\nEndpoint = " + ep, text, count=1)
    return text.rstrip() + f"\n\n[Peer]\nPublicKey = {CF_PEER}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {ep}\n"


def fmt_ep(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _open(req, timeout=20):
    """先直连 Cloudflare API；失败且核心在跑时经核心的 7890 代理再试一次（国内常连不上）"""
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except Exception as e:
        if not core_proc_alive():
            raise
        try:
            return proxy_opener(True).open(req, timeout=timeout)
        except Exception:
            raise e


def register():
    """注册一个新的免费 WARP 账户，写入配置文件；返回 (成功?, 提示)"""
    priv, pub = wg.keypair()
    body = {"key": wg.b64(pub), "install_id": "", "fcm_token": "", "model": "PC", "serial_number": "", "locale": "zh_CN",
            "tos": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())}
    req = urllib.request.Request(REG_API, data=json.dumps(body).encode(), headers=REG_HDR, method="POST")
    try:
        with _open(req) as r:
            j = json.loads(r.read().decode())
        c = j["config"]
        a = c["interface"]["addresses"]
        reserved = list(base64.b64decode(c.get("client_id") or "AAAA"))[:3]
        old = parse_conf(read_conf()) if read_conf() else None
        ep = fmt_ep(old["host"], old["port"]) if old else "engage.cloudflareclient.com:2408"  # 已经优选过的 Endpoint 保留
        write_conf(conf_text(wg.b64(priv), a["v4"], a.get("v6", ""), reserved, ep, c["peers"][0].get("public_key") or CF_PEER))
        write_json(WARP_ACC, {"id": j["id"], "token": j["token"], "license": j.get("account", {}).get("license", ""),
                              "type": j.get("account", {}).get("account_type", "free"), "t": int(time.time())})
    except Exception as e:
        log_err("warp register", e)
        return False, f"注册失败：{str(e)[:160]}（Cloudflare 接口可能连不上，可先启动核心再注册，或粘贴现成的 wgcf 配置）"
    return True, "已注册新的 WARP 账户并写入配置" + ("，重启 WARP 后生效" if warp_running() else "")


def set_license(key):
    """把账户升级为 WARP+（填入 WARP+ 许可证，形如 xxxxxxxx-xxxxxxxx-xxxxxxxx）"""
    key = str(key or "").strip()
    if not re.fullmatch(r"[0-9A-Za-z]{8}-[0-9A-Za-z]{8}-[0-9A-Za-z]{8}", key):
        return False, "许可证格式应为 xxxxxxxx-xxxxxxxx-xxxxxxxx"
    acc = read_json(WARP_ACC, {})
    if not acc.get("id"):
        return False, "只有在面板里注册的账户可以填许可证，请先点「注册新账户」"
    hdr = dict(REG_HDR, Authorization="Bearer " + acc["token"])
    req = urllib.request.Request(f"{REG_API}/{acc['id']}/account", data=json.dumps({"license": key}).encode(), headers=hdr, method="PUT")
    try:
        with _open(req) as r:
            j = json.loads(r.read().decode())
    except Exception as e:
        return False, f"提交失败：{str(e)[:160]}"
    acc.update(license=key, type=j.get("account_type") or j.get("warp_plus") and "plus" or acc.get("type", ""))
    write_json(WARP_ACC, acc)
    return True, "许可证已提交" + ("，账户已是 WARP+" if j.get("warp_plus") else "（Cloudflare 未确认 WARP+，许可证可能已用满 5 台设备）")


# ---------------- 运行实例 ----------------
def engine():
    """WARP 实例用哪个程序：优先 mihomo（含 Smart），没有就用 sing-box"""
    for kind, b in (("mihomo", MIHOMO_BIN), ("mihomo", SMART_BIN), ("singbox", SB_BIN)):
        if b and os.path.isfile(b) and os.access(b, os.X_OK):
            return kind, b
    return "", ""


def _geo_mihomo():
    """国内直连需要 geosite / geoip 数据；直接用主核心已下载好的文件（软链接），没有就不加国内直连规则"""
    files = [f for f in ("geosite.dat", "geoip.dat") if os.path.isfile(os.path.join(CONF_DIR, f))]
    if len(files) < 2:
        return False
    for f in files:
        dst = os.path.join(WARP_DIR, f)
        try:
            if os.path.realpath(dst) != os.path.realpath(os.path.join(CONF_DIR, f)):
                if os.path.lexists(dst):
                    os.remove(dst)
                os.symlink(os.path.join(CONF_DIR, f), dst)
        except OSError:
            return False
    return True


def build_mihomo(c, d, cn, tproxy=True, mixed=WARP_MIXED):
    v6 = bool(d.get("ipv6"))
    px = {"name": "WARP", "type": "wireguard", "server": c["host"], "port": c["port"], "ip": c["v4"] or "172.16.0.2",
          "private-key": wg.b64(c["priv"]), "public-key": wg.b64(c["pub"]), "allowed-ips": ["0.0.0.0/0", "::/0"],
          "reserved": c["reserved"], "mtu": c["mtu"], "udp": True}
    if c["v6"]:
        px["ipv6"] = c["v6"]
    cfg = {"mixed-port": mixed, "allow-lan": False, "bind-address": "127.0.0.1", "mode": "rule", "log-level": "warning",
           "ipv6": v6, "unified-delay": True, "proxies": [px], "rules": []}
    if not tproxy:  # 测速实例：只有本地 mixed 端口
        cfg["rules"] = ["MATCH,WARP"]
        return cfg
    cfg.update({"tproxy-port": 7893, "allow-lan": True, "bind-address": "*",
                "profile": {"store-selected": False, "store-fake-ip": False}})
    dns = {"enable": True, "listen": "0.0.0.0:1053", "ipv6": v6, "enhanced-mode": "redir-host",
           "default-nameserver": ["223.5.5.5", "119.29.29.29"], "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
           "nameserver": ["https://1.1.1.1/dns-query#WARP", "https://8.8.8.8/dns-query#WARP"]}
    rules = ["IP-CIDR,10.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
             "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve", "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve"]
    if cn:
        cfg.update({"geodata-mode": True, "geo-auto-update": False})
        dns["nameserver-policy"] = {"geosite:cn,private": ["223.5.5.5", "119.29.29.29"]}
        rules += ["GEOSITE,private,DIRECT", "GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT"]
    cfg["dns"] = dns
    cfg["rules"] = rules + ["MATCH,WARP"]
    return cfg


def build_singbox(c, d, cn, tproxy=True, mixed=WARP_MIXED):
    v6 = bool(d.get("ipv6"))
    addr = ([c["v4"] + "/32"] if c["v4"] else []) + ([c["v6"] + "/128"] if c["v6"] else [])
    ep = {"type": "wireguard", "tag": "WARP", "address": addr, "private_key": wg.b64(c["priv"]), "mtu": c["mtu"],
          "peers": [{"address": c["host"], "port": c["port"], "public_key": wg.b64(c["pub"]),
                     "allowed_ips": ["0.0.0.0/0", "::/0"], "reserved": c["reserved"]}]}
    cfg = {"log": {"level": "warn", "timestamp": True}, "endpoints": [ep],
           "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": mixed}],
           "outbounds": [{"type": "direct", "tag": "DIRECT"}],
           "dns": {"servers": [{"type": "udp", "tag": "local", "server": "223.5.5.5"}], "strategy": "prefer_ipv4" if v6 else "ipv4_only"},
           "route": {"rules": [], "final": "WARP", "default_domain_resolver": "local"}}
    if not tproxy:
        return cfg
    lis = "::" if v6 else "0.0.0.0"
    cfg["inbounds"] += [{"type": "tproxy", "tag": "tproxy-in", "listen": lis, "listen_port": 7893},
                        {"type": "direct", "tag": "dns-in", "listen": lis, "listen_port": 1053}]
    cfg["dns"]["servers"].insert(0, {"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "WARP"})
    cfg["dns"]["final"] = "remote"
    rules = [{"action": "sniff"}, {"inbound": "dns-in", "action": "hijack-dns"}, {"protocol": "dns", "action": "hijack-dns"},
             {"ip_is_private": True, "action": "route", "outbound": "DIRECT"}]
    if cn:
        sets = [{"type": "local", "tag": t, "format": "binary", "path": os.path.join(SB_RULE_DIR, t + ".srs")}
                for t in ("geosite-cn", "geoip-cn")]
        cfg["route"]["rule_set"] = sets
        cfg["dns"]["rules"] = [{"rule_set": ["geosite-cn"], "action": "route", "server": "local"}]
        rules += [{"rule_set": ["geosite-cn", "geoip-cn"], "action": "route", "outbound": "DIRECT"}]
    cfg["route"]["rules"] = rules
    return cfg


def _cn_ok(kind):
    if kind == "singbox":
        return all(os.path.isfile(os.path.join(SB_RULE_DIR, t + ".srs")) for t in ("geosite-cn", "geoip-cn"))
    return _geo_mihomo()


def write_run(c=None, tproxy=True, mixed=WARP_MIXED, name="run"):
    """生成 WARP 实例配置并校验；返回 (程序类型, 程序路径, 配置路径)，失败抛 ValueError"""
    kind, b = engine()
    if not kind:
        raise ValueError("没有找到 mihomo 或 sing-box 程序，请先在 设置 → 核心 安装内核")
    c = c or parse_conf(read_conf())
    os.makedirs(WARP_DIR, exist_ok=True)
    st, d = _state(), load()
    cn = bool(st.get("cn_direct")) and tproxy and _cn_ok(kind)
    if kind == "singbox":
        cfg, path = build_singbox(c, d, cn, tproxy, mixed), os.path.join(WARP_DIR, name + ".json")
    else:
        cfg, path = build_mihomo(c, d, cn, tproxy, mixed), os.path.join(WARP_DIR, name + ".yaml")
    write_json(path, cfg)  # JSON 也是合法的 YAML
    if kind == "singbox":
        code, out = sh(f"{shlex.quote(b)} check -c {shlex.quote(path)} -D {shlex.quote(WARP_DIR)}", timeout=60)
    else:
        code, out = sh(f"{shlex.quote(b)} -t -d {shlex.quote(WARP_DIR)} -f {shlex.quote(path)}", timeout=60)
    if code != 0:
        lines = [x for x in out.splitlines() if re.search(r"error|fatal|FATAL|ERROR|failed", x)]
        raise ValueError("WARP 配置校验失败：" + ("\n".join(lines[-3:]) or out[-300:]))
    return kind, b, path


def _cmd(kind, b, path):
    if kind == "singbox":
        return [b, "run", "--disable-color", "-c", path, "-D", WARP_DIR]
    return [b, "-d", WARP_DIR, "-f", path]


def _alive(pid):
    try:
        os.kill(pid, 0)
        with open(f"/proc/{pid}/stat") as f:
            if f.read().rsplit(")", 1)[-1].split()[0] == "Z":
                return False
        with open(f"/proc/{pid}/cmdline", "rb") as f:  # pid 被别的进程复用了不算
            return WARP_DIR.encode() in f.read()
    except (OSError, IndexError):
        return False


def warp_pid():
    try:
        with open(WARP_PID) as f:
            pid = int(f.read().strip() or 0)
    except (OSError, ValueError):
        return 0
    return pid if pid > 0 and _alive(pid) else 0


def warp_running():
    return bool(warp_pid())


def _port_open(port, host="127.0.0.1", timeout=1):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _spawn(kind, b, path, log=WARP_LOG, pidfile=WARP_PID):
    try:
        lf = open(log, "w")
    except OSError:
        lf = subprocess.DEVNULL
    pr = subprocess.Popen(_cmd(kind, b, path), stdin=subprocess.DEVNULL, stdout=lf, stderr=subprocess.STDOUT,
                          start_new_session=True, close_fds=True)
    if lf is not subprocess.DEVNULL:
        lf.close()
    threading.Thread(target=pr.wait, daemon=True).start()  # 回收僵尸
    if pidfile:
        with open(pidfile, "w") as f:
            f.write(str(pr.pid))
    return pr


def _kill(pid, grace=8):
    if not pid:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return
    end = time.time() + grace
    while time.time() < end and _alive(pid):
        time.sleep(0.2)
    if _alive(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def log_tail(n=40):
    try:
        with open(WARP_LOG, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 16384))
            return f.read().decode("utf-8", "ignore").splitlines()[-n:]
    except OSError:
        return []


def core_running():
    """mihomo / sing-box 核心是否在跑（pid 文件或扫描到的核心进程；WARP 实例不算）"""
    return core_proc_alive() or bool(core_procs())


def _stop_core():
    """启动 WARP 前停止核心：记为手动停止，看门狗 / 定时重启都不会再把它拉起来"""
    if not core_running():
        set_manual_stop(True)
        return ""
    set_manual_stop(True)
    wd_hold(150, "启动 WARP，停止核心")
    try:
        rc_run("stop", timeout=90)
        for _ in range(40):
            if not core_proc_alive():
                break
            time.sleep(0.2)
        kill_core_procs()
    finally:
        wd_hold(0, "启动 WARP", reset=True)
    if core_running():
        raise RuntimeError("核心停不下来，未启动 WARP（请先在顶栏停止核心）")
    return "已停止核心，"


def _start_proc():
    """（已持有 SVC_OP）生成配置、拉起 WARP 实例并挂上透明代理规则"""
    kind, b, path = write_run()
    _kill(warp_pid())
    for _ in range(25):  # 核心刚退出时端口可能还没释放
        if not _port_open(7893):
            break
        time.sleep(0.2)
    pr = _spawn(kind, b, path)
    for i in range(50):
        time.sleep(0.2)
        if pr.poll() is not None:
            tail = [x for x in log_tail(10) if x.strip()]
            raise RuntimeError("WARP 实例启动后立即退出：" + (tail[-1][-200:] if tail else f"退出码 {pr.returncode}"))
        if _port_open(WARP_MIXED) and (i >= 3 or _port_open(7893)):
            break
    code, out = sh(TPROXY_SH + " start")
    if code != 0:
        raise RuntimeError("透明代理规则加载失败：" + out[-200:])
    WARP["started"] = time.time()
    return kind


def warp_start():
    with SVC_OP:
        if not read_conf():
            return False, "还没有 WARP 配置：先点「注册新账户」，或粘贴 wgcf 配置后保存"
        try:
            pre = _stop_core()
            kind = _start_proc()
        except (ValueError, RuntimeError) as e:
            return False, str(e)
        _save_state(on=True)
        WARP["fails"] = 0
    msg = pre + f"WARP 已启动（{ 'sing-box' if kind == 'singbox' else 'mihomo' } 实例），局域网流量经 WARP 透明代理"
    event(msg)
    return True, msg


def warp_stop(direct=True, why="手动停止"):
    """结束 WARP 实例；direct=True 时撤掉透明代理规则（局域网直连）"""
    with SVC_OP:
        _kill(warp_pid())
        try:
            os.remove(WARP_PID)
        except OSError:
            pass
        if direct:
            sh(TPROXY_SH + " stop")
        _save_state(on=False)
    msg = "WARP 已停止" + ("，局域网直连" if direct else "") + (f"（{why}）" if why != "手动停止" else "")
    event(msg)
    return True, msg


def warp_restart():
    with SVC_OP:
        if not read_conf():
            return False, "还没有 WARP 配置"
        try:
            _stop_core()
            kind = _start_proc()
        except (ValueError, RuntimeError) as e:
            return False, str(e)
        _save_state(on=True)
        WARP["fails"] = 0
    event("WARP 已重启")
    return True, f"WARP 已重启（{'sing-box' if kind == 'singbox' else 'mihomo'} 实例）"


def _yield_to_core(act):
    """PRE_START 钩子：核心要启动 / 重启时 WARP 让出 7893 / 1053（规则由核心的 start_post 重新挂上）"""
    if act in ("start", "restart") and warp_running():
        _kill(warp_pid())
        try:
            os.remove(WARP_PID)
        except OSError:
            pass
        _save_state(on=False)
        event("核心启动，WARP 已自动停止")


PRE_START.append(_yield_to_core)


def job(act):
    """后台执行启停，前端轮询 WARP 状态拿结果"""
    if not _JOB.acquire(blocking=False):
        return False
    WARP.update(busy=True, act=act, ok=None, message="", t=time.time())

    def run():
        try:
            ok, msg = {"start": warp_start, "stop": warp_stop, "restart": warp_restart}[act]()
        except Exception as e:
            log_err("warp " + act, e)
            ok, msg = False, f"操作失败：{e}"
        WARP.update(busy=False, ok=ok, message=msg, t=time.time())
        _JOB.release()
    threading.Thread(target=run, daemon=True).start()
    return True


def trace(timeout=10):
    """经 WARP 实例访问 Cloudflare trace，返回出口 IP / 地区 / 是否 WARP"""
    if not warp_running():
        return {"ok": False, "error": "WARP 未运行"}
    op = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{WARP_MIXED}",
                                                                  "https": f"http://127.0.0.1:{WARP_MIXED}"}))
    t0 = time.time()
    try:
        with op.open(urllib.request.Request("https://www.cloudflare.com/cdn-cgi/trace", headers={"User-Agent": UA}), timeout=timeout) as r:
            txt = r.read(4096).decode("utf-8", "ignore")
    except Exception as e:
        return {"ok": False, "error": str(e)[:160]}
    kv = dict(x.split("=", 1) for x in txt.splitlines() if "=" in x)
    return {"ok": True, "ip": kv.get("ip", ""), "loc": kv.get("loc", ""), "colo": kv.get("colo", ""), "warp": kv.get("warp", ""),
            "ms": int((time.time() - t0) * 1000)}


def status():
    st, kind_b = _state(), engine()
    try:
        c = parse_conf(read_conf()) if read_conf() else None
        err = ""
    except ValueError as e:
        c, err = None, str(e)
    acc = read_json(WARP_ACC, {})
    pid = warp_pid()
    return {"running": bool(pid), "pid": pid, "on": st["on"], "uptime": int(time.time() - WARP["started"]) if pid and WARP["started"] else 0,
            "engine": {"mihomo": "mihomo", "singbox": "sing-box"}.get(kind_b[0], ""), "core_running": core_running(),
            "conf": read_conf(), "conf_err": err, "endpoint": fmt_ep(c["host"], c["port"]) if c else "",
            "address": ", ".join(x for x in ((c or {}).get("v4"), (c or {}).get("v6")) if x),
            "account": {"type": acc.get("type", ""), "has": bool(acc.get("id")), "license": bool(acc.get("license"))},
            "cn_direct": st["cn_direct"], "cn_ok": _cn_ok(kind_b[0]) if kind_b[0] else False,
            "job": {k: WARP[k] for k in ("busy", "act", "ok", "message", "t")}, "events": list(WARP["events"])[:15],
            "log": log_tail(30), "scan": st.get("scan") or [], "scan_t": st.get("scan_t", 0), "scan_job": dict(SCAN),
            "ranges": DEFAULT_RANGES, "common_ports": COMMON_PORTS, "all_ports": ALL_PORTS}


def tick():
    """看门狗：应该运行却退出了就重启，连续 3 次失败撤掉透明代理规则（局域网直连），之后每 5 分钟再试"""
    if not _state()["on"] or WARP["busy"] or warp_running():
        if warp_running():
            WARP["fails"] = 0
        return
    if core_proc_alive():  # 核心已经被别的途径（SSH 等）启动：让给核心
        _save_state(on=False)
        event("检测到核心在运行，WARP 不再自动恢复")
        return
    WARP["fails"] += 1
    if WARP["fails"] <= 3 or WARP["fails"] % 10 == 0:
        try:
            with SVC_OP:
                _start_proc()
            event(f"WARP 实例已退出，已自动重启（第 {WARP['fails']} 次）")
        except Exception as e:
            event(f"WARP 自动重启失败：{str(e)[:160]}")
            if WARP["fails"] == 3:
                sh(TPROXY_SH + " stop")
                event("WARP 连续 3 次启动失败，已撤掉透明代理规则，局域网暂时直连")


def loop():
    """面板启动：上次 WARP 在运行（开机、面板重启 / 更新）就恢复，然后每 30 秒检查一次"""
    time.sleep(15)  # 等开机时 OpenRC 把核心拉起来，再按上次状态停掉核心、恢复 WARP
    if _state()["on"] and not warp_running():
        ok, msg = warp_start()
        event(("已恢复上次的 WARP：" if ok else "恢复 WARP 失败：") + msg)
    elif warp_running():
        WARP["started"] = WARP["started"] or time.time()
    while True:
        time.sleep(30)
        try:
            tick()
        except Exception as e:
            log_err("warp tick", e)


# ---------------- 优选 IP ----------------
def _targets(ranges, ports, per):
    ips = []
    for r in ranges:
        try:
            net = ipaddress.ip_network(r.strip(), strict=False)
        except ValueError:
            continue
        n = net.num_addresses
        if n <= 2:
            pick = list(net)
        else:
            k = min(per, n - 2 if net.version == 4 else per)
            seen = set()
            while len(seen) < k:
                off = random.randrange(1, n - 1) if n > 2 else 0
                seen.add(off)
            pick = [net.network_address + o for o in sorted(seen)]
        ips += [str(x) for x in pick]
    return [(ip, p) for ip in ips for p in ports]


def _probe_round(ini, targets, timeout=1.2, gap=0.004):
    """一个 UDP 套接字按顺序发出全部握手包（时间戳单调递增，不会被对端当重放丢掉），另一个线程收应答。
    返回 {(ip, port): 往返毫秒}"""
    res = {}
    socks = {}
    pend = {}
    lock = threading.Lock()
    stop = [False]

    def recv(s):
        while not stop[0]:
            try:
                data, _ = s.recvfrom(256)
            except socket.timeout:
                continue
            except OSError:
                return
            key = data[8:12] if data[:1] == b"\x02" else data[4:8]
            with lock:
                hit = pend.pop(key, None)
            if hit and wg.is_reply(data, key):
                res[hit[0]] = max(1, int((time.time() - hit[1]) * 1000))
    for fam in {socket.AF_INET6 if ":" in t[0] else socket.AF_INET for t in targets}:
        try:
            s = socket.socket(fam, socket.SOCK_DGRAM)
            s.settimeout(0.3)
            socks[fam] = s
            threading.Thread(target=recv, args=(s,), daemon=True).start()
        except OSError:
            pass
    for i, t in enumerate(targets):
        s = socks.get(socket.AF_INET6 if ":" in t[0] else socket.AF_INET)
        if not s:
            continue
        pkt, idx = ini.packet()
        with lock:
            pend[idx] = (t, time.time())
        try:
            s.sendto(pkt, (t[0], t[1]))
        except OSError:
            with lock:
                pend.pop(idx, None)
        SCAN["done"] += 1
        time.sleep(gap)
    time.sleep(timeout)
    stop[0] = True
    for s in socks.values():
        s.close()
    return res


def scan(ranges=None, ports=None, per=20, rounds=3):
    """后台任务：抽样候选 IP × 端口，每个目标发 rounds 次握手，按丢包率、平均延迟排序，保留前 50 个"""
    if SCAN["busy"]:
        return False, "正在测试中"
    try:
        c = parse_conf(read_conf())
    except ValueError as e:
        return False, "需要先有可用的 WARP 配置（握手要用账户密钥）：" + str(e)
    ranges = [r for r in (ranges or DEFAULT_RANGES) if r.strip()][:40]
    ports = sorted({int(p) for p in (ports or COMMON_PORTS) if 0 < int(p) < 65536})[:60]
    per = max(1, min(int(per or 20), 256))
    targets = _targets(ranges, ports, per)[:4000]
    if not targets:
        return False, "没有有效的 IP 段 / 端口"
    rounds = max(1, min(int(rounds or 3), 5))
    SCAN.update(busy=True, stage="握手测试", done=0, total=len(targets) * rounds, message="", t=time.time())

    def run():
        try:
            ini = wg.Initiator(c["priv"], c["pub"])  # 握手不带 Reserved：Cloudflare 对带 Reserved 的握手包不回应
            got = {}
            for r in range(rounds):
                SCAN["stage"] = f"握手测试 第 {r + 1}/{rounds} 轮"
                for k, ms in _probe_round(ini, targets).items():
                    got.setdefault(k, []).append(ms)
            rows = [{"ip": k[0], "port": k[1], "ms": int(sum(v) / len(v)), "loss": round(100 * (rounds - len(v)) / rounds),
                     "mbps": None} for k, v in got.items()]
            rows.sort(key=lambda x: (x["loss"], x["ms"]))
            rows = rows[:50]
            _save_state(scan=rows, scan_t=int(time.time()))
            SCAN["message"] = f"测试了 {len(targets)} 个 IP:端口，{len(got)} 个可用" + ("" if got else "（全部无响应：检查配置是否有效，或本地网络屏蔽了 UDP）")
        except Exception as e:
            log_err("warp scan", e)
            SCAN["message"] = f"测试出错：{e}"
        finally:
            SCAN.update(busy=False, stage="")
    threading.Thread(target=run, daemon=True).start()
    return True, f"开始测试 {len(targets)} 个 IP:端口 × {rounds} 轮"


def speed(ep_host, port, sec=8):
    """临时起一个只开本地端口的 WARP 实例，经指定 Endpoint 下载 Cloudflare 测速文件；返回 Mbps"""
    if not _SPEED.acquire(blocking=False):
        return {"ok": False, "error": "另一个测速正在进行"}
    pr = None
    try:
        c = parse_conf(read_conf())
        c.update(host=ep_host, port=int(port))
        kind, b, path = write_run(c, tproxy=False, mixed=SPEED_PORT, name="speed")
        pr = _spawn(kind, b, path, log=os.path.join(WARP_DIR, "speed.log"), pidfile=None)
        for _ in range(30):
            time.sleep(0.2)
            if _port_open(SPEED_PORT):
                break
        op = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{SPEED_PORT}",
                                                                      "https": f"http://127.0.0.1:{SPEED_PORT}"}))
        t0, n = time.time(), 0
        req = urllib.request.Request("https://speed.cloudflare.com/__down?bytes=50000000", headers={"User-Agent": UA})
        with op.open(req, timeout=10) as r:
            ttfb = time.time() - t0
            t1 = time.time()
            while time.time() - t1 < sec:
                blk = r.read(1 << 16)
                if not blk:
                    break
                n += len(blk)
            dt = max(time.time() - t1, 0.001)
        mbps = round(n * 8 / dt / 1e6, 1)
        st = _state()
        for row in st.get("scan") or []:
            if row["ip"] == ep_host and int(row["port"]) == int(port):
                row["mbps"] = mbps
        _save_state(scan=st.get("scan") or [])
        return {"ok": True, "mbps": mbps, "mb": round(n / 1e6, 1), "ttfb": int(ttfb * 1000)}
    except Exception as e:
        return {"ok": False, "error": str(e)[:160]}
    finally:
        if pr is not None:
            try:
                pr.terminate()
                pr.wait(5)
            except Exception:
                try:
                    pr.kill()
                except Exception:
                    pass
        _SPEED.release()


def use_endpoint(host, port):
    """把优选出的 IP:端口写进配置；WARP 在运行就重启生效"""
    try:
        ipaddress.ip_address(host)
        port = int(port)
        assert 0 < port < 65536
    except (ValueError, AssertionError, TypeError):
        return False, "IP 或端口不合法"
    text = read_conf()
    if not text:
        return False, "还没有 WARP 配置"
    new = set_endpoint(text, fmt_ep(host, port))
    try:
        parse_conf(new)
    except ValueError as e:
        return False, str(e)
    write_conf(new)
    if warp_running():
        ok, msg = warp_restart()
        return ok, f"已改用 {fmt_ep(host, port)}，" + msg
    return True, f"已改用 {fmt_ep(host, port)}，启动 WARP 后生效"
