# ---------------------------------------------------------------- sing-box 内核
# 面板数据（订阅、节点、规则、DNS、设备）两个内核共用；切换内核时按各自格式生成独立的配置文件：
#   mihomo   → /etc/mihomo/config.yaml
#   sing-box → /etc/sing-box/config.json
# sing-box 没有负载均衡 / 故障转移组：自定义的这两类组降级为 urltest（自动测速），地区「⚖️ 负载均衡」组与
# 「自动优选」完全相同，不再重复生成，引用它的地方自动改指向同地区的「自动优选」。
SB_BIN = os.environ.get("SB_BIN", "/usr/local/bin/sing-box")
SB_DIR = os.environ.get("SB_DIR", "/etc/sing-box")
SB_CONF = os.path.join(SB_DIR, "config.json")
SB_RULE_DIR = os.environ.get("SB_RULES", os.path.join(SB_DIR, "rules"))
SB_SUB_DIR = os.path.join(PANEL_DIR, "sb_subs")
CORE_FILE = os.path.join(PANEL_DIR, "core")  # init.d/mihomo 读取它决定启动哪个内核
CORE_PID = os.environ.get("PANEL_CORE_PID", "/run/mihomo.pid")
CORES = {"mihomo": "mihomo", "smart": "mihomo Smart", "singbox": "sing-box"}
SB_GEO = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo"
SB_REPO = os.environ.get("SB_REPO", "https://github.com/SagerNet/sing-box/releases")
SB_API = os.environ.get("SB_API", "https://api.github.com/repos/SagerNet/sing-box/releases")
SB_UA = ("clash.meta", "v2rayN/6.45")
SB_STATE = {"warn": [], "subs": {}}


def active_core(d=None):
    c = (d or load()).get("core") or "mihomo"
    return c if c in CORES else "mihomo"


def core_conf_path(kind=None):
    return SB_CONF if (kind or active_core()) == "singbox" else os.path.join(CONF_DIR, "config.yaml")


def write_core_file(kind):
    try:
        wfile(CORE_FILE, kind + "\n")
    except Exception:
        pass


