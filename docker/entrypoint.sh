#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Shunt Docker 镜像入口（由 tini 以 PID 1 拉起）。容器里没有真正的 init：
# - 用 OpenRC 的 rc-service 管 shunt（面板）和 shunt-core（核心），和 Alpine 实机共用同一份 init.d 脚本，
#   面板里的启动 / 停止 / 重启、看门狗、在线更新后重启面板等都照常走 rc-service
# - 本脚本负责：准备数据卷、清理上次异常退出留下的 nftables / 策略路由、按顺序启动、面板意外退出时拉起、
#   收到 SIGTERM（docker stop）时先撤透明代理规则（局域网立即恢复直连）再停面板和核心
# 数据全部在 /data（VOLUME）：/etc/mihomo-panel、/etc/mihomo、/etc/sing-box 是指向 /data 下同名目录的软链接
set -u
SEED=/opt/shunt-seed          # 镜像里预装的 geo 数据 / LightGBM 模型 / sing-box 规则集，数据卷里没有时复制过去
PANEL=/opt/mihomo-panel
log() { echo "[shunt] $*"; }

# ---- 数据卷
mkdir -p /data/mihomo-panel /data/mihomo/providers /data/sing-box/rules /var/log
for f in geoip.dat geosite.dat geoip.metadb Model.bin; do
  [ -s "/data/mihomo/$f" ] || { [ -f "$SEED/geo/$f" ] && cp "$SEED/geo/$f" "/data/mihomo/$f"; }
done
for f in "$SEED"/sb-rules/*; do
  [ -f "$f" ] && { [ -s "/data/sing-box/rules/${f##*/}" ] || cp "$f" /data/sing-box/rules/; }
done
NEW=""
if [ ! -f /data/mihomo-panel/data.json ]; then
  printf '{"secret":"","mode":"rule","tproxy":true,"subs":[],"rules":[]}\n' > /data/mihomo-panel/data.json
  NEW=1
fi
chmod 600 /data/mihomo-panel/data.json
if [ -n "${TZ:-}" ] && [ -f "/usr/share/zoneinfo/$TZ" ]; then cp "/usr/share/zoneinfo/$TZ" /etc/localtime; echo "$TZ" > /etc/timezone; fi

# ---- OpenRC：容器没有经过 OpenRC 开机，状态目录每次启动都重建（docker restart 会保留上次的 started / pid 记录）
rm -rf /run/openrc && mkdir -p /run/openrc/exclusive && touch /run/openrc/softlevel
rm -f /run/shunt.pid /run/shunt-core.pid /run/shunt-core.prep

# ---- 运行环境检查（network_mode: host 时规则写在宿主机的网络命名空间里）
# 探测语句与 tproxy.sh 实际下发的写法一致（inet 表里 tproxy ip 前要有 meta nfproto ipv4）
TP_OK=""; TP_ERR=$(nft -f - 2>&1 <<'NFT') && TP_OK=1
table inet shunt_probe { chain p { type filter hook prerouting priority mangle; meta nfproto ipv4 meta l4proto tcp tproxy ip to 127.0.0.1:1 } }
NFT
nft delete table inet shunt_probe 2>/dev/null
if [ -n "$TP_OK" ]; then log "TProxy 可用"
elif nft list tables >/dev/null 2>&1; then
  log "!! TProxy 不可用：宿主机内核没有加载 nft_tproxy（宿主机执行 modprobe nft_tproxy）"
  [ -n "$TP_ERR" ] && log "   nft: $(echo "$TP_ERR" | head -n 3 | tr '\n' ' ')"
else log "!! nftables 不可用：容器缺少 NET_ADMIN 权限（--cap-add NET_ADMIN）或宿主机内核不支持 nf_tables"; fi
if [ -c /dev/net/tun ]; then log "TUN 设备 /dev/net/tun 已映射"; else log "!! 没有 /dev/net/tun：TUN 模式不可用（--device /dev/net/tun）"; fi
[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = 1 ] || log "!! 宿主机未开启 IPv4 转发：请在宿主机执行 sysctl -w net.ipv4.ip_forward=1 并写入 /etc/sysctl.conf"

# 上次被 SIGKILL（docker stop 超时、宿主机断电）没来得及撤的规则：表 / 策略路由在宿主机命名空间里，留着局域网会断网
"$PANEL/tproxy.sh" stop leftovers >/dev/null 2>&1

# 镜像升级（面板版本变化）：和 install.sh 一样先记下各策略组的选择，新配置生效后面板按新组名恢复
VER=$(sed -n 's/^PANEL_VERSION = "\(.*\)"/\1/p' "$PANEL/server.py")
if [ -z "$NEW" ] && [ "$(cat /data/mihomo-panel/.image-version 2>/dev/null)" != "$VER" ]; then
  python3 "$PANEL/server.py" --snapshot >/dev/null 2>&1 || true
fi
echo "$VER" > /data/mihomo-panel/.image-version
log "面板 v$VER"

STOPPING=""
shutdown() {
  [ -n "$STOPPING" ] && return
  STOPPING=1
  log "收到停止信号：撤透明代理规则，停止面板和核心"
  nft delete table inet mihomo_panel 2>/dev/null   # 先撤规则：局域网立即直连，不等核心退出（sing-box 最多 15 秒）
  rc-service shunt stop >/dev/null 2>&1
  rc-service shunt-core stop >/dev/null 2>&1        # init.d 的 stop_pre / stop_post 会再撤一次规则并清 TUN 残留
  kill_core
  "$PANEL/tproxy.sh" stop leftovers >/dev/null 2>&1
  [ -n "${TAIL_PID:-}" ] && kill "$TAIL_PID" 2>/dev/null
  log "已停止"
  exit 0
}
# rc-service 停不掉的核心（如面板正在重启核心时收到信号）：TERM 后最多等 15 秒，再 KILL
kill_core() {
  pidof mihomo mihomo-smart sing-box >/dev/null 2>&1 || return 0
  kill $(pidof mihomo mihomo-smart sing-box) 2>/dev/null
  i=0; while [ $i -lt 75 ] && pidof mihomo mihomo-smart sing-box >/dev/null 2>&1; do sleep 0.2; i=$((i+1)); done
  pidof mihomo mihomo-smart sing-box >/dev/null 2>&1 && kill -9 $(pidof mihomo mihomo-smart sing-box) 2>/dev/null
  return 0
}
trap shutdown TERM INT QUIT HUP

# ---- 启动：核心（用户在面板里手动停止过就不启动，与实机开机一致）→ 面板
if [ -f /data/mihomo-panel/core_stopped ]; then
  log "核心已在面板里手动停止，本次不自动启动"
else
  rc-service shunt-core start || log "!! 核心启动失败，详情见面板「日志」或 /var/log/mihomo.log"
fi
rc-service shunt start || log "!! 面板启动失败，详情见 /var/log/mihomo-panel.log"
touch /var/log/mihomo-panel.log
tail -n 20 -F /var/log/mihomo-panel.log 2>/dev/null &  # 面板日志同时输出到 docker logs
TAIL_PID=$!
PORT=8080; grep -q '"https": *true' /data/mihomo-panel/data.json && [ -f /data/mihomo-panel/cert.pem ] && S=https || S=http
log "面板地址: $S://<本机IP>:$PORT"

# ---- 守护：面板进程意外退出时拉起。在线更新、切 HTTPS、恢复备份时面板会自己 rc-service shunt restart，
# 连续两次（20 秒）检查都不在才算退出，不和它抢
miss=0
while :; do
  sleep 10 &
  wait $! 2>/dev/null
  [ -n "$STOPPING" ] && break
  pid=$(cat /run/shunt.pid 2>/dev/null)
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then miss=0; continue; fi
  miss=$((miss+1))
  [ $miss -lt 2 ] && continue
  log "面板未运行，重新启动"
  rc-service shunt zap >/dev/null 2>&1
  rc-service shunt start >/dev/null 2>&1
  miss=0
done
