#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# mihomo 旁路由透明代理规则 (nftables)。
# 用法: tproxy.sh start|dns|stop|apply|status
#   start  TProxy 模式：TCP/UDP 打标记转发到 mihomo 的 7893，DNS 劫持到 1053
#   dns    TUN 模式：只保留 “发往本机 53 端口的 DNS 重定向到 1053”（流量本身由 mihomo TUN 的 auto-route 接管）
#   stop   删除本脚本创建的全部规则
#   apply  按面板里的“代理方式”(TProxy / TUN / 关闭) 自动选择上面三者之一
#          环境变量 TPENV_FILE：直接读这个文件里的参数（面板 / --gen 预先写好），不再起 Python 跑 --tpenv
#          环境变量 WAIT_PID：核心 pid 文件。先等核心监听好端口再挂规则，核心已退出则不挂（init.d 的 start_post 用）
#   leftovers  （或 stop leftovers）没有核心进程时清掉核心被 KILL 后残留的 TUN 策略路由与 auto-redirect 表（init.d 的 stop_post 用）
TPROXY_PORT=7893
DNS_PORT=1053
MARK=0x162
TABLE_ID=162
TABLE=mihomo_panel        # 不用 "mihomo"：mihomo 自身 TUN auto-redirect 也会创建 inet mihomo 表
DATA=/etc/mihomo-panel/data.json
SELF="$(cd "$(dirname "$0")" && pwd)"
SERVER="$SELF/server.py"
[ -f "$SERVER" ] || SERVER=/opt/mihomo-panel/server.py
ENV_LOADED=""  # 不继承外部环境变量

load_env() {
  [ -n "$ENV_LOADED" ] && return 0  # apply 已加载过：start / dns_only 不再启动第二次 Python（每次都要加载整个面板）
  ENV_LOADED=1
  B_IP=""; B_MAC=""; B_IP6=""; LOCAL6=""; IPV6=0; MODE=""; DNS_ALL=0
  if [ -n "$TPENV_FILE" ] && [ -r "$TPENV_FILE" ]; then
    ENV=$(cat "$TPENV_FILE") && eval "$ENV"  # 面板进程 / --gen 刚写好的（同一份 tp_env 输出）：省一次 Python 启动
  else
    ENV=$(python3 "$SERVER" --tpenv 2>/dev/null) && eval "$ENV"
  fi
  if [ -z "$MODE" ]; then  # 面板脚本不可用时直接读 data.json
    if grep -q '"proxy_mode": *"tun"' "$DATA" 2>/dev/null; then MODE=tun
    elif grep -q '"proxy_mode": *"off"' "$DATA" 2>/dev/null; then MODE=off
    elif grep -q '"tproxy": *false' "$DATA" 2>/dev/null; then MODE=off
    else MODE=tproxy; fi
  fi
  IP_SET=""; MAC_SET=""; IP6_SET=""; LOCAL6_SET=""
  [ -n "$B_IP" ] && IP_SET="elements = { $B_IP }"
  [ -n "$B_MAC" ] && MAC_SET="elements = { $B_MAC }"
  [ -n "$B_IP6" ] && IP6_SET="elements = { $B_IP6 }"
  [ -n "$LOCAL6" ] && LOCAL6_SET="elements = { $LOCAL6 }"
}

drop_legacy() {
  # 旧版本使用 inet mihomo 表；只有确认是本脚本创建的（含 bypass_mac 集合）才删除，避免误删 mihomo auto-redirect 的表
  nft list set inet mihomo bypass_mac >/dev/null 2>&1 && nft delete table inet mihomo 2>/dev/null
  return 0
}

clear_route() {
  # ip rule del 一次只删一条：以前 start 中途失败又重试时可能留下多条相同的策略路由，循环删干净（最多 20 次防死循环）
  n=0; while [ $n -lt 20 ] && ip rule del fwmark $MARK table $TABLE_ID 2>/dev/null; do n=$((n+1)); done
  ip route flush table $TABLE_ID 2>/dev/null
  n=0; while [ $n -lt 20 ] && ip -6 rule del fwmark $MARK table $TABLE_ID 2>/dev/null; do n=$((n+1)); done
  ip -6 route flush table $TABLE_ID 2>/dev/null
  return 0
}

sets() {
  cat <<NFT
  set reserved {
    type ipv4_addr; flags interval
    elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16,
                 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }
  }
  set reserved6 {
    type ipv6_addr; flags interval
    elements = { ::/128, ::1/128, ::ffff:0:0/96, 64:ff9b::/96, 100::/64, 2001:db8::/32,
                 fe80::/10, fc00::/7, ff00::/8 }
  }
  set bypass {
    type ipv4_addr; flags interval
    $IP_SET
  }
  set bypass6 {
    type ipv6_addr; flags interval
    $IP6_SET
  }
  set local6 {
    type ipv6_addr; flags interval
    $LOCAL6_SET
  }
  set bypass_mac {
    type ether_addr
    $MAC_SET
  }
NFT
}

dns_chain() {
  # DNS_ALL=1（面板“阻止客户端绕过 DNS”）：客户端发往任意服务器的 53 端口查询（如手动设置 114.114.114.114）也交给 mihomo
  DST="fib daddr type local "; [ "$DNS_ALL" = 1 ] && DST=""
  cat <<NFT
  chain dns {
    type nat hook prerouting priority dstnat; policy accept;
    ip saddr @bypass return
    ip6 saddr @bypass6 return
    ether saddr @bypass_mac return
    $DNS_FAMILY ${DST}udp dport 53 redirect to :$DNS_PORT
    $DNS_FAMILY ${DST}tcp dport 53 redirect to :$DNS_PORT
  }
NFT
}

start() {
  load_env
  sysctl -qw net.ipv4.ip_forward=1
  modprobe nft_tproxy 2>/dev/null; modprobe nf_tproxy_ipv4 2>/dev/null
  drop_legacy; clear_route
  ip rule add fwmark $MARK table $TABLE_ID
  ip route replace local 0.0.0.0/0 dev lo table $TABLE_ID

  V6_RULES=""; DNS_FAMILY="meta nfproto ipv4"
  DNS_SKIP=""; [ "$DNS_ALL" = 1 ] && DNS_SKIP="meta l4proto { tcp, udp } th dport 53 return"  # 交给 dns 链重定向，不走 TProxy
  if [ "$IPV6" = 1 ]; then
    sysctl -qw net.ipv6.conf.all.forwarding=1
    modprobe nf_tproxy_ipv6 2>/dev/null
    ip -6 rule add fwmark $MARK table $TABLE_ID
    ip -6 route replace local ::/0 dev lo table $TABLE_ID
    DNS_FAMILY=""
    # Fake-IP 的 IPv6 段（sing-box fc00::/18、mihomo fdfe:dcba:9876::/64）都落在 reserved6 的 fc00::/7 里：
    # 以前先被 return 掉、不进核心，客户端拿到 AAAA 假地址的连接全部不通（只能等回退 IPv4）。先把这两段交给核心
    V6_RULES="meta nfproto ipv6 ip6 saddr @bypass6 return
    meta nfproto ipv6 ip6 daddr { fc00::/18, fdfe:dcba:9876::/64 } meta l4proto { tcp, udp } meta mark set $MARK tproxy ip6 to [::1]:$TPROXY_PORT accept
    meta nfproto ipv6 ip6 daddr @reserved6 return
    meta nfproto ipv6 ip6 daddr @local6 return
    meta nfproto ipv6 meta l4proto { tcp, udp } meta mark set $MARK tproxy ip6 to [::1]:$TPROXY_PORT accept"
  fi

  nft -f - <<NFT
table inet $TABLE
delete table inet $TABLE
table inet $TABLE {
$(sets)
$(dns_chain)
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    fib daddr type local return
    $DNS_SKIP
    meta nfproto ipv4 ip saddr @bypass return
    ether saddr @bypass_mac return
    meta nfproto ipv4 ip daddr @reserved return
    meta nfproto ipv4 meta l4proto { tcp, udp } meta mark set $MARK tproxy ip to 127.0.0.1:$TPROXY_PORT accept
    $V6_RULES
  }
}
NFT
  RC=$?
  [ $RC = 0 ] || { echo "nftables 规则加载失败"; return $RC; }
  [ "$IPV6" = 1 ] && echo "TProxy 已开启（IPv4 + IPv6）" || echo "TProxy 已开启"
}

dns_only() {
  load_env
  sysctl -qw net.ipv4.ip_forward=1
  [ "$IPV6" = 1 ] && sysctl -qw net.ipv6.conf.all.forwarding=1
  modprobe tun 2>/dev/null
  drop_legacy; clear_route
  DNS_FAMILY="meta nfproto ipv4"; [ "$IPV6" = 1 ] && DNS_FAMILY=""
  nft -f - <<NFT
table inet $TABLE
delete table inet $TABLE
table inet $TABLE {
$(sets)
$(dns_chain)
}
NFT
  RC=$?
  [ $RC = 0 ] || { echo "nftables DNS 规则加载失败"; return $RC; }
  echo "TUN 模式：TProxy 规则已关闭，仅保留 DNS 重定向（53 → $DNS_PORT）"
}

stop() {
  nft delete table inet $TABLE 2>/dev/null
  drop_legacy; clear_route
  echo "透明代理规则已关闭"
}

port_up() {
  # $1 = tcp | udp，$2 = 端口（4 位大写十六进制）。/proc/net 里 TCP 要处于 LISTEN（0A）；UDP 绑定即可（PROC_NET 供测试改目录）
  for f in "${PROC_NET:-/proc/net}/$1" "${PROC_NET:-/proc/net}/${1}6"; do
    [ -r "$f" ] || continue
    awk -v p=":$2" -v t="$1" 'NR > 1 && substr($2, length($2) - 4) == p && (t == "udp" || $4 == "0A") { ok = 1; exit } END { exit !ok }' "$f" && return 0
  done
  return 1
}

wait_ready() {
  # 等核心监听好 DNS（1053）及 TProxy（7893）端口再挂规则：以前 init.d 固定 sleep 1，核心早就绪也要白等，
  # 大规则集加载超过 1 秒时又先挂上规则、流量被导向还没监听的端口。每 0.1 秒查一次，最多 10 秒（超时照常挂规则）；
  # 核心进程已退出返回 1：不挂规则，局域网保持直连，不被导向不存在的端口
  [ -n "$WAIT_PID" ] || return 0
  case "$MODE" in tproxy|tun) ;; *) return 0 ;; esac
  PID=$(cat "$WAIT_PID" 2>/dev/null)
  END=$(( $(date +%s) + 10 ))
  while :; do
    if [ -n "$PID" ] && ! kill -0 "$PID" 2>/dev/null; then echo "核心进程已退出，未加载透明代理规则"; return 1; fi
    if port_up udp 041D && { [ "$MODE" != tproxy ] || port_up tcp 1ED5; }; then return 0; fi
    [ "$(date +%s)" -ge "$END" ] && { echo "等待核心监听端口超时（10 秒），照常加载规则"; return 0; }
    sleep 0.1 2>/dev/null || sleep 1
  done
}

leftovers() {
  # 核心 15 秒没正常退出被 KILL 时，来不及撤 TUN 的 auto-route 策略路由（指向 2022 路由表，strict_route 还有 unreachable）
  # 与 auto-redirect 的 nftables 表，留着会让局域网和本机断网。正常退出的核心已自己撤掉：先用 3 条命令看有没有残留，没有就结束；
  # 有残留也只在一个核心进程都没有时才清（有核心在跑，含不受服务管理的，一律不动）
  T=$(nft list tables 2>/dev/null | grep -E "^table inet (sing-box|mihomo)$")
  R4=$(ip -4 rule show 2>/dev/null | grep -c "lookup 2022"); R6=$(ip -6 rule show 2>/dev/null | grep -c "lookup 2022")
  [ -z "$T" ] && [ "${R4:-0}" = 0 ] && [ "${R6:-0}" = 0 ] && return 0
  command -v pidof >/dev/null 2>&1 || return 0
  pidof mihomo mihomo-smart sing-box >/dev/null 2>&1 && return 0
  echo "$T" | grep -q "inet sing-box" && nft delete table inet sing-box 2>/dev/null
  # inet mihomo：mihomo auto-redirect 的表（本脚本旧版的同名表含 bypass_mac，由 drop_legacy 处理，这里不碰）
  if echo "$T" | grep -q "inet mihomo" && ! nft list set inet mihomo bypass_mac >/dev/null 2>&1; then
    nft delete table inet mihomo 2>/dev/null
  fi
  # 两个内核的默认值：iproute2 路由表 2022、策略路由优先级从 9000 起。只有确实有指向 2022 的规则才清 9000～9099 这一段
  for v in 4 6; do
    eval "n=\${R$v:-0}"
    [ "$n" = 0 ] && continue
    for p in $(ip -$v rule show 2>/dev/null | awk -F: '$1 >= 9000 && $1 < 9100 { print $1 }'); do
      ip -$v rule del pref "$p" 2>/dev/null
    done
  done
  return 0
}

status() {
  if nft list chain inet $TABLE prerouting >/dev/null 2>&1; then echo tproxy
  elif nft list chain inet $TABLE dns >/dev/null 2>&1; then echo dns
  else echo off; fi
}

case "$1" in
  start) start ;;
  dns) dns_only ;;
  stop) stop; [ "$2" = leftovers ] && leftovers ;;  # init.d 的 stop_post：stop leftovers 一次调用做完
  status) status ;;
  leftovers) leftovers ;;
  apply)
    load_env
    wait_ready || exit 1
    case "$MODE" in
      tproxy) start ;;
      tun) dns_only ;;
      *) stop ;;
    esac ;;
  *) echo "usage: $0 start|dns|stop|apply|status|leftovers"; exit 1 ;;
esac
