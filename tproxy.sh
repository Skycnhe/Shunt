#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# mihomo 旁路由透明代理规则 (nftables)。
# 用法: tproxy.sh start|dns|stop|apply|status
#   start  TProxy 模式：TCP/UDP 打标记转发到 mihomo 的 7893，DNS 劫持到 1053
#   dns    TUN 模式：只保留 “发往本机 53 端口的 DNS 重定向到 1053”（流量本身由 mihomo TUN 的 auto-route 接管）
#   stop   删除本脚本创建的全部规则
#   apply  按面板里的“代理方式”(TProxy / TUN / 关闭) 自动选择上面三者之一
TPROXY_PORT=7893
DNS_PORT=1053
MARK=0x162
TABLE_ID=162
TABLE=mihomo_panel        # 不用 "mihomo"：mihomo 自身 TUN auto-redirect 也会创建 inet mihomo 表
DATA=/etc/mihomo-panel/data.json
SELF="$(cd "$(dirname "$0")" && pwd)"
SERVER="$SELF/server.py"
[ -f "$SERVER" ] || SERVER=/opt/mihomo-panel/server.py

load_env() {
  B_IP=""; B_MAC=""; B_IP6=""; LOCAL6=""; IPV6=0; MODE=""; DNS_ALL=0
  ENV=$(python3 "$SERVER" --tpenv 2>/dev/null) && eval "$ENV"
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
  ip rule del fwmark $MARK table $TABLE_ID 2>/dev/null
  ip route flush table $TABLE_ID 2>/dev/null
  ip -6 rule del fwmark $MARK table $TABLE_ID 2>/dev/null
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
    V6_RULES="meta nfproto ipv6 ip6 saddr @bypass6 return
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

status() {
  if nft list chain inet $TABLE prerouting >/dev/null 2>&1; then echo tproxy
  elif nft list chain inet $TABLE dns >/dev/null 2>&1; then echo dns
  else echo off; fi
}

case "$1" in
  start) start ;;
  dns) dns_only ;;
  stop) stop ;;
  status) status ;;
  apply)
    load_env
    case "$MODE" in
      tproxy) start ;;
      tun) dns_only ;;
      *) stop ;;
    esac ;;
  *) echo "usage: $0 start|dns|stop|apply|status"; exit 1 ;;
esac
