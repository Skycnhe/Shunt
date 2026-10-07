#!/bin/sh
# mihomo 旁路由面板一键安装 (Alpine Linux)
# 用法: sh install.sh [--cn] [--update-core] [--https] [--selftest]
# 一键安装（无需先下载仓库）:
#   国外: wget -qO- https://raw.githubusercontent.com/Skycnhe/mihomo-panel/main/install.sh | sh
#   国内: wget -qO- https://ghfast.top/https://raw.githubusercontent.com/Skycnhe/mihomo-panel/main/install.sh | sh -s -- --cn
#   --cn           国内网络：apk 换国内镜像，GitHub 下载走加速代理（默认 https://ghfast.top/，可用 GH_PROXY 覆盖）
#   --update-core  重新下载最新 mihomo 核心
#   --https        生成自签名证书并让面板使用 https://（也可之后在“设置”里开关）
#   --selftest     安装后用真实核心校验多种配置场景（selftest.sh）
set -e
[ "$(id -u)" = 0 ] || { echo "请用 root 运行"; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"
GH="${GH_PROXY:-}"   # 国内可设置 GH_PROXY=https://ghfast.top/ 加速
REPO="${PANEL_REPO:-Skycnhe/-mihomo-panel}"; BRANCH="${PANEL_BRANCH:-main}"
CN=""; UPDATE_CORE=""; HTTPS=""; SELFTEST=""
for a in "$@"; do
  case "$a" in
    --cn) CN=1 ;;
    --update-core) UPDATE_CORE=1 ;;
    --https) HTTPS=1 ;;
    --selftest) SELFTEST=1 ;;
    *) echo "未知参数 $a"; exit 1 ;;
  esac
done

[ -f /etc/alpine-release ] || { echo "本脚本仅支持 Alpine Linux"; exit 1; }
if [ -n "$CN" ]; then
  GH="${GH:-https://ghfast.top/}"
  MIRROR="${APK_MIRROR:-mirrors.ustc.edu.cn}"
  echo ">> 国内模式：apk 镜像 $MIRROR，GitHub 加速 $GH"
  sed -i -E "s#https?://[^/]+/alpine#https://$MIRROR/alpine#g" /etc/apk/repositories
fi

echo ">> 补齐软件源（main + community）"
REL=$(cut -d. -f1,2 /etc/alpine-release)
BASE=$(sed -n -E 's#^(https?://[^ ]*/alpine)/.*#\1#p' /etc/apk/repositories | head -n1)
BASE="${BASE:-https://dl-cdn.alpinelinux.org/alpine}"
sed -i -E "s@^#[[:space:]]*(.*/v$REL/community)@\1@" /etc/apk/repositories
for r in main community; do
  grep -Eq "^[^#].*/(v$REL|edge|latest-stable)/$r/?[[:space:]]*$" /etc/apk/repositories || echo "$BASE/v$REL/$r" >> /etc/apk/repositories
done

echo ">> 安装依赖"
apk update >/dev/null || { echo "!! apk update 失败，请检查网络/软件源（国内请加 --cn）"; exit 1; }
PKGS="curl wget ca-certificates python3 nftables iptables ip6tables iproute2 gzip tar tzdata kmod coreutils"
[ -n "$HTTPS" ] && PKGS="$PKGS openssl"
for p in $PKGS; do apk add --no-cache "$p" >/dev/null 2>&1 || echo "!! 依赖 $p 安装失败"; done
for c in curl python3 nft ip gunzip; do command -v $c >/dev/null || { echo "!! 缺少 $c，安装中止"; exit 1; }; done
update-ca-certificates >/dev/null 2>&1 || true

# 通过 wget | sh 运行时本地没有项目文件：从 GitHub 拉取
if [ ! -f "$SRC/server.py" ]; then
  SRC=$(mktemp -d); mkdir -p "$SRC/init.d"
  RAW="${GH}https://raw.githubusercontent.com/$REPO/$BRANCH"
  echo ">> 下载面板文件 ($REPO@$BRANCH)"
  for f in server.py index.html tproxy.sh selftest.sh init.d/mihomo init.d/mihomo-panel; do
    curl -fsSL --retry 3 -o "$SRC/$f" "$RAW/$f" || { echo "!! 下载 $f 失败（国内请加 --cn 或设置 GH_PROXY）"; exit 1; }
  done
fi

case "$(uname -m)" in
  x86_64) ARCH=amd64-compatible ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv8l) ARCH=armv7 ;;
  *) echo "不支持的架构 $(uname -m)"; exit 1 ;;
esac

if [ ! -x /usr/local/bin/mihomo ] || [ -n "$UPDATE_CORE" ]; then
  echo ">> 获取 mihomo 最新版本"
  VER=$(curl -fsSL --retry 3 "${GH}https://github.com/MetaCubeX/mihomo/releases/latest/download/version.txt" | tr -d ' \r\n')
  [ -n "$VER" ] || VER=$(curl -fsSL https://api.github.com/repos/MetaCubeX/mihomo/releases/latest | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
  [ -n "$VER" ] || { echo "获取版本失败，可设置 GH_PROXY 后重试"; exit 1; }
  echo ">> 下载 mihomo $VER ($ARCH)"
  curl -fL "${GH}https://github.com/MetaCubeX/mihomo/releases/download/$VER/mihomo-linux-$ARCH-$VER.gz" | gunzip > /usr/local/bin/mihomo.new
  chmod +x /usr/local/bin/mihomo.new && mv /usr/local/bin/mihomo.new /usr/local/bin/mihomo
fi

mkdir -p /etc/mihomo/providers /etc/mihomo-panel /opt/mihomo-panel
for f in geoip.dat geosite.dat geoip.metadb; do
  [ -s /etc/mihomo/$f ] || { echo ">> 下载 $f"; curl -fL -o /etc/mihomo/$f "${GH}https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/$f"; }
done

echo ">> 安装面板"
cp "$SRC/server.py" "$SRC/index.html" "$SRC/tproxy.sh" "$SRC/selftest.sh" /opt/mihomo-panel/
chmod +x /opt/mihomo-panel/tproxy.sh /opt/mihomo-panel/selftest.sh
cp "$SRC/init.d/mihomo" "$SRC/init.d/mihomo-panel" /etc/init.d/
chmod +x /etc/init.d/mihomo /etc/init.d/mihomo-panel

if [ ! -f /etc/mihomo-panel/data.json ]; then
  PW=$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')
  printf '{"password":"%s","secret":"","mode":"rule","tproxy":true,"subs":[],"rules":[]}\n' "$PW" > /etc/mihomo-panel/data.json
  NEWPW=1
fi
chmod 600 /etc/mihomo-panel/data.json

if [ -n "$HTTPS" ]; then
  echo ">> 生成自签名证书"
  python3 /opt/mihomo-panel/server.py --gen-cert >/dev/null
  python3 - <<'EOF'
import json
p = "/etc/mihomo-panel/data.json"
d = json.load(open(p)); d["https"] = True
json.dump(d, open(p, "w"), ensure_ascii=False, indent=2)
EOF
fi

# 开启转发并持久化（IPv6 转发由 tproxy.sh 在开启 IPv6 透明代理时设置）
mkdir -p /etc/sysctl.d
printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/99-mihomo-panel.conf
grep -q '^net.ipv4.ip_forward' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -qw net.ipv4.ip_forward=1
rc-update add sysctl boot >/dev/null 2>&1 || true

# TUN 模式需要 tun 内核模块；TProxy 需要 nft_tproxy。加载并写入 /etc/modules 开机自动加载
for m in tun nft_tproxy; do
  modprobe "$m" 2>/dev/null || echo "!! 无法加载内核模块 $m（容器 / 精简内核可能不支持，对应的代理方式将不可用）"
  grep -qx "$m" /etc/modules 2>/dev/null || echo "$m" >> /etc/modules
done
[ -c /dev/net/tun ] || { mkdir -p /dev/net && mknod /dev/net/tun c 10 200 2>/dev/null && chmod 666 /dev/net/tun; }
[ -c /dev/net/tun ] && echo ">> TUN 可用（/dev/net/tun）" || echo "!! 未找到 /dev/net/tun，TUN 模式不可用，请使用 TProxy"

python3 /opt/mihomo-panel/server.py --gen >/dev/null
if [ -n "$SELFTEST" ]; then
  echo ">> 校验配置"
  sh /opt/mihomo-panel/selftest.sh || echo "!! 自检未全部通过，请把输出反馈给作者"
fi
rc-update add mihomo default >/dev/null
rc-update add mihomo-panel default >/dev/null
rc-service mihomo restart
rc-service mihomo-panel restart

IP=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p')
SCHEME=http; grep -q '"https": *true' /etc/mihomo-panel/data.json && [ -f /etc/mihomo-panel/cert.pem ] && SCHEME=https
echo
echo "================ 安装完成 ================"
echo " 面板地址: ${SCHEME}://${IP:-本机IP}:8080"
[ "$SCHEME" = https ] && echo " （自签名证书，浏览器提示不安全时选择继续访问）"
[ -n "$NEWPW" ] && echo " 初始密码: $PW   (登录后可在“设置”里修改)"
echo " 客户端把 网关 和 DNS 都设为 ${IP:-本机IP} 即可走透明代理"
echo " 代理方式（TProxy / TUN / 关闭）、DNS、广告拦截都在面板“设置 / 广告拦截”里配置"
echo " 配置自检: sh /opt/mihomo-panel/selftest.sh"
echo "==========================================="
