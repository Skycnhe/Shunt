#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Shunt 分流 —— mihomo 旁路由面板一键安装 (Alpine Linux)
# 用法: sh install.sh [--cn] [--update-core] [--https] [--selftest]
# 离线安装包（面板 + 全部内核 + 依赖，GitHub Releases「offline」）:
#   一键: wget -qO- https://raw.githubusercontent.com/Skycnhe/Shunt/Hk001/offline.sh | sh
#   本地: tar xzf shunt-offline-aarch64-alpine3.24.tar.gz && sh shunt-offline/install.sh
# 一键安装（无需先下载仓库）:
#   国外: wget -qO- https://raw.githubusercontent.com/Skycnhe/Shunt/Hk001/install.sh | sh
#   国内: wget -qO- https://ghfast.top/https://raw.githubusercontent.com/Skycnhe/Shunt/Hk001/install.sh | sh -s -- --cn
#   --cn           国内网络：apk 换国内镜像，GitHub 下载走加速代理（默认 https://ghfast.top/，可用 GH_PROXY 覆盖）
#   --update-core  重新下载最新 mihomo 核心
#   --https        生成自签名证书并让面板使用 https://（也可之后在“设置”里开关）
#   --selftest     安装后用真实核心校验多种配置场景（selftest.sh）
set -e
[ "$(id -u)" = 0 ] || { echo "请用 root 运行"; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"
GH="${GH_PROXY:-}"   # 国内可设置 GH_PROXY=https://ghfast.top/ 加速
REPO="${PANEL_REPO:-Skycnhe/Shunt}"; BRANCH="${PANEL_BRANCH:-Hk001}"
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
REL=$(cut -d. -f1,2 /etc/alpine-release)
# 离线安装包：同目录有 offline/（内核、geo 数据、apk 依赖），全程不需要联网
OFF=""; [ -f "$SRC/server.py" ] && [ -f "$SRC/offline/VERSION" ] && OFF="$SRC/offline"
PKGS="curl wget ca-certificates python3 nftables iptables ip6tables iproute2 gzip tar tzdata kmod coreutils"
[ -n "$HTTPS" ] && PKGS="$PKGS openssl"
ONLINE_DEPS=1
if [ -n "$OFF" ]; then
  echo ">> 离线安装包：$(tr '\n' ' ' < "$OFF/VERSION")"
  BREL=$(sed -n 's/^alpine=//p' "$OFF/VERSION"); BARCH=$(sed -n 's/^arch=//p' "$OFF/VERSION")
  [ "$BARCH" = "$(uname -m)" ] || { echo "!! 安装包是 $BARCH 的，本机是 $(uname -m)，请下载对应架构的包"; exit 1; }
  [ "$BREL" = "$REL" ] || echo "!! 安装包按 Alpine $BREL 打包，本机是 $REL：包内依赖装不上时会改为联网安装"
  echo ">> 安装依赖（包内离线源）"
  if apk add --no-network --allow-untrusted --repositories-file /dev/null --repository "$OFF/apk" $PKGS openssl py3-yaml >/tmp/shunt-apk.log 2>&1; then
    ONLINE_DEPS=""
  else
    echo "!! 包内依赖安装失败（详情 /tmp/shunt-apk.log），改为联网安装"
  fi
fi
if [ -n "$ONLINE_DEPS" ]; then
if [ -n "$CN" ]; then
  GH="${GH:-https://ghfast.top/}"
  MIRROR="${APK_MIRROR:-mirrors.ustc.edu.cn}"
  echo ">> 国内模式：apk 镜像 $MIRROR，GitHub 加速 $GH"
  sed -i -E "s#https?://[^/]+/alpine#https://$MIRROR/alpine#g" /etc/apk/repositories
fi

echo ">> 补齐软件源（main + community）"
BASE=$(sed -n -E 's#^(https?://[^ ]*/alpine)/.*#\1#p' /etc/apk/repositories | head -n1)
BASE="${BASE:-https://dl-cdn.alpinelinux.org/alpine}"
sed -i -E "s@^#[[:space:]]*(.*/v$REL/community)@\1@" /etc/apk/repositories
for r in main community; do
  grep -Eq "^[^#].*/(v$REL|edge|latest-stable)/$r/?[[:space:]]*$" /etc/apk/repositories || echo "$BASE/v$REL/$r" >> /etc/apk/repositories
done

echo ">> 安装依赖"
apk update >/dev/null || { echo "!! apk update 失败，请检查网络/软件源（国内请加 --cn）"; exit 1; }
for p in $PKGS; do apk add --no-cache "$p" >/dev/null 2>&1 || echo "!! 依赖 $p 安装失败"; done
fi
for c in curl python3 nft ip gunzip; do command -v $c >/dev/null || { echo "!! 缺少 $c，安装中止"; exit 1; }; done
update-ca-certificates >/dev/null 2>&1 || true

# 通过 wget | sh 运行时本地没有项目文件：从 GitHub 拉取（文件清单见仓库的 update-files.txt）
if [ ! -f "$SRC/server.py" ]; then
  SRC=$(mktemp -d)
  # 能连上 GitHub API 时锁定到具体提交，并按 Git blob SHA1 校验每个文件；连不上时只能不校验
  MAN="$SRC/.manifest"
  REF=$(python3 - "$REPO" "$BRANCH" "$MAN" <<'PY' 2>/dev/null
import json, sys, urllib.request
repo, br, out = sys.argv[1:4]
get = lambda u: json.load(urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "shunt-install"}), timeout=15))
c = get(f"https://api.github.com/repos/{repo}/commits/{br}")
t = get(f"https://api.github.com/repos/{repo}/git/trees/{c['commit']['tree']['sha']}?recursive=1")
open(out, "w").write("".join(f"{x['sha']} {x['path']}\n" for x in t["tree"] if x["type"] == "blob"))
print(c["sha"])
PY
)
  [ -n "$REF" ] || { REF="$BRANCH"; rm -f "$MAN"; echo "!! 无法访问 GitHub API，下载的文件不做完整性校验"; }
  RAW="${GH}https://raw.githubusercontent.com/$REPO/$REF"
  echo ">> 下载面板文件 ($REPO@$REF)"
  FILES="server.py index.html tproxy.sh selftest.sh init.d/mihomo init.d/mihomo-panel"
  if curl -fsSL --retry 3 -o "$SRC/update-files.txt" "$RAW/update-files.txt"; then
    L=$(sed 's/#.*//' "$SRC/update-files.txt" | tr -s ' \t\r' '\n' | grep -E '^[A-Za-z0-9_][A-Za-z0-9_./-]*$' | grep -v '\.\.' | tr '\n' ' ')
    [ -n "$L" ] && FILES="update-files.txt $L"
  fi
  for f in $FILES; do
    mkdir -p "$SRC/$(dirname "$f")"
    curl -fsSL --retry 3 -o "$SRC/$f" "$RAW/$f" || { echo "!! 下载 $f 失败（国内请加 --cn 或设置 GH_PROXY）"; exit 1; }
    if [ -f "$MAN" ]; then
      want=$(awk -v f="$f" '$2==f{print $1}' "$MAN")
      got=$({ printf 'blob %d\000' "$(wc -c < "$SRC/$f")"; cat "$SRC/$f"; } | sha1sum | cut -d' ' -f1)
      [ -n "$want" ] && [ "$want" = "$got" ] || { echo "!! $f 校验失败（可能被篡改或下载不完整），安装中止"; exit 1; }
    fi
  done
fi

case "$(uname -m)" in
  x86_64) ARCH=amd64-compatible ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv8l) ARCH=armv7 ;;
  *) echo "不支持的架构 $(uname -m)"; exit 1 ;;
esac

mkdir -p /etc/mihomo/providers /etc/mihomo-panel /opt/mihomo-panel /etc/sing-box/rules
if [ -n "$OFF" ]; then
  # 内核：没装过或带 --update-core 时用包里的（旧的留 .bak，面板里可回滚）
  for b in mihomo mihomo-smart sing-box; do
    [ -f "$OFF/bin/$b" ] || continue
    if [ ! -x /usr/local/bin/$b ] || [ -n "$UPDATE_CORE" ]; then
      [ -x /usr/local/bin/$b ] && ! cmp -s "$OFF/bin/$b" /usr/local/bin/$b && cp /usr/local/bin/$b /usr/local/bin/$b.bak
      cp "$OFF/bin/$b" /usr/local/bin/$b.new && chmod 755 /usr/local/bin/$b.new && mv /usr/local/bin/$b.new /usr/local/bin/$b
      echo ">> 安装内核 $b"
    fi
  done
  for f in geoip.dat geosite.dat geoip.metadb Model.bin; do
    [ -f "$OFF/geo/$f" ] && { [ -s /etc/mihomo/$f ] && [ -z "$UPDATE_CORE" ] || cp "$OFF/geo/$f" /etc/mihomo/$f; }
  done
  for f in "$OFF"/sb-rules/*; do [ -f "$f" ] && { [ -s "/etc/sing-box/rules/${f##*/}" ] || cp "$f" /etc/sing-box/rules/; }; done
elif [ ! -x /usr/local/bin/mihomo ] || [ -n "$UPDATE_CORE" ]; then
  echo ">> 获取 mihomo 最新版本"
  VER=$(curl -fsSL --retry 3 "${GH}https://github.com/MetaCubeX/mihomo/releases/latest/download/version.txt" | tr -d ' \r\n')
  [ -n "$VER" ] || VER=$(curl -fsSL https://api.github.com/repos/MetaCubeX/mihomo/releases/latest | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
  [ -n "$VER" ] || { echo "获取版本失败，可设置 GH_PROXY 后重试"; exit 1; }
  echo ">> 下载 mihomo $VER ($ARCH)"
  curl -fL "${GH}https://github.com/MetaCubeX/mihomo/releases/download/$VER/mihomo-linux-$ARCH-$VER.gz" | gunzip > /usr/local/bin/mihomo.new
  chmod +x /usr/local/bin/mihomo.new && mv /usr/local/bin/mihomo.new /usr/local/bin/mihomo
fi

for f in geoip.dat geosite.dat geoip.metadb; do
  [ -s /etc/mihomo/$f ] || { echo ">> 下载 $f"; curl -fL -o /etc/mihomo/$f "${GH}https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/$f"; }
done

echo ">> 安装面板"
cp "$SRC/server.py" "$SRC/index.html" "$SRC/tproxy.sh" "$SRC/selftest.sh" /opt/mihomo-panel/
for f in icon.svg icon-180.png icon-512.png; do [ -f "$SRC/$f" ] && cp "$SRC/$f" /opt/mihomo-panel/; done
chmod +x /opt/mihomo-panel/tproxy.sh /opt/mihomo-panel/selftest.sh
cp "$SRC/init.d/mihomo" "$SRC/init.d/mihomo-panel" /etc/init.d/
chmod +x /etc/init.d/mihomo /etc/init.d/mihomo-panel

if [ ! -f /etc/mihomo-panel/data.json ]; then
  printf '{"secret":"","mode":"rule","tproxy":true,"subs":[],"rules":[]}\n' > /etc/mihomo-panel/data.json
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

# 运行环境检测：容器（LXC / Docker）没有自己的内核，模块和设备要在宿主机上准备
CT=""
if [ -e /dev/.lxc-boot-id ] || grep -q ' lxcfs ' /proc/self/mountinfo 2>/dev/null || grep -q '/lxc' /proc/1/cgroup 2>/dev/null; then CT=lxc
elif [ -f /.dockerenv ] || [ -f /run/.containerenv ] || grep -Eq '/(docker|kubepods)' /proc/1/cgroup 2>/dev/null; then CT=docker; fi
[ -n "$CT" ] && echo ">> 检测到 $CT 容器：内核模块、TUN 设备由宿主机提供"
# TUN 模式需要 tun 内核模块；TProxy 需要 nft_tproxy。加载并写入 /etc/modules 开机自动加载（容器里由宿主机负责）
if [ -z "$CT" ]; then
  for m in tun nft_tproxy; do
    modprobe "$m" 2>/dev/null || echo "!! 无法加载内核模块 $m（精简内核可能不支持，对应的代理方式将不可用）"
    grep -qx "$m" /etc/modules 2>/dev/null || echo "$m" >> /etc/modules
  done
fi
[ -c /dev/net/tun ] || { mkdir -p /dev/net && mknod /dev/net/tun c 10 200 2>/dev/null && chmod 666 /dev/net/tun; }
TUN_OK=""; [ -c /dev/net/tun ] && python3 -c "import fcntl,os,struct;f=os.open('/dev/net/tun',os.O_RDWR);fcntl.ioctl(f,0x400454ca,struct.pack('16sH',b'shuntprobe',0x1001))" 2>/dev/null && TUN_OK=1
TP_OK=""; nft -f - 2>/dev/null <<'NFT' && TP_OK=1
table inet shunt_probe { chain p { type filter hook prerouting priority mangle; meta l4proto tcp tproxy ip to 127.0.0.1:1 } }
NFT
nft delete table inet shunt_probe 2>/dev/null || true
[ -n "$TP_OK" ] && echo ">> TProxy 可用（nftables tproxy）" || echo "!! TProxy 不可用：内核缺少 nft_tproxy / nf_tables"
[ -n "$TUN_OK" ] && echo ">> TUN 可用（/dev/net/tun）" || echo "!! TUN 不可用：没有 /dev/net/tun 或无权创建网卡"
if [ "$CT" = lxc ] && { [ -z "$TP_OK" ] || [ -z "$TUN_OK" ]; }; then
  echo "   PVE 宿主机上这样设置后重启容器（<ID> 换成容器编号）："
  [ -z "$TP_OK" ] && echo "     modprobe nft_tproxy && echo nft_tproxy >> /etc/modules"
  [ -z "$TUN_OK" ] && { echo "     在 /etc/pve/lxc/<ID>.conf 末尾加两行："
    echo "       lxc.cgroup2.devices.allow: c 10:200 rwm"
    echo "       lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file"; }
  echo "     容器需在 选项 → 功能 里勾选 nesting；非特权容器不能用 TProxy 时可改用特权容器"
fi
[ -z "$TP_OK" ] && [ -z "$TUN_OK" ] && echo "!! TProxy 和 TUN 都不可用：只能把设备的 HTTP/SOCKS 代理指向本机 7890 端口使用"

# 升级安装：先记下各策略组当前选择（v6 地区组改名，如「🇺🇸 美国」→「🇺🇸 美国自动优选」），面板启动后按新名称恢复
[ -z "$NEWPW" ] && python3 /opt/mihomo-panel/server.py --snapshot >/dev/null 2>&1 || true
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
echo "========= Shunt 分流 · 安装完成 ========="
echo " 面板地址: ${SCHEME}://${IP:-本机IP}:8080"
[ "$SCHEME" = https ] && echo " （自签名证书，浏览器提示不安全时选择继续访问）"
echo " 面板不需要密码，默认只允许局域网访问"
echo " 客户端把 网关 和 DNS 都设为 ${IP:-本机IP} 即可走透明代理"
echo " 代理方式（TProxy / TUN / 关闭）、DNS、广告拦截都在面板“设置 / 广告拦截”里配置"
echo " 配置自检: sh /opt/mihomo-panel/selftest.sh"
echo "==========================================="
