#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# 在 Alpine 容器里运行（容器架构 = 目标架构）：把面板、全部内核、geo 数据、sing-box 规则集和 apk 依赖打成离线安装包
# 用法: sh .github/offline/build.sh <仓库目录> <输出目录>
set -eu
SRC=$(cd "$1" && pwd); OUT=$(mkdir -p "$2" && cd "$2" && pwd)
REL=$(cut -d. -f1,2 /etc/alpine-release); M=$(uname -m)
case "$M" in
  aarch64) MA=arm64; SA=arm64 ;;
  x86_64) MA=amd64-compatible; SA=amd64 ;;
  *) echo "不支持的架构 $M"; exit 1 ;;
esac
apk add --no-cache curl python3 tar gzip >/dev/null
C="curl -fsSL --retry 5 --retry-delay 3"
latest_tag() { curl -fsSI "https://github.com/$1/releases/latest" | sed -n 's#^[Ll]ocation: .*/tag/\([^[:space:]]*\).*#\1#p' | tr -d '\r'; }

W=/tmp/shunt-offline; rm -rf "$W"
mkdir -p "$W/offline/apk/$M" "$W/offline/bin" "$W/offline/geo" "$W/offline/sb-rules"
cd "$SRC"
cp server.py index.html tproxy.sh selftest.sh install.sh LICENSE README.md CHANGELOG.md "$W/"
for f in icon.svg icon-180.png icon-512.png offline.sh; do [ -f "$f" ] && cp "$f" "$W/"; done
cp -r init.d "$W/"

echo ">> apk 依赖 (Alpine $REL $M)"
PKGS="curl wget ca-certificates python3 nftables iptables ip6tables iproute2 gzip tar tzdata kmod coreutils openssl py3-yaml chrony"
apk update >/dev/null
apk fetch -R -o "$W/offline/apk/$M" $PKGS >/dev/null
apk index --allow-untrusted -o "$W/offline/apk/$M/APKINDEX.tar.gz" "$W/offline/apk/$M"/*.apk  # apk 按 <源>/<架构>/APKINDEX.tar.gz 读取
ln -s "$M" "$W/offline/apk/noarch"  # apk v3 按包自身的架构找文件，noarch 包也指到同一目录
echo "$PKGS" > "$W/offline/apk/PKGS"

echo ">> mihomo"
MV=$($C https://github.com/MetaCubeX/mihomo/releases/latest/download/version.txt | tr -d ' \r\n')
$C "https://github.com/MetaCubeX/mihomo/releases/download/$MV/mihomo-linux-$MA-$MV.gz" | gunzip > "$W/offline/bin/mihomo"
echo ">> mihomo Smart (vernesong, Alpha)"
SV=$($C https://github.com/vernesong/mihomo/releases/download/Prerelease-Alpha/version.txt | tr -d ' \r\n')
$C "https://github.com/vernesong/mihomo/releases/download/Prerelease-Alpha/mihomo-linux-$MA-$SV.gz" | gunzip > "$W/offline/bin/mihomo-smart"
$C -o "$W/offline/geo/Model.bin" https://github.com/vernesong/mihomo/releases/download/LightGBM-Model/Model.bin
echo ">> sing-box (musl)"
BT=$(latest_tag SagerNet/sing-box); BV=${BT#v}
$C "https://github.com/SagerNet/sing-box/releases/download/$BT/sing-box-$BV-linux-$SA-musl.tar.gz" | tar xz -C /tmp
cp "/tmp/sing-box-$BV-linux-$SA-musl/sing-box" "$W/offline/bin/sing-box"
chmod 755 "$W"/offline/bin/*
"$W/offline/bin/mihomo" -v | head -n1
"$W/offline/bin/mihomo-smart" -v | head -n1
"$W/offline/bin/sing-box" version | head -n1

echo ">> geo 数据"
for f in geoip.dat geosite.dat geoip.metadb; do
  $C -o "$W/offline/geo/$f" "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/$f"
done

echo ">> sing-box 默认规则集"
T=$(mktemp -d); echo '{}' > "$T/data.json"
PANEL_OFFLINE=1 PANEL_DATA="$T/data.json" MIHOMO_DIR="$T" SB_DIR="$T/sb" SB_RULES="$W/offline/sb-rules" python3 - "$W/server.py" <<'PY' || echo "!! 规则集预下载失败（不影响安装，切到 sing-box 时会自动下载）"
import runpy, sys
g = runpy.run_path(sys.argv[1], run_name="offline")
d = g["load"]()
bad = g["sb_sync_assets"](d, need=g["build_singbox"](d)[2])
print("失败:", bad) if bad else print("ok")
PY

PV=$(sed -n 's/^PANEL_VERSION = "\(.*\)"/\1/p' "$W/server.py")
cat > "$W/offline/VERSION" <<V
panel=$PV
alpine=$REL
arch=$M
mihomo=$MV
mihomo-smart=$SV
sing-box=$BV
built=$(date -u +%F)
V
cat "$W/offline/VERSION"
NAME="shunt-offline-$M-alpine$REL.tar.gz"
tar -C /tmp -czf "$OUT/$NAME" shunt-offline
ls -lh "$OUT/$NAME"
