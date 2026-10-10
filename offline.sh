#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Shunt 分流 —— 一键下载离线安装包（面板 + mihomo / mihomo Smart / sing-box 内核 + geo 数据 + apk 依赖）并安装
#   国外: wget -qO- https://raw.githubusercontent.com/Skycnhe/Shunt/Hk001/offline.sh | sh
#   国内: wget -qO- https://ghfast.top/https://raw.githubusercontent.com/Skycnhe/Shunt/Hk001/offline.sh | sh -s -- --cn
#   其余参数（--https、--update-core、--selftest）原样传给 install.sh
# 不联网的设备：在电脑上从 https://github.com/Skycnhe/Shunt/releases/tag/offline 下载对应的
#   shunt-offline-<架构>-alpine<版本>.tar.gz，传到设备后执行：
#   tar xzf shunt-offline-*.tar.gz && sh shunt-offline/install.sh
set -e
[ "$(id -u)" = 0 ] || { echo "请用 root 运行"; exit 1; }
[ -f /etc/alpine-release ] || { echo "仅支持 Alpine Linux"; exit 1; }
ARGS="$*"; REPO="${PANEL_REPO:-Skycnhe/Shunt}"; GH="${GH_PROXY:-}"
for a in "$@"; do [ "$a" = --cn ] && GH="${GH:-https://ghfast.top/}"; done
M=$(uname -m)
case "$M" in aarch64|x86_64) ;; arm64) M=aarch64 ;; *) echo "离线包只提供 aarch64 / x86_64，本机 $M 请用 install.sh 联网安装"; exit 1 ;; esac
REL=$(cut -d. -f1,2 /etc/alpine-release)
# 有本机版本的包就用它，没有就用最新 Alpine 的包（依赖装不上时 install.sh 会改为联网安装）
LIST="${OFFLINE_ALPINE:-3.24 3.23 3.22}"
PICK=""; for v in $LIST; do [ "$v" = "$REL" ] && PICK=$v; done
[ -n "$PICK" ] || { PICK=${LIST%% *}; echo "!! 没有 Alpine $REL 的离线包，改用 Alpine $PICK 的"; }
NAME="shunt-offline-$M-alpine$PICK.tar.gz"
URL="https://github.com/$REPO/releases/download/offline/$NAME"
DIR=$(mktemp -d)
echo ">> 下载 $NAME"
dl() { if command -v curl >/dev/null; then curl -fL --retry 3 -o "$2" "$1"; else wget -O "$2" "$1"; fi; }
{ [ -n "$GH" ] && dl "$GH$URL" "$DIR/$NAME"; } || dl "$URL" "$DIR/$NAME" || { echo "!! 下载失败（国内请加 --cn）"; exit 1; }
tar -xzf "$DIR/$NAME" -C "$DIR"
# shellcheck disable=SC2086
sh "$DIR/shunt-offline/install.sh" $ARGS
rm -rf "$DIR"
