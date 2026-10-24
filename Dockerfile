# syntax=docker/dockerfile:1
# SPDX-License-Identifier: GPL-3.0-or-later
# Shunt 分流 Docker 镜像：面板 + mihomo / mihomo Smart / sing-box 内核 + geo 数据 + sing-box 默认规则集
# 内容由离线安装包的打包脚本 .github/offline/build.sh 准备（同一套下载与三内核自测，自测失败则构建失败）
# 构建：docker buildx build --platform linux/amd64,linux/arm64 -t shunt .
# 运行要求（network_mode host、NET_ADMIN、/dev/net/tun、宿主机内核模块与 ip_forward）见 README「Docker」一节
ARG ALPINE=3.24

FROM alpine:${ALPINE} AS bundle
COPY . /src
RUN NO_APK=1 NO_TAR=1 sh /src/.github/offline/build.sh /src /out \
 && W=/tmp/shunt-offline && R=/rootfs \
 && mkdir -p $R/opt/mihomo-panel $R/opt/shunt-seed $R/usr/local/bin $R/etc/init.d \
 && cp $W/server.py $W/index.html $W/tproxy.sh $W/selftest.sh $W/icon.svg $W/icon-180.png $W/icon-512.png $R/opt/mihomo-panel/ \
 && chmod 755 $R/opt/mihomo-panel/tproxy.sh $R/opt/mihomo-panel/selftest.sh \
 && cp $W/init.d/shunt $W/init.d/shunt-core $R/etc/init.d/ && chmod 755 $R/etc/init.d/* \
 && cp $W/offline/bin/* $R/usr/local/bin/ \
 && cp -r $W/offline/geo $W/offline/sb-rules $W/offline/VERSION $R/opt/shunt-seed/ \
 && install -m 755 /src/docker/entrypoint.sh $R/usr/local/bin/shunt-entrypoint

FROM alpine:${ALPINE}
ARG ALPINE
# 与 install.sh 相同的运行时依赖，另加 OpenRC（rc-service 管面板 / 核心，复用 init.d 脚本）和 tini（PID 1：转发信号、回收僵尸进程）
RUN apk add --no-cache curl wget ca-certificates python3 nftables iptables ip6tables iproute2 gzip tar tzdata kmod \
      coreutils openssl py3-yaml openrc tini \
 && printf '%s\n' '# Shunt Docker：容器内只用 rc-service 管面板 / 核心（不经 OpenRC 开机），不挂 cgroup、不检查 need net 依赖' \
      'rc_sys="docker"' 'rc_provide="loopback net"' 'rc_controller_cgroups="NO"' 'rc_depend_strict="NO"' >> /etc/rc.conf \
 && mkdir -p /data /var/log /run/openrc && touch /run/openrc/softlevel \
 && rm -rf /etc/mihomo /etc/mihomo-panel /etc/sing-box \
 && ln -s /data/mihomo /etc/mihomo && ln -s /data/mihomo-panel /etc/mihomo-panel && ln -s /data/sing-box /etc/sing-box
COPY --from=bundle /rootfs/ /
RUN /usr/local/bin/mihomo -v && /usr/local/bin/mihomo-smart -v && /usr/local/bin/sing-box version \
 && python3 -c "compile(open('/opt/mihomo-panel/server.py').read(), 'server.py', 'exec')" && cat /opt/shunt-seed/VERSION

LABEL org.opencontainers.image.title="Shunt" \
      org.opencontainers.image.description="Shunt 分流：旁路由透明代理 + Web 面板（mihomo / mihomo Smart / sing-box，nftables TProxy / TUN）" \
      org.opencontainers.image.source="https://github.com/Skycnhe/Shunt" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"
ENV TZ=Asia/Shanghai
VOLUME ["/data"]
EXPOSE 8080 7890 7893 1053
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=60s --timeout=10s --start-period=90s --retries=3 \
  CMD wget -q -T 5 -O /dev/null http://127.0.0.1:8080/manifest.webmanifest \
   || wget -q -T 5 --no-check-certificate -O /dev/null https://127.0.0.1:8080/manifest.webmanifest || exit 1
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/shunt-entrypoint"]
