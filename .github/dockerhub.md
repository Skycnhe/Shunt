# Shunt 分流

Alpine 旁路由透明代理 + Web 管理面板，支持 **mihomo / mihomo Smart / sing-box** 三内核一键切换。

源码与完整文档：[github.com/Skycnhe/Shunt](https://github.com/Skycnhe/Shunt/tree/Hk001)

## 镜像

| 项目 | 说明 |
| --- | --- |
| 镜像 | `skycn2022/shunt`（Docker Hub）、`ghcr.io/skycnhe/shunt`（GHCR，内容相同） |
| 标签 | `latest`、`hk001`、`v<面板版本>`（如 `v8.4.16`） |
| 架构 | `linux/amd64`、`linux/arm64` |
| 内置 | 面板、mihomo / mihomo Smart / sing-box、geo 数据、sing-box 默认规则集 |
| 基础 | Alpine 3.24，面板发新版时自动构建、自测后发布 |

## 能做什么

- 局域网设备把 **网关和 DNS** 指向宿主机就能科学上网，支持 TProxy / TUN、Fake-IP、IPv6
- 粘贴订阅即可，节点按地区自动分组，自动选最快 / 负载均衡
- 国内直连、国外走代理，YouTube、Google、Telegram、AI、Netflix 可单独选节点，支持自定义规则
- 连接、日志、统计、广告拦截、DNS 防泄露、流媒体 / AI 解锁检测
- 核心无响应自动重启，修不好自动切直连，保证家里能上网

## 使用前提

- **只支持 Linux 宿主机 + host 网络**。透明代理规则（nftables、策略路由、TUN 网卡）写在宿主机网络里
- Docker Desktop（Windows / macOS）或 bridge 网络下透明代理不可用，只能用 7890 端口的 HTTP / SOCKS 代理
- 宿主机上不要再跑别的透明代理，也不要占用 8080 / 7890 / 7893 / 1053 / 9090 端口

## 1. 宿主机准备

容器和宿主机共用内核，模块和转发开关只能在宿主机上设置：

```sh
# 内核模块：TProxy 需要 nft_tproxy，TUN 需要 tun
modprobe nft_tproxy; modprobe tun
printf 'nft_tproxy\ntun\n' > /etc/modules-load.d/shunt.conf   # 开机自动加载（Alpine 写 /etc/modules）

# 开启转发
sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-shunt.conf
```

Docker 会把宿主机 FORWARD 默认策略改成 DROP，局域网转发流量会被丢掉，需要放行（`eth0` 换成宿主机连局域网的网卡）：

```sh
iptables -I DOCKER-USER -i eth0 -j ACCEPT
```

这条规则重启后会丢，要用 `iptables-persistent` 等方式持久化；Docker Engine 28 及以上也可以在 `/etc/docker/daemon.json` 加 `"ip-forward-no-drop": true` 后重启 Docker。

## 2. 启动

docker run：

```sh
docker run -d --name shunt --restart unless-stopped \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun \
  -v shunt-data:/data \
  -e TZ=Asia/Shanghai \
  --stop-timeout 30 \
  skycn2022/shunt:latest
```

docker-compose：

```yaml
services:
  shunt:
    image: skycn2022/shunt:latest
    container_name: shunt
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_ADMIN        # 必需：nftables 规则、策略路由、TUN 网卡
      - NET_RAW          # 建议：延迟测试等
    devices:
      - /dev/net/tun:/dev/net/tun   # TUN 模式需要；只用 TProxy 可去掉
    volumes:
      - ./shunt-data:/data          # 全部设置和数据
    environment:
      - TZ=Asia/Shanghai
    stop_grace_period: 30s
```

## 3. 使用

1. 浏览器打开 `宿主机IP:8080` 进入面板（默认只允许局域网访问）
2. 「订阅」页粘贴订阅链接
3. 把要上网的设备（或主路由 DHCP）的 **网关** 和 **DNS** 改成宿主机 IP
4. 回到「概览」，各站点延迟变绿就好了

## 数据与升级

- 所有设置和数据都在 `/data` 卷里，删容器不丢
- 升级：`docker compose pull && docker compose up -d`（或删掉容器用新镜像重建）
- 面板里的在线更新只保存在当前容器里，重建容器后以镜像自带版本为准
- `docker stop` 会先撤掉透明代理规则，局域网立即恢复直连
- 启动有问题先看 `docker logs shunt`，缺内核模块或 TUN 时会提示

## 说明

- 不需要 `privileged`，`NET_ADMIN` + `/dev/net/tun` 就够
- 不建议给 `SYS_MODULE`，直接在宿主机 `modprobe` 更简单
- 停止超时请设 30 秒，默认 10 秒可能来不及让 sing-box 保存缓存
- 本项目属于自娱自乐，更新随缘；许可证 GPL-3.0
