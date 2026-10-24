<p align="center"><img src="icon.svg" width="96" alt="Shunt"></p>

<h1 align="center">Shunt 分流</h1>

<p align="center">Alpine 旁路由一键透明代理 + Web 管理面板，支持 mihomo / sing-box 双内核</p>

![概览](docs/overview.jpg)

本项目属于自娱自乐，更新随缘

## 能做什么

- **一键装好**：一条命令装完核心、面板和开机自启，也有不联网的离线安装包
- **透明代理**：局域网设备把网关和 DNS 指向旁路由就能用，支持 TProxy / TUN、Fake-IP、IPv6
- **订阅和节点**：粘贴订阅链接或节点链接即可，按地区自动分组；每个地区有「竞技」（自动选最快）和「哈希」负载均衡组
- **分流**：国内直连，国外走代理；YouTube、Google、Telegram、AI、Netflix 可单独选节点，支持自定义规则和策略组
- **三内核**：mihomo、mihomo Smart、sing-box 一键切换，共用同一份设置
- **概览一眼看清**：各站点延迟柱状图、实时流量、IP 信息（本地公网 / 代理出口和归属地，可一键隐藏）、域名过滤统计，顶栏显示面板和内核版本、有更新会提示
- **好用的面板**：连接、日志、统计、广告拦截（内置分类规则）、DNS 防泄露；设置 → 网络里有流媒体 / AI 解锁检测和网络诊断
- **省心**：核心无响应自动重启，修不好就自动切直连保证家里能上网；面板和内核都能在线更新、一键回滚
- **10 套主题 + 自定义背景图**（可每天自动换），手机上也好用

## 安装

在 Alpine Linux 上用 root 执行：

```sh
# 国内网络
wget -qO- https://ghfast.top/https://raw.githubusercontent.com/Skycnhe/Shunt/Hk001/install.sh | sh -s -- --cn

# 国外网络
wget -qO- https://raw.githubusercontent.com/Skycnhe/Shunt/Hk001/install.sh | sh
```

装完会显示面板地址（默认 `http://旁路由IP:8080`）。面板不需要密码，默认只允许局域网访问；要用域名（DDNS / 反向代理）访问，先在路由器上执行 `python3 /opt/mihomo-panel/server.py --allow-host 你的域名`，确需外网直连时执行 `--allow-public on`。脚本调用改动类接口需加请求头 `X-Shunt: 1`。

### 离线安装包

[Releases · offline](https://github.com/Skycnhe/Shunt/releases/tag/offline) 里有打包好的离线安装包：面板 + mihomo / mihomo Smart / sing-box 三个内核 + geo 数据 + sing-box 规则集 + 全部 apk 依赖，装的时候不用联网。每次面板更新和每周一自动重新打包，内核始终是最新版。

```sh
# 一键：自动选对应架构和 Alpine 版本的包，下载后安装
wget -qO- https://ghfast.top/https://raw.githubusercontent.com/Skycnhe/Shunt/Hk001/offline.sh | sh -s -- --cn   # 国内
wget -qO- https://raw.githubusercontent.com/Skycnhe/Shunt/Hk001/offline.sh | sh                                  # 国外

# 设备不联网：在电脑上下载 shunt-offline-<aarch64|x86_64>-alpine<3.22|3.23|3.24>.tar.gz，传到设备后
tar xzf shunt-offline-aarch64-alpine3.24.tar.gz && sh shunt-offline/install.sh
```

架构看 `uname -m`，Alpine 版本看 `cat /etc/alpine-release`。已安装的设备加 `--update-core` 可以用包里的内核和 geo 数据覆盖升级（旧内核留作 .bak，面板里可回滚）。

### Docker

镜像 `skycn2022/shunt`（Docker Hub）/ `ghcr.io/skycnhe/shunt`（GHCR），支持 `linux/amd64`、`linux/arm64`，标签 `latest`、`hk001`、`v<面板版本>`（如 `v8.4.16`）。基于 Alpine 3.24，已内置面板、mihomo / mihomo Smart / sing-box 三个内核、geo 数据、LightGBM 模型和 sing-box 默认规则集（与离线安装包同一套打包和自测），面板版本更新时自动发布。

镜像只适合 **Linux 宿主机 + host 网络** 当旁路由用：透明代理规则（nftables、策略路由、TUN 网卡）是写在宿主机网络里的，所以要 `network_mode: host` 和 `NET_ADMIN` 权限。Docker Desktop（Windows / macOS）、bridge 网络下透明代理不可用，只能用 7890 端口的 HTTP / SOCKS 代理。

```sh
docker run -d --name shunt --restart unless-stopped \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun \
  -v shunt-data:/data \
  --stop-timeout 30 \
  skycn2022/shunt:latest
```

docker-compose：

```yaml
services:
  shunt:
    image: skycn2022/shunt:latest      # 或 ghcr.io/skycnhe/shunt:latest
    container_name: shunt
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_ADMIN                      # 必需：nftables 规则、策略路由、TUN 网卡
      - NET_RAW                        # 建议：核心的 ICMP / 原始套接字（延迟测试等）
      # - SYS_MODULE                   # 一般不需要，见下方说明
    devices:
      - /dev/net/tun:/dev/net/tun      # TUN 模式需要；只用 TProxy 可去掉
    volumes:
      - ./shunt-data:/data             # 全部设置和数据
    environment:
      - TZ=Asia/Shanghai
    stop_grace_period: 30s             # sing-box 正常退出最多要 15 秒（写 Fake-IP 缓存）
```

面板地址 `http://宿主机IP:8080`，其余用法和 Alpine 实机相同（局域网设备的网关和 DNS 指向宿主机 IP）。

**宿主机准备**（容器和宿主机共用内核，模块和转发开关只能在宿主机上设置）：

```sh
# 内核模块：TProxy 需要 nft_tproxy（会带上 nf_tproxy_ipv4 / nf_tproxy_ipv6），TUN 需要 tun
modprobe nft_tproxy; modprobe tun
printf 'nft_tproxy\ntun\n' > /etc/modules-load.d/shunt.conf      # systemd 发行版开机自动加载（Alpine 写 /etc/modules）
# 开启转发（容器里的 /proc/sys 只读，面板改不了）；开启了面板里的 IPv6 透明代理时再加 IPv6 那行
sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-shunt.conf
# sysctl -w net.ipv6.conf.all.forwarding=1 && echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.d/99-shunt.conf
```

**Docker 的 FORWARD 拦截**：Docker 会把宿主机 iptables 的 FORWARD 默认策略改成 DROP，局域网经旁路由转发的流量（TUN 模式的全部流量、TProxy 下绕过的设备和直连网段）会被丢掉。在宿主机上放行局域网网卡转发（`eth0` 换成宿主机连局域网的网卡）：

```sh
iptables -I DOCKER-USER -i eth0 -j ACCEPT
ip6tables -I DOCKER-USER -i eth0 -j ACCEPT 2>/dev/null   # 开了 IPv6 透明代理时
```

这条规则重启后会丢，需要用发行版的方式持久化（如 `iptables-persistent`）；Docker Engine 28 及以上也可以在 `/etc/docker/daemon.json` 里加 `"ip-forward-no-drop": true` 后重启 Docker，不再改 FORWARD 策略（按 Docker 文档，Docker 只在自己去开启转发时才改策略，所以先按上面把 `ip_forward=1` 写进 sysctl.d、开机时比 Docker 先生效，一般也不会被改）。TProxy 模式下走代理的流量由核心本机接收，不受这条影响。

说明与限制：

- 数据都在 `/data`（`mihomo-panel/` 面板设置、`mihomo/` mihomo 配置与 geo 数据、`sing-box/` sing-box 配置与规则集）。首次启动时把镜像里的 geo 数据和规则集复制进去，已有的不覆盖（之后由面板定时更新）
- 宿主机缺少 `nft_tproxy` 时 TProxy 不可用，可在面板里改用 TUN；`/dev/net/tun` 也没有时只能用 7890 代理。启动日志（`docker logs shunt`）会提示缺什么
- `SYS_MODULE`：只有想让容器自己加载内核模块时才需要，还得把宿主机的 `/lib/modules` 只读挂进容器；直接在宿主机上 `modprobe` 更简单安全，不建议给
- 不要用 `privileged`，`NET_ADMIN` + `/dev/net/tun` 已经够用
- `docker stop` 时先撤掉透明代理规则（局域网立即恢复直连），再停面板和核心；被强杀（超时、断电）留下的规则在下次启动时清理。超时请设 30 秒（`--stop-timeout 30` / `stop_grace_period: 30s`），默认 10 秒可能来不及让 sing-box 写完 Fake-IP 缓存
- 换新版本：`docker compose pull && docker compose up -d`（或删掉容器用新镜像重建），数据卷保留。面板里的在线更新、内核更新也能用，但只保存在当前容器里，重建容器后以镜像自带的版本为准
- 宿主机上不要再跑别的透明代理或占用 8080 / 7890 / 7893 / 1053 / 9090 端口的程序；系统优化里的 sysctl、BBR 等全局参数在容器里不生效，需要时在宿主机上设置
- 自己构建：`docker buildx build --platform linux/amd64,linux/arm64 -t shunt .`（构建时联网下载内核和数据）

## 使用

1. 打开面板 →「订阅」粘贴你的订阅链接
2. 把要上网的设备（或主路由的 DHCP）的 **网关** 和 **DNS** 都改成旁路由的 IP
3. 回到「概览」看各站点延迟变绿就好了

## 截图

**节点**：按地区分组，点一下就能切换

![节点](docs/nodes.jpg)

**策略组**：地区分组、负载均衡、自定义分组

![策略组](docs/groups.jpg)

**外观**：10 套主题，可换背景图（图中为「赛博朋克」）

![主题](docs/themes.jpg)

**手机**

<p align="center"><img src="docs/mobile.jpg" width="520" alt="手机"></p>

## 常用命令

```sh
rc-service shunt-core restart      # 重启核心
rc-service shunt restart           # 重启面板
/opt/mihomo-panel/tproxy.sh stop   # 临时关闭透明代理（apply 恢复）
```

面板和内核都能在「设置」里在线更新，出问题可一键回滚。

## 常见问题

- **日志页偶尔出现「内核未运行或正在重启」**：sing-box 不支持热重载，保存规则、订阅、DNS、策略组等设置或自动更新订阅时会重新加载，控制端口会断开几秒，恢复后自动重连。mihomo 是热重载，没有这个现象
- **在线更新失败**：面板会列出镜像、代理、直连各条线路的错误；都不通时可重新执行上面的安装命令覆盖更新，设置会保留
- **截图时不想暴露 IP**：点概览「IP 信息」卡片的「隐藏 IP」


## 端口

8080 面板 · 7890 HTTP/SOCKS 代理 · 7893 TProxy · 1053 DNS · 9090 控制器（仅本机）

## 开发

- 后端源码在 `shunt/`（Python 包），前端源码在 `web/`；设备上部署的单文件 `server.py`、`index.html` 由 `python3 tools/build.py` 生成，改完源码后一起提交
- 测试：`python3 -m unittest discover -s tests -t .`（单元测试）、`sh selftest.sh`（端到端，需要内核二进制）
- 详细说明见 [shunt/README.md](shunt/README.md)
- 当前版本见 [CHANGELOG.md](CHANGELOG.md)

## 特别鸣谢

- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo)：代理核心
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)：代理核心
- [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)：GeoIP / GeoSite 数据与规则集
- [AdGuard DNS filter](https://github.com/AdguardTeam/AdGuardSDNSFilter)、[anti-AD](https://github.com/privacy-protection-tools/anti-AD)：广告拦截规则
- [ghfast.top](https://ghfast.top/)：国内 GitHub 下载加速
- [Alpine Linux](https://alpinelinux.org/)：运行系统

---

更新记录和详细说明见 [CHANGELOG.md](CHANGELOG.md)。
