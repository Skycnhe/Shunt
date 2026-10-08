<p align="center"><img src="icon.svg" width="96" alt="Shunt"></p>

# Shunt 分流

> 项目仓库与服务名仍为 `mihomo-panel`，升级不受影响。

Alpine Linux 上运行的 **mihomo 旁路由透明代理 + 一体化 Web 面板**。后端是零依赖的 Python3，前端是单个 HTML 文件。

## v6 新增
- 🚀 **节点选择自适应**：只包含「<地区>自动优选」（url-test，顺序 日本 / 新加坡 / 香港 / 美国 / 其他）、「⚖️ <地区>负载均衡」（每个有节点的地区都生成，顺序 香港 / 日本 / 新加坡 / 美国 / 其他）、「🖐️ 手动选择」（全部节点）、「⚡ 全局自动选择」「🏠 直连」。没有节点的地区不生成；完全没有节点时只剩 🏠 直连。自定义策略组不再加入节点选择，只作为分流组候选
- 🔁 **旧版名称自动迁移**：如「🇺🇸 美国」→「🇺🇸 美国自动优选」、「🇺🇸 美国均衡」→「⚖️ 美国负载均衡」、「♻️ 自动选择」→「⚡ 全局自动选择」，规则、规则集、自定义组、DNS 引用和当前选中的节点都会保留
- 🌐 **DNS 页（新）**：直连 DNS、代理 DNS、默认 DNS、节点域名解析 DNS、Fake-IP 过滤 均可逐条添加 / 删除 / 拖动排序（添加时校验格式）；新增 hosts 静态解析、nameserver-policy 分流规则编辑；清空 DNS 缓存、DNS 查询（显示该域名会走哪个上游）
- 🔒 **防 DNS 泄露**：一键「应用防泄露设置」、「DNS 泄露检测」（约 14 项配置检查 + Fake-IP 探测 + 经代理调用 bash.ws 实测出口 DNS），可选「阻止客户端绕过 DNS」
- 🕘 **配置历史**：自动保留最近 10 个版本，可一键恢复；概览新增节点快速切换卡片
- 🐞 规则测试改为经 mihomo 解析域名，不再走路由器系统 DNS

## DNS 防泄露说明
- 布局：`nameserver` = 代理 DNS（经 🚀 节点选择发出），`nameserver-policy` 把 `geosite:cn,private` 交给直连 DNS；开启 `respect-rules`，节点域名用 `proxy-server-nameserver`（国内 DoH）解析，直连流量用 `direct-nameserver`；不使用 `fallback`，`prefer-h3: false`，`use-system-hosts: false`，DNS 的 IPv6 跟随 IPv6 开关；默认 fake-ip
- 「阻止客户端绕过 DNS」：拒绝局域网设备访问 853（DoT）以及常见公共 DoH 的 IP / 域名（只匹配 TProxy / TUN 入站，不影响 mihomo 自身查询），并让 `tproxy.sh` 把发往任意服务器的 53 端口请求都重定向到 mihomo
- 旁路由**自身**的 `/etc/resolv.conf` 不会被强制改走 mihomo，泄露检测里会列出它；如需本机也防泄露，可改为 `nameserver 127.0.0.1` 并让 53 指向 mihomo（或把上游换成你信任的 DNS）。面板在代理不可用时的直连兜底请求仍使用系统 DNS
- 浏览器自带的「安全 DNS（DoH）」会绕过旁路由，建议关闭或开启上面的阻止选项

## v5 新增
- 🧭 **策略组页（新）**
  - **地区负载均衡**：同一地区有 2 个及以上节点时自动生成「🇺🇸 美国均衡」「🇯🇵 日本均衡」等 `load-balance` 组，策略可选 一致性哈希（默认）/ 轮询 / 粘性会话；原有地区组（url-test 自动测速）保留
  - **地区主分组类型可选**：自动测速 / 手动 / 故障转移 / 负载均衡；不是自动测速时另生成「🇯🇵 日本自动」url-test 组；可设测速间隔、容差、测速地址、懒惰测速
  - **地区识别扩展**：新增韩国、英国、德国、法国、荷兰、加拿大、澳大利亚、俄罗斯、印度、土耳其、马来西亚、泰国、越南、菲律宾、阿根廷、巴西，以及「🌐 其他」；**只为确实有节点的地区生成分组**（订阅节点从核心读取并缓存）。英文缩写不再误匹配（如 `US` 不再匹配 Russia / Plus / Australia）
  - **自定义策略组**：名称、图标、类型（手动 / 自动测速 / 故障转移 / 负载均衡 + 策略）、成员（节点 / 分组 / DIRECT / REJECT，可排序）、按正则筛选全部节点（可含订阅节点，实时预览匹配数）、是否加入「节点选择」与分流组候选；可在自定义规则、规则集、代理 DNS（`#组名`）中引用。拒绝重名、与节点 / 内置组同名、成员不存在、循环引用；改名自动同步规则 / 规则集 / DNS / 其他组里的引用，删除时引用改为「🚀 节点选择」
  - （v6 起节点选择结构见上；）地区组、均衡组、自定义组会加入 YouTube / Google / Telegram / AI / Netflix / 漏网之鱼 的候选
- 🛰 **节点页重做**
  - 顶部「策略选择」：每个手动选择组一个下拉框，直接切换走哪个节点 / 分组
  - 每个策略组是**可折叠卡片**：标题显示类型、当前选择链路（如 `→ 🇺🇸 美国 → US 03`）、负载均衡策略、节点数 / 分组数、组延迟、健康圆点和单组测速；节点多于 12 个的组默认收起，展开状态记在浏览器里，支持全部展开 / 全部收起
  - 自动测速 / 故障转移组可点选节点**临时固定**，点 📌 取消固定恢复自动
- ➕ 其他：
  - 🔍 **域名嗅探开关**（设置 → 核心服务）
  - 📄 **查看 / 下载生成的 config.yaml**（控制器密钥自动隐藏，可搜索）
  - ⬆️ **面板在线更新**：从 `Skycnhe/mihomo-panel`（Hk001）下载最新文件，先经 mihomo 代理、失败直连，可填 GitHub 加速地址（如 `https://ghfast.top/`）；更新前校验 Python / Shell 语法并备份，可一键回滚
  - 📶 订阅列表显示流量进度条与剩余天数；订阅更新后自动重新识别地区分组（另外每 10 分钟检查一次）
  - 节点选择在核心重启后保持（`profile.store-selected`，已验证）
  - `mihomo -t` 报正则错误（panic）时也能显示具体原因

## v4 新增
- 🎛 **顶栏常驻**：核心运行状态 + 启动 / 停止（二次确认）/ 重启按钮；上传 / 下载速率、累计上传 / 下载、内存占用（读取核心 `/traffic`、`/memory` 流）始终可见
- 🔀 **代理方式三选一：TProxy / TUN / 关闭**。TUN 使用 mihomo 内置 `tun`（协议栈 system / gvisor / mixed 可选，auto-route、auto-redirect、auto-detect-interface，DNS 劫持 any:53，strict-route 默认关闭，网卡名可改）；两种模式互斥，看门狗与 `tproxy.sh` 都按当前模式处理
- 🛡 **广告拦截**（AdGuard Home 风格）：订阅 AdGuard DNS filter、anti-AD 或任意列表（ABP `||domain^`、`@@||domain^`、hosts、纯域名），自定义黑 / 白名单、自动更新、总开关、可选 DNS 层拦截，统计每个列表的规则数与今日拦截、拦截排行，并提供「检测域名」
- 🌐 **DNS 设置**：直连 DNS / 代理 DNS（`#策略组` 经节点发出）/ 默认 DNS、nameserver-policy 分流、fake-ip / redir-host、Fake-IP 过滤、缓存算法 ARC / LRU，以及经 mihomo 的「DNS 查询」工具
- 🧹 **日志自动清理**：日志上限 1 / 2 / 5 / 10 / 20 MB（默认 5），超限自动截断保留最后 200 行，显示当前大小，可立即清理
- 💎 **苹果风毛玻璃主题**：彩色柔和背景 + 半透明模糊卡片、iOS 分段控件与开关、SF 字体，深色 / 浅色均适配，手机自适应
- ➕ 另外新增：
  - 🏷 **设备名称**：连接 / 统计 / 概览里显示设备名（备注 → DHCP 租约 → /etc/hosts → 反向解析），可直接点 ✎ 设置备注
  - ⏰ **定时任务**：每天定时更新订阅、重启核心、更新 GEO；节点定时自动测速，节点页可按延迟排序、一键全部测速
  - 🩺 **一键网络诊断**：核心、配置校验、IP 转发、TProxy 规则 / TUN 网卡与模块、DNS 端口与国内外解析、直连与代理出站、磁盘空间，逐项给出修复建议

## 功能
- 📊 概览：实时上传/下载速度、活动连接数、累计流量、内存占用
- 🌐 站点延迟：自动检测 Google / YouTube / Telegram / GitHub / 百度（每 60 秒）
- 🔀 代理模式：规则 / 全局 / 直连 一键切换
- 🛰 节点：可折叠策略组卡片、策略选择下拉、点选切换节点、整组测速
- 🧭 策略组：地区分组（含负载均衡组）设置、自定义策略组
- 📥 订阅：直接粘贴订阅链接添加，显示节点数、已用流量、到期时间，一键更新/删除
- 📜 规则：可视化添加自定义规则（优先于内置分流），支持批量编辑；查看并搜索当前生效规则
- 🔗 连接：实时显示正在访问的网站、来源设备、命中规则、节点链路、速度，可单个/全部断开
- 🗺 自动地区分组（香港 / 台湾 / 日本 / 新加坡 / 美国 + 扩展地区，自动测速选优 + 负载均衡）
- 🤖 AI 服务、🎬 Netflix、YouTube、Google、Telegram 独立分流组
- 📦 规则集订阅（rule-providers），一键添加 广告拦截 / OpenAI / Apple / 微软 / Steam
- 📈 实时流量曲线、设备排行（哪台设备在用、最常访问的网站）
- 🚫 绕过设备：按 IP / 网段 / MAC 不走代理
- 🎯 自定义延迟检测站点、订阅自动更新间隔
- 💾 配置备份 / 恢复、在线升级 mihomo 核心
- 🧾 日志、重载/重启核心、更新 GEO 数据库、清空 Fake-IP、修改面板密码
- 🧱 TProxy 透明代理（nftables），TCP + UDP，DNS 劫持到 mihomo（fake-ip）；或 TUN 模式
- 🌍 IPv6 透明代理（可选）：核心 / DNS 启用 IPv6，nftables ip6 TProxy + 保留地址绕过
- ✍️ 手动导入单节点：粘贴 vless / vmess / ss / trojan / hysteria2(hy2) / tuic 链接，自动加入节点选择、自动选择、地区分组
- 🧹 订阅节点过滤：每个订阅可设“保留”与“排除”正则（默认排除 剩余 / 到期 / 官网 等信息节点）
- 📡 实时日志：SSE 推送核心日志，按级别、关键字过滤，可暂停 / 清空；保留日志文件查看
- 📊 流量统计：按天 / 按月统计总流量，按设备、按节点明细，近 30 天柱状图（保留 60 天）
- 🎬 解锁检测：出口位置、Netflix、ChatGPT、Disney+、YouTube Premium、Gemini
- 🧪 规则测试：输入域名 / IP，发起真实连接读取核心命中的规则与节点链路（失败时静态推断）
- 🛟 故障自动直连：核心无响应自动重启，仍失败则关闭透明代理保证局域网能上网，恢复后自动接管
- 🔔 Telegram 通知：看门狗事件、节点全部超时、订阅 3 天内到期 / 流量超 90%
- 🔒 登录防爆破（同一 IP 失败 5 次锁定 10 分钟）、可选 HTTPS（自签名证书）
- ✅ 改配置前先用 `mihomo -t` 校验，不通过自动撤销，避免核心起不来
- 📱 手机自适应布局，深色 / 浅色主题切换

## 安装

在 Alpine Linux 上用 root 执行一条命令即可，脚本会自动补齐软件源（main + community）和全部依赖（python3、nftables、iptables、iproute2、curl 等），下载面板文件、mihomo 核心和 GEO 数据，并设置开机自启。

**国外网络：**

```sh
wget -qO- https://raw.githubusercontent.com/Skycnhe/mihomo-panel/Hk001/install.sh | sh
```

**国内网络**（apk 换中科大镜像，GitHub 下载走 ghfast.top 加速）：

```sh
wget -qO- https://ghfast.top/https://raw.githubusercontent.com/Skycnhe/mihomo-panel/Hk001/install.sh | sh -s -- --cn
```

需要额外参数时加在最后，例如 `| sh -s -- --cn --https --selftest`。可选环境变量：`GH_PROXY`（换加速代理）、`APK_MIRROR`（换 apk 镜像，如 `mirrors.aliyun.com`）。

也可以下载仓库后本地安装：

```sh
sh install.sh            # 国外
sh install.sh --cn       # 国内
```

安装完成会打印面板地址和初始密码，默认 `http://旁路由IP:8080`。

可选参数：

```sh
sh install.sh --cn           # 国内网络：apk 国内镜像 + GitHub 加速
sh install.sh --https        # 生成自签名证书，面板改用 https://（也可之后在“设置 → 面板安全”开关）
sh install.sh --selftest     # 安装后用真实 mihomo 核心校验多种配置场景
sh install.sh --update-core  # 重新下载最新 mihomo 核心
```

## 代理方式 / DNS / 广告拦截说明

- **代理方式**在“设置”里切换：TProxy（nftables，默认）、TUN（mihomo 虚拟网卡，stack 可选 system / gvisor / mixed）、关闭。切换前先用 `mihomo -t` 校验，失败自动回滚。
- **TUN 模式**：auto-route、auto-detect-interface、DNS 劫持始终开启；auto-redirect 默认开启，内核不支持时面板会自动关闭它并重试一次。TUN 下设备绕过只支持按 IP（转为 `SRC-IP-CIDR,…,DIRECT`），按 MAC 绕过仅 TProxy 可用。`install.sh` 会加载 `tun` / `nft_tproxy` 模块并写入 `/etc/modules`，持久化 `net.ipv4.ip_forward=1`。
- **DNS**：直连 DNS 用于国内域名（`geosite:cn`），代理 DNS 用于其余全部域名（可写成 `https://1.1.1.1/dns-query#🚀 节点选择` 指定走哪个策略组）；可切换 fake-ip / redir-host、编辑 fake-ip 过滤列表，“DNS 查询”工具可直接测解析结果。
- **广告拦截**：兼容 AdGuard / ABP（`||domain^`、`@@||domain^`）、hosts 和纯域名格式的规则列表，自动转换为 mihomo 规则集并放在所有规则之前；白名单优先于拦截。AdGuard DNS filter + anti-AD 全开约 27 万条，核心内存多约 50MB。可选 DNS 级拦截（返回 NXDOMAIN），此方式的拦截不计入“今日拦截”统计。
- **日志**：超过设定上限（默认 5MB）自动保留最后 200 行，也可在“日志”页手动清理。

## 策略组说明
- **负载均衡策略**：一致性哈希——同一目标域名固定走同一节点，兼顾分流与登录状态（推荐）；轮询——每个新连接换一个节点，多线程下载叠加带宽最明显，但有的网站会因 IP 变化要求重新验证；粘性会话——同一设备访问同一网站 10 分钟内固定节点。负载均衡只会使用健康检查通过的节点。
- **地区识别**基于节点名称（中文、英文、城市名、国旗 emoji、ISO 缩写）。订阅刚添加还没下载时，先生成 5 个常用地区，下载完成后自动按实际节点重新生成。
- **自定义组引用内置分流组**：开启“加入节点选择”的自定义组会出现在「🚀 节点选择」等组的候选里，因此它不能再引用这些组（会循环）；需要“跟随节点选择”这类组时关闭该开关即可。
- 地区组消失（例如订阅里没有某地区的节点了）时，引用它的规则自动改走「🚀 节点选择」，自定义组里跳过该成员，配置不会因此失效。

## 客户端设置
把需要代理的设备（或主路由 DHCP 下发）的 **网关** 和 **DNS** 都设为旁路由的 IP。

## 内置分流
（TUN 模式绕过设备）→ 广告拦截（白名单优先）→ 自定义规则 → 规则集 → 局域网直连 → AI 服务 → Netflix → YouTube → Google → Telegram → 境外走「🚀 节点选择」→ 国内直连 → 「🐟 漏网之鱼」。

## 文件位置
| 路径 | 说明 |
|---|---|
| `/etc/mihomo/config.yaml` | 面板自动生成的 mihomo 配置（勿手改，会被覆盖） |
| `/etc/mihomo-panel/data.json` | 面板数据：密码、订阅、手动节点、自定义规则、通知设置 |
| `/etc/mihomo-panel/stats.json` | 流量统计（保留 60 天） |
| `/etc/mihomo-panel/provider_nodes.json` | 订阅节点名缓存（核心未运行时用于生成地区分组） |
| `/opt/mihomo-panel/.backup/` | 面板在线更新前的备份（用于回滚） |
| `/etc/mihomo-panel/adblock_stats.json` | 广告拦截统计（保留 14 天） |
| `/etc/mihomo/adblock/` | 转换后的广告拦截规则文件与 meta.json |
| `/etc/mihomo-panel/cert.pem` `key.pem` | HTTPS 自签名证书（开启 HTTPS 时生成） |
| `/opt/mihomo-panel/` | 面板程序 |
| `/var/log/mihomo.log` | 核心日志 |

## 常用命令
```sh
rc-service mihomo restart        # 重启核心
rc-service mihomo-panel restart  # 重启面板
sh install.sh --update-core      # 升级 mihomo 核心（也可在面板「设置 → 内核更新」一键升级 / 回滚，支持稳定版和 Alpha）
/opt/mihomo-panel/tproxy.sh stop # 临时关闭透明代理（apply 按当前代理方式恢复，status 查看状态）
sh /opt/mihomo-panel/selftest.sh # 用真实核心校验配置
```

## 注意事项
- 流量统计每 5 秒采样一次连接：总量来自核心计数器（准确），设备 / 节点明细按连接增量累计，存活不足 5 秒的短连接或连接最后几秒的流量可能不计入明细。
- 解锁检测走 mixed 端口（7890）并按当前规则分流，结果反映各服务实际使用的节点；地区识别为尽力而为，各网站页面改版后可能需要更新。
- 规则测试会通过 7890 对目标的 443 端口发起一次真实连接；核心不可用时回退为静态推断（GEOSITE / GEOIP / RULE-SET 无法静态判断，会列出供参考）。
- Telegram 通知优先经代理发送，核心故障时改为直连，国内网络直连 Telegram 可能失败。
- 看门狗只在核心“意外”停止时介入；在面板里手动“停止”核心不会被自动拉起。TUN 模式下核心退出后 TUN 路由随之消失，看门狗再撤掉 DNS 重定向保证局域网能上网。
- 日志清理是原地截断：OpenRC 以追加模式写日志，截断后继续写到新末尾。
- 设备名称的反向解析在后台进行，结果缓存 30 分钟；只对私有地址做反向解析。
- 面板在线更新只替换面板文件（server.py、index.html、tproxy.sh、selftest.sh、init.d 脚本），不动 mihomo 核心和 data.json；更新后面板自动重启。
- 自定义策略组的正则同时用于面板（Python）和 mihomo（regexp2）；保存时两边都会校验，个别仅一方支持的语法会被 `mihomo -t` 拒绝并自动撤销。
- 定时任务按旁路由本机时区执行（Alpine 默认 UTC，可 `setup-timezone -z Asia/Shanghai`）。

## 端口
- 8080 面板 · 7890 mixed (HTTP/SOCKS) · 7893 TProxy · 1053 DNS · 9090 控制器（仅本机）
