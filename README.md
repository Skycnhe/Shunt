# mihomo-panel

Alpine Linux 上运行的 **mihomo 旁路由透明代理 + 一体化 Web 面板**。后端是零依赖的 Python3，前端是单个 HTML 文件。

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
- 🛰 节点：所有策略组、点选切换节点、整组测速
- 📥 订阅：直接粘贴订阅链接添加，显示节点数、已用流量、到期时间，一键更新/删除
- 📜 规则：可视化添加自定义规则（优先于内置分流），支持批量编辑；查看并搜索当前生效规则
- 🔗 连接：实时显示正在访问的网站、来源设备、命中规则、节点链路、速度，可单个/全部断开
- 🗺 自动地区分组（香港 / 台湾 / 日本 / 新加坡 / 美国，自动测速选优）
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
```sh
apk add git
git clone https://github.com/Skycnhe/mihomo-panel.git
cd mihomo-panel
sh install.sh
# 国内下载慢可以： GH_PROXY=https://ghfast.top/ sh install.sh
```
安装完成会打印面板地址和初始密码，默认 `http://旁路由IP:8080`。

可选参数（可组合）：
```sh
sh install.sh --https        # 生成自签名证书，面板改用 https://（也可之后在“设置 → 面板安全”开关）
sh install.sh --selftest     # 安装后用真实 mihomo 核心校验多种配置场景
sh install.sh --update-core  # 重新下载最新 mihomo 核心
```

### 自检
```sh
sh /opt/mihomo-panel/selftest.sh
```
会生成 16 种场景（含 TUN 三种协议栈、广告拦截规则 / DNS 层拦截、自定义 DNS、旧版数据迁移），先检查生成结果（TUN 与代理方式一致、白名单优先等），再逐个 `mihomo -t` 校验。

### TUN 模式说明
- 设置 → 代理方式 选 **TUN**：面板生成 `tun.enable: true`（auto-route、auto-detect-interface、`dns-hijack: [any:53, tcp://any:53]`），先 `mihomo -t` 校验再热重载，随后确认 TUN 网卡确实创建成功；失败会把核心日志里的原因显示出来。
- 选 TUN 时 `tproxy.sh` 会撤掉 TProxy 的 nftables 规则，只保留「发往本机 53 端口的 DNS → 1053」重定向，让把 DNS 指向旁路由的设备继续可用；切回 TProxy 时反之。
- **auto-redirect** 依赖 nftables（或 iptables）；内核不支持时面板会自动关闭它并重试一次。`install.sh` 会安装 iptables、加载 `tun` 模块并写入 `/etc/modules`、持久化 `net.ipv4.ip_forward=1`。
- 绕过设备：TUN 模式下 IP / 网段会生成 `SRC-IP-CIDR,…,DIRECT` 规则（流量仍经过 TUN 但直连）；**MAC 绕过只在 TProxy 模式有效**。
- 协议栈：`mixed`（默认，TCP 走 system、UDP 走 gVisor）、`system`（性能最好）、`gvisor`（兼容性最好）。容器 / LXC 里通常没有 `/dev/net/tun`，请用 TProxy。
- nftables 表名改为 `inet mihomo_panel`，避免与 mihomo auto-redirect 自己的表冲突；旧版的 `inet mihomo` 表只有确认是面板创建的才会被删除。

### 广告拦截说明
- 打开「广告拦截」页的总开关，点预设 **AdGuard DNS filter** / **anti-AD** 或填入任意列表地址。后端先经代理、失败再直连下载，解析并转换为 mihomo `behavior: domain / format: text` 的本地规则文件（`/etc/mihomo/adblock/`），去重并去掉被上级域名覆盖的条目，无效行（正则、`$client=` 等修饰符、URL 规则）直接丢弃。
- 转换规则：`||a.com^` → `+.a.com`（含子域）；hosts（`0.0.0.0 a.com`）与纯域名 → `a.com`（仅该域名，与 AdGuard Home 一致）；自定义黑 / 白名单里的纯域名按「含子域」处理。
- 生成的规则排在所有规则之前：`AND,((RULE-SET,ad-xxx),(NOT,((RULE-SET,ad-allow)))),REJECT`。白名单（自定义白名单 + 各列表中的 `@@` 例外）优先，被放行的域名**继续走正常分流**而不是强制直连。
- **DNS 层拦截**（可选）：通过 `nameserver-policy` 把命中列表的域名指向 `rcode://name_error`（白名单先走直连 DNS），客户端收到 NXDOMAIN 不再发起连接——因此这部分不计入「今日拦截」。已用真实核心验证顺序生效。
- 统计来自核心 info 日志中 `match …RuleSet,ad-xxx… using REJECT` 的连接，保留 14 天；「检测域名」直接查本地规则文件，并说明命中了哪个列表 / 被哪条白名单放行。
- 列表按设置的间隔自动更新；只有规则文件变化时仅刷新对应 rule-provider，不重载配置、不断开连接。
- 两个预设列表约 27 万条域名，实测核心内存增加约 50 MB、`mihomo -t` 约 1.2 秒，内存较小的设备建议只开一个列表。

### DNS 说明
- 设置 → DNS：直连 DNS（默认 doh.pub、alidns）用于国内域名与节点域名解析；代理 DNS（默认 `https://1.1.1.1/dns-query#🚀 节点选择`、`https://dns.google/dns-query#🚀 节点选择`，`#策略组` 表示查询经该组的节点发出）；默认 DNS 必须是 IP。
- 开启「按域名分流」时生成 `nameserver-policy`：`geosite:cn` → 直连 DNS，`geosite:geolocation-!cn` → 代理 DNS（按顺序匹配）。
- 增强模式 fake-ip / redir-host、Fake-IP 过滤列表、缓存算法 ARC / LRU 均可改；保存前做格式与策略组校验，再 `mihomo -t`，失败自动撤销；保存后清空 DNS / Fake-IP 缓存。
- 「DNS 查询」经核心 `/dns/query` 解析，显示状态码、耗时与全部记录，可用来确认分流与广告拦截是否生效。

### IPv6 说明
在“设置”里开启 IPv6 透明代理后，客户端还需要把本机当作 **IPv6 网关**（主路由的 RA 指向旁路由，或干脆关闭主路由 IPv6 只用 IPv4）。否则 IPv6 流量不会经过旁路由。

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
| `/etc/mihomo-panel/adblock_stats.json` | 广告拦截统计（保留 14 天） |
| `/etc/mihomo/adblock/` | 转换后的广告拦截规则文件与 meta.json |
| `/etc/mihomo-panel/cert.pem` `key.pem` | HTTPS 自签名证书（开启 HTTPS 时生成） |
| `/opt/mihomo-panel/` | 面板程序 |
| `/var/log/mihomo.log` | 核心日志 |

## 常用命令
```sh
rc-service mihomo restart        # 重启核心
rc-service mihomo-panel restart  # 重启面板
sh install.sh --update-core      # 升级 mihomo 核心
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
- 定时任务按旁路由本机时区执行（Alpine 默认 UTC，可 `setup-timezone -z Asia/Shanghai`）。

## 端口
- 8080 面板 · 7890 mixed (HTTP/SOCKS) · 7893 TProxy · 1053 DNS · 9090 控制器（仅本机）
