# shunt/：面板后端源码

按功能拆成的 Python 包，每个模块都有自己的命名空间。设备上运行的是仓库根目录的 `server.py`，它由 `tools/build.py` 生成，**内嵌了本目录全部模块的源码**，所以部署时仍然只有一个文件：旧版面板的在线更新、install.sh、离线包都不受影响。

```sh
python3 tools/build.py          # 改完 shunt/ 后重新生成 server.py（两者一起提交）
python3 tools/build.py --check  # 检查是否一致（CI 会跑）
python3 tools/build.py --split  # 直接改了 server.py 时，把内嵌源码写回 shunt/
```

## 模块间引用

- 引用**排在前面**的模块：文件开头直接 `from .base import X`
- 引用**排在后面**的模块：写在文件末尾的 `_link()` 里（如 core、devroute）（`global X` + `from .later import X`），由 `shunt.load()` 在全部模块加载后调用，避免循环导入
- 加载顺序见 `__init__.py` 的 `MODULES`；模块顶层代码只能用到排在前面的模块
- 运行中需要整体替换的全局对象（如统计实例 `stats.STATS`、`adblock.AD_STATS`）通过模块属性访问，不要 from-import
- 测试打桩：`server.X = ...` 会同时改掉所有模块里的同名变量（`shunt.setvar`）

## 模块

| 模块 | 内容 |
|---|---|
| base | 路径、常量、预设、通用工具 |
| errlog | 错误记录（log_err，进日志和诊断页） |
| data | 数据读写、迁移、组名 |
| links | 节点链接解析 |
| groups | 策略组 |
| devroute | 按设备分流：设备（IP / 网段 / MAC）→ 策略组 / 直连 / 拦截，MAC 解析成当前 IP，生成 SRC-IP-CIDR 规则 |
| mihomo | 生成 mihomo 配置、DNS 校验 |
| validate | /api/settings、/api/restore 的数据形状校验（坏条目 400，不写入） |
| core | 与内核交互（API、重载） |
| sb_common / sb_yaml / sb_subs / sb_nodes / sb_rules / sb_dns / sb_config / sb_switch | sing-box：公共、YAML 解析、订阅、节点转换、规则转换、DNS、生成配置、内核切换 |
| panel_update / core_update | 面板在线更新（按 update-files.txt）、内核更新 |
| sysopt | Alpine 系统优化、测速 |
| notify / latency / stats / unlock / ruletest / logstream | Telegram 与故障直连、延迟缓存、流量统计、流媒体解锁、规则测试、实时日志 |
| adblock / live / logclean / schedule / devices / diag / dnsleak | 广告拦截、实时速率、日志清理、定时任务、设备名、网络诊断、DNS 防泄露 |
| migrate / https / access / update_guard / svcmigrate | 升级迁移、HTTPS、访问控制、更新回滚守护、服务改名迁移（mihomo-panel → shunt） |
| static / webapi / cli | 静态资源、HTTP 接口（`@api_route` 路由表）、命令行入口 |

## 前端与测试

- 前端源码在 `web/`：`index.html` 模板 + `style.css` + `js/NN-*.js`（按页面分），`tools/build.py` 合并成根目录的单文件 `index.html`
- 单元测试在 `tests/`：`python3 -m unittest discover -s tests -t .`；端到端测试仍是 `selftest.sh`
- 新增接口：在 `webapi.py` 的类 H 里加一个 `@api_route("/api/xxx", "GET")` 方法
