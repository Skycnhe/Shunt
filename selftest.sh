#!/bin/sh
# 用真实 mihomo 核心校验面板生成的配置（多种场景）。
# 用法: sh selftest.sh            （设备上默认使用 /usr/local/bin/mihomo 与 /etc/mihomo 下的 GEO 数据）
#       MIHOMO_BIN=/tmp/mihomo GEO_DIR=/tmp/geo sh selftest.sh
# 装有 sing-box（SB_BIN，默认 /usr/local/bin/sing-box）时，同样的场景再生成 sing-box 配置并用 sing-box check 校验；
# 规则集文件取自 SB_RULES（默认 /etc/sing-box/rules），缺少的会下载一次
SRC="$(cd "$(dirname "$0")" && pwd)"
[ -f "$SRC/server.py" ] || SRC=/opt/mihomo-panel
MIHOMO_BIN="${MIHOMO_BIN:-/usr/local/bin/mihomo}"
GEO_DIR="${GEO_DIR:-/etc/mihomo}"
WORK="$(mktemp -d /tmp/mihomo-selftest.XXXXXX)"
[ -n "$KEEP" ] || trap 'rm -rf "$WORK"' EXIT
SB_BIN="${SB_BIN:-/usr/local/bin/sing-box}"
SB_RULES="${SB_RULES:-/etc/sing-box/rules}"
[ -x "$MIHOMO_BIN" ] || [ -x "$SB_BIN" ] || { echo "找不到 mihomo（$MIHOMO_BIN）或 sing-box（$SB_BIN）"; exit 1; }
[ -x "$MIHOMO_BIN" ] && echo ">> mihomo: $("$MIHOMO_BIN" -v | head -n1)" || echo ">> 未安装 mihomo，跳过 mihomo 校验"
[ -x "$SB_BIN" ] && echo ">> sing-box: $("$SB_BIN" version | head -n1)" || echo ">> 未安装 sing-box，跳过 sing-box 校验"

cat > "$WORK/links.txt" <<'EOF'
vless://b831381d-6324-4d53-ad4f-8cda48b30811@hk1.example.com:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2&type=tcp&flow=xtls-rprx-vision#香港 Reality
vless://b831381d-6324-4d53-ad4f-8cda48b30811@jp.example.com:443?encryption=none&security=tls&sni=jp.example.com&type=ws&host=jp.example.com&path=%2Fws#日本 WS
vless://b831381d-6324-4d53-ad4f-8cda48b30811@sg.example.com:443?security=tls&type=grpc&serviceName=grpcsvc&sni=sg.example.com#SG gRPC
vmess://eyJ2IjoiMiIsInBzIjoi576O5Zu9IFZNZXNzIiwiYWRkIjoidXMuZXhhbXBsZS5jb20iLCJwb3J0IjoiNDQzIiwiaWQiOiJiODMxMzgxZC02MzI0LTRkNTMtYWQ0Zi04Y2RhNDhiMzA4MTEiLCJhaWQiOiIwIiwic2N5IjoiYXV0byIsIm5ldCI6IndzIiwidHlwZSI6Im5vbmUiLCJob3N0IjoidXMuZXhhbXBsZS5jb20iLCJwYXRoIjoiL3ZtZXNzIiwidGxzIjoidGxzIiwic25pIjoidXMuZXhhbXBsZS5jb20ifQ==
ss://YWVzLTI1Ni1nY206cGFzc3dvcmQxMjM=@ss.example.com:8388#SS Base64
ss://2022-blake3-aes-128-gcm:YctPZ6U7xPPcU%2Bgp3u%2BRaQ%3D%3D@ss2.example.com:8388#SS2022
ss://YWVzLTEyOC1nY206dGVzdA@obfs.example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dwww.bing.com#SS obfs
trojan://password@tw.example.com:443?sni=tw.example.com&type=ws&path=%2Ftrojan&host=tw.example.com#台湾 Trojan
hysteria2://hypass@hy.example.com:443?sni=hy.example.com&obfs=salamander&obfs-password=obfspw&insecure=1#HY2 Japan
hy2://pw@hp.example.com:443,20000-30000/?sni=hp.example.com#HY2 hop
tuic://b831381d-6324-4d53-ad4f-8cda48b30811:tuicpw@tuic.example.com:443?congestion_control=bbr&alpn=h3&sni=tuic.example.com&udp_relay_mode=native#TUIC US
EOF

# 生成各场景的 data.json
python3 - "$SRC" "$WORK" <<'EOF'
import json, os, re, sys
src, work = sys.argv[1], sys.argv[2]
os.environ["PANEL_OFFLINE"] = "1"  # 不读取正在运行的核心的订阅节点
sys.path.insert(0, src)
import server
nodes, errs = server.add_links(open(os.path.join(work, "links.txt")).read(), [])
assert not errs, errs
sub = {"name": "机场A", "url": "https://example.com/sub?token=x", "filter": "", "exclude": server.DEFAULT_EXCLUDE}
sub2 = {"name": "机场 B", "url": "https://example.org/clash", "filter": "(?i)港|日|新", "exclude": "(?i)剩余|到期|0\\.1x"}
rs = [{"name": "广告拦截", "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/category-ads-all.mrs", "behavior": "domain", "format": "mrs", "target": "REJECT"},
      {"name": "OpenAI", "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/openai.mrs", "behavior": "domain", "format": "mrs", "target": "🤖 AI 服务"},
      {"name": "telegram-ip", "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geoip/telegram.mrs", "behavior": "ipcidr", "format": "mrs", "target": "🇯🇵 日本"}]
rules = ["DOMAIN-SUFFIX,openai.com,🤖 AI 服务", "DOMAIN-KEYWORD,steam,DIRECT", "IP-CIDR,1.1.1.1/32,🚀 节点选择,no-resolve",
         "DOMAIN,example.com,不存在的组", "# 注释行"]
scen = {
    "1-无订阅": {},
    "2-订阅+过滤": {"subs": [sub, sub2]},
    "3-手动节点": {"nodes": nodes},
    "4-订阅+节点+规则集+自定义规则": {"subs": [sub], "nodes": nodes, "rulesets": rs, "rules": rules},
    "5-IPv6": {"subs": [sub], "nodes": nodes, "ipv6": True},
    "6-仅节点无地区分组+全局": {"nodes": nodes[:2], "region_groups": False, "mode": "global", "rulesets": rs},
    "7-规则集无节点": {"rulesets": rs, "rules": rules[:2]},
}
# ---- v4 新增场景：TUN / 广告拦截 / 自定义 DNS
tun = lambda stack, **kw: dict({"stack": stack, "device": "Meta", "auto_redirect": True, "strict_route": False}, **kw)
FILTER = """! AdGuard 语法
||doubleclick.net^
||ads.example.com^$important
@@||ok.ads.example.com^
||x.com^$client=1.2.3.4
/regex-ignored/
# hosts 语法
0.0.0.0 tracker.example.org analytics.example.net
127.0.0.1 localhost
plain-ad.example.cn
"""
ab_lists = [{"id": server.list_id("https://example.com/a.txt"), "name": "示例 A", "url": "https://example.com/a.txt", "enabled": True},
            {"id": server.list_id("https://example.com/b.txt"), "name": "示例 B", "url": "https://example.com/b.txt", "enabled": True},
            {"id": server.list_id("https://example.com/c.txt"), "name": "未下载", "url": "https://example.com/c.txt", "enabled": True}]
adblock = {"enabled": True, "lists": ab_lists, "black": ["evil.example.com", "||pop.example.net^"],
           "white": ["safe.doubleclick.net", "@@||analytics.example.net^"], "interval": 86400, "dns": False}
dns_custom = {"direct": ["223.5.5.5", "tls://dot.pub", "https://dns.alidns.com/dns-query"],
              "proxy": ["https://1.1.1.1/dns-query#🇭🇰 香港", "tls://8.8.8.8#不存在的组"], "default": ["223.5.5.5", "tls://1.12.12.12"],
              "mode": "redir-host", "fake_filter": [], "cache": "lru", "policy": True}
scen.update({
    "8-TUN-gvisor+绕过设备": {"nodes": nodes, "proxy_mode": "tun", "tun": tun("gvisor"), "bypass": ["192.168.1.50", "10.0.0.0/24", "AA:BB:CC:DD:EE:FF"]},
    "9-TUN-system+IPv6+订阅": {"subs": [sub], "nodes": nodes[:3], "proxy_mode": "tun", "tun": tun("system", auto_redirect=False, strict_route=True), "ipv6": True},
    "10-TUN-mixed+无节点": {"proxy_mode": "tun", "tun": tun("mixed", device="utun_test!!")},
    "11-广告拦截(规则)": {"nodes": nodes, "adblock": adblock, "rules": rules},
    "12-广告拦截(DNS层)+TUN": {"nodes": nodes, "adblock": dict(adblock, dns=True), "proxy_mode": "tun", "tun": tun("mixed")},
    "13-广告拦截(仅自定义黑名单)": {"adblock": dict(adblock, lists=[], white=[])},
    "14-DNS-redir-host+自定义": {"nodes": nodes, "dns": dns_custom},
    "15-DNS-fake-ip+关闭分流": {"nodes": nodes, "dns": {"direct": ["https://doh.pub/dns-query"], "proxy": ["https://dns.google/dns-query#🚀 节点选择"],
                                "default": ["119.29.29.29"], "mode": "fake-ip", "fake_filter": ["+.lan", "+.example.com"], "cache": "arc", "policy": False}},
    "16-旧版数据(tproxy=false)": {"tproxy": False, "nodes": nodes[:1]},
})
# ---- v5 新增场景：地区负载均衡 / 地区主组类型 / 已知订阅节点 / 自定义策略组
ssn = lambda n, port: {"link": "", "proxy": {"name": n, "type": "ss", "server": "127.0.0.1", "port": port, "cipher": "aes-128-gcm",
                                              "password": "pw", "udp": True}}
multi = [ssn(n, 20000 + i) for i, n in enumerate(["🇺🇸 美国 01", "US 02 洛杉矶", "美国 03", "🇯🇵 日本 01", "JP 02 Osaka", "香港 01",
                                                   "🇰🇷 韩国 01", "Korea 02", "UK 01 London", "Russia 01", "Plus 节点", "Australia 1"])]
gcfg = lambda **kw: dict({"type": "url-test", "lb": True, "auto": True, "strategy": "consistent-hashing", "interval": 300,
                          "tolerance": 50, "url": "https://www.gstatic.com/generate_204", "extra": True, "other": True, "lazy": True}, **kw)
cg = lambda name, t, members, **kw: dict({"name": name, "type": t, "proxies": members, "filter": "", "subs": True, "expose": True, "icon": ""}, **kw)
customs = [
    cg("🎯 美日均衡", "load-balance", ["🇺🇸 美国自动优选", "🇯🇵 日本自动优选"], strategy="round-robin"),
    cg("🧷 粘性", "load-balance", [], filter="(?i)美国|US", strategy="sticky-sessions", interval=120),
    cg("🔗 一致性", "load-balance", ["⚖️ 美国负载均衡", "⚖️ 日本负载均衡"], strategy="consistent-hashing"),
    cg("🎮 游戏", "select", ["🇭🇰 香港自动优选", "DIRECT"], filter="(?i)香港|日本", icon="https://example.com/game.png"),
    cg("⚡ 低延迟", "url-test", [], filter="(?i)美国|日本", tolerance=80),
    cg("🧯 稳定优先", "fallback", ["🎯 美日均衡", "🇭🇰 香港自动优选", "DIRECT"]),
    cg("🔁 跟随节点选择", "select", ["🚀 节点选择", "🎮 游戏", "REJECT"], expose=False),
    cg("空筛选", "select", [], filter="根本不存在的节点XYZ", subs=False),
    cg("引用已消失的组", "select", ["🇫🇷 法国自动优选", "DIRECT"]),
    cg("🧭 跟随主选择", "select", ["🚀 节点选择", "🖐️ 手动选择", "🏠 直连"]),  # v6：节点选择不再含自定义组，加入候选的组也能引用它
]
crules = ["DOMAIN-SUFFIX,steampowered.com,🎮 游戏", "DOMAIN-SUFFIX,netflix.com,🎯 美日均衡", "DST-PORT,8099,⚖️ 美国负载均衡",
          "DOMAIN,x.com,🔁 跟随节点选择", "DOMAIN,y.com,🏠 直连", "DOMAIN,z.com,⚡ 全局自动选择"]
crs = [dict(rs[1], target="⚡ 低延迟")]
cdns = dict(dns_custom, proxy=["https://1.1.1.1/dns-query#🧯 稳定优先"])
A, LB = "自动优选", "负载均衡"
TAIL = ["🖐️ 手动选择", "⚡ 全局自动选择", "🏠 直连"]
EXPECT = {  # 场景名: (必须存在的组 {名称: [类型, 策略]}, 必须不存在的组[, 🚀 节点选择 的完整成员列表])
    "17-地区均衡(手动节点)": ({"🇺🇸 美国自动优选": ["url-test", None], "⚖️ 美国负载均衡": ["load-balance", "consistent-hashing"],
                         "⚖️ 日本负载均衡": ["load-balance", None], "⚖️ 韩国负载均衡": ["load-balance", None], "🌐 其他自动优选": ["url-test", None],
                         "🇷🇺 俄罗斯自动优选": ["url-test", None], "🇦🇺 澳大利亚自动优选": ["url-test", None], "🏠 直连": ["select", None],
                         "🖐️ 手动选择": ["select", None], "⚡ 全局自动选择": ["url-test", None]},
                        ["🇺🇸 美国", "🇺🇸 美国均衡", "♻️ 自动选择", "🇸🇬 新加坡自动优选", "🇹🇼 台湾自动优选"],
                        ["🇯🇵 日本" + A, "🇭🇰 香港" + A, "🇺🇸 美国" + A, "🇰🇷 韩国" + A, "🇬🇧 英国" + A, "🇦🇺 澳大利亚" + A, "🇷🇺 俄罗斯" + A,
                         "🌐 其他" + A, "⚖️ 香港" + LB, "⚖️ 日本" + LB, "⚖️ 美国" + LB, "⚖️ 韩国" + LB, "⚖️ 英国" + LB,
                         "⚖️ 澳大利亚" + LB, "⚖️ 俄罗斯" + LB, "⚖️ 其他" + LB] + TAIL),
    "18-均衡关闭+无扩展地区": ({"🇺🇸 美国自动优选": ["url-test", None], "🇭🇰 香港自动优选": ["url-test", None]},
                          ["⚖️ 美国负载均衡", "🌐 其他自动优选", "🇰🇷 韩国自动优选"], ["🇯🇵 日本" + A, "🇭🇰 香港" + A, "🇺🇸 美国" + A] + TAIL),
    "19-轮询策略+非懒惰": ({"⚖️ 美国负载均衡": ["load-balance", "round-robin"], "⚖️ 日本负载均衡": ["load-balance", "round-robin"]}, []),
    "20-关闭地区分组": ({"🖐️ 手动选择": ["select", None], "⚡ 全局自动选择": ["url-test", None]}, ["🇺🇸 美国自动优选"], TAIL),
    "21-订阅节点已知": ({"⚖️ 美国负载均衡": ["load-balance", None], "🇬🇧 英国自动优选": ["url-test", None], "🌐 其他自动优选": ["url-test", None],
                    "🇯🇵 日本自动优选": ["url-test", None], "⚖️ 日本负载均衡": ["load-balance", None]}, ["🇸🇬 新加坡自动优选", "🇹🇼 台湾自动优选", "🇭🇰 香港自动优选"]),
    "22-订阅未加载(旧行为)": ({"🇭🇰 香港自动优选": ["url-test", None], "🇸🇬 新加坡自动优选": ["url-test", None], "⚖️ 美国负载均衡": ["load-balance", None]},
                        ["🇬🇧 英国自动优选"]),
    "23-自定义策略组(全部类型)": ({"🎯 美日均衡": ["load-balance", "round-robin"], "🧷 粘性": ["load-balance", "sticky-sessions"],
                            "🔗 一致性": ["load-balance", "consistent-hashing"], "🎮 游戏": ["select", None],
                            "⚡ 低延迟": ["url-test", None], "🧯 稳定优先": ["fallback", None], "🔁 跟随节点选择": ["select", None],
                            "空筛选": ["select", None], "🧭 跟随主选择": ["select", None]}, []),
    "24-自定义组+订阅+TUN+嗅探关": ({"🎮 游戏": ["select", None], "🧷 粘性": ["load-balance", "sticky-sessions"]}, []),
    # v6：用户要求的 🚀 节点选择 结构
    "25-节点选择(日新港美各≥2)": ({}, [], ["🇯🇵 日本" + A, "🇸🇬 新加坡" + A, "🇭🇰 香港" + A, "🇺🇸 美国" + A,
                                          "⚖️ 香港" + LB, "⚖️ 日本" + LB, "⚖️ 新加坡" + LB, "⚖️ 美国" + LB] + TAIL),
    "26-单节点地区(新加坡、台湾各1)": ({"🇸🇬 新加坡自动优选": ["url-test", None], "⚖️ 新加坡负载均衡": ["load-balance", None],
                                   "⚖️ 台湾负载均衡": ["load-balance", None]}, [],
                                  ["🇯🇵 日本" + A, "🇸🇬 新加坡" + A, "🇭🇰 香港" + A, "🇺🇸 美国" + A, "🇹🇼 台湾" + A,
                                   "⚖️ 香港" + LB, "⚖️ 日本" + LB, "⚖️ 新加坡" + LB, "⚖️ 美国" + LB, "⚖️ 台湾" + LB] + TAIL),
    "27-无节点(只有直连)": ({"🏠 直连": ["select", None]}, ["🖐️ 手动选择", "⚡ 全局自动选择"], ["🏠 直连"]),
    "28-只有扩展地区": ({}, [], ["🇰🇷 韩国" + A, "🇬🇧 英国" + A, "⚖️ 韩国" + LB, "⚖️ 英国" + LB] + TAIL),
    "29-旧版名称迁移": ({"⚖️ 美国负载均衡": ["load-balance", None], "🎯 旧组": ["load-balance", None]},
                    ["🇺🇸 美国", "🇺🇸 美国均衡", "♻️ 自动选择"]),
}
scen.update({
    "17-地区均衡(手动节点)": {"nodes": multi},
    "18-均衡关闭+无扩展地区": {"nodes": multi, "groups_cfg": gcfg(type="select", lb=False, extra=False, other=False)},
    "19-轮询策略+非懒惰": {"nodes": multi, "groups_cfg": gcfg(type="load-balance", strategy="round-robin", lazy=False)},
    "20-关闭地区分组": {"nodes": multi, "region_groups": False, "groups_cfg": gcfg(interval=600, tolerance=0)},
    "21-订阅节点已知": {"subs": [sub], "nodes": multi[:3], "_prov": {"机场A": ["US 05", "US 06 Pro", "JP 03", "🇬🇧 英国 02", "Mars 01"]}},
    "22-订阅未加载(旧行为)": {"subs": [sub], "nodes": multi[:3]},
    "23-自定义策略组(全部类型)": {"nodes": multi, "custom_groups": customs, "rules": crules, "rulesets": crs, "dns": cdns},
    "24-自定义组+订阅+TUN+嗅探关": {"subs": [sub, sub2], "nodes": multi, "custom_groups": customs, "rules": crules,
                             "proxy_mode": "tun", "tun": tun("mixed"), "sniffer": False, "groups_cfg": gcfg(strategy="sticky-sessions")},
})
# 校验逻辑：重名 / 循环 / 成员不存在应被拒绝
server.PROV_FILE = os.path.join(work, "_none.json")
base = dict(server.DEFAULT, nodes=multi, subs=[], custom_groups=customs[:2])
bad_cases = {
    "循环": customs[:1] + [cg("A", "select", ["B"], expose=False), cg("B", "select", ["A"], expose=False)],
    "引用分流组且加入候选": [cg("X", "select", ["📹 YouTube"])],
    "重名": [customs[0], dict(customs[0])],
    "与地区组同名": [cg("⚖️ 美国负载均衡", "select", ["DIRECT"])],
    "与旧版地区组同名": [cg("🇺🇸 美国均衡", "select", ["DIRECT"])],
    "与直连组同名": [cg("🏠 直连", "select", ["DIRECT"])],
    "成员不存在": [cg("X", "select", ["不存在"])],
}
for k, v in bad_cases.items():
    assert server.validate_groups(dict(base, custom_groups=v)), "应拒绝：" + k
ok_errs = server.validate_groups(dict(base, custom_groups=customs[:7] + customs[9:]))
assert not ok_errs, ok_errs
for k in ("名称,逗号", "", "a#b"):
    try:
        server.clean_custom_group({"name": k, "type": "select", "proxies": ["DIRECT"]})
        raise AssertionError("应拒绝名称：" + k)
    except ValueError:
        pass
us = server.REGIONS[4][1]
assert not re.search(us, "Russia 01") and not re.search(us, "Plus") and re.search(us, "US01") and re.search(us, "美国 01")
print("策略组校验 ok", file=sys.stderr)
# ---- v6：节点选择新结构 / 迁移 / DNS 列表 / 防泄露
reg = lambda *pairs: [ssn(n, 21000 + i) for i, n in enumerate([x for p in pairs for x in p])]
JP2, SG2, HK2, US2 = ["🇯🇵 日本 01", "JP 02 Tokyo"], ["🇸🇬 新加坡 01", "SG 02"], ["🇭🇰 香港 01", "HK 02"], ["🇺🇸 美国 01", "US 02 LA"]
old_dns = dict(dns_custom, proxy=["https://1.1.1.1/dns-query#🇭🇰 香港", "https://dns.google/dns-query#♻️ 自动选择"], mode="fake-ip")
dns_lists = {"direct": ["https://doh.pub/dns-query", "223.5.5.5"], "proxy": ["https://1.1.1.1/dns-query#🚀 节点选择", "tls://8.8.8.8#⚖️ 美国负载均衡"],
             "default": ["223.5.5.5", "119.29.29.29"], "pserver": ["https://dns.alidns.com/dns-query", "119.29.29.29"], "mode": "fake-ip",
             "fake_filter": ["+.lan", "geosite:connectivity-check", "+.corp.example"], "cache": "lru", "policy": True, "respect_rules": True,
             "block_bypass": False,
             "hosts": [{"domain": "nas.lan", "value": ["192.168.1.10"]}, {"domain": "+.dev.test", "value": ["10.0.0.1", "10.0.0.2"]},
                       {"domain": "alias.test", "value": ["www.baidu.com"]}],
             "policies": [{"match": "geosite:apple,microsoft@cn", "servers": ["https://doh.pub/dns-query"]},
                          {"match": "+.corp.example,intranet.example", "servers": ["10.0.0.53", "udp://10.0.0.54:53"]},
                          {"match": "geosite:openai", "servers": ["https://1.1.1.1/dns-query#🇺🇸 美国自动优选"]},
                          {"match": "+.blocked.example", "servers": ["rcode://success"]}]}
leaky = {"direct": ["223.5.5.5"], "proxy": ["119.29.29.29", "https://dns.google/dns-query"], "default": ["223.5.5.5"], "mode": "redir-host",
         "respect_rules": False, "policy": False, "block_bypass": False,
         "policies": [{"match": "geosite:google", "servers": ["223.5.5.5"]}, {"match": "geosite:cn", "servers": ["119.29.29.29"]}]}
scen.update({
    "25-节点选择(日新港美各≥2)": {"nodes": reg(JP2, SG2, HK2, US2)},
    "26-单节点地区(新加坡、台湾各1)": {"nodes": reg(JP2, SG2[:1], HK2 + ["香港 03"], US2, ["台湾 01"])},
    "27-无节点(只有直连)": {"rules": ["DOMAIN,a.com,🏠 直连", "DOMAIN,b.com,🖐️ 手动选择"]},
    "28-只有扩展地区": {"nodes": reg(["🇰🇷 韩国 01", "Korea 02"], ["UK 01 London"])},
    "29-旧版名称迁移": {"nodes": reg(US2, JP2, HK2[:1]), "rules": ["DST-PORT,8099,🇺🇸 美国均衡", "DOMAIN,x.com,♻️ 自动选择", "DOMAIN,y.com,🇭🇰 香港"],
                    "rulesets": [dict(rs[2], target="🇯🇵 日本")], "dns": old_dns, "groups_cfg": gcfg(type="fallback", auto=True),
                    "custom_groups": [cg("🎯 旧组", "load-balance", ["🇺🇸 美国", "🇯🇵 日本均衡", "♻️ 自动选择", "🇭🇰 香港自动"], expose=False)]},
    "30-DNS列表+hosts+策略": {"nodes": reg(US2, JP2), "dns": dns_lists},
    "31-防泄露预设+阻止绕过+IPv6+TUN": {"nodes": reg(US2, HK2), "ipv6": True, "proxy_mode": "tun", "tun": tun("mixed"),
                                  "dns": server.antileak_dns(server.dns_cfg({"dns": leaky}))},
    "32-redir-host+无代理DNS": {"nodes": reg(US2), "dns": {"direct": ["223.5.5.5"], "proxy": [], "default": ["223.5.5.5"], "mode": "redir-host",
                                                        "respect_rules": False, "policy": True}},
    "33-阻止绕过+广告DNS拦截": {"nodes": reg(JP2), "adblock": dict(adblock, dns=True), "dns": dict(dns_lists, block_bypass=True)},
})
# 迁移：旧数据经 load() 后引用全部换成新名称
import tempfile
tmpd = tempfile.mkdtemp()
server.DATA_FILE = os.path.join(tmpd, "data.json")
json.dump(dict(password="x", secret="s", **scen["29-旧版名称迁移"]), open(server.DATA_FILE, "w"), ensure_ascii=False)
m = server.load()
assert m["rules"] == ["DST-PORT,8099,⚖️ 美国负载均衡", "DOMAIN,x.com,⚡ 全局自动选择", "DOMAIN,y.com,🇭🇰 香港自动优选"], m["rules"]
assert m["rulesets"][0]["target"] == "🇯🇵 日本自动优选"
assert m["custom_groups"][0]["proxies"] == ["🇺🇸 美国自动优选", "⚖️ 日本负载均衡", "⚡ 全局自动选择", "🇭🇰 香港自动优选"], m["custom_groups"][0]["proxies"]
assert m["dns"]["proxy"] == ["https://1.1.1.1/dns-query#🇭🇰 香港自动优选", "https://dns.google/dns-query#⚡ 全局自动选择"], m["dns"]["proxy"]
assert m["schema"] == server.SCHEMA and json.load(open(server.DATA_FILE))["schema"] == server.SCHEMA
assert server.legacy_map()["🌐 其他均衡"] == "⚖️ 其他负载均衡" and server.legacy_map()["🇺🇸 美国自动"] == "🇺🇸 美国自动优选"
# 改名 / 删除自定义组同步 DNS 策略里的引用
t = json.loads(json.dumps({"rules": ["DOMAIN,a.com,G1"], "rulesets": [], "custom_groups": [cg("H", "select", ["G1", "DIRECT"])],
                           "dns": dict(dns_lists, policies=[{"match": "+.a.com", "servers": ["https://1.1.1.1/dns-query#G1"]}], pserver=[])}))
assert server.rename_policy(t, "G1", "G2") == 3 and t["dns"]["policies"][0]["servers"] == ["https://1.1.1.1/dns-query#G2"]
assert server.rename_policy(t, "G2", "🚀 节点选择") == 3 and t["custom_groups"][0]["proxies"] == ["DIRECT"]
# DNS 校验
vbase = dict(server.DEFAULT, nodes=reg(US2), subs=[], custom_groups=[])
assert not server.validate_dns(server.dns_cfg({"dns": dns_lists}), vbase), server.validate_dns(server.dns_cfg({"dns": dns_lists}), vbase)
bad_dns = {
    "错误协议": {"direct": ["ftp://1.2.3.4"]}, "默认 DNS 非 IP": {"default": ["https://dns.google/dns-query"]},
    "节点解析带策略组": {"pserver": ["https://doh.pub/dns-query#🚀 节点选择"]}, "策略组不存在": {"proxy": ["https://1.1.1.1/dns-query#不存在"]},
    "hosts 域名": {"hosts": [{"domain": "bad domain", "value": ["1.1.1.1"]}]}, "hosts 值": {"hosts": [{"domain": "a.lan", "value": ["999.1.1.1x"]}]},
    "hosts 多别名": {"hosts": [{"domain": "a.lan", "value": ["a.com", "b.com"]}]},
    "策略匹配项": {"policies": [{"match": "geo site:x", "servers": ["223.5.5.5"]}]},
    "策略混用": {"policies": [{"match": "geosite:apple,+.a.com", "servers": ["223.5.5.5"]}]},
    "策略 DNS": {"policies": [{"match": "+.a.com", "servers": ["ftp://x"]}]},
    "策略重复": {"policies": [{"match": "+.a.com", "servers": ["223.5.5.5"]}, {"match": "+.a.com", "servers": ["1.1.1.1"]}]},
    "策略引用不存在的组": {"policies": [{"match": "+.a.com", "servers": ["tls://1.1.1.1#没有这个组"]}]},
    "直连为空": {"direct": []},
}
for k, v in bad_dns.items():
    assert server.validate_dns(server.dns_cfg({"dns": dict(dns_lists, **v)}), vbase), "应拒绝 DNS：" + k
# 防泄露预设
pre = server.antileak_dns(server.dns_cfg({"dns": leaky}))
assert pre["proxy"] == ["https://dns.google/dns-query#🚀 节点选择"], pre["proxy"]
assert pre["mode"] == "fake-ip" and pre["respect_rules"] and pre["policy"] and pre["block_bypass"]
assert [p["match"] for p in pre["policies"]] == ["geosite:cn"], pre["policies"]
assert server.dns_cfg({"dns": {"policies": [{"match": "geosite:apple, geosite:microsoft@cn", "servers": "223.5.5.5"}]}})["policies"][0]["match"] == "geosite:apple,microsoft@cn"
server.DATA_FILE = os.path.join(tmpd, "leak.json")
server.TPROXY_SH = "true"
json.dump(dict(password="x", secret="s", nodes=reg(US2), proxy_mode="off", dns=leaky), open(server.DATA_FILE, "w"), ensure_ascii=False)
r1 = server.leak_check(live=False)
json.dump(dict(password="x", secret="s", nodes=reg(US2), proxy_mode="off", dns=pre), open(server.DATA_FILE, "w"), ensure_ascii=False)
r2 = server.leak_check(live=False)
assert r1["bad"] >= 2 and r2["bad"] == 0, (r1["bad"], r2["bad"], [x for x in r2["items"] if x["ok"] is False])
rt = server.dns_route("x.dev.test", {"dns": dns_lists})
assert rt.startswith("hosts") and server.dns_route("a.corp.example", {"dns": dns_lists}).startswith("自定义策略 +.corp.example"), rt
print("迁移 / DNS / 防泄露校验 ok", file=sys.stderr)
for name, extra in scen.items():
    extra = dict(extra)
    prov = extra.pop("_prov", None)
    d = dict(password="x", secret="selftest", **extra)
    os.makedirs(os.path.join(work, name))
    json.dump(d, open(os.path.join(work, name, "data.json"), "w"), ensure_ascii=False)
    if prov is not None:
        json.dump(prov, open(os.path.join(work, name, "provider_nodes.json"), "w"), ensure_ascii=False)
    # sing-box：订阅由面板下载解析，这里放入模拟的订阅缓存（多种协议 + 不支持的协议）
    if extra.get("subs"):
        os.makedirs(os.path.join(work, name, "sb_subs"))
        for s_ in extra["subs"]:
            if prov is not None:
                ns = [ssn(n, 22000 + i)["proxy"] for i, n in enumerate(prov.get(s_["name"], []))]
            else:
                ns = [dict(n["proxy"]) for n in nodes] + [dict(m["proxy"]) for m in multi[:6]] + \
                     [{"name": "WG 不支持", "type": "wireguard", "server": "1.1.1.1", "port": 1}]
            json.dump({"name": s_["name"], "updated": 1, "nodes": ns}, open(os.path.join(work, name, "sb_subs", server.safe(s_["name"]) + ".json"), "w"), ensure_ascii=False)
    if name in EXPECT:
        json.dump(EXPECT[name], open(os.path.join(work, name, "expect.json"), "w"), ensure_ascii=False)
    if extra.get("adblock"):  # 生成本地规则文件（离线，不下载）
        server.AB_DIR = os.path.join(work, name, "adblock")
        bs, be, as_, ae, _ = server.parse_filter(FILTER)
        for l in ab_lists[:2]:
            server.write_lines(os.path.join(server.AB_DIR, l["id"] + ".txt"), server.domain_lines(bs, be)[0])
            server.write_lines(os.path.join(server.AB_DIR, l["id"] + ".allow.txt"), server.domain_lines(as_, ae)[0])
        server.ab_compose(dict(extra, adblock=extra["adblock"]))
print("\n".join(scen))
EOF
[ $? = 0 ] || { echo "生成场景失败"; exit 1; }

PASS=0; FAIL=0
[ -x "$MIHOMO_BIN" ] && for d in "$WORK"/*/; do
  d=${d%/}; n=$(basename "$d")
  for f in geoip.dat geosite.dat geoip.metadb; do [ -f "$GEO_DIR/$f" ] && ln -sf "$GEO_DIR/$f" "$d/$f"; done
  PANEL_OFFLINE=1 MIHOMO_DIR="$d" PANEL_DATA="$d/data.json" python3 "$SRC/server.py" --gen >/dev/null || { echo "✗ $n: server.py --gen 失败"; FAIL=$((FAIL+1)); continue; }
  if ! CHK=$(python3 - "$d" 2>&1 <<'PY'
import json, sys
d = sys.argv[1]
c, data = json.load(open(d + "/config.yaml")), json.load(open(d + "/data.json"))
mode = data.get("proxy_mode") or ("tproxy" if data.get("tproxy", True) else "off")
assert c["tun"]["enable"] == (mode == "tun"), "TUN 开关与代理方式不一致"
if mode == "tun":
    assert c["tun"]["auto-route"] and c["tun"]["dns-hijack"], "TUN 缺少 auto-route / dns-hijack"
    assert all(r.startswith("SRC-IP-CIDR") for r in c["rules"][:len([b for b in data.get("bypass", []) if ":" not in b or "/" in b])]), "绕过设备规则缺失"
ab = data.get("adblock") or {}
if ab.get("enabled"):
    rej = [r for r in c["rules"] if "ad-" in r and r.endswith("REJECT")]
    assert rej, "广告拦截规则缺失"
    assert c["rules"].index(rej[0]) < len(c["rules"]) - 5, "广告规则位置异常"
    if ab.get("white") or ab.get("lists"):
        assert "ad-allow" in c["rule-providers"] and all("NOT,((RULE-SET,ad-allow))" in r for r in rej), "白名单未优先"
    assert ("rcode://name_error" in json.dumps(c["dns"].get("nameserver-policy", {}))) == bool(ab.get("dns")), "DNS 层拦截开关不一致"
# v5：策略组成员都存在、负载均衡带策略、规则引用的策略存在、预期的分组生成 / 不生成
groups = {g["name"]: g for g in c["proxy-groups"]}
names = set(groups) | {p["name"] for p in c["proxies"]} | {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}
for g in c["proxy-groups"]:
    assert g.get("proxies") or g.get("use"), "策略组 %s 没有成员" % g["name"]
    for m in g.get("proxies") or []:
        assert m in names, "%s 的成员 %s 不存在" % (g["name"], m)
    if g["type"] == "load-balance":
        assert g.get("strategy") in ("consistent-hashing", "round-robin", "sticky-sessions"), "负载均衡缺少策略"
for r in c["rules"]:
    if r.startswith(("AND,", "OR,", "NOT,")):
        continue
    parts = [x for x in r.split(",") if x not in ("no-resolve", "src")]
    assert parts[-1] in names, "规则引用了不存在的策略：" + r
assert c["sniffer"]["enable"] == data.get("sniffer", True), "嗅探开关不一致"
# v6：节点选择只含 地区自动优选 → 地区负载均衡 → 手动 / 全局 / 直连
sel = groups["🚀 节点选择"]["proxies"]
kinds = ["a" if x.endswith("自动优选") else "l" if x.startswith("⚖️ ") else "t" for x in sel]
assert kinds == sorted(kinds), "节点选择顺序错误：%s" % sel
assert sel[-1] == "🏠 直连" and groups["🏠 直连"]["proxies"] == ["DIRECT"], "缺少 🏠 直连"
assert all(x in ("🖐️ 手动选择", "⚡ 全局自动选择", "🏠 直连") for x, k in zip(sel, kinds) if k == "t"), "节点选择含多余成员：%s" % sel
assert not any(g in groups for g in ("♻️ 自动选择",)), "仍有旧版组名"
# v6：DNS 防泄露布局
dn, dd = c["dns"], data.get("dns") or {}
assert "fallback" not in dn and dn["prefer-h3"] is False and dn["use-system-hosts"] is False, "DNS 存在泄露风险项"
assert dn["proxy-server-nameserver"] and all("#" not in x for x in dn["proxy-server-nameserver"]), "proxy-server-nameserver 异常"
assert dn["direct-nameserver"] and dn["ipv6"] == bool(data.get("ipv6")), "direct-nameserver / ipv6 不一致"
if dd.get("proxy", [1]):
    assert all(x.endswith(("#🚀 节点选择", "#⚖️ 美国负载均衡")) or "#" in x for x in dn["nameserver"]), "默认 nameserver 应为代理 DNS：%s" % dn["nameserver"]
    if dd.get("policy", True):
        assert "geosite:cn,private" in dn.get("nameserver-policy", {}), "缺少 geosite:cn 直连策略"
    assert "geosite:geolocation-!cn" not in dn.get("nameserver-policy", {}), "仍使用旧版白名单分流"
for pe in dd.get("policies") or []:
    assert pe["match"] in dn["nameserver-policy"], "自定义 DNS 策略缺失：" + pe["match"]
for h in dd.get("hosts") or []:
    assert h["domain"] in c["hosts"], "hosts 缺失：" + h["domain"]
guard = [r for r in c["rules"] if "IN-TYPE,TPROXY/TUN/REDIR" in r]
assert bool(guard) == bool(dd.get("block_bypass")), "阻止客户端绕过 DNS 规则与开关不一致"
if guard:
    assert c["rules"].index(guard[0]) <= len([r for r in c["rules"] if r.startswith("SRC-IP-CIDR")]), "绕过拦截规则应排在最前"
    assert c["rule-providers"]["dns-bypass-ip"]["type"] == "inline"
import os
if os.path.isfile(d + "/expect.json"):
    exp = json.load(open(d + "/expect.json"))
    must, mustnot = exp[0], exp[1]
    if len(exp) > 2:
        assert groups["🚀 节点选择"]["proxies"] == exp[2], "🚀 节点选择 成员不符：%s" % groups["🚀 节点选择"]["proxies"]
    for n, (t, st) in must.items():
        assert n in groups, "缺少策略组 " + n
        assert groups[n]["type"] == t, "%s 类型应为 %s，实际 %s" % (n, t, groups[n]["type"])
        assert st is None or groups[n].get("strategy") == st, "%s 策略应为 %s" % (n, st)
    for n in mustnot:
        assert n not in groups, "不应生成策略组 " + n
print("ok")
PY
); then echo "✗ $n: 生成结果断言失败"; echo "$CHK" | tail -n 2; FAIL=$((FAIL+1)); continue; fi
  if OUT=$(timeout 120 "$MIHOMO_BIN" -t -d "$d" -f "$d/config.yaml" 2>&1); then
    echo "✓ $n"; PASS=$((PASS+1))
  else
    echo "✗ $n"; echo "$OUT" | grep -iE 'error|fatal|fail' | tail -n 5; FAIL=$((FAIL+1))
  fi
done

# ---------------------------------------------------------------- sing-box
if [ -x "$SB_BIN" ]; then
  mkdir -p "$SB_RULES" 2>/dev/null || SB_RULES="$WORK/_sbrules"
  for d in "$WORK"/*/; do
    d=${d%/}; n=$(basename "$d")
    case "$n" in _*) continue;; esac
    if ! OUT=$(PANEL_OFFLINE=1 SB_DIR="$d/sb" SB_RULES="$SB_RULES" MIHOMO_DIR="$d" PANEL_DATA="$d/data.json" python3 - "$SRC" "$d" 2>&1 <<'PY'
import json, os, sys
src, d = sys.argv[1], sys.argv[2]
sys.path.insert(0, src)
import server
server.core_alive = lambda: False
data = server.load()
server.AB_DIR = os.path.join(d, "adblock")
conf, warn, need = server.build_singbox(data)
bad = server.sb_sync_assets(data, need=need)
assert not bad, "规则集下载失败：%s" % bad
conf, warn, need = server.build_singbox(data)
os.makedirs(server.SB_DIR, exist_ok=True)
json.dump(conf, open(os.path.join(server.SB_DIR, "config.json"), "w"), ensure_ascii=False, indent=1)
tags = {o["tag"] for o in conf["outbounds"]}
for o in conf["outbounds"]:
    assert o["type"] not in ("loadbalance",), o
    if o.get("outbounds") is not None:
        assert o["outbounds"], "%s 没有成员" % o["tag"]
        for m_ in o["outbounds"]:
            assert m_ in tags, "%s 的成员 %s 不存在" % (o["tag"], m_)
assert not any(t.startswith("⚖️ ") and t.endswith("负载均衡") for t in tags), "地区负载均衡组应并入自动优选"
def walk(rs):
    for r in rs:
        if r.get("type") == "logical":
            walk(r["rules"])
        for k in r.get("rule_set") or []:
            assert k in {x["tag"] for x in conf["route"]["rule_set"]}, "规则集未定义：" + k
        if r.get("outbound"):
            assert r["outbound"] in tags, "规则引用了不存在的出站：%s" % r
walk(conf["route"]["rules"]); walk(conf["dns"]["rules"])
assert conf["route"]["final"] in tags
mode = data.get("proxy_mode") or ("tproxy" if data.get("tproxy", True) else "off")
assert any(i["type"] == "tun" for i in conf["inbounds"]) == (mode == "tun"), "TUN 入站与代理方式不一致"
dm = server.dns_cfg(data)["mode"]
assert any(s["type"] == "fakeip" for s in conf["dns"]["servers"]) == (dm == "fake-ip"), "Fake-IP 与 DNS 模式不一致"
assert conf["experimental"]["clash_api"]["external_controller"]
print("warn:", len(warn), "|", "；".join(warn)[:160])
PY
); then echo "✗ [sing-box] $n: 生成失败"; echo "$OUT" | tail -n 3; FAIL=$((FAIL+1)); continue; fi
    if CK=$(timeout 120 "$SB_BIN" check -c "$d/sb/config.json" -D "$d/sb" 2>&1); then
      echo "✓ [sing-box] $n  $(echo "$OUT" | grep '^warn:' | cut -c1-60)"; PASS=$((PASS+1))
    else
      echo "✗ [sing-box] $n"; echo "$CK" | tail -n 3; FAIL=$((FAIL+1))
    fi
  done
fi
echo ">> 通过 $PASS，失败 $FAIL"
[ "$FAIL" = 0 ]
