#!/bin/sh
# 用真实 mihomo 核心校验面板生成的配置（多种场景）。
# 用法: sh selftest.sh            （设备上默认使用 /usr/local/bin/mihomo 与 /etc/mihomo 下的 GEO 数据）
#       MIHOMO_BIN=/tmp/mihomo GEO_DIR=/tmp/geo sh selftest.sh
SRC="$(cd "$(dirname "$0")" && pwd)"
[ -f "$SRC/server.py" ] || SRC=/opt/mihomo-panel
MIHOMO_BIN="${MIHOMO_BIN:-/usr/local/bin/mihomo}"
GEO_DIR="${GEO_DIR:-/etc/mihomo}"
WORK="$(mktemp -d /tmp/mihomo-selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
[ -x "$MIHOMO_BIN" ] || { echo "找不到 mihomo 核心：$MIHOMO_BIN"; exit 1; }
echo ">> mihomo: $("$MIHOMO_BIN" -v | head -n1)"

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
    cg("🎯 美日均衡", "load-balance", ["🇺🇸 美国", "🇯🇵 日本"], strategy="round-robin"),
    cg("🧷 粘性", "load-balance", [], filter="(?i)美国|US", strategy="sticky-sessions", interval=120),
    cg("🔗 一致性", "load-balance", ["🇺🇸 美国均衡", "🇯🇵 日本均衡"], strategy="consistent-hashing"),
    cg("🎮 游戏", "select", ["🇭🇰 香港", "DIRECT"], filter="(?i)香港|日本", icon="https://example.com/game.png"),
    cg("⚡ 低延迟", "url-test", [], filter="(?i)美国|日本", tolerance=80),
    cg("🧯 稳定优先", "fallback", ["🎯 美日均衡", "🇭🇰 香港", "DIRECT"]),
    cg("🔁 跟随节点选择", "select", ["🚀 节点选择", "🎮 游戏", "REJECT"], expose=False),
    cg("空筛选", "select", [], filter="根本不存在的节点XYZ", subs=False),
    cg("引用已消失的组", "select", ["🇫🇷 法国", "DIRECT"]),
]
crules = ["DOMAIN-SUFFIX,steampowered.com,🎮 游戏", "DOMAIN-SUFFIX,netflix.com,🎯 美日均衡", "DST-PORT,8099,🇺🇸 美国均衡",
          "DOMAIN,x.com,🔁 跟随节点选择"]
crs = [dict(rs[1], target="⚡ 低延迟")]
cdns = dict(dns_custom, proxy=["https://1.1.1.1/dns-query#🧯 稳定优先"])
EXPECT = {  # 场景名: (必须存在的组 {名称: [类型, 策略]}, 必须不存在的组)
    "17-地区均衡(手动节点)": ({"🇺🇸 美国": ["url-test", None], "🇺🇸 美国均衡": ["load-balance", "consistent-hashing"],
                         "🇯🇵 日本均衡": ["load-balance", None], "🇰🇷 韩国均衡": ["load-balance", None], "🌐 其他": ["url-test", None],
                         "🇷🇺 俄罗斯": ["url-test", None], "🇦🇺 澳大利亚": ["url-test", None]},
                        ["🇭🇰 香港均衡", "🇺🇸 美国自动", "🇸🇬 新加坡", "🇹🇼 台湾"]),
    "18-地区主组select+自动+轮询": ({"🇺🇸 美国": ["select", None], "🇺🇸 美国自动": ["url-test", None],
                              "🇺🇸 美国均衡": ["load-balance", "round-robin"], "🇭🇰 香港自动": ["url-test", None]}, ["🌐 其他", "🇰🇷 韩国"]),
    "19-地区主组load-balance粘性": ({"🇺🇸 美国": ["load-balance", "sticky-sessions"], "🇺🇸 美国自动": ["url-test", None]}, ["🇺🇸 美国均衡"]),
    "20-地区主组fallback无均衡": ({"🇯🇵 日本": ["fallback", None], "🇯🇵 日本自动": ["url-test", None]}, ["🇯🇵 日本均衡"]),
    "21-订阅节点已知": ({"🇺🇸 美国均衡": ["load-balance", None], "🇬🇧 英国": ["url-test", None], "🌐 其他": ["url-test", None],
                    "🇯🇵 日本": ["url-test", None]}, ["🇯🇵 日本均衡", "🇸🇬 新加坡", "🇹🇼 台湾", "🇭🇰 香港"]),
    "22-订阅未加载(旧行为)": ({"🇭🇰 香港": ["url-test", None], "🇸🇬 新加坡": ["url-test", None], "🇺🇸 美国均衡": ["load-balance", None]},
                        ["🇬🇧 英国"]),
    "23-自定义策略组(全部类型)": ({"🎯 美日均衡": ["load-balance", "round-robin"], "🧷 粘性": ["load-balance", "sticky-sessions"],
                            "🔗 一致性": ["load-balance", "consistent-hashing"], "🎮 游戏": ["select", None],
                            "⚡ 低延迟": ["url-test", None], "🧯 稳定优先": ["fallback", None], "🔁 跟随节点选择": ["select", None],
                            "空筛选": ["select", None]}, []),
    "24-自定义组+订阅+TUN+嗅探关": ({"🎮 游戏": ["select", None], "🧷 粘性": ["load-balance", "sticky-sessions"]}, []),
}
scen.update({
    "17-地区均衡(手动节点)": {"nodes": multi},
    "18-地区主组select+自动+轮询": {"nodes": multi, "groups_cfg": gcfg(type="select", strategy="round-robin", extra=False, other=False)},
    "19-地区主组load-balance粘性": {"nodes": multi, "groups_cfg": gcfg(type="load-balance", strategy="sticky-sessions", lazy=False)},
    "20-地区主组fallback无均衡": {"nodes": multi, "groups_cfg": gcfg(type="fallback", lb=False, interval=600, tolerance=0)},
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
    "引用节点选择且加入候选": [cg("X", "select", ["🚀 节点选择"])],
    "重名": [customs[0], dict(customs[0])],
    "与地区组同名": [cg("🇺🇸 美国均衡", "select", ["DIRECT"])],
    "成员不存在": [cg("X", "select", ["不存在"])],
}
for k, v in bad_cases.items():
    assert server.validate_groups(dict(base, custom_groups=v)), "应拒绝：" + k
ok_errs = server.validate_groups(dict(base, custom_groups=customs[:7]))
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
for name, extra in scen.items():
    extra = dict(extra)
    prov = extra.pop("_prov", None)
    d = dict(password="x", secret="selftest", **extra)
    os.makedirs(os.path.join(work, name))
    json.dump(d, open(os.path.join(work, name, "data.json"), "w"), ensure_ascii=False)
    if prov is not None:
        json.dump(prov, open(os.path.join(work, name, "provider_nodes.json"), "w"), ensure_ascii=False)
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
for d in "$WORK"/*/; do
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
import os
if os.path.isfile(d + "/expect.json"):
    must, mustnot = json.load(open(d + "/expect.json"))
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
echo ">> 通过 $PASS，失败 $FAIL"
[ "$FAIL" = 0 ]
