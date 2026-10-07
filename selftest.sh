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
import json, os, sys
src, work = sys.argv[1], sys.argv[2]
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
for name, extra in scen.items():
    d = dict(password="x", secret="selftest", **extra)
    os.makedirs(os.path.join(work, name))
    json.dump(d, open(os.path.join(work, name, "data.json"), "w"), ensure_ascii=False)
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
  MIHOMO_DIR="$d" PANEL_DATA="$d/data.json" python3 "$SRC/server.py" --gen >/dev/null || { echo "✗ $n: server.py --gen 失败"; FAIL=$((FAIL+1)); continue; }
  if ! CHK=$(python3 - "$d" <<'PY'
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
print("ok")
PY
); then echo "✗ $n: 生成结果断言失败"; FAIL=$((FAIL+1)); continue; fi
  if OUT=$(timeout 120 "$MIHOMO_BIN" -t -d "$d" -f "$d/config.yaml" 2>&1); then
    echo "✓ $n"; PASS=$((PASS+1))
  else
    echo "✗ $n"; echo "$OUT" | grep -iE 'error|fatal|fail' | tail -n 5; FAIL=$((FAIL+1))
  fi
done
echo ">> 通过 $PASS，失败 $FAIL"
[ "$FAIL" = 0 ]
