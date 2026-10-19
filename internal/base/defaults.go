package base

import (
	"encoding/json"
	"sync"
)

// 复杂默认结构以 JSON 字面量保存，保证与 Python 版逐字节一致；init 时解析一次。

const defaultFakeFilterJSON = `["*.lan","+.local","+.msftconnecttest.com","+.msftncsi.com","time.*.com","ntp.*.com","+.ntp.org","+.stun.*.*","+.market.xiaomi.com","localhost.ptlogin2.qq.com"]`

const dnsDefaultJSON = `{"direct":["https://doh.pub/dns-query","https://dns.alidns.com/dns-query"],"proxy":["https://1.1.1.1/dns-query#🚀 节点选择","https://dns.google/dns-query#🚀 节点选择"],"default":["223.5.5.5","119.29.29.29"],"pserver":[],"mode":"fake-ip","fake_filter":["*.lan","+.local","+.msftconnecttest.com","+.msftncsi.com","time.*.com","ntp.*.com","+.ntp.org","+.stun.*.*","+.market.xiaomi.com","localhost.ptlogin2.qq.com"],"cache":"arc","policy":true,"respect_rules":true,"block_bypass":false,"hosts":[],"policies":[]}`

const abDefaultJSON = `{"enabled":false,"lists":[],"black":[],"white":[],"interval":86400,"dns":false}`

const abPresetsJSON = `[
{"cat":"国内 · 视频 / App","name":"秋风广告规则","url":"https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt","dsc":"国内 App 开屏、视频贴片、广告 SDK"},
{"cat":"国内 · 视频 / App","name":"小米电视广告","url":"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/AdvertisingMiTV/AdvertisingMiTV.list","dsc":"小米电视 / 盒子开机与界面广告"},
{"cat":"国内 · 网页","name":"anti-AD","url":"https://anti-ad.net/easylist.txt","dsc":"国内网页、App 广告综合"},
{"cat":"国内 · 网页","name":"AdGuard 中文","url":"https://filters.adtidy.org/extension/ublock/filters/224.txt","dsc":"中文网站广告"},
{"cat":"国内 · 隐私","name":"隐私追踪 (blackmatrix7)","url":"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Privacy/Privacy.list","dsc":"统计、埋点、行为追踪"},
{"cat":"国外 · 视频 / 电视","name":"Smart-TV","url":"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt","dsc":"三星 / LG / 索尼等电视界面广告与回传"},
{"cat":"国外 · 网页","name":"AdGuard DNS filter","url":"https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt","dsc":"国外网站、App 广告综合"},
{"cat":"国外 · 网页","name":"HaGeZi Multi","url":"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt","dsc":"广告 + 追踪 + 恶意域名，覆盖更广"},
{"cat":"国外 · 隐私","name":"EasyPrivacy","url":"https://easylist.to/easylist/easyprivacy.txt","dsc":"国外统计与追踪"},
{"cat":"国外 · 隐私","name":"Frogeye 一方追踪","url":"https://hostfiles.frogeye.fr/firstparty-trackers.txt","dsc":"伪装成网站子域名的追踪器"}]`

const tunDefaultJSON = `{"stack":"mixed","device":"Meta","auto_redirect":true,"strict_route":false}`

const groupsDefaultJSON = `{"type":"url-test","lb":true,"auto":true,"strategy":"consistent-hashing","interval":60,"tolerance":0,"url":"https://www.gstatic.com/generate_204","extra":true,"other":true,"lazy":true,"lgbm":false}`

const schedDefaultJSON = `{"sub_update":"","core_restart":"","geo_update":"","latency":0}`

const testsJSON = `[
{"name":"Google","url":"https://www.google.com/generate_204"},
{"name":"YouTube","url":"https://www.youtube.com/generate_204"},
{"name":"Telegram","url":"https://api.telegram.org"},
{"name":"GitHub","url":"https://github.com"},
{"name":"百度","url":"https://www.baidu.com"},
{"name":"淘宝","url":"https://www.taobao.com"}]`

const defaultJSON = `{"secret":"","mode":"rule","tproxy":true,"subs":[],"rules":[],"rulesets":[],"bypass":[],"tests":null,"sub_interval":86400,"region_groups":true,"nodes":[],"ipv6":false,"https":false,"allow_public":false,"allow_hosts":[],"watchdog":true,"tg_token":"","tg_chat":"","proxy_mode":"","tun":{"stack":"mixed","device":"Meta","auto_redirect":true,"strict_route":false},"log_limit":5,"adblock":{"enabled":false,"lists":[],"black":[],"white":[],"interval":86400,"dns":false},"dns":{"direct":["https://doh.pub/dns-query","https://dns.alidns.com/dns-query"],"proxy":["https://1.1.1.1/dns-query#🚀 节点选择","https://dns.google/dns-query#🚀 节点选择"],"default":["223.5.5.5","119.29.29.29"],"pserver":[],"mode":"fake-ip","fake_filter":["*.lan","+.local","+.msftconnecttest.com","+.msftncsi.com","time.*.com","ntp.*.com","+.ntp.org","+.stun.*.*","+.market.xiaomi.com","localhost.ptlogin2.qq.com"],"cache":"arc","policy":true,"respect_rules":true,"block_bypass":false,"hosts":[],"policies":[]},"devices":{},"device_routes":[],"schedule":{"sub_update":"","core_restart":"","geo_update":"","latency":0},"groups_cfg":{"type":"url-test","lb":true,"auto":true,"strategy":"consistent-hashing","interval":60,"tolerance":0,"url":"https://www.gstatic.com/generate_204","extra":true,"other":true,"lazy":true,"lgbm":false},"custom_groups":[],"sniffer":true,"gh_proxy":"","core":"mihomo","schema":0,"sysopt":[],"sysopt_orig":{},"sysopt_mods":[]}`

// Regions 地区分组：(分组名, 正则)。正则同时在 Python 与 mihomo(regexp2) 中使用，只用两者都支持的语法。
type Region struct {
	Name    string
	Pattern string
}

var Regions = []Region{
	{"🇭🇰 香港", `🇭🇰|(?i:香港|港|Hong ?Kong)|(?<![A-Za-z])HKG?(?![A-Za-z])`},
	{"🇹🇼 台湾", `🇹🇼|(?i:台|Taiwan|Taipei)|(?<![A-Za-z])TWN?(?![A-Za-z])`},
	{"🇯🇵 日本", `🇯🇵|(?i:日本|东京|東京|大阪|埼玉|Japan|Tokyo|Osaka)|(?<![A-Za-z])JPN?(?![A-Za-z])`},
	{"🇸🇬 新加坡", `🇸🇬|(?i:新加坡|狮城|獅城|Singapore)|(?<![A-Za-z])SGP?(?![A-Za-z])`},
	{"🇺🇸 美国", `🇺🇸|(?i:美国|美國|洛杉矶|圣何塞|硅谷|纽约|西雅图|芝加哥|达拉斯|凤凰城|United ?States|America|Los ?Angeles|San ?Jose|Seattle|New ?York|Chicago|Dallas)|(?<![A-Za-z])USA?(?![A-Za-z])`},
	{"🇰🇷 韩国", `🇰🇷|(?i:韩国|韓國|首尔|首爾|春川|Korea|Seoul)|(?<![A-Za-z])KOR?(?![A-Za-z])`},
	{"🇬🇧 英国", `🇬🇧|(?i:英国|英國|伦敦|倫敦|United ?Kingdom|Britain|London)|(?<![A-Za-z])(?:UK|GB|GBR)(?![A-Za-z])`},
	{"🇩🇪 德国", `🇩🇪|(?i:德国|德國|法兰克福|Germany|Frankfurt)|(?<![A-Za-z])DEU?(?![A-Za-z])`},
	{"🇫🇷 法国", `🇫🇷|(?i:法国|法國|巴黎|France|Paris)|(?<![A-Za-z])FRA?(?![A-Za-z])`},
	{"🇳🇱 荷兰", `🇳🇱|(?i:荷兰|荷蘭|阿姆斯特丹|Netherlands|Amsterdam)|(?<![A-Za-z])NLD?(?![A-Za-z])`},
	{"🇨🇦 加拿大", `🇨🇦|(?i:加拿大|多伦多|温哥华|Canada|Toronto|Vancouver)|(?<![A-Za-z])CAN?(?![A-Za-z])`},
	{"🇦🇺 澳大利亚", `🇦🇺|(?i:澳大利亚|澳洲|悉尼|墨尔本|Australia|Sydney|Melbourne)|(?<![A-Za-z])AUS?(?![A-Za-z])`},
	{"🇷🇺 俄罗斯", `🇷🇺|(?i:俄罗斯|俄羅斯|莫斯科|Russia|Moscow)|(?<![A-Za-z])RUS?(?![A-Za-z])`},
	{"🇮🇳 印度", `🇮🇳|(?i:印度|孟买|India|Mumbai)|(?<![A-Za-z])IND?(?![A-Za-z])`},
	{"🇹🇷 土耳其", `🇹🇷|(?i:土耳其|伊斯坦布尔|Turkey|Türkiye|Istanbul)|(?<![A-Za-z])TUR?(?![A-Za-z])`},
	{"🇲🇾 马来西亚", `🇲🇾|(?i:马来|馬來|吉隆坡|Malaysia)|(?<![A-Za-z])MYS?(?![A-Za-z])`},
	{"🇹🇭 泰国", `🇹🇭|(?i:泰国|泰國|曼谷|Thailand|Bangkok)|(?<![A-Za-z])THA?(?![A-Za-z])`},
	{"🇻🇳 越南", `🇻🇳|(?i:越南|胡志明|Vietnam)|(?<![A-Za-z])VNM?(?![A-Za-z])`},
	{"🇵🇭 菲律宾", `🇵🇭|(?i:菲律宾|菲律賓|马尼拉|Philippines)|(?<![A-Za-z])PHL?(?![A-Za-z])`},
	{"🇦🇷 阿根廷", `🇦🇷|(?i:阿根廷|Argentina)|(?<![A-Za-z])ARG?(?![A-Za-z])`},
	{"🇧🇷 巴西", `🇧🇷|(?i:巴西|圣保罗|Brazil)|(?<![A-Za-z])BRA?(?![A-Za-z])`},
}

var (
	DefaultFakeFilter []string
	DNSDefault        map[string]any
	AbDefault         map[string]any
	AbPresets         []any
	TunDefault        map[string]any
	GroupsDefault     map[string]any
	SchedDefault      map[string]any
	TestsDefault      []any
	Default           map[string]any

	DNSLists = []string{"direct", "proxy", "default", "pserver", "fake_filter"}

	BuiltinPolicies = map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true}

	LeaseFiles = []string{"/var/lib/misc/dnsmasq.leases", "/tmp/dhcp.leases", "/var/lib/dnsmasq/dnsmasq.leases"}

	// CnApps 国内常用 App / 网站直连名单（内置 cn-apps 规则集）
	CnApps       map[string][]string
	CnAppDomains []string
)

var defaultsOnce sync.Once

func mustUnmarshal(s string, v any) {
	if err := json.Unmarshal([]byte(s), v); err != nil {
		panic("base defaults: " + err.Error())
	}
}

func init() {
	defaultsOnce.Do(func() {
		mustUnmarshal(defaultFakeFilterJSON, &DefaultFakeFilter)
		mustUnmarshal(dnsDefaultJSON, &DNSDefault)
		mustUnmarshal(abDefaultJSON, &AbDefault)
		mustUnmarshal(abPresetsJSON, &AbPresets)
		mustUnmarshal(tunDefaultJSON, &TunDefault)
		mustUnmarshal(groupsDefaultJSON, &GroupsDefault)
		mustUnmarshal(schedDefaultJSON, &SchedDefault)
		mustUnmarshal(testsJSON, &TestsDefault)
		mustUnmarshal(defaultJSON, &Default)
		mustUnmarshal(cnAppsJSON, &CnApps)
		seen := map[string]bool{}
		// 按 Python 插入顺序（社交→视频→短视频→头部网站→支付银行）构造，保证确定性
		for _, cat := range []string{"社交", "视频", "短视频", "头部网站", "支付银行"} {
			for _, x := range CnApps[cat] {
				k := "+." + x
				if !seen[k] {
					seen[k] = true
					CnAppDomains = append(CnAppDomains, k)
				}
			}
		}
	})
}

// DeepCopyDefault 返回 DEFAULT 的深拷贝（供 store 做 setdefault 用）
func DeepCopyDefault() map[string]any {
	b, _ := json.Marshal(Default)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func deepCopyAny(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

// DefaultValue 返回 DEFAULT[key] 的深拷贝
func DefaultValue(key string) any {
	return deepCopyAny(Default[key])
}
