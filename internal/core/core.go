// Package core 移植自 shunt/core.py（核心配置下发/重载）与
// shunt/sb_switch.py（mihomo↔sing-box 内核切换、sing-box 更新）。
//
// 导出命名按"Python foo_bar → Go FooBar"契约：ReloadCore、RefreshRegions、
// RefreshAfterSub、ConnsSnapshot、GroupSig、CoreSwitchJob、SbUpdateJob、
// SbArch、SbRemoteVersion 等。
//
// 本包 import shunt/internal/coreupdate（sb_switch 依赖 core_update 的函数）；
// coreupdate 对 core.ReloadCore 的反向依赖通过 coreupdate.ReloadCoreHook
// 注入（init 中接线），避免 import cycle。
package core

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"shunt/internal/base"
	"shunt/internal/coreupdate"
	"shunt/internal/data"
	"shunt/internal/stats"
)

// ReloadTries 对应 RELOAD_TRIES：校验期间配置又被改了时重新生成再校验，
// 最后一次在锁内校验（保证能结束）。
const ReloadTries = 3

var (
	// lock 对应 core.py 的 LOCK（可重入场景在 Go 侧已拆为不嵌套的临界区）。
	lock   sync.Mutex
	tmpSeq int64 // 对应 _TMP_SEQ = itertools.count(1)
)

func init() {
	// core_update.py `from .core import reload_core` 的反向依赖：
	// coreupdate 不能 import core（循环），改为注入。
	coreupdate.ReloadCoreHook = func(prev map[string]any) (bool, string) {
		return ReloadCore(prev)
	}
	// stats 不能 import core（core → mihomo → devroute → stats 会循环），
	// conns_snapshot 经 ConnsSnapshotHook 注入。
	stats.ConnsSnapshotHook = func(timeoutSec int, ttlSec float64) map[string]any {
		v, _ := ConnsSnapshot(timeoutSec, ttlSec).(map[string]any)
		return v
	}
}

// GroupSigItem 对应 group_sig 返回的 (name, type, filter, proxies) 元组。
type GroupSigItem struct {
	Name    string
	Type    string
	Filter  string
	Proxies []string
}

// GroupSig 对应 group_sig(cfg)：mihomo proxy-groups 的签名，用于判断地区分组是否变化。
func GroupSig(cfg map[string]any) []GroupSigItem {
	out := []GroupSigItem{}
	for _, g := range data.List(cfg, "proxy-groups") {
		gm, _ := g.(map[string]any)
		if gm == nil {
			continue
		}
		proxies := []string{}
		for _, p := range data.List(gm, "proxies") {
			if s, ok := p.(string); ok {
				proxies = append(proxies, s)
			}
		}
		out = append(out, GroupSigItem{
			Name:    data.Str(gm, "name"),
			Type:    data.Str(gm, "type"),
			Filter:  data.Str(gm, "filter"),
			Proxies: proxies,
		})
	}
	return out
}

// outboundSigItem 是 sing-box 出站签名的单项（tag + 引用的出站）。
type outboundSigItem struct {
	Tag       string
	Outbounds []string
}

// outboundSig 对应 refresh_regions 里 sing-box 分支的 sig(c)：
// [(o["tag"], tuple(o.get("outbounds") or [])) for o in outbounds if o.get("outbounds")]。
func outboundSig(cfg map[string]any) []outboundSigItem {
	out := []outboundSigItem{}
	for _, o := range data.List(cfg, "outbounds") {
		om, _ := o.(map[string]any)
		if om == nil {
			continue
		}
		refs := data.List(om, "outbounds")
		if len(refs) == 0 {
			continue
		}
		tags := []string{}
		for _, x := range refs {
			if s, ok := x.(string); ok {
				tags = append(tags, s)
			}
		}
		out = append(out, outboundSigItem{Tag: data.Str(om, "tag"), Outbounds: tags})
	}
	return out
}

var connSnap struct {
	sync.Mutex
	at  time.Time
	v   any
	has bool
}

// ConnsSnapshot 对应 conns_snapshot(timeout=5, ttl=2)：1~2 秒 TTL 的
// /connections 进程内共享快照。抓取失败返回 nil（与原来语义一致），不缓存失败结果。
func ConnsSnapshot(timeoutSec int, ttlSec float64) any {
	connSnap.Lock()
	if connSnap.has && time.Since(connSnap.at).Seconds() < ttlSec {
		v := connSnap.v
		connSnap.Unlock()
		return v
	}
	connSnap.Unlock()
	c := coreJSON("/connections", timeoutSec)
	if c == nil {
		return nil
	}
	connSnap.Lock()
	connSnap.at = time.Now()
	connSnap.v = c
	connSnap.has = true
	connSnap.Unlock()
	return c
}

// ReloadCore 对应 reload_core(prev=None)：写配置 → mihomo -t / sing-box check
// 校验 → 热重载。prev（修改前的 data.json）给出时，任何一步失败都回滚到它。
func ReloadCore(prev map[string]any) (ok bool, msg string) {
	defer func() {
		if r := recover(); r != nil {
			// 对应 except Exception：stub 未接线或真实异常都走回滚语义
			safeLogErr("重载核心配置", fmt.Errorf("%v", r))
			if prev == nil {
				ok, msg = false, "生成配置失败："+truncate(fmt.Sprint(r), 300)
			} else {
				rollback(prev, nil)
				ok, msg = false, "生成配置失败，已撤销本次修改："+truncate(fmt.Sprint(r), 300)
			}
		}
	}()
	return reloadCoreImpl(prev)
}

// rollback 对应 _rollback(prev, sb=None)：data.json 恢复为 prev，并按它重写
// 当前内核的配置文件；返回 (内核是否 sing-box, 配置路径)。
func rollback(prev map[string]any, sb *bool) (bool, string) {
	lock.Lock()
	defer lock.Unlock()
	data.Save(prev)
	d := data.Load()
	isSb := false
	if sb != nil {
		isSb = *sb
	} else {
		isSb = activeCore(d) == "singbox"
	}
	final := sbConf
	if !isSb {
		final = filepath.Join(base.ConfDir, "config.yaml")
	}
	func() {
		defer func() {
			// 旧数据本身也生成不了：保留磁盘上原来的配置文件
			if r := recover(); r != nil {
				safeLogErr("回滚后重写配置", fmt.Errorf("%v", r))
			}
		}()
		if isSb {
			writeSbConfig(d, final)
		} else {
			writeConfig(d, final)
		}
	}()
	return isSb, final
}

// genConfig 对应 _gen_config(d, sb, tmp)：生成待校验的配置到临时文件 tmp。
func genConfig(d map[string]any, sb bool, tmp string) string {
	if sb {
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Println("sb adblock sync", r)
				}
			}()
			// 广告/白名单列表改动后，先把对应的 sing-box 规则集文件转换好，
			// 否则这些规则会被跳过
			need := map[string]map[string]string{}
			for k, v := range sbRuleNeed(d) {
				if v["kind"] == "adblock" {
					need[k] = v
				}
			}
			if len(need) > 0 {
				sbSyncAssets(d, need)
			}
		}()
		return writeSbConfig(d, tmp)
	}
	return writeConfig(d, tmp)
}

// reloadCoreImpl 对应 _reload_core(prev)。
//
// mihomo -t / sing-box check 最长 90 秒：以前整段持有全局 LOCK，期间所有
// update()（设备备注、定时任务设置等）都被卡住。现在锁内只生成配置并记下
// config_version，校验在锁外做；校验完再拿锁，版本没变才替换正式配置，
// 变了就按最新数据重来。
func reloadCoreImpl(prev map[string]any) (bool, string) {
	var tmp string
	defer func() {
		if tmp != "" {
			os.Remove(tmp)
		}
	}()
	var sb bool
	var final string
	for i := 0; i < ReloadTries; i++ {
		last := i == ReloadTries-1
		var ok bool
		var checkErr string
		var ver int
		func() { // 锁内：生成配置并记下版本（最后一次在锁内校验）
			lock.Lock()
			defer lock.Unlock()
			d := data.Load()
			ver = data.ConfigVersion()
			sb = activeCore(d) == "singbox"
			if sb {
				final = sbConf
			} else {
				final = filepath.Join(base.ConfDir, "config.yaml")
			}
			tmp = fmt.Sprintf("%s.new%d", final, atomic.AddInt64(&tmpSeq, 1)) // 唯一临时文件
			genConfig(d, sb, tmp)
			if last {
				if sb {
					ok, checkErr = checkSbConfig(tmp)
				} else {
					ok, checkErr = checkConfig(tmp, activeCore(d))
				}
			}
		}()
		if !last { // 锁外校验
			if sb {
				ok, checkErr = checkSbConfig(tmp)
			} else {
				ok, checkErr = checkConfig(tmp, activeCore(data.Load()))
			}
		}
		var failed, retry bool
		var failMsg string
		func() {
			lock.Lock()
			defer lock.Unlock()
			if !ok {
				if prev != nil {
					data.Save(prev)
				}
				failed = true
				failMsg = "配置校验失败，已撤销本次修改：" + checkErr
				return
			}
			if data.ConfigVersion() != ver && !last {
				os.Remove(tmp) // 校验期间 data.json 被改过：这份配置已过时，丢掉重来
				tmp = ""
				retry = true
				return
			}
			if err := os.Rename(tmp, final); err != nil {
				panic(err) // 外层 recover 转为"生成配置失败"并回滚
			}
			tmp = ""
		}()
		if failed {
			return false, failMsg
		}
		if retry {
			continue
		}
		break
	}
	if wdManualStop() { // 用户手动停止了核心：只写配置，不替用户把核心拉起来
		return true, "配置已保存；核心已手动停止，下次启动时生效"
	}
	retestSoon()
	if sb {
		ok, msg := sbHotReload()
		if !ok && prev != nil { // 配置能通过 sing-box check 但运行时启动失败：撤销并恢复
			tail := sbLogError()
			rollback(prev, boolPtr(true))
			svcRestart(90)
			suffix := ""
			if tail != "" {
				suffix = "：" + tail
			}
			return false, "sing-box 启动失败，已撤销本次修改" + suffix
		}
		return ok, msg
	}
	base.WdHold(45, "mihomo 重载配置", false)
	code, body := coreAPI("PUT", "/configs?force=true", map[string]any{"path": final}, 30)
	if code == 502 { // 核心没在跑，尝试启动
		svcRestart(90)
		return true, "已写入配置并重启 mihomo"
	}
	var text string
	switch b := body.(type) {
	case []byte:
		text = string(b)
	case nil:
		text = ""
	default:
		text = fmt.Sprint(b)
	}
	if code >= 300 {
		if prev == nil {
			if text == "" {
				text = fmt.Sprintf("mihomo 重载失败（%d）", code)
			}
			return false, text
		}
		// 核心拒绝了新配置、还在跑旧配置：data.json 和 config.yaml 也退回去，
		// 界面与实际生效的配置保持一致
		_, newFinal := rollback(prev, boolPtr(false))
		coreAPI("PUT", "/configs?force=true", map[string]any{"path": newFinal}, 30)
		suffix := truncate(text, 300)
		if suffix == "" {
			suffix = fmt.Sprintf("%d", code)
		}
		return false, "mihomo 重载失败，已撤销本次修改：" + suffix
	}
	if text == "" {
		text = "配置已重载"
	}
	return true, text
}

// RefreshRegions 对应 refresh_regions()：订阅节点变化后，地区分组（存在哪些地区、
// 是否生成均衡组）可能变化：与当前配置不同就重新生成并重载。
func RefreshRegions() (bool, string) {
	if !coreAlive() { // 核心没在运行（可能是手动停止）时不重载，免得把它拉起来
		return false, "核心未运行"
	}
	providerNodes(true)
	if activeCore() == "singbox" {
		cur := data.ReadJSON[map[string]any](sbConf, nil)
		newCfg := buildSingbox(data.Load())
		var newMap map[string]any
		if len(newCfg) > 0 {
			newMap, _ = newCfg[0].(map[string]any)
		}
		if cur != nil && reflect.DeepEqual(outboundSig(cur), outboundSig(newMap)) {
			return true, "地区分组无变化"
		}
		ok, msg := ReloadCore(nil)
		if ok {
			return true, "地区分组已按最新订阅节点更新"
		}
		return false, msg
	}
	cur := data.ReadJSON[map[string]any](filepath.Join(base.ConfDir, "config.yaml"), nil)
	if cur == nil {
		return false, "当前配置不存在"
	}
	if reflect.DeepEqual(GroupSig(cur), GroupSig(buildConfig(data.Load()))) {
		return true, "地区分组无变化"
	}
	ok, msg := ReloadCore(nil)
	fmt.Printf("%s [groups] 订阅节点变化，已重新生成地区分组： %v %s\n",
		time.Now().Format("2006-01-02 15:04:05"), ok, truncate(msg, 120))
	if ok {
		return true, "地区分组已按最新订阅节点更新"
	}
	return false, msg
}

// RefreshAfterSub 对应 refresh_after_sub(name, wait=90)：新订阅加入后等核心下载完
// 节点，再更新地区分组（后台 goroutine）。
func RefreshAfterSub(name string, waitSec int) {
	go func() {
		end := time.Now().Add(time.Duration(waitSec) * time.Second)
		for time.Now().Before(end) {
			time.Sleep(10 * time.Second)
			if _, found := providerNodes(true)[name]; found {
				break
			}
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Println("refresh regions error", r)
				}
			}()
			RefreshRegions()
		}()
	}()
}
