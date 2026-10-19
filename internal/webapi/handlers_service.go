package webapi

// handlers_service.go：服务类路由（对应 webapi.py 的 /api/service，含 _svc_do 的启停确认逻辑）。

import (
	"fmt"
	"sync"
	"time"

	"shunt/internal/base"
	"shunt/internal/core"
	"shunt/internal/corehttp"
	"shunt/internal/errlog"
	"shunt/internal/latency"
	"shunt/internal/notify"
	"shunt/internal/schedule"
	"shunt/internal/sysopt"
)

// svcOpMu 对应 _SVC_LOCK：启动 / 停止 / 重启同一时间只允许一个（防连点 / 多标签页同时操作）。
// svcStateMu 保护 svcJob 的读写。
var (
	svcOpMu    sync.Mutex
	svcStateMu sync.Mutex
	// svcJob 最近一次启停操作，GET /api/service 返回给前端轮询
	svcJob = map[string]any{"busy": false, "act": "", "ok": nil, "message": "", "t": int64(0)}
)

var svcNames = map[string]string{"start": "启动", "stop": "停止", "restart": "重启"}

func registerServiceRoutes() {
	Route("GET", "/api/service", hServiceGet)
	Route("POST", "/api/service", hServicePost)
}

func svcJobSnapshot() map[string]any {
	svcStateMu.Lock()
	defer svcStateMu.Unlock()
	out := make(map[string]any, len(svcJob)+1)
	for k, v := range svcJob {
		out[k] = v
	}
	return out
}

func svcJobUpdate(busy bool, act string, ok *bool, message string) {
	svcStateMu.Lock()
	defer svcStateMu.Unlock()
	var okAny any
	if ok != nil {
		okAny = *ok
	}
	svcJob = map[string]any{"busy": busy, "act": act, "ok": okAny, "message": message, "t": time.Now().Unix()}
}

// GET /api/service
func hServiceGet(c *Ctx) (int, any) {
	out := svcJobSnapshot()
	out["alive"] = notify.CoreProcAlive()
	return 200, out
}

// POST /api/service
func hServicePost(c *Ctx) (int, any) {
	act := c.BodyStr("action")
	if act == "reload" {
		ok, msg := core.ReloadCore(nil)
		return c.Reply(ok, msg)
	}
	if act == "restart" || act == "stop" || act == "start" {
		if !svcOpMu.TryLock() { // 防连点 / 多标签页同时操作：两个 rc-service 并发会互相打断
			out := svcJobSnapshot()
			out["message"] = "正在" + svcNames[toStr(out["act"])] + "核心，请稍候"
			return 409, out
		}
		svcJobUpdate(true, act, nil, "")
		go svcJobRun(act) // 后台执行：请求立即返回，前端轮询结果
		out := svcJobSnapshot()
		out["message"] = "正在" + svcNames[act] + "核心…"
		return 202, out
	}
	if act == "upgrade" && activeCore() == "singbox" {
		return 400, map[string]any{"message": "请在 设置 → 核心 → 内核更新 里更新 sing-box"}
	}
	if act == "upgrade" {
		code, raw := corehttp.Core("POST", "/upgrade", map[string]any{}, 300)
		if code == 502 {
			code = 500
		}
		if len(raw) == 0 {
			raw = []byte(`{"message":"ok"}`)
		}
		return rawResp(code, raw, "application/json")
	}
	if act == "geo" && activeCore() == "singbox" {
		ok, msg := schedule.RunTask("geo_update")
		return c.Reply(ok, msg)
	}
	if act == "geo" {
		code, raw := corehttp.Core("POST", "/configs/geo", map[string]any{}, 120)
		if len(raw) == 0 {
			raw = []byte(`{"message":"ok"}`)
		}
		return rawResp(code, raw, "application/json")
	}
	return 400, map[string]any{"message": "未知操作"}
}

// svcJobRun 对应 _svc_job：在后台执行启停，结束时更新 SVC_JOB 并释放锁。
func svcJobRun(act string) {
	defer svcOpMu.Unlock()
	ok, msg := func() (ok bool, msg string) {
		defer func() {
			if r := recover(); r != nil {
				errlog.LogErr("api/service "+act, fmt.Errorf("%v", r), false)
				ok, msg = false, svcNames[act]+"失败："+fmt.Sprint(r)
			}
		}()
		return svcDo(act)
	}()
	svcJobUpdate(false, act, &ok, msg)
}

// svcDo 对应 _svc_do(act)：执行启停并确认结果，返回 (成功?, 提示)。
//
// 与 Python 的差异：Python 用可重入的 RLock 在整个操作期间持有 SVC_OP（与看门狗/定时任务的
// 重启互斥）；Go 的 sync.Mutex 不可重入，而 RcRun/SvcRestart 内部已加锁，因此 Go 版按顺序
// 执行、不跨 rc 调用持有锁。看门狗的重启仍通过同一把锁与 rc 命令本身互斥。
func svcDo(act string) (bool, string) {
	if act == "stop" {
		// 看门狗 / 定时任务正在重启核心时，等它做完再停，不并发跑两个 rc-service
		notify.SetManualStop(true) // 拿到锁后置位（并落盘）：之后看门狗不会再把它拉起来，面板重启后也记得
		base.WdHold(150, "手动停止", false)
		code, out := sysopt.RcRun("stop", 90)
		for i := 0; i < 40; i++ { // rc-service 的返回值不可靠，以 pid 为准，每 0.2 秒查一次，最多等 8 秒
			if !notify.CoreProcAlive() {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		// pid 文件之外还有核心进程（OpenRC 被 zap 过、旧服务名留下的、SSH 手动运行的）：rc-service 管不到，
		// 以前这里直接报「已停止」，实际核心还占着端口在跑，顶栏一直显示运行中
		stray := 0
		if !notify.CoreProcAlive() {
			stray = sysopt.KillCoreProcs(15)
		}
		stopped := !notify.CoreProcAlive() && len(sysopt.CoreProcs()) == 0
		base.WdHold(0, "手动停止", true)
		if stopped {
			if stray > 0 {
				errlog.LogErr("api/service stop", fmt.Errorf("结束了 %d 个不在 pid 文件里的残留核心进程", stray), false)
			}
			msg := "核心已停止"
			if stray > 0 {
				msg += fmt.Sprintf("（另外结束了 %d 个不受服务管理的残留核心进程）", stray)
			}
			return true, msg
		}
		notify.SetManualStop(false) // 没停下来：交还给看门狗，避免核心卡死后再也没人拉起
		tail := tailRunes(out, 200)
		if tail == "" {
			tail = "无输出"
		}
		errlog.LogErr("api/service stop", fmt.Errorf("停止后核心进程仍在（rc 返回 %d）：%s", code, tail), false)
		return false, "核心进程仍在运行，停止失败：" + tail
	}
	notify.SetManualStop(false)
	if !notify.CoreProcAlive() && len(sysopt.CoreProcs()) > 0 { // 服务没在跑却有核心进程：残留孤儿占着端口，新核心会起不来
		n := sysopt.KillCoreProcs(15)
		errlog.LogErr("api/service "+act, fmt.Errorf("启动前结束了 %d 个不受服务管理的残留核心进程", n), false)
	}
	var code int
	var out string
	if act == "restart" {
		code, out = sysopt.SvcRestart(90, "手动重启", nil) // 与看门狗、切换内核同一入口：含看门狗暂停和 IP 信息重查
	} else {
		base.WdHold(150, "手动启动", false)
		code, out = sysopt.RcRun("start", 90)
		base.WdHold(60, "手动启动", true)
	}
	if code == 124 {
		return false, "核心" + svcNames[act] + "超时，请 SSH 检查 `" + base.Svc + " status` 和核心日志"
	}
	// 后台启动的服务 rc 总返回 0，要自己确认：控制接口一应答就算成功（通常 1 秒内）；
	// 进程在但接口还没起来（加载大规则集）最多等 8 秒，期间进程退出立即判失败
	for i := 0; i < 40; i++ {
		if !notify.CoreProcAlive() {
			if i >= 3 { // 前 0.6 秒 pid 文件可能还没写好
				break
			}
		} else if notify.CoreAlive() {
			latency.RetestSoon(6)
			return true, "核心已" + svcNames[act]
		}
		time.Sleep(200 * time.Millisecond)
	}
	if notify.CoreProcAlive() {
		latency.RetestSoon(6)
		return true, "核心已" + svcNames[act] + "（控制接口仍在加载）"
	}
	tail := tailRunes(out, 200)
	if tail == "" {
		tail = "无输出"
	}
	return false, "核心没有运行起来，请查看核心日志：" + tail
}
