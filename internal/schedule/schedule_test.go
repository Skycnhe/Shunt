package schedule

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"shunt/internal/base"
	"shunt/internal/data"
)

func setupEnv(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	oldData, oldHist, oldDaily, oldAb := base.DataFile, data.HistoryFile, DailyFile, base.AbDir
	base.DataFile = filepath.Join(dir, "data.json")
	data.HistoryFile = filepath.Join(dir, "history.json")
	DailyFile = filepath.Join(dir, "sched_done.json")
	base.AbDir = filepath.Join(dir, "adblock")
	// 重置 daily 缓存
	dailyMu.Lock()
	dailyData = nil
	dailyMu.Unlock()
	t.Cleanup(func() {
		base.DataFile, data.HistoryFile, DailyFile, base.AbDir = oldData, oldHist, oldDaily, oldAb
		dailyMu.Lock()
		dailyData = nil
		dailyMu.Unlock()
	})
}

func TestDailyDueInvalid(t *testing.T) {
	setupEnv(t)
	for _, at := range []string{"", "25:00", "9:00", "ab:cd"} {
		if DailyDue("t", at, "10:00", "2026-10-19") {
			t.Fatalf("at=%q should never fire", at)
		}
	}
}

func TestDailyDueFlow(t *testing.T) {
	setupEnv(t)
	today := "2026-10-19"
	// 还没到点：不触发，但记下设定时刻
	if DailyDue("job", "15:00", "10:00", today) {
		t.Fatal("should not fire before time")
	}
	// 到了时间：触发一次
	if !DailyDue("job", "15:00", "15:00", today) {
		t.Fatal("should fire at time")
	}
	// 今天已跑过：不再触发
	if DailyDue("job", "15:00", "16:00", today) {
		t.Fatal("should not fire twice a day")
	}
	// 第二天：再触发
	if !DailyDue("job", "15:00", "15:00", "2026-10-20") {
		t.Fatal("should fire next day")
	}
}

func TestDailyDueMissedFirstSight(t *testing.T) {
	setupEnv(t)
	// 第一次见到任务、今天的时刻已过：记为今天已执行（不补跑），明天正常
	if DailyDue("newjob", "08:00", "10:00", "2026-10-19") {
		t.Fatal("first sight after time should not run today")
	}
	if !DailyDue("newjob", "08:00", "08:00", "2026-10-20") {
		t.Fatal("should fire next day")
	}
}

func TestDailyDueAtChanged(t *testing.T) {
	setupEnv(t)
	// 07:00 见到 08:00 的任务：只记下时刻
	if DailyDue("chg", "08:00", "07:00", "2026-10-19") {
		t.Fatal("should not fire before time")
	}
	// 到点触发
	if !DailyDue("chg", "08:00", "08:30", "2026-10-19") {
		t.Fatal("should fire")
	}
	// 跑过之后改了时刻：只更新记录，今天不再跑
	if DailyDue("chg", "09:00", "10:00", "2026-10-19") {
		t.Fatal("changed at should not refire today")
	}
	if !DailyDue("chg", "09:00", "09:00", "2026-10-20") {
		t.Fatal("new time should fire next day")
	}
}

func TestSchedEventCap(t *testing.T) {
	Sched.Lock()
	Sched.Events = nil
	Sched.Unlock()
	for i := 0; i < 40; i++ {
		SchedEvent("msg")
	}
	Sched.Lock()
	defer Sched.Unlock()
	if len(Sched.Events) != 30 {
		t.Fatalf("events should cap at 30, got %d", len(Sched.Events))
	}
	if Sched.Events[0].T == 0 || Sched.Events[0].Msg != "msg" {
		t.Fatal("event shape")
	}
}

func TestTaskNames(t *testing.T) {
	for _, k := range []string{"sub_update", "core_restart", "geo_update", "latency", "adblock", "health"} {
		if TaskNames[k] == "" {
			t.Fatalf("missing task name for %s", k)
		}
	}
}

func TestRunTaskUnknown(t *testing.T) {
	setupEnv(t)
	data.Save(map[string]any{})
	ok, msg := RunTask("nope")
	if ok || msg != "未知任务" {
		t.Fatalf("got %v %q", ok, msg)
	}
}

func wireCoreStubs(t *testing.T) {
	t.Helper()
	oldCall, oldJSON, oldActive, oldRefresh := coreCall, coreJSON, activeCore, refreshRegions
	coreCall = func(method, path string, body any, timeoutSec int) (int, []byte, error) {
		return 200, []byte(`{}`), nil
	}
	coreJSON = func(path string, timeoutSec int) map[string]any { return map[string]any{"all": []any{"n1"}} }
	activeCore = func(d map[string]any) string { return "mihomo" }
	refreshRegions = func() (bool, string) { return true, "ok" }
	t.Cleanup(func() { coreCall, coreJSON, activeCore, refreshRegions = oldCall, oldJSON, oldActive, oldRefresh })
}

func TestRunTaskSubUpdate(t *testing.T) {
	setupEnv(t)
	wireCoreStubs(t)
	data.Save(map[string]any{"subs": []any{map[string]any{"name": "s1"}}})
	ok, msg := RunTask("sub_update")
	if !ok || msg != "订阅已更新" {
		t.Fatalf("got %v %q", ok, msg)
	}
	// 失败路径
	oldCall := coreCall
	coreCall = func(method, path string, body any, timeoutSec int) (int, []byte, error) {
		return 500, []byte("boom"), nil
	}
	defer func() { coreCall = oldCall }()
	ok, msg = RunTask("sub_update")
	if ok || msg != "以下订阅更新失败：s1：boom" {
		t.Fatalf("got %v %q", ok, msg)
	}
}

func TestRunTaskCoreRestartManualStop(t *testing.T) {
	setupEnv(t)
	old := wdManualStop
	wdManualStop = func() bool { return true }
	defer func() { wdManualStop = old }()
	ok, msg := RunTask("core_restart")
	if !ok || msg != "核心已手动停止，跳过定时重启" {
		t.Fatalf("got %v %q", ok, msg)
	}
}

func TestRunTaskLatency(t *testing.T) {
	setupEnv(t)
	oldCall, oldJSON := coreCall, coreJSON
	coreCall = func(method, path string, body any, timeoutSec int) (int, []byte, error) {
		return 200, []byte(`{"n1": 120, "n2": 0}`), nil
	}
	coreJSON = func(path string, timeoutSec int) map[string]any { return map[string]any{} }
	defer func() { coreCall, coreJSON = oldCall, oldJSON }()
	ok, msg := RunTask("latency")
	if !ok || msg != "节点测速完成，1 个节点可达" {
		t.Fatalf("got %v %q", ok, msg)
	}
}

func TestDevrouteTick(t *testing.T) {
	setupEnv(t)
	oldMac, oldReload, oldWd := macChanged, reloadCore, wdManualStop
	defer func() { macChanged, reloadCore, wdManualStop = oldMac, oldReload, oldWd }()
	wdManualStop = func() bool { return false }
	calls := 0
	macChanged = func(d map[string]any) map[string]any { return map[string]any{"aa:bb": "192.168.1.5"} }
	reloadCore = func() (bool, string) { calls++; return true, "" }
	Sched.Lock()
	Sched.Events = nil
	Sched.Unlock()
	devrouteState.Lock()
	devrouteState.has = false
	devrouteState.tried = nil
	devrouteState.Unlock()

	DevrouteTick(map[string]any{})
	if calls != 1 {
		t.Fatalf("should reload once, got %d", calls)
	}
	DevrouteTick(map[string]any{}) // 同一结果不再重载
	if calls != 1 {
		t.Fatalf("should not reload twice, got %d", calls)
	}
	macChanged = func(d map[string]any) map[string]any { return map[string]any{"aa:bb": "192.168.1.6"} }
	DevrouteTick(map[string]any{})
	if calls != 2 {
		t.Fatalf("changed IP should reload, got %d", calls)
	}
	macChanged = func(d map[string]any) map[string]any { return nil }
	DevrouteTick(map[string]any{}) // nil 时什么都不做
	if calls != 2 {
		t.Fatalf("nil should not reload, got %d", calls)
	}
}

func TestAbLastUpdate(t *testing.T) {
	setupEnv(t)
	os.MkdirAll(base.AbDir, 0o755)
	meta := map[string]any{
		"a": map[string]any{"updated": 100},
		"b": map[string]any{"updated": 300},
	}
	data.WriteJSON(base.AbDir+"/meta.json", meta)
	if AbLastUpdate() != 300 {
		t.Fatalf("got %d", AbLastUpdate())
	}
	os.Remove(base.AbDir + "/meta.json")
	if AbLastUpdate() != 0 {
		t.Fatalf("missing meta should be 0, got %d", AbLastUpdate())
	}
}

func TestSchedTickLatencyDue(t *testing.T) {
	setupEnv(t)
	wireCoreStubs(t)
	// latency 每 1 分钟，且上次是 2 分钟前 → due
	data.Save(map[string]any{"schedule": map[string]any{"latency": 1}})
	Sched.Lock()
	Sched.Done["latency"] = float64(time.Now().Unix()) - 120
	Sched.Unlock()
	// coreCall 返回 200 且 coreJSON 非空 → latency 任务 ok，不记事件
	schedTick(1)
	Sched.Lock()
	last := Sched.Done["latency"]
	Sched.Unlock()
	if time.Now().Unix()-int64(last) > 5 {
		t.Fatal("latency done should be updated")
	}
}
