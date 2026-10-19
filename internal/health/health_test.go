package health

import (
	"os"
	"path/filepath"
	"testing"

	"shunt/internal/base"
	"shunt/internal/data"
)

func TestRecordOneSuccess(t *testing.T) {
	rec := map[string]any{"fail_days": 5, "fail_dates": []any{"2026-10-18"}, "hidden": true}
	RecordOne(rec, true, 120)
	if data.Int(rec, "fail_days") != 0 || data.Bool(rec, "hidden") {
		t.Fatalf("success should reset: %+v", rec)
	}
	if data.Int(rec, "latency") != 120 {
		t.Fatalf("latency not recorded: %+v", rec)
	}
	// latency=0 时不覆盖旧延迟
	RecordOne(rec, true, 0)
	if data.Int(rec, "latency") != 120 {
		t.Fatalf("latency should be kept: %+v", rec)
	}
}

func TestRecordOneFailDedup(t *testing.T) {
	rec := map[string]any{}
	RecordOne(rec, false, 0)
	RecordOne(rec, false, 0) // 同一天第二次不重复计数
	if data.Int(rec, "fail_days") != 1 {
		t.Fatalf("fail_days should be 1: %+v", rec)
	}
	if len(data.List(rec, "fail_dates")) != 1 {
		t.Fatalf("fail_dates should dedup: %+v", rec)
	}
}

func TestApplyResultsAutoHide(t *testing.T) {
	d := map[string]any{"health_cfg": map[string]any{"hide_days": 2}}
	results := map[string]int{"n1": 0, "n2": 50}
	ApplyResults(results, d, nil)
	health := data.Map(d, "health")
	// 第一次失败：fail_days=1 < 2，不隐藏
	if data.Bool(data.Map(health, "n1"), "hidden") {
		t.Fatal("n1 should not be hidden yet")
	}
	// 模拟昨天也失败过：再合并一次应达到阈值
	rec := data.Map(health, "n1")
	dates := data.List(rec, "fail_dates")
	dates = append([]any{"2000-01-01"}, dates...)
	rec["fail_dates"] = dates
	rec["fail_days"] = len(dates)
	ApplyResults(results, d, nil)
	if !data.Bool(data.Map(health, "n1"), "hidden") {
		t.Fatal("n1 should be hidden after 2 fail days")
	}
	if data.Int(data.Map(health, "n2"), "fail_days") != 0 {
		t.Fatal("n2 success should reset fail_days")
	}
}

func TestApplyResultsCleanup(t *testing.T) {
	d := map[string]any{"health": map[string]any{
		"keep": map[string]any{"fail_days": 1},
		"gone": map[string]any{"fail_days": 9},
	}}
	ApplyResults(map[string]int{"keep": 10}, d, []string{"keep"})
	health := data.Map(d, "health")
	if _, ok := health["gone"]; ok {
		t.Fatal("deleted node record should be cleaned")
	}
	if _, ok := health["keep"]; !ok {
		t.Fatal("kept node record should remain")
	}
	// universe=nil 时按 results 的键清理
	ApplyResults(map[string]int{}, d, nil)
	if len(data.Map(d, "health")) != 0 {
		t.Fatal("empty results with nil universe should clean all")
	}
}

func TestMergeDelay(t *testing.T) {
	members := []string{"a", "b", "c", "DIRECT"}
	payload := map[string]any{"a": float64(120), "b": float64(0), "c": "x"}
	r := MergeDelay(members, 200, payload)
	if r["a"] != 120 || r["b"] != 0 || r["c"] != 0 {
		t.Fatalf("merge: %+v", r)
	}
	if _, ok := r["DIRECT"]; ok {
		t.Fatal("builtin policies should be excluded")
	}
	// 504：全部记为失败
	r = MergeDelay(members, 504, nil)
	if len(r) != 3 || r["a"] != 0 {
		t.Fatalf("504 merge: %+v", r)
	}
	// code 非 200/504 → 空对象
	if len(MergeDelay(nil, 500, map[string]any{"a": float64(1)})) != 0 {
		t.Fatal("non-200/504 with nil members should be empty")
	}
}

func TestHealthCfgDefaults(t *testing.T) {
	cfg := HealthCfg(map[string]any{})
	if data.Int(cfg, "warn_days") != 3 || data.Int(cfg, "hide_days") != 7 || data.Str(cfg, "time") != "03:00" {
		t.Fatalf("defaults: %+v", cfg)
	}
	cfg = HealthCfg(map[string]any{"health_cfg": map[string]any{"time": "04:00"}})
	if data.Str(cfg, "time") != "04:00" || data.Int(cfg, "warn_days") != 3 {
		t.Fatalf("merge: %+v", cfg)
	}
}

func TestUnhideAndGetRecords(t *testing.T) {
	dir := t.TempDir()
	old, oldHist := base.DataFile, data.HistoryFile
	base.DataFile = filepath.Join(dir, "data.json")
	data.HistoryFile = filepath.Join(dir, "history.json")
	defer func() { base.DataFile = old; data.HistoryFile = oldHist }()

	data.Save(map[string]any{"health": map[string]any{
		"x": map[string]any{"hidden": true, "fail_days": 9, "fail_dates": []any{"2026-10-18"}},
	}})
	if !Unhide("x") {
		t.Fatal("unhide should return true")
	}
	rec := data.Map(GetRecords(nil), "x")
	if data.Bool(rec, "hidden") || data.Int(rec, "fail_days") != 0 || len(data.List(rec, "fail_dates")) != 0 {
		t.Fatalf("unhide should reset: %+v", rec)
	}
	if Unhide("missing") {
		t.Fatal("unhide of missing node should return false")
	}
	_ = os.Remove(base.DataFile)
}
