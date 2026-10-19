// Package live 对应 Python shunt/live.py：实时速率 / 内存（订阅 /traffic 与 /memory 流）。
package live

import (
	"encoding/json"
	"net"
	"sync"
	"time"

	"shunt/internal/core"
	"shunt/internal/data"
	"shunt/internal/errlog"
	"shunt/internal/logstream"
)

// STUB:core.ConnsSnapshot —— 接线到 core.ConnsSnapshot（ttl=2 秒，与 Python conns_snapshot(timeout=5, ttl=2) 一致）
func connsSnapshot(timeoutSec int) map[string]any {
	v, _ := core.ConnsSnapshot(timeoutSec, 2).(map[string]any)
	return v
}

var (
	liveMu sync.Mutex
	// LIVE 实时状态：up/down 瞬时速率，upTotal/downTotal 累计，inuse/oslimit 内存
	LIVE = map[string]any{
		"up": 0, "down": 0, "upTotal": 0, "downTotal": 0,
		"inuse": 0, "oslimit": 0, "t": 0,
	}
)

// Live 返回实时状态的副本。
func Live() map[string]any {
	liveMu.Lock()
	defer liveMu.Unlock()
	out := make(map[string]any, len(LIVE))
	for k, v := range LIVE {
		out[k] = v
	}
	return out
}

func liveFloat(key string) float64 {
	if f, ok := LIVE[key].(float64); ok {
		return f
	}
	return 0
}

// LiveLoop 对应 live_loop(path)：订阅核心的 /traffic 或 /memory 流，断线 3 秒后重连。
func LiveLoop(path string) {
	for {
		stop := &logstream.Stop{}
		sink := func(line string) {
			var j map[string]any
			if err := json.Unmarshal([]byte(line), &j); err != nil {
				return
			}
			liveMu.Lock()
			defer liveMu.Unlock()
			if path == "/memory" {
				if data.Int(j, "inuse") != 0 { // 首条消息固定为 0
					LIVE["inuse"], LIVE["oslimit"] = data.Int(j, "inuse"), data.Int(j, "oslimit")
				}
				return
			}
			LIVE["up"], LIVE["down"] = data.Int(j, "up"), data.Int(j, "down")
			_, hasUp := j["upTotal"]
			_, hasDown := j["downTotal"]
			if hasUp || hasDown {
				LIVE["upTotal"], LIVE["downTotal"] = data.Int(j, "upTotal"), data.Int(j, "downTotal")
			} else if time.Since(time.Unix(int64(liveFloat("_tt")), 0)) > 2*time.Second {
				// sing-box 的 /traffic 不带累计值，从 /connections 取
				LIVE["_tt"] = float64(time.Now().Unix())
				c := connsSnapshot(3)
				if c == nil {
					c = map[string]any{}
				}
				LIVE["upTotal"] = data.Int(c, "uploadTotal")
				LIVE["downTotal"] = data.Int(c, "downloadTotal")
			}
			LIVE["t"] = float64(time.Now().UnixNano()) / 1e9
		}
		err := logstream.CoreStream(path, sink, stop, 15*time.Second)
		if err != nil {
			if _, ok := err.(net.Error); !ok { // 内核未运行 / 断线（OSError）稍后重连
				errlog.LogErr("实时速率", err, false)
			}
		}
		liveMu.Lock()
		if path == "/traffic" {
			LIVE["up"], LIVE["down"], LIVE["t"] = 0, 0, 0
		} else {
			LIVE["inuse"] = 0
		}
		liveMu.Unlock()
		time.Sleep(3 * time.Second)
	}
}

// MemoryOnce 对应 memory_once()：不依赖后台线程，读取 /memory 流的前两行（首行恒为 0）。
func MemoryOnce() map[string]any {
	var mu sync.Mutex
	var got []map[string]any
	stop := &logstream.Stop{}
	sink := func(line string) {
		var j map[string]any
		if err := json.Unmarshal([]byte(line), &j); err != nil {
			return
		}
		mu.Lock()
		got = append(got, j)
		done := data.Int(j, "inuse") != 0 || len(got) >= 2
		mu.Unlock()
		if done {
			stop.MarkStop()
			stop.Shutdown()
		}
	}
	_ = logstream.CoreStream("/memory", sink, stop, 3*time.Second)
	mu.Lock()
	defer mu.Unlock()
	for i := len(got) - 1; i >= 0; i-- {
		if data.Int(got[i], "inuse") != 0 {
			return got[i]
		}
	}
	return map[string]any{"inuse": 0, "oslimit": 0}
}
