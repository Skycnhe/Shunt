// Package static 对应 Python shunt/static.py：静态资源 gzip + ETag。
package static

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"shunt/internal/base"
)

var (
	cacheMu sync.Mutex
	// STATIC 按文件修改时间缓存
	cache = map[string]staticEntry{}
)

type staticEntry struct {
	mtime int64
	size  int64
	raw   []byte
	gz    []byte // png 不压缩，为 nil
	etag  string
	ctype string
}

// StaticTypes 对应 STATIC_TYPES
var StaticTypes = map[string]string{
	"index.html":   "text/html",
	"icon.svg":     "image/svg+xml",
	"icon-180.png": "image/png",
	"icon-512.png": "image/png",
}

// Manifest 对应 MANIFEST
var Manifest = map[string]any{
	"name": "Shunt 分流", "short_name": "Shunt", "description": "mihomo 旁路由面板",
	"start_url": "/", "scope": "/", "display": "standalone",
	"background_color": "#f2f2f7", "theme_color": "#0a84ff",
	"icons": []any{
		map[string]any{"src": "/icon-180.png", "sizes": "180x180", "type": "image/png"},
		map[string]any{"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"},
	},
}

var appleIconRe = regexp.MustCompile(`rel="apple-touch-icon" href="data:image/png;base64,([A-Za-z0-9+/=]+)"`)

// StaticFile 对应 static_file(name)：返回 (原始, gzip, etag, 类型, 是否命中)。
// 图标文件缺失时（旧版面板在线更新上来）从 index.html 内嵌的图标取。
func StaticFile(name string) (raw, gz []byte, etag, ctype string, ok bool) {
	path := filepath.Join(base.Base, name)
	if st, err := os.Stat(path); err == nil {
		key := [2]int64{st.ModTime().UnixNano(), st.Size()}
		cacheMu.Lock()
		if e, hit := cache[name]; hit && e.mtime == key[0] && e.size == key[1] {
			raw, gz, etag, ctype = e.raw, e.gz, e.etag, e.ctype
			cacheMu.Unlock()
			return raw, gz, etag, ctype, true
		}
		cacheMu.Unlock()
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, "", "", false
		}
		var z []byte
		if !strings.HasSuffix(name, ".png") {
			var buf bytes.Buffer
			w, _ := gzip.NewWriterLevel(&buf, 6)
			_, _ = w.Write(b)
			_ = w.Close()
			z = buf.Bytes()
		}
		ct := StaticTypes[name]
		if ct == "" {
			ct = "application/octet-stream"
		}
		e := staticEntry{
			mtime: key[0], size: key[1], raw: b, gz: z,
			etag: etagOf(b, ""), ctype: ct,
		}
		cacheMu.Lock()
		cache[name] = e
		cacheMu.Unlock()
		return e.raw, e.gz, e.etag, e.ctype, true
	}
	if !strings.HasSuffix(name, ".png") {
		return nil, nil, "", "", false
	}
	rawIdx, _, _, _, ok := StaticFile("index.html")
	if !ok {
		return nil, nil, "", "", false
	}
	m := appleIconRe.FindSubmatch(rawIdx)
	if m == nil {
		return nil, nil, "", "", false
	}
	rawPng, err := base64.StdEncoding.DecodeString(string(m[1]))
	if err != nil {
		return nil, nil, "", "", false
	}
	return rawPng, nil, etagOf(rawPng, "i"), "image/png", true
}

// etagOf 对应 Python 的 '"%s"' % md5(raw).hexdigest()[:16]（png 回退时前缀为 "i"）。
func etagOf(b []byte, prefix string) string {
	return `"` + prefix + fmt.Sprintf("%x", md5.Sum(b))[:16] + `"`
}
