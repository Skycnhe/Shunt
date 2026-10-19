package static

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shunt/internal/base"
)

func withBase(t *testing.T, dir string) {
	t.Helper()
	old := base.Base
	base.Base = dir
	t.Cleanup(func() { base.Base = old })
	cacheMu.Lock()
	cache = map[string]staticEntry{}
	cacheMu.Unlock()
}

func TestManifest(t *testing.T) {
	if Manifest["name"] != "Shunt 分流" {
		t.Fatalf("manifest=%v", Manifest)
	}
	icons, _ := Manifest["icons"].([]any)
	if len(icons) != 2 {
		t.Fatalf("icons=%v", icons)
	}
}

func TestStaticFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	withBase(t, dir)
	content := []byte("<html><body>hello shunt</body></html>")
	if err := os.WriteFile(filepath.Join(dir, "index.html"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	raw, gz, etag, ctype, ok := StaticFile("index.html")
	if !ok {
		t.Fatal("should hit")
	}
	if string(raw) != string(content) {
		t.Fatal("raw mismatch")
	}
	if len(gz) == 0 {
		t.Fatal("html should be gzipped")
	}
	want := `"` + fmt.Sprintf("%x", md5.Sum(content))[:16] + `"`
	if etag != want {
		t.Fatalf("etag=%q want %q", etag, want)
	}
	if ctype != "text/html" {
		t.Fatalf("ctype=%q", ctype)
	}
	// 第二次命中缓存
	raw2, _, etag2, _, ok2 := StaticFile("index.html")
	if !ok2 || string(raw2) != string(raw) || etag2 != etag {
		t.Fatal("cache miss on second call")
	}
	// png 不压缩
	png := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00}
	if err := os.WriteFile(filepath.Join(dir, "icon-180.png"), png, 0o644); err != nil {
		t.Fatal(err)
	}
	_, gzPng, _, ctypePng, ok := StaticFile("icon-180.png")
	if !ok || gzPng != nil || ctypePng != "image/png" {
		t.Fatalf("png: ok=%v gz=%v ctype=%q", ok, gzPng != nil, ctypePng)
	}
	// 未知类型
	if err := os.WriteFile(filepath.Join(dir, "a.bin"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, _, ctypeBin, _ := StaticFile("a.bin")
	if ctypeBin != "application/octet-stream" {
		t.Fatalf("ctype=%q", ctypeBin)
	}
}

func TestStaticFilePngFallback(t *testing.T) {
	dir := t.TempDir()
	withBase(t, dir)
	png := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x01, 0x02}
	b64 := base64.StdEncoding.EncodeToString(png)
	html := `<html><head><link rel="apple-touch-icon" href="data:image/png;base64,` + b64 + `"></head></html>`
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(html), 0o644); err != nil {
		t.Fatal(err)
	}
	// icon-180.png 文件不存在 → 从 index.html 内嵌图标取
	raw, gz, etag, ctype, ok := StaticFile("icon-180.png")
	if !ok {
		t.Fatal("fallback should hit")
	}
	if string(raw) != string(png) {
		t.Fatal("fallback raw mismatch")
	}
	if gz != nil || ctype != "image/png" {
		t.Fatalf("gz=%v ctype=%q", gz != nil, ctype)
	}
	if !strings.HasPrefix(etag, `"i`) || len(etag) != 19 {
		t.Fatalf("etag=%q", etag)
	}
}

func TestStaticFileMissing(t *testing.T) {
	dir := t.TempDir()
	withBase(t, dir)
	if _, _, _, _, ok := StaticFile("no-such-file.xyz"); ok {
		t.Fatal("missing non-png should not be ok")
	}
	// index.html 也不存在时 png 回退失败
	if _, _, _, _, ok := StaticFile("icon-180.png"); ok {
		t.Fatal("png fallback without index.html should not be ok")
	}
}
