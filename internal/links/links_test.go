package links

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestQ1(t *testing.T) {
	qs := map[string][]string{"a": {""}, "b": {"x", "y"}}
	if Q1(qs, "a", "b") != "x" {
		t.Fatal("q1 should skip empty first value")
	}
	if Q1(qs, "zzz") != "" {
		t.Fatal("q1 default should be empty")
	}
}

func TestHostPort(t *testing.T) {
	h, p, err := HostPort("example.com:443")
	if err != nil || h != "example.com" || p != "443" {
		t.Fatalf("got %q %q %v", h, p, err)
	}
	h, p, err = HostPort("[::1]:443,8443-8445")
	if err != nil || h != "::1" || p != "443,8443-8445" {
		t.Fatalf("ipv6 multiport: got %q %q %v", h, p, err)
	}
	if _, _, err = HostPort("noport"); err == nil {
		t.Fatal("expected error for missing port")
	}
}

func TestParseVless(t *testing.T) {
	p, err := ParseLink("vless://550e8400-e29b-41d4-a716-446655440000@example.com:2053?security=reality&pbk=PUBKEY&sid=abcd&fp=chrome&sni=www.microsoft.com&type=ws&path=%2Fws&host=example.com#Test%20Node")
	if err != nil {
		t.Fatal(err)
	}
	if p["type"] != "vless" || p["server"] != "example.com" || p["port"] != 2053 {
		t.Fatalf("basic fields: %+v", p)
	}
	if p["name"] != "Test Node" {
		t.Fatalf("name not unquoted: %q", p["name"])
	}
	if p["tls"] != true {
		t.Fatal("tls should be true for reality")
	}
	ro := p["reality-opts"].(map[string]any)
	if ro["public-key"] != "PUBKEY" || ro["short-id"] != "abcd" {
		t.Fatalf("reality-opts: %+v", ro)
	}
	if p["network"] != "ws" {
		t.Fatalf("network: %v", p["network"])
	}
}

func TestParseTrojan(t *testing.T) {
	p, err := ParseLink("trojan://pass@example.com:443?sni=sni.example.com#trojan1")
	if err != nil {
		t.Fatal(err)
	}
	if p["type"] != "trojan" || p["password"] != "pass" || p["sni"] != "sni.example.com" {
		t.Fatalf("trojan: %+v", p)
	}
}

func TestParseHysteria2MultiPort(t *testing.T) {
	p, err := ParseLink("hy2://secret@example.com:443,8443-8445?obfs=salamander&obfs-password=pw#hy2node")
	if err != nil {
		t.Fatal(err)
	}
	if p["port"] != 443 {
		t.Fatalf("first port: %v", p["port"])
	}
	if p["ports"] != "443,8443-8445" {
		t.Fatalf("ports: %v", p["ports"])
	}
	if p["obfs"] != "salamander" {
		t.Fatalf("obfs: %v", p["obfs"])
	}
}

func TestParseSsOldFormat(t *testing.T) {
	raw := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:secret@example.com:8388"))
	p, err := ParseLink("ss://" + raw + "#oldss")
	if err != nil {
		t.Fatal(err)
	}
	if p["cipher"] != "aes-256-gcm" || p["password"] != "secret" || p["server"] != "example.com" || p["port"] != 8388 {
		t.Fatalf("ss old format: %+v", p)
	}
}

func TestParseVmess(t *testing.T) {
	j, _ := json.Marshal(map[string]any{"ps": "v1", "add": "v.example.com", "port": "443", "id": "uuid-1", "aid": "0", "net": "ws", "type": "none", "host": "v.example.com", "path": "/p", "tls": "tls"})
	line := "vmess://" + base64.StdEncoding.EncodeToString(j)
	p, err := ParseLink(line)
	if err != nil {
		t.Fatal(err)
	}
	if p["type"] != "vmess" || p["server"] != "v.example.com" || p["port"] != 443 || p["tls"] != true {
		t.Fatalf("vmess: %+v", p)
	}
	if p["network"] != "ws" {
		t.Fatalf("vmess ws network: %v", p["network"])
	}
}

func TestParseLinkUnknown(t *testing.T) {
	if _, err := ParseLink("wireguard://abc@x:1#n"); err == nil {
		t.Fatal("expected error for unknown scheme")
	}
}

func TestAddLinksDedup(t *testing.T) {
	text := "vless://u1@h1:1#Node\nvless://u2@h2:2#Node\nnot-a-link\nvless://u3@h3#NoPort"
	existing := []map[string]any{{"proxy": map[string]any{"name": "Node"}}}
	out, errs := AddLinks(text, existing, nil)
	if len(out) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(out))
	}
	names := []string{out[0]["proxy"].(map[string]any)["name"].(string), out[1]["proxy"].(map[string]any)["name"].(string)}
	if names[0] != "Node (2)" || names[1] != "Node (3)" {
		t.Fatalf("dedup names: %v", names)
	}
	if len(errs) != 2 {
		t.Fatalf("expected 2 errors, got %v", errs)
	}
	if !strings.HasPrefix(errs[0], "第 3 行：") {
		t.Fatalf("error format: %v", errs)
	}
}

func TestReservedNames(t *testing.T) {
	r := ReservedNames(nil)
	for _, n := range []string{"🚀 节点选择", "🖐️ 手动选择", "GLOBAL", "DIRECT", "🏠 直连"} {
		if !r[n] {
			t.Fatalf("%q should be reserved", n)
		}
	}
	if !r["🇭🇰 香港"] {
		t.Fatal("region name should be reserved")
	}
	d := map[string]any{"custom_groups": []any{map[string]any{"name": "MyGroup"}}}
	if !ReservedNames(d)["MyGroup"] {
		t.Fatal("custom group name should be reserved")
	}
}

func TestTruthy(t *testing.T) {
	for _, v := range []string{"1", "true", "yes", "TRUE"} {
		if !Truthy(v) {
			t.Fatalf("%q should be truthy", v)
		}
	}
	if Truthy("0") || Truthy("") {
		t.Fatal("0/empty should be falsy")
	}
}
