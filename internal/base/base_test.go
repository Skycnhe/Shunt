package base

import (
	"testing"
)

func TestDefaultsLoaded(t *testing.T) {
	if PanelVersion != "10.2.7" {
		t.Fatalf("PanelVersion = %q", PanelVersion)
	}
	if Schema != 9 {
		t.Fatalf("Schema = %d", Schema)
	}
	if len(Regions) != 21 {
		t.Fatalf("Regions len = %d, want 21", len(Regions))
	}
	if Regions[0].Name != "🇭🇰 香港" {
		t.Fatalf("Regions[0] = %q", Regions[0].Name)
	}
	if Default["core"] != "mihomo" {
		t.Fatalf("Default[core] = %v", Default["core"])
	}
	if len(DefaultFakeFilter) != 10 {
		t.Fatalf("DefaultFakeFilter len = %d", len(DefaultFakeFilter))
	}
	if len(TestsDefault) != 6 {
		t.Fatalf("TestsDefault len = %d", len(TestsDefault))
	}
	if len(AbPresets) != 10 {
		t.Fatalf("AbPresets len = %d", len(AbPresets))
	}
	if len(CnAppDomains) == 0 {
		t.Fatal("CnAppDomains empty")
	}
	// CnDNS 正则可用
	if !CnDNS.MatchString("https://223.5.5.5/dns-query") {
		t.Fatal("CnDNS should match 223.5.5.5")
	}
	// FakeIP 网段
	if len(FakeIPNets) != 3 {
		t.Fatalf("FakeIPNets len = %d", len(FakeIPNets))
	}
}

func TestSharedState(t *testing.T) {
	if !UpdBegin("panel") {
		t.Fatal("UpdBegin should succeed")
	}
	if UpdBegin("core") {
		t.Fatal("UpdBegin should fail while panel busy")
	}
	UpdEnd("panel")
	if !UpdBegin("core") {
		t.Fatal("UpdBegin(core) should succeed after release")
	}
	UpdEnd("core")

	tok := MassBegin()
	if !MassTesting() {
		t.Fatal("MassTesting should be true")
	}
	MassEnd(tok)
	if MassTesting() {
		t.Fatal("MassTesting should be false")
	}
}

func TestUrlHostForbidden(t *testing.T) {
	if !UrlHostForbidden("http://192.168.1.1/x", false) {
		t.Fatal("literal private IP should be forbidden")
	}
	if !UrlHostForbidden("http://localhost/x", false) {
		t.Fatal("localhost should be forbidden")
	}
	if UrlHostForbidden("https://www.google.com/x", true) {
		t.Fatal("public host via proxy should be allowed")
	}
}
