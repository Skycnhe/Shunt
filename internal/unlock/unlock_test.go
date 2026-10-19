package unlock

import "testing"

func TestUnlockChecks(t *testing.T) {
	want := []string{"出口位置", "Netflix", "ChatGPT", "Disney+", "YouTube Premium", "Gemini"}
	if len(UnlockChecks) != len(want) {
		t.Fatalf("UnlockChecks 条数 = %d, want %d", len(UnlockChecks), len(want))
	}
	for i, c := range UnlockChecks {
		if c.Name != want[i] {
			t.Errorf("UnlockChecks[%d].Name = %q, want %q", i, c.Name, want[i])
		}
		if c.Fn == nil {
			t.Errorf("UnlockChecks[%d].Fn 为 nil", i)
		}
	}
}
