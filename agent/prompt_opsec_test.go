package agent

import (
	"strings"
	"testing"
)

// withOpsec installs the OpsecEnabled hook for one test and restores it after.
func withOpsec(t *testing.T, enabled bool) {
	t.Helper()
	prev := OpsecEnabled
	OpsecEnabled = func() bool { return enabled }
	t.Cleanup(func() { OpsecEnabled = prev })
}

// withOverride installs a PromptOverride for one test and restores it after.
func withOverride(t *testing.T, tmpl string) {
	t.Helper()
	prev := PromptOverride
	PromptOverride = func(string) (string, bool) { return tmpl, true }
	t.Cleanup(func() { PromptOverride = prev })
}

type opsecVars struct{ Now string }

// The default is off: an unconfigured server must produce byte-identical
// prompts to the ones it produced before the toggle existed.
func TestRenderSystemWithoutOpsecIsUnchanged(t *testing.T) {
	prev := OpsecEnabled
	OpsecEnabled = nil
	t.Cleanup(func() { OpsecEnabled = prev })

	got := renderSystem("worker", "body {{.Now}}", opsecVars{Now: "T"})
	if got != "body T" {
		t.Fatalf("nil hook: renderSystem = %q, want %q", got, "body T")
	}

	withOpsec(t, false)
	got = renderSystem("worker", "body {{.Now}}", opsecVars{Now: "T"})
	if got != "body T" {
		t.Fatalf("hook off: renderSystem = %q, want %q", got, "body T")
	}
	if strings.Contains(got, "OPSEC") {
		t.Fatal("the OPSEC block leaked into a prompt while the toggle was off")
	}
}

// All three render paths must carry the tail. The point of keeping the block in
// code is that no DB prompt edit — not even one that breaks rendering — can drop
// the operational safety guidance.
func TestRenderSystemAppendsOpsecOnEveryPath(t *testing.T) {
	withOpsec(t, true)

	cases := []struct {
		name     string
		override string // "" installs no override
		def      string
		vars     any
		wantBody string
	}{
		{
			name:     "db template renders",
			override: "from db {{.Now}}",
			def:      "built-in {{.Now}}",
			vars:     opsecVars{Now: "T"},
			wantBody: "from db T",
		},
		{
			name:     "db template references an out-of-catalog var",
			override: "from db {{.NotInCatalog}}",
			def:      "built-in {{.Now}}",
			vars:     opsecVars{Now: "T"},
			wantBody: "built-in T",
		},
		{
			name:     "even the built-in default fails to render",
			override: "",
			def:      "built-in {{",
			vars:     opsecVars{Now: "T"},
			wantBody: "built-in {{",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.override != "" {
				withOverride(t, tc.override)
			} else {
				prev := PromptOverride
				PromptOverride = nil
				t.Cleanup(func() { PromptOverride = prev })
			}
			got := renderSystem("worker", tc.def, tc.vars)
			want := tc.wantBody + "\n\n" + opsecPromptBlock
			if got != want {
				t.Fatalf("renderSystem =\n%q\nwant\n%q", got, want)
			}
		})
	}
}

// The block is read by the model, so it must not carry CJK or full-width
// punctuation left over from the upstream fork this was ported from.
func TestOpsecPromptBlockIsEnglish(t *testing.T) {
	for _, r := range opsecPromptBlock {
		switch {
		case r >= 0x4E00 && r <= 0x9FFF, // CJK unified ideographs
			r >= 0x3000 && r <= 0x303F, // CJK punctuation, incl. the brackets
			r >= 0xFF00 && r <= 0xFFEF: // full-width forms
			t.Fatalf("non-English rune %q (U+%04X) in opsecPromptBlock", r, r)
		}
	}
	if !strings.Contains(opsecPromptBlock, "OPSEC") {
		t.Fatal("opsecPromptBlock should announce itself as OPSEC rules")
	}
}
