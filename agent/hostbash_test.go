package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// On a Windows host with Git Bash, the Bash tool runs real bash: pipes, GNU
// tools, exit codes, UTF-8, and arguments reach native programs unconverted.
func TestHostBashRunsBash(t *testing.T) {
	if gitBash() == "" {
		t.Skip("no Git Bash on this host (or not Windows)")
	}
	tool := HostBash(actool.NewBash())
	if !strings.Contains(tool.Description(), "bash") {
		t.Fatalf("description does not say bash: %s", tool.Description())
	}
	run := func(cmd string) (string, bool) {
		in, _ := json.Marshal(map[string]any{"command": cmd})
		res, err := tool.Call(context.Background(), in, &actool.ToolContext{WorkingDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		for _, c := range res.Content {
			b.WriteString(c.Text)
		}
		return b.String(), res.IsError
	}
	if out, isErr := run(`printf 'a\nb\nc\n' | head -2 | tail -1 && echo "kiểm thử ✓"`); isErr || !strings.Contains(out, "b\nkiểm thử ✓") {
		t.Fatalf("pipe/UTF-8: err=%v out=%q", isErr, out)
	}
	if out, isErr := run(`exit 3`); !isErr || !strings.Contains(out, "exit code 3") {
		t.Fatalf("exit code not propagated: err=%v out=%q", isErr, out)
	}
	if out, _ := run(`python3 -c "import sys; print(sys.argv[1])" path=/etc/passwd`); !strings.Contains(out, "path=/etc/passwd") {
		t.Fatalf("argument was path-converted or python3 missing: %q", out)
	}
}
