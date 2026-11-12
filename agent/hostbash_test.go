package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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

// A Git-Bash style /c/... path to an existing file reaches native python as
// C:/..., not as the broken C:\c\... the model produced before.
func TestHostBashConvertsExistingPosixPaths(t *testing.T) {
	if gitBash() == "" {
		t.Skip("no Git Bash on this host (or not Windows)")
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "x.py")
	if err := os.WriteFile(f, []byte("print('ok-run')"), 0o600); err != nil {
		t.Fatal(err)
	}
	posix := "/" + strings.ToLower(f[:1]) + filepath.ToSlash(f[2:])
	tool := HostBash(actool.NewBash())
	in, _ := json.Marshal(map[string]any{"command": "python " + posix + " && python3 -c \"import sys;print(sys.argv[1])\" path=/etc/passwd"})
	res, err := tool.Call(context.Background(), in, &actool.ToolContext{WorkingDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		b.WriteString(c.Text)
	}
	if res.IsError || !strings.Contains(b.String(), "ok-run") || !strings.Contains(b.String(), "path=/etc/passwd") {
		t.Fatalf("err=%v out=%q", res.IsError, b.String())
	}
}
