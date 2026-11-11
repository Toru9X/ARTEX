package server

import (
	"os"
	"path/filepath"
	"testing"
)

// The side-channel evidence file must stay inside the task's data directory:
// relative and absolute paths inside it resolve, anything outside is refused.
func TestSideChannelFileConfinement(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "tasks", "7")
	if err := os.MkdirAll(filepath.Join(root, "i3"), 0o755); err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(root, "i3", "oob.log")
	out := filepath.Join(base, "secret.txt")
	for _, f := range []string{in, out} {
		if err := os.WriteFile(f, []byte("hit from 10.0.0.5 token-abc123xyz789"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if p, err := insideDir(root, "i3/oob.log"); err != nil || p == "" {
		t.Fatalf("relative path inside root refused: %v", err)
	}
	if _, err := insideDir(root, in); err != nil {
		t.Fatalf("absolute path inside root refused: %v", err)
	}
	for _, bad := range []string{out, "../../secret.txt", ""} {
		if _, err := insideDir(root, bad); err == nil {
			t.Errorf("%q outside the task directory was accepted", bad)
		}
	}
	if ok, err := fileContains(in, "token-abc123xyz789"); err != nil || !ok {
		t.Fatalf("token not found: %v", err)
	}
}
