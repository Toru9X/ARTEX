package server

import (
	"os"
	"path/filepath"
	"testing"
)

// A stored interpreter path missing on this host (a Windows path carried into the
// Docker image) must fall back to live detection instead of breaking script tools.
func TestPythonInterpreterIgnoresMissingStoredPath(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer m.Close()
	old, exists, err := m.pg.GetSetting(settingPythonInterp)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if exists {
			_ = m.pg.SetSetting(settingPythonInterp, old)
		} else {
			_, _ = m.pg.Exec("DELETE FROM settings WHERE key=$1", settingPythonInterp)
		}
	}()
	s := &Server{m: m}

	missing := `C:\nope\Python313\python.exe`
	if err := m.pg.SetSetting(settingPythonInterp, missing); err != nil {
		t.Fatal(err)
	}
	if got := s.pythonInterpreter(); got != detectPython() {
		t.Fatalf("missing stored path: got %q, want live detection %q", got, detectPython())
	}

	real := filepath.Join(t.TempDir(), "python")
	if err := os.WriteFile(real, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := m.pg.SetSetting(settingPythonInterp, real); err != nil {
		t.Fatal(err)
	}
	if got := s.pythonInterpreter(); got != real {
		t.Fatalf("existing stored path: got %q, want %q", got, real)
	}
}
