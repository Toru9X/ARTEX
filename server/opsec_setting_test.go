package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
)

// opsecServer wires a bare Server (no traffic store needed) and returns an
// authenticated request helper, mirroring ingestServer.
func opsecServer(t *testing.T) (*Server, func(method, path, body string) *httptest.ResponseRecorder) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { m.Close() })
	// New() installs the package-level agent hooks; put them back afterwards so
	// this test cannot leak a toggle into the rest of the package.
	prevOpsec := agent.OpsecEnabled
	t.Cleanup(func() { agent.OpsecEnabled = prevOpsec })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	s.archiveWG.Wait()
	<-s.side.done
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	return s, func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
}

func opsecFromSettings(t *testing.T, w *httptest.ResponseRecorder) bool {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode settings: %v (body = %s)", err, w.Body)
	}
	v, ok := got["opsec_enabled"]
	if !ok {
		t.Fatal("GET /api/settings does not expose opsec_enabled")
	}
	b, ok := v.(bool)
	if !ok {
		t.Fatalf("opsec_enabled = %#v, want a bool", v)
	}
	return b
}

// The toggle has to survive the whole path: HTTP → settings row → the hook the
// agents read at render time. A regression anywhere in that chain silently
// stops the OPSEC block from reaching any prompt.
func TestOpsecSettingRoundTrip(t *testing.T) {
	_, request := opsecServer(t)

	if opsecFromSettings(t, request("GET", "/api/settings", "")) {
		t.Fatal("opsec_enabled must default to false")
	}
	if agent.OpsecEnabled == nil {
		t.Fatal("the server did not wire agent.OpsecEnabled")
	}
	if agent.OpsecEnabled() {
		t.Fatal("the agent hook must report false before the setting is written")
	}

	if w := request("PUT", "/api/settings", `{"opsec_enabled":true}`); w.Code != 200 {
		t.Fatalf("enable: status = %d, body = %s", w.Code, w.Body)
	}
	if !opsecFromSettings(t, request("GET", "/api/settings", "")) {
		t.Fatal("opsec_enabled did not persist as true")
	}
	if !agent.OpsecEnabled() {
		t.Fatal("the agent hook still reports false after enabling")
	}

	if w := request("PUT", "/api/settings", `{"opsec_enabled":false}`); w.Code != 200 {
		t.Fatalf("disable: status = %d, body = %s", w.Code, w.Body)
	}
	if opsecFromSettings(t, request("GET", "/api/settings", "")) {
		t.Fatal("opsec_enabled did not persist as false")
	}
	if agent.OpsecEnabled() {
		t.Fatal("the agent hook still reports true after disabling")
	}
}

// A PUT that omits the field must not reset it — the settings endpoint patches,
// it does not replace.
func TestOpsecSettingUntouchedByUnrelatedPut(t *testing.T) {
	_, request := opsecServer(t)

	if w := request("PUT", "/api/settings", `{"opsec_enabled":true}`); w.Code != 200 {
		t.Fatalf("enable: status = %d, body = %s", w.Code, w.Body)
	}
	if w := request("PUT", "/api/settings", `{"noa_compaction":false}`); w.Code != 200 {
		t.Fatalf("unrelated put: status = %d, body = %s", w.Code, w.Body)
	}
	if !opsecFromSettings(t, request("GET", "/api/settings", "")) {
		t.Fatal("an unrelated PUT cleared opsec_enabled")
	}
}
