package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// proxyTestManager opens a Manager against the test database, skipping when
// no PostgreSQL is configured.
func proxyTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// preserveEgressProbeSetting restores the row these tests overwrite. The dev
// database is shared, so a test must not leave a custom probe behind.
func preserveEgressProbeSetting(t *testing.T, m *Manager) {
	t.Helper()
	old, existed, err := m.pg.GetSetting(settingEgressProbeURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if existed {
			if err := m.pg.SetSetting(settingEgressProbeURL, old); err != nil {
				t.Error(err)
			}
		} else if _, err := m.pg.Exec("DELETE FROM settings WHERE key=$1", settingEgressProbeURL); err != nil {
			t.Error(err)
		}
	})
}

// The probe URL goes through the settings endpoint, so it must authenticate,
// validate before storing, survive a restart, and be clearable.
func TestEgressProbeSettingsPersistence(t *testing.T) {
	m := proxyTestManager(t)
	preserveEgressProbeSetting(t, m)
	if _, err := m.pg.Exec("DELETE FROM settings WHERE key=$1", settingEgressProbeURL); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New(ctx, m, dir, dir, dir)
	s.archiveWG.Wait()
	<-s.side.done
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, body string, authenticated bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/settings", strings.NewReader(body))
		if authenticated {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		return w
	}
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		if w := request(method, `{"egress_probe_url":"http://10.0.0.5/ip"}`, false); w.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s: %d", method, w.Code)
		}
	}
	assertResponse := func(method, body, want string) {
		t.Helper()
		w := request(method, body, true)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status=%d body=%s", method, w.Code, w.Body.String())
		}
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		var got string
		if err := json.Unmarshal(payload[settingEgressProbeURL], &got); err != nil || got != want {
			t.Fatalf("egress_probe_url=%q want=%q err=%v", got, want, err)
		}
	}
	assertResponse(http.MethodGet, "", "")
	if got := m.egressProbes(); !reflect.DeepEqual(got, defaultEgressProbes) {
		t.Fatalf("default probes=%v", got)
	}
	const custom = "http://192.168.132.130:19000/ip"
	assertResponse(http.MethodPut, `{"egress_probe_url":"  `+custom+`  "}`, custom)
	assertResponse(http.MethodGet, "", custom)
	// A PUT that omits the field, or sends null, must leave it alone.
	assertResponse(http.MethodPut, `{}`, custom)
	assertResponse(http.MethodPut, `{"egress_probe_url":null}`, custom)
	for _, invalid := range []string{"ftp://example.com/ip", "/relative", "http://127.0.0.1:8787", "http://169.254.169.254/latest", "http://[::1]/", "http://2130706433/"} {
		body, _ := json.Marshal(map[string]string{settingEgressProbeURL: invalid})
		if w := request(http.MethodPut, string(body), true); w.Code != http.StatusBadRequest {
			t.Fatalf("invalid URL %q accepted: %d %s", invalid, w.Code, w.Body.String())
		}
		assertResponse(http.MethodGet, "", custom)
	}
	// A fresh manager must read the persisted value, without sharing runtime state.
	reloaded := proxyTestManager(t)
	if got := reloaded.egressProbes(); !reflect.DeepEqual(got, []string{custom}) {
		t.Fatalf("reloaded probes=%v", got)
	}
	assertResponse(http.MethodPut, `{"egress_probe_url":"  "}`, "")
	if got := reloaded.egressProbes(); !reflect.DeepEqual(got, defaultEgressProbes) {
		t.Fatalf("cleared probes=%v", got)
	}
}

// A temporary probe_url in the request body must not touch the saved setting,
// and an omitted one must fall back to it.
func TestEgressProbeSavedAndTemporaryURLs(t *testing.T) {
	m := proxyTestManager(t)
	preserveEgressProbeSetting(t, m)
	const saved = "http://10.0.0.5/ip"
	if err := m.pg.SetSetting(settingEgressProbeURL, saved); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: m}
	for _, tc := range []struct {
		name string
		body string
		want []string
	}{
		{"omitted uses saved", `{}`, []string{saved}},
		{"null uses saved", `{"probe_url":null}`, []string{saved}},
		{"unsaved override", `{"probe_url":" https://example.com/ip "}`, []string{"https://example.com/ip"}},
		{"empty previews defaults", `{"probe_url":""}`, defaultEgressProbes},
		{"whitespace previews defaults", `{"probe_url":"  "}`, defaultEgressProbes},
		{"global proxy uses saved", `{"global_proxy":"http://10.0.0.9:8080"}`, []string{saved}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s.proxyProbe = func(_ context.Context, _, _ string, probes []string, _ time.Duration) egressProbeResult {
				calls++
				if !reflect.DeepEqual(probes, tc.want) {
					t.Fatalf("probes=%v want=%v", probes, tc.want)
				}
				return egressProbeResult{OK: true, ExitIP: "203.0.113.7", Probes: []egressAttempt{}}
			}
			w := httptest.NewRecorder()
			s.testEgressProxy(w, httptest.NewRequest(http.MethodPost, "/api/settings/proxy/test", strings.NewReader(tc.body)))
			// A configured proxy adds the second (global) check.
			wantCalls := 1
			if strings.Contains(tc.body, "global_proxy") {
				wantCalls = 2
			}
			if w.Code != http.StatusOK || calls != wantCalls {
				t.Fatalf("status=%d calls=%d body=%s", w.Code, calls, w.Body.String())
			}
			if got := m.EgressProbeURL(); got != saved {
				t.Fatalf("a temporary probe changed the saved setting: %q", got)
			}
		})
	}
	s.proxyProbe = func(context.Context, string, string, []string, time.Duration) egressProbeResult {
		t.Fatal("an invalid URL must not send a probe")
		return egressProbeResult{}
	}
	w := httptest.NewRecorder()
	s.testEgressProxy(w, httptest.NewRequest(http.MethodPost, "/api/settings/proxy/test", strings.NewReader(`{"probe_url":"http://127.0.0.1"}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid probe status=%d", w.Code)
	}
}
