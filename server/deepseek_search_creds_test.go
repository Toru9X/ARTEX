package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestDeepSeekSearchCredsOverride pins how the "deepseek" search backend picks
// its credentials: a dedicated key may replace the active LLM profile, and each
// of the three fields falls back on its own rather than all-or-nothing.
func TestDeepSeekSearchCredsOverride(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("manager unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	profile := &db.LLMProfile{Name: "ds-active", Format: "anthropic", Model: "claude-x", BaseURL: "https://api.active.example", APIKey: "sk-active"}
	id, err := m.pg.SaveProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.pg.SetActiveProfile(id); err != nil {
		t.Fatal(err)
	}
	if err := m.SetWebSearch(true, deepSeekWebSearchBackend, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	set := func(key, value string) {
		t.Helper()
		if err := m.pg.SetSetting(key, value); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, key := range []string{settingDeepSeekSearchKey, settingDeepSeekSearchBaseURL, settingDeepSeekSearchModel} {
			_ = m.pg.SetSetting(key, "")
		}
	})

	// 1. No dedicated settings: the active profile is used, exactly as before.
	got := m.WebSearchOpts()
	if got.DeepSeekBaseURL != profile.BaseURL || got.DeepSeekAPIKey != profile.APIKey || got.DeepSeekModel != profile.Model {
		t.Fatalf("without an override, the active profile must be used: %+v", got)
	}

	// 2. All three set: the profile is not consulted at all.
	set(settingDeepSeekSearchKey, "sk-dedicated")
	set(settingDeepSeekSearchBaseURL, "https://search.deepseek.example")
	set(settingDeepSeekSearchModel, "deepseek-search")
	got = m.WebSearchOpts()
	if got.DeepSeekAPIKey != "sk-dedicated" || got.DeepSeekBaseURL != "https://search.deepseek.example" || got.DeepSeekModel != "deepseek-search" {
		t.Fatalf("the dedicated settings were not used: %+v", got)
	}

	// 3. Only the key is set: base URL and model still come from the profile.
	set(settingDeepSeekSearchBaseURL, "")
	set(settingDeepSeekSearchModel, "")
	got = m.WebSearchOpts()
	if got.DeepSeekAPIKey != "sk-dedicated" {
		t.Fatalf("the dedicated key was lost: %+v", got)
	}
	if got.DeepSeekBaseURL != profile.BaseURL || got.DeepSeekModel != profile.Model {
		t.Fatalf("missing fields must fall back per field, not all-or-nothing: %+v", got)
	}
}
