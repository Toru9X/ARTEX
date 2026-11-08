package server

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestBrowserMCPArgsScreenshotToggle(t *testing.T) {
	// Off: only the baseline flags are added, and a persistent profile survives.
	off := ensureBrowserMCPArgs([]string{"--user-data-dir=/tmp/profile"}, false)
	for _, want := range []string{"--headless", "--no-sandbox", "--user-data-dir=/tmp/profile"} {
		if !slices.Contains(off, want) {
			t.Fatalf("screenshot off lost %s: %v", want, off)
		}
	}
	for _, unwanted := range []string{"--isolated", "--ignore-https-errors"} {
		if slices.Contains(off, unwanted) {
			t.Fatalf("screenshot off added %s: %v", unwanted, off)
		}
	}

	// On: Playwright rejects --isolated together with --user-data-dir, so the
	// stale persistent profile has to go, in both spellings.
	for _, profile := range [][]string{{"--user-data-dir", "/tmp/profile"}, {"--user-data-dir=/tmp/profile"}} {
		on := ensureBrowserMCPArgs(profile, true)
		for _, want := range []string{"--headless", "--no-sandbox", "--ignore-https-errors", "--isolated"} {
			if !slices.Contains(on, want) {
				t.Fatalf("screenshot on lost %s: %v", want, on)
			}
		}
		for _, arg := range on {
			if arg == "--user-data-dir" || arg == "/tmp/profile" || arg == "--user-data-dir=/tmp/profile" {
				t.Fatalf("screenshot on kept the persistent profile: %v", on)
			}
		}
	}

	// Idempotent: a second pass adds nothing.
	once := ensureBrowserMCPArgs(nil, true)
	if twice := ensureBrowserMCPArgs(once, true); len(twice) != len(once) {
		t.Fatalf("not idempotent: %v then %v", once, twice)
	}

	// The input slice is never mutated.
	input := []string{"--headless"}
	_ = ensureBrowserMCPArgs(input, true)
	if len(input) != 1 {
		t.Fatalf("input mutated: %v", input)
	}
}

func TestBrowserScreenshotToolDetection(t *testing.T) {
	for _, name := range []string{"browser_take_screenshot", "Browser_Screenshot", " screenshot "} {
		if !isBrowserScreenshotTool(name) {
			t.Fatalf("%q should be a screenshot tool", name)
		}
	}
	for _, name := range []string{"browser_navigate", "traffic_search", ""} {
		if isBrowserScreenshotTool(name) {
			t.Fatalf("%q should not be a screenshot tool", name)
		}
	}
}

func TestResolveExportScreenshot(t *testing.T) {
	workspace := t.TempDir()
	rel := filepath.Join("findings", "screenshots", "finding-7-step-1.png")
	session := filepath.Join(workspace, "sessions", "conv-1", rel)
	if err := os.MkdirAll(filepath.Dir(session), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(session, []byte("png"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A leading slash is deliberately not listed: on POSIX that is an absolute
	// path and takes the in-workspace branch below instead.
	for _, raw := range []string{
		"findings/screenshots/finding-7-step-1.png",
		"workspace://findings/screenshots/finding-7-step-1.png",
	} {
		got, ok := resolveExportScreenshot(workspace, raw)
		if !ok || got != session {
			t.Fatalf("%q resolved to %q (%v), want %q", raw, got, ok, session)
		}
	}

	// The newest session wins when several hold the same relative path.
	older := filepath.Join(workspace, "sessions", "conv-0", rel)
	if err := os.MkdirAll(filepath.Dir(older), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(older, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-time.Hour)
	if err := os.Chtimes(older, stale, stale); err != nil {
		t.Fatal(err)
	}
	if got, ok := resolveExportScreenshot(workspace, "findings/screenshots/finding-7-step-1.png"); !ok || got != session {
		t.Fatalf("newest session not preferred: %q", got)
	}

	// An absolute path is accepted only inside the workspace.
	if got, ok := resolveExportScreenshot(workspace, session); !ok || got != session {
		t.Fatalf("absolute in-workspace path rejected: %q %v", got, ok)
	}
	outside := filepath.Join(t.TempDir(), "evil.png")
	if err := os.WriteFile(outside, []byte("png"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := resolveExportScreenshot(workspace, outside); ok {
		t.Fatal("an absolute path outside the workspace must be refused")
	}

	// Anything that is not a findings screenshot, or escapes upward, is refused.
	for _, raw := range []string{"", "notes/secret.png", "findings/screenshots/../../secret.png", "findings/screenshots/missing.png"} {
		if _, ok := resolveExportScreenshot(workspace, raw); ok {
			t.Fatalf("%q should not resolve", raw)
		}
	}
}

func TestReportScreenshotTimestampUsesFixedZone(t *testing.T) {
	at := time.Date(2026, 11, 8, 4, 30, 0, 0, time.UTC)
	if got := reportScreenshotTimestamp(at); got != "2026-11-08 12:30:00" {
		t.Fatalf("timestamp = %q, want the UTC+8 report zone", got)
	}
}
