package db

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// settingsTestKeys returns n unique keys that cannot collide with real settings
// or with a parallel run, plus a cleanup that removes them.
func settingsTestKeys(t *testing.T, d *DB, n int) []string {
	t.Helper()
	stamp := time.Now().UnixNano()
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("test.atomic.%d.%d", stamp, i)
	}
	t.Cleanup(func() {
		for _, key := range keys {
			_, _ = d.Exec(`DELETE FROM settings WHERE key=$1`, key)
		}
	})
	return keys
}

// SetSettingsAtomic is what the proxy-pool settings endpoint uses to write its
// seven knobs as one unit: a half-applied rotation policy is worse than none.
func TestSetSettingsAtomicWritesAllKeys(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	keys := settingsTestKeys(t, d, 3)
	want := map[string]string{keys[0]: "a", keys[1]: "b", keys[2]: "c"}
	if err := d.SetSettingsAtomic(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	for key, expect := range want {
		got, ok, err := d.GetSetting(key)
		if err != nil || !ok {
			t.Fatalf("GetSetting(%q): ok=%v err=%v", key, ok, err)
		}
		if got != expect {
			t.Fatalf("GetSetting(%q) = %q, want %q", key, got, expect)
		}
	}

	// A second call must overwrite, not conflict on the primary key.
	want[keys[1]] = "b2"
	if err := d.SetSettingsAtomic(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := d.GetSetting(keys[1]); got != "b2" {
		t.Fatalf("second write: GetSetting(%q) = %q, want %q", keys[1], got, "b2")
	}
}

// An empty map is a no-op, not an error: callers build the map from whichever
// fields the request actually carried and must not special-case "none".
func TestSetSettingsAtomicEmptyMapIsNoOp(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	if err := d.SetSettingsAtomic(context.Background(), nil); err != nil {
		t.Fatalf("nil map: %v", err)
	}
	if err := d.SetSettingsAtomic(context.Background(), map[string]string{}); err != nil {
		t.Fatalf("empty map: %v", err)
	}
}

// The whole point of the transaction: a context that dies partway must leave
// every key at its previous value, never a mix of old and new.
func TestSetSettingsAtomicRollsBackOnDeadContext(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	keys := settingsTestKeys(t, d, 2)
	for _, key := range keys {
		if err := d.SetSetting(key, "before"); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already dead when the transaction starts
	if err := d.SetSettingsAtomic(ctx, map[string]string{keys[0]: "after", keys[1]: "after"}); err == nil {
		t.Fatal("a cancelled context must fail the write")
	}
	for _, key := range keys {
		got, ok, err := d.GetSetting(key)
		if err != nil || !ok {
			t.Fatalf("GetSetting(%q): ok=%v err=%v", key, ok, err)
		}
		if got != "before" {
			t.Fatalf("GetSetting(%q) = %q, want the pre-transaction value %q", key, got, "before")
		}
	}
}

// SetSettingContext is the deadline-aware single write that the basic-auth
// handler needs; a dead context must not silently write anyway.
func TestSetSettingContextHonoursCancellation(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	key := settingsTestKeys(t, d, 1)[0]
	if err := d.SetSetting(key, "before"); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.SetSettingContext(ctx, key, "after"); err == nil {
		t.Fatal("a cancelled context must fail the write")
	}
	if got, _, _ := d.GetSetting(key); got != "before" {
		t.Fatalf("GetSetting(%q) = %q, want the untouched value %q", key, got, "before")
	}

	// A live context still writes — the cancellation check must not break the
	// ordinary path that SetSetting now routes through.
	if err := d.SetSettingContext(context.Background(), key, "after"); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := d.GetSetting(key); got != "after" {
		t.Fatalf("GetSetting(%q) = %q, want %q", key, got, "after")
	}
}
