package db

import (
	"fmt"
	"testing"
	"time"
)

// CurrentPromptAuthor is what tells a prompt migration apart from a prompt the
// user wrote: the attribution-gate migration in server/orchestration.go skips an
// agent whose active version came from the agent page ("ui") instead of
// superseding it. If this ever stopped distinguishing the two, that migration
// would quietly overwrite everyone's customized prompts.
func TestCurrentPromptAuthorDistinguishesSeedFromUserEdit(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	key := fmt.Sprintf("prompt_author_%d", time.Now().UnixNano())
	a, err := d.CreateAgent(key, "prompt author probe", "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteAgent(a.Key) //nolint:errcheck

	author := func(stage string) string {
		t.Helper()
		by, err := d.CurrentPromptAuthor(a.ID)
		if err != nil {
			t.Fatalf("%s: %v", stage, err)
		}
		return by
	}

	if got := author("no version yet"); got != "" {
		t.Errorf("an agent with no prompt version reports author %q, want empty", got)
	}

	if err := d.SeedPromptIfEmpty(a.ID, "built-in body"); err != nil {
		t.Fatal(err)
	}
	if got := author("after seeding"); got != "system" {
		t.Errorf("a seeded prompt reports author %q, want \"system\"", got)
	}

	// The agent page saves through this path (server/server_mgmt.go).
	if _, err := d.SavePrompt(a.ID, "the operator's own wording", "edited", "ui"); err != nil {
		t.Fatal(err)
	}
	if got := author("after a UI edit"); got != "ui" {
		t.Errorf("a prompt saved from the agent page reports author %q, want \"ui\"", got)
	}
	if cur, err := d.CurrentPrompt(a.ID); err != nil || cur != "the operator's own wording" {
		t.Errorf("current prompt = %q, %v; want the edited body", cur, err)
	}

	// Restoring the default makes it a system version again, and the edited
	// version stays in history rather than being destroyed.
	if _, err := d.ResetPromptToDefault(a.ID, "built-in body v2"); err != nil {
		t.Fatal(err)
	}
	if got := author("after restoring the default"); got != "system" {
		t.Errorf("a restored default reports author %q, want \"system\"", got)
	}
	var kept int
	if err := d.QueryRow(`SELECT count(*) FROM agent_prompts WHERE agent_id=$1 AND template_text='the operator''s own wording'`, a.ID).Scan(&kept); err != nil {
		t.Fatal(err)
	}
	if kept != 1 {
		t.Errorf("the superseded user version is no longer in history (%d rows); SavePrompt must append, never replace", kept)
	}
}
