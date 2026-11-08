package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// Missing host/setting means off. Rechecked on every write for running sessions.
var IntelligenceEnabled func() bool
var IntelligenceRecord func(context.Context, int64, int64, string, db.IntelligenceInput) (int64, error)
var CredentialRecorded func()

func intelligenceEnabled() bool { return IntelligenceEnabled != nil && IntelligenceEnabled() }
func intelligenceSchema() map[string]any {
	return obj(map[string]any{
		"kind":       map[string]any{"type": "string", "enum": []string{"credential", "lead", "sensitive_data"}},
		"title":      str("A short title. It must not contain a password, token or any secret verbatim"),
		"content":    str("What was actually obtained. For a credential, store account/password/token as a JSON string; for sensitive data, only a few samples, the count and the file location — never paste a whole dataset"),
		"evidence":   str("The real source: the command, request, response or file location plus the key observation. Do not invent one"),
		"confidence": map[string]any{"type": "string", "enum": []string{"observed", "inferred"}},
		"status":     str("credential: unverified/verified/invalid; lead: pending/in_progress/dismissed/converted; sensitive_data: suspected/confirmed/dismissed. Omitted defaults conservatively, and verified requires real evidence that authentication succeeded"),
		"asset_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}},
	}, "kind", "title", "content", "evidence", "confidence")
}
func (t *ToolSet) saveIntelligence(ctx context.Context, nodeID int64, in db.IntelligenceInput) (int64, error) {
	if !intelligenceEnabled() || IntelligenceRecord == nil {
		return 0, fmt.Errorf("automatic task-intelligence recording is disabled")
	}
	taskID := t.taskID
	if taskID <= 0 {
		taskID = RunInfoFrom(ctx).TaskID
	}
	if taskID <= 0 {
		return 0, fmt.Errorf("task intelligence requires the current task context")
	}
	if nodeID <= 0 {
		nodeID = t.ownerNode
	}
	if nodeID <= 0 {
		nodeID = RunInfoFrom(ctx).IntentID
	}
	id, err := IntelligenceRecord(ctx, taskID, nodeID, t.worker, in)
	if err == nil {
		t.writes.Intelligence++
	}
	return id, err
}
func (t *ToolSet) recordIntelligence() actool.CoreTool {
	return writeTool("record_intelligence", "Record a credential, a lead worth following up, or sensitive data actually obtained in this task. The task and the executing worker are bound by the system. Finding a credential is not the same as verifying it. Repeated records are de-duplicated. insert_assets.auth already registers credentials, so do not call this again for those.", intelligenceSchema(), func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		var in db.IntelligenceInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return actool.Errorf("invalid intelligence arguments"), nil
		}
		id, err := t.saveIntelligence(ctx, 0, in)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		return actool.Text(fmt.Sprintf("intelligence recorded: %d", id)), nil
	})
}
func intelligenceWorkflow(ctx context.Context, tools []actool.CoreTool) ([]actool.CoreTool, string) {
	enabled := intelligenceEnabled() && RunInfoFrom(ctx).TaskID > 0
	out := make([]actool.CoreTool, 0, len(tools))
	hasRecord := false
	hasFact := false
	for _, tool := range tools {
		if tool.Name() == "record_intelligence" {
			if !enabled {
				continue
			}
			hasRecord = true
		}
		if tool.Name() == "record_fact" {
			raw, _ := json.Marshal(tool.InputSchema())
			var schema map[string]any
			if json.Unmarshal(raw, &schema) == nil {
				props, _ := schema["properties"].(map[string]any)
				if props != nil {
					delete(props, "intelligence")
					if enabled {
						props["intelligence"] = map[string]any{"type": "array", "maxItems": 20, "description": "Write intelligence back together with the fact; the fields match record_intelligence, so that tool need not be called separately", "items": intelligenceSchema()}
						hasFact = true
					}
				}
				tool = DecorateTool(tool, tool.Description(), schema)
			}
		}
		out = append(out, tool)
	}
	guide := ""
	if enabled && (hasRecord || hasFact) {
		guide = "\n\n**Task-intelligence recording is on**: when you obtain a credential, a lead worth following up, or real sensitive data, write it back in structured form immediately " +
			"rather than waiting to be asked, and check for anything missed before you finish. " +
			"record_fact can carry an intelligence array alongside the fact (both a single fact and each " +
			"element of a batch); use record_intelligence on its own where it is available. " +
			"insert_assets.auth is registered by the backend already, so do not duplicate it. " +
			"Record only new, valuable information - ordinary fingerprints and port states remain plain facts. " +
			"The title must never contain a secret verbatim; the body carries the actual content and its source. " +
			"A credential is unverified by default and may be marked verified only on real successful " +
			"authentication; anything deduced must be inferred. For sensitive data, record the type, the count, " +
			"a few samples and the file location - never paste a whole dataset."
	}
	return out, guide
}
