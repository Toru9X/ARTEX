package agent

import (
	"context"
	"encoding/json"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// Run data showed no agent ever invoked a skill on its own, so the skills that
// matter for a run are loaded by the host at the moment they apply instead of
// being left to the model: the intent's skills when a worker starts, the
// evidence standard for every worker, chain reasoning when a finding wakes the
// planner. Loading goes through the agent's own Skill tool, so the skill's MCPs
// are unlocked and the usage ledger records it, exactly as a model call would.
// The bodies go into the system prompt, which compaction never drops.

// maxPreloadedSkillBytes caps one preloaded skill body.
// ponytail: hard cap, a long skill is cut; per-section loading if that bites.
const maxPreloadedSkillBytes = 24 << 10

// preloadSkills invokes each named skill through the run's Skill tool and
// returns a system-prompt block with their instructions. Names the agent cannot
// see are skipped; "" when nothing loaded.
func preloadSkills(ctx context.Context, tools []actool.CoreTool, names ...string) string {
	var skillTool actool.CoreTool
	for _, t := range tools {
		if t.Name() == "Skill" {
			skillTool = t
			break
		}
	}
	if skillTool == nil {
		return ""
	}
	var b strings.Builder
	seen := map[string]bool{}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		in, _ := json.Marshal(map[string]string{"name": n})
		res, err := skillTool.Call(ctx, in, nil)
		if err != nil || res.IsError {
			continue // not visible to this agent
		}
		var body strings.Builder
		for _, m := range res.Extra {
			for _, c := range m.Content {
				body.WriteString(c.Text)
			}
		}
		text := body.String()
		if len(text) > maxPreloadedSkillBytes {
			text = text[:maxPreloadedSkillBytes] + "\n[... skill truncated; the full file is in its base directory]"
		}
		b.WriteString("\n\n[Preloaded skill: " + n + " (already loaded for you — follow it; do not call Skill for it again)]\n")
		b.WriteString(text)
		for _, c := range res.Content { // MCP tools this skill unlocked, if any
			if strings.Contains(c.Text, "deferred") {
				b.WriteString("\n" + c.Text)
			}
		}
	}
	return b.String()
}

// workerAlwaysSkills are loaded into every worker run: the bar a result must
// clear before it is a finding.
var workerAlwaysSkills = []string{"testing-evidence-standards"}

// chatAgentSkills are loaded into every run of these chat-driven agents: the
// retester re-judges a finding, the reporter writes it up, the solo pentest
// agent does both. Technique skills stay on demand through the Skill tool.
var chatAgentSkills = map[string][]string{
	"retester": {"testing-evidence-standards", "retraction-discipline"},
	"reporter": {"testing-evidence-standards", "triage-severity", "client-report-writing"},
	"pentest":  {"testing-evidence-standards"},
}

// plannerFindingSkills are loaded into a planning round woken by a new finding,
// when the next question is whether it chains into something bigger.
var plannerFindingSkills = []string{"chains-meta"}
