package agent

import (
	"context"
	"encoding/json"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/skill"
)

// Every skill the default placement binds must exist in the shipped skills
// directory under that name, or the binding silently shows nothing.
func TestSkillPlacementNamesExist(t *testing.T) {
	reg, err := skill.LoadDir("../skills")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, s := range reg.List() {
		got[s.Name] = true
	}
	for name := range db.BuiltinSkillVisibility() {
		if !got[name] {
			t.Errorf("placement names %q but no such skill loads", name)
		}
	}
}

// preloadSkills goes through the Skill tool and inlines the skill body; names
// the agent cannot see are skipped. Every name the host preloads must exist.
func TestPreloadSkills(t *testing.T) {
	reg, err := skill.LoadDir("../skills")
	if err != nil {
		t.Fatal(err)
	}
	tools := []actool.CoreTool{reg.Tool()}
	out := preloadSkills(context.Background(), tools, "testing-evidence-standards", "no-such-skill", "testing-evidence-standards")
	if strings.Count(out, "[Preloaded skill: testing-evidence-standards") != 1 || strings.Contains(out, "no-such-skill") || len(out) < 500 {
		t.Fatalf("unexpected preload output (%d bytes): %.300s", len(out), out)
	}
	names := append(append(append([]string{}, workerAlwaysSkills...), plannerFindingSkills...), coreBugClasses...)
	for _, k := range skillKeywords {
		names = append(names, k.skill)
	}
	for _, v := range chatAgentSkills {
		names = append(names, v...)
	}
	for _, n := range names {
		if _, ok := reg.Get(n); !ok {
			t.Errorf("host preloads %q but no such skill exists", n)
		}
	}
}

// A goal is not closed by evidence older than the goal or by a thin write-up;
// a finding always closes it.
func TestThinGoalProof(t *testing.T) {
	ts := &ToolSet{}
	goal := &db.Node{ID: 100, Kind: db.KindGoal}
	long := strings.Repeat("ran GET /x with param variants and compared responses; ", 8)
	mk := func(id int64, kind, summary string) *db.Node {
		b, _ := json.Marshal(map[string]any{"summary": summary})
		return &db.Node{ID: id, Kind: kind, Payload: b}
	}
	if ts.thinGoalProof(goal, mk(50, db.KindFact, long)) == "" {
		t.Error("a fact recorded before the goal must not close it")
	}
	if ts.thinGoalProof(goal, mk(150, db.KindFact, "nothing found")) == "" {
		t.Error("a thin fact must not close a goal")
	}
	if ts.thinGoalProof(goal, mk(150, db.KindFinding, "x")) != "" {
		t.Error("a finding must always close a goal")
	}
}
