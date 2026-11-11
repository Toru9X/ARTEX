package agent

import (
	"context"
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
	for _, v := range chatAgentSkills {
		names = append(names, v...)
	}
	for _, n := range names {
		if _, ok := reg.Get(n); !ok {
			t.Errorf("host preloads %q but no such skill exists", n)
		}
	}
}
