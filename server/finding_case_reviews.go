package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/intercept"
	actool "github.com/Autumn-27/norma/tool"
)

type findingReviewDecision struct {
	FindingID         int64  `json:"finding_id"`
	Verdict           string `json:"verdict"`
	Reason            string `json:"reason"`
	RootCauseEvidence string `json:"root_cause_evidence"`
}
type findingReviewConclusion struct {
	Summary   string                  `json:"summary"`
	Decisions []findingReviewDecision `json:"decisions"`
}

func (s *Server) isHistoricalFindingReview(conv int64) (bool, error) {
	var exists bool
	err := s.m.pg.QueryRow(`SELECT EXISTS(SELECT 1 FROM finding_case_review_runs WHERE conversation_id=$1)`, conv).Scan(&exists)
	return exists, err
}

func (s *Server) toolCompleteFindingCaseReview() actool.CoreTool {
	decision := objSchema(map[string]any{
		"finding_id":          idParam("the selected standalone finding record id"),
		"verdict":             map[string]any{"type": "string", "enum": []string{"independent", "merged", "suggested"}},
		"reason":              strParam("the reason, citing the evidenced commonality or the differing code path; a shared class, title or asset is not enough to prove one root cause"),
		"root_cause_evidence": strParam("the specific material in the original reports or evidence that supports one root cause or distinct ones; for suggested, name the concrete commonality, the missing decisive evidence and the saved group; with no concrete commonality, answer independent")}, "finding_id", "verdict", "reason", "root_cause_evidence")
	return wrTool("complete_finding_case_review", "Before a historical consolidation ends, submit the root-cause verdict for every selected record and have it accepted: you must have read all of them, a suggested verdict needs a saved pending group, and a merged verdict only needs the record to be in an active case (the unified report may follow later). A rejected submission is not a completed review.", objSchema(map[string]any{"summary": strParam("a summary of the consolidation"), "decisions": map[string]any{"type": "array", "items": decision}}, "summary", "decisions"), func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		var a findingReviewConclusion
		if err := json.Unmarshal(raw, &a); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		conv := intercept.ConvIDFromContext(ctx)
		if err := s.saveFindingReviewConclusion(ctx, conv, a); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		return actool.Text("the consolidation was accepted; the original records and reports are untouched and every verdict was saved."), nil
	})
}

func (s *Server) saveFindingReviewConclusion(ctx context.Context, conv int64, a findingReviewConclusion) error {
	if conv <= 0 {
		return errors.New("only usable inside a historical consolidation session")
	}
	return s.m.pg.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		var idsRaw, readsRaw json.RawMessage
		var state string
		if err := tx.QueryRow(`SELECT finding_ids,reviewed_ids,state FROM finding_case_review_runs WHERE conversation_id=$1 FOR UPDATE`, conv).Scan(&idsRaw, &readsRaw, &state); err != nil {
			return err
		}
		if state != "running" {
			return errors.New("the consolidation session is not running, so nothing can be submitted")
		}
		var ids, reads []int64
		if err := json.Unmarshal(idsRaw, &ids); err != nil {
			return err
		}
		if err := json.Unmarshal(readsRaw, &reads); err != nil {
			return err
		}
		read := map[int64]bool{}
		for _, id := range reads {
			read[id] = true
		}
		decisions := map[int64]findingReviewDecision{}
		for _, d := range a.Decisions {
			if _, ok := decisions[d.FindingID]; ok {
				return errors.New("duplicate verdict id")
			}
			decisions[d.FindingID] = d
		}
		if strings.TrimSpace(a.Summary) == "" || len(ids) != len(decisions) {
			return errors.New("a summary and one verdict per selected record are required")
		}
		for _, id := range ids {
			d, ok := decisions[id]
			if !ok || !read[id] {
				return fmt.Errorf("read and judge selected record #%d with get_finding_record first", id)
			}
			if strings.TrimSpace(d.Reason) == "" || strings.TrimSpace(d.RootCauseEvidence) == "" {
				return fmt.Errorf("record #%d has no reason or root-cause evidence", id)
			}
			var cid sql.NullInt64
			if err := tx.QueryRow(`SELECT m.case_id FROM findings f LEFT JOIN finding_case_members m ON m.finding_id=f.id WHERE f.id=$1`, id).Scan(&cid); err != nil {
				return err
			}
			switch d.Verdict {
			case "merged":
				if !cid.Valid {
					return fmt.Errorf("record #%d has not been merged", id)
				}
			case "suggested":
				var pending bool
				if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM finding_case_suggestions s
                    JOIN finding_case_suggestion_members sm ON sm.suggestion_id=s.id
                    WHERE s.state='pending' AND sm.finding_id=$1)`, id).Scan(&pending); err != nil {
					return err
				}
				if !pending {
					return fmt.Errorf("record #%d needs a saved pending suggestion first", id)
				}
			case "independent":
				if cid.Valid {
					return fmt.Errorf("record #%d is already in a case and cannot be called independent", id)
				}
			default:
				return errors.New("invalid verdict")
			}
			if cid.Valid {
				var active bool
				if err := tx.QueryRow(`SELECT active FROM finding_cases WHERE id=$1 FOR SHARE`, cid.Int64).Scan(&active); err != nil {
					return err
				}
				if !active {
					return fmt.Errorf("case #%d is closed", cid.Int64)
				}
			}
		}
		raw, err := json.Marshal(a)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`UPDATE finding_case_review_runs SET conclusion=$2 WHERE conversation_id=$1`, conv, string(raw))
		return err
	})
}

func (s *Server) validateFindingReviewCompletion(conv int64) error {
	var raw json.RawMessage
	if err := s.m.pg.QueryRow(`SELECT conclusion FROM finding_case_review_runs WHERE conversation_id=$1`, conv).Scan(&raw); err != nil {
		return err
	}
	var a findingReviewConclusion
	if err := json.Unmarshal(raw, &a); err != nil {
		return err
	}
	if len(a.Decisions) == 0 {
		return errors.New("the consolidation was not accepted: complete_finding_case_review never submitted a per-record verdict; see the execution log")
	}
	// Recheck after the last model turn; concurrent evidence changes invalidate completion.
	return s.saveFindingReviewConclusion(context.Background(), conv, a)
}

// Require substantive sections and balanced fenced blocks. This validates report
// completeness, not the truth of a model's root-cause claim or a live exploit.
func validateUnifiedFindingReport(report string) error {
	aliases := [][]string{{"overview", "summary"}, {"impact"}, {"prerequisite", "precondition"}, {"reproduction", "reproduce", "steps to reproduce"}, {"evidence"}, {"poc", "proof of concept", "exploit script"}, {"root cause", "root-cause", "rootcause"}, {"remediation", "recommendation", "fix"}}
	names := []string{"overview", "impact", "preconditions", "reproduction", "evidence", "PoC", "root-cause analysis", "remediation"}
	found := make([]bool, len(aliases))
	current := -1
	hasContent := false
	fence := ""
	finish := func() {
		if current >= 0 && hasContent {
			found[current] = true
		}
	}
	for _, line := range strings.Split(report, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") {
			marker := t[:3]
			if fence == "" {
				fence = marker
			} else if fence == marker {
				fence = ""
			}
			continue
		}
		if fence != "" {
			if t != "" {
				hasContent = true
			}
			continue
		}
		if strings.HasPrefix(t, "#") {
			heading := strings.TrimLeft(t, "#")
			if len(heading) == len(t) || !strings.HasPrefix(heading, " ") {
				continue
			}
			// Subheadings belong to the current section unless they start another required section.
			next := -1
			lower := strings.ToLower(heading)
			for i, words := range aliases {
				for _, word := range words {
					if strings.Contains(lower, word) {
						next = i
						break
					}
				}
				if next >= 0 {
					break
				}
			}
			if next >= 0 {
				finish()
				current = next
				hasContent = false
			}
			continue
		}
		if t != "" && t != "---" && t != "***" && t != ">" {
			hasContent = true
		}
	}
	finish()
	if fence != "" {
		return errors.New("the unified report has an unclosed code block and looks truncated; complete it before saving")
	}
	missing := []string{}
	for i, ok := range found {
		if !ok {
			missing = append(missing, names[i])
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("the unified report is missing non-empty sections: %s; complete it before saving", strings.Join(missing, ", "))
	}
	return nil
}

func (s *Server) historicalFindingReviewSelection(ctx context.Context) ([]int64, error) {
	conv := intercept.ConvIDFromContext(ctx)
	if conv == 0 {
		return nil, nil
	}
	var raw json.RawMessage
	err := s.m.pg.QueryRow(`SELECT finding_ids FROM finding_case_review_runs WHERE conversation_id=$1`, conv).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ids := []int64{}
	err = json.Unmarshal(raw, &ids)
	return ids, err
}
