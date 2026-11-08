package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/intercept"
)

func TestFindingCaseReviewTaskMessagePolicy(t *testing.T) {
	message := fmt.Sprintf(findingCaseReviewTaskMessage, `[101,102,103]`)
	for _, want := range []string{
		"finding_ids=[101,102,103]",
		"the root cause is clearly the same, merge directly",
		"the same endpoint, handler or backend component, parameter or missing check",
		"the decisive evidence for one root cause is missing",
		"one group covering 2..20 suspected members of the same task",
		"not a series of pairs",
		"A shared class or asset alone is not enough to suggest",
		"with no concrete commonality stay independent",
		"different code paths you may answer independent",
		"make a real effort to update the unified report",
		"never blocks complete_finding_case_review",
		"merge unselected records",
		"probe the target",
		"honour human vetoes",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("task message missing policy: %s", want)
		}
	}
	if strings.Contains(message, "suggesting out of uncertainty is fine") {
		t.Fatal("task message suggests solely because of uncertainty")
	}
	schema, err := json.Marshal((&Server{}).toolCompleteFindingCaseReview().InputSchema())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(schema), "with no concrete commonality, answer independent") || strings.Contains(string(schema), "if unsure, state the missing evidence and the saved suggestion") {
		t.Fatal("completion schema must not require suggestions solely because of uncertainty")
	}
}

const completeFindingReviewReport = `# One missing object-permission check
## Overview
The same object permission check is missing.
## Impact
Reading another account's orders was verified.
## Preconditions
An existing low-privilege session and an order id.
## Reproduction
Compare your own order, then request another account's order; the response proves the same check is missing.
## Evidence
The saved responses and command output from the original reports; nothing was re-probed.
## PoC
The full commands live in the original evidence; this test uses isolated material.
## Root-cause analysis
The order handler never checks the order owner.
## Remediation
Check the requester against the order owner in one place and add a regression test for object permissions.
`

func TestUnifiedFindingReportRejectsIncompleteAndTruncated(t *testing.T) {
	if err := validateUnifiedFindingReport(completeFindingReviewReport); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{strings.Split(completeFindingReviewReport, "## Root-cause analysis")[0], completeFindingReviewReport + "\n```bash\nunclosed", strings.Replace(completeFindingReviewReport, "Check the requester against the order owner in one place and add a regression test for object permissions.", "", 1)} {
		if err := validateUnifiedFindingReport(s); err == nil {
			t.Fatal("incomplete report accepted")
		}
	}
	// Section labels appearing inside a script are not real report sections.
	if err := validateUnifiedFindingReport("## Overview\ntext\n```bash\n" + completeFindingReviewReport + "\n```"); err == nil {
		t.Fatal("script comments counted as sections")
	}
}

func TestFindingCaseReviewCompletionRequiresReadsNotFreshReport(t *testing.T) {
	s, task, ids := testCaseServer(t)
	runs, err := s.m.pg.CreateFindingCaseReviews(t.Context(), map[int64][]int64{task: ids})
	if err != nil {
		t.Fatal(err)
	}
	conv := runs[0].ConversationID
	defer s.m.pg.Exec(`DELETE FROM conversations WHERE id=$1`, conv)
	if _, err := s.m.pg.Exec(`UPDATE finding_case_review_runs SET state='running' WHERE conversation_id=$1`, conv); err != nil {
		t.Fatal(err)
	}
	ctx := intercept.WithConvID(context.Background(), conv)
	a := findingReviewConclusion{Summary: "judged on the concrete object-permission evidence"}
	for _, id := range ids {
		a.Decisions = append(a.Decisions, findingReviewDecision{FindingID: id, Verdict: "merged", Reason: "the same handler", RootCauseEvidence: "each record's baseline/proof points at the same missing object-owner check"})
	}
	if err := s.saveFindingReviewConclusion(ctx, conv, a); err == nil {
		t.Fatal("unread findings accepted")
	}
	for _, id := range ids {
		if _, err := s.performFindingCaseTool(ctx, "get_finding_record", findingCaseRequest{FindingID: json.RawMessage(fmt.Sprint(id))}); err != nil {
			t.Fatal(err)
		}
	}
	cid, err := s.m.pg.MergeFindingCase(ctx, task, ids, "orders", "same concrete check", "reporter")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.saveFindingReviewConclusion(ctx, conv, a); err != nil {
		t.Fatal(err)
	}
	if err := s.validateFindingReviewCompletion(conv); err != nil {
		t.Fatal(err)
	}
	if err := s.checkCaseReviewScope(ctx, "update_finding_case_report", findingCaseRequest{CaseID: json.RawMessage(fmt.Sprint(cid))}); err == nil {
		t.Fatal("sealed review can still mutate")
	}
	if _, err := s.m.pg.Exec(`UPDATE findings SET evidence='new proof' WHERE id=$1`, ids[0]); err != nil {
		t.Fatal(err)
	}
	if err := s.validateFindingReviewCompletion(conv); err != nil {
		t.Fatalf("stale unified report should not block merged conclusion: %v", err)
	}
}

func TestFindingCaseReviewProtectsOriginalToolWrites(t *testing.T) {
	s, f, _ := trafficEvidenceServer(t)
	original, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := s.m.pg.CreateFindingCaseReviews(t.Context(), map[int64][]int64{*original.TaskID: {original.ID}})
	if err != nil {
		t.Fatal(err)
	}
	conv := runs[0].ConversationID
	defer s.m.pg.Exec(`DELETE FROM conversations WHERE id=$1`, conv)
	ctx := intercept.WithConvID(context.Background(), conv)
	workflowCall(t, ctx, s.toolUpdateFindingReport(), map[string]any{"finding_id": f.NodeID, "report": "OVERWRITE", "evidence_version": original.EvidenceVersion}, true)
	if err := s.agentFindingTrafficAccess(ctx, f.FindingID, true); err == nil {
		t.Fatal("historical review can change evidence")
	}
	after, _ := s.m.pg.GetFinding(original.ID)
	if after.Report != original.Report || after.EvidenceVersion != original.EvidenceVersion || after.Status != original.Status || after.Severity != original.Severity {
		t.Fatal("original changed")
	}
	// Normal reporting is still able to write its own standalone report.
	workflowCall(t, context.Background(), s.toolUpdateFindingReport(), map[string]any{"finding_id": f.NodeID, "report": "normal report", "evidence_version": original.EvidenceVersion}, false)
}

func TestFindingCaseReviewSuggestionNeedsSavedSuggestion(t *testing.T) {
	s, task, ids := testCaseServer(t)
	runs, err := s.m.pg.CreateFindingCaseReviews(t.Context(), map[int64][]int64{task: ids[:2]})
	if err != nil {
		t.Fatal(err)
	}
	conv := runs[0].ConversationID
	defer s.m.pg.Exec(`DELETE FROM conversations WHERE id=$1`, conv)
	s.m.pg.Exec(`UPDATE finding_case_review_runs SET state='running' WHERE conversation_id=$1`, conv)
	ctx := intercept.WithConvID(context.Background(), conv)
	a := findingReviewConclusion{Summary: "a human needs to confirm the shared component"}
	for _, id := range ids[:2] {
		s.performFindingCaseTool(ctx, "get_finding_record", findingCaseRequest{FindingID: json.RawMessage(fmt.Sprint(id))})
		a.Decisions = append(a.Decisions, findingReviewDecision{FindingID: id, Verdict: "suggested", Reason: "the same boundary, root cause unconfirmed", RootCauseEvidence: "the original reports point at the object-permission boundary but the shared-component evidence is missing"})
	}
	if err := s.saveFindingReviewConclusion(ctx, conv, a); err == nil {
		t.Fatal("unpersisted suggestion accepted")
	}
	if _, err := s.m.pg.SuggestFindingCase(ctx, task, []int64{ids[0], ids[1]}, "orders", "common component unknown"); err != nil {
		t.Fatal(err)
	}
	if err := s.saveFindingReviewConclusion(ctx, conv, a); err != nil {
		t.Fatal(err)
	}
}

func TestFindingCaseReviewCandidatesStayWithinSelection(t *testing.T) {
	s, task, ids := testCaseServer(t)
	runs, err := s.m.pg.CreateFindingCaseReviews(t.Context(), map[int64][]int64{task: ids[:2]})
	if err != nil {
		t.Fatal(err)
	}
	conv := runs[0].ConversationID
	defer s.m.pg.Exec(`DELETE FROM conversations WHERE id=$1`, conv)
	ctx := intercept.WithConvID(context.Background(), conv)
	a := findingCaseRequest{FindingID: json.RawMessage(fmt.Sprint(ids[0]))}
	v, err := s.performFindingCaseTool(ctx, "search_finding_duplicates", a)
	if err != nil {
		t.Fatal(err)
	}
	if v.(map[string]any)["total"].(int) != 1 {
		t.Fatal("unselected candidates leaked", v)
	}
	v, err = s.performFindingCaseTool(context.Background(), "search_finding_duplicates", a)
	if err != nil || v.(map[string]any)["total"].(int) != 2 {
		t.Fatal("normal candidate search changed", v, err)
	}
}
