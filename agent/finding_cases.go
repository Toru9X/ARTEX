package agent

import (
	"context"
	actool "github.com/Autumn-27/norma/tool"
)

type findingReviewKey struct{}

// Historical consolidation has a narrower capability set than new reporting.
func WithFindingCaseReview(ctx context.Context) context.Context {
	return context.WithValue(ctx, findingReviewKey{}, true)
}
func isFindingCaseReview(ctx context.Context) bool {
	v, _ := ctx.Value(findingReviewKey{}).(bool)
	return v
}

func historicalFindingCaseTools(tools []actool.CoreTool) []actool.CoreTool {
	allowed := map[string]bool{}
	for _, name := range []string{"search_finding_duplicates", "get_finding_record", "merge_finding_records", "suggest_finding_merge", "get_finding_case", "update_finding_case_report", "complete_finding_case_review", "get_finding_traffic", "traffic_search", "traffic_get", "traffic_blob", "get_task_node_detail", "list_task_findings", "get_task_graph", "list_task_worker_traces", "get_task_worker_trace", "Read"} {
		allowed[name] = true
	}
	out := make([]actool.CoreTool, 0, len(tools))
	for _, tool := range tools {
		if allowed[tool.Name()] {
			out = append(out, tool)
		}
	}
	return out
}

// This guidance is appended to the runtime prompt, including editable old prompts.
// Never reintroduce unbound tools or recreate a deleted Reporter.
func findingCaseWorkflow(key string, tools []actool.CoreTool) ([]actool.CoreTool, string) {
	if key != "reporter" {
		return tools, ""
	}
	has := map[string]bool{}
	for _, t := range tools {
		has[t.Name()] = true
	}
	if !has["search_finding_duplicates"] || !has["merge_finding_records"] || !has["get_finding_case"] || !has["update_finding_case_report"] {
		return tools, ""
	}
	return tools, `

[Consolidating repeated reports of one defect] Keep this run's own report; never overwrite another finding's original report. This extends the older guidance that stopped once a report was written: save this report first, then call search_finding_duplicates(finding_id=<standalone record id>) and page through the candidate summaries from the same task (ordered by score; strong = same vulnerability class with overlapping assets, check these first; weak = lacking either the same class or the asset overlap, so read hit_reasons and treat it as a hint only), and call get_finding_record where you need the evidence. A similar class, title, token, or login entry point, or the same severity, is never on its own a reason to merge; check the target, the endpoint, the parameters, the permission boundary, the root cause and the verification evidence. You may only consolidate within one task, and you must respect human vetoes and finding_case_blocks.
[Decision rules] Where the evidence shows the endpoint or route, the handler or backend component, the affected parameter, or the missing check belongs to a different code path, you may call it independent; say what the evidence for each was. The same or a different path, endpoint, login entry point, token, title or vulnerability class never by itself proves a shared or a distinct root cause. Call merge_finding_records(task_id,finding_ids,title,reason) only when the root cause is clearly the same. Call suggest_finding_merge only when there is a concrete commonality (both records point, with evidence, at the same endpoint, parameter, component or missing check) but the evidence that would confirm one root cause is missing; submit one group covering 2..20 records of the same task, not a series of pairs. A shared class or asset with no concrete commonality is not a suggestion; with no concrete commonality, stay independent rather than suggesting out of uncertainty. Never re-report, delete a record, or re-probe the target. A human-selected consolidation may judge only the selected records and may not pull in unselected ones (existing case members may still be read as context).
Once a merge succeeds, or a case_id already exists, call get_finding_case for the actual version, page through all members, and read the original reports, PoCs and saved traffic with get_finding_record and get_finding_traffic as needed. A merge is not blocked by the unified report: when the root cause is clear, merge, then make a real effort to save the unified report with update_finding_case_report; if you cannot finish it this run, the case shows "unified report pending" for a later reporter run or a human to complete. A unified report must still carry non-empty overview, impact, preconditions, reproduction, evidence, PoC, root-cause analysis and remediation sections, never a truncated half; the rating and severity_reason must rest on verified impact, not on simply taking the highest member severity. Give the preconditions, the full execution order, how inputs and outputs connect, and a runnable end-to-end script and commands in one place rather than scattering necessary steps across the original reports; state missing preconditions and unverified steps honestly. On a version conflict, re-read the material and regenerate — never just retry with a new version. Every member keeps its own report, rating and evidence. When a tool is switched off, do not work around the configuration.`
}

const historicalFindingReviewGuidance = `

[Historical consolidation mode; this takes precedence over the older report-writing and automatic traffic-binding guidance] This run only consolidates reports that already exist. Even where an original report is empty or pending, record that it is missing and never call update_finding_report, report_finding or bind_finding_traffic, never change an original title, rating, status, evidence or report, and never run Bash, write files or re-probe the target.
Read each selected record with get_finding_record first and reuse any existing original report as material rather than writing it again. Look for one and the same actual defect, within the selected scope only, reading existing evidence as needed. Where structured evidence shows a different endpoint or route, handler or backend component, parameter or missing check — that is, a different code path — you may call it independent; a similar class, asset, title, token or login entry point is not enough. Save a suspected group of 2..20 records only when a concrete commonality is clear and the decisive root-cause evidence is missing; with no concrete commonality, stay independent. Historical consolidation may act only on the selected scope and must honour the same-task limit and human vetoes.
Historical mode forbids update_finding_report, report_finding and bind_finding_traffic, changing an original title, rating, status, evidence or report, and running Bash, writing files or re-probing the target. For a case that exists or that you create, read every member and make a real effort to write a complete, current unified report with update_finding_case_report; a merge is never blocked by a missing report, and while it is unwritten the case shows "unified report pending" for a later run or a human to complete. The unified report is separate material and never overwrites an original. You must finish by calling complete_finding_case_review with a verdict (independent/merged/suggested), a reason and root_cause_evidence for every selected finding_id, plus a summary. The root-cause evidence should name the specific check that is the same or different and where that evidence came from; a suggestion should say what evidence is still needed. Only once the server accepts the submission may you declare the review done. A human-driven consolidation may judge only the selected scope and may not pull in unselected records. Where a tool is unavailable or the submission is rejected, say so rather than claiming success in prose.`
