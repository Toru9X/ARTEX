package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// generateFindingReport requeues the existing reporter workflow for a finding.
// This is intentionally separate from report_finding: a restart can leave a
// finding persisted while the one-shot trigger conversation is gone.
func (s *Server) generateFindingReport(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "bad finding id")
		return
	}
	f, err := s.m.pg.GetFinding(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if f == nil {
		writeErr(w, http.StatusNotFound, "finding not found")
		return
	}
	if f.NodeID == nil || *f.NodeID <= 0 {
		writeErr(w, http.StatusConflict, "this finding has no exploration node, so reproduction steps cannot be generated")
		return
	}
	reporter, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if reporter == nil || !reporter.Enabled {
		writeErr(w, http.StatusConflict, "the report agent is disabled; enable reporter under Agents")
		return
	}
	if s.resolveChatAgent(&db.Conversation{AgentKey: reporter.Key}) == nil {
		writeErr(w, http.StatusServiceUnavailable, s.chatUnavailableReason())
		return
	}
	if s.ctx.Err() != nil {
		writeErr(w, http.StatusServiceUnavailable, "the service is shutting down")
		return
	}

	var taskID int64
	var taskDesc, taskGoal string
	if f.TaskID != nil {
		taskID = *f.TaskID
		if task := s.m.ResolveTask(strconv.FormatInt(taskID, 10)); task != nil {
			taskDesc, taskGoal = task.Description, task.Goal
		}
	}
	message := manualFindingReportMessage(f, taskID)
	conversation, err := s.m.pg.CreateConversation("reporter", fmt.Sprintf("vulnerability report · finding#%d", f.ID), nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create the report conversation: "+err.Error())
		return
	}
	if err := s.m.pg.SetFindingReportConversationID(f.ID, conversation.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not link the report conversation: "+err.Error())
		return
	}
	s.StartTriggeredRunWithConversation(
		"reporter",
		fmt.Sprintf("manually generated steps and report · finding#%d", f.ID),
		message,
		taskID,
		false,
		taskDesc,
		taskGoal, conversation.ID,
	)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"queued":          true,
		"agent_key":       "reporter",
		"finding_id":      f.ID,
		"finding_node_id": *f.NodeID,
		"conversation_id": conversation.ID,
	})
}

func manualFindingReportMessage(f *db.DBFinding, taskID int64) string {
	var b strings.Builder
	b.WriteString("[Manual regeneration of steps and report] This finding is already registered. Write its structured reproduction steps and a full detailed report; do not create a new finding record, and do not change or delete the original evidence.\n")
	fmt.Fprintf(&b, "standalone finding record id (finding_id)=%d; exploration node id (finding_node_id)=%d.\n", f.ID, *f.NodeID)
	if taskID > 0 {
		fmt.Fprintf(&b, "source task id=%d.\n", taskID)
	}
	b.WriteString("Read the current evidence list and version from get_finding_traffic(finding_id) first, then the node detail and the task execution records. Use only requests, responses and execution evidence that were actually saved; never invent a step or a packet.\n")
	b.WriteString("The report must contain Overview, Impact, Affected scope, Reproduction steps, Root-cause analysis and Remediation, with the reproduction written out as Step 1, Step 2 and so on. Packets may only quote traffic actually bound to this finding.\n")
	b.WriteString("Finish with update_finding_report: pass the exploration node id as finding_id and the evidence version you just read as evidence_version; save the report body as Markdown.")
	return b.String()
}
