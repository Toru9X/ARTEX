package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestNormalizeRemark(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"trims surrounding whitespace", "  note  ", "note", false},
		{"empty clears the note", "   ", "", false},
		{"keeps inner newlines", "line one\nline two", "line one\nline two", false},
		{"at the limit", strings.Repeat("a", db.MaxTaskRemarkRunes), strings.Repeat("a", db.MaxTaskRemarkRunes), false},
		{"over the limit", strings.Repeat("a", db.MaxTaskRemarkRunes+1), "", true},
		// Counted in runes, not bytes: this is 3x the byte limit but well under
		// the rune limit, and must be accepted.
		{"multi-byte runes count as one", strings.Repeat("ü", db.MaxTaskRemarkRunes), strings.Repeat("ü", db.MaxTaskRemarkRunes), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeRemark(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("normalizeRemark() = %q, want %q", got, tc.want)
			}
		})
	}
}

// A remark survives the whole path: PATCH -> tasks row -> live handle -> DTO.
// It must also be independently patchable: sending only a remark must not
// clear the name, and sending only a name must not clear the remark.
func TestTaskRemarkRoundTripAndIndependence(t *testing.T) {
	m := proxyTestManager(t)
	task, err := m.CreateTask("remark task", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()

	patch := func(body string) TaskDTO {
		t.Helper()
		updated, err := m.UpdateTaskMetadata(task.ID, decodeTaskPatch(t, body))
		if err != nil {
			t.Fatal(err)
		}
		if updated == nil {
			t.Fatal("task not found")
		}
		return taskDTO(updated, updated.Status)
	}

	if got := patch(`{"name":"named"}`).Name; got != "named" {
		t.Fatalf("name = %q", got)
	}
	dto := patch(`{"remark":"  scope: only /api/*  "}`)
	if dto.Remark != "scope: only /api/*" {
		t.Fatalf("remark = %q, want the trimmed note", dto.Remark)
	}
	if dto.Name != "named" {
		t.Fatalf("a remark-only patch cleared the name: %q", dto.Name)
	}
	dto = patch(`{"name":"renamed"}`)
	if dto.Remark != "scope: only /api/*" {
		t.Fatalf("a name-only patch cleared the remark: %q", dto.Remark)
	}

	// Reload from PostgreSQL: the note must be persisted, not just in memory.
	stored, err := m.pg.GetTask(mustTaskID(t, task.ID))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Remark != "scope: only /api/*" {
		t.Fatalf("stored remark = %q", stored.Remark)
	}

	if got := patch(`{"remark":""}`).Remark; got != "" {
		t.Fatalf("an empty remark must clear the note, got %q", got)
	}
}

// decodeTaskPatch mirrors what the HTTP handler builds, so the test exercises
// the same optional-field semantics without spinning a full Server.
func decodeTaskPatch(t *testing.T, body string) db.TaskPatch {
	t.Helper()
	var req struct {
		Name   *string `json:"name"`
		Remark *string `json:"remark"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	if req.Remark != nil {
		normalized, err := normalizeRemark(*req.Remark)
		if err != nil {
			t.Fatal(err)
		}
		req.Remark = &normalized
	}
	return db.TaskPatch{Name: req.Name, Remark: req.Remark}
}

// The handler must reject an over-long remark rather than truncate it.
func TestUpdateTaskMetadataRejectsOverlongRemark(t *testing.T) {
	m := proxyTestManager(t)
	task, err := m.CreateTask("remark limit", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()

	s := &Server{m: m}
	body, _ := json.Marshal(map[string]string{"remark": strings.Repeat("x", db.MaxTaskRemarkRunes+1)})
	r := httptest.NewRequest("PATCH", "/api/tasks/"+task.ID, strings.NewReader(string(body)))
	r.SetPathValue("id", task.ID)
	w := httptest.NewRecorder()
	s.updateTaskMetadata(w, r)
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400; body = %s", w.Code, w.Body)
	}

	stored, err := m.pg.GetTask(mustTaskID(t, task.ID))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Remark != "" {
		t.Fatalf("a rejected remark was still written: %q", stored.Remark)
	}
}
