package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

// maxRemarkRunes bounds every free-form operator note. Counted in runes, not
// bytes: a 2000-byte limit would cut a CJK note to roughly 660 characters and
// the UI would show a limit the user cannot reconcile with what they typed.
const maxRemarkRunes = db.MaxTaskRemarkRunes

// normalizeRemark trims and length-checks a remark. An empty result is valid
// and means "clear the note".
func normalizeRemark(value string) (string, error) {
	value = strings.TrimSpace(value)
	if utf8.RuneCountInString(value) > maxRemarkRunes {
		return "", fmt.Errorf("a remark may be at most %d characters", maxRemarkRunes)
	}
	return value, nil
}

// updateScheduleMetadata patches a schedule's name and/or remark. Both fields
// are optional and independent, so renaming cannot clear a note.
func (s *Server) updateScheduleMetadata(w http.ResponseWriter, r *http.Request) {
	id, err := parseScheduleID(r)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid schedule id")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTaskMetadataRequestSize)
	var request struct {
		Name   *string `json:"name"`
		Remark *string `json:"remark"`
	}
	if err := decode(r, &request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErr(w, 413, "request body too large")
		} else {
			writeErr(w, 400, err.Error())
		}
		return
	}
	if request.Name == nil && request.Remark == nil {
		writeErr(w, 400, "at least one of name or remark must be provided")
		return
	}
	if request.Name != nil {
		name := strings.TrimSpace(*request.Name)
		if name == "" || utf8.RuneCountInString(name) > maxTaskNameRunes {
			writeErr(w, 400, fmt.Sprintf("a schedule name must be 1 to %d characters", maxTaskNameRunes))
			return
		}
		request.Name = &name
	}
	if request.Remark != nil {
		remark, err := normalizeRemark(*request.Remark)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		request.Remark = &remark
	}
	item, err := s.m.pg.UpdateTaskScheduleMetadata(id, db.TaskSchedulePatch{Name: request.Name, Remark: request.Remark})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if item == nil {
		writeErr(w, 404, "no such schedule")
		return
	}
	writeJSON(w, 200, item)
}
