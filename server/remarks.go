package server

import (
	"fmt"
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
