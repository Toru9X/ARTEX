package agent

import "testing"

// report_finding is the only boundary a model-written severity crosses before it
// reaches findings.severity, which has no CHECK. Case and spacing are folded;
// anything still outside the vocabulary must be refused, because every reader
// (the severity filter, the COUNT(*) FILTER buckets, both sort ranks) matches
// the four values exactly.
func TestNormalizeSeverity(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"critical", "critical", true},
		{"High", "high", true},
		{"  medium  ", "medium", true},
		{"LOW", "low", true},
		{"", "", false},
		{"info", "info", false},
		{"informational", "informational", false},
		{"critical (CVSS 9.9)", "critical (cvss 9.9)", false},
		{"severe", "severe", false},
	} {
		got, ok := normalizeSeverity(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("normalizeSeverity(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}
