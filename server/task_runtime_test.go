package server

import "testing"

// taskRunSeconds decides the duration every task row shows. The cases that
// matter are the ones where a task exists but is not executing: counting those
// would make a task parked overnight look like it ran all night.
func TestTaskRunSeconds(t *testing.T) {
	const (
		started = 1_000
		now     = 1_100 // 100s into the open segment
	)
	cases := []struct {
		name                   string
		active, segmentStarted int64
		status                 string
		paused, queued         bool
		want                   int64
	}{
		{"running with an open segment", 50, started, "running", false, false, 150},
		{"running with no open segment", 50, 0, "running", false, false, 50},
		{"paused does not accrue", 50, started, "running", true, false, 50},
		{"queued does not accrue", 50, started, "running", false, true, 50},
		{"a non-running status does not accrue", 50, started, "created", false, false, 50},
		{"a terminal status does not accrue", 50, started, "done", false, false, 50},
		// Clock skew or a segment stamped in the future must not subtract time.
		{"segment in the future", 50, now + 10, "running", false, false, 50},
		{"segment exactly now", 50, now, "running", false, false, 50},
		{"negative stored value is floored", -5, 0, "running", false, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := taskRunSeconds(tc.active, tc.segmentStarted, now, tc.status, tc.paused, tc.queued)
			if got != tc.want {
				t.Fatalf("taskRunSeconds() = %d, want %d", got, tc.want)
			}
		})
	}
}

// finalizeTaskRunSeconds mirrors the SQL fold. It must be idempotent: pause and
// terminal paths can both fire for the same task, and a second fold with no
// open segment must not add anything.
func TestFinalizeTaskRunSeconds(t *testing.T) {
	active, started := finalizeTaskRunSeconds(50, 1_000, 1_100)
	if active != 150 || started != 0 {
		t.Fatalf("first fold = (%d, %d), want (150, 0)", active, started)
	}
	active, started = finalizeTaskRunSeconds(active, started, 1_200)
	if active != 150 || started != 0 {
		t.Fatalf("second fold changed the total: (%d, %d), want (150, 0)", active, started)
	}
	if active, started = finalizeTaskRunSeconds(10, 2_000, 1_000); active != 10 || started != 0 {
		t.Fatalf("a segment in the future = (%d, %d), want (10, 0)", active, started)
	}
}
