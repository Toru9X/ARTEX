package db

import (
	"testing"
	"time"
)

// The SQL side of the execution clock: opening a segment is idempotent and
// gated on the task actually running, folding is idempotent, and a restart
// drops segments whose wall time is unknowable.
func TestTaskRunSegmentLifecycle(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	task, err := d.CreateTask("runtime segment", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID) })

	active, started, err := d.StartTaskRunSegment(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if started == nil {
		t.Fatal("StartTaskRunSegment did not open a segment")
	}
	if active != 0 {
		t.Fatalf("active_run_seconds = %d on a fresh task, want 0", active)
	}
	first := *started

	// Opening again must keep the original start, or every planner round would
	// reset the clock and the task would report almost no runtime.
	_, started, err = d.StartTaskRunSegment(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if started == nil || !started.Equal(first) {
		t.Fatalf("a second start moved the segment: %v -> %v", first, started)
	}

	active, started, err = d.FinalizeTaskRunSegment(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if started != nil {
		t.Fatalf("the segment is still open after finalizing: %v", started)
	}
	folded := active

	// Folding again must be a no-op rather than adding time a second time.
	active, started, err = d.FinalizeTaskRunSegment(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if started != nil || active != folded {
		t.Fatalf("a second fold changed the total: %d -> %d (started=%v)", folded, active, started)
	}

	// A paused task must not be able to open a segment.
	if err := d.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	_, started, err = d.StartTaskRunSegment(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if started != nil {
		t.Fatal("a paused task opened a run segment")
	}
}

// A segment still open when the process stops has unknowable wall time, so
// startup drops it instead of letting the outage count as execution.
func TestClearOpenTaskRunSegments(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	task, err := d.CreateTask("runtime restart", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID) })

	if _, _, err := d.StartTaskRunSegment(task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ClearOpenTaskRunSegments(); err != nil {
		t.Fatal(err)
	}
	var started *time.Time
	var active int64
	if err := d.QueryRow(`SELECT active_run_seconds, run_segment_started_at FROM tasks WHERE id=$1`, task.ID).
		Scan(&active, &started); err != nil {
		t.Fatal(err)
	}
	if started != nil {
		t.Fatalf("an open segment survived the restart sweep: %v", started)
	}
	if active != 0 {
		t.Fatalf("the dropped segment was credited as runtime: %d", active)
	}
}
