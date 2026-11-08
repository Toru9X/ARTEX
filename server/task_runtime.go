package server

// taskRunSeconds is the runtime shown for a task: finished segments plus the
// open one, and only while the task is really executing. A paused or queued
// task stops accruing, which is what makes this number different from
// "now - created_at".
//
// Segment timestamps are unix seconds; a zero start means no open segment.
func taskRunSeconds(active, segmentStarted, now int64, status string, paused, queued bool) int64 {
	if active < 0 {
		active = 0
	}
	if status == "running" && !paused && !queued && segmentStarted > 0 && now > segmentStarted {
		return active + now - segmentStarted
	}
	return active
}

// finalizeTaskRunSeconds mirrors the database transition, so the fold can be
// reasoned about — and tested — without a live database.
func finalizeTaskRunSeconds(active, segmentStarted, now int64) (int64, int64) {
	if active < 0 {
		active = 0
	}
	if segmentStarted > 0 && now > segmentStarted {
		active += now - segmentStarted
	}
	return active, 0
}
