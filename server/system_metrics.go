package server

import (
	"encoding/json"
	"net/http"
	"time"
)

// metricValue is one resource reading. Percent is always 0-100; CPU reports
// only Percent because there is no meaningful "used bytes" for it.
type metricValue struct {
	UsedBytes  uint64  `json:"used_bytes"`
	TotalBytes uint64  `json:"total_bytes"`
	Percent    float64 `json:"percent"`
}

// systemMetricsResponse is the host/container resource snapshot the dashboard
// polls. Supported=false means this build cannot read them (every OS but
// Linux), and the caller should hide the widget rather than show zeros.
type systemMetricsResponse struct {
	Scope     string      `json:"scope"`
	Supported bool        `json:"supported"`
	Timestamp time.Time   `json:"timestamp"`
	CPU       metricValue `json:"cpu"`
	Memory    metricValue `json:"memory"`
	Disk      metricValue `json:"disk"`
	DataDisk  metricValue `json:"data_disk"`
	Container bool        `json:"container_metrics"`
}

// systemMetrics serves the snapshot. CPU percent is computed from the delta
// since the previous call, so it is no-store: a cached response would also
// freeze the sampling window and report 0%.
func (s *Server) systemMetrics(w http.ResponseWriter, r *http.Request) {
	out := systemMetricsSnapshot(s)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// dataDirPath is the absolute data directory the Manager resolved at startup.
// Empty when there is no manager (unit tests build a bare Server), which makes
// the data-disk reading fall back to the root filesystem.
func (s *Server) dataDirPath() string {
	if s == nil || s.m == nil {
		return ""
	}
	return s.m.dir
}

// percent and clampPercent live here rather than beside the Linux readers so
// they compile — and can be tested — on every platform.

// percent is used/total as a 0-100 percentage; a zero total reads as 0 rather
// than NaN, so the UI never has to special-case an unreadable mount.
func percent(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return clampPercent(float64(used) / float64(total) * 100)
}

// clampPercent bounds a percentage to 0-100. A CPU delta sampled across a
// clock jump, or a filesystem whose reserved blocks make used exceed total,
// would otherwise render as a negative or overflowing bar.
func clampPercent(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
