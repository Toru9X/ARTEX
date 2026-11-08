//go:build !linux

package server

import "time"

// systemMetricsSnapshot has no reader outside Linux: the numbers come from
// cgroup files and statfs. Report Supported=false so the dashboard hides the
// widget instead of drawing empty bars.
func systemMetricsSnapshot(_ *Server) systemMetricsResponse {
	return systemMetricsResponse{Scope: "unsupported", Supported: false, Timestamp: time.Now().UTC()}
}
