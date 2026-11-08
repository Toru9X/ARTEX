package server

import (
	"encoding/json"
	"math"
	"net/http/httptest"
	"runtime"
	"testing"
)

// The endpoint must answer on every platform: on Linux with real readings, and
// elsewhere with Supported=false so the dashboard hides the widget instead of
// drawing zeroed bars.
func TestSystemMetricsReturnsContainerAndDiskValues(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest("GET", "/api/system/metrics", nil)
	w := httptest.NewRecorder()
	s.systemMetrics(w, r)
	if w.Code != 200 {
		t.Fatalf("status=%d, want 200", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store: a cached response freezes the CPU sampling window", cc)
	}
	var got systemMetricsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Scope == "" || got.Timestamp.IsZero() {
		t.Fatalf("unexpected response metadata: %+v", got)
	}
	if runtime.GOOS != "linux" {
		if got.Supported || got.Scope != "unsupported" {
			t.Fatalf("unsupported platform returned metrics: %+v", got)
		}
		return
	}
	if got.Disk.TotalBytes == 0 || got.DataDisk.TotalBytes == 0 {
		t.Fatalf("disk metrics missing: %+v", got)
	}
	for name, m := range map[string]metricValue{"cpu": got.CPU, "memory": got.Memory, "disk": got.Disk, "data_disk": got.DataDisk} {
		if m.Percent < 0 || m.Percent > 100 || math.IsNaN(m.Percent) {
			t.Fatalf("%s percent out of range: %v", name, m.Percent)
		}
	}
}

// A bare Server (no Manager) must not panic — the metrics handler is reachable
// before anything else is wired, and unit tests construct Servers this way.
func TestDataDirPathWithoutManager(t *testing.T) {
	if got := (&Server{}).dataDirPath(); got != "" {
		t.Fatalf("dataDirPath() = %q, want empty when there is no manager", got)
	}
	var nilServer *Server
	if got := nilServer.dataDirPath(); got != "" {
		t.Fatalf("nil receiver: dataDirPath() = %q, want empty", got)
	}
}

func TestPercentAndClamp(t *testing.T) {
	cases := []struct {
		used, total uint64
		want        float64
	}{
		{0, 0, 0}, // unreadable mount: 0, never NaN
		{1, 0, 0}, // zero denominator still cannot divide
		{1, 4, 25},
		{4, 4, 100},
		{8, 4, 100}, // reserved blocks can push used past total
		{0, 100, 0},
		{33, 100, 33},
	}
	for _, tc := range cases {
		if got := percent(tc.used, tc.total); got != tc.want {
			t.Fatalf("percent(%d, %d) = %v, want %v", tc.used, tc.total, got, tc.want)
		}
	}

	for _, tc := range []struct{ in, want float64 }{
		{-0.5, 0}, {0, 0}, {42.5, 42.5}, {100, 100}, {100.1, 100}, {math.Inf(1), 100}, {math.Inf(-1), 0},
	} {
		if got := clampPercent(tc.in); got != tc.want {
			t.Fatalf("clampPercent(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
