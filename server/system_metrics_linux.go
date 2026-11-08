//go:build linux

package server

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// systemMetricsSnapshot reads CPU/memory from the cgroup (so a container
// reports its own limits, not the host's) and disk from statfs. CPU is a rate,
// so it needs two samples: the first call after startup always reports 0%.
func systemMetricsSnapshot(s *Server) systemMetricsResponse {
	use, cpuLimit, cpuOK := cgroupCPU()
	cpuPct := 0.0
	if cpuOK {
		now := time.Now()
		s.metricsMu.Lock()
		// use < lastCPUUse means the counter was reset (cgroup recreated);
		// treat it as a fresh baseline instead of reporting a negative rate.
		if !s.lastCPUAt.IsZero() && use >= s.lastCPUUse && cpuLimit > 0 {
			elapsed := now.Sub(s.lastCPUAt).Seconds()
			if elapsed > 0 {
				cpuPct = float64(use-s.lastCPUUse) / 1e6 / elapsed / cpuLimit * 100
			}
		}
		s.lastCPUUse, s.lastCPUAt = use, now
		s.metricsMu.Unlock()
	}
	memUsed, memTotal, memOK := cgroupMemory()
	root := diskMetric("/")
	data := diskMetric(s.dataDirPath())
	if data.TotalBytes == 0 {
		data = root // no separate data volume, or the path is unreadable
	}
	return systemMetricsResponse{
		Scope:     "container",
		Supported: true,
		Timestamp: time.Now().UTC(),
		Container: cpuOK || memOK,
		CPU:       metricValue{Percent: clampPercent(cpuPct)},
		Memory:    metricValue{UsedBytes: memUsed, TotalBytes: memTotal, Percent: percent(memUsed, memTotal)},
		Disk:      root,
		DataDisk:  data,
	}
}

// cgroupCPU returns cumulative CPU microseconds and the core limit, trying
// cgroup v2 ("/sys/fs/cgroup") before the v1 controller directory.
func cgroupCPU() (usageUsec uint64, cpuLimit float64, ok bool) {
	for _, dir := range []string{"/sys/fs/cgroup", "/sys/fs/cgroup/cpu"} {
		b, err := os.ReadFile(filepath.Join(dir, "cpu.stat"))
		if err != nil {
			continue
		}
		var use uint64
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && f[0] == "usage_usec" {
				use, _ = strconv.ParseUint(f[1], 10, 64)
			}
		}
		// Without a quota the ceiling is every visible core; "max" in cpu.max
		// means exactly that, so it keeps the NumCPU default.
		limit := float64(runtime.NumCPU())
		if q, err := os.ReadFile(filepath.Join(dir, "cpu.max")); err == nil {
			f := strings.Fields(string(q))
			if len(f) == 2 && f[0] != "max" {
				quota, _ := strconv.ParseFloat(f[0], 64)
				period, _ := strconv.ParseFloat(f[1], 64)
				if period > 0 {
					limit = quota / period
				}
			}
		}
		if use > 0 {
			return use, limit, true
		}
	}
	return 0, 0, false
}

// cgroupMemory returns current and limit bytes. An unlimited cgroup reports
// the host total instead, so the bar has a denominator the user recognizes.
func cgroupMemory() (used, total uint64, ok bool) {
	for _, dir := range []string{"/sys/fs/cgroup", "/sys/fs/cgroup/memory"} {
		// cgroup v2
		cur, curErr := readUint(filepath.Join(dir, "memory.current"))
		lim, limErr := readUint(filepath.Join(dir, "memory.max"))
		if curErr == nil && limErr == nil {
			return cur, lim, lim > 0
		}
		if curErr == nil {
			if b, err := os.ReadFile(filepath.Join(dir, "memory.max")); err == nil && strings.TrimSpace(string(b)) == "max" {
				return cur, hostMemoryTotal(), true
			}
		}
		// cgroup v1. An unlimited v1 cgroup stores a sentinel near 2^64, which
		// would render as a meaningless multi-exabyte total — reject it.
		cur, curErr = readUint(filepath.Join(dir, "memory.usage_in_bytes"))
		lim, limErr = readUint(filepath.Join(dir, "memory.limit_in_bytes"))
		if curErr == nil && limErr == nil && lim < ^uint64(0)/2 {
			return cur, lim, true
		}
	}
	return 0, 0, false
}

// hostMemoryTotal reads MemTotal from /proc/meminfo, in bytes.
func hostMemoryTotal() uint64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "MemTotal:" {
			n, _ := strconv.ParseUint(f[1], 10, 64)
			return n * 1024 // /proc/meminfo reports kB
		}
	}
	return 0
}

func readUint(path string) (uint64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}

// diskMetric reports usage of the filesystem holding path. Free space uses
// Bavail (what a non-root process may actually use), not Bfree.
func diskMetric(path string) metricValue {
	var st syscall.Statfs_t
	if path == "" || syscall.Statfs(path, &st) != nil {
		return metricValue{}
	}
	total := st.Blocks * uint64(st.Bsize)
	free := st.Bavail * uint64(st.Bsize)
	used := total - free
	return metricValue{UsedBytes: used, TotalBytes: total, Percent: percent(used, total)}
}
