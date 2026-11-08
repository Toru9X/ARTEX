package server

import "testing"

// An installation that never touches the proxy pool must behave exactly as it
// did before the pool existed. ProxyAddr is the one place where that could
// regress silently: it now routes through the local forwarder, and handing a
// bare "http://127.0.0.1:PORT" to agents on a direct-egress install would send
// every tool through a hop that should not be there.
func TestProxyAddrUnchangedWithoutProxyConfiguration(t *testing.T) {
	fp, err := newDynamicForwardProxy(func() string { return "" })
	if err != nil {
		t.Skipf("cannot listen locally: %v", err)
	}
	t.Cleanup(func() { _ = fp.Close() })

	m := &Manager{forwardProxy: fp, proxyPool: &proxyPoolState{}}
	if got := m.ProxyAddr(); got != "" {
		t.Fatalf("ProxyAddr() = %q with no proxy and no pool, want empty (direct egress)", got)
	}

	// A pool that exists but holds no entry is still "not configured".
	if m.proxyPoolConfigured.Load() {
		t.Fatal("an empty pool must not report itself as configured")
	}
}

// With a proxy configured, agents must get the forwarder's address rather than
// the raw URL: that is what keeps credentials out of the agent environment and
// lets a pool switch take effect without rebuilding agents.
func TestProxyAddrUsesForwarderWhenProxyConfigured(t *testing.T) {
	fp, err := newDynamicForwardProxy(func() string { return "http://upstream.example:8080" })
	if err != nil {
		t.Skipf("cannot listen locally: %v", err)
	}
	t.Cleanup(func() { _ = fp.Close() })

	m := &Manager{forwardProxy: fp, globalProxy: "http://user:secret@upstream.example:8080"}
	got := m.ProxyAddr()
	if got != fp.Addr() {
		t.Fatalf("ProxyAddr() = %q, want the local forwarder %q", got, fp.Addr())
	}
	if got == "" {
		t.Fatal("ProxyAddr() must not be empty while a proxy is configured")
	}
}

// Without a forwarder (its listener failed to start) the raw value is handed
// back, exactly as before this feature. Masking here would hand agents a URL
// that cannot connect.
func TestProxyAddrFallsBackToRawValueWithoutForwarder(t *testing.T) {
	const raw = "http://user:secret@upstream.example:8080"
	m := &Manager{globalProxy: raw}
	if got := m.ProxyAddr(); got != raw {
		t.Fatalf("ProxyAddr() = %q, want the raw value %q when no forwarder is running", got, raw)
	}
}
