package server

// egress_probe_test.go — offline tests for egress probing. Every server is a
// local httptest instance; nothing reaches the real internet, or CI would fail
// at random on network jitter.

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeIPServer starts a stand-in IP echo service. The addresses come from the
// documentation ranges so they cannot be confused with real ones.
func fakeIPServer(ip string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"` + ip + `"}`))
	}))
}

// TestProbeEgress covers probeEgress's input/response shapes: success, invalid
// scheme, dead proxy, unusable response, and falling through to the next
// address. Each case carries its own server and assertion, so the t.Run name
// points straight at the broken one.
func TestProbeEgress(t *testing.T) {
	okSrv := fakeIPServer("203.0.113.7")
	defer okSrv.Close()
	htmlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>access denied</body></html>"))
	}))
	defer htmlSrv.Close()
	deniedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer deniedSrv.Close()
	fallbackSrv := fakeIPServer("203.0.113.42")
	defer fallbackSrv.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Host {
		case strings.TrimPrefix(okSrv.URL, "http://"):
			_, _ = w.Write([]byte(`{"ip":"203.0.113.7"}`))
		case strings.TrimPrefix(htmlSrv.URL, "http://"):
			_, _ = w.Write([]byte("<html><body>access denied</body></html>"))
		case strings.TrimPrefix(deniedSrv.URL, "http://"):
			http.Error(w, "nope", http.StatusForbidden)
		case strings.TrimPrefix(fallbackSrv.URL, "http://"):
			_, _ = w.Write([]byte(`{"ip":"203.0.113.42"}`))
		default:
			http.Error(w, "unknown target", http.StatusBadGateway)
		}
	}))
	defer proxy.Close()

	cases := []struct {
		name    string
		proxy   string
		probes  []string
		timeout time.Duration
		check   func(t *testing.T, res egressProbeResult)
	}{
		{
			name: "gets an IP through the proxy", proxy: proxy.URL, probes: []string{okSrv.URL}, timeout: 5 * time.Second,
			check: func(t *testing.T, res egressProbeResult) {
				if !res.OK || res.ExitIP != "203.0.113.7" || res.Via != "http" {
					t.Fatalf("got %+v, want success with via=http and IP=203.0.113.7", res)
				}
			},
		},
		{
			// The latency assertion is what proves it never touched the network.
			name: "an invalid scheme is rejected locally", proxy: "ftp://127.0.0.1:21", probes: nil, timeout: time.Second,
			check: func(t *testing.T, res egressProbeResult) {
				if res.OK || res.Error == "" {
					t.Fatalf("an invalid scheme must fail and carry a reason, got %+v", res)
				}
				if res.LatencyMS > 500 {
					t.Fatalf("shape validation should happen locally; %dms is too long", res.LatencyMS)
				}
				// A nil slice serialises to JSON null and crashes a frontend
				// that treats the field as an array.
				if res.Probes == nil {
					t.Fatal("probes must not be nil (it serialises to null)")
				}
			},
		},
		{
			// The core regression: a well-formed proxy whose port is closed
			// must be recognised as such.
			name: "a dead proxy carries the reason back", proxy: "socks5://127.0.0.1:1",
			probes: []string{"http://example.invalid"}, timeout: 2 * time.Second,
			check: func(t *testing.T, res egressProbeResult) {
				if res.OK {
					t.Fatal("a dead proxy must not succeed")
				}
				if len(res.Probes) == 0 || res.Probes[0].Error == "" {
					t.Fatalf("expected at least one attempt with a reason, got %+v", res.Probes)
				}
			},
		},
		{
			name: "HTML is not mistaken for an IP", proxy: proxy.URL, probes: []string{htmlSrv.URL}, timeout: 5 * time.Second,
			check: func(t *testing.T, res egressProbeResult) {
				if res.OK {
					t.Fatalf("an anti-bot or error page must not count as an IP, got exit_ip=%q", res.ExitIP)
				}
			},
		},
		{
			name: "falls through to the next address", proxy: proxy.URL,
			probes: []string{deniedSrv.URL, fallbackSrv.URL}, timeout: 5 * time.Second,
			check: func(t *testing.T, res egressProbeResult) {
				if !res.OK || res.ExitIP != "203.0.113.42" {
					t.Fatalf("expected the second address to succeed, got %+v", res)
				}
				if len(res.Probes) != 2 {
					t.Fatalf("expected two recorded attempts, got %d", len(res.Probes))
				}
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.check(t, probeEgress(context.Background(), c.proxy, "", c.probes, c.timeout))
		})
	}
}

// TestProbeEgressThroughProxy verifies the request really went through the
// proxy, and that via / via_label are filled in alongside.
//
// It asserts "the proxy received a request", not "the result looks right": if
// Transport.Proxy were never set, the probe would still succeed by going
// direct, producing a result that looks proxied but is not. The stand-in proxy
// does not forward; it answers with an IP, which works because Go sends an
// absolute URI to a proxy for plaintext HTTP.
func TestProbeEgressThroughProxy(t *testing.T) {
	var proxied int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&proxied, 1)
		_, _ = w.Write([]byte(`{"ip":"198.51.100.9"}`))
	}))
	defer proxy.Close()

	res := probeEgress(context.Background(), proxy.URL, "", []string{"http://example.invalid/ip"}, 5*time.Second)
	if !res.OK {
		t.Fatalf("probing through the proxy should succeed: %s / %+v", res.Error, res.Probes)
	}
	if atomic.LoadInt32(&proxied) == 0 {
		t.Fatal("the proxy received no request — the Transport did not use it")
	}
	if res.ExitIP != "198.51.100.9" {
		t.Fatalf("exit IP = %q, want the proxy's 198.51.100.9", res.ExitIP)
	}
	if res.Via != "http" || res.ViaLabel != "HTTP proxy" {
		t.Fatalf("via/via_label wrong: %q / %q", res.Via, res.ViaLabel)
	}
}

// TestProbeEgressTrustsCustomCA exercises the "via the MITM" path: without the
// CA it must fail (proving the trust step is required), with it, succeed.
func TestProbeEgressTrustsCustomCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ip":"192.0.2.5"}`))
	}))
	defer srv.Close()

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	if res := probeEgress(context.Background(), "", "", []string{srv.URL}, 5*time.Second); res.OK {
		t.Fatal("must not succeed without trusting the self-signed CA")
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		client, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			_ = upstream.Close()
			return
		}
		_, _ = fmt.Fprint(rw, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = rw.Flush()
		go func() {
			_, _ = io.Copy(upstream, client)
			_ = upstream.Close()
		}()
		_, _ = io.Copy(client, upstream)
		_ = client.Close()
	}))
	defer proxy.Close()
	res := probeEgress(context.Background(), proxy.URL, caPath, []string{srv.URL}, 5*time.Second)
	if !res.OK || res.ExitIP != "192.0.2.5" {
		t.Fatalf("should get an IP once the CA is trusted, got %+v / %+v", res.Error, res.Probes)
	}
}

// TestJudgeEgress pins the overall verdict: with a proxy configured it is
// decided by (2), and (1) counts only when (2) was skipped.
func TestJudgeEgress(t *testing.T) {
	ok := egressProbeResult{OK: true, ExitIP: "1.2.3.4"}
	bad := egressProbeResult{OK: false, Error: "x"}

	cases := []struct {
		name string
		rep  egressReport
		want bool
	}{
		{"no proxy: only (1) direct", egressReport{Checks: []egressCheck{
			{Key: "direct", Result: ok}, {Key: "global", Skipped: true},
		}}, true},
		{"proxy configured and working", egressReport{Checks: []egressCheck{
			{Key: "direct", Result: ok}, {Key: "global", Result: ok},
		}}, true},
		// The decisive case: direct works, proxy does not — the overall verdict
		// must be a failure, or the UI shows a green light for a dead proxy.
		{"direct works but the proxy does not", egressReport{Checks: []egressCheck{
			{Key: "direct", Result: ok}, {Key: "global", Result: bad},
		}}, false},
		{"proxy works, direct does not", egressReport{Checks: []egressCheck{
			{Key: "direct", Result: bad}, {Key: "global", Result: ok},
		}}, true},
		{"both rows fail", egressReport{Checks: []egressCheck{
			{Key: "direct", Result: bad}, {Key: "global", Result: bad},
		}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := judgeEgress(c.rep); got != c.want {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
}

// TestEgressWarnings covers when each of the five notes fires and, just as
// importantly, when it must not. Every case pins both sides.
func TestEgressWarnings(t *testing.T) {
	okChecks := []egressCheck{
		{Key: "direct", Result: egressProbeResult{OK: true, ExitIP: "9.9.9.9"}},
		{Key: "global", Result: egressProbeResult{OK: true, ExitIP: "8.8.8.8"}},
	}
	sameIP := []egressCheck{
		{Key: "direct", Result: egressProbeResult{OK: true, ExitIP: "9.9.9.9"}},
		{Key: "global", Result: egressProbeResult{OK: true, ExitIP: "9.9.9.9"}},
	}
	proxyDown := []egressCheck{
		{Key: "direct", Result: egressProbeResult{OK: true, ExitIP: "9.9.9.9"}},
		{Key: "global", Result: egressProbeResult{OK: false, Error: "connection refused"}},
	}

	cases := []struct {
		name    string
		rep     egressReport
		pending bool
		saved   string
		want    string // substring that must appear (empty = do not check)
		wantNot string // substring that must not appear
	}{
		{"W2 capture off + socks5", egressReport{Capture: false, Configured: "socks5://1.2.3.4:1080", Checks: okChecks},
			false, "socks5://1.2.3.4:1080", "python urllib", ""},
		{"W2 no false positive: the saved proxy is http", egressReport{Capture: false, Configured: "socks5://1.2.3.4:1080", Checks: okChecks},
			true, "http://1.2.3.4:8080", "", "python urllib"},
		{"W2 no false negative: the saved proxy is the socks5 one", egressReport{Capture: false, Configured: "http://1.2.3.4:8080", Checks: okChecks},
			true, "socks5://1.2.3.4:1080", "python urllib", ""},
		{"W2 silent when (2) failed", egressReport{Capture: false, Configured: "socks5://1.2.3.4:1080", Checks: proxyDown},
			false, "socks5://1.2.3.4:1080", "", "python urllib"},
		{"W3 both rows report the same IP", egressReport{Configured: "http://1.2.3.4:8080", Checks: sameIP},
			false, "", "exit IPs are the same", ""},
		{"W3 no false positive: different IPs", egressReport{Configured: "http://1.2.3.4:8080", Checks: okChecks},
			false, "", "", "exit IPs are the same"},
		{"W4 capture on + no proxy", egressReport{Capture: true, Configured: ""},
			false, "", "the exit is still direct", ""},
		{"W4 no false positive: a saved proxy still exists", egressReport{Capture: true, Configured: ""},
			true, "http://1.2.3.4:8080", "", "global proxy is empty"},
		{"W1 the form value is unsaved", egressReport{Capture: false, Configured: "socks5://1.2.3.4:1080"},
			true, "", "not saved yet", ""},
		{"W5 loopback 127.0.0.1", egressReport{Configured: "http://127.0.0.1:7897"},
			false, "", "loopback address", ""},
		{"W5 loopback localhost", egressReport{Configured: "socks5://localhost:1080"},
			false, "", "loopback address", ""},
		{"W5 no false positive: a LAN address", egressReport{Configured: "http://192.168.1.5:8080"},
			false, "", "", "loopback address"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := egressWarnings(c.rep, c.pending, c.saved)
			if c.want != "" && !hasSubstr(w, c.want) {
				t.Fatalf("should contain %q, got %v", c.want, w)
			}
			if c.wantNot != "" && hasSubstr(w, c.wantNot) {
				t.Fatalf("should not contain %q, got %v", c.wantNot, w)
			}
		})
	}
}

// TestSchemeLabel keeps fragments like "via http" out of the UI.
func TestSchemeLabel(t *testing.T) {
	cases := map[string]string{
		"http":    "HTTP proxy",
		"HTTPS":   "HTTPS proxy", // case-insensitive
		"socks5":  "SOCKS5 proxy",
		"socks5h": "SOCKS5 proxy",
		"socks4":  "SOCKS4 proxy", // unknown scheme fallback: at least readable
	}
	for in, want := range cases {
		if got := schemeLabel(in); got != want {
			t.Errorf("schemeLabel(%q)=%q, want %q", in, got, want)
		}
	}
}

// TestEgressTarget pins the core decision: where row (2) is actually sent.
// The third case (capture on + unsaved) is the easy one to get wrong — going
// through the MITM there would silently test the old proxy.
func TestEgressTarget(t *testing.T) {
	const (
		cfg  = "http://10.0.0.9:8080"
		mitm = "http://127.0.0.1:8788"
		ca   = "/app/data/traffic/_ca/mitmproxy-ca-cert.pem"
	)

	cases := []struct {
		name      string
		cfg       string
		capture   bool
		pending   bool
		agentPrxy string
		wantAddr  string
		wantCA    string
		wantViaM  bool
	}{
		{"capture off: the form value, direct", cfg, false, false, mitm, cfg, "", false},
		{"capture off + unsaved: still the form value", cfg, false, true, mitm, cfg, "", false},
		{"capture on + saved: via the MITM, with the CA", cfg, true, false, mitm, mitm, ca, true},
		{"capture on + unsaved: skip the MITM", cfg, true, true, mitm, cfg, "", false},
		{"empty proxy: send nothing", "", true, false, mitm, "", "", false},
		// Edge case: capture is on but no MITM address is available — fall back
		// to the form value rather than returning an empty address.
		{"capture on but no MITM address", cfg, true, false, "", cfg, "", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addr, gotCA, viaM := egressTarget(c.cfg, c.capture, c.pending, c.agentPrxy, ca)
			if addr != c.wantAddr || gotCA != c.wantCA || viaM != c.wantViaM {
				t.Fatalf("got (addr=%q ca=%q viaMITM=%v), want (%q %q %v)",
					addr, gotCA, viaM, c.wantAddr, c.wantCA, c.wantViaM)
			}
		})
	}
}

// TestBuildProbeTransport covers the Transport's three invariants: a direct
// probe ignores the environment, a missing CA file errors, and invalid CA
// content errors.
func TestBuildProbeTransport(t *testing.T) {
	// This cannot be tested by setting the env and sending a request:
	// ProxyFromEnvironment initialises once per process, so after an earlier
	// case the variable no longer takes effect and the test would pass for the
	// wrong reason. Assert Proxy is nil instead.
	t.Run("a direct probe ignores HTTP_PROXY", func(t *testing.T) {
		t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
		t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
		tr, err := buildProbeTransport(nil, "")
		if err != nil {
			t.Fatalf("an empty CA path must not error: %v", err)
		}
		if tr.Proxy != nil {
			t.Fatal("a direct Transport must not set Proxy, or it picks up HTTP_PROXY")
		}
	})

	t.Run("the CA file does not exist", func(t *testing.T) {
		if _, err := buildProbeTransport(nil, "/nonexistent/ca.pem"); err == nil {
			t.Fatal("expected an error rather than a silent downgrade to a Transport that will report x509")
		}
	})

	t.Run("the CA content is not PEM", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.pem")
		if err := os.WriteFile(bad, []byte("not a pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := buildProbeTransport(nil, bad); err == nil {
			t.Fatal("expected an error")
		}
	})
}

// hasSubstr reports whether any warning in the list contains sub.
func hasSubstr(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// TestValidateProbeURL pins where probe_url draws the line: private ranges
// allowed, this machine and link-local refused.
func TestValidateProbeURL(t *testing.T) {
	ok := []string{
		"http://192.168.132.130:19000/", // the main reason to configure a custom probe
		"https://api.ipify.org?format=json",
		"http://10.0.0.5:8080/",
		"https://172.16.10.20/",
		"http://example.com/",
	}
	for _, raw := range ok {
		if _, err := validateProbeURL(raw); err != nil {
			t.Fatalf("%s should be allowed, got %v", raw, err)
		}
	}

	bad := map[string]string{
		"ftp://example.com/":             "only http / https",
		"file:///etc/passwd":             "only http / https",
		"/relative/path":                 "only http / https",
		"http:///nohost":                 "no hostname",
		"http://127.0.0.1:8080/":         "loopback",
		"http://localhost:8080/":         "loopback",
		"http://169.254.169.254/latest/": "loopback",
		"http://[::1]:8080/":             "loopback",
		// inet_aton spellings of 127.0.0.1 — the reason parseLegacyIPv4 exists.
		"http://2130706433/": "loopback",
		"http://0x7f.1/":     "loopback",
		"http://127.1/":      "loopback",
	}
	for raw, want := range bad {
		_, err := validateProbeURL(raw)
		if err == nil {
			t.Fatalf("%s should be rejected", raw)
		}
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error for %s should contain %q, got %v", raw, want, err)
		}
	}
}

// TestProbeCheckRedirect confirms every hop is re-checked: cross-host, this
// machine and too many hops all abort.
func TestProbeCheckRedirect(t *testing.T) {
	via := []*http.Request{httptest.NewRequest(http.MethodGet, "https://api.ipify.org", nil)}
	if err := probeCheckRedirect(httptest.NewRequest(http.MethodGet, "https://api.ipify.org/ip", nil), via); err != nil {
		t.Fatalf("a same-host redirect should be allowed, got %v", err)
	}
	if err := probeCheckRedirect(httptest.NewRequest(http.MethodGet, "https://ifconfig.me/ip", nil), via); err == nil {
		t.Fatal("a redirect to another public host must be refused")
	}
	if err := probeCheckRedirect(httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787/api/settings", nil), via); err == nil {
		t.Fatal("a redirect to this machine must be refused")
	}
	if err := probeCheckRedirect(httptest.NewRequest(http.MethodGet, "https://api.ipify.org", nil),
		[]*http.Request{via[0], via[0], via[0]}); err == nil {
		t.Fatal("more than 3 hops must be refused")
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ip":"203.0.113.9"}`))
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusFound))
	defer redirector.Close()
	_, err := (&http.Client{CheckRedirect: probeCheckRedirect}).Get(redirector.URL)
	if err == nil || !strings.Contains(err.Error(), "refusing cross-host redirect") {
		t.Fatalf("a cross-host 302 between httptest servers should fail, got %v", err)
	}
}

// TestProbeEgressBlocksLoopback confirms the dial stage really blocks local
// addresses. This is the backstop beyond URL validation, and what catches a
// name that only resolves to 127.0.0.1 at dial time.
func TestProbeEgressBlocksLoopback(t *testing.T) {
	srv := fakeIPServer("203.0.113.7")
	defer srv.Close()

	res := probeEgress(context.Background(), "", "", []string{srv.URL}, 2*time.Second)
	if res.OK {
		t.Fatalf("dialling 127.0.0.1 should fail, got %+v", res)
	}
	if len(res.Probes) != 1 || !strings.Contains(res.Probes[0].Error, "loopback") {
		t.Fatalf("the error should say the local address was refused, got %+v", res.Probes)
	}
}

// TestMaskSecrets confirms credentials cannot leak to the UI with the result.
func TestMaskSecrets(t *testing.T) {
	cases := map[string]string{
		"http://user:pass@192.168.1.5:8080": "http://***@192.168.1.5:8080",
		"http://192.168.1.5:8080":           "http://192.168.1.5:8080",
		`socks5://u:p@h:1080: dial tcp`:     "socks5://***@h:1080: dial tcp",
	}
	for in, want := range cases {
		if got := maskSecrets(in); got != want {
			t.Fatalf("maskSecrets(%q) = %q, want %q", in, got, want)
		}
	}
}
