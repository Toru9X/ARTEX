package server

// egress_probe.go — connectivity probing for the global egress proxy.
//
// Saving settings.global_proxy only validates its shape; not one byte goes out,
// so a dead proxy saves just fine. This file sends the real request: (1) the
// exit IP when going direct, (2) the exit IP through that proxy. Where (2) is
// sent is decided by egressTarget — the only judgement call in this file.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Autumn-27/artex/traffic"
)

// defaultEgressProbes are tried in order and the first success wins; used when
// no custom address is configured.
var defaultEgressProbes = []string{
	"https://api.ipify.org?format=json", // returns {"ip":"1.2.3.4"}
	"https://ifconfig.me/ip",            // returns plain text 1.2.3.4
}

// EgressProbeURL is the operator's custom echo endpoint, empty when unset.
func (m *Manager) EgressProbeURL() string {
	if m == nil || m.pg == nil {
		return ""
	}
	raw, _, _ := m.pg.GetSetting(settingEgressProbeURL)
	return strings.TrimSpace(raw)
}

// egressProbes reads the setting on every probe so a save takes effect without
// a restart.
func (m *Manager) egressProbes() []string {
	if raw := m.EgressProbeURL(); raw != "" {
		return []string{raw}
	}
	return defaultEgressProbes
}

// runProxyProbe is the seam reconnect tests inject against. Production servers
// leave s.proxyProbe nil and go straight to probeEgress.
func (s *Server) runProxyProbe(ctx context.Context, proxyRaw, caPEMPath string, probes []string, timeout time.Duration) egressProbeResult {
	if s != nil && s.proxyProbe != nil {
		return s.proxyProbe(ctx, proxyRaw, caPEMPath, probes, timeout)
	}
	return probeEgress(ctx, proxyRaw, caPEMPath, probes, timeout)
}

// validateProbeURL admits only absolute http(s) addresses that point somewhere
// other than this machine or the link-local range.
//
// The endpoint requires login, but the check still matters: an agent can be
// talked into calling it by a page it is testing, and "this machine" inside a
// container is ARTEX itself (its admin port, and cloud metadata at
// 169.254.169.254). Private addresses are deliberately allowed — an intranet
// echo service is the main reason to configure a custom probe at all.
func validateProbeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("probe_url is not a valid URL")
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return "", errors.New("probe_url supports only http / https")
	}
	if u.Host == "" || u.Hostname() == "" {
		return "", errors.New("probe_url has no hostname")
	}
	if err := probeCheckURL(u); err != nil {
		return "", err
	}
	return raw, nil
}

// probeCheckRedirect re-checks every hop, closing the "public address 302s to
// 127.0.0.1" bypass.
func probeCheckRedirect(next *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return errors.New("too many redirects")
	}
	if len(via) > 0 && next.URL.Host != via[0].URL.Host {
		return fmt.Errorf("refusing cross-host redirect (%s -> %s)", via[0].URL.Host, next.URL.Host)
	}
	return probeCheckURL(next.URL)
}

// probeCheckURL rejects only loopback, link-local, unspecified and multicast
// destinations. RFC1918 addresses stay valid for intranet echo services.
func probeCheckURL(u *url.URL) error {
	host := strings.TrimSuffix(strings.TrimSpace(u.Hostname()), ".")
	if zone := strings.IndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	ip := net.ParseIP(host)
	if ip == nil && looksNumericHost(host) {
		var ok bool
		ip, ok = parseLegacyIPv4(host)
		if !ok {
			return fmt.Errorf("refusing unparseable numeric host %q", host)
		}
	}
	if strings.EqualFold(host, "localhost") || (ip != nil && isBlockedDialIP(ip)) {
		return errors.New("refusing a loopback / link-local address")
	}
	return nil
}

// probeBlockSensitiveDial is always on for direct probes. Unlike the repeater,
// probe_url has no local-target escape hatch.
func probeBlockSensitiveDial(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("cannot parse destination address %q", host)
	}
	if isBlockedDialIP(ip) {
		return fmt.Errorf("refusing a loopback / link-local address %s", ip)
	}
	return nil
}

// userinfoRe matches the user:pass@ part of a URL.
var userinfoRe = regexp.MustCompile(`://[^/@\s]+@`)

// maskSecrets strips username and password from a URL. They reach Configured,
// Path and probes[].error, all three of which are rendered or logged.
func maskSecrets(s string) string { return userinfoRe.ReplaceAllString(s, "://***@") }

// egressAttempt keeps the failure reason per address, which is what separates
// "cannot reach the proxy" from "proxy is up but has no route out".
type egressAttempt struct {
	URL       string `json:"url"`
	OK        bool   `json:"ok"`
	IP        string `json:"ip,omitempty"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

// egressProbeResult summarises probing one path shape.
type egressProbeResult struct {
	OK        bool            `json:"ok"`
	ExitIP    string          `json:"exit_ip,omitempty"` // the exit IP the outside world sees
	Via       string          `json:"via,omitempty"`     // direct / http / https / socks5
	ViaLabel  string          `json:"via_label,omitempty"`
	LatencyMS int64           `json:"latency_ms"`
	Error     string          `json:"error,omitempty"`
	Probes    []egressAttempt `json:"probes"` // per-address detail, for diagnosis
}

// egressCheck is one line of the report, for one path shape.
type egressCheck struct {
	Key        string            `json:"key"`   // direct | global
	Label      string            `json:"label"` // shown verbatim by the UI
	Path       string            `json:"path"`  // proxy address actually used (empty = direct)
	Skipped    bool              `json:"skipped,omitempty"`
	SkipReason string            `json:"skip_reason,omitempty"`
	Result     egressProbeResult `json:"result"`
}

// egressReport is the body of POST /api/settings/proxy/test.
type egressReport struct {
	OK         bool          `json:"ok"`          // judged on (2); on (1) when no proxy is configured
	Capture    bool          `json:"capture"`     // whether traffic capture is currently on
	Configured string        `json:"configured"`  // the global_proxy submitted in the form
	AgentProxy string        `json:"agent_proxy"` // what ProxyAddr() actually returns
	Checks     []egressCheck `json:"checks"`
	Warnings   []string      `json:"warnings,omitempty"`
}

// probeEgress touches neither the database nor the Server, so tests can call
// it directly and entirely offline.
func probeEgress(ctx context.Context, proxyRaw, caPEMPath string, probes []string, timeout time.Duration) egressProbeResult {
	start := time.Now()

	// Reuse the traffic package's validator so "what counts as a valid proxy"
	// is defined in exactly one place project-wide.
	var proxyURL *url.URL
	if strings.TrimSpace(proxyRaw) != "" {
		u, err := traffic.ValidateProxyURL(proxyRaw)
		if err != nil {
			return egressProbeResult{
				OK:        false,
				Error:     maskSecrets(err.Error()),
				LatencyMS: time.Since(start).Milliseconds(),
				// An empty slice, not nil: nil serialises to JSON null and the
				// frontend treats the field as an array.
				Probes: []egressAttempt{},
			}
		}
		proxyURL = u
	}

	tr, caErr := buildProbeTransport(proxyURL, caPEMPath)

	client := &http.Client{
		Transport: tr,
		// 2s wider than ctx so ctx expires first and the error reads
		// "context deadline exceeded".
		Timeout:       timeout + 2*time.Second,
		CheckRedirect: probeCheckRedirect,
	}

	attempts := make([]egressAttempt, 0, len(probes))
	for _, target := range probes {
		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		t0 := time.Now()
		ip, err := probeOne(reqCtx, client, target)
		cancel()

		a := egressAttempt{URL: maskSecrets(target), LatencyMS: time.Since(t0).Milliseconds()}
		if err != nil {
			a.Error = maskSecrets(err.Error())
			// Only add the CA note on certificate errors; otherwise a plain
			// connection failure would carry an irrelevant explanation. It has
			// to go in probes[].error — that is what the UI renders, not
			// result.error.
			if caErr != nil && strings.Contains(a.Error, "certificate") {
				a.Error = "the traffic-capture CA is unusable (" + caErr.Error() + "): the certificate error may come from this. " + a.Error
			}
		} else {
			a.OK, a.IP = true, ip
		}
		attempts = append(attempts, a)

		if a.OK {
			// via names the proxy protocol, not the kind of network at the exit.
			via, viaLabel := "direct", "Direct"
			if proxyURL != nil {
				via, viaLabel = proxyURL.Scheme, schemeLabel(proxyURL.Scheme)
			}
			return egressProbeResult{
				OK:        true,
				ExitIP:    ip,
				Via:       via,
				ViaLabel:  viaLabel,
				LatencyMS: time.Since(start).Milliseconds(),
				Probes:    attempts,
			}
		}
	}

	return egressProbeResult{
		OK:        false,
		Error:     "every probe address failed",
		LatencyMS: time.Since(start).Milliseconds(),
		Probes:    attempts,
	}
}

// schemeLabel turns a scheme into something readable ("http" -> "HTTP proxy").
func schemeLabel(scheme string) string {
	switch strings.ToLower(scheme) {
	case "http":
		return "HTTP proxy"
	case "https":
		return "HTTPS proxy"
	case "socks5", "socks5h":
		return "SOCKS5 proxy"
	default:
		return strings.ToUpper(scheme) + " proxy"
	}
}

// buildProbeTransport cannot use http.DefaultTransport: its Proxy reads the
// container's HTTP_PROXY, which would make "test direct" go through a proxy.
// Leaving Proxy nil here is what makes it a real direct connection.
func buildProbeTransport(proxyURL *url.URL, caPEMPath string) (*http.Transport, error) {
	tr := &http.Transport{
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 8 * time.Second,
	}
	if proxyURL != nil {
		tr.Proxy = http.ProxyURL(proxyURL)
	} else {
		// On a direct probe, check again at dial time: this catches a name that
		// only becomes 127.0.0.1 after resolution (DNS rebinding). Not installed
		// when proxying — there the dial goes to the proxy, and a local proxy at
		// 127.0.0.1 is a legitimate configuration.
		tr.DialContext = (&net.Dialer{Timeout: 10 * time.Second, Control: probeBlockSensitiveDial}).DialContext
	}
	// An unusable CA does not panic; the reason is carried back and folded into
	// the failure message, otherwise the user only sees x509 and not the cause.
	if path := strings.TrimSpace(caPEMPath); path != "" {
		pemBytes, err := os.ReadFile(path)
		if err != nil {
			return tr, fmt.Errorf("cannot read %s", path)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return tr, fmt.Errorf("%s is not valid PEM", path)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	return tr, nil
}

// probeOne accepts JSON ({"ip":"..."}) and plain text; anything it cannot
// recognise is an error — it never guesses an IP.
func probeOne(ctx context.Context, client *http.Client, target string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "artex-egress-probe/1.0")

	resp, err := client.Do(req)
	if err != nil {
		// Returned as-is: dial refused / deadline exceeded / x509 each point at
		// a different fault.
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var v struct {
		IP string `json:"ip"`
	}
	if json.Unmarshal(body, &v) == nil && v.IP != "" {
		if net.ParseIP(strings.TrimSpace(v.IP)) == nil {
			return "", errors.New("the ip field in the response is not a valid IP")
		}
		return strings.TrimSpace(v.IP), nil
	}

	// net.ParseIP also rejects HTML (anti-bot pages, proxy error pages).
	if s := strings.TrimSpace(string(body)); net.ParseIP(s) != nil {
		return s, nil
	}
	return "", fmt.Errorf("could not parse an IP from the response (%d bytes; possibly an anti-bot or proxy error page)", len(body))
}

// egressTarget decides where check (2) is sent:
//
//	capture off -> the form value; capture on + saved -> the MITM;
//	capture on + unsaved -> the form value (skipping the MITM)
//
// The third case must not go through the MITM: the MITM's upstream is only
// updated by SetGlobalProxy, so it cannot see the new value in the request
// body and would test the old proxy instead. viaMITM lets the caller widen the
// timeout.
func egressTarget(cfg string, capture, pending bool, agentProxy, agentCA string) (addr, ca string, viaMITM bool) {
	if cfg == "" {
		return "", "", false
	}
	if capture && !pending && agentProxy != "" {
		return agentProxy, agentCA, true
	}
	return cfg, "", false
}

// testEgressProxy mirrors testWebSearch: the address comes from the request
// body (so an unsaved value can be tested), empty means test the direct path,
// and it always answers 200 with the verdict in ok.
func (s *Server) testEgressProxy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GlobalProxy string  `json:"global_proxy"`
		ProbeURL    *string `json:"probe_url"` // omitted = saved address; "" = defaults; set = temporary override
	}
	// The body holds a single address; cap it so nobody posts a large payload.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	// An empty body means "test the direct path".
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, 400, err.Error())
		return
	}

	probes := s.m.egressProbes()
	if req.ProbeURL != nil {
		probes = defaultEgressProbes
		if u := strings.TrimSpace(*req.ProbeURL); u != "" {
			checked, err := validateProbeURL(u)
			if err != nil {
				writeErr(w, 400, err.Error())
				return
			}
			probes = []string{checked}
		}
	}

	// These three decide which path the agent actually takes.
	capture := s.m.TrafficEnabled() // traffic capture switch
	agentProxy := s.m.ProxyAddr()   // the proxy address the agent really uses
	agentCA := s.m.ProxyCACert()    // the MITM CA path when capture is on; empty otherwise
	savedProxy := s.m.GlobalProxy() // the persisted global_proxy

	// 40s overall: the per-request timeout bounds one attempt, not the total,
	// and the frontend fetch has no timeout of its own.
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()

	configuredProxy := strings.TrimSpace(req.GlobalProxy)
	if strings.Contains(configuredProxy, "***") {
		// The form echoes back a masked value; treat that as "unchanged".
		configuredProxy = savedProxy
	}
	// When the form value differs from the saved one, (2) still tests the form
	// value while the agent keeps using the saved one — that has to be said.
	// Normalise first: a trailing slash does not make it unsaved.
	pending := normalizeProxy(configuredProxy) != normalizeProxy(savedProxy)
	rep := egressReport{
		Capture:    capture,
		Configured: maskSecrets(configuredProxy),
		AgentProxy: maskSecrets(agentProxy),
	}

	rep.Checks = append(rep.Checks, egressCheck{
		Key:    "direct",
		Label:  "(1) Direct exit IP (no proxy)",
		Result: s.runProxyProbe(ctx, "", "", probes, 10*time.Second),
	})

	if configuredProxy != "" {
		probeAddr, probeCA, viaMITM := egressTarget(configuredProxy, capture, pending, agentProxy, agentCA)
		timeout := 10 * time.Second
		if viaMITM {
			timeout = 15 * time.Second // one more hop of TLS decrypt + re-sign
		}
		rep.Checks = append(rep.Checks, egressCheck{
			Key:   "global",
			Label: "(2) Exit IP through the global proxy",
			// Path is the address actually probed (port 8788 when via the MITM);
			// this is the field to look at when diagnosing.
			Path:   maskSecrets(probeAddr),
			Result: s.runProxyProbe(ctx, probeAddr, probeCA, probes, timeout),
		})
	} else {
		skipReason := "the field is empty; no proxy configured"
		if savedProxy != "" {
			// Saying "no proxy configured" would contradict W1 ("the agent still uses ...").
			skipReason = "the field is empty; the saved proxy is still in effect"
		}
		rep.Checks = append(rep.Checks, egressCheck{
			Key:        "global",
			Label:      "(2) Exit IP through the global proxy",
			Skipped:    true,
			SkipReason: skipReason,
			Result:     egressProbeResult{Probes: []egressAttempt{}},
		})
	}

	rep.OK = judgeEgress(rep)
	rep.Warnings = egressWarnings(rep, pending, savedProxy)
	writeJSON(w, 200, rep)
}

// normalizeProxy only normalises spelling; it does not validate. An empty
// string or a parse failure is returned unchanged.
func normalizeProxy(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

// judgeEgress is decided by (2); (1) is consulted only when (2) was skipped.
// "Any row succeeded" would be wrong: a working direct path says nothing about
// a proxy that is down.
func judgeEgress(rep egressReport) bool {
	for _, c := range rep.Checks {
		if c.Key == "global" && !c.Skipped {
			return c.Result.OK
		}
	}
	for _, c := range rep.Checks {
		if c.Key == "direct" {
			return c.Result.OK
		}
	}
	return false
}

// egressWarnings produces the notes that are easy to miss when only reading
// the numbers.
func egressWarnings(rep egressReport, pending bool, savedProxy string) []string {
	var out []string
	safeSavedProxy := maskSecrets(savedProxy)

	// W1 the agent runs on the saved configuration; without saying so, a green
	// result reads as "configured correctly".
	if pending {
		switch {
		case rep.Configured == "":
			out = append(out, "This address is not saved yet; the agent still uses "+safeSavedProxy+". Saving switches it to direct.")
		case savedProxy == "":
			out = append(out, "This address is not saved yet; the agent is still direct. "+
				"The results above are for the value in the field and take effect once saved.")
		default:
			out = append(out, "This address is not saved yet; the agent still uses "+safeSavedProxy+
				". The results above are for the value in the field and take effect once saved.")
		}
	}

	var directIP, proxyIP string
	proxyOK := false
	for _, c := range rep.Checks {
		switch c.Key {
		case "direct":
			directIP = c.Result.ExitIP
		case "global":
			if !c.Skipped {
				proxyIP = c.Result.ExitIP
				proxyOK = c.Result.OK
			}
		}
	}

	// W2 judged on the saved value, and only when (2) passed — if it did not,
	// "passing here does not mean" has nothing to qualify.
	if !rep.Capture && proxyOK && strings.HasPrefix(strings.ToLower(savedProxy), "socks5") {
		out = append(out, "This is \"capture off + socks5\": the test uses a Go client, which always honours the proxy, "+
			"but the agent's tools may not — curl can, python urllib fails outright. "+
			"So a pass here does not mean every tool gets through; turn on traffic capture to have the MITM dial for them.")
	}

	// W3 identical rows mean the proxy may not be in effect, or is only
	// forwarding transparently.
	if directIP != "" && proxyIP != "" && directIP == proxyIP {
		out = append(out, fmt.Sprintf("Direct and proxied exit IPs are the same (%s): the proxy may not be in effect or may be forwarding transparently, "+
			"or the jump host and this machine sit behind the same NAT (the exit is genuinely identical). "+
			"To tell them apart, point \"custom IP probe service\" at an intranet echo server and see whether the source IP it reports becomes the jump host.", directIP))
	}

	// W4 also judged on the saved value, or it would contradict W1.
	if rep.Capture && savedProxy == "" {
		out = append(out, "Traffic capture is on but the global proxy is empty: capture only records, the exit is still direct.")
	}

	// W5 inside a container 127.0.0.1 is the container itself.
	if isLoopbackProxy(rep.Configured) {
		out = append(out, "The proxy address is a loopback address (127.0.0.1 / localhost). "+
			"If ARTEX runs in a container, 127.0.0.1 here means the container itself and cannot reach a proxy on the host; "+
			"use the host's reachable IP instead (e.g. http://192.168.x.x:port).")
	}

	return out
}

func isLoopbackProxy(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return false
	}
	h := strings.ToLower(u.Hostname())
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
