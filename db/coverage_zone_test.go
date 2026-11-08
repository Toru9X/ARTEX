package db

import "testing"

// TestCoverageZone pins the evidence-based zoning: a private address is always
// internal, a public domain is internet-facing, and a service/app/endpoint is
// boundary exposure only when it actually has a reachable host.
func TestCoverageZone(t *testing.T) {
	cases := []struct {
		name string
		node CoverageGraphNode
		want string
	}{
		{"private ip", CoverageGraphNode{Kind: "ip", IP: "10.0.0.5"}, "internal"},
		{"loopback service", CoverageGraphNode{Kind: "service", IP: "127.0.0.1"}, "internal"},
		{"link local", CoverageGraphNode{Kind: "endpoint", IP: "169.254.1.1"}, "internal"},
		{"public ip", CoverageGraphNode{Kind: "ip", IP: "203.0.113.9"}, "internet"},
		{"root domain", CoverageGraphNode{Kind: "root_domain", Domain: "example.com"}, "internet"},
		{"subdomain", CoverageGraphNode{Kind: "subdomain", Domain: "api.example.com"}, "internet"},
		{"company", CoverageGraphNode{Kind: "company"}, "internet"},
		// The kind alone never decides: a public endpoint is boundary, not internal.
		{"public endpoint", CoverageGraphNode{Kind: "endpoint", Domain: "api.example.com"}, "boundary"},
		{"endpoint by url", CoverageGraphNode{Kind: "endpoint", URL: "https://api.example.com/v1/orders"}, "boundary"},
		{"hostless app", CoverageGraphNode{Kind: "app", AppName: "billing"}, "internal"},
		{"unknown kind", CoverageGraphNode{Kind: "whatever"}, "internal"},
	}
	for _, c := range cases {
		node := c.node
		coverageZone(&node)
		if node.Zone != c.want {
			t.Errorf("%s: zone = %q, want %q", c.name, node.Zone, c.want)
		}
		if node.ZoneReason == "" {
			t.Errorf("%s: zone has no reason", c.name)
		}
	}

	// A nil node must not panic: the graph builder calls this per row.
	coverageZone(nil)
}
