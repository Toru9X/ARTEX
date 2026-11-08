package server

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

// A handler that exists but was never registered is invisible to every test
// that calls it directly, and to the compiler. This walks the real mux for the
// endpoints added by the ported features: anything unrouted answers 404 with
// Go's own "404 page not found" body, which is what this detects.
//
// It is deliberately a list of paths rather than a reflection trick: the point
// is that adding a handler without a route is caught, and that only happens if
// the route is written down twice — once in server.go, once here.
func TestPortedRoutesAreRegistered(t *testing.T) {
	m := proxyTestManager(t)
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New(ctx, m, dir, dir, dir)
	s.archiveWG.Wait()
	<-s.side.done
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	handler := s.Handler()

	routes := []struct{ method, path string }{
		{"GET", "/api/system/metrics"},
		{"POST", "/api/settings/proxy/test"},
		{"GET", "/api/settings/proxy-pool"},
		{"POST", "/api/settings/proxy-pool/import"},
		{"PUT", "/api/settings/proxy-pool/some-id"},
		{"DELETE", "/api/settings/proxy-pool/some-id"},
		{"POST", "/api/settings/proxy-pool/some-id/test"},
		{"POST", "/api/settings/proxy-pool/test-all"},
		{"POST", "/api/settings/proxy-pool/some-id/activate"},
		{"POST", "/api/tasks/1/proxy/test"},
		{"GET", "/api/schedules"},
		{"POST", "/api/schedules"},
		{"GET", "/api/schedules/1"},
		{"PATCH", "/api/schedules/1"},
		{"DELETE", "/api/schedules/1"},
		{"PATCH", "/api/schedules/1/metadata"},
		{"PATCH", "/api/schedules/1/remark"},
		{"POST", "/api/schedules/1/pause"},
		{"POST", "/api/schedules/1/resume"},
		{"POST", "/api/schedules/1/run-now"},
	}
	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			r := httptest.NewRequest(route.method, route.path, strings.NewReader("{}"))
			r.Header.Set("Authorization", "Bearer "+token)
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			// The handler may legitimately answer 400/404/500 for this made-up
			// input. Only the mux's own miss means the route does not exist.
			if strings.Contains(w.Body.String(), "404 page not found") {
				t.Fatalf("%s %s is not registered on the mux", route.method, route.path)
			}
		})
	}
}
