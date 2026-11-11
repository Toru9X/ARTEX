package agent

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// Anthropic Messages requests gain a top-level cache_control; other paths and
// bodies that already carry one pass through untouched.
func TestAutoCacheTransport(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, r.URL.Path+" "+string(b))
	}))
	defer srv.Close()
	c := &http.Client{Transport: autoCacheTransport{base: http.DefaultTransport}}
	post := func(path, body string) {
		resp, err := c.Post(srv.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	post("/v1/messages", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`)
	post("/v1/messages", `{"cache_control":{"type":"ephemeral","ttl":"1h"},"messages":[]}`)
	post("/v1/messages/count_tokens", `{"messages":[]}`)
	post("/v1/messages", `not json`)

	var first map[string]json.RawMessage
	if err := json.Unmarshal([]byte(strings.TrimPrefix(got[0], "/v1/messages ")), &first); err != nil {
		t.Fatal(err)
	}
	if string(first["cache_control"]) != `{"type":"ephemeral"}` || first["model"] == nil {
		t.Fatalf("messages request not auto-cached: %s", got[0])
	}
	for i, want := range []string{
		`/v1/messages {"cache_control":{"type":"ephemeral","ttl":"1h"},"messages":[]}`,
		`/v1/messages/count_tokens {"messages":[]}`,
		`/v1/messages not json`,
	} {
		if got[i+1] != want {
			t.Errorf("request %d changed: %s", i+1, got[i+1])
		}
	}
}

// prove_goal refuses the origin fact and inferred facts as evidence.
func TestWeakGoalEvidence(t *testing.T) {
	cases := []struct {
		node *db.Node
		weak bool
	}{
		{&db.Node{Kind: db.KindFact, State: "origin", Payload: []byte(`{}`)}, true},
		{&db.Node{Kind: db.KindFact, State: "done", Payload: []byte(`{"confidence":"Inferred"}`)}, true},
		{&db.Node{Kind: db.KindFact, State: "done", Payload: []byte(`{"confidence":"observed"}`)}, false},
		{&db.Node{Kind: db.KindFinding, State: "done", Payload: []byte(`{"confidence":"inferred"}`)}, false},
	}
	for i, c := range cases {
		if got := weakGoalEvidence(c.node) != ""; got != c.weak {
			t.Errorf("case %d: weak=%v, want %v", i, got, c.weak)
		}
	}
}
