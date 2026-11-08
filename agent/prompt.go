package agent

import (
	"bytes"
	"text/template"
	"time"
)

// PromptOverride, if set, returns the stored system-prompt template for an agent
// key and whether one exists. The server wires it to the PG agent_prompts table.
// When nil or no override exists, agents use their built-in default prompt — so
// behavior is identical until a user edits a prompt in the UI.
var PromptOverride func(agentKey string) (string, bool)

// OpsecEnabled is wired by the server to the persisted global setting. Keeping
// the block here makes it a code-owned runtime tail: database-edited prompts
// cannot accidentally remove the operational safety guidance. A nil hook means
// off, so an unconfigured server renders exactly the prompts it did before.
var OpsecEnabled func() bool

const opsecPromptBlock = `**OPSEC rules (hard constraints, second only to the authorized scope and the task's operation constraints)**

- Reuse existing traffic, browser sessions and already-verified evidence first; when traffic_search/traffic_get or the browser can answer it, do not issue a duplicate direct request.
- Every interaction with the target must go through the platform's configured recording proxy or the browser tools, so the request stays traceable.
- Do not reach the target directly with the default headers of bare curl, urllib, requests and the like. A command-line request must reuse the User-Agent, Accept, Referer and Cookie characteristics found in the target's existing traffic as far as possible; never fabricate an identity, device or browser fingerprint without a real basis.
- Do not bypass certificate validation with -k, --ignore-https-errors, verify=False or similar; when the platform proxy CA is configured, validation must pass normally.
- Do not randomly rotate User-Agents, run bulk concurrency, tight loops, unbounded retries, port sweeps, directory brute force or large-scale scanning; stop the current direction immediately on a rate limit, CAPTCHA, WAF or anomalous response.
- OPSEC does not widen the authorized scope; do not touch a target, host, port, path or account outside it.
- Leaving a trail of requests and responses is the platform proxy's and the browser's job; do not additionally copy full request headers, cookies or response bodies.`

// withOpsecTail appends the code-owned OPSEC tail when the toggle is on. Every
// renderSystem exit goes through it so no render path can skip the block.
func withOpsecTail(body string) string {
	if OpsecEnabled != nil && OpsecEnabled() {
		return body + "\n\n" + opsecPromptBlock
	}
	return body
}

// Prompt-variable structs — fields mirror each agent's catalog (docs §5a) so a
// user template referencing a catalog variable renders; referencing anything else
// fails template execution and falls back to the built-in default.
type PlannerVars struct{ Goal, Scope, AssetSummary, DataDir, Now string }
type WorkerVars struct{ ProxyAddr, WorkerName, DataDir, Now string }
type MainVars struct{ Goal, AssetSummary, FindingsSummary, DataDir, Now string }
type GoalsVars struct{ EngagementDescription, DataDir, Now string }

// nowStr is the server-local wall-clock string exposed as the universal {{.Now}}
// prompt variable. renderSystem runs on every agent turn/round, so this is fresh
// each run — a prompt can subtract it from a fixed start stamp to reason about
// elapsed time (e.g. a timed benchmark's "last N hours" window).
func nowStr() string { return time.Now().Format("2006-01-02 15:04:05 MST") }

// renderSystem returns the rendered system-prompt BODY (section [A]) for agentKey.
// Precedence: the DB-stored template (if any) over the built-in default template
// (def). BOTH are Go templates now — the built-in default is seeded into the DB
// verbatim, so the two paths render identically until a user edits the prompt.
// Rendering always runs (def used to be pre-substituted plain text; it is now a
// {{.Var}} template like the DB one). On any render error we fall back to the
// default template, then to the raw default string — an agent never starts with a
// half-rendered prompt. Callers append the code-owned tail (trafficTool /
// intermediate artifact output rules) AFTER this, so those can't be edited away via
// the DB body.
func renderSystem(agentKey, def string, vars any) string {
	tmpl := def
	if PromptOverride != nil {
		if t, ok := PromptOverride(agentKey); ok && t != "" {
			tmpl = t
		}
	}
	if out, err := renderTmpl(tmpl, vars); err == nil {
		return withOpsecTail(out)
	}
	// DB template broke (e.g. references an out-of-catalog var) → code default.
	if out, err := renderTmpl(def, vars); err == nil {
		return withOpsecTail(out)
	}
	return withOpsecTail(def)
}

func renderTmpl(tmpl string, vars any) (string, error) {
	t, err := template.New("p").Option("missingkey=error").Parse(tmpl)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, vars); err != nil {
		return "", err
	}
	return b.String(), nil
}
