package agent

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// Models retype long tokens badly: a 520-character JWT copied into a script with
// one wrong character is rejected as "Invalid authentication token", and the
// worker then reads that as an expired session and stops to ask the operator.
// credentialEnv exposes each stored token to Bash as an environment variable so
// scripts say $ARTEX_TOKEN_<USER> instead of carrying a copy.

var jwtShape = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

// credEnvName turns "trungnd66@vingroup.net" into "TRUNGND66_VINGROUP_NET".
func credEnvName(user string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(user) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if b.Len() > 0 && !strings.HasSuffix(b.String(), "_") {
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

// credentialEnv returns KEY=VALUE pairs (and the key names) for every credential
// of the task whose password or auth value is a JWT. The first such token is also
// exported as ARTEX_TOKEN.
func credentialEnv(ts *db.ExplorationStore, taskID int64) (env, names []string) {
	if ts == nil || taskID <= 0 {
		return nil, nil
	}
	creds, err := ts.TaskCredentials(taskID)
	if err != nil {
		return nil, nil
	}
	for _, c := range creds {
		tok := strings.TrimSpace(c.Password)
		if !jwtShape.MatchString(tok) {
			tok = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(c.Auth), "Authorization:"), "authorization:"))
			tok = strings.TrimSpace(strings.TrimPrefix(tok, "Bearer "))
			if !jwtShape.MatchString(tok) {
				continue
			}
		}
		key := "ARTEX_TOKEN_" + credEnvName(c.Username)
		env = append(env, key+"="+tok)
		names = append(names, key)
		if len(env) == 1 {
			env = append(env, "ARTEX_TOKEN="+tok)
			names = append([]string{"ARTEX_TOKEN"}, names...)
		}
	}
	return env, names
}

// credEnvNote tells the worker which variables exist.
func credEnvNote(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return fmt.Sprintf("\n\n[Credential tokens in your shell environment]: %s. Use them in scripts as \"authorization: Bearer $ARTEX_TOKEN\" (inline, in double quotes). NEVER retype or paste a token into a command or file: a single wrong character makes the gateway answer 401 \"Invalid authentication token\", which is a copy error, not an expired session. Do not ask the operator for a token while these variables are set.", strings.Join(names, ", "))
}
