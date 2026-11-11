package db

import (
	"errors"
	"strings"
	"time"
)

// TaskCredential is a per-task test account (#3): either declared by the user at
// task creation (source=user, e.g. a program-provided alias account) or registered
// by the agent itself and recorded so it is not forgotten (source=agent).
//
// Passwords are stored in the local Postgres, plaintext — the same trust domain as
// captured traffic evidence, which already contains credentials by nature. The UI
// masks them by default; anything injected into agent context transits to the LLM
// provider, so only dedicated test accounts belong here.
type TaskCredential struct {
	ID        int64     `json:"id"`
	TaskID    int64     `json:"task_id"`
	Domain    string    `json:"domain"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Source    string    `json:"source"` // "user" | "agent"
	Note      string    `json:"note,omitempty"`
	Role      string    `json:"role,omitempty"`   // e.g. admin, user, viewer
	Tenant    string    `json:"tenant,omitempty"` // org / tenant the account belongs to
	Auth      string    `json:"auth,omitempty"`   // headers of its current logged-in session, one per line
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// credCols / scan keep the column list and the scan targets in one place.
const credCols = `id, task_id, domain, username, password, source, note, role, tenant, auth, created_at, updated_at`

func (c *TaskCredential) scan(r interface{ Scan(...any) error }) error {
	return r.Scan(&c.ID, &c.TaskID, &c.Domain, &c.Username, &c.Password, &c.Source, &c.Note, &c.Role, &c.Tenant, &c.Auth, &c.CreatedAt, &c.UpdatedAt)
}

// TaskCredentialInput validates and normalizes one upsert. Empty username or
// domain is rejected; an empty password is allowed only for source=user (the
// "agent generates and records it later" mode from #3).
type TaskCredentialInput struct {
	Domain   string
	Username string
	Password string
	Source   string
	Note     string
	Role     string
	Tenant   string
	Auth     string
}

var ErrTaskCredentialInvalid = errors.New("credential domain and username are required")

func (in TaskCredentialInput) normalize() (TaskCredentialInput, error) {
	in.Domain = strings.TrimSpace(in.Domain)
	in.Username = strings.TrimSpace(in.Username)
	in.Password = strings.TrimSpace(in.Password)
	in.Note = strings.TrimSpace(in.Note)
	in.Role = strings.TrimSpace(in.Role)
	in.Tenant = strings.TrimSpace(in.Tenant)
	in.Auth = strings.TrimSpace(in.Auth)
	if in.Source != "agent" {
		in.Source = "user"
	}
	if in.Domain == "" || in.Username == "" {
		return in, ErrTaskCredentialInvalid
	}
	if in.Password == "" && in.Source == "agent" {
		return in, errors.New("agent-recorded credentials need the password that was set")
	}
	return in, nil
}

// UpsertTaskCredential inserts or updates the (task, domain, username) entry: an
// agent re-registering the same account overwrites the password in place instead
// of piling up a second row.
func (d *DB) UpsertTaskCredential(taskID int64, in TaskCredentialInput) (TaskCredential, error) {
	in, err := in.normalize()
	if err != nil {
		return TaskCredential{}, err
	}
	var c TaskCredential
	row := d.QueryRow(`
		INSERT INTO task_credentials (task_id, domain, username, password, source, note, role, tenant, auth)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (task_id, domain, username) DO UPDATE
		SET password = EXCLUDED.password,
		    source   = EXCLUDED.source,
		    note     = CASE WHEN EXCLUDED.note = '' THEN task_credentials.note ELSE EXCLUDED.note END,
		    role     = CASE WHEN EXCLUDED.role = '' THEN task_credentials.role ELSE EXCLUDED.role END,
		    tenant   = CASE WHEN EXCLUDED.tenant = '' THEN task_credentials.tenant ELSE EXCLUDED.tenant END,
		    auth     = CASE WHEN EXCLUDED.auth = '' THEN task_credentials.auth ELSE EXCLUDED.auth END,
		    updated_at = now()
		RETURNING `+credCols,
		taskID, in.Domain, in.Username, in.Password, in.Source, in.Note, in.Role, in.Tenant, in.Auth)
	err = c.scan(row)
	return c, err
}

// TaskCredentials lists a task's credentials, oldest first (the user-declared
// ones keep their position ahead of agent-discovered ones).
func (d *DB) TaskCredentials(taskID int64) ([]TaskCredential, error) {
	rows, err := d.Query(`
		SELECT `+credCols+`
		FROM task_credentials WHERE task_id = $1 ORDER BY id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TaskCredential
	for rows.Next() {
		var c TaskCredential
		if err := c.scan(rows); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteTaskCredential removes one entry; taskID scopes the delete so a stale
// request cannot cross tasks.
func (d *DB) DeleteTaskCredential(taskID, id int64) error {
	tag, err := d.Exec(`DELETE FROM task_credentials WHERE id = $1 AND task_id = $2`, id, taskID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return errors.New("credential not found")
	}
	return nil
}

// Thin wrappers on ExplorationStore: the ToolSet already holds the task's
// exploration store, so credential tools need no extra wiring.

func (s *ExplorationStore) UpsertTaskCredential(taskID int64, in TaskCredentialInput) (TaskCredential, error) {
	return s.db.UpsertTaskCredential(taskID, in)
}

func (s *ExplorationStore) TaskCredentials(taskID int64) ([]TaskCredential, error) {
	return s.db.TaskCredentials(taskID)
}
