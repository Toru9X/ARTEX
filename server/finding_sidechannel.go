package server

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// Blind and client-side bugs never put their proof in the target's response:
// blind SSRF/XXE/RCE/injection prove themselves with an out-of-band callback,
// XSS with script running in a real browser. The S1 rule (data quoted from a
// bound response, L3+) can never verify them, so they used to end up as
// hardening notes. sideChannelProof is the second way to verified for them:
//
//   - a unique token (>= 12 chars) appears in a bound proof/verification
//     REQUEST, so the payload demonstrably went to the target, and
//   - the same token appears in an evidence file under the task's own data
//     directory: the interactsh-client log for oob_callback, the browser
//     console/dialog log for browser_execution.
//
// The token ties the callback or the execution to that exact request, so a
// stale or unrelated callback cannot verify a finding.
type sideChannelProof struct {
	Kind  string `json:"kind"`  // oob_callback | browser_execution
	Token string `json:"token"` // unique marker carried by the payload
	File  string `json:"file"`  // evidence file inside the task's data directory
}

const (
	sideChannelMinToken = 12
	sideChannelReadCap  = 4 << 20
	sideChannelMinPOE   = 2 // the payload reached a sink; the callback/execution is the proof
)

func (s *Server) assessSideChannel(ctx context.Context, findingID int64, poe int, p *sideChannelProof) (status, note string) {
	if p.Kind != "oob_callback" && p.Kind != "browser_execution" {
		return db.VerificationUnverified, "side_channel.kind must be oob_callback or browser_execution"
	}
	tok := strings.TrimSpace(p.Token)
	if len(tok) < sideChannelMinToken {
		return db.VerificationUnverified, fmt.Sprintf("side_channel.token must be a unique marker of at least %d characters", sideChannelMinToken)
	}
	if poe < sideChannelMinPOE {
		return db.VerificationUnverified, fmt.Sprintf("POE L%d below L%d for a side-channel proof", poe, sideChannelMinPOE)
	}
	f, err := s.m.pg.GetFinding(findingID)
	if err != nil || f == nil || f.TaskID == nil {
		return db.VerificationNotAssessed, "finding has no task, so no evidence directory"
	}
	root := filepath.Join(s.m.dir, "tasks", strconv.FormatInt(*f.TaskID, 10))
	path, err := insideDir(root, p.File)
	if err != nil {
		return db.VerificationUnverified, "side_channel.file: " + err.Error()
	}
	if found, err := fileContains(path, tok); err != nil {
		return db.VerificationNotAssessed, "side_channel.file unreadable: " + err.Error()
	} else if !found {
		return db.VerificationUnverified, "side_channel.token not found in the evidence file"
	}
	tr, err := s.m.pg.GetFindingTraffic(ctx, findingID)
	if err != nil {
		return db.VerificationNotAssessed, "binding read error: " + err.Error()
	}
	store := s.evidenceStore()
	for _, b := range tr.Bindings {
		if b.Role != "proof" && b.Role != "verification" {
			continue
		}
		if strings.Contains(b.Snapshot.URL, tok) || strings.Contains(b.Snapshot.ReqHead, tok) {
			return db.VerificationVerified, "side-channel proof: " + p.Kind
		}
		if fh, _, err := store.OpenBody(b.Snapshot, "request"); err == nil {
			body, _ := io.ReadAll(io.LimitReader(fh, sideChannelReadCap))
			fh.Close()
			if strings.Contains(string(body), tok) {
				return db.VerificationVerified, "side-channel proof: " + p.Kind
			}
		}
	}
	return db.VerificationUnverified, "side_channel.token not found in any bound proof/verification request"
}

// insideDir resolves file (absolute, or relative to root) and refuses anything
// outside root, symlinks included.
func insideDir(root, file string) (string, error) {
	file = strings.TrimSpace(file)
	if file == "" {
		return "", fmt.Errorf("required")
	}
	if !filepath.IsAbs(file) {
		file = filepath.Join(root, file)
	}
	real, err := filepath.EvalSymlinks(file)
	if err != nil {
		return "", err
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(realRoot, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("must be inside this task's data directory %s", root)
	}
	return real, nil
}

func fileContains(path, tok string) (bool, error) {
	fh, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, sideChannelReadCap))
	if err != nil {
		return false, err
	}
	return strings.Contains(string(b), tok), nil
}
