package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// On Windows norma runs the Bash tool through PowerShell 5.1, while every model
// writes bash: run transcripts showed ~43% of all tool errors were PowerShell
// parse errors and missing Unix commands. hostBashTool keeps norma's execution
// path (task manager, background runs, tree kill on timeout) but turns each
// command into a script that Git for Windows bash runs. Network, VPN routes,
// the recording proxy and file paths stay those of the host.
//
// ARTEX_BASH overrides the bash.exe path; ARTEX_BASH=off keeps PowerShell.

var (
	hostBashOnce sync.Once
	hostBashPath string
	hostBashDir  string
	hostBashRuns atomic.Int64
)

// gitBash returns the Git for Windows bash.exe to run commands with, or "" when
// not on Windows, disabled, or not found. The WSL launcher in System32 is never
// used: it would run in another network namespace with other paths.
func gitBash() string {
	hostBashOnce.Do(func() {
		if runtime.GOOS != "windows" {
			return
		}
		env := strings.TrimSpace(os.Getenv("ARTEX_BASH"))
		if strings.EqualFold(env, "off") {
			return
		}
		cands := []string{env}
		if git, err := exec.LookPath("git"); err == nil {
			root := filepath.Dir(filepath.Dir(git)) // <Git>\cmd\git.exe → <Git>
			cands = append(cands, filepath.Join(root, "bin", "bash.exe"))
		}
		for _, base := range []string{os.Getenv("ProgramFiles"), filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs")} {
			if base != "" {
				cands = append(cands, filepath.Join(base, "Git", "bin", "bash.exe"))
			}
		}
		for _, c := range cands {
			if c == "" || strings.Contains(strings.ToLower(c), `\system32\`) {
				continue
			}
			if st, err := os.Stat(c); err == nil && !st.IsDir() {
				hostBashPath = c
				break
			}
		}
		if hostBashPath == "" {
			return
		}
		hostBashDir = filepath.Join(os.TempDir(), "artex-bash")
		_ = os.MkdirAll(hostBashDir, 0o700)
		pruneHostBashScripts()
	})
	return hostBashPath
}

// hostBashPreamble runs before every command: UTF-8 everywhere, no MSYS path
// mangling of arguments (a payload like path=/etc/passwd must reach python or
// curl untouched), python3/pip3 mapped to the real Python instead of the
// Microsoft Store stub, and the wordlist location exported.
func hostBashPreamble() string {
	b := `export LANG=C.UTF-8 PYTHONIOENCODING=utf-8 PYTHONUTF8=1 MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
case "$(command -v python3 2>/dev/null)" in ""|*WindowsApps*) if command -v python >/dev/null 2>&1; then python3() { python "$@"; }; pip3() { python -m pip "$@"; }; export -f python3 pip3; fi;; esac
`
	if wl := wordlistDir(); wl != "" {
		b += "export ARTEX_WORDLISTS='" + filepath.ToSlash(wl) + "'\n"
	}
	return b
}

// hostBashTool wraps norma's Bash tool. The model-facing input, permission
// checks and intercept hooks all see the original command; only execution is
// redirected.
type hostBashTool struct {
	actool.CoreTool
	bash string
}

func (h hostBashTool) Description() string {
	return "Executes a command with bash (Git for Windows bash on this Windows host) in the working directory and returns combined stdout and stderr. " +
		"GNU tools are available (grep, sed, awk, find, head, tail, xargs, curl, openssl, base64) and Windows programs on PATH run by name (python, node, nmap, and the recon tools listed in the system prompt). " +
		"Automatic POSIX path conversion is off: pass file paths to Windows programs as C:/... . python3 and pip3 map to the installed Python. " +
		strings.TrimPrefix(h.CoreTool.Description(), "Executes a shell command in the working directory and returns combined stdout and stderr. ")
}

func (h hostBashTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	var m map[string]any
	if json.Unmarshal(in, &m) != nil {
		return h.CoreTool.Call(ctx, in, tc)
	}
	cmd, _ := m["command"].(string)
	if strings.TrimSpace(cmd) == "" {
		return h.CoreTool.Call(ctx, in, tc)
	}
	script, err := writeHostBashScript(cmd)
	if err != nil {
		return actool.Errorf("Error: could not stage the bash script: " + err.Error()), nil
	}
	m["command"] = "& " + psQuote(h.bash) + " --noprofile --norc " + psQuote(script) + "; exit $LASTEXITCODE"
	out, _ := json.Marshal(m)
	return h.CoreTool.Call(ctx, out, tc)
}

func writeHostBashScript(cmd string) (string, error) {
	if hostBashRuns.Add(1)%500 == 0 {
		go pruneHostBashScripts()
	}
	var id [8]byte
	_, _ = rand.Read(id[:])
	p := filepath.Join(hostBashDir, hex.EncodeToString(id[:])+".sh")
	return p, os.WriteFile(p, []byte(hostBashPreamble()+cmd+"\n"), 0o600)
}

// pruneHostBashScripts drops staged scripts older than a day. A background
// command may still be running its script, so recent files stay.
// ponytail: age-based sweep; delete-on-exit needs a hook into norma's task manager.
func pruneHostBashScripts() {
	ents, err := os.ReadDir(hostBashDir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, e := range ents {
		if info, err := e.Info(); err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(hostBashDir, e.Name()))
		}
	}
}

// psQuote single-quotes s for PowerShell.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// withHostBash swaps the Bash tool for the Git Bash wrapper when one is
// available; otherwise returns tools unchanged.
func withHostBash(tools []actool.CoreTool) []actool.CoreTool {
	bash := gitBash()
	if bash == "" {
		return tools
	}
	out := make([]actool.CoreTool, len(tools))
	for i, t := range tools {
		if t.Name() == "Bash" {
			t = hostBashTool{CoreTool: t, bash: bash}
		}
		out[i] = t
	}
	return out
}

// DefaultTools is norma's default tool set with the host-appropriate Bash.
func DefaultTools() []actool.CoreTool { return withHostBash(actool.DefaultTools()) }

// HostBash wraps a single Bash tool the same way (custom tools build their own).
func HostBash(t actool.CoreTool) actool.CoreTool { return withHostBash([]actool.CoreTool{t})[0] }

// hostToolNames are the recon/exploitation CLIs worth telling an agent about
// when they are installed. Run transcripts showed workers hand-writing scripts
// for everything because nothing said these existed.
var hostToolNames = []string{
	"nuclei", "httpx", "subfinder", "dnsx", "naabu", "katana", "hakrawler", "gau", "waybackurls",
	"ffuf", "feroxbuster", "gobuster", "kr", "arjun", "sqlmap", "dalfox", "kxss", "crlfuzz",
	"interactsh-client", "nmap", "jq", "gf", "gowitness", "grpcurl", "playwright-cli", "bbot",
}

var (
	hostToolsOnce  sync.Once
	hostToolsBlock string
	wordlistOnce   sync.Once
	wordlistPath   string
)

// wordlistDir finds a SecLists checkout: ARTEX_WORDLISTS, then common install
// locations. "" when none exists.
func wordlistDir() string {
	wordlistOnce.Do(func() {
		home, _ := os.UserHomeDir()
		for _, c := range []string{
			os.Getenv("ARTEX_WORDLISTS"),
			"/usr/share/seclists", "/usr/share/wordlists/seclists", "/opt/SecLists",
			filepath.Join(home, "SecLists"), filepath.Join(home, "SecTools", "SecLists"),
		} {
			if c == "" {
				continue
			}
			if st, err := os.Stat(filepath.Join(c, "Discovery")); err == nil && st.IsDir() {
				wordlistPath = c
				return
			}
		}
	})
	return wordlistPath
}

// HostToolsBlock is a code-owned system-prompt section naming the shell and the
// installed tools, so agents reach for them instead of hand-rolling scripts.
// Detected once per process.
func HostToolsBlock() string {
	hostToolsOnce.Do(func() {
		var found []string
		for _, n := range hostToolNames {
			if _, err := exec.LookPath(n); err == nil {
				found = append(found, n)
			}
		}
		shell := "bash"
		if gitBash() != "" {
			shell = "bash (Git for Windows on a Windows host; pass file paths to Windows programs as C:/...)"
		} else if runtime.GOOS == "windows" {
			shell = "Windows PowerShell 5.1 (not bash: no grep/head/&&; use Select-String, Select-Object, ;)"
		}
		b := "\n\n[Execution environment]\n- The Bash tool runs " + shell + ".\n"
		if len(found) > 0 {
			b += "- Installed tools (prefer them over hand-written scripts for scanning, fuzzing and crawling; route them through the recording proxy in $HTTP_PROXY when they do not read it themselves): " + strings.Join(found, ", ") + ".\n"
		}
		if wl := wordlistDir(); wl != "" {
			b += "- Wordlists (SecLists): $ARTEX_WORDLISTS = " + filepath.ToSlash(wl) + ".\n"
		}
		b += "- A missing tool is not a blocker: use an installed equivalent or install it into your work dir.\n"
		b += "- Some skills name tools from other installs that do not exist here: for oob_new/oob_check or a Burp Collaborator MCP use interactsh-client; for verify_dom_xss use playwright-cli or the browser MCP; mail_alias_new/mail_wait/mail_read are unavailable (use the task credentials, or ask_operator for an inbox code).\n"
		hostToolsBlock = b
	})
	return hostToolsBlock
}
