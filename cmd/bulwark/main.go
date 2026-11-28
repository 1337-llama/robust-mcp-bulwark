// Command bulwark is the MCP Bulwark gateway CLI (DESIGN.md §6.1).
//
// Exit codes: 0 success; 1 error; 2 usage; 3 check failed; for wrap, the
// upstream's exit code, or 70 if Bulwark itself failed.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/1337-llama/robust-mcp-bulwark/internal/audit"
	"github.com/1337-llama/robust-mcp-bulwark/internal/config"
	"github.com/1337-llama/robust-mcp-bulwark/internal/mcprev"
	"github.com/1337-llama/robust-mcp-bulwark/internal/pipeline"
	"github.com/1337-llama/robust-mcp-bulwark/internal/proxy"
	"github.com/1337-llama/robust-mcp-bulwark/internal/state"
	"github.com/1337-llama/robust-mcp-bulwark/internal/termsafe"
)

var version = "dev" // set with -ldflags at release

var validID = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

const usage = `usage:
  bulwark wrap    [--server-id ID] [--mode learn|warn|enforce] [--config FILE] [--state-dir DIR] -- <command> [args...]
  bulwark audit   verify  [--server-id ID | FILE...]
  bulwark audit   tail    [--server-id ID] [--event TYPE] [--follow] [--json]
  bulwark version
`

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch {
	case args[0] == "wrap":
		return wrap(args[1:], stdin, stdout, stderr)
	case args[0] == "audit" && len(args) > 1 && args[1] == "verify":
		return verify(args[2:], stdout, stderr)
	case args[0] == "audit" && len(args) > 1 && args[1] == "tail":
		return tail(args[2:], stdout, stderr)
	case args[0] == "version":
		fmt.Fprintln(stdout, "bulwark", version)
		return 0
	case args[0] == "-h" || args[0] == "--help" || args[0] == "help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprint(stderr, usage)
	return 2
}

func defaultStateDir() string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "bulwark")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "bulwark")
}

func defaultConfig() string {
	if p := os.Getenv("BULWARK_CONFIG"); p != "" {
		return p
	}
	d := os.Getenv("XDG_CONFIG_HOME")
	if d == "" {
		home, _ := os.UserHomeDir()
		d = filepath.Join(home, ".config")
	}
	return filepath.Join(d, "bulwark", "config.yaml")
}

func wrap(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("wrap", flag.ContinueOnError)
	fs.SetOutput(stderr)
	serverID := fs.String("server-id", "", "server identifier (required in enforce mode)")
	mode := fs.String("mode", "", "learn | warn | enforce (default warn)")
	cfgPath := fs.String("config", defaultConfig(), "configuration file")
	stateDir := fs.String("state-dir", defaultStateDir(), "state directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	argv := fs.Args()
	if len(argv) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	fail := func(f string, a ...any) int { fmt.Fprintf(stderr, "bulwark: "+f+"\n", a...); return 1 }

	cfg, cfgErr := config.Load(*cfgPath)
	effective := *mode
	if effective == "" && cfg != nil && *serverID != "" {
		effective = cfg.Servers[*serverID].Mode
	}
	if effective == "" {
		effective = "warn"
	}
	if !contains(config.Modes, effective) {
		fmt.Fprintf(stderr, "bulwark: unknown mode %q\n", effective)
		return 2
	}
	if cfgErr != nil {
		// AC-28. Without --mode the intended mode can't be known from a broken
		// file (it may say enforce), so fail closed too.
		if effective == "enforce" || *mode == "" {
			return fail("%v", cfgErr)
		}
		fmt.Fprintf(stderr, "bulwark: warning: %v (using defaults)\n", cfgErr)
		cfg = config.Default()
	}
	warnings, err := state.Prepare(*stateDir, effective)
	for _, w := range warnings {
		fmt.Fprintln(stderr, "bulwark: warning:", w)
	}
	if err != nil {
		return fail("%v", err)
	}
	digest, err := state.CommandDigest(argv)
	if err != nil {
		return fail("%v", err)
	}
	if *serverID != "" && !validID.MatchString(*serverID) { // it becomes a path and a glob
		return fail("--server-id must match %s", validID)
	}
	id, err := state.ServerID(*serverID, effective, digest)
	if err != nil {
		return fail("%v", err)
	}
	cfgDigest := "none"
	if b, err := os.ReadFile(*cfgPath); err == nil {
		sum := sha256.Sum256(b)
		cfgDigest = "sha256:" + hex.EncodeToString(sum[:])
	}
	if *serverID == "" {
		fmt.Fprintln(stderr, "bulwark: server id", id)
	}
	aw, err := audit.Open(filepath.Join(*stateDir, "audit", id), filepath.Join(*stateDir, "audit.key"), time.Now)
	if err != nil {
		return fail("%v", err)
	}
	defer aw.Close()
	conn := &mcprev.Conn{}
	chain := pipeline.Chain{
		pipeline.Revision{Conn: conn},
		&pipeline.RateLimit{PerSecond: cfg.Limits.NotificationsPerSecond, Now: time.Now},
	}
	code, err := proxy.Run(context.Background(), proxy.Options{
		Mode: effective, ServerID: id, MaxMessage: cfg.Limits.MaxMessageBytes, MaxDepth: cfg.Limits.MaxDepth,
		MaxOutstanding: cfg.Limits.MaxOutstandingRequests, Chain: chain, Conn: conn, Audit: aw,
		Digest: digest, ConfigDigest: cfgDigest, Version: version,
	}, argv, stdin, stdout, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "bulwark:", err)
		aw.Write(audit.Record{Event: "stop", ServerID: id, Reason: "internal_error"})
		return 70
	}
	return code
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func auditFiles(stateDir, serverID string) []string {
	pattern := filepath.Join(stateDir, "audit", "*", "*.jsonl")
	if serverID != "" {
		pattern = filepath.Join(stateDir, "audit", serverID, "*.jsonl")
	}
	files, _ := filepath.Glob(pattern)
	sort.Strings(files)
	return files
}

func verify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	serverID := fs.String("server-id", "", "verify this server's logs")
	stateDir := fs.String("state-dir", defaultStateDir(), "state directory")
	if fs.Parse(args) != nil {
		return 2
	}
	files := fs.Args()
	if len(files) == 0 {
		files = auditFiles(*stateDir, *serverID)
	}
	if len(files) == 0 {
		fmt.Fprintln(stderr, "bulwark: no audit files found")
		return 1
	}
	code := 0
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			fmt.Fprintln(stderr, "bulwark:", err)
			return 1
		}
		n, err := audit.Verify(fh)
		fh.Close()
		if err != nil {
			fmt.Fprintf(stdout, "BROKEN %s: %s\n", termsafe.String(f), termsafe.String(err.Error()))
			code = 3
			continue
		}
		fmt.Fprintf(stdout, "OK %s (%d records)\n", termsafe.String(f), n)
	}
	fmt.Fprintln(stdout, audit.Limit)
	return code
}

func tail(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tail", flag.ContinueOnError)
	fs.SetOutput(stderr)
	serverID := fs.String("server-id", "", "only this server")
	event := fs.String("event", "", "only this event type")
	follow := fs.Bool("follow", false, "keep printing new records")
	asJSON := fs.Bool("json", false, "print records as JSON lines")
	stateDir := fs.String("state-dir", defaultStateDir(), "state directory")
	if fs.Parse(args) != nil {
		return 2
	}
	files := auditFiles(*stateDir, *serverID)
	if len(files) == 0 {
		fmt.Fprintln(stderr, "bulwark: no audit files found")
		return 1
	}
	print := func(line []byte) {
		var r audit.Record
		if json.Unmarshal(line, &r) != nil || (*event != "" && r.Event != *event) {
			return
		}
		if *asJSON {
			fmt.Fprintln(stdout, termsafe.String(string(line)))
			return
		}
		// Every field may carry server-controlled text: all of it goes through termsafe (AC-23).
		fmt.Fprintln(stdout, termsafe.String(fmt.Sprintf("%s %-4d %-18s %-14s %-3s %-22s %-8s %s",
			r.TS, r.Seq, r.Event, r.ServerID, r.Direction, r.Method, r.Decision, strings.Join(r.Controls, ","))))
	}
	for i, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			fmt.Fprintln(stderr, "bulwark:", err)
			return 1
		}
		br := bufio.NewReader(fh)
		for {
			line, err := br.ReadBytes('\n')
			if len(line) > 0 && line[len(line)-1] == '\n' {
				print(line[:len(line)-1])
			} else if err == io.EOF && *follow && i == len(files)-1 {
				time.Sleep(200 * time.Millisecond) // shortcut: polling, upgrade to fsnotify if it matters
				br = bufio.NewReader(io.MultiReader(strings.NewReader(string(line)), fh))
				continue
			}
			if err != nil {
				break
			}
		}
		fh.Close()
	}
	return 0
}
