//go:build !windows

package proxy

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// ownGroup starts the child in its own process group, so signals reach
// grandchildren started by npx, uvx or docker (AC-4).
func ownGroup(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

func signalGroup(c *exec.Cmd, sig os.Signal) {
	if c.Process != nil {
		syscall.Kill(-c.Process.Pid, sig.(syscall.Signal))
	}
}

var termSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM}

// ignoreSIGPIPE keeps a crashed client from killing the gateway on its next
// write; the write error is handled as "client gone" instead.
func ignoreSIGPIPE() { signal.Ignore(syscall.SIGPIPE) }

// exitCode maps a wait error to the child's exit code; a signal-killed child
// gives 128 + signal, as shells report it.
func exitCode(err error) int {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return 0
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ee.ExitCode()
}

const sigTerm, sigKill = syscall.SIGTERM, syscall.SIGKILL
