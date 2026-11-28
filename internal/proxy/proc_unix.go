//go:build !windows

package proxy

import (
	"os"
	"os/exec"
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

const sigTerm, sigKill = syscall.SIGTERM, syscall.SIGKILL
