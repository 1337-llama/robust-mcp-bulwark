//go:build windows

package proxy

import (
	"errors"
	"os"
	"os/exec"
)

// Windows has no process groups here; signal handling is best-effort (NFR-010).
func ownGroup(*exec.Cmd) {}

func signalGroup(c *exec.Cmd, _ os.Signal) {
	if c.Process != nil {
		c.Process.Kill()
	}
}

var termSignals = []os.Signal{os.Interrupt}

func ignoreSIGPIPE() {}

func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 0
}

var sigTerm, sigKill = os.Kill, os.Kill
