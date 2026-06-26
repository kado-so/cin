//go:build windows

package cli

import (
	"os"
	"os/exec"
)

func handledSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}

func signalSelf(os.Signal) {
	os.Exit(130)
}

func signalProcess(process *os.Process, _ os.Signal) error {
	return process.Kill()
}

func processExitCode(err *exec.ExitError) int {
	return err.ExitCode()
}
