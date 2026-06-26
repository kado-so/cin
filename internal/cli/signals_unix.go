//go:build !windows

package cli

import (
	"os"
	"os/exec"
	"syscall"
)

func handledSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func signalSelf(sig os.Signal) {
	if unixSig, ok := sig.(syscall.Signal); ok {
		_ = syscall.Kill(syscall.Getpid(), unixSig)
		return
	}
	os.Exit(1)
}

func signalProcess(process *os.Process, sig os.Signal) error {
	return process.Signal(sig)
}

func processExitCode(err *exec.ExitError) int {
	if status, ok := err.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return err.ExitCode()
}
