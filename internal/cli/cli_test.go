package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run(nil, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if stdout.Len() == 0 {
		t.Fatal("expected help output")
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"nope"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout, got %q", stdout.String())
	}
	if stderr.Len() == 0 {
		t.Fatal("expected stderr output")
	}
}

func TestNewRootCommandUsesCobraCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd := NewRootCommand(&stdout, &stderr)
	cmd.SetArgs([]string{"--version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to execute: %v", err)
	}
	if got := strings.TrimSpace(stdout.String()); got != version {
		t.Fatalf("expected version %q, got %q", version, got)
	}
}
