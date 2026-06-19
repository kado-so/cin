package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cin/internal/config"
	"cin/internal/envelope"
	"filippo.io/age"
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

func TestInitSetGetPhase1Flow(t *testing.T) {
	identity := testIdentity(t)
	t.Setenv("CIN_AGE_KEY", identity.String())

	path := filepath.Join(t.TempDir(), "configs.secret.yaml")
	runOK(t, []string{"-f", path, "init", "vaishnav"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "options.postgres.host", "postgres"})

	stdout, stderr, code := runCLI([]string{"-f", path, "get", "-e", "dev", "options.postgres.host"})
	if code != 0 {
		t.Fatalf("get redacted failed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if strings.Contains(stdout, " = postgres") {
		t.Fatalf("redacted get leaked plaintext: %q", stdout)
	}
	if got := strings.TrimSpace(stdout); got != "options.postgres.host = [secret]" {
		t.Fatalf("unexpected redacted output: %q", got)
	}

	stdout, stderr, code = runCLI([]string{"-f", path, "--user", "vaishnav", "get", "-e", "dev", "options.postgres.host", "--show"})
	if code != 0 {
		t.Fatalf("get --show failed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "options.postgres.host = postgres" {
		t.Fatalf("unexpected plaintext output: %q", got)
	}
}

func TestSetTemplateAndPreservesUnrelatedEncryptedValue(t *testing.T) {
	identity := testIdentity(t)
	t.Setenv("CIN_AGE_KEY", identity.String())

	path := filepath.Join(t.TempDir(), "configs.secret.yaml")
	runOK(t, []string{"-f", path, "init", "vaishnav"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "options.postgres.host", "postgres"})

	doc, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	hostEnvelope, ok := doc.GetScalar([]string{"envs", "dev", "options", "postgres", "host"})
	if !ok {
		t.Fatal("expected encrypted host value")
	}

	runOK(t, []string{
		"-f", path,
		"set", "-e", "dev", "-a", "api",
		"DATABASE_URL",
		"postgres://{{ .options.postgres.host }}/api",
	})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(data), hostEnvelope) {
		t.Fatal("unrelated encrypted option was not preserved byte-identical")
	}

	doc, err = config.Load(path)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	databaseURL, ok := doc.GetScalar([]string{"envs", "dev", "apps", "api", "values", "DATABASE_URL"})
	if !ok {
		t.Fatal("expected encrypted app value")
	}
	enc, err := envelope.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse app envelope: %v", err)
	}
	if enc.Kind != envelope.Template {
		t.Fatalf("expected template envelope, got %q", enc.Kind)
	}
}

func testIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return identity
}

func runOK(t *testing.T, args []string) string {
	t.Helper()
	stdout, stderr, code := runCLI(args)
	if code != 0 {
		t.Fatalf("command %v failed: code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
	}
	return stdout
}

func runCLI(args []string) (string, string, int) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(args, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}
