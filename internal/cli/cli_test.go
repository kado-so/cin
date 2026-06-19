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

func TestGetAppliesLocalOverrideAtHighestPrecedence(t *testing.T) {
	identity := testIdentity(t)
	t.Setenv("CIN_AGE_KEY", identity.String())

	dir := t.TempDir()
	chdir(t, dir)

	runOK(t, []string{"init", "vaishnav"})
	runOK(t, []string{"set", "-e", "dev", "options.postgres.host", "shared"})

	runOK(t, []string{"-f", "configs.local.secret.yaml", "init", "intruder"})
	runOK(t, []string{"-f", "configs.local.secret.yaml", "set", "-e", "dev", "options.postgres.host", "local"})

	stdout, stderr, code := runCLI([]string{"--user", "vaishnav", "get", "-e", "dev", "options.postgres.host", "--show"})
	if code != 0 {
		t.Fatalf("get with default local failed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "options.postgres.host = local" {
		t.Fatalf("expected default local override, got %q", got)
	}

	stdout, stderr, code = runCLI([]string{"--no-local", "--user", "vaishnav", "get", "-e", "dev", "options.postgres.host", "--show"})
	if code != 0 {
		t.Fatalf("get with --no-local failed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "options.postgres.host = shared" {
		t.Fatalf("expected shared value with --no-local, got %q", got)
	}

	runOK(t, []string{"-f", "custom.local.secret.yaml", "init", "other"})
	runOK(t, []string{"-f", "custom.local.secret.yaml", "set", "-e", "dev", "options.postgres.host", "custom"})
	stdout, stderr, code = runCLI([]string{"--local-file", "custom.local.secret.yaml", "--user", "vaishnav", "get", "-e", "dev", "options.postgres.host", "--show"})
	if code != 0 {
		t.Fatalf("get with --local-file failed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "options.postgres.host = custom" {
		t.Fatalf("expected chosen local override, got %q", got)
	}
}

func TestGetShowRequiresExplicitCurrentUser(t *testing.T) {
	identity := testIdentity(t)
	t.Setenv("CIN_AGE_KEY", identity.String())
	t.Setenv("CIN_USER", "")

	path := filepath.Join(t.TempDir(), "configs.secret.yaml")
	runOK(t, []string{"-f", path, "init", "vaishnav"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "options.postgres.host", "postgres"})

	stdout, stderr, code := runCLI([]string{"-f", path, "--no-local", "get", "-e", "dev", "options.postgres.host", "--show"})
	if code != 2 {
		t.Fatalf("expected current user error exit, got code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "current user is required") || !strings.Contains(stderr, "pass --user <username> or set CIN_USER") {
		t.Fatalf("expected current user guidance, got %q", stderr)
	}
}

func TestRenderResolvesTemplateWithLocalOverride(t *testing.T) {
	identity := testIdentity(t)
	t.Setenv("CIN_AGE_KEY", identity.String())

	dir := t.TempDir()
	chdir(t, dir)

	runOK(t, []string{"init", "vaishnav"})
	runOK(t, []string{"set", "-e", "shared", "options.postgres.host", "shared"})
	runOK(t, []string{"set", "-e", "shared", "-a", "api", "DATABASE_URL", "postgres://{{ .options.postgres.host }}/api"})
	setExtends(t, "configs.secret.yaml", "dev", "shared")

	runOK(t, []string{"-f", "configs.local.secret.yaml", "init", "local"})
	runOK(t, []string{"-f", "configs.local.secret.yaml", "set", "-e", "dev", "options.postgres.host", "local"})

	stdout, stderr, code := runCLI([]string{"--user", "vaishnav", "render", "-e", "dev", "-a", "api"})
	if code != 0 {
		t.Fatalf("render redacted failed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "DATABASE_URL=[secret template resolved]" {
		t.Fatalf("unexpected redacted render: %q", got)
	}
	if strings.Contains(stdout, "local") || strings.Contains(stdout, "postgres://") {
		t.Fatalf("redacted render leaked plaintext: %q", stdout)
	}

	stdout, stderr, code = runCLI([]string{"--user", "vaishnav", "render", "-e", "dev", "-a", "api", "--show"})
	if code != 0 {
		t.Fatalf("render --show failed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "DATABASE_URL=postgres://local/api" {
		t.Fatalf("expected local override in parent template, got %q", got)
	}
}

func TestGetShowResolvesSelectedAppValuesAlias(t *testing.T) {
	identity := testIdentity(t)
	t.Setenv("CIN_AGE_KEY", identity.String())

	path := filepath.Join(t.TempDir(), "configs.secret.yaml")
	runOK(t, []string{"-f", path, "init", "vaishnav"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "api", "HOST", "example.test"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "api", "URL", "https://{{ .values.HOST }}/v1"})

	stdout, stderr, code := runCLI([]string{"-f", path, "--user", "vaishnav", "get", "-e", "dev", "-a", "api", "URL", "--show"})
	if code != 0 {
		t.Fatalf("get template failed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "URL = https://example.test/v1" {
		t.Fatalf("unexpected resolved get output: %q", got)
	}
}

func TestRenderIgnoresUnrelatedBrokenAppTemplate(t *testing.T) {
	identity := testIdentity(t)
	t.Setenv("CIN_AGE_KEY", identity.String())

	path := filepath.Join(t.TempDir(), "configs.secret.yaml")
	runOK(t, []string{"-f", path, "init", "vaishnav"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "api", "URL", "ok"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "worker", "BROKEN", "{{ .values.DOES_NOT_EXIST }}"})

	stdout, stderr, code := runCLI([]string{"-f", path, "--user", "vaishnav", "render", "-e", "dev", "-a", "api", "--show"})
	if code != 0 {
		t.Fatalf("render api failed due to unrelated app: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "URL=ok" {
		t.Fatalf("unexpected api render: %q", got)
	}
}

func TestRenderIgnoresUnrelatedUndecryptableAppValue(t *testing.T) {
	identity := testIdentity(t)
	t.Setenv("CIN_AGE_KEY", identity.String())

	path := filepath.Join(t.TempDir(), "configs.secret.yaml")
	runOK(t, []string{"-f", path, "init", "vaishnav"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "api", "URL", "ok"})
	setRawScalar(t, path, []string{"envs", "dev", "apps", "worker", "values", "SECRET"}, "ENC[age-v1;set=team;users=vaishnav;data=*]")

	stdout, stderr, code := runCLI([]string{"-f", path, "--user", "vaishnav", "render", "-e", "dev", "-a", "api", "--show"})
	if code != 0 {
		t.Fatalf("render api failed due to unrelated undecryptable app value: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "URL=ok" {
		t.Fatalf("unexpected api render: %q", got)
	}
}

func TestRenderFailsWhenReferencedCrossAppValueCannotDecrypt(t *testing.T) {
	identity := testIdentity(t)
	t.Setenv("CIN_AGE_KEY", identity.String())

	path := filepath.Join(t.TempDir(), "configs.secret.yaml")
	runOK(t, []string{"-f", path, "init", "vaishnav"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "api", "URL", "https://{{ .apps.worker.values.X }}"})
	setRawScalar(t, path, []string{"envs", "dev", "apps", "worker", "values", "X"}, "ENC[age-v1;set=team;users=vaishnav;data=Y2lwaGVy]")

	_, stderr, code := runCLI([]string{"-f", path, "--user", "vaishnav", "render", "-e", "dev", "-a", "api", "--show"})
	if code != 2 {
		t.Fatalf("expected referenced cross-app decrypt failure, got code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "cannot decrypt apps.worker.values.X with current identity") {
		t.Fatalf("expected cross-app decrypt error, got %q", stderr)
	}
}

func TestRenderValuesAliasUsesOwningWorkerApp(t *testing.T) {
	identity := testIdentity(t)
	t.Setenv("CIN_AGE_KEY", identity.String())

	path := filepath.Join(t.TempDir(), "configs.secret.yaml")
	runOK(t, []string{"-f", path, "init", "vaishnav"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "api", "HOST", "api.example"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "worker", "HOST", "worker.example"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "worker", "URL", "https://{{ .values.HOST }}"})

	stdout, stderr, code := runCLI([]string{"-f", path, "--user", "vaishnav", "render", "-e", "dev", "-a", "worker", "--show"})
	if code != 0 {
		t.Fatalf("render worker failed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "URL=https://worker.example") {
		t.Fatalf("expected worker alias to use worker HOST, got %q", stdout)
	}
	if strings.Contains(stdout, "URL=https://api.example") {
		t.Fatalf("worker alias used selected/api HOST incorrectly: %q", stdout)
	}
}

func TestRenderValuesAliasUsesSelectedAPIApp(t *testing.T) {
	identity := testIdentity(t)
	t.Setenv("CIN_AGE_KEY", identity.String())

	path := filepath.Join(t.TempDir(), "configs.secret.yaml")
	runOK(t, []string{"-f", path, "init", "vaishnav"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "api", "HOST", "api.example"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "worker", "HOST", "worker.example"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "api", "URL", "https://{{ .values.HOST }}"})

	stdout, stderr, code := runCLI([]string{"-f", path, "--user", "vaishnav", "render", "-e", "dev", "-a", "api", "--show"})
	if code != 0 {
		t.Fatalf("render api failed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "URL=https://api.example") {
		t.Fatalf("expected api alias to use api HOST, got %q", stdout)
	}
	if strings.Contains(stdout, "URL=https://worker.example") {
		t.Fatalf("api alias used worker HOST incorrectly: %q", stdout)
	}
}

func TestRenderErrorsOnMissingTemplateReference(t *testing.T) {
	identity := testIdentity(t)
	t.Setenv("CIN_AGE_KEY", identity.String())

	path := filepath.Join(t.TempDir(), "configs.secret.yaml")
	runOK(t, []string{"-f", path, "init", "vaishnav"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "api", "URL", "https://{{ .options.missing.host }}"})

	_, stderr, code := runCLI([]string{"-f", path, "--user", "vaishnav", "render", "-e", "dev", "-a", "api"})
	if code != 2 {
		t.Fatalf("expected missing reference failure, got code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "missing template reference: options.missing.host") {
		t.Fatalf("expected missing reference error, got %q", stderr)
	}
}

func TestRenderErrorsOnTemplateCycle(t *testing.T) {
	identity := testIdentity(t)
	t.Setenv("CIN_AGE_KEY", identity.String())

	path := filepath.Join(t.TempDir(), "configs.secret.yaml")
	runOK(t, []string{"-f", path, "init", "vaishnav"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "api", "API_URL", "{{ .values.BASE_URL }}"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "api", "BASE_URL", "{{ .values.API_URL }}"})

	_, stderr, code := runCLI([]string{"-f", path, "--user", "vaishnav", "render", "-e", "dev", "-a", "api"})
	if code != 2 {
		t.Fatalf("expected cycle failure, got code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "template cycle detected") || !strings.Contains(stderr, "values.API_URL") {
		t.Fatalf("expected cycle path, got %q", stderr)
	}
}

func TestRenderRejectsUnsupportedTemplateSyntax(t *testing.T) {
	identity := testIdentity(t)
	t.Setenv("CIN_AGE_KEY", identity.String())

	tests := map[string]string{
		"function": "{{ printf \"%s\" .values.HOST }}",
		"if":       "{{ if .values.HOST }}x{{ end }}",
		"range":    "{{ range .values.HOST }}x{{ end }}",
		"pipeline": "{{ .values.HOST | printf \"%s\" }}",
	}

	for name, template := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "configs.secret.yaml")
			runOK(t, []string{"-f", path, "init", "vaishnav"})
			runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "api", "HOST", "example.test"})
			runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "api", "URL", template})

			_, stderr, code := runCLI([]string{"-f", path, "--user", "vaishnav", "render", "-e", "dev", "-a", "api"})
			if code != 2 {
				t.Fatalf("expected unsupported syntax failure, got code=%d stderr=%q", code, stderr)
			}
			if !strings.Contains(stderr, "unsupported template syntax") {
				t.Fatalf("expected unsupported syntax error, got %q", stderr)
			}
		})
	}
}

func TestExplainRedactsResultAndShowsDependencies(t *testing.T) {
	identity := testIdentity(t)
	t.Setenv("CIN_AGE_KEY", identity.String())

	path := filepath.Join(t.TempDir(), "configs.secret.yaml")
	runOK(t, []string{"-f", path, "init", "vaishnav"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "options.postgres.host", "db.internal"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "api", "DATABASE_URL", "postgres://{{ .options.postgres.host }}/api"})

	stdout, stderr, code := runCLI([]string{"-f", path, "--user", "vaishnav", "explain", "-e", "dev", "-a", "api", "DATABASE_URL"})
	if code != 0 {
		t.Fatalf("explain failed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, want := range []string{
		"kind: encrypted template",
		"recipientSet: team",
		"references:",
		"options.postgres.host ok secret",
		"result: [secret]",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected explain output to contain %q, got %q", want, stdout)
		}
	}
	if strings.Contains(stdout, "db.internal") || strings.Contains(stdout, "postgres://") {
		t.Fatalf("explain leaked plaintext: %q", stdout)
	}
}

func TestRunInjectsSelectedAppValues(t *testing.T) {
	identity := testIdentity(t)
	t.Setenv("CIN_AGE_KEY", identity.String())
	t.Setenv("API_TOKEN", "preexisting")

	path := filepath.Join(t.TempDir(), "configs.secret.yaml")
	runOK(t, []string{"-f", path, "init", "vaishnav"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "api", "API_TOKEN", "from-cin"})

	stdout, stderr, code := runCLI([]string{"-f", path, "--user", "vaishnav", "run", "-e", "dev", "-a", "api", "--", "/bin/sh", "-c", "printf %s \"$API_TOKEN\""})
	if code != 0 {
		t.Fatalf("run failed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if stdout != "from-cin" {
		t.Fatalf("expected injected value to override process env, got %q", stdout)
	}
}

func TestRunRequiresApp(t *testing.T) {
	stdout, stderr, code := runCLI([]string{"run", "-e", "dev", "--", "/usr/bin/true"})
	if code != 2 {
		t.Fatalf("expected missing app failure, got code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "cin run requires -a <app>") {
		t.Fatalf("expected app guidance, got %q", stderr)
	}
}

func TestRunRequiresEnv(t *testing.T) {
	stdout, stderr, code := runCLI([]string{"run", "-a", "api", "--", "/usr/bin/true"})
	if code != 2 {
		t.Fatalf("expected missing env failure, got code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "environment is required") {
		t.Fatalf("expected env guidance, got %q", stderr)
	}
}

func TestRunPreservesChildExitCode(t *testing.T) {
	identity := testIdentity(t)
	t.Setenv("CIN_AGE_KEY", identity.String())

	path := filepath.Join(t.TempDir(), "configs.secret.yaml")
	runOK(t, []string{"-f", path, "init", "vaishnav"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "api", "API_TOKEN", "from-cin"})

	stdout, stderr, code := runCLI([]string{"-f", path, "--user", "vaishnav", "run", "-e", "dev", "-a", "api", "--", "/bin/sh", "-c", "exit 7"})
	if code != 7 {
		t.Fatalf("expected child exit code 7, got code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestRunAppliesLocalOverrideAndTemplateResolution(t *testing.T) {
	identity := testIdentity(t)
	t.Setenv("CIN_AGE_KEY", identity.String())

	dir := t.TempDir()
	chdir(t, dir)

	runOK(t, []string{"init", "vaishnav"})
	runOK(t, []string{"set", "-e", "shared", "options.postgres.host", "shared"})
	runOK(t, []string{"set", "-e", "shared", "-a", "api", "DATABASE_URL", "postgres://{{ .options.postgres.host }}/api"})
	setExtends(t, "configs.secret.yaml", "dev", "shared")

	runOK(t, []string{"-f", "configs.local.secret.yaml", "init", "local"})
	runOK(t, []string{"-f", "configs.local.secret.yaml", "set", "-e", "dev", "options.postgres.host", "local"})

	stdout, stderr, code := runCLI([]string{"--user", "vaishnav", "run", "-e", "dev", "-a", "api", "--", "/bin/sh", "-c", "printf %s \"$DATABASE_URL\""})
	if code != 0 {
		t.Fatalf("run failed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if stdout != "postgres://local/api" {
		t.Fatalf("expected resolved template with local override, got %q", stdout)
	}
}

func TestRunDoesNotPrintPlaintextFromCin(t *testing.T) {
	identity := testIdentity(t)
	t.Setenv("CIN_AGE_KEY", identity.String())

	path := filepath.Join(t.TempDir(), "configs.secret.yaml")
	runOK(t, []string{"-f", path, "init", "vaishnav"})
	runOK(t, []string{"-f", path, "set", "-e", "dev", "-a", "api", "SECRET_TOKEN", "do-not-print"})

	stdout, stderr, code := runCLI([]string{"-f", path, "--user", "vaishnav", "run", "-e", "dev", "-a", "api", "--", "/usr/bin/true"})
	if code != 0 {
		t.Fatalf("run failed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if strings.Contains(stdout, "do-not-print") || strings.Contains(stderr, "do-not-print") {
		t.Fatalf("cin output leaked plaintext: stdout=%q stderr=%q", stdout, stderr)
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

func chdir(t *testing.T, dir string) {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(cwd); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})
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

func setExtends(t *testing.T, path string, env string, parent string) {
	t.Helper()
	setRawScalar(t, path, []string{"envs", env, "extends"}, parent)
}

func setRawScalar(t *testing.T, path string, yamlPath []string, value string) {
	t.Helper()
	doc, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if err := doc.SetScalar(yamlPath, value); err != nil {
		t.Fatalf("set scalar: %v", err)
	}
	if err := doc.Save(path); err != nil {
		t.Fatalf("save config: %v", err)
	}
}
