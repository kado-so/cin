// Story: a developer edits an environment as a whole, including shared options
// and app values, without naming one app at a time.
//
// Protects: env-wide edit must decrypt only editable values into the temporary
// document, re-encrypt changed values, preserve untouched ciphertext, reject
// unsafe edits without saving, and never write edited plaintext to config.
package behavior

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cin/internal/config"
	"cin/internal/envelope"
)

func TestEditEnvStory(t *testing.T) {
	story := NewStory(t)

	secrets := []string{
		"dev-db-old", "dev-db-new",
		"dev-token-old", "dev-token-new",
		"dev-worker-keep",
		"prod-db-old", "prod-db-new",
		"prod-token-old", "prod-token-new",
		"prod-queue-old", "prod-queue-new",
		"prod-worker-keep",
		"should-not-save",
	}

	story.OK(story.RunAs("vaishnav", "init", "vaishnav"))
	setStoryDefaultEnv(t, story.ConfigPath, "prod")

	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "options.postgres.host", "dev-db-old"))
	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "-a", "api", "DATABASE_URL", "postgres://{{ .options.postgres.host }}/api"))
	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "-a", "api", "API_TOKEN", "dev-token-old"))
	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "-a", "worker", "QUEUE", "dev-worker-keep"))

	story.OK(story.RunAs("vaishnav", "set", "-e", "prod", "options.postgres.host", "prod-db-old"))
	story.OK(story.RunAs("vaishnav", "set", "-e", "prod", "-a", "api", "API_TOKEN", "prod-token-old"))
	story.OK(story.RunAs("vaishnav", "set", "-e", "prod", "-a", "worker", "QUEUE", "prod-queue-old"))
	story.OK(story.RunAs("vaishnav", "set", "-e", "prod", "-a", "worker", "UNCHANGED", "prod-worker-keep"))

	devHostBefore := storyEncryptedScalar(t, story.ConfigPath, "envs", "dev", "options", "postgres", "host")
	devTokenBefore := storyEncryptedScalar(t, story.ConfigPath, "envs", "dev", "apps", "api", "values", "API_TOKEN")
	devWorkerBefore := storyEncryptedScalar(t, story.ConfigPath, "envs", "dev", "apps", "worker", "values", "QUEUE")

	t.Setenv("VISUAL", storyFakeEditor(t, `grep -q 'dev-db-old' "$1" || exit 1
grep -q 'dev-token-old' "$1" || exit 1
grep -q 'dev-worker-keep' "$1" || exit 1
cat > "$1" <<'EOF'
options:
  postgres:
    host: dev-db-new
apps:
  api:
    values:
      API_TOKEN: dev-token-new
      DATABASE_URL: postgres://{{ .options.postgres.host }}/api
  worker:
    values:
      QUEUE: dev-worker-keep
EOF
`))
	t.Setenv("EDITOR", "")

	editDev := story.OK(story.RunAs("vaishnav", "edit", "-e", "dev"))
	if editDev.Stdout != "" || editDev.Stderr != "" {
		t.Fatalf("expected quiet dev edit, stdout=%q stderr=%q", editDev.Stdout, editDev.Stderr)
	}

	if got := storyEncryptedScalar(t, story.ConfigPath, "envs", "dev", "apps", "worker", "values", "QUEUE"); got != devWorkerBefore {
		t.Fatal("unchanged dev app value was not preserved byte-identical")
	}
	assertStoryReencrypted(t, story.ConfigPath, devHostBefore, "envs", "dev", "options", "postgres", "host")
	assertStoryReencrypted(t, story.ConfigPath, devTokenBefore, "envs", "dev", "apps", "api", "values", "API_TOKEN")

	devHost := story.OK(story.RunAs("vaishnav", "get", "-e", "dev", "options.postgres.host", "--show"))
	if devHost.Stdout != "dev-db-new\n" {
		t.Fatalf("unexpected edited dev option: %q", devHost.Stdout)
	}
	devExport := story.OK(story.RunAs("vaishnav", "export", "-e", "dev", "-a", "api", "--stdout", "--yes"))
	for _, want := range []string{"API_TOKEN=dev-token-new", "DATABASE_URL=postgres://dev-db-new/api"} {
		if !strings.Contains(devExport.Stdout, want) {
			t.Fatalf("expected dev export to contain %q, got %q", want, devExport.Stdout)
		}
	}
	story.AssertNoPlaintext(story.ReadConfig(), secrets...)

	prodUnchangedBefore := storyEncryptedScalar(t, story.ConfigPath, "envs", "prod", "apps", "worker", "values", "UNCHANGED")

	t.Setenv("VISUAL", storyFakeEditor(t, `grep -q 'prod-db-old' "$1" || exit 1
grep -q 'prod-token-old' "$1" || exit 1
grep -q 'prod-queue-old' "$1" || exit 1
grep -q 'dev-token-new' "$1" && exit 1
cat > "$1" <<'EOF'
options:
  postgres:
    host: prod-db-new
apps:
  api:
    values:
      API_TOKEN: prod-token-new
  worker:
    values:
      QUEUE: prod-queue-new
      UNCHANGED: prod-worker-keep
EOF
`))

	story.OK(story.RunAs("vaishnav", "edit"))
	if got := storyEncryptedScalar(t, story.ConfigPath, "envs", "prod", "apps", "worker", "values", "UNCHANGED"); got != prodUnchangedBefore {
		t.Fatal("unchanged default-env value was not preserved byte-identical")
	}

	prodHost := story.OK(story.RunAs("vaishnav", "get", "-e", "prod", "options.postgres.host", "--show"))
	if prodHost.Stdout != "prod-db-new\n" {
		t.Fatalf("unexpected edited default env option: %q", prodHost.Stdout)
	}
	prodAPI := story.OK(story.RunAs("vaishnav", "get", "-e", "prod", "-a", "api", "API_TOKEN", "--show"))
	if prodAPI.Stdout != "prod-token-new\n" {
		t.Fatalf("unexpected edited default env app value: %q", prodAPI.Stdout)
	}
	prodWorkerExport := story.OK(story.RunAs("vaishnav", "export", "-e", "prod", "-a", "worker", "--stdout", "--yes"))
	for _, want := range []string{"QUEUE=prod-queue-new", "UNCHANGED=prod-worker-keep"} {
		if !strings.Contains(prodWorkerExport.Stdout, want) {
			t.Fatalf("expected prod worker export to contain %q, got %q", want, prodWorkerExport.Stdout)
		}
	}
	devStillEdited := story.OK(story.RunAs("vaishnav", "get", "-e", "dev", "-a", "api", "API_TOKEN", "--show"))
	if devStillEdited.Stdout != "dev-token-new\n" {
		t.Fatalf("default-env edit touched dev env: %q", devStillEdited.Stdout)
	}
	story.AssertNoPlaintext(story.ReadConfig(), secrets...)

	tokenBeforeRejectedEdit := storyEncryptedScalar(t, story.ConfigPath, "envs", "dev", "apps", "api", "values", "API_TOKEN")
	t.Setenv("VISUAL", storyFakeEditor(t, `cat > "$1" <<'EOF'
apps:
  api:
    values:
      API_TOKEN: should-not-save
      EXTRA: no
  worker:
    values:
      QUEUE: dev-worker-keep
options:
  postgres:
    host: dev-db-new
EOF
`))

	rejected := story.RunAs("vaishnav", "edit", "-e", "dev")
	if rejected.Code != 2 {
		t.Fatalf("expected unknown-key edit failure, got code=%d stdout=%q stderr=%q", rejected.Code, rejected.Stdout, rejected.Stderr)
	}
	if rejected.Stdout != "" || !strings.Contains(rejected.Stderr, "unknown editable key: apps.api.values.EXTRA") {
		t.Fatalf("unexpected unknown-key failure: stdout=%q stderr=%q", rejected.Stdout, rejected.Stderr)
	}
	if got := storyEncryptedScalar(t, story.ConfigPath, "envs", "dev", "apps", "api", "values", "API_TOKEN"); got != tokenBeforeRejectedEdit {
		t.Fatal("unknown-key edit saved a changed value")
	}
	story.AssertNoPlaintext(story.ReadConfig(), secrets...)
}

func storyFakeEditor(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "editor.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil {
		t.Fatalf("write fake editor: %v", err)
	}
	return path
}

func setStoryDefaultEnv(t *testing.T, path string, env string) {
	t.Helper()
	doc, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if err := doc.SetScalar([]string{"cin", "defaults", "env"}, env); err != nil {
		t.Fatalf("set default env: %v", err)
	}
	if err := doc.Save(path); err != nil {
		t.Fatalf("save default env: %v", err)
	}
}

func storyEncryptedScalar(t *testing.T, path string, parts ...string) string {
	t.Helper()
	doc, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	value, ok := doc.GetScalar(parts)
	if !ok {
		t.Fatalf("missing scalar at %s", strings.Join(parts, "."))
	}
	if _, err := envelope.Parse(value); err != nil {
		t.Fatalf("value at %s is not encrypted: %v", strings.Join(parts, "."), err)
	}
	return value
}

func assertStoryReencrypted(t *testing.T, path string, before string, parts ...string) {
	t.Helper()
	after := storyEncryptedScalar(t, path, parts...)
	if after == before {
		t.Fatalf("changed value at %s was not re-encrypted", strings.Join(parts, "."))
	}
}
