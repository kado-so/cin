// Story: a local developer initializes config, inherits shared dev defaults,
// applies encrypted local overrides, and runs the app with resolved plaintext.
//
// Protects: redacted commands must not leak secret values, explicit plaintext
// commands must resolve local overrides, and encrypted config files must not
// contain the secret plaintext they protect.
package behavior

import (
	"os"
	"strings"
	"testing"
)

func TestLocalDeveloperStory(t *testing.T) {
	story := NewStory(t)

	sharedUser := "api_user"
	sharedPassword := "shared-password-123"
	sharedHost := "postgres.internal"
	localHost := "host.docker.internal"
	sharedRedis := "redis://dev-redis:6379"
	localRedis := "redis://localhost:6379"
	databaseURL := "postgres://api_user:shared-password-123@host.docker.internal:5432/api"
	secrets := []string{
		sharedUser,
		sharedPassword,
		sharedHost,
		localHost,
		sharedRedis,
		localRedis,
		databaseURL,
		"postgres://",
	}

	story.OK(story.RunAs("vaishnav", "init", "vaishnav"))
	story.OK(story.RunAs("vaishnav", "set", "-e", "shared", "options.postgres.user", sharedUser))
	story.OK(story.RunAs("vaishnav", "set", "-e", "shared", "options.postgres.password", sharedPassword))
	story.OK(story.RunAs("vaishnav", "set", "-e", "shared", "options.postgres.port", "5432"))
	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "options.postgres.host", sharedHost))
	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "-a", "api", "DATABASE_URL", "postgres://{{ .options.postgres.user }}:{{ .options.postgres.password }}@{{ .options.postgres.host }}:{{ .options.postgres.port }}/api"))
	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "-a", "api", "REDIS_URL", sharedRedis))
	story.SetExtends(story.ConfigPath, "dev", "shared")

	story.OK(story.RunAs("vaishnav", "-f", story.LocalPath, "init", "vaishnav"))
	story.OK(story.RunAs("vaishnav", "-f", story.LocalPath, "set", "-e", "dev", "options.postgres.host", localHost))
	story.OK(story.RunAs("vaishnav", "-f", story.LocalPath, "set", "-e", "dev", "-a", "api", "REDIS_URL", localRedis))

	redactedGet := story.OK(story.RunAs("vaishnav", "get", "-e", "dev", "-a", "api", "DATABASE_URL"))
	if redactedGet.Stdout != "[secret]\n" {
		t.Fatalf("unexpected redacted get output: %q", redactedGet.Stdout)
	}
	story.AssertNoPlaintext(redactedGet.Combined(), secrets...)

	redactedExport := story.OK(story.RunAs("vaishnav", "export", "-e", "dev", "-a", "api", "--redact-values"))
	if got := strings.TrimSpace(redactedExport.Stdout); got != "DATABASE_URL=[secret]\nREDIS_URL=[secret]" {
		t.Fatalf("unexpected redacted export output: %q", redactedExport.Stdout)
	}
	story.AssertNoPlaintext(redactedExport.Combined(), secrets...)

	shownGet := story.OK(story.RunAs("vaishnav", "get", "-e", "dev", "-a", "api", "DATABASE_URL", "--show"))
	if got := strings.TrimSpace(shownGet.Stdout); got != databaseURL {
		t.Fatalf("expected local override in get --show, got %q", got)
	}

	plaintextExport := story.OK(story.RunAs("vaishnav", "export", "-e", "dev", "-a", "api", "--stdout", "--yes"))
	for _, want := range []string{"DATABASE_URL=" + databaseURL, "REDIS_URL=" + localRedis} {
		if !strings.Contains(plaintextExport.Stdout, want) {
			t.Fatalf("expected plaintext export to contain %q, got %q", want, plaintextExport.Stdout)
		}
	}

	run := story.OK(story.RunAs("vaishnav", "run", "-e", "dev", "-a", "api", "--", "/bin/sh", "-c", "printf '%s\n%s\n' \"$DATABASE_URL\" \"$REDIS_URL\""))
	if got := strings.TrimSpace(run.Stdout); got != databaseURL+"\n"+localRedis {
		t.Fatalf("expected run to inject local overrides, got %q", got)
	}

	story.AssertNoPlaintext(story.ReadConfig(), secrets...)
	localData, err := os.ReadFile(story.LocalPath)
	if err != nil {
		t.Fatalf("read local config: %v", err)
	}
	story.AssertNoPlaintext(string(localData), secrets...)
}
