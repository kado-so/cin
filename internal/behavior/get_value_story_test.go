// Story: a developer reads one config value at a time, with secrets redacted by
// default and plaintext shown only when explicitly requested.
//
// Protects: get must print exactly one value with no labels or metadata,
// templates must resolve through local overrides, and encrypted config files
// must not contain the plaintext values they protect.
package behavior

import (
	"os"
	"testing"

	"cin/internal/envelope"
)

func TestGetValueStory(t *testing.T) {
	story := NewStory(t)

	sharedUser := "get-story-user"
	sharedHost := "shared-get-db.behavior.test"
	localHost := "local-get-db.behavior.test"
	apiToken := "get-story-api-token-17"
	databaseURL := "postgres://get-story-user@local-get-db.behavior.test/api"
	secrets := []string{
		sharedUser,
		sharedHost,
		localHost,
		apiToken,
		databaseURL,
		"postgres://",
	}

	story.OK(story.RunAs("vaishnav", "init", "vaishnav"))
	story.OK(story.RunAs("vaishnav", "set", "-e", "shared", "options.postgres.user", sharedUser))
	story.OK(story.RunAs("vaishnav", "set", "-e", "shared", "options.postgres.host", sharedHost))
	story.OK(story.RunAs("vaishnav", "set", "-e", "shared", "-a", "api", "DATABASE_URL", "postgres://{{ .options.postgres.user }}@{{ .options.postgres.host }}/api"))
	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "-a", "api", "API_TOKEN", apiToken))
	story.SetExtends(story.ConfigPath, "dev", "shared")

	story.OK(story.RunAs("vaishnav", "-f", story.LocalPath, "init", "vaishnav"))
	story.OK(story.RunAs("vaishnav", "-f", story.LocalPath, "set", "-e", "dev", "options.postgres.host", localHost))

	assertEncryptedKind(t, story.ConfigPath, envelope.Scalar, "envs", "shared", "options", "postgres", "user")
	assertEncryptedKind(t, story.ConfigPath, envelope.Scalar, "envs", "shared", "options", "postgres", "host")
	assertEncryptedKind(t, story.ConfigPath, envelope.Template, "envs", "shared", "apps", "api", "values", "DATABASE_URL")
	assertEncryptedKind(t, story.ConfigPath, envelope.Scalar, "envs", "dev", "apps", "api", "values", "API_TOKEN")
	assertEncryptedKind(t, story.LocalPath, envelope.Scalar, "envs", "dev", "options", "postgres", "host")

	redacted := story.OK(story.RunAs("vaishnav", "get", "-e", "dev", "-a", "api", "API_TOKEN"))
	if redacted.Stdout != "[secret]\n" {
		t.Fatalf("unexpected redacted get output: %q", redacted.Stdout)
	}
	if redacted.Stderr != "" {
		t.Fatalf("expected redacted get to be quiet on stderr, got %q", redacted.Stderr)
	}
	story.AssertNoPlaintext(redacted.Combined(), secrets...)

	shownOption := story.OK(story.RunAs("vaishnav", "get", "-e", "dev", "options.postgres.host", "--show"))
	if shownOption.Stdout != localHost+"\n" {
		t.Fatalf("expected get --show option to print only the value, got %q", shownOption.Stdout)
	}
	if shownOption.Stderr != "" {
		t.Fatalf("expected get --show option to be quiet on stderr, got %q", shownOption.Stderr)
	}

	shownTemplate := story.OK(story.RunAs("vaishnav", "get", "-e", "dev", "-a", "api", "DATABASE_URL", "--show"))
	if shownTemplate.Stdout != databaseURL+"\n" {
		t.Fatalf("expected get --show template to print only the resolved value, got %q", shownTemplate.Stdout)
	}
	if shownTemplate.Stderr != "" {
		t.Fatalf("expected get --show template to be quiet on stderr, got %q", shownTemplate.Stderr)
	}

	story.AssertNoPlaintext(story.ReadConfig(), secrets...)
	localData, err := os.ReadFile(story.LocalPath)
	if err != nil {
		t.Fatalf("read local config: %v", err)
	}
	story.AssertNoPlaintext(string(localData), secrets...)
}
