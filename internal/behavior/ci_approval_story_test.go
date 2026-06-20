// Story: CI is modeled as a normal pending user, then approved into the prod
// recipient set before it can decrypt production app config.
//
// Protects: pending CI users cannot read existing prod secrets, approval must
// require the exact interactive confirmation, approval rekeys affected values,
// and redacted output plus approval summaries must not leak plaintext.
package behavior

import (
	"strings"
	"testing"

	"cin/internal/config"
)

func TestCIApprovalStory(t *testing.T) {
	story := NewStory(t)

	databaseURL := "postgres://prod_user:prod-pass-17@prod-db.internal:5432/api"
	apiToken := "prod-api-token-ci-story-17"
	secrets := []string{databaseURL, apiToken, "prod-pass-17", "prod-db.internal"}

	story.OK(story.RunAs("vaishnav", "init", "vaishnav"))
	addStoryRecipientSet(t, story.ConfigPath, "prod", "vaishnav")
	setStoryDefaultRecipientSet(t, story.ConfigPath, "prod")
	story.OK(story.RunAs("vaishnav", "set", "-e", "prod", "-a", "api", "DATABASE_URL", databaseURL))
	story.OK(story.RunAs("vaishnav", "set", "-e", "prod", "-a", "api", "API_TOKEN", apiToken))

	databaseBefore := encryptedStoryScalar(t, story.ConfigPath, "envs", "prod", "apps", "api", "values", "DATABASE_URL")
	tokenBefore := encryptedStoryScalar(t, story.ConfigPath, "envs", "prod", "apps", "api", "values", "API_TOKEN")

	addCI := story.OK(story.RunAs("vaishnav", "users", "add", "ci-prod", "--age", story.Identity("ci-prod").Recipient().String()))
	if !strings.Contains(addCI.Stdout, "added pending user ci-prod") {
		t.Fatalf("unexpected users add output: %q", addCI.Stdout)
	}
	story.AssertNoPlaintext(addCI.Combined(), secrets...)

	users := story.OK(story.RunAs("vaishnav", "users", "list"))
	fields := storyUserFields(users.Stdout, "ci-prod")
	if len(fields) != 4 || fields[1] != "pending" || fields[3] != "prod" {
		t.Fatalf("unexpected ci-prod users list row: fields=%v stdout=%q", fields, users.Stdout)
	}
	story.AssertNoPlaintext(users.Combined(), secrets...)

	redacted := story.OK(story.RunAs("vaishnav", "export", "-e", "prod", "-a", "api", "--redact-values"))
	for _, want := range []string{"API_TOKEN=[secret]", "DATABASE_URL=[secret]"} {
		if !strings.Contains(redacted.Stdout, want) {
			t.Fatalf("redacted export missing %q: %q", want, redacted.Stdout)
		}
	}
	story.AssertNoPlaintext(redacted.Combined(), secrets...)

	pendingGet := story.RunAs("ci-prod", "get", "-e", "prod", "-a", "api", "DATABASE_URL", "--show")
	if pendingGet.Code != 2 {
		t.Fatalf("expected pending ci-prod decrypt failure, got code=%d stdout=%q stderr=%q", pendingGet.Code, pendingGet.Stdout, pendingGet.Stderr)
	}
	story.AssertNoPlaintext(pendingGet.Combined(), secrets...)

	cancelled := story.RunAsWithInput("vaishnav", "Approve\n", "users", "approve", "ci-prod")
	if cancelled.Code != 2 {
		t.Fatalf("expected approval cancellation, got code=%d stdout=%q stderr=%q", cancelled.Code, cancelled.Stdout, cancelled.Stderr)
	}
	if !strings.Contains(cancelled.Stdout, "Type approve to continue:") || !strings.Contains(cancelled.Stderr, "approval cancelled") {
		t.Fatalf("unexpected cancelled approval output: stdout=%q stderr=%q", cancelled.Stdout, cancelled.Stderr)
	}
	story.AssertNoPlaintext(cancelled.Combined(), secrets...)
	if got := encryptedStoryScalar(t, story.ConfigPath, "envs", "prod", "apps", "api", "values", "DATABASE_URL"); got != databaseBefore {
		t.Fatal("cancelled approval rekeyed DATABASE_URL")
	}
	if got := encryptedStoryScalar(t, story.ConfigPath, "envs", "prod", "apps", "api", "values", "API_TOKEN"); got != tokenBefore {
		t.Fatal("cancelled approval rekeyed API_TOKEN")
	}

	approved := story.OK(story.RunAsWithInput("vaishnav", "approve\n", "users", "approve", "ci-prod"))
	for _, want := range []string{"Approving ci-prod", "prod", "values to rekey: 2", "Type approve to continue:"} {
		if !strings.Contains(approved.Stdout, want) {
			t.Fatalf("approve summary missing %q: %q", want, approved.Stdout)
		}
	}
	story.AssertNoPlaintext(approved.Combined(), secrets...)
	if got := encryptedStoryScalar(t, story.ConfigPath, "envs", "prod", "apps", "api", "values", "DATABASE_URL"); got == databaseBefore {
		t.Fatal("approved ci-prod did not rekey DATABASE_URL")
	}
	if got := encryptedStoryScalar(t, story.ConfigPath, "envs", "prod", "apps", "api", "values", "API_TOKEN"); got == tokenBefore {
		t.Fatal("approved ci-prod did not rekey API_TOKEN")
	}

	shown := story.OK(story.RunAs("ci-prod", "get", "-e", "prod", "-a", "api", "DATABASE_URL", "--show"))
	if got := strings.TrimSpace(shown.Stdout); got != databaseURL {
		t.Fatalf("approved ci-prod decrypted DATABASE_URL as %q", got)
	}

	exported := story.OK(story.RunAs("ci-prod", "export", "-e", "prod", "-a", "api", "--stdout", "--yes"))
	for _, want := range []string{"API_TOKEN=" + apiToken, "DATABASE_URL=" + databaseURL} {
		if !strings.Contains(exported.Stdout, want) {
			t.Fatalf("plaintext export missing %q: %q", want, exported.Stdout)
		}
	}

	story.AssertNoPlaintext(story.ReadConfig(), secrets...)
}

func addStoryRecipientSet(t *testing.T, path string, set string, users ...string) {
	t.Helper()
	doc, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	for _, user := range users {
		doc.AddUserToRecipientSet(user, set)
	}
	if err := doc.Save(path); err != nil {
		t.Fatalf("save config: %v", err)
	}
}

func setStoryDefaultRecipientSet(t *testing.T, path string, set string) {
	t.Helper()
	doc, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if err := doc.SetScalar([]string{"cin", "defaults", "recipientSet"}, set); err != nil {
		t.Fatalf("set default recipient set: %v", err)
	}
	if err := doc.Save(path); err != nil {
		t.Fatalf("save config: %v", err)
	}
}

func encryptedStoryScalar(t *testing.T, path string, parts ...string) string {
	t.Helper()
	doc, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	value, ok := doc.GetScalar(parts)
	if !ok {
		t.Fatalf("missing encrypted scalar at %s", strings.Join(parts, "."))
	}
	return value
}

func storyUserFields(output string, username string) []string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == username {
			return fields
		}
	}
	return nil
}
