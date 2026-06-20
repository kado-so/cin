// Story: an approved teammate is removed from shared app config access, and
// existing encrypted values are rekeyed for the remaining users.
//
// Protects: removal must stop future decrypt/export access after rekey,
// preserve revocation warnings, change affected ciphertext, keep original user
// access working, and never write plaintext secrets into encrypted config files.
package behavior

import (
	"strings"
	"testing"
)

func TestUserRemovalStory(t *testing.T) {
	story := NewStory(t)

	databaseURL := "postgres://api_remove:remove-pass-17@remove-db.internal:5432/api"
	apiToken := "remove-story-api-token-17"
	secrets := []string{databaseURL, apiToken, "remove-pass-17", "remove-db.internal"}

	story.OK(story.RunAs("vaishnav", "init", "vaishnav"))
	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "-a", "api", "DATABASE_URL", databaseURL))
	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "-a", "api", "API_TOKEN", apiToken))
	story.OK(story.RunAs("vaishnav", "users", "add", "alice", "--age", story.Identity("alice").Recipient().String()))
	story.OK(story.RunAsWithInput("vaishnav", "approve\n", "users", "approve", "alice"))

	beforeDatabase := encryptedStoryScalar(t, story.ConfigPath, "envs", "dev", "apps", "api", "values", "DATABASE_URL")
	beforeToken := encryptedStoryScalar(t, story.ConfigPath, "envs", "dev", "apps", "api", "values", "API_TOKEN")

	aliceGet := story.OK(story.RunAs("alice", "get", "-e", "dev", "-a", "api", "DATABASE_URL", "--show"))
	if got := strings.TrimSpace(aliceGet.Stdout); got != databaseURL {
		t.Fatalf("approved alice decrypted DATABASE_URL as %q", got)
	}

	remove := story.OK(story.RunAs("vaishnav", "users", "remove", "alice"))
	for _, want := range []string{"warning: removing alice", "Git history", "rotate affected secrets"} {
		if !strings.Contains(remove.Stderr, want) {
			t.Fatalf("remove warning missing %q: %q", want, remove.Stderr)
		}
	}
	story.AssertNoPlaintext(remove.Combined(), secrets...)

	if got := encryptedStoryScalar(t, story.ConfigPath, "envs", "dev", "apps", "api", "values", "DATABASE_URL"); got == beforeDatabase {
		t.Fatal("removing alice did not rekey DATABASE_URL")
	}
	if got := encryptedStoryScalar(t, story.ConfigPath, "envs", "dev", "apps", "api", "values", "API_TOKEN"); got == beforeToken {
		t.Fatal("removing alice did not rekey API_TOKEN")
	}

	aliceExport := story.RunAs("alice", "export", "-e", "dev", "-a", "api", "--stdout", "--yes")
	if aliceExport.Code != 2 {
		t.Fatalf("expected removed alice export failure, got code=%d stdout=%q stderr=%q", aliceExport.Code, aliceExport.Stdout, aliceExport.Stderr)
	}
	story.AssertNoPlaintext(aliceExport.Combined(), secrets...)

	ownerExport := story.OK(story.RunAs("vaishnav", "export", "-e", "dev", "-a", "api", "--stdout", "--yes"))
	for _, want := range []string{"API_TOKEN=" + apiToken, "DATABASE_URL=" + databaseURL} {
		if !strings.Contains(ownerExport.Stdout, want) {
			t.Fatalf("remaining user export missing %q: %q", want, ownerExport.Stdout)
		}
	}

	story.AssertNoPlaintext(story.ReadConfig(), secrets...)
}
