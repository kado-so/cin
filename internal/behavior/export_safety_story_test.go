// Story: a developer exports app config for inspection or dotenv handoff, but
// plaintext secrets stay blocked unless the command is explicitly confirmed.
//
// Protects: redacted export must reveal only the key set, unsafe plaintext
// stdout/file exports must fail closed without leaks, confirmed file export may
// write plaintext, and encrypted config files must never store plaintext.
package behavior

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportSafetyStory(t *testing.T) {
	story := NewStory(t)

	databaseURL := "postgres://export_user:export-pass-17@export-db.internal:5432/api"
	apiToken := "export-story-api-token-17"
	secrets := []string{databaseURL, apiToken, "export-pass-17", "export-db.internal"}

	story.OK(story.RunAs("vaishnav", "init", "vaishnav"))
	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "-a", "api", "DATABASE_URL", databaseURL))
	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "-a", "api", "API_TOKEN", apiToken))

	redacted := story.OK(story.RunAs("vaishnav", "export", "-e", "dev", "-a", "api", "--redact-values"))
	if redacted.Stdout != "API_TOKEN=[secret]\nDATABASE_URL=[secret]\n" {
		t.Fatalf("unexpected redacted export output: %q", redacted.Stdout)
	}
	story.AssertNoPlaintext(redacted.Combined(), secrets...)

	stdoutBlocked := story.RunAs("vaishnav", "export", "-e", "dev", "-a", "api", "--stdout")
	if stdoutBlocked.Code != 2 {
		t.Fatalf("expected stdout export to require confirmation, got code=%d stdout=%q stderr=%q", stdoutBlocked.Code, stdoutBlocked.Stdout, stdoutBlocked.Stderr)
	}
	if stdoutBlocked.Stdout != "" || !strings.Contains(stdoutBlocked.Stderr, "--stdout --yes") {
		t.Fatalf("unexpected stdout confirmation failure: stdout=%q stderr=%q", stdoutBlocked.Stdout, stdoutBlocked.Stderr)
	}
	story.AssertNoPlaintext(stdoutBlocked.Combined(), secrets...)

	out := filepath.Join(story.Dir, ".env.export")
	fileBlocked := story.RunAs("vaishnav", "export", "-e", "dev", "-a", "api", "--out", out)
	if fileBlocked.Code != 2 {
		t.Fatalf("expected file export to require confirmation, got code=%d stdout=%q stderr=%q", fileBlocked.Code, fileBlocked.Stdout, fileBlocked.Stderr)
	}
	if fileBlocked.Stdout != "" || !strings.Contains(fileBlocked.Stderr, "--yes") {
		t.Fatalf("unexpected file confirmation failure: stdout=%q stderr=%q", fileBlocked.Stdout, fileBlocked.Stderr)
	}
	story.AssertNoPlaintext(fileBlocked.Combined(), secrets...)
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("expected failed export not to create output file, stat err=%v", err)
	}

	confirmed := story.OK(story.RunAs("vaishnav", "export", "-e", "dev", "-a", "api", "--out", out, "--yes"))
	if confirmed.Stdout != "" || confirmed.Stderr != "" {
		t.Fatalf("expected quiet confirmed file export, stdout=%q stderr=%q", confirmed.Stdout, confirmed.Stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read confirmed export: %v", err)
	}
	if got := string(data); got != "API_TOKEN="+apiToken+"\nDATABASE_URL="+databaseURL+"\n" {
		t.Fatalf("unexpected confirmed export contents: %q", got)
	}

	story.AssertNoPlaintext(story.ReadConfig(), secrets...)
}
