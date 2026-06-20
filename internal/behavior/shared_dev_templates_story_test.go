// Story: shared dev config keeps common encrypted options and encrypted
// templates, while named child environments derive concrete app config.
//
// Protects: inherited parent templates must resolve with child option
// overrides, .values aliases must bind to the owning app, and redacted command
// output plus encrypted config files must not reveal plaintext secrets.
package behavior

import (
	"strings"
	"testing"

	"cin/internal/config"
	"cin/internal/envelope"
)

func TestSharedDevTemplatesStory(t *testing.T) {
	story := NewStory(t)

	region := "story-region-17"
	scheme := "https"
	sharedAPIHost := "shared-api.behavior.test"
	sharedWorkerHost := "shared-worker.behavior.test"
	devAPIHost := "dev-api.behavior.test"
	devWorkerHost := "dev-worker.behavior.test"
	apiPath := "/v1"
	workerPath := "/jobs"
	apiURL := "https://dev-api.behavior.test/v1?region=story-region-17"
	workerURL := "https://dev-worker.behavior.test/jobs"
	secrets := []string{
		region,
		sharedAPIHost,
		sharedWorkerHost,
		devAPIHost,
		devWorkerHost,
		apiPath,
		workerPath,
		apiURL,
		workerURL,
	}

	story.OK(story.RunAs("vaishnav", "init", "vaishnav"))
	story.OK(story.RunAs("vaishnav", "set", "-e", "base", "options.region", region))
	story.OK(story.RunAs("vaishnav", "set", "-e", "shared", "options.scheme", scheme))
	story.OK(story.RunAs("vaishnav", "set", "-e", "shared", "options.host.api", sharedAPIHost))
	story.OK(story.RunAs("vaishnav", "set", "-e", "shared", "options.host.worker", sharedWorkerHost))
	story.OK(story.RunAs("vaishnav", "set", "-e", "shared", "-a", "api", "PATH", apiPath))
	story.OK(story.RunAs("vaishnav", "set", "-e", "shared", "-a", "api", "API_URL", "{{ .options.scheme }}://{{ .options.host.api }}{{ .values.PATH }}?region={{ .options.region }}"))
	story.OK(story.RunAs("vaishnav", "set", "-e", "shared", "-a", "api", "WORKER_URL", "{{ .apps.worker.values.URL }}"))
	story.OK(story.RunAs("vaishnav", "set", "-e", "shared", "-a", "worker", "PATH", workerPath))
	story.OK(story.RunAs("vaishnav", "set", "-e", "shared", "-a", "worker", "URL", "{{ .options.scheme }}://{{ .options.host.worker }}{{ .values.PATH }}"))
	story.SetExtends(story.ConfigPath, "shared", "base")

	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "options.host.api", devAPIHost))
	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "options.host.worker", devWorkerHost))
	story.SetExtends(story.ConfigPath, "dev", "shared")

	assertEncryptedKind(t, story.ConfigPath, envelope.Scalar, "envs", "base", "options", "region")
	assertEncryptedKind(t, story.ConfigPath, envelope.Scalar, "envs", "dev", "options", "host", "api")
	assertEncryptedKind(t, story.ConfigPath, envelope.Template, "envs", "shared", "apps", "api", "values", "API_URL")
	assertEncryptedKind(t, story.ConfigPath, envelope.Template, "envs", "shared", "apps", "api", "values", "WORKER_URL")
	assertEncryptedKind(t, story.ConfigPath, envelope.Template, "envs", "shared", "apps", "worker", "values", "URL")

	redactedExport := story.OK(story.RunAs("vaishnav", "export", "-e", "dev", "-a", "api", "--redact-values"))
	for _, want := range []string{
		"API_URL=[secret]",
		"PATH=[secret]",
		"WORKER_URL=[secret]",
	} {
		if !strings.Contains(redactedExport.Stdout, want) {
			t.Fatalf("expected redacted export to contain %q, got %q", want, redactedExport.Stdout)
		}
	}
	story.AssertNoPlaintext(redactedExport.Combined(), secrets...)

	plaintextExport := story.OK(story.RunAs("vaishnav", "export", "-e", "dev", "-a", "api", "--stdout", "--yes"))
	for _, want := range []string{
		"API_URL=" + apiURL,
		"PATH=" + apiPath,
		"WORKER_URL=" + workerURL,
	} {
		if !strings.Contains(plaintextExport.Stdout, want) {
			t.Fatalf("expected plaintext export to contain %q, got %q", want, plaintextExport.Stdout)
		}
	}
	if strings.Contains(plaintextExport.Stdout, sharedAPIHost) || strings.Contains(plaintextExport.Stdout, sharedWorkerHost) {
		t.Fatalf("parent template ignored child option overrides: %q", plaintextExport.Stdout)
	}

	story.AssertNoPlaintext(story.ReadConfig(), secrets...)
}

func assertEncryptedKind(t *testing.T, path string, kind envelope.Kind, parts ...string) {
	t.Helper()
	doc, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	value, ok := doc.GetScalar(parts)
	if !ok {
		t.Fatalf("missing encrypted scalar at %s", strings.Join(parts, "."))
	}
	enc, err := envelope.Parse(value)
	if err != nil {
		t.Fatalf("parse encrypted scalar at %s: %v", strings.Join(parts, "."), err)
	}
	if enc.Kind != kind {
		t.Fatalf("expected %s at %s, got %s", kind, strings.Join(parts, "."), enc.Kind)
	}
}
