// Story: a developer runs doctor on a broken repo with mixed encryption,
// schema, template, and user-access problems before trying to run the app.
//
// Protects: doctor must report concrete env/app/key diagnostics with actionable
// fixes while never printing the plaintext values that made the repo unsafe.
package behavior

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cin/internal/config"
	"gopkg.in/yaml.v3"
)

func TestDoctorBrokenRepoStory(t *testing.T) {
	story := NewStory(t)

	databaseURL := "postgres://story_user:plaintext-pass-17@broken-db.internal/app"
	extraSecret := "extra-secret-doctor-story-17"
	secrets := []string{databaseURL, "plaintext-pass-17", "broken-db.internal", extraSecret}

	story.OK(story.RunAs("vaishnav", "init", "vaishnav"))
	writeDoctorStorySchema(t, story.Dir)
	setDoctorStorySchemas(t, story.ConfigPath, "apps/*/cin.schema.yaml", "missing/*.yaml")

	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "-a", "api", "DATABASE_URL", databaseURL))
	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "-a", "api", "EXTRA", extraSecret))
	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "-a", "api", "MISSING_TEMPLATE", "https://{{ .options.missing.host }}"))
	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "-a", "api", "CYCLE_A", "{{ .values.CYCLE_B }}"))
	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "-a", "api", "CYCLE_B", "{{ .values.CYCLE_A }}"))
	story.OK(story.RunAs("vaishnav", "users", "add", "alice", "--age", story.Identity("alice").Recipient().String()))

	setDoctorStoryPlaintext(t, story.ConfigPath, []string{"envs", "dev", "apps", "api", "values", "DATABASE_URL"}, databaseURL)
	story.AssertNoPlaintext(story.ReadConfig(), extraSecret)

	result := story.RunAs("vaishnav", "doctor", "-e", "dev", "-a", "api")
	if result.Code != 1 {
		t.Fatalf("expected doctor errors, got code=%d stdout=%q stderr=%q", result.Code, result.Stdout, result.Stderr)
	}

	for _, want := range []string{
		"Users",
		"error alice is pending and cannot decrypt existing values",
		"fix: cin users approve alice",
		"Encryption",
		"envs.dev.apps.api.values.DATABASE_URL is plaintext value",
		"fix: rewrite it with cin set",
		"Schemas",
		"schema glob missing/*.yaml matches no files",
		"apps/api/cin.schema.yaml requires REDIS_URL, but dev/api does not define it",
		"fix: cin set -e dev -a api REDIS_URL <value>",
		"EXTRA exists in dev/api but is not declared by any schema",
		"fix: add it to the schema or remove it",
		"Templates",
		"dev/api/CYCLE_A has a template cycle",
		"fix: break the cycle between template references",
		"dev/api/MISSING_TEMPLATE is missing template reference options.missing.host",
		"fix: set the referenced value or fix the template reference",
	} {
		if !strings.Contains(result.Stdout, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, result.Stdout)
		}
	}
	story.AssertNoPlaintext(result.Combined(), secrets...)
}

func writeDoctorStorySchema(t *testing.T, dir string) {
	t.Helper()
	schemaDir := filepath.Join(dir, "apps", "api")
	if err := os.MkdirAll(schemaDir, 0o700); err != nil {
		t.Fatalf("mkdir schema dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(schemaDir, "cin.schema.yaml"), []byte(`
app: api
values:
  type: object
  additionalProperties: false
  required: [DATABASE_URL, REDIS_URL]
  properties:
    DATABASE_URL:
      type: string
    REDIS_URL:
      type: string
    MISSING_TEMPLATE:
      type: string
    CYCLE_A:
      type: string
    CYCLE_B:
      type: string
`), 0o600); err != nil {
		t.Fatalf("write schema: %v", err)
	}
}

func setDoctorStorySchemas(t *testing.T, path string, patterns ...string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cin, ok := root["cin"].(map[string]any)
	if !ok {
		t.Fatal("missing cin map")
	}
	items := make([]any, len(patterns))
	for i, pattern := range patterns {
		items[i] = pattern
	}
	cin["configSchemas"] = items
	out, err := yaml.Marshal(root)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func setDoctorStoryPlaintext(t *testing.T, path string, yamlPath []string, value string) {
	t.Helper()
	doc, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if err := doc.SetScalar(yamlPath, value); err != nil {
		t.Fatalf("set plaintext: %v", err)
	}
	if err := doc.Save(path); err != nil {
		t.Fatalf("save config: %v", err)
	}
}
