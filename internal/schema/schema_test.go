package schema

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cin/internal/config"
)

func TestDiscoverReportsMissingGlobAndLoadsAppSchema(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "apps", "services", "api"), 0o700); err != nil {
		t.Fatalf("mkdir schema dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "apps", "services", "api", "cin.schema.yaml"), []byte(`
app: api
values:
  type: object
  additionalProperties: false
  required: [DATABASE_URL]
  properties:
    DATABASE_URL:
      type: string
`), 0o600); err != nil {
		t.Fatalf("write schema: %v", err)
	}
	doc := loadDoc(t, `
cin:
  configSchemas:
    - "apps/**/cin.schema.yaml"
    - "missing/*.yaml"
envs: {}
`)

	set, err := Discover(doc, filepath.Join(dir, "configs.secret.yaml"))
	if err != nil {
		t.Fatalf("discover schemas: %v", err)
	}
	if len(set.Schemas) != 1 || set.Schemas[0].App != "api" {
		t.Fatalf("expected api schema, got %#v", set.Schemas)
	}
	if len(set.GlobErrors) != 1 || set.GlobErrors[0].Pattern != "missing/*.yaml" {
		t.Fatalf("expected missing glob diagnostic, got %#v", set.GlobErrors)
	}
}

func TestValidateValuesUsesJSONSchemaAndEnvRequirements(t *testing.T) {
	appSchema := AppSchema{
		Path: "apps/api/cin.schema.yaml",
		App:  "api",
		Values: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []any{"DATABASE_URL"},
			"properties": map[string]any{
				"DATABASE_URL": map[string]any{"type": "string"},
				"PORT":         map[string]any{"type": "number"},
			},
		},
		Envs: map[string]EnvSchema{
			"prod": {Values: map[string]any{
				"required": []any{"SENTRY_DSN"},
				"properties": map[string]any{
					"SENTRY_DSN": map[string]any{"type": "string"},
				},
			}},
		},
	}

	errs := ValidateValues(appSchema, "prod", map[string]any{
		"PORT":       json.Number("3000"),
		"SENTRY_DSN": "https://sentry.example",
	})
	if len(errs) == 0 {
		t.Fatal("expected missing base required key")
	}
	if got := errs[0].Err.Error(); !strings.Contains(got, "DATABASE_URL") {
		t.Fatalf("expected validation error to mention base required key, got %q", got)
	}

	errs = ValidateValues(appSchema, "prod", map[string]any{
		"DATABASE_URL": "postgres://db",
		"PORT":         json.Number("3000"),
		"SENTRY_DSN":   "https://sentry.example",
	})
	if len(errs) != 0 {
		t.Fatalf("expected merged base/env properties to pass, got %v", errs[0].Err)
	}

	errs = ValidateValues(appSchema, "prod", map[string]any{
		"DATABASE_URL": "postgres://db",
		"PORT":         "not-a-number",
		"SENTRY_DSN":   "https://sentry.example",
		"EXTRA":        "x",
	})
	if len(errs) == 0 {
		t.Fatal("expected type and additional property errors")
	}
	var got strings.Builder
	for _, err := range errs {
		got.WriteString(err.Err.Error())
		got.WriteByte('\n')
	}
	for _, want := range []string{"PORT", "EXTRA"} {
		if !strings.Contains(got.String(), want) {
			t.Fatalf("expected validation errors to mention %s, got %q", want, got.String())
		}
	}
}

func loadDoc(t *testing.T, body string) *config.Document {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	doc, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return doc
}
