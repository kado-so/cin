package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecipientsSortsUsersAndLooksUpPublicKeys(t *testing.T) {
	doc := loadTestConfig(t, `
cin:
  users:
    alice:
      age: age1alice
    vaishnav:
      age: age1vaishnav
  recipientSets:
    team:
      users: [vaishnav, alice]
envs: {}
`)

	set, err := doc.Recipients("team")
	if err != nil {
		t.Fatalf("lookup recipients: %v", err)
	}
	if got := join(set.Users); got != "alice,vaishnav" {
		t.Fatalf("expected sorted users, got %q", got)
	}
	if got := join(set.Recipients); got != "age1alice,age1vaishnav" {
		t.Fatalf("expected public keys in sorted user order, got %q", got)
	}
}

func TestRecipientSetForWritePrecedence(t *testing.T) {
	doc := loadTestConfig(t, `
cin:
  defaults:
    recipientSet: team
envs:
  dev:
    defaults:
      recipientSet: dev
    options:
      postgres:
        host: ENC[age-v1;set=old;users=vaishnav;data=Y2lwaGVy]
  prod: {}
`)

	path := []string{"envs", "dev", "options", "postgres", "host"}
	if got := mustRecipientSet(t, doc, path, "dev", "forced"); got != "forced" {
		t.Fatalf("expected override recipient set, got %q", got)
	}
	if got := mustRecipientSet(t, doc, path, "dev", ""); got != "old" {
		t.Fatalf("expected existing recipient set, got %q", got)
	}
	if got := mustRecipientSet(t, doc, []string{"envs", "dev", "options", "postgres", "port"}, "dev", ""); got != "dev" {
		t.Fatalf("expected env default recipient set, got %q", got)
	}
	if got := mustRecipientSet(t, doc, []string{"envs", "prod", "options", "postgres", "host"}, "prod", ""); got != "team" {
		t.Fatalf("expected global default recipient set, got %q", got)
	}
}

func TestOptionPath(t *testing.T) {
	parts, ok := OptionPath("options.postgres.host")
	if !ok {
		t.Fatal("expected option path")
	}
	if got := join(parts); got != "postgres,host" {
		t.Fatalf("unexpected option path: %q", got)
	}
	if _, ok := OptionPath("DATABASE_URL"); ok {
		t.Fatal("expected app value key not to parse as option path")
	}
}

func TestSaveMutatedEmptyEnvsUsesBlockStyle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("cin:\n  version: 1\nenvs: {}\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	doc, err := Load(path)
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	if err := doc.SetOption("dev", []string{"postgres", "host"}, "ENC[age-v1;set=team;users=vaishnav;data=Y2lwaGVy]"); err != nil {
		t.Fatalf("set option: %v", err)
	}
	if err := doc.SetAppValue("dev", "api", "DATABASE_URL", "ENC_TEMPLATE[age-v1;set=team;users=vaishnav;data=Y2lwaGVy]"); err != nil {
		t.Fatalf("set app value: %v", err)
	}
	if err := doc.Save(path); err != nil {
		t.Fatalf("save config: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, "envs:\n  dev:") {
		t.Fatalf("expected block-style envs, got:\n%s", out)
	}
	if strings.Contains(out, "envs: {dev:") {
		t.Fatalf("expected envs not to use flow style, got:\n%s", out)
	}
	if !strings.Contains(out, "host: ENC[age-v1;set=team;users=vaishnav;data=Y2lwaGVy]") {
		t.Fatalf("expected encrypted scalar to stay compact, got:\n%s", out)
	}
}

func loadTestConfig(t *testing.T, yaml string) *Document {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	doc, err := Load(path)
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	return doc
}

func mustRecipientSet(t *testing.T, doc *Document, path []string, env string, override string) string {
	t.Helper()
	set, err := doc.RecipientSetForWrite(path, env, override)
	if err != nil {
		t.Fatalf("recipient set for write: %v", err)
	}
	return set
}

func join(values []string) string {
	return strings.Join(values, ",")
}
