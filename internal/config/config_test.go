package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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

func TestResolvedEnvMergesStringInheritance(t *testing.T) {
	doc := loadTestConfig(t, `
envs:
  shared:
    options:
      postgres:
        host: ENC[shared-host]
        port: ENC[shared-port]
    apps:
      api:
        values:
          DATABASE_URL: ENC[shared-db]
  dev:
    extends: shared
    options:
      postgres:
        host: ENC[dev-host]
    apps:
      api:
        values:
          REDIS_URL: ENC[dev-redis]
`)

	env := mustResolvedEnv(t, doc, "dev")
	assertResolvedScalar(t, env, []string{"options", "postgres", "host"}, "ENC[dev-host]")
	assertResolvedScalar(t, env, []string{"options", "postgres", "port"}, "ENC[shared-port]")
	assertResolvedScalar(t, env, []string{"apps", "api", "values", "DATABASE_URL"}, "ENC[shared-db]")
	assertResolvedScalar(t, env, []string{"apps", "api", "values", "REDIS_URL"}, "ENC[dev-redis]")
}

func TestResolvedEnvMergesListInheritanceWithRightmostParentPrecedence(t *testing.T) {
	doc := loadTestConfig(t, `
envs:
  shared:
    options:
      feature:
        enabled: ENC[shared-enabled]
      list: [shared]
    apps:
      api:
        values:
          MODE: ENC[shared-mode]
  dev:
    options:
      feature:
        level: ENC[dev-level]
      list: [dev]
    apps:
      api:
        values:
          MODE: ENC[dev-mode]
  vaishnav:
    extends: [shared, dev]
    options:
      feature:
        enabled: ENC[child-enabled]
`)

	env := mustResolvedEnv(t, doc, "vaishnav")
	assertResolvedScalar(t, env, []string{"options", "feature", "enabled"}, "ENC[child-enabled]")
	assertResolvedScalar(t, env, []string{"options", "feature", "level"}, "ENC[dev-level]")
	assertResolvedScalar(t, env, []string{"apps", "api", "values", "MODE"}, "ENC[dev-mode]")

	list := getMap(getMap(env, "options"), "list")
	if list == nil || list.Kind != yaml.SequenceNode || len(list.Content) != 1 || list.Content[0].Value != "dev" {
		t.Fatalf("expected array to be replaced by rightmost parent, got %#v", list)
	}
}

func TestMergeEnvAppliesLocalHighestPrecedence(t *testing.T) {
	shared := loadTestConfig(t, `
envs:
  dev:
    options:
      postgres:
        host: ENC[shared-host]
        port: ENC[shared-port]
`)
	local := loadTestConfig(t, `
cin:
  users:
    ignored: {}
envs:
  dev:
    options:
      postgres:
        host: ENC[local-host]
`)

	env := configMergeForTest(t, shared, local, "dev")
	assertResolvedScalar(t, env, []string{"options", "postgres", "host"}, "ENC[local-host]")
	assertResolvedScalar(t, env, []string{"options", "postgres", "port"}, "ENC[shared-port]")
}

func TestResolvedEnvErrorsOnMissingParent(t *testing.T) {
	doc := loadTestConfig(t, `
envs:
  dev:
    extends: shared
`)

	_, err := doc.ResolvedEnv("dev")
	if err == nil || !strings.Contains(err.Error(), "environment parent not found: shared") {
		t.Fatalf("expected missing parent error, got %v", err)
	}
}

func TestResolvedEnvErrorsOnCycle(t *testing.T) {
	doc := loadTestConfig(t, `
envs:
  a:
    extends: b
  b:
    extends: c
  c:
    extends: a
`)

	_, err := doc.ResolvedEnv("a")
	if err == nil || !strings.Contains(err.Error(), "inheritance cycle detected: a -> b -> c -> a") {
		t.Fatalf("expected cycle error, got %v", err)
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

func mustResolvedEnv(t *testing.T, doc *Document, env string) *yaml.Node {
	t.Helper()
	resolved, err := doc.ResolvedEnv(env)
	if err != nil {
		t.Fatalf("resolve env: %v", err)
	}
	return resolved
}

func assertResolvedScalar(t *testing.T, env *yaml.Node, path []string, want string) {
	t.Helper()
	got, ok := ScalarIn(env, path)
	if !ok {
		t.Fatalf("expected scalar at %v", path)
	}
	if got != want {
		t.Fatalf("expected %q at %v, got %q", want, path, got)
	}
}

func configMergeForTest(t *testing.T, shared *Document, local *Document, env string) *yaml.Node {
	t.Helper()
	sharedEnv := mustResolvedEnv(t, shared, env)
	localEnv := mustResolvedEnv(t, local, env)
	return MergeEnv(sharedEnv, localEnv)
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
