package localenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCurrentDirectoryDotenv(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	restoreEnv(t, "CIN_USER", "API_TOKEN")
	unsetEnv(t, "CIN_USER", "API_TOKEN")
	writeFile(t, filepath.Join(dir, ".env"), "CIN_USER=local\nAPI_TOKEN=app\n")

	if err := Load(); err != nil {
		t.Fatalf("load .env: %v", err)
	}
	if got := os.Getenv("CIN_USER"); got != "local" {
		t.Fatalf("expected CIN_USER from cwd .env, got %q", got)
	}
	if _, ok := os.LookupEnv("API_TOKEN"); ok {
		t.Fatal("expected non-CIN value to be ignored")
	}
}

func TestLoadGitRootDotenv(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".env"), "CIN_USER=root\n")
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	subdir := filepath.Join(root, "app")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	chdir(t, subdir)
	restoreEnv(t, "CIN_USER")
	unsetEnv(t, "CIN_USER")

	if err := Load(); err != nil {
		t.Fatalf("load .env: %v", err)
	}
	if got := os.Getenv("CIN_USER"); got != "root" {
		t.Fatalf("expected CIN_USER from git root .env, got %q", got)
	}
}

func TestLoadCurrentDirectoryPrecedenceOverGitRoot(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".env"), "CIN_USER=root\n")
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	subdir := filepath.Join(root, "app")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	writeFile(t, filepath.Join(subdir, ".env"), "CIN_USER=cwd\n")
	chdir(t, subdir)
	restoreEnv(t, "CIN_USER")
	unsetEnv(t, "CIN_USER")

	if err := Load(); err != nil {
		t.Fatalf("load .env: %v", err)
	}
	if got := os.Getenv("CIN_USER"); got != "cwd" {
		t.Fatalf("expected cwd .env precedence, got %q", got)
	}
}

func TestLoadDoesNotOverrideProcessEnv(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	restoreEnv(t, "CIN_USER")
	if err := os.Setenv("CIN_USER", "process"); err != nil {
		t.Fatalf("set env: %v", err)
	}
	writeFile(t, filepath.Join(dir, ".env"), "CIN_USER=local\n")

	if err := Load(); err != nil {
		t.Fatalf("load .env: %v", err)
	}
	if got := os.Getenv("CIN_USER"); got != "process" {
		t.Fatalf("expected process env to win, got %q", got)
	}
}

func TestLoadWorktreeRootDotenv(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".env"), "CIN_USER=worktree\n")
	writeFile(t, filepath.Join(root, ".git"), "gitdir: /tmp/repo/.git/worktrees/app\n")
	subdir := filepath.Join(root, "app")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	chdir(t, subdir)
	restoreEnv(t, "CIN_USER")
	unsetEnv(t, "CIN_USER")

	if err := Load(); err != nil {
		t.Fatalf("load .env: %v", err)
	}
	if got := os.Getenv("CIN_USER"); got != "worktree" {
		t.Fatalf("expected worktree root .env, got %q", got)
	}
}

func TestLoadQuotedValuesAndComments(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	restoreEnv(t, "CIN_USER", "CIN_AGE_KEY", "CIN_AGE_KEY_FILE")
	unsetEnv(t, "CIN_USER", "CIN_AGE_KEY", "CIN_AGE_KEY_FILE")
	writeFile(t, filepath.Join(dir, ".env"), `
# comment
export CIN_USER="vaishnav # not a comment" # comment
CIN_AGE_KEY='AGE-SECRET'
CIN_AGE_KEY_FILE=keys.txt # comment
`)

	if err := Load(); err != nil {
		t.Fatalf("load .env: %v", err)
	}
	if got := os.Getenv("CIN_USER"); got != "vaishnav # not a comment" {
		t.Fatalf("unexpected quoted double value: %q", got)
	}
	if got := os.Getenv("CIN_AGE_KEY"); got != "AGE-SECRET" {
		t.Fatalf("unexpected quoted single value: %q", got)
	}
	if got := os.Getenv("CIN_AGE_KEY_FILE"); got != "keys.txt" {
		t.Fatalf("unexpected unquoted value: %q", got)
	}
}

func TestLoadInvalidSyntaxNamesFileLineAndRedactsValue(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	restoreEnv(t, "CIN_AGE_KEY")
	unsetEnv(t, "CIN_AGE_KEY")
	path := filepath.Join(dir, ".env")
	writeFile(t, path, "CIN_USER=ok\nCIN_AGE_KEY=\"super-secret\n")

	err := Load()
	if err == nil {
		t.Fatal("expected invalid syntax error")
	}
	msg := err.Error()
	if !strings.Contains(msg, path+":2:") {
		t.Fatalf("expected file and line in error, got %q", msg)
	}
	if strings.Contains(msg, "super-secret") {
		t.Fatalf("expected secret value to be redacted, got %q", msg)
	}
	if _, ok := os.LookupEnv("CIN_AGE_KEY"); ok {
		t.Fatal("expected invalid file not to set env")
	}
}

func chdir(t *testing.T, dir string) {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(cwd); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func restoreEnv(t *testing.T, keys ...string) {
	t.Helper()
	type savedValue struct {
		value string
		ok    bool
	}
	saved := map[string]savedValue{}
	for _, key := range keys {
		value, ok := os.LookupEnv(key)
		saved[key] = savedValue{value: value, ok: ok}
	}
	t.Cleanup(func() {
		for _, key := range keys {
			if saved[key].ok {
				_ = os.Setenv(key, saved[key].value)
			} else {
				_ = os.Unsetenv(key)
			}
		}
	})
}

func unsetEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, key := range keys {
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset %s: %v", key, err)
		}
	}
}
