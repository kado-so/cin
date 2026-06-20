package behavior

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cin/internal/cli"
	"cin/internal/config"
	"filippo.io/age"
)

type Story struct {
	t          *testing.T
	Dir        string
	ConfigPath string
	LocalPath  string
	Home       string
	keys       map[string]*age.X25519Identity
}

type Result struct {
	Stdout string
	Stderr string
	Code   int
}

func NewStory(t *testing.T) *Story {
	t.Helper()
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatalf("create home: %v", err)
	}

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(oldWD)
	})

	t.Setenv("HOME", home)
	t.Setenv("PWD", dir)
	t.Setenv("CIN_USER", "")
	t.Setenv("CIN_AGE_KEY", "")
	t.Setenv("CIN_AGE_KEY_FILE", "")

	return &Story{
		t:          t,
		Dir:        dir,
		ConfigPath: filepath.Join(dir, "configs.secret.yaml"),
		LocalPath:  filepath.Join(dir, "configs.local.secret.yaml"),
		Home:       home,
		keys:       map[string]*age.X25519Identity{},
	}
}

func (s *Story) Identity(user string) *age.X25519Identity {
	s.t.Helper()
	if identity, ok := s.keys[user]; ok {
		return identity
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		s.t.Fatalf("generate age identity: %v", err)
	}
	s.keys[user] = identity
	return identity
}

func (s *Story) Run(args ...string) Result {
	s.t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := cli.Run(args, &stdout, &stderr)
	return Result{Stdout: stdout.String(), Stderr: stderr.String(), Code: code}
}

func (s *Story) RunWithInput(input string, args ...string) Result {
	s.t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		s.t.Fatalf("create stdin pipe: %v", err)
	}
	if _, err := writer.WriteString(input); err != nil {
		s.t.Fatalf("write stdin pipe: %v", err)
	}
	if err := writer.Close(); err != nil {
		s.t.Fatalf("close stdin pipe writer: %v", err)
	}
	oldStdin := os.Stdin
	os.Stdin = reader
	defer func() {
		os.Stdin = oldStdin
		_ = reader.Close()
	}()
	return s.Run(args...)
}

func (s *Story) RunAs(user string, args ...string) Result {
	s.t.Helper()
	identity := s.Identity(user)
	s.t.Setenv("CIN_USER", user)
	s.t.Setenv("CIN_AGE_KEY", identity.String())
	return s.Run(args...)
}

func (s *Story) RunAsWithInput(user string, input string, args ...string) Result {
	s.t.Helper()
	identity := s.Identity(user)
	s.t.Setenv("CIN_USER", user)
	s.t.Setenv("CIN_AGE_KEY", identity.String())
	return s.RunWithInput(input, args...)
}

func (s *Story) OK(result Result) Result {
	s.t.Helper()
	if result.Code != 0 {
		s.t.Fatalf("command failed: code=%d stdout=%q stderr=%q", result.Code, result.Stdout, result.Stderr)
	}
	return result
}

func (s *Story) ReadConfig() string {
	s.t.Helper()
	data, err := os.ReadFile(s.ConfigPath)
	if err != nil {
		s.t.Fatalf("read config: %v", err)
	}
	return string(data)
}

func (s *Story) SetExtends(path string, env string, parent string) {
	s.t.Helper()
	doc, err := config.Load(path)
	if err != nil {
		s.t.Fatalf("load config: %v", err)
	}
	if err := doc.SetScalar([]string{"envs", env, "extends"}, parent); err != nil {
		s.t.Fatalf("set extends: %v", err)
	}
	if err := doc.Save(path); err != nil {
		s.t.Fatalf("save config: %v", err)
	}
}

func (s *Story) AssertNoPlaintext(haystack string, values ...string) {
	s.t.Helper()
	for _, value := range values {
		if value != "" && strings.Contains(haystack, value) {
			s.t.Fatalf("plaintext %q leaked in %q", value, haystack)
		}
	}
}

func (r Result) Combined() string {
	return r.Stdout + r.Stderr
}
