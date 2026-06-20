package localenv

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// Load applies CIN_* defaults from local .env files without overriding the
// real process environment.
func Load() error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	files, err := discoverFiles(cwd)
	if err != nil {
		return err
	}

	envs := make([]map[string]string, 0, len(files))
	for _, file := range files {
		values, err := parseFile(file)
		if err != nil {
			return err
		}
		envs = append(envs, values)
	}

	for _, values := range envs {
		for key, value := range values {
			if !strings.HasPrefix(key, "CIN_") {
				continue
			}
			if _, ok := os.LookupEnv(key); !ok {
				if err := os.Setenv(key, value); err != nil {
					return fmt.Errorf("%s: set %s: %w", ".env", key, err)
				}
			}
		}
	}
	return nil
}

func discoverFiles(cwd string) ([]string, error) {
	var files []string
	cwdEnv := filepath.Join(cwd, ".env")
	if exists, err := fileExists(cwdEnv); err != nil {
		return nil, err
	} else if exists {
		files = append(files, cwdEnv)
	}

	root, err := gitRoot(cwd)
	if err != nil {
		return nil, err
	}
	if root == "" || root == cwd {
		return files, nil
	}
	rootEnv := filepath.Join(root, ".env")
	if exists, err := fileExists(rootEnv); err != nil {
		return nil, err
	} else if exists {
		files = append(files, rootEnv)
	}
	return files, nil
}

func fileExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if err == nil {
		return !info.IsDir(), nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func gitRoot(dir string) (string, error) {
	for {
		dotGit := filepath.Join(dir, ".git")
		info, err := os.Stat(dotGit)
		if err == nil {
			if info.IsDir() {
				return dir, nil
			}
			data, err := os.ReadFile(dotGit)
			if err != nil {
				return "", err
			}
			if strings.HasPrefix(strings.TrimSpace(string(data)), "gitdir:") {
				return dir, nil
			}
		} else if !os.IsNotExist(err) {
			return "", err
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil
		}
		dir = parent
	}
}

func parseFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	values := map[string]string{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		key, value, ok, err := parseLine(scanner.Text())
		if err != nil {
			return nil, fmt.Errorf("%s:%d: invalid .env syntax: %w", path, lineNo, err)
		}
		if ok {
			values[key] = value
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func parseLine(line string) (string, string, bool, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false, nil
	}
	if strings.HasPrefix(line, "export ") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
	}

	key, rawValue, ok := strings.Cut(line, "=")
	if !ok {
		return "", "", false, fmt.Errorf("expected KEY=value")
	}
	key = strings.TrimSpace(key)
	if !validKey(key) {
		return "", "", false, fmt.Errorf("invalid key")
	}
	value, err := parseValue(rawValue)
	if err != nil {
		return "", "", false, err
	}
	return key, value, true, nil
}

func validKey(key string) bool {
	for i, r := range key {
		if i == 0 {
			if r != '_' && !unicode.IsLetter(r) {
				return false
			}
			continue
		}
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return key != ""
}

func parseValue(raw string) (string, error) {
	raw = strings.TrimLeftFunc(raw, unicode.IsSpace)
	if raw == "" {
		return "", nil
	}
	if raw[0] != '"' && raw[0] != '\'' {
		return stripComment(raw), nil
	}

	quote := raw[0]
	var b strings.Builder
	escaped := false
	for i := 1; i < len(raw); i++ {
		c := raw[i]
		if escaped {
			b.WriteByte(unescape(c))
			escaped = false
			continue
		}
		if quote == '"' && c == '\\' {
			escaped = true
			continue
		}
		if c == quote {
			rest := strings.TrimSpace(raw[i+1:])
			if rest != "" && !strings.HasPrefix(rest, "#") {
				return "", fmt.Errorf("unexpected text after quoted value")
			}
			return b.String(), nil
		}
		b.WriteByte(c)
	}
	return "", fmt.Errorf("unterminated quoted value")
}

func unescape(c byte) byte {
	switch c {
	case 'n':
		return '\n'
	case 'r':
		return '\r'
	case 't':
		return '\t'
	default:
		return c
	}
}

func stripComment(value string) string {
	for i, r := range value {
		if r == '#' && (i == 0 || unicode.IsSpace(rune(value[i-1]))) {
			return strings.TrimSpace(value[:i])
		}
	}
	return strings.TrimSpace(value)
}
