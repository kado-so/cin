package cryptoage

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

func Encrypt(plaintext []byte, publicKeys []string) ([]byte, error) {
	recipients, err := parseRecipients(publicKeys)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func Decrypt(ciphertext []byte, identities []age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identities...)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func DiscoverIdentity(user string) ([]age.Identity, error) {
	if key := os.Getenv("CIN_AGE_KEY"); key != "" {
		return age.ParseIdentities(strings.NewReader(key))
	}
	if path := os.Getenv("CIN_AGE_KEY_FILE"); path != "" {
		return identitiesFromFile(path)
	}
	if user == "" {
		return nil, fmt.Errorf("current user is required")
	}
	return identitiesFromFile(DefaultKeyPath(user))
}

func EnsureIdentity(user string) (*age.X25519Identity, error) {
	if key := os.Getenv("CIN_AGE_KEY"); key != "" {
		return firstX25519(age.ParseIdentities(strings.NewReader(key)))
	}
	if path := os.Getenv("CIN_AGE_KEY_FILE"); path != "" {
		return firstX25519(identitiesFromFile(path))
	}
	path := DefaultKeyPath(user)
	if _, err := os.Stat(path); err == nil {
		return firstX25519(identitiesFromFile(path))
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	data := []byte(identity.String() + "\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, err
	}
	return identity, nil
}

func DefaultKeyPath(user string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".config", "cin", "keys", user+".txt")
	}
	return filepath.Join(home, ".config", "cin", "keys", user+".txt")
}

func parseRecipients(publicKeys []string) ([]age.Recipient, error) {
	recipients := make([]age.Recipient, 0, len(publicKeys))
	for _, key := range publicKeys {
		recipient, err := age.ParseX25519Recipient(key)
		if err != nil {
			return nil, fmt.Errorf("parse recipient: %w", err)
		}
		recipients = append(recipients, recipient)
	}
	return recipients, nil
}

func identitiesFromFile(path string) ([]age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return age.ParseIdentities(f)
}

func firstX25519(identities []age.Identity, err error) (*age.X25519Identity, error) {
	if err != nil {
		return nil, err
	}
	for _, identity := range identities {
		if x, ok := identity.(*age.X25519Identity); ok {
			return x, nil
		}
	}
	return nil, fmt.Errorf("no age X25519 identity found")
}
