package envelope

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const AlgorithmAgeV1 = "age-v1"

type Kind string

const (
	Scalar   Kind = "scalar"
	Template Kind = "template"
)

type EncryptedValue struct {
	Kind         Kind
	Algorithm    string
	RecipientSet string
	Users        []string
	Ciphertext   []byte
}

func Parse(s string) (EncryptedValue, error) {
	var v EncryptedValue
	body, kind, ok := encryptedBody(s)
	if !ok {
		return v, errors.New("not an encrypted value")
	}

	parts := strings.Split(body, ";")
	if len(parts) != 4 {
		return v, errors.New("encrypted value must have four fields")
	}
	if parts[0] != AlgorithmAgeV1 {
		return v, fmt.Errorf("unsupported encrypted value algorithm: %s", parts[0])
	}

	fields := map[string]string{}
	for _, part := range parts[1:] {
		k, val, ok := strings.Cut(part, "=")
		if !ok || k == "" {
			return v, fmt.Errorf("malformed encrypted value field: %s", part)
		}
		fields[k] = val
	}
	if _, ok := fields["set"]; !ok {
		return v, errors.New("encrypted value missing set field")
	}
	if _, ok := fields["users"]; !ok {
		return v, errors.New("encrypted value missing users field")
	}
	data, ok := fields["data"]
	if !ok {
		return v, errors.New("encrypted value missing data field")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return v, fmt.Errorf("decode encrypted data: %w", err)
	}

	users := splitUsers(fields["users"])
	sort.Strings(users)
	return EncryptedValue{
		Kind:         kind,
		Algorithm:    parts[0],
		RecipientSet: fields["set"],
		Users:        users,
		Ciphertext:   ciphertext,
	}, nil
}

func Format(v EncryptedValue) string {
	prefix := "ENC"
	if v.Kind == Template {
		prefix = "ENC_TEMPLATE"
	}
	algorithm := v.Algorithm
	if algorithm == "" {
		algorithm = AlgorithmAgeV1
	}
	users := append([]string(nil), v.Users...)
	sort.Strings(users)
	return fmt.Sprintf("%s[%s;set=%s;users=%s;data=%s]",
		prefix,
		algorithm,
		v.RecipientSet,
		strings.Join(users, ","),
		base64.RawURLEncoding.EncodeToString(v.Ciphertext),
	)
}

func IsEncrypted(s string) bool {
	_, _, ok := encryptedBody(s)
	return ok
}

func encryptedBody(s string) (string, Kind, bool) {
	if strings.HasPrefix(s, "ENC_TEMPLATE[") && strings.HasSuffix(s, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(s, "ENC_TEMPLATE["), "]"), Template, true
	}
	if strings.HasPrefix(s, "ENC[") && strings.HasSuffix(s, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(s, "ENC["), "]"), Scalar, true
	}
	return "", "", false
}

func splitUsers(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
