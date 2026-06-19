package envelope

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseAndFormatEncryptedValue(t *testing.T) {
	ciphertext := []byte("ciphertext")
	input := "ENC[age-v1;set=team;users=vaishnav,alice;data=" + base64.RawURLEncoding.EncodeToString(ciphertext) + "]"

	value, err := Parse(input)
	if err != nil {
		t.Fatalf("parse encrypted value: %v", err)
	}
	if value.Kind != Scalar {
		t.Fatalf("expected scalar kind, got %q", value.Kind)
	}
	if value.RecipientSet != "team" {
		t.Fatalf("expected team recipient set, got %q", value.RecipientSet)
	}
	if got := strings.Join(value.Users, ","); got != "alice,vaishnav" {
		t.Fatalf("expected sorted users, got %q", got)
	}

	formatted := Format(value)
	want := "ENC[age-v1;set=team;users=alice,vaishnav;data=" + base64.RawURLEncoding.EncodeToString(ciphertext) + "]"
	if formatted != want {
		t.Fatalf("expected %q, got %q", want, formatted)
	}
}

func TestParseTemplateEncryptedValue(t *testing.T) {
	input := "ENC_TEMPLATE[age-v1;set=team;users=vaishnav;data=" + base64.RawURLEncoding.EncodeToString([]byte("ciphertext")) + "]"

	value, err := Parse(input)
	if err != nil {
		t.Fatalf("parse encrypted template: %v", err)
	}
	if value.Kind != Template {
		t.Fatalf("expected template kind, got %q", value.Kind)
	}
	if got := Format(value); !strings.HasPrefix(got, "ENC_TEMPLATE[age-v1;") {
		t.Fatalf("expected template format, got %q", got)
	}
}

func TestParseRejectsMalformedValues(t *testing.T) {
	tests := []string{
		"ENC[age-v2;set=team;users=vaishnav;data=abc]",
		"ENC[age-v1;users=vaishnav;data=abc]",
		"ENC[age-v1;set=team;users=vaishnav]",
		"ENC[age-v1;set=team;users=vaishnav;data=*]",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			if _, err := Parse(input); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}
