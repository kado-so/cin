// Story: a developer asks why an app value resolves the way it does across
// encrypted templates, inherited environments, and local overrides.
//
// Protects: explain must show dependency and source provenance for encrypted
// values without printing the resolved secret or any plaintext inputs.
package behavior

import (
	"os"
	"strings"
	"testing"

	"cin/internal/envelope"
)

func TestExplainProvenanceStory(t *testing.T) {
	story := NewStory(t)

	baseUser := "base-user-provenance-secret"
	sharedUser := "shared-user-provenance-secret"
	selectedHost := "selected-host-provenance-secret"
	localHost := "local-host-provenance-secret"
	selectedPort := "selected-port-provenance-secret"
	baseTemplate := "postgres://{{ .options.postgres.user }}@base-provenance.invalid/api"
	sharedTemplate := "postgres://{{ .options.postgres.user }}@{{ .options.postgres.host }}:{{ .options.postgres.port }}/api"
	secrets := []string{
		baseUser,
		sharedUser,
		selectedHost,
		localHost,
		selectedPort,
		"base-provenance.invalid",
		"postgres://",
	}

	story.OK(story.RunAs("vaishnav", "init", "vaishnav"))
	story.OK(story.RunAs("vaishnav", "set", "-e", "base", "options.postgres.user", baseUser))
	story.OK(story.RunAs("vaishnav", "set", "-e", "base", "-a", "api", "DATABASE_URL", baseTemplate))
	story.OK(story.RunAs("vaishnav", "set", "-e", "shared", "options.postgres.user", sharedUser))
	story.OK(story.RunAs("vaishnav", "set", "-e", "shared", "-a", "api", "DATABASE_URL", sharedTemplate))
	story.SetExtends(story.ConfigPath, "shared", "base")
	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "options.postgres.host", selectedHost))
	story.OK(story.RunAs("vaishnav", "set", "-e", "dev", "options.postgres.port", selectedPort))
	story.SetExtends(story.ConfigPath, "dev", "shared")

	story.OK(story.RunAs("vaishnav", "-f", story.LocalPath, "init", "vaishnav"))
	story.OK(story.RunAs("vaishnav", "-f", story.LocalPath, "set", "-e", "dev", "options.postgres.host", localHost))

	assertEncryptedKind(t, story.ConfigPath, envelope.Scalar, "envs", "base", "options", "postgres", "user")
	assertEncryptedKind(t, story.ConfigPath, envelope.Scalar, "envs", "shared", "options", "postgres", "user")
	assertEncryptedKind(t, story.ConfigPath, envelope.Scalar, "envs", "dev", "options", "postgres", "host")
	assertEncryptedKind(t, story.ConfigPath, envelope.Scalar, "envs", "dev", "options", "postgres", "port")
	assertEncryptedKind(t, story.ConfigPath, envelope.Template, "envs", "base", "apps", "api", "values", "DATABASE_URL")
	assertEncryptedKind(t, story.ConfigPath, envelope.Template, "envs", "shared", "apps", "api", "values", "DATABASE_URL")
	assertEncryptedKind(t, story.LocalPath, envelope.Scalar, "envs", "dev", "options", "postgres", "host")

	explain := story.OK(story.RunAs("vaishnav", "explain", "-e", "dev", "-a", "api", "DATABASE_URL"))
	for _, want := range []string{
		"source: envs.shared.apps.api.values.DATABASE_URL",
		"kind: encrypted template",
		"recipientSet: team",
		"layers:",
		"parent env envs.base.apps.api.values.DATABASE_URL overridden",
		"parent env envs.shared.apps.api.values.DATABASE_URL active",
		"references:",
		"options.postgres.user ok secret source: parent env envs.shared.options.postgres.user",
		"options.postgres.host ok secret source: local override local envs.dev.options.postgres.host",
		"options.postgres.port ok secret source: selected env envs.dev.options.postgres.port",
		"result: [secret]",
	} {
		if !strings.Contains(explain.Stdout, want) {
			t.Fatalf("expected explain output to contain %q, got %q", want, explain.Stdout)
		}
	}
	story.AssertNoPlaintext(explain.Combined(), secrets...)

	story.AssertNoPlaintext(story.ReadConfig(), secrets...)
	localData, err := os.ReadFile(story.LocalPath)
	if err != nil {
		t.Fatalf("read local config: %v", err)
	}
	story.AssertNoPlaintext(string(localData), secrets...)
}
