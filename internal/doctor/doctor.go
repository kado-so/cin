package doctor

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"cin/internal/config"
	"cin/internal/cryptoage"
	"cin/internal/envelope"
	"cin/internal/resolve"
	cinschema "cin/internal/schema"
	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

type Options struct {
	FilePath  string
	LocalFile string
	NoLocal   bool
	User      string
	Env       string
	App       string
}

type Diagnostic struct {
	Category string
	Severity string
	Message  string
	Fix      string
	Path     string
}

func Run(stdout io.Writer, doc *config.Document, schemas *cinschema.Set, localDoc *config.Document, opt Options) bool {
	var diags []Diagnostic
	diags = append(diags, userDiagnostics(doc)...)
	diags = append(diags, recipientDiagnostics(doc)...)
	diags = append(diags, valueDiagnostics(doc, opt)...)
	diags = append(diags, inheritanceDiagnostics(doc, opt)...)
	diags = append(diags, localDiagnostics(localDoc, opt)...)
	diags = append(diags, schemaDiagnostics(doc, schemas, opt)...)
	diags = append(diags, keyConsistencyDiagnostics(doc, opt)...)
	diags = append(diags, decryptSkippedDiagnostics(doc, opt)...)
	diags = append(diags, runtimeDiagnostics(doc, localDoc, schemas, opt)...)
	print(stdout, diags)
	return hasSeverity(diags, "error")
}

func LoadLocal(path string, disabled bool) (*config.Document, error) {
	if disabled {
		return nil, nil
	}
	defaultPath := path == ""
	if defaultPath {
		path = "configs.local.secret.yaml"
	}
	doc, err := config.Load(path)
	if err == nil {
		return doc, nil
	}
	if os.IsNotExist(err) && defaultPath {
		return nil, nil
	}
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("local config file not found: %s", path)
	}
	return nil, err
}

func userDiagnostics(doc *config.Document) []Diagnostic {
	var out []Diagnostic
	for _, user := range doc.Users() {
		if user.Status == "pending" {
			out = append(out, Diagnostic{
				Category: "Users",
				Severity: "error",
				Message:  fmt.Sprintf("%s is pending and cannot decrypt existing values", user.Name),
				Fix:      fmt.Sprintf("cin users approve %s", user.Name),
			})
		}
		if doc.UserActive(user.Name) && len(user.RecipientSets) == 0 {
			out = append(out, Diagnostic{
				Category: "Users",
				Severity: "warn",
				Message:  fmt.Sprintf("%s is active but is not present in any recipient set", user.Name),
				Fix:      fmt.Sprintf("add %s to a recipient set or remove the user", user.Name),
			})
		}
		sets := doc.RecipientSetsForUser(user.Name)
		if user.Status == "pending" {
			if count := valueCountForSets(doc, sets); len(sets) > 1 || count >= 10 {
				out = append(out, Diagnostic{
					Category: "Recipients",
					Severity: "warn",
					Message:  fmt.Sprintf("approving %s would grant access to %d values through %d recipient sets", user.Name, count, len(sets)),
					Fix:      "review recipient set membership before approving the user",
				})
			}
		}
	}
	return out
}

func recipientDiagnostics(doc *config.Document) []Diagnostic {
	var out []Diagnostic
	for _, set := range doc.RecipientSetNames() {
		if _, err := doc.Recipients(set); err != nil {
			out = append(out, Diagnostic{
				Category: "Recipients",
				Severity: "error",
				Message:  err.Error(),
				Fix:      "add the missing user or remove it from the recipient set",
			})
		}
	}
	return out
}

func valueDiagnostics(doc *config.Document, opt Options) []Diagnostic {
	var out []Diagnostic
	for _, ref := range doc.ValueRefs() {
		if !matches(opt, ref.Env, ref.App) {
			continue
		}
		path := strings.Join(ref.Path, ".")
		enc, err := envelope.Parse(ref.Raw)
		if err != nil {
			severity := "error"
			if envelope.IsEncrypted(ref.Raw) {
				out = append(out, Diagnostic{Category: "Encryption", Severity: severity, Message: fmt.Sprintf("%s has malformed encrypted value metadata", path), Fix: "rewrite the value with cin set"})
			} else {
				kind := "value"
				if strings.Contains(ref.Raw, "{{") {
					kind = "template"
				}
				out = append(out, Diagnostic{Category: "Encryption", Severity: severity, Message: fmt.Sprintf("%s is plaintext %s", path, kind), Fix: "rewrite it with cin set"})
			}
			continue
		}
		recipients, err := doc.Recipients(enc.RecipientSet)
		if err != nil {
			out = append(out, Diagnostic{Category: "Encryption", Severity: "error", Message: fmt.Sprintf("%s references unknown recipient set %s", path, enc.RecipientSet), Fix: "create the recipient set or re-encrypt the value"})
			continue
		}
		if !sameStrings(enc.Users, recipients.Users) {
			out = append(out, Diagnostic{Category: "Encryption", Severity: "error", Message: fmt.Sprintf("%s recipient metadata does not match active users in recipient set %s", path, enc.RecipientSet), Fix: "rewrite or rekey the value"})
		}
	}

	current, identities := currentIdentities(opt.User)
	if current == "" || len(identities) == 0 {
		return out
	}
	for _, ref := range doc.EncryptedValues() {
		if !pathMatches(opt, ref.Path) || !contains(ref.Value.Users, current) {
			continue
		}
		if _, err := cryptoage.Decrypt(ref.Value.Ciphertext, identities); err != nil {
			out = append(out, Diagnostic{Category: "Runtime", Severity: "error", Message: fmt.Sprintf("current user cannot decrypt %s", strings.Join(ref.Path, ".")), Fix: "use the matching identity or rekey the value"})
		}
	}
	return out
}

func inheritanceDiagnostics(doc *config.Document, opt Options) []Diagnostic {
	var out []Diagnostic
	for _, env := range targetEnvs(doc, opt.Env) {
		if _, err := doc.ResolvedEnv(env); err != nil {
			out = append(out, Diagnostic{Category: "Env inheritance", Severity: "error", Message: err.Error(), Fix: "fix the env extends chain"})
		}
		parents, err := doc.EnvExtends(env)
		if err != nil {
			out = append(out, Diagnostic{Category: "Env inheritance", Severity: "error", Message: fmt.Sprintf("invalid extends for %s: %v", env, err), Fix: "use a string or list of env names"})
			continue
		}
		childDefault := doc.EnvDefaultRecipientSet(env)
		for _, parent := range parents {
			parentDefault := doc.EnvDefaultRecipientSet(parent)
			if childDefault != "" && parentDefault != "" && childDefault != parentDefault {
				out = append(out, Diagnostic{Category: "Env inheritance", Severity: "warn", Message: fmt.Sprintf("%s extends %s but default recipient sets differ", env, parent), Fix: "confirm the override or re-encrypt values with the intended recipient set"})
			}
		}
	}
	return out
}

func localDiagnostics(localDoc *config.Document, opt Options) []Diagnostic {
	if localDoc == nil {
		return nil
	}
	path := opt.LocalFile
	if path == "" {
		path = "configs.local.secret.yaml"
	}
	var out []Diagnostic
	for _, key := range localDoc.TopLevelKeys() {
		if key != "envs" {
			out = append(out, Diagnostic{Category: "Local overrides", Severity: "warn", Message: fmt.Sprintf("%s contains top-level %s, which is ignored", path, key), Fix: "local override files should contain only envs"})
		}
	}
	return out
}

func schemaDiagnostics(doc *config.Document, schemas *cinschema.Set, opt Options) []Diagnostic {
	if schemas == nil {
		return nil
	}
	var out []Diagnostic
	for _, err := range schemas.GlobErrors {
		out = append(out, Diagnostic{Category: "Schemas", Severity: "error", Message: fmt.Sprintf("schema glob %s matches no files", err.Pattern), Fix: "fix cin.configSchemas or add the schema file"})
	}
	for _, err := range schemas.LoadErrors {
		out = append(out, Diagnostic{Category: "Schemas", Severity: "error", Message: fmt.Sprintf("%s is invalid: %v", err.Path, err.Err), Fix: "fix the schema YAML"})
	}

	apps := configuredApps(doc)
	for _, appSchema := range schemas.Schemas {
		if opt.App != "" && appSchema.App != opt.App {
			continue
		}
		if !apps[appSchema.App] {
			out = append(out, Diagnostic{Category: "Schemas", Severity: "error", Message: fmt.Sprintf("%s references unknown app %s", appSchema.Path, appSchema.App), Fix: "set values for the app or fix the schema app name"})
		}
		for _, env := range targetEnvs(doc, opt.Env) {
			if opt.App != "" && opt.App != appSchema.App {
				continue
			}
			if err := appSchema.Compile(env); err != nil {
				out = append(out, Diagnostic{Category: "Schemas", Severity: "error", Message: fmt.Sprintf("%s is invalid for %s: %v", appSchema.Path, env, err), Fix: "fix the schema YAML"})
				continue
			}
			resolved, err := doc.ResolvedEnv(env)
			if err != nil {
				continue
			}
			for _, key := range appSchema.Required(env) {
				if _, ok := config.ScalarIn(resolved, []string{"apps", appSchema.App, "values", key}); !ok {
					out = append(out, Diagnostic{Category: "Schemas", Severity: "error", Message: fmt.Sprintf("%s requires %s, but %s/%s does not define it", appSchema.Path, key, env, appSchema.App), Fix: fmt.Sprintf("cin set -e %s -a %s %s <value>", env, appSchema.App, key)})
				}
			}
			if appSchema.AdditionalPropertiesFalse() {
				for _, key := range appKeys(resolved, appSchema.App) {
					if !appSchema.Declares(key) {
						out = append(out, Diagnostic{Category: "Schemas", Severity: "warn", Message: fmt.Sprintf("%s exists in %s/%s but is not declared by any schema", key, env, appSchema.App), Fix: "add it to the schema or remove it"})
					}
				}
			}
		}
	}
	return out
}

func keyConsistencyDiagnostics(doc *config.Document, opt Options) []Diagnostic {
	envs := targetEnvs(doc, opt.Env)
	if len(envs) < 2 {
		return nil
	}
	keysByAppEnv := map[string]map[string]map[string]bool{}
	for _, env := range envs {
		resolved, err := doc.ResolvedEnv(env)
		if err != nil {
			continue
		}
		for _, app := range targetApps(resolved, opt.App) {
			if keysByAppEnv[app] == nil {
				keysByAppEnv[app] = map[string]map[string]bool{}
			}
			keys := map[string]bool{}
			for _, key := range appKeys(resolved, app) {
				keys[key] = true
			}
			keysByAppEnv[app][env] = keys
		}
	}

	var out []Diagnostic
	for app, byEnv := range keysByAppEnv {
		all := map[string]bool{}
		for _, keys := range byEnv {
			for key := range keys {
				all[key] = true
			}
		}
		for key := range all {
			for _, env := range envs {
				keys := byEnv[env]
				if keys == nil || !keys[key] {
					out = append(out, Diagnostic{Category: "Values", Severity: "warn", Message: fmt.Sprintf("%s/%s is missing %s, which exists in another env for app %s", env, app, key, app), Fix: fmt.Sprintf("add %s to %s/%s or confirm the env-specific difference", key, env, app)})
				}
			}
		}
	}
	return out
}

func decryptSkippedDiagnostics(doc *config.Document, opt Options) []Diagnostic {
	if !hasDecryptTargets(doc, opt) {
		return nil
	}
	current, identities := currentIdentities(opt.User)
	if current == "" {
		return []Diagnostic{{Category: "Runtime", Severity: "info", Message: "decrypt-dependent checks were skipped because no current user is configured", Fix: "pass --user <username> or set CIN_USER"}}
	}
	if len(identities) == 0 {
		return []Diagnostic{{Category: "Runtime", Severity: "info", Message: fmt.Sprintf("decrypt-dependent checks were skipped because no identity was found for %s", current), Fix: "install the matching age identity or set CIN_AGE_KEY"}}
	}
	return nil
}

func hasDecryptTargets(doc *config.Document, opt Options) bool {
	for _, ref := range doc.ValueRefs() {
		if matches(opt, ref.Env, ref.App) {
			return true
		}
	}
	return false
}

func runtimeDiagnostics(doc, localDoc *config.Document, schemas *cinschema.Set, opt Options) []Diagnostic {
	var out []Diagnostic
	if opt.Env != "" && !doc.HasEnv(opt.Env) {
		out = append(out, Diagnostic{Category: "Values", Severity: "error", Message: fmt.Sprintf("selected env is missing: %s", opt.Env), Fix: "choose an existing env or add it"})
		return out
	}
	envs := targetEnvs(doc, opt.Env)
	current, identities := currentIdentities(opt.User)
	if current == "" || len(identities) == 0 {
		return out
	}
	for _, env := range envs {
		resolved, err := resolvedEnv(doc, localDoc, env)
		if err != nil {
			continue
		}
		apps := targetApps(resolved, opt.App)
		if opt.App != "" && len(apps) == 0 {
			out = append(out, Diagnostic{Category: "Values", Severity: "error", Message: fmt.Sprintf("selected app is missing: %s/%s", env, opt.App), Fix: "choose an existing app or add values for it"})
			continue
		}
		for _, app := range apps {
			result, err := resolve.Env(resolved, app, identities)
			if err != nil {
				out = append(out, Diagnostic{Category: "Runtime", Severity: "error", Message: err.Error(), Fix: "fix encrypted values"})
				continue
			}
			for _, key := range result.AppKeys() {
				if err := result.Resolve(resolve.CanonicalPath(app, key)); err != nil {
					out = append(out, templateDiagnostic(env, app, key, resolved, err))
				}
			}
			for _, err := range cinschema.ValidateResult(schemas, env, app, result) {
				out = append(out, Diagnostic{Category: "Schemas", Severity: "error", Message: fmt.Sprintf("%s failed for %s/%s: %v", err.Path, env, app, err.Err), Fix: "update the config value or schema"})
			}
		}
	}
	return out
}

func templateDiagnostic(env, app, key string, resolved *yaml.Node, err error) Diagnostic {
	where := fmt.Sprintf("%s/%s/%s", env, app, key)
	msg := err.Error()
	switch {
	case strings.Contains(msg, "missing template reference: apps."):
		ref := strings.TrimPrefix(after(msg, "missing template reference: "), "apps.")
		parts := strings.Split(ref, ".")
		if len(parts) >= 3 && parts[1] == "values" && len(appKeys(resolved, parts[0])) == 0 {
			return Diagnostic{Category: "Templates", Severity: "error", Message: fmt.Sprintf("%s references unknown app %s", where, parts[0]), Fix: "add the app values or fix the template reference"}
		}
		return Diagnostic{Category: "Templates", Severity: "error", Message: fmt.Sprintf("%s is missing template reference %s", where, after(msg, "missing template reference: ")), Fix: "set the referenced value or fix the template reference"}
	case strings.Contains(msg, "missing template reference:"):
		return Diagnostic{Category: "Templates", Severity: "error", Message: fmt.Sprintf("%s is missing template reference %s", where, after(msg, "missing template reference: ")), Fix: "set the referenced value or fix the template reference"}
	case strings.Contains(msg, "template cycle detected"):
		return Diagnostic{Category: "Templates", Severity: "error", Message: fmt.Sprintf("%s has a template cycle", where), Fix: "break the cycle between template references"}
	case strings.Contains(msg, "uses unsupported template syntax"):
		return Diagnostic{Category: "Templates", Severity: "error", Message: fmt.Sprintf("%s uses unsupported template syntax", where), Fix: "use only {{ .options.x }}, {{ .values.X }}, or {{ .apps.app.values.X }} lookups"}
	default:
		return Diagnostic{Category: "Templates", Severity: "error", Message: fmt.Sprintf("%s: %v", where, err), Fix: "fix the template reference or value"}
	}
}

func resolvedEnv(doc, localDoc *config.Document, env string) (*yaml.Node, error) {
	resolved, err := doc.ResolvedEnv(env)
	if err != nil {
		return nil, err
	}
	if localDoc == nil || !localDoc.HasEnv(env) {
		return resolved, nil
	}
	localResolved, err := localDoc.ResolvedEnv(env)
	if err != nil {
		return nil, err
	}
	return config.MergeEnv(resolved, localResolved), nil
}

func print(stdout io.Writer, diags []Diagnostic) {
	if len(diags) == 0 {
		fmt.Fprintln(stdout, "No issues found")
		return
	}
	order := []string{"Users", "Recipients", "Encryption", "Env inheritance", "Local overrides", "Schemas", "Templates", "Values", "Runtime"}
	byCategory := map[string][]Diagnostic{}
	for _, diag := range diags {
		byCategory[diag.Category] = append(byCategory[diag.Category], diag)
	}
	for _, category := range order {
		items := byCategory[category]
		if len(items) == 0 {
			continue
		}
		sort.SliceStable(items, func(i, j int) bool {
			if severityRank(items[i].Severity) != severityRank(items[j].Severity) {
				return severityRank(items[i].Severity) < severityRank(items[j].Severity)
			}
			return items[i].Message < items[j].Message
		})
		fmt.Fprintln(stdout, category)
		for _, item := range items {
			fmt.Fprintf(stdout, "  %s %s\n", item.Severity, item.Message)
			if item.Path != "" {
				fmt.Fprintf(stdout, "    path: %s\n", item.Path)
			}
			if item.Fix != "" {
				fmt.Fprintf(stdout, "    fix: %s\n", item.Fix)
			}
		}
	}
}

func currentIdentities(user string) (string, []age.Identity) {
	if user == "" {
		user = os.Getenv("CIN_USER")
	}
	if user == "" {
		return "", nil
	}
	identities, err := cryptoage.DiscoverIdentity(user)
	if err != nil {
		return user, nil
	}
	return user, identities
}

func targetEnvs(doc *config.Document, env string) []string {
	if env != "" {
		return []string{env}
	}
	return doc.EnvNames()
}

func targetApps(env *yaml.Node, app string) []string {
	if app != "" {
		if len(appKeys(env, app)) == 0 {
			return nil
		}
		return []string{app}
	}
	apps := lookup(env, []string{"apps"})
	if apps == nil || apps.Kind != yaml.MappingNode {
		return nil
	}
	out := make([]string, 0, len(apps.Content)/2)
	for i := 0; i < len(apps.Content); i += 2 {
		out = append(out, apps.Content[i].Value)
	}
	sort.Strings(out)
	return out
}

func configuredApps(doc *config.Document) map[string]bool {
	out := map[string]bool{}
	for _, env := range doc.EnvNames() {
		for _, app := range doc.AppNames(env) {
			out[app] = true
		}
	}
	return out
}

func appKeys(env *yaml.Node, app string) []string {
	values := lookup(env, []string{"apps", app, "values"})
	if values == nil || values.Kind != yaml.MappingNode {
		return nil
	}
	out := make([]string, 0, len(values.Content)/2)
	for i := 0; i < len(values.Content); i += 2 {
		out = append(out, values.Content[i].Value)
	}
	sort.Strings(out)
	return out
}

func matches(opt Options, env, app string) bool {
	if opt.Env != "" && opt.Env != env {
		return false
	}
	if opt.App != "" && opt.App != app {
		return false
	}
	return true
}

func pathMatches(opt Options, path []string) bool {
	if len(path) < 2 || path[0] != "envs" {
		return false
	}
	if opt.Env != "" && path[1] != opt.Env {
		return false
	}
	if opt.App == "" {
		return true
	}
	return len(path) >= 5 && path[2] == "apps" && path[3] == opt.App
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func hasSeverity(diags []Diagnostic, severity string) bool {
	for _, diag := range diags {
		if diag.Severity == severity {
			return true
		}
	}
	return false
}

func severityRank(severity string) int {
	switch severity {
	case "error":
		return 0
	case "warn":
		return 1
	case "info":
		return 2
	default:
		return 3
	}
}

func valueCountForSets(doc *config.Document, sets []string) int {
	if len(sets) == 0 {
		return 0
	}
	inSet := map[string]bool{}
	for _, set := range sets {
		inSet[set] = true
	}
	count := 0
	for _, ref := range doc.EncryptedValues() {
		if inSet[ref.Value.RecipientSet] {
			count++
		}
	}
	return count
}

func after(text, marker string) string {
	i := strings.Index(text, marker)
	if i < 0 {
		return text
	}
	return text[i+len(marker):]
}

func lookup(cur *yaml.Node, path []string) *yaml.Node {
	for _, key := range path {
		if cur == nil || cur.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for i := 0; i < len(cur.Content); i += 2 {
			if cur.Content[i].Value == key {
				next = cur.Content[i+1]
				break
			}
		}
		cur = next
	}
	return cur
}
