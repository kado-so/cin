package resolve

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/template/parse"

	"cin/internal/cryptoage"
	"cin/internal/envelope"
	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

type Value struct {
	Path         string
	App          string
	Raw          string
	Kind         envelope.Kind
	RecipientSet string
	Value        string
	Resolved     string
	References   []string
	decoded      bool
	resolved     bool
	template     *templatePlan
}

type Result struct {
	Values     map[string]*Value
	App        string
	Identities []age.Identity
}

type templatePlan struct {
	nodes []any
	refs  []string
}

type fieldRef struct {
	path string
}

func Env(env *yaml.Node, app string, identities []age.Identity) (*Result, error) {
	values := map[string]*Value{}
	if options := lookup(env, []string{"options"}); options != nil {
		if err := collect(values, options, []string{"options"}, ""); err != nil {
			return nil, err
		}
	}
	if apps := lookup(env, []string{"apps"}); apps != nil && apps.Kind == yaml.MappingNode {
		for i := 0; i < len(apps.Content); i += 2 {
			appName := apps.Content[i].Value
			appValues := lookup(apps.Content[i+1], []string{"values"})
			if appValues == nil {
				continue
			}
			if err := collect(values, appValues, []string{"apps", appName, "values"}, appName); err != nil {
				return nil, err
			}
		}
	}
	return &Result{Values: values, App: app, Identities: identities}, nil
}

func CanonicalPath(app, key string) string {
	if strings.HasPrefix(key, "options.") {
		return key
	}
	if strings.HasPrefix(key, "values.") {
		return "apps." + app + "." + key
	}
	if strings.HasPrefix(key, "apps.") {
		return key
	}
	return "apps." + app + ".values." + key
}

func (r *Result) AppKeys() []string {
	prefix := "apps." + r.App + ".values."
	keys := make([]string, 0)
	for path := range r.Values {
		if strings.HasPrefix(path, prefix) {
			keys = append(keys, strings.TrimPrefix(path, prefix))
		}
	}
	sort.Strings(keys)
	return keys
}

func (r *Result) Value(path string) (*Value, bool) {
	v, ok := r.Values[path]
	return v, ok
}

func (r *Result) Resolve(path string) error {
	_, err := r.resolve(path, nil)
	return err
}

func (r *Result) resolve(path string, stack []string) (string, error) {
	v, ok := r.Values[path]
	if !ok {
		return "", fmt.Errorf("missing template reference: %s", path)
	}
	if v.resolved {
		return v.Resolved, nil
	}
	if err := r.decode(v); err != nil {
		return "", err
	}
	if v.Kind != envelope.Template {
		v.Resolved = v.Value
		v.resolved = true
		return v.Resolved, nil
	}
	for i, seen := range stack {
		if seen == path {
			cycle := append(append([]string{}, stack[i:]...), path)
			return "", fmt.Errorf("template cycle detected\npath: %s", strings.Join(cycle, " -> "))
		}
	}
	if v.template == nil {
		app := r.App
		if v.App != "" {
			app = v.App
		}
		plan, err := parseTemplate(v.Value, app)
		if err != nil {
			return "", fmt.Errorf("%s uses unsupported template syntax: %w", v.Path, err)
		}
		v.template = plan
		v.References = plan.refs
	}
	var buf strings.Builder
	for _, n := range v.template.nodes {
		switch x := n.(type) {
		case string:
			buf.WriteString(x)
		case fieldRef:
			value, err := r.resolve(x.path, append(stack, path))
			if err != nil {
				return "", err
			}
			buf.WriteString(value)
		}
	}
	v.Resolved = buf.String()
	v.resolved = true
	return v.Resolved, nil
}

func (r *Result) decode(v *Value) error {
	if v.decoded {
		return nil
	}
	enc, err := envelope.Parse(v.Raw)
	if err != nil {
		return fmt.Errorf("%s is plaintext, but all config values must be encrypted", v.Path)
	}
	plaintext, err := cryptoage.Decrypt(enc.Ciphertext, r.Identities)
	if err != nil {
		return fmt.Errorf("cannot decrypt %s with current identity", v.Path)
	}
	value, err := DecodePayload(plaintext)
	if err != nil {
		return err
	}
	v.Kind = enc.Kind
	v.RecipientSet = enc.RecipientSet
	v.Value = value
	v.decoded = true
	return nil
}

func collect(values map[string]*Value, node *yaml.Node, path []string, app string) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			if err := collect(values, node.Content[i+1], append(path, node.Content[i].Value), app); err != nil {
				return err
			}
		}
		return nil
	}
	if node.Kind != yaml.ScalarNode {
		return nil
	}

	display := strings.Join(path, ".")
	values[display] = &Value{
		Path: display,
		App:  app,
		Raw:  node.Value,
	}
	return nil
}

func parseTemplate(text string, app string) (*templatePlan, error) {
	trees, err := parse.Parse("template", text, "", "", nil)
	if err != nil {
		return nil, err
	}
	tree := trees["template"]
	if tree == nil || tree.Root == nil {
		return nil, fmt.Errorf("empty template")
	}
	plan := &templatePlan{}
	for _, n := range tree.Root.Nodes {
		switch node := n.(type) {
		case *parse.TextNode:
			plan.nodes = append(plan.nodes, string(node.Text))
		case *parse.ActionNode:
			ref, err := actionRef(node, app)
			if err != nil {
				return nil, err
			}
			plan.nodes = append(plan.nodes, fieldRef{path: ref})
			plan.refs = append(plan.refs, ref)
		default:
			return nil, fmt.Errorf("only variable lookups are allowed")
		}
	}
	return plan, nil
}

func actionRef(node *parse.ActionNode, app string) (string, error) {
	if node.Pipe == nil || len(node.Pipe.Decl) > 0 || len(node.Pipe.Cmds) != 1 {
		return "", fmt.Errorf("pipelines are not allowed")
	}
	cmd := node.Pipe.Cmds[0]
	if len(cmd.Args) != 1 {
		return "", fmt.Errorf("functions are not allowed")
	}
	field, ok := cmd.Args[0].(*parse.FieldNode)
	if !ok {
		return "", fmt.Errorf("only field lookups are allowed")
	}
	if len(field.Ident) < 2 {
		return "", fmt.Errorf("field path is too short")
	}
	switch field.Ident[0] {
	case "options":
		return strings.Join(field.Ident, "."), nil
	case "values":
		return strings.Join(append([]string{"apps", app}, field.Ident...), "."), nil
	case "apps":
		if len(field.Ident) < 4 || field.Ident[2] != "values" {
			return "", fmt.Errorf("app references must use .apps.<app>.values.<key>")
		}
		return strings.Join(field.Ident, "."), nil
	default:
		return "", fmt.Errorf("unknown template root: %s", field.Ident[0])
	}
}

func DecodePayload(data []byte) (string, error) {
	var payload struct {
		Type  string          `json:"type"`
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", err
	}
	switch payload.Type {
	case "string", "template":
		var s string
		if err := json.Unmarshal(payload.Value, &s); err != nil {
			return "", err
		}
		return s, nil
	case "number", "boolean":
		return string(payload.Value), nil
	case "array", "object":
		var buf bytes.Buffer
		if err := json.Compact(&buf, payload.Value); err != nil {
			return "", err
		}
		return buf.String(), nil
	default:
		return "", fmt.Errorf("unknown payload type: %s", payload.Type)
	}
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
