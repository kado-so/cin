package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"cin/internal/envelope"
	"gopkg.in/yaml.v3"
)

type Document struct {
	root yaml.Node
}

type RecipientSet struct {
	Users      []string
	Recipients []string
}

func New(username, publicKey string) *Document {
	doc := &Document{root: yaml.Node{Kind: yaml.DocumentNode}}
	root := mapNode()
	doc.root.Content = []*yaml.Node{root}

	setMap(root, "cin", mapNode(
		pair("version", scalar("1")),
		pair("defaults", mapNode(pair("recipientSet", scalar("team")))),
		pair("users", mapNode(pair(username, mapNode(
			pair("age", scalar(publicKey)),
			pair("status", scalar("active")),
			pair("approvedBy", seqNode(scalar(username))),
		)))),
		pair("recipientSets", mapNode(pair("team", mapNode(
			pair("users", seqNode(scalar(username))),
		)))),
	))
	setMap(root, "envs", mapNode())
	return doc
}

func Load(path string) (*Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	if len(root.Content) == 0 {
		root.Content = []*yaml.Node{mapNode()}
	}
	if root.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("config root must be a map")
	}
	return &Document{root: root}, nil
}

func (d *Document) Save(path string) error {
	d.sort()
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&d.root); err != nil {
		enc.Close()
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

func (d *Document) SetOption(env string, optionPath []string, value string) error {
	if env == "" {
		return errors.New("environment is required")
	}
	if len(optionPath) == 0 {
		return errors.New("option path is required")
	}
	path := append([]string{"envs", env, "options"}, optionPath...)
	return d.SetScalar(path, value)
}

func (d *Document) SetAppValue(env, app, key string, value string) error {
	if env == "" {
		return errors.New("environment is required")
	}
	if app == "" {
		return errors.New("app is required")
	}
	if key == "" {
		return errors.New("value key is required")
	}
	return d.SetScalar([]string{"envs", env, "apps", app, "values", key}, value)
}

func (d *Document) GetOption(env string, optionPath []string) (string, bool) {
	if len(optionPath) == 0 {
		return "", false
	}
	return d.GetScalar(append([]string{"envs", env, "options"}, optionPath...))
}

func (d *Document) GetAppValue(env, app, key string) (string, bool) {
	return d.GetScalar([]string{"envs", env, "apps", app, "values", key})
}

func (d *Document) SetScalar(path []string, value string) error {
	parent := d.ensureMap(path[:len(path)-1])
	setMap(parent, path[len(path)-1], scalar(value))
	return nil
}

func (d *Document) GetScalar(path []string) (string, bool) {
	node := d.lookup(path)
	if node == nil || node.Kind != yaml.ScalarNode {
		return "", false
	}
	return node.Value, true
}

func (d *Document) ExistingEncrypted(path []string) (envelope.EncryptedValue, bool) {
	value, ok := d.GetScalar(path)
	if !ok {
		return envelope.EncryptedValue{}, false
	}
	enc, err := envelope.Parse(value)
	return enc, err == nil
}

func (d *Document) RecipientSetForWrite(path []string, env, override string) (string, error) {
	if override != "" {
		return override, nil
	}
	if enc, ok := d.ExistingEncrypted(path); ok && enc.RecipientSet != "" {
		return enc.RecipientSet, nil
	}
	if set, ok := d.GetScalar([]string{"envs", env, "defaults", "recipientSet"}); ok && set != "" {
		return set, nil
	}
	if set, ok := d.GetScalar([]string{"cin", "defaults", "recipientSet"}); ok && set != "" {
		return set, nil
	}
	return "", errors.New("recipient set is required")
}

func (d *Document) Recipients(set string) (RecipientSet, error) {
	userNodes := d.lookup([]string{"cin", "recipientSets", set, "users"})
	if userNodes == nil || userNodes.Kind != yaml.SequenceNode {
		return RecipientSet{}, fmt.Errorf("recipient set not found: %s", set)
	}

	users := make([]string, 0, len(userNodes.Content))
	for _, n := range userNodes.Content {
		if n.Kind == yaml.ScalarNode && n.Value != "" {
			users = append(users, n.Value)
		}
	}
	sort.Strings(users)

	recipients := make([]string, 0, len(users))
	for _, user := range users {
		key, ok := d.GetScalar([]string{"cin", "users", user, "age"})
		if !ok || key == "" {
			return RecipientSet{}, fmt.Errorf("recipient set %s references unknown user %s", set, user)
		}
		recipients = append(recipients, key)
	}
	return RecipientSet{Users: users, Recipients: recipients}, nil
}

func (d *Document) EnvNames() []string {
	envs := d.lookup([]string{"envs"})
	if envs == nil || envs.Kind != yaml.MappingNode {
		return nil
	}
	names := make([]string, 0, len(envs.Content)/2)
	for i := 0; i < len(envs.Content); i += 2 {
		names = append(names, envs.Content[i].Value)
	}
	sort.Strings(names)
	return names
}

func (d *Document) AppNames(env string) []string {
	apps := d.lookup([]string{"envs", env, "apps"})
	if apps == nil || apps.Kind != yaml.MappingNode {
		return nil
	}
	names := make([]string, 0, len(apps.Content)/2)
	for i := 0; i < len(apps.Content); i += 2 {
		names = append(names, apps.Content[i].Value)
	}
	sort.Strings(names)
	return names
}

func OptionPath(key string) ([]string, bool) {
	if !strings.HasPrefix(key, "options.") {
		return nil, false
	}
	parts := strings.Split(strings.TrimPrefix(key, "options."), ".")
	for _, part := range parts {
		if part == "" {
			return nil, false
		}
	}
	return parts, true
}

func (d *Document) ensureMap(path []string) *yaml.Node {
	cur := d.root.Content[0]
	for _, key := range path {
		next := getMap(cur, key)
		if next == nil || next.Kind != yaml.MappingNode {
			next = mapNode()
			setMap(cur, key, next)
		}
		cur = next
	}
	return cur
}

func (d *Document) lookup(path []string) *yaml.Node {
	cur := d.root.Content[0]
	for _, key := range path {
		if cur == nil || cur.Kind != yaml.MappingNode {
			return nil
		}
		cur = getMap(cur, key)
	}
	return cur
}

func (d *Document) sort() {
	normalizeNode(d.root.Content[0])
}

func normalizeNode(n *yaml.Node) {
	if n == nil {
		return
	}
	if n.Kind == yaml.MappingNode {
		n.Style = 0
		for i := 1; i < len(n.Content); i += 2 {
			normalizeNode(n.Content[i])
		}
		pairs := make([][2]*yaml.Node, 0, len(n.Content)/2)
		for i := 0; i < len(n.Content); i += 2 {
			pairs = append(pairs, [2]*yaml.Node{n.Content[i], n.Content[i+1]})
		}
		sort.SliceStable(pairs, func(i, j int) bool {
			return pairs[i][0].Value < pairs[j][0].Value
		})
		n.Content = n.Content[:0]
		for _, pair := range pairs {
			n.Content = append(n.Content, pair[0], pair[1])
		}
		return
	}
	if n.Kind == yaml.SequenceNode {
		n.Style = 0
	}
	for _, child := range n.Content {
		normalizeNode(child)
	}
}

func getMap(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func setMap(m *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = value
			return
		}
	}
	m.Content = append(m.Content, scalar(key), value)
}

func mapNode(pairs ...[2]*yaml.Node) *yaml.Node {
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, pair := range pairs {
		n.Content = append(n.Content, pair[0], pair[1])
	}
	return n
}

func seqNode(values ...*yaml.Node) *yaml.Node {
	return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: values}
}

func scalar(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

func pair(key string, value *yaml.Node) [2]*yaml.Node {
	return [2]*yaml.Node{scalar(key), value}
}
