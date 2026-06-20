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

type User struct {
	Name          string
	Age           string
	Status        string
	ApprovedBy    []string
	RecipientSets []string
}

type EncryptedRef struct {
	Path  []string
	Value envelope.EncryptedValue
	Raw   string
}

type ValueRef struct {
	Env  string
	App  string
	Key  string
	Path []string
	Raw  string
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

func (d *Document) HasEnv(env string) bool {
	node := d.lookup([]string{"envs", env})
	return node != nil
}

func (d *Document) ResolvedEnv(env string) (*yaml.Node, error) {
	return d.resolveEnv(env, nil)
}

func MergeEnv(base, overlay *yaml.Node) *yaml.Node {
	return mergeNodes(base, overlay)
}

func ScalarIn(node *yaml.Node, path []string) (string, bool) {
	node = lookupNode(node, path)
	if node == nil || node.Kind != yaml.ScalarNode {
		return "", false
	}
	return node.Value, true
}

func (d *Document) SetScalar(path []string, value string) error {
	parent := d.ensureMap(path[:len(path)-1])
	setMap(parent, path[len(path)-1], scalar(value))
	return nil
}

func (d *Document) SetNode(path []string, value *yaml.Node) error {
	parent := d.ensureMap(path[:len(path)-1])
	setMap(parent, path[len(path)-1], cloneNode(value))
	return nil
}

func (d *Document) ReplaceRoot(value *yaml.Node) {
	d.root.Content = []*yaml.Node{cloneNode(value)}
}

func (d *Document) DeletePath(path []string) {
	if len(path) == 0 {
		return
	}
	parent := d.lookup(path[:len(path)-1])
	if parent == nil || parent.Kind != yaml.MappingNode {
		return
	}
	deleteMap(parent, path[len(path)-1])
}

func (d *Document) CloneNode(path []string) *yaml.Node {
	return cloneNode(d.lookup(path))
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

	activeUsers := make([]string, 0, len(users))
	recipients := make([]string, 0, len(users))
	for _, user := range users {
		key, ok := d.GetScalar([]string{"cin", "users", user, "age"})
		if !ok || key == "" {
			return RecipientSet{}, fmt.Errorf("recipient set %s references unknown user %s", set, user)
		}
		if !d.UserActive(user) {
			continue
		}
		activeUsers = append(activeUsers, user)
		recipients = append(recipients, key)
	}
	return RecipientSet{Users: activeUsers, Recipients: recipients}, nil
}

func (d *Document) AddUser(username, publicKey string) error {
	if username == "" {
		return errors.New("username is required")
	}
	if _, ok := d.GetScalar([]string{"cin", "users", username, "age"}); ok {
		return fmt.Errorf("user already exists: %s", username)
	}
	setMap(d.ensureMap([]string{"cin", "users"}), username, mapNode(
		pair("age", scalar(publicKey)),
		pair("status", scalar("pending")),
		pair("approvedBy", seqNode()),
	))
	if set, ok := d.GetScalar([]string{"cin", "defaults", "recipientSet"}); ok && set != "" {
		d.AddUserToRecipientSet(username, set)
	}
	return nil
}

func (d *Document) Users() []User {
	users := d.lookup([]string{"cin", "users"})
	if users == nil || users.Kind != yaml.MappingNode {
		return nil
	}
	out := make([]User, 0, len(users.Content)/2)
	for i := 0; i < len(users.Content); i += 2 {
		name := users.Content[i].Value
		out = append(out, User{
			Name:          name,
			Age:           scalarIn(users.Content[i+1], "age"),
			Status:        scalarIn(users.Content[i+1], "status"),
			ApprovedBy:    stringsIn(users.Content[i+1], "approvedBy"),
			RecipientSets: d.RecipientSetsForUser(name),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (d *Document) UserActive(username string) bool {
	if !d.UserExists(username) {
		return false
	}
	status := d.UserStatus(username)
	return status == "active" || status == ""
}

func (d *Document) UserExists(username string) bool {
	node := d.lookup([]string{"cin", "users", username})
	return node != nil && node.Kind == yaml.MappingNode
}

func (d *Document) UserStatus(username string) string {
	status, ok := d.GetScalar([]string{"cin", "users", username, "status"})
	if !ok {
		return ""
	}
	return status
}

func (d *Document) ApproveUser(username, approver string) error {
	user := d.lookup([]string{"cin", "users", username})
	if user == nil || user.Kind != yaml.MappingNode {
		return fmt.Errorf("user not found: %s", username)
	}
	setMap(user, "status", scalar("active"))
	approvedBy := getMap(user, "approvedBy")
	if approvedBy == nil || approvedBy.Kind != yaml.SequenceNode {
		approvedBy = seqNode()
		setMap(user, "approvedBy", approvedBy)
	}
	for _, n := range approvedBy.Content {
		if n.Kind == yaml.ScalarNode && n.Value == approver {
			return nil
		}
	}
	approvedBy.Content = append(approvedBy.Content, scalar(approver))
	return nil
}

func (d *Document) RecipientSetNames() []string {
	sets := d.lookup([]string{"cin", "recipientSets"})
	if sets == nil || sets.Kind != yaml.MappingNode {
		return nil
	}
	names := make([]string, 0, len(sets.Content)/2)
	for i := 0; i < len(sets.Content); i += 2 {
		names = append(names, sets.Content[i].Value)
	}
	sort.Strings(names)
	return names
}

func (d *Document) RecipientSetsForUser(username string) []string {
	var out []string
	for _, set := range d.RecipientSetNames() {
		users := d.lookup([]string{"cin", "recipientSets", set, "users"})
		if sequenceContains(users, username) {
			out = append(out, set)
		}
	}
	return out
}

func (d *Document) AddUserToRecipientSet(username, set string) {
	users := d.lookup([]string{"cin", "recipientSets", set, "users"})
	if users == nil || users.Kind != yaml.SequenceNode {
		users = seqNode()
		setMap(d.ensureMap([]string{"cin", "recipientSets", set}), "users", users)
	}
	if !sequenceContains(users, username) {
		users.Content = append(users.Content, scalar(username))
	}
}

func (d *Document) RemoveUser(username string) []string {
	sets := d.RecipientSetsForUser(username)
	for _, set := range sets {
		users := d.lookup([]string{"cin", "recipientSets", set, "users"})
		removeFromSequence(users, username)
	}
	deleteMap(d.ensureMap([]string{"cin", "users"}), username)
	return sets
}

func (d *Document) EncryptedValues() []EncryptedRef {
	var out []EncryptedRef
	collectEncrypted(&out, d.root.Content[0], nil)
	return out
}

func (d *Document) ValueRefs() []ValueRef {
	var out []ValueRef
	for _, env := range d.EnvNames() {
		envNode := d.lookup([]string{"envs", env})
		collectValueRefs(&out, envNode, []string{"options"}, env, "")
		apps := lookupNode(envNode, []string{"apps"})
		if apps == nil || apps.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i < len(apps.Content); i += 2 {
			app := apps.Content[i].Value
			collectValueRefs(&out, apps.Content[i+1], []string{"values"}, env, app)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.Join(out[i].Path, ".") < strings.Join(out[j].Path, ".")
	})
	return out
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

func (d *Document) ConfigSchemaGlobs() []string {
	return stringsIn(d.lookup([]string{"cin"}), "configSchemas")
}

func (d *Document) EnvExtends(env string) ([]string, error) {
	node := d.lookup([]string{"envs", env})
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, nil
	}
	return extendsList(node)
}

func (d *Document) EnvDefaultRecipientSet(env string) string {
	value, _ := d.GetScalar([]string{"envs", env, "defaults", "recipientSet"})
	return value
}

func (d *Document) DefaultEnv() string {
	value, _ := d.GetScalar([]string{"cin", "defaults", "env"})
	return value
}

func (d *Document) HasPath(path []string) bool {
	return d.lookup(path) != nil
}

func (d *Document) TopLevelKeys() []string {
	root := d.root.Content[0]
	if root == nil || root.Kind != yaml.MappingNode {
		return nil
	}
	keys := make([]string, 0, len(root.Content)/2)
	for i := 0; i < len(root.Content); i += 2 {
		keys = append(keys, root.Content[i].Value)
	}
	sort.Strings(keys)
	return keys
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
	return lookupNode(d.root.Content[0], path)
}

func (d *Document) resolveEnv(env string, stack []string) (*yaml.Node, error) {
	for i, name := range stack {
		if name == env {
			cycle := append(append([]string{}, stack[i:]...), env)
			return nil, fmt.Errorf("inheritance cycle detected: %s", strings.Join(cycle, " -> "))
		}
	}

	envNode := d.lookup([]string{"envs", env})
	if envNode == nil {
		if len(stack) > 0 {
			return nil, fmt.Errorf("environment parent not found: %s", env)
		}
		return nil, fmt.Errorf("environment not found: %s", env)
	}
	if envNode.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("environment must be a map: %s", env)
	}

	parents, err := extendsList(envNode)
	if err != nil {
		return nil, fmt.Errorf("invalid extends for %s: %w", env, err)
	}

	resolved := mapNode()
	for _, parent := range parents {
		parentNode, err := d.resolveEnv(parent, append(stack, env))
		if err != nil {
			return nil, err
		}
		resolved = mergeNodes(resolved, parentNode)
	}

	child := cloneNode(envNode)
	deleteMap(child, "extends")
	return mergeNodes(resolved, child), nil
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

func extendsList(env *yaml.Node) ([]string, error) {
	node := getMap(env, "extends")
	if node == nil {
		return nil, nil
	}
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Value == "" {
			return nil, nil
		}
		return []string{node.Value}, nil
	case yaml.SequenceNode:
		parents := make([]string, 0, len(node.Content))
		for _, child := range node.Content {
			if child.Kind != yaml.ScalarNode || child.Value == "" {
				return nil, errors.New("list entries must be non-empty strings")
			}
			parents = append(parents, child.Value)
		}
		return parents, nil
	default:
		return nil, errors.New("must be a string or list")
	}
}

func mergeNodes(base, overlay *yaml.Node) *yaml.Node {
	if base == nil {
		return cloneNode(overlay)
	}
	if overlay == nil {
		return cloneNode(base)
	}
	if base.Kind != yaml.MappingNode || overlay.Kind != yaml.MappingNode {
		return cloneNode(overlay)
	}

	merged := cloneNode(base)
	for i := 0; i < len(overlay.Content); i += 2 {
		key := overlay.Content[i].Value
		left := getMap(merged, key)
		right := overlay.Content[i+1]
		if left == nil {
			setMap(merged, key, cloneNode(right))
		} else {
			setMap(merged, key, mergeNodes(left, right))
		}
	}
	return merged
}

func cloneNode(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	clone := *node
	clone.Content = make([]*yaml.Node, len(node.Content))
	for i, child := range node.Content {
		clone.Content[i] = cloneNode(child)
	}
	return &clone
}

func lookupNode(cur *yaml.Node, path []string) *yaml.Node {
	for _, key := range path {
		if cur == nil || cur.Kind != yaml.MappingNode {
			return nil
		}
		cur = getMap(cur, key)
	}
	return cur
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

func deleteMap(m *yaml.Node, key string) {
	if m == nil || m.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
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

func scalarIn(node *yaml.Node, key string) string {
	child := getMap(node, key)
	if child == nil || child.Kind != yaml.ScalarNode {
		return ""
	}
	return child.Value
}

func stringsIn(node *yaml.Node, key string) []string {
	child := getMap(node, key)
	if child == nil || child.Kind != yaml.SequenceNode {
		return nil
	}
	values := make([]string, 0, len(child.Content))
	for _, n := range child.Content {
		if n.Kind == yaml.ScalarNode && n.Value != "" {
			values = append(values, n.Value)
		}
	}
	sort.Strings(values)
	return values
}

func sequenceContains(node *yaml.Node, value string) bool {
	if node == nil || node.Kind != yaml.SequenceNode {
		return false
	}
	for _, n := range node.Content {
		if n.Kind == yaml.ScalarNode && n.Value == value {
			return true
		}
	}
	return false
}

func removeFromSequence(node *yaml.Node, value string) {
	if node == nil || node.Kind != yaml.SequenceNode {
		return
	}
	out := node.Content[:0]
	for _, n := range node.Content {
		if n.Kind != yaml.ScalarNode || n.Value != value {
			out = append(out, n)
		}
	}
	node.Content = out
}

func collectEncrypted(out *[]EncryptedRef, node *yaml.Node, path []string) {
	if node == nil {
		return
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			collectEncrypted(out, node.Content[i+1], append(path, node.Content[i].Value))
		}
		return
	}
	if node.Kind != yaml.ScalarNode {
		return
	}
	value, err := envelope.Parse(node.Value)
	if err != nil {
		return
	}
	*out = append(*out, EncryptedRef{
		Path:  append([]string(nil), path...),
		Value: value,
		Raw:   node.Value,
	})
}

func collectValueRefs(out *[]ValueRef, node *yaml.Node, path []string, env, app string) {
	node = lookupNode(node, path)
	if node == nil {
		return
	}
	collectValueRefScalars(out, node, nil, env, app, path)
}

func collectValueRefScalars(out *[]ValueRef, node *yaml.Node, suffix []string, env, app string, root []string) {
	if node == nil {
		return
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			collectValueRefScalars(out, node.Content[i+1], append(suffix, node.Content[i].Value), env, app, root)
		}
		return
	}
	if node.Kind != yaml.ScalarNode {
		return
	}

	key := strings.Join(suffix, ".")
	path := append([]string{"envs", env}, root...)
	if app != "" {
		path = append([]string{"envs", env, "apps", app}, root...)
	}
	path = append(path, suffix...)
	*out = append(*out, ValueRef{Env: env, App: app, Key: key, Path: path, Raw: node.Value})
}
