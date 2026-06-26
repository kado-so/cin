package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cin/internal/config"
	"cin/internal/resolve"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/yargevad/filepathx"
	"gopkg.in/yaml.v3"
)

type Set struct {
	Schemas    []AppSchema
	GlobErrors []GlobError
	LoadErrors []LoadError
}

type GlobError struct {
	Pattern string
}

type LoadError struct {
	Path string
	Err  error
}

type AppSchema struct {
	Path   string
	App    string
	Values map[string]any
	Envs   map[string]EnvSchema
}

type EnvSchema struct {
	Values map[string]any
}

type ValidationError struct {
	Path string
	Err  error
}

func Discover(doc *config.Document, configPath string) (*Set, error) {
	base := filepath.Dir(configPath)
	if base == "" {
		base = "."
	}
	out := &Set{}
	for _, pattern := range doc.ConfigSchemaGlobs() {
		matches, err := filepathx.Glob(filepath.Join(base, pattern))
		if err != nil {
			return nil, fmt.Errorf("invalid schema glob %s: %w", pattern, err)
		}
		if len(matches) == 0 {
			out.GlobErrors = append(out.GlobErrors, GlobError{Pattern: pattern})
			continue
		}
		sort.Strings(matches)
		for _, match := range matches {
			s, err := Load(match)
			if err != nil {
				out.LoadErrors = append(out.LoadErrors, LoadError{Path: filepath.ToSlash(match), Err: err})
				continue
			}
			out.Schemas = append(out.Schemas, s)
		}
	}
	return out, nil
}

func Load(path string) (AppSchema, error) {
	displayPath := filepath.ToSlash(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return AppSchema{}, err
	}
	var s AppSchema
	if err := yaml.Unmarshal(data, &s); err != nil {
		return AppSchema{}, fmt.Errorf("invalid schema file %s: %w", displayPath, err)
	}
	if s.App == "" {
		return AppSchema{}, fmt.Errorf("invalid schema file %s: app is required", displayPath)
	}
	s.Path = displayPath
	s.Values = normalizeMap(s.Values)
	for env, envSchema := range s.Envs {
		envSchema.Values = normalizeMap(envSchema.Values)
		s.Envs[env] = envSchema
	}
	return s, nil
}

func (s *Set) App(app string) *AppSchema {
	for i := range s.Schemas {
		if s.Schemas[i].App == app {
			return &s.Schemas[i]
		}
	}
	return nil
}

func (s AppSchema) Required(env string) []string {
	base := stringSlice(s.Values["required"])
	if envSchema, ok := s.Envs[env]; ok {
		base = append(base, stringSlice(envSchema.Values["required"])...)
	}
	sort.Strings(base)
	return compactStrings(base)
}

func (s AppSchema) Declares(key string) bool {
	props, _ := s.Values["properties"].(map[string]any)
	_, ok := props[key]
	return ok
}

func (s AppSchema) AdditionalPropertiesFalse() bool {
	v, ok := s.Values["additionalProperties"].(bool)
	return ok && !v
}

func ValidateResult(set *Set, env, app string, result *resolve.Result) []ValidationError {
	if set == nil {
		return nil
	}
	appSchema := set.App(app)
	if appSchema == nil {
		return nil
	}
	instance, err := instanceFromResult(result)
	if err != nil {
		return []ValidationError{{Path: appSchema.Path, Err: err}}
	}
	return validateInstance(*appSchema, env, instance)
}

func ValidateValues(appSchema AppSchema, env string, values map[string]any) []ValidationError {
	return validateInstance(appSchema, env, values)
}

func (s AppSchema) Compile(env string) error {
	_, err := s.compile(env)
	return err
}

func validateInstance(appSchema AppSchema, env string, values map[string]any) []ValidationError {
	compiled, err := appSchema.compile(env)
	if err != nil {
		return []ValidationError{{Path: appSchema.Path, Err: err}}
	}
	if err := compiled.Validate(values); err != nil {
		return validationErrors(appSchema.Path, err)
	}
	return nil
}

func validationErrors(path string, err error) []ValidationError {
	var schemaErr *jsonschema.ValidationError
	if !errors.As(err, &schemaErr) {
		return []ValidationError{{Path: path, Err: err}}
	}
	var leaves []*jsonschema.ValidationError
	collectValidationLeaves(&leaves, schemaErr)
	out := make([]ValidationError, 0, len(leaves))
	for _, leaf := range leaves {
		out = append(out, ValidationError{Path: path, Err: leaf})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Err.Error() < out[j].Err.Error()
	})
	return out
}

func collectValidationLeaves(out *[]*jsonschema.ValidationError, err *jsonschema.ValidationError) {
	if len(err.Causes) == 0 {
		*out = append(*out, err)
		return
	}
	for _, cause := range err.Causes {
		collectValidationLeaves(out, cause)
	}
}

func (s AppSchema) compile(env string) (*jsonschema.Schema, error) {
	values := cloneMap(s.Values)
	if envSchema, ok := s.Envs[env]; ok {
		values = mergeMap(values, envSchema.Values)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(s.Path, values); err != nil {
		return nil, err
	}
	return c.Compile(s.Path)
}

func instanceFromResult(result *resolve.Result) (map[string]any, error) {
	values := map[string]any{}
	for _, key := range result.AppKeys() {
		canonical := resolve.CanonicalPath(result.App, key)
		if err := result.Resolve(canonical); err != nil {
			return nil, err
		}
		value, _ := result.Value(canonical)
		v, err := typedValue(value)
		if err != nil {
			return nil, fmt.Errorf("%s cannot be converted to env var string: %w", key, err)
		}
		values[key] = v
	}
	return values, nil
}

func typedValue(value *resolve.Value) (any, error) {
	switch value.Type {
	case "number", "boolean", "array", "object":
		dec := json.NewDecoder(strings.NewReader(value.Resolved))
		dec.UseNumber()
		var out any
		if err := dec.Decode(&out); err != nil {
			return nil, err
		}
		return out, nil
	default:
		return value.Resolved, nil
	}
}

func normalizeMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := map[string]any{}
	for k, v := range m {
		out[k] = normalize(v)
	}
	return out
}

func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return normalizeMap(x)
	case map[any]any:
		out := map[string]any{}
		for k, v := range x {
			out[fmt.Sprint(k)] = normalize(v)
		}
		return out
	case []any:
		for i := range x {
			x[i] = normalize(x[i])
		}
	}
	return v
}

func cloneMap(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = cloneValue(v)
	}
	return out
}

func cloneValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return cloneMap(x)
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = cloneValue(x[i])
		}
		return out
	default:
		return v
	}
}

func mergeMap(base, overlay map[string]any) map[string]any {
	for k, v := range overlay {
		if k == "required" {
			base[k] = mergedRequired(base[k], v)
			continue
		}
		if left, ok := base[k].(map[string]any); ok {
			if right, ok := v.(map[string]any); ok {
				base[k] = mergeMap(cloneMap(left), right)
				continue
			}
		}
		base[k] = cloneValue(v)
	}
	return base
}

func mergedRequired(base, overlay any) []any {
	values := append(stringSlice(base), stringSlice(overlay)...)
	sort.Strings(values)
	values = compactStrings(values)
	out := make([]any, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}

func stringSlice(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func compactStrings(values []string) []string {
	out := values[:0]
	last := ""
	for _, value := range values {
		if value != "" && value != last {
			out = append(out, value)
		}
		last = value
	}
	return out
}
