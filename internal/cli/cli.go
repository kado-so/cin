package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"cin/internal/config"
	"cin/internal/cryptoage"
	"cin/internal/envelope"
	"cin/internal/resolve"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

const version = "0.0.0-dev"

func Run(args []string, stdout io.Writer, stderr io.Writer) int {
	cmd := NewRootCommand(stdout, stderr)
	cmd.SetArgs(args)

	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	return 0
}

func NewRootCommand(stdout io.Writer, stderr io.Writer) *cobra.Command {
	var showVersion bool
	var filePath string
	var localFile string
	var noLocal bool
	var user string

	root := &cobra.Command{
		Use:           "cin",
		Short:         "Encrypt app config in Git and inject it at runtime.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if showVersion {
				fmt.Fprintln(stdout, version)
				return nil
			}

			return cmd.Help()
		},
	}

	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetIn(os.Stdin)
	root.PersistentFlags().StringVarP(&filePath, "file", "f", "configs.secret.yaml", "config file")
	root.PersistentFlags().StringVar(&localFile, "local-file", "", "local override file")
	root.PersistentFlags().BoolVar(&noLocal, "no-local", false, "disable local override file")
	root.PersistentFlags().StringVar(&user, "user", "", "current cin user")
	root.Flags().BoolVarP(&showVersion, "version", "v", false, "show the cin version")

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Show the cin version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(stdout, version)
		},
	})

	root.AddCommand(newInitCommand(stdout, &filePath))
	root.AddCommand(newSetCommand(&filePath))
	root.AddCommand(newGetCommand(stdout, &filePath, &localFile, &noLocal, &user))
	root.AddCommand(newRenderCommand(stdout, &filePath, &localFile, &noLocal, &user))
	root.AddCommand(newExplainCommand(stdout, &filePath, &localFile, &noLocal, &user))

	return root
}

func newInitCommand(stdout io.Writer, filePath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "init <username>",
		Short: "Create a cin config file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			username := args[0]
			if _, err := os.Stat(*filePath); err == nil {
				return fmt.Errorf("config file already exists: %s", *filePath)
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}

			identity, err := cryptoage.EnsureIdentity(username)
			if err != nil {
				return err
			}
			doc := config.New(username, identity.Recipient().String())
			if err := doc.Save(*filePath); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "created %s\n", *filePath)
			return nil
		},
	}
}

func newSetCommand(filePath *string) *cobra.Command {
	var env string
	var app string
	var recipientSet string
	var prompt bool
	var fromStdin bool

	cmd := &cobra.Command{
		Use:   "set -e <env> [-a <app>] <key> [value]",
		Short: "Encrypt and set a config value",
		Args: func(cmd *cobra.Command, args []string) error {
			if prompt && fromStdin {
				return errors.New("use only one of --prompt or --stdin")
			}
			wantArgs := 2
			if prompt || fromStdin {
				wantArgs = 1
			}
			if len(args) != wantArgs {
				return fmt.Errorf("expected %d argument(s), got %d", wantArgs, len(args))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			doc, err := loadConfig(*filePath)
			if err != nil {
				return err
			}
			key := args[0]
			value := ""
			if prompt {
				value, err = readSecret(cmd)
			} else if fromStdin {
				value, err = readAllTrimRight(cmd.InOrStdin())
			} else {
				value = args[1]
			}
			if err != nil {
				return err
			}

			path, err := targetPath(env, app, key)
			if err != nil {
				return err
			}
			set, err := doc.RecipientSetForWrite(path, env, recipientSet)
			if err != nil {
				return err
			}
			recipients, err := doc.Recipients(set)
			if err != nil {
				return err
			}

			kind := envelope.Scalar
			if strings.Contains(value, "{{") && strings.Contains(value, "}}") {
				kind = envelope.Template
			}
			payload, err := encodePayload(kind, value)
			if err != nil {
				return err
			}
			ciphertext, err := cryptoage.Encrypt(payload, recipients.Recipients)
			if err != nil {
				return err
			}
			enc := envelope.Format(envelope.EncryptedValue{
				Kind:         kind,
				Algorithm:    envelope.AlgorithmAgeV1,
				RecipientSet: set,
				Users:        recipients.Users,
				Ciphertext:   ciphertext,
			})
			if err := doc.SetScalar(path, enc); err != nil {
				return err
			}
			return doc.Save(*filePath)
		},
	}
	cmd.Flags().StringVarP(&env, "env", "e", "", "environment")
	cmd.Flags().StringVarP(&app, "app", "a", "", "app")
	cmd.Flags().StringVar(&recipientSet, "recipient-set", "", "recipient set")
	cmd.Flags().BoolVar(&prompt, "prompt", false, "read value from prompt")
	cmd.Flags().BoolVar(&fromStdin, "stdin", false, "read value from stdin")
	return cmd
}

func newGetCommand(stdout io.Writer, filePath *string, localFile *string, noLocal *bool, user *string) *cobra.Command {
	var env string
	var app string
	var show bool

	cmd := &cobra.Command{
		Use:   "get -e <env> [-a <app>] <key>",
		Short: "Read a config value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			doc, err := loadConfig(*filePath)
			if err != nil {
				return err
			}
			key := args[0]
			path, err := targetPath(env, app, key)
			if err != nil {
				return err
			}
			resolved, err := resolvedEnv(doc, *localFile, *noLocal, env)
			if err != nil {
				return err
			}
			value, ok := config.ScalarIn(resolved, path[2:])
			if !ok {
				return missingValueError(doc, env, app, key)
			}
			if _, err := envelope.Parse(value); err != nil {
				return fmt.Errorf("%s is plaintext, but all config values must be encrypted", key)
			}
			if !show {
				fmt.Fprintf(stdout, "%s = [secret]\n", key)
				return nil
			}

			result, err := resolveResult(doc, *localFile, *noLocal, *user, env, app)
			if err != nil {
				return err
			}
			canonical := strings.Join(path[2:], ".")
			if err := result.Resolve(canonical); err != nil {
				return err
			}
			resolvedValue, ok := result.Value(canonical)
			if !ok {
				return missingValueError(doc, env, app, key)
			}
			fmt.Fprintf(stdout, "%s = %s\n", key, resolvedValue.Resolved)
			return nil
		},
	}
	cmd.Flags().StringVarP(&env, "env", "e", "", "environment")
	cmd.Flags().StringVarP(&app, "app", "a", "", "app")
	cmd.Flags().BoolVar(&show, "show", false, "show plaintext")
	return cmd
}

func newRenderCommand(stdout io.Writer, filePath *string, localFile *string, noLocal *bool, user *string) *cobra.Command {
	var env string
	var app string
	var show bool

	cmd := &cobra.Command{
		Use:   "render -e <env> -a <app>",
		Short: "Render resolved app config",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if env == "" {
				return errors.New("environment is required")
			}
			if app == "" {
				return errors.New("app is required")
			}
			doc, err := loadConfig(*filePath)
			if err != nil {
				return err
			}
			result, err := resolveResult(doc, *localFile, *noLocal, *user, env, app)
			if err != nil {
				return err
			}
			for _, key := range result.AppKeys() {
				canonical := resolve.CanonicalPath(app, key)
				if err := result.Resolve(canonical); err != nil {
					return err
				}
				value, _ := result.Value(canonical)
				if show {
					fmt.Fprintf(stdout, "%s=%s\n", key, value.Resolved)
				} else if value.Kind == envelope.Template {
					fmt.Fprintf(stdout, "%s=[secret template resolved]\n", key)
				} else {
					fmt.Fprintf(stdout, "%s=[secret]\n", key)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&env, "env", "e", "", "environment")
	cmd.Flags().StringVarP(&app, "app", "a", "", "app")
	cmd.Flags().BoolVar(&show, "show", false, "show plaintext")
	return cmd
}

func newExplainCommand(stdout io.Writer, filePath *string, localFile *string, noLocal *bool, user *string) *cobra.Command {
	var env string
	var app string

	cmd := &cobra.Command{
		Use:   "explain -e <env> [-a <app>] <key>",
		Short: "Explain a resolved config value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			doc, err := loadConfig(*filePath)
			if err != nil {
				return err
			}
			key := args[0]
			path, err := targetPath(env, app, key)
			if err != nil {
				return err
			}
			result, err := resolveResult(doc, *localFile, *noLocal, *user, env, app)
			if err != nil {
				return err
			}
			canonical := strings.Join(path[2:], ".")
			if err := result.Resolve(canonical); err != nil {
				return err
			}
			value, ok := result.Value(canonical)
			if !ok {
				return missingValueError(doc, env, app, key)
			}

			kind := "encrypted scalar"
			if value.Kind == envelope.Template {
				kind = "encrypted template"
			}
			fmt.Fprintln(stdout, key)
			fmt.Fprintf(stdout, "  source: envs.%s.%s\n", env, canonical)
			fmt.Fprintf(stdout, "  kind: %s\n", kind)
			fmt.Fprintf(stdout, "  recipientSet: %s\n", value.RecipientSet)
			if len(value.References) > 0 {
				fmt.Fprintln(stdout, "  references:")
				for _, ref := range value.References {
					fmt.Fprintf(stdout, "    %s ok secret\n", displayRef(app, ref))
				}
			}
			fmt.Fprintln(stdout, "  result: [secret]")
			return nil
		},
	}
	cmd.Flags().StringVarP(&env, "env", "e", "", "environment")
	cmd.Flags().StringVarP(&app, "app", "a", "", "app")
	return cmd
}

func loadConfig(path string) (*config.Document, error) {
	doc, err := config.Load(path)
	if err == nil {
		return doc, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("config file not found: %s\nfix: run `cin init <username>` or pass -f <file>", path)
	}
	return nil, err
}

func resolveResult(doc *config.Document, localFile string, noLocal bool, user string, env string, app string) (*resolve.Result, error) {
	resolved, err := resolvedEnv(doc, localFile, noLocal, env)
	if err != nil {
		return nil, err
	}
	currentUser, err := currentUser(user)
	if err != nil {
		return nil, err
	}
	identities, err := cryptoage.DiscoverIdentity(currentUser)
	if err != nil {
		return nil, err
	}
	return resolve.Env(resolved, app, identities)
}

func resolvedEnv(doc *config.Document, localFile string, noLocal bool, env string) (*yaml.Node, error) {
	resolved, err := doc.ResolvedEnv(env)
	if err != nil {
		return nil, err
	}
	localDoc, err := loadLocalConfig(localFile, noLocal)
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

func loadLocalConfig(path string, disabled bool) (*config.Document, error) {
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
	if errors.Is(err, os.ErrNotExist) && defaultPath {
		return nil, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("local config file not found: %s", path)
	}
	return nil, err
}

func targetPath(env, app, key string) ([]string, error) {
	if env == "" {
		return nil, errors.New("environment is required")
	}
	if optionPath, ok := config.OptionPath(key); ok {
		if app != "" {
			return nil, errors.New("option writes do not use -a")
		}
		return append([]string{"envs", env, "options"}, optionPath...), nil
	}
	if app == "" {
		return nil, errors.New("app value writes require -a <app>")
	}
	return []string{"envs", env, "apps", app, "values", key}, nil
}

func currentUser(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if user := os.Getenv("CIN_USER"); user != "" {
		return user, nil
	}
	return "", errors.New("current user is required\nfix: pass --user <username> or set CIN_USER")
}

func readSecret(cmd *cobra.Command) (string, error) {
	if f, ok := cmd.InOrStdin().(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		value, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(cmd.ErrOrStderr())
		return string(value), err
	}
	return readAllTrimRight(cmd.InOrStdin())
}

func readAllTrimRight(r io.Reader) (string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(data), "\r\n"), nil
}

func encodePayload(kind envelope.Kind, value string) ([]byte, error) {
	payloadType := "string"
	var payloadValue any = value
	if kind == envelope.Template {
		payloadType = "template"
	} else if decoded, typ, ok := decodeJSONScalar(value); ok {
		payloadType = typ
		payloadValue = decoded
	}
	return json.Marshal(map[string]any{
		"type":  payloadType,
		"value": payloadValue,
	})
}

func decodeJSONScalar(value string) (any, string, bool) {
	dec := json.NewDecoder(strings.NewReader(value))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, "", false
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, "", false
	}
	switch v.(type) {
	case bool:
		return v, "boolean", true
	case json.Number:
		return v, "number", true
	case []any:
		return v, "array", true
	case map[string]any:
		return v, "object", true
	default:
		return nil, "", false
	}
}

func displayRef(app string, ref string) string {
	prefix := "apps." + app + ".values."
	if strings.HasPrefix(ref, prefix) {
		return "values." + strings.TrimPrefix(ref, prefix)
	}
	return ref
}

func missingValueError(doc *config.Document, env, app, key string) error {
	if len(doc.EnvNames()) > 0 && !contains(doc.EnvNames(), env) {
		return fmt.Errorf("environment not found: %s\navailable: %s", env, strings.Join(doc.EnvNames(), ", "))
	}
	if app != "" {
		if apps := doc.AppNames(env); len(apps) > 0 && !contains(apps, app) {
			return fmt.Errorf("app not found in env %s: %s\navailable: %s", env, app, strings.Join(apps, ", "))
		}
	}
	return fmt.Errorf("value not found: %s", key)
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
