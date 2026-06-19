package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"cin/internal/config"
	"cin/internal/cryptoage"
	"cin/internal/envelope"
	"github.com/spf13/cobra"
	"golang.org/x/term"
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
	root.AddCommand(newGetCommand(stdout, &filePath, &user))

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

func newGetCommand(stdout io.Writer, filePath *string, user *string) *cobra.Command {
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
			value, ok := doc.GetScalar(path)
			if !ok {
				return missingValueError(doc, env, app, key)
			}
			enc, err := envelope.Parse(value)
			if err != nil {
				return fmt.Errorf("%s is plaintext, but all config values must be encrypted", key)
			}
			if !show {
				fmt.Fprintf(stdout, "%s = [secret]\n", key)
				return nil
			}

			currentUser, err := currentUser(*user)
			if err != nil {
				return err
			}
			identities, err := cryptoage.DiscoverIdentity(currentUser)
			if err != nil {
				return err
			}
			plaintext, err := cryptoage.Decrypt(enc.Ciphertext, identities)
			if err != nil {
				return fmt.Errorf("cannot decrypt %s with current identity", key)
			}
			rendered, err := decodePayload(plaintext)
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, "%s = %s\n", key, rendered)
			return nil
		},
	}
	cmd.Flags().StringVarP(&env, "env", "e", "", "environment")
	cmd.Flags().StringVarP(&app, "app", "a", "", "app")
	cmd.Flags().BoolVar(&show, "show", false, "show plaintext")
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

func decodePayload(data []byte) (string, error) {
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
