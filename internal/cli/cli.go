package cli

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"

	"cin/internal/config"
	"cin/internal/cryptoage"
	"cin/internal/doctor"
	"cin/internal/envelope"
	"cin/internal/resolve"
	cinschema "cin/internal/schema"
	"filippo.io/age"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

const version = "0.0.0-dev"

func Run(args []string, stdout io.Writer, stderr io.Writer) int {
	cmd := NewRootCommand(stdout, stderr)
	cmd.SetArgs(args)

	if err := cmd.Execute(); err != nil {
		var exitErr commandExitError
		if errors.As(err, &exitErr) {
			return exitErr.code
		}
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
	root.AddCommand(newRunCommand(stdout, stderr, &filePath, &localFile, &noLocal, &user))
	root.AddCommand(newExportCommand(stdout, &filePath, &localFile, &noLocal, &user))
	root.AddCommand(newEditCommand(&filePath, &user))
	root.AddCommand(newRenderCommand(stdout, &filePath, &localFile, &noLocal, &user))
	root.AddCommand(newExplainCommand(stdout, &filePath, &localFile, &noLocal, &user))
	root.AddCommand(newUsersCommand(stdout, stderr, &filePath, &user))
	root.AddCommand(newDoctorCommand(stdout, &filePath, &localFile, &noLocal, &user))

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

func newUsersCommand(stdout io.Writer, stderr io.Writer, filePath *string, user *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "users",
		Short: "Manage cin users",
	}
	cmd.AddCommand(newUsersAddCommand(stdout, filePath))
	cmd.AddCommand(newUsersListCommand(stdout, filePath))
	cmd.AddCommand(newUsersApproveCommand(stdout, filePath, user))
	cmd.AddCommand(newUsersRemoveCommand(stderr, filePath, user))
	return cmd
}

func newUsersAddCommand(stdout io.Writer, filePath *string) *cobra.Command {
	var publicKey string
	cmd := &cobra.Command{
		Use:   "add <username>",
		Short: "Add a pending user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			doc, err := loadConfig(*filePath)
			if err != nil {
				return err
			}
			username := args[0]
			if publicKey == "" {
				identity, err := cryptoage.EnsureLocalIdentity(username)
				if err != nil {
					return err
				}
				publicKey = identity.Recipient().String()
			}
			if err := doc.AddUser(username, publicKey); err != nil {
				return err
			}
			if err := doc.Save(*filePath); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "added pending user %s\n", username)
			return nil
		},
	}
	cmd.Flags().StringVar(&publicKey, "age", "", "age public key")
	return cmd
}

func newUsersListCommand(stdout io.Writer, filePath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List cin users",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			doc, err := loadConfig(*filePath)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "USER\tSTATUS\tFINGERPRINT\tRECIPIENT_SETS")
			for _, user := range doc.Users() {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
					user.Name,
					user.Status,
					fingerprint(user.Age),
					strings.Join(user.RecipientSets, ","),
				)
			}
			return w.Flush()
		},
	}
}

func newUsersApproveCommand(stdout io.Writer, filePath *string, user *string) *cobra.Command {
	return &cobra.Command{
		Use:   "approve <username>",
		Short: "Approve a pending user and rekey affected values",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			doc, err := loadConfig(*filePath)
			if err != nil {
				return err
			}
			current, identities, err := rekeyOperator(doc, *user)
			if err != nil {
				return err
			}
			username := args[0]
			if !doc.UserExists(username) {
				return fmt.Errorf("user not found: %s", username)
			}
			sets := doc.RecipientSetsForUser(username)
			counts := impactCounts(doc, sets)
			printApprovalSummary(stdout, username, sets, counts)
			confirmation, err := readApproval(cmd.InOrStdin())
			if err != nil {
				return err
			}
			if confirmation != "approve" {
				return errors.New("approval cancelled")
			}
			if err := doc.ApproveUser(username, current); err != nil {
				return err
			}
			if _, err := rekey(doc, identities, sets); err != nil {
				return err
			}
			return doc.Save(*filePath)
		},
	}
}

func newUsersRemoveCommand(stderr io.Writer, filePath *string, user *string) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <username>",
		Short: "Remove a user from recipient sets and rekey",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			doc, err := loadConfig(*filePath)
			if err != nil {
				return err
			}
			_, identities, err := rekeyOperator(doc, *user)
			if err != nil {
				return err
			}
			username := args[0]
			if !doc.UserExists(username) {
				return fmt.Errorf("user not found: %s", username)
			}
			sets := doc.RemoveUser(username)
			fmt.Fprintf(stderr, "warning: removing %s prevents future decryption after rekey\n", username)
			fmt.Fprintln(stderr, "warning: this cannot revoke plaintext already copied locally or secrets present in Git history")
			fmt.Fprintf(stderr, "fix: rotate affected secrets if %s may have accessed them\n", username)
			if _, err := rekey(doc, identities, sets); err != nil {
				return err
			}
			return doc.Save(*filePath)
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

func newRunCommand(stdout io.Writer, stderr io.Writer, filePath *string, localFile *string, noLocal *bool, user *string) *cobra.Command {
	var env string
	var app string

	cmd := &cobra.Command{
		Use:   "run -e <env> -a <app> -- <command>",
		Short: "Run a command with resolved app config",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if env == "" {
				return errors.New("environment is required")
			}
			if app == "" {
				return errors.New("cin run requires -a <app>\nfix: rerun with -a api")
			}
			envVars, err := resolvedAppEnv(*filePath, *localFile, *noLocal, *user, env, app)
			if err != nil {
				return err
			}
			code, err := runChild(args, envVars, cmd.InOrStdin(), stdout, stderr)
			if err != nil {
				return err
			}
			if code != 0 {
				return commandExitError{code: code}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&env, "env", "e", "", "environment")
	cmd.Flags().StringVarP(&app, "app", "a", "", "app")
	return cmd
}

func newExportCommand(stdout io.Writer, filePath *string, localFile *string, noLocal *bool, user *string) *cobra.Command {
	var env string
	var app string
	var format string
	var out string
	var yes bool

	cmd := &cobra.Command{
		Use:   "export -e <env> -a <app>",
		Short: "Export resolved app config",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if env == "" {
				return errors.New("environment is required")
			}
			if app == "" {
				return errors.New("cin export requires -a <app>\nfix: rerun with -a api")
			}
			if out != "" && !yes {
				return fmt.Errorf("refusing to write plaintext secrets to %s without confirmation\nfix: rerun with --yes", out)
			}
			envVars, err := resolvedAppEnv(*filePath, *localFile, *noLocal, *user, env, app)
			if err != nil {
				return err
			}
			data, err := formatExport(envVars, format)
			if err != nil {
				return err
			}
			if out == "" {
				_, err = stdout.Write(data)
				return err
			}
			return writeSecretFile(out, data)
		},
	}
	cmd.Flags().StringVarP(&env, "env", "e", "", "environment")
	cmd.Flags().StringVarP(&app, "app", "a", "", "app")
	cmd.Flags().StringVar(&format, "format", "dotenv", "output format: dotenv or json")
	cmd.Flags().StringVar(&out, "out", "", "write output to file")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm plaintext file output")
	return cmd
}

func newEditCommand(filePath *string, user *string) *cobra.Command {
	var env string
	var app string

	cmd := &cobra.Command{
		Use:   "edit -e <env> -a <app>",
		Short: "Edit app config values in a secure temp file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if env == "" {
				return errors.New("environment is required")
			}
			if app == "" {
				return errors.New("app is required")
			}
			editor, err := editCommand()
			if err != nil {
				return err
			}
			doc, err := loadConfig(*filePath)
			if err != nil {
				return err
			}
			current, err := currentUser(*user)
			if err != nil {
				return err
			}
			identities, err := cryptoage.DiscoverIdentity(current)
			if err != nil {
				return err
			}
			session, err := buildEditSession(doc, env, app, identities)
			if err != nil {
				return err
			}
			if len(session.Values) == 0 {
				return fmt.Errorf("no editable values found for env %s app %s", env, app)
			}
			data, err := renderEditSession(session)
			if err != nil {
				return err
			}
			tmp, cleanup, err := secureTempFile("config-*.yaml")
			if err != nil {
				return err
			}
			tmpPath := tmp.Name()
			defer cleanup()
			if _, err := tmp.Write(data); err != nil {
				tmp.Close()
				return err
			}
			if err := tmp.Close(); err != nil {
				return err
			}
			if err := runEditor(editor, tmpPath, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
				return err
			}
			editedData, err := os.ReadFile(tmpPath)
			if err != nil {
				return err
			}
			edited, err := parseEditDocument(editedData)
			if err != nil {
				return err
			}
			changed, err := applyEditSession(doc, env, session, edited)
			if err != nil {
				return err
			}
			if !changed {
				return nil
			}
			if err := validateEditedDoc(doc, *filePath, env, app, identities); err != nil {
				return err
			}
			return doc.Save(*filePath)
		},
	}
	cmd.Flags().StringVarP(&env, "env", "e", "", "environment")
	cmd.Flags().StringVarP(&app, "app", "a", "", "app")
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

func newDoctorCommand(stdout io.Writer, filePath *string, localFile *string, noLocal *bool, user *string) *cobra.Command {
	var env string
	var app string

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check config health",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			doc, err := loadConfig(*filePath)
			if err != nil {
				return err
			}
			localDoc, err := doctor.LoadLocal(*localFile, *noLocal)
			if err != nil {
				return err
			}
			schemas, err := cinschema.Discover(doc, *filePath)
			if err != nil {
				return err
			}
			hasErrors := doctor.Run(stdout, doc, schemas, localDoc, doctor.Options{
				FilePath:  *filePath,
				LocalFile: *localFile,
				NoLocal:   *noLocal,
				User:      *user,
				Env:       env,
				App:       app,
			})
			if hasErrors {
				return commandExitError{code: 1}
			}
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

func resolvedAppEnv(filePath string, localFile string, noLocal bool, user string, env string, app string) (map[string]string, error) {
	doc, err := loadConfig(filePath)
	if err != nil {
		return nil, err
	}
	result, err := resolveResult(doc, localFile, noLocal, user, env, app)
	if err != nil {
		return nil, err
	}
	schemas, err := cinschema.Discover(doc, filePath)
	if err != nil {
		return nil, err
	}
	if len(schemas.LoadErrors) > 0 {
		return nil, fmt.Errorf("schema file is invalid: %s: %v", schemas.LoadErrors[0].Path, schemas.LoadErrors[0].Err)
	}
	if errs := cinschema.ValidateResult(schemas, env, app, result); len(errs) > 0 {
		return nil, fmt.Errorf("schema validation failed: %s", errs[0].Err)
	}
	return appEnv(result, app)
}

func appEnv(result *resolve.Result, app string) (map[string]string, error) {
	envVars := map[string]string{}
	for _, key := range result.AppKeys() {
		canonical := resolve.CanonicalPath(app, key)
		if err := result.Resolve(canonical); err != nil {
			return nil, err
		}
		value, _ := result.Value(canonical)
		envVars[key] = value.Resolved
	}
	return envVars, nil
}

func formatExport(envVars map[string]string, format string) ([]byte, error) {
	switch format {
	case "dotenv":
		var b strings.Builder
		for _, key := range sortedKeys(envVars) {
			fmt.Fprintf(&b, "%s=%s\n", key, dotenvValue(envVars[key]))
		}
		return []byte(b.String()), nil
	case "json":
		data, err := json.MarshalIndent(envVars, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(data, '\n'), nil
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

func dotenvValue(value string) string {
	if value == "" || strings.ContainsAny(value, " \t\r\n\"'#$") {
		return strconv.Quote(value)
	}
	return value
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func writeSecretFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

type editSession struct {
	Values  map[string]editEntry
	Options map[string]editEntry
}

type editEntry struct {
	Path   []string
	Value  string
	Exists bool
}

type editDocument struct {
	Values  map[string]string
	Options map[string]string
}

func buildEditSession(doc *config.Document, env, app string, identities []age.Identity) (*editSession, error) {
	resolved, err := doc.ResolvedEnv(env)
	if err != nil {
		return nil, err
	}
	result, err := resolve.Env(resolved, app, identities)
	if err != nil {
		return nil, err
	}

	session := &editSession{
		Values:  map[string]editEntry{},
		Options: map[string]editEntry{},
	}
	var refs []string
	for _, key := range result.AppKeys() {
		canonical := resolve.CanonicalPath(app, key)
		value, ok := result.Value(canonical)
		if !ok {
			continue
		}
		plaintext, kind, decryptable, err := editablePlaintext(value.Raw, canonical, identities)
		if err != nil {
			return nil, err
		}
		if !decryptable {
			continue
		}
		session.Values[key] = editEntry{
			Path:   []string{"envs", env, "apps", app, "values", key},
			Value:  plaintext,
			Exists: true,
		}
		if kind == envelope.Template {
			more, err := resolve.TemplateReferences(plaintext, app)
			if err != nil {
				return nil, fmt.Errorf("%s uses unsupported template syntax: %w", canonical, err)
			}
			refs = append(refs, more...)
		}
	}

	seen := map[string]bool{}
	for len(refs) > 0 {
		ref := refs[0]
		refs = refs[1:]
		if seen[ref] || !strings.HasPrefix(ref, "options.") {
			continue
		}
		seen[ref] = true
		optionPath, ok := config.OptionPath(ref)
		if !ok {
			continue
		}
		value, ok := result.Value(ref)
		if !ok {
			session.Options[ref] = editEntry{
				Path:   append([]string{"envs", env, "options"}, optionPath...),
				Value:  "",
				Exists: false,
			}
			continue
		}
		plaintext, kind, decryptable, err := editablePlaintext(value.Raw, ref, identities)
		if err != nil {
			return nil, err
		}
		if !decryptable {
			continue
		}
		session.Options[ref] = editEntry{
			Path:   append([]string{"envs", env, "options"}, optionPath...),
			Value:  plaintext,
			Exists: true,
		}
		if kind == envelope.Template {
			more, err := resolve.TemplateReferences(plaintext, app)
			if err != nil {
				return nil, fmt.Errorf("%s uses unsupported template syntax: %w", ref, err)
			}
			refs = append(refs, more...)
		}
	}
	return session, nil
}

func editablePlaintext(raw, path string, identities []age.Identity) (string, envelope.Kind, bool, error) {
	enc, err := envelope.Parse(raw)
	if err != nil {
		return "", "", false, fmt.Errorf("%s is plaintext, but all config values must be encrypted", path)
	}
	plaintext, err := cryptoage.Decrypt(enc.Ciphertext, identities)
	if err != nil {
		return "", "", false, nil
	}
	value, _, err := resolve.DecodePayloadTyped(plaintext)
	if err != nil {
		return "", "", false, fmt.Errorf("cannot decode %s", path)
	}
	return value, enc.Kind, true, nil
}

func renderEditSession(session *editSession) ([]byte, error) {
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	values := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, key := range sortedEditKeys(session.Values) {
		values.Content = append(values.Content, yamlScalar(key), yamlScalar(session.Values[key].Value))
	}
	root.Content = append(root.Content, yamlScalar("values"), values)

	if len(session.Options) > 0 {
		options := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		for _, key := range sortedEditKeys(session.Options) {
			path, _ := config.OptionPath(key)
			setYAMLPath(options, path, yamlScalar(session.Options[key].Value))
		}
		root.Content = append(root.Content, yamlScalar("options"), options)
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		enc.Close()
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parseEditDocument(data []byte) (editDocument, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return editDocument{}, fmt.Errorf("edited document is not valid YAML")
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return editDocument{}, errors.New("edited document must be a map")
	}
	out := editDocument{
		Values:  map[string]string{},
		Options: map[string]string{},
	}
	for i := 0; i < len(root.Content[0].Content); i += 2 {
		key := root.Content[0].Content[i].Value
		node := root.Content[0].Content[i+1]
		switch key {
		case "values":
			values, err := editValues(node)
			if err != nil {
				return editDocument{}, fmt.Errorf("values must be a map")
			}
			for k, v := range values {
				out.Values[k] = v
			}
		case "options":
			options, err := editOptions(node, nil)
			if err != nil {
				return editDocument{}, fmt.Errorf("options must be a map")
			}
			for k, v := range options {
				out.Options["options."+k] = v
			}
		default:
			return editDocument{}, fmt.Errorf("unknown edit section: %s", key)
		}
	}
	return out, nil
}

func editValues(node *yaml.Node) (map[string]string, error) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, errors.New("not a map")
	}
	out := map[string]string{}
	for i := 0; i < len(node.Content); i += 2 {
		text, err := editNodeText(node.Content[i+1])
		if err != nil {
			return nil, err
		}
		out[node.Content[i].Value] = text
	}
	return out, nil
}

func editOptions(node *yaml.Node, prefix []string) (map[string]string, error) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, errors.New("not a map")
	}
	out := map[string]string{}
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i].Value
		value := node.Content[i+1]
		path := append(prefix, key)
		if value.Kind == yaml.MappingNode {
			nested, err := editOptions(value, path)
			if err != nil {
				return nil, err
			}
			for k, v := range nested {
				out[k] = v
			}
			continue
		}
		text, err := editNodeText(value)
		if err != nil {
			return nil, err
		}
		out[strings.Join(path, ".")] = text
	}
	return out, nil
}

func editNodeText(node *yaml.Node) (string, error) {
	if node.Kind == yaml.ScalarNode {
		return node.Value, nil
	}
	value := editNodeValue(node)
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func editNodeValue(node *yaml.Node) any {
	switch node.Kind {
	case yaml.SequenceNode:
		values := make([]any, 0, len(node.Content))
		for _, child := range node.Content {
			values = append(values, editNodeValue(child))
		}
		return values
	case yaml.MappingNode:
		values := map[string]any{}
		for i := 0; i < len(node.Content); i += 2 {
			values[node.Content[i].Value] = editNodeValue(node.Content[i+1])
		}
		return values
	case yaml.ScalarNode:
		return node.Value
	default:
		return nil
	}
}

func applyEditSession(doc *config.Document, env string, session *editSession, edited editDocument) (bool, error) {
	if err := rejectUnknownEdits("values", edited.Values, session.Values); err != nil {
		return false, err
	}
	if err := rejectUnknownEdits("options", edited.Options, session.Options); err != nil {
		return false, err
	}
	changed := false
	for key, entry := range session.Values {
		value, ok := edited.Values[key]
		if !ok {
			return false, fmt.Errorf("edited document is missing values.%s", key)
		}
		if (!entry.Exists && value == "") || value == entry.Value {
			continue
		}
		if err := encryptEditedValue(doc, env, entry.Path, value); err != nil {
			return false, err
		}
		changed = true
	}
	for key, entry := range session.Options {
		value, ok := edited.Options[key]
		if !ok {
			return false, fmt.Errorf("edited document is missing %s", key)
		}
		if (!entry.Exists && value == "") || value == entry.Value {
			continue
		}
		if err := encryptEditedValue(doc, env, entry.Path, value); err != nil {
			return false, err
		}
		changed = true
	}
	return changed, nil
}

func rejectUnknownEdits(section string, edited map[string]string, allowed map[string]editEntry) error {
	for key := range edited {
		if _, ok := allowed[key]; !ok {
			if section == "options" {
				return fmt.Errorf("unknown editable key: %s", key)
			}
			return fmt.Errorf("unknown editable key: %s.%s", section, key)
		}
	}
	return nil
}

func encryptEditedValue(doc *config.Document, env string, path []string, value string) error {
	set, err := doc.RecipientSetForWrite(path, env, "")
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
	return doc.SetScalar(path, envelope.Format(envelope.EncryptedValue{
		Kind:         kind,
		Algorithm:    envelope.AlgorithmAgeV1,
		RecipientSet: set,
		Users:        recipients.Users,
		Ciphertext:   ciphertext,
	}))
}

func validateEditedDoc(doc *config.Document, filePath, env, app string, identities []age.Identity) error {
	resolved, err := doc.ResolvedEnv(env)
	if err != nil {
		return err
	}
	result, err := resolve.Env(resolved, app, identities)
	if err != nil {
		return err
	}
	for _, key := range result.AppKeys() {
		if err := result.Resolve(resolve.CanonicalPath(app, key)); err != nil {
			return err
		}
	}
	schemas, err := cinschema.Discover(doc, filePath)
	if err != nil {
		return err
	}
	if len(schemas.LoadErrors) > 0 {
		return fmt.Errorf("schema file is invalid: %s: %v", schemas.LoadErrors[0].Path, schemas.LoadErrors[0].Err)
	}
	if errs := cinschema.ValidateResult(schemas, env, app, result); len(errs) > 0 {
		return fmt.Errorf("schema validation failed: %s", errs[0].Err)
	}
	return nil
}

func editCommand() ([]string, error) {
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		return nil, errors.New("editor is required\nfix: set VISUAL or EDITOR")
	}
	fields := strings.Fields(editor)
	if len(fields) == 0 {
		return nil, errors.New("editor is required\nfix: set VISUAL or EDITOR")
	}
	return fields, nil
}

func runEditor(editor []string, path string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	args := append(append([]string(nil), editor[1:]...), path)
	cmd := exec.Command(editor[0], args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return errors.New("edit cancelled")
	}
	return nil
}

func sortedEditKeys(values map[string]editEntry) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func setYAMLPath(root *yaml.Node, path []string, value *yaml.Node) {
	cur := root
	for _, key := range path[:len(path)-1] {
		next := yamlMapValue(cur, key)
		if next == nil || next.Kind != yaml.MappingNode {
			next = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			cur.Content = append(cur.Content, yamlScalar(key), next)
		}
		cur = next
	}
	last := path[len(path)-1]
	for i := 0; i < len(cur.Content); i += 2 {
		if cur.Content[i].Value == last {
			cur.Content[i+1] = value
			return
		}
	}
	cur.Content = append(cur.Content, yamlScalar(last), value)
}

func yamlMapValue(node *yaml.Node, key string) *yaml.Node {
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func yamlScalar(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

func secureTempFile(pattern string) (*os.File, func(), error) {
	dir, err := os.MkdirTemp("", "cin-edit-*")
	if err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		os.RemoveAll(dir)
		return nil, nil, err
	}
	file, err := os.CreateTemp(dir, pattern)
	if err != nil {
		os.RemoveAll(dir)
		return nil, nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		os.RemoveAll(dir)
		return nil, nil, err
	}
	cleanup := signalCleanup(dir)
	return file, cleanup, nil
}

func signalCleanup(path string) func() {
	done := make(chan struct{})
	signals := make(chan os.Signal, 1)
	var once sync.Once
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case sig := <-signals:
			_ = os.RemoveAll(path)
			signal.Stop(signals)
			_ = syscall.Kill(syscall.Getpid(), sig.(syscall.Signal))
		case <-done:
		}
	}()
	return func() {
		once.Do(func() {
			close(done)
			signal.Stop(signals)
			_ = os.RemoveAll(path)
		})
	}
}

func runChild(args []string, envVars map[string]string, stdin io.Reader, stdout io.Writer, stderr io.Writer) (int, error) {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = childEnv(envVars)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return 0, err
	}

	done := make(chan struct{})
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	go func() {
		for {
			select {
			case sig := <-signals:
				_ = cmd.Process.Signal(sig)
			case <-done:
				return
			}
		}
	}()

	err := cmd.Wait()
	close(done)
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return processExitCode(exitErr), nil
	}
	return 0, err
}

func childEnv(envVars map[string]string) []string {
	keys := make([]string, 0, len(envVars))
	for key := range envVars {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	overrides := map[string]bool{}
	for _, key := range keys {
		overrides[key] = true
	}

	env := make([]string, 0, len(os.Environ())+len(envVars))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !overrides[key] {
			env = append(env, entry)
		}
	}
	for _, key := range keys {
		env = append(env, key+"="+envVars[key])
	}
	return env
}

func processExitCode(err *exec.ExitError) int {
	if status, ok := err.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return err.ExitCode()
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

func rekeyOperator(doc *config.Document, userFlag string) (string, []age.Identity, error) {
	current, err := currentUser(userFlag)
	if err != nil {
		return "", nil, err
	}
	if !doc.UserActive(current) {
		return "", nil, fmt.Errorf("current user is not active: %s", current)
	}
	identities, err := cryptoage.DiscoverIdentity(current)
	if err != nil {
		return "", nil, err
	}
	return current, identities, nil
}

func rekey(doc *config.Document, identities []age.Identity, sets []string) (int, error) {
	affected := setMapFromSlice(sets)
	count := 0
	for _, ref := range doc.EncryptedValues() {
		if !affected[ref.Value.RecipientSet] {
			continue
		}
		recipients, err := doc.Recipients(ref.Value.RecipientSet)
		if err != nil {
			return count, err
		}
		if sameStrings(ref.Value.Users, recipients.Users) {
			continue
		}
		plaintext, err := cryptoage.Decrypt(ref.Value.Ciphertext, identities)
		if err != nil {
			return count, fmt.Errorf("cannot decrypt %s with current identity", strings.Join(ref.Path, "."))
		}
		ciphertext, err := cryptoage.Encrypt(plaintext, recipients.Recipients)
		if err != nil {
			return count, err
		}
		if err := doc.SetScalar(ref.Path, envelope.Format(envelope.EncryptedValue{
			Kind:         ref.Value.Kind,
			Algorithm:    envelope.AlgorithmAgeV1,
			RecipientSet: ref.Value.RecipientSet,
			Users:        recipients.Users,
			Ciphertext:   ciphertext,
		})); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func impactCounts(doc *config.Document, sets []string) map[string]int {
	affected := setMapFromSlice(sets)
	counts := map[string]int{}
	for _, ref := range doc.EncryptedValues() {
		if affected[ref.Value.RecipientSet] {
			counts[ref.Value.RecipientSet]++
		}
	}
	return counts
}

func printApprovalSummary(stdout io.Writer, username string, sets []string, counts map[string]int) {
	fmt.Fprintf(stdout, "Approving %s will grant access through these recipient sets:\n\n", username)
	for _, set := range sets {
		fmt.Fprintf(stdout, "  %s\n", set)
		fmt.Fprintf(stdout, "    values to rekey: %d\n", counts[set])
	}
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "This will allow %s to decrypt values encrypted to those recipient sets.\n", username)
	fmt.Fprint(stdout, "Type approve to continue: ")
}

func readApproval(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func fingerprint(publicKey string) string {
	sum := sha256.Sum256([]byte(publicKey))
	return hex.EncodeToString(sum[:])[:12]
}

func setMapFromSlice(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
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

type commandExitError struct {
	code int
}

func (e commandExitError) Error() string {
	return fmt.Sprintf("command exited with status %d", e.code)
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
